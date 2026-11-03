use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::handshake::server::create_response;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use url::{Url, form_urlencoded};

use crate::websocket::{AddressedTransport, WebSocketTransport};
use crate::{DEFAULT_CONNECT_PATH, DEFAULT_HEALTH_PATH, PeerWebSocket, websocket_config};

/// Determines how a peer obtains a connection, independently of its capabilities.
#[derive(Clone)]
pub enum EndpointConfig {
    Connect {
        url: Url,
        extra_roots: Vec<CertificateDer<'static>>,
    },
    Listen {
        address: SocketAddr,
        join_token: String,
    },
}

/// One established transport. Admission remains reserved for the connection's lifetime.
pub struct PeerConnection {
    pub websocket: PeerWebSocket,
    pub local_address: SocketAddr,
    pub peer_address: SocketAddr,
    pub encrypted: bool,
    pub(crate) admission: Option<OwnedSemaphorePermit>,
}

impl PeerConnection {
    pub fn into_socket(self) -> (PeerWebSocket, Option<OwnedSemaphorePermit>) {
        (self.websocket, self.admission)
    }
}

pub(crate) enum Endpoint {
    Connect {
        url: Url,
        extra_roots: Vec<CertificateDer<'static>>,
    },
    Listen(Listener),
}

pub(crate) struct Listener {
    address: SocketAddr,
    incoming: mpsc::Receiver<PeerConnection>,
    cancellation: CancellationToken,
    task: Option<AbortOnDropHandle<Result<()>>>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl Endpoint {
    pub(crate) async fn bind(config: EndpointConfig) -> Result<Self> {
        Self::bind_with_capacity(config, 1).await
    }

    pub(crate) async fn bind_with_capacity(
        config: EndpointConfig,
        max_sessions: usize,
    ) -> Result<Self> {
        if max_sessions == 0 {
            bail!("peer capacity must not be zero");
        }
        match config {
            EndpointConfig::Connect { url, extra_roots } => Ok(Self::Connect { url, extra_roots }),
            EndpointConfig::Listen {
                address,
                join_token,
            } => {
                if join_token.is_empty() {
                    bail!("join token must not be empty");
                }
                let listener = TcpListener::bind(address)
                    .await
                    .with_context(|| format!("failed to bind rendezvous to {address}"))?;
                let address = listener.local_addr()?;
                let (sender, incoming) = mpsc::channel(1);
                let cancellation = CancellationToken::new();
                let task = AbortOnDropHandle::new(tokio::spawn(run_listener(
                    listener,
                    join_token,
                    sender,
                    cancellation.clone(),
                    ListenerLimits {
                        max_sessions,
                        ..ListenerLimits::default()
                    },
                )));
                Ok(Self::Listen(Listener {
                    address,
                    incoming,
                    cancellation,
                    task: Some(task),
                }))
            }
        }
    }

    pub(crate) fn bound_address(&self) -> Option<SocketAddr> {
        match self {
            Self::Listen(listener) => Some(listener.address),
            Self::Connect { .. } => None,
        }
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        if let Self::Listen(listener) = self {
            listener.cancellation.cancel();
            if let Some(task) = listener.task.take() {
                task.await.context("rendezvous task failed to join")??;
            }
        }
        Ok(())
    }

    pub(crate) fn is_listener(&self) -> bool {
        matches!(self, Self::Listen(_))
    }

    pub(crate) async fn next(&mut self) -> Result<PeerConnection> {
        match self {
            Self::Connect { url, extra_roots } => {
                let (websocket, _) =
                    crate::connect_async_with_env_proxy_and_extra_roots(url, extra_roots.clone())
                        .await?;
                let addresses = match websocket.get_ref() {
                    MaybeTlsStream::Plain(stream) => stream.addresses(),
                    MaybeTlsStream::Rustls(stream) => stream.get_ref().0.addresses(),
                    _ => bail!("unsupported WebSocket transport"),
                };
                Ok(PeerConnection {
                    websocket,
                    local_address: addresses.0,
                    peer_address: addresses.1,
                    encrypted: url.scheme() == "wss",
                    admission: None,
                })
            }
            Self::Listen(listener) => {
                tokio::select! {
                    connection = listener.incoming.recv() => connection.context("rendezvous stopped before a peer connected"),
                    result = listener.task.as_mut().expect("rendezvous task is owned") => {
                        listener.task.take();
                        result.context("rendezvous task failed to join")??;
                        bail!("rendezvous stopped before a peer connected")
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ListenerLimits {
    max_connections: usize,
    max_sessions: usize,
    header_timeout: Duration,
    upgrade_timeout: Duration,
}

impl Default for ListenerLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_sessions: 1,
            header_timeout: Duration::from_secs(10),
            upgrade_timeout: Duration::from_secs(30),
        }
    }
}

async fn run_listener(
    listener: TcpListener,
    join_token: String,
    sender: mpsc::Sender<PeerConnection>,
    cancellation: CancellationToken,
    limits: ListenerLimits,
) -> Result<()> {
    if limits.max_connections == 0
        || limits.header_timeout.is_zero()
        || limits.upgrade_timeout.is_zero()
    {
        bail!("rendezvous limits must not be zero");
    }
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout)
        .max_headers(64)
        .max_buf_size(16 * 1024);
    let http_admission = Arc::new(Semaphore::new(limits.max_connections));
    let session_admission = Arc::new(Semaphore::new(limits.max_sessions));
    let join_token = Arc::new(join_token);
    let mut connections = JoinSet::new();
    let (upgrades, mut jobs) = mpsc::channel::<UpgradeJob>(1);
    let mut upgrades_in_flight = JoinSet::new();
    let result = loop {
        if let Err(error) =
            reap_finished(&mut connections).and_then(|_| reap_finished(&mut upgrades_in_flight))
        {
            break Err(error);
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break Ok(()),
            accepted = async {
                let permit = Arc::clone(&http_admission).acquire_owned().await?;
                let (socket, peer) = listener.accept().await?;
                Ok::<_, anyhow::Error>((socket, peer, permit))
            } => {
                let (socket, peer, permit) = match accepted { Ok(value) => value, Err(error) => break Err(error) };
                if socket.set_nodelay(true).is_err() { continue; }
                let local = match socket.local_addr() { Ok(address) => address, Err(error) => break Err(error).context("failed to read rendezvous socket address") };
                let token = Arc::clone(&join_token);
                let admission = Arc::clone(&session_admission);
                let upgrades = upgrades.clone();
                let builder = builder.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let service = service_fn(move |request| std::future::ready(handle_request(request, &token, &admission, &upgrades, local, peer, limits.max_sessions)));
                    builder.serve_connection(TokioIo::new(socket), service).with_upgrades().await.context("HTTP connection failed")
                });
            }
            job = jobs.recv() => {
                let Some(job) = job else { break Err(anyhow::anyhow!("upgrade queue closed")); };
                let sender = sender.clone();
                upgrades_in_flight.spawn(async move {
                    let upgraded = tokio::time::timeout(limits.upgrade_timeout, job.upgrade).await
                        .context("WebSocket upgrade timed out")??;
                    let stream: Box<dyn WebSocketTransport> = Box::new(AddressedTransport::new(TokioIo::new(upgraded), job.local, job.peer));
                    let websocket = WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(stream), Role::Server, Some(websocket_config())).await;
                    sender.send(PeerConnection { websocket, local_address: job.local, peer_address: job.peer,
                        encrypted: false, admission: Some(job.permit) }).await.map_err(|_| anyhow::anyhow!("peer receiver closed"))
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result && !error.is_cancelled() {
                    break Err(error).context("HTTP task failed to join");
                }
            }
            result = upgrades_in_flight.join_next(), if !upgrades_in_flight.is_empty() => {
                match result {
                    Some(Err(error)) if !error.is_cancelled() => break Err(error).context("upgrade task failed to join"),
                    Some(Ok(Err(error))) => eprintln!("WebSocket upgrade failed: {error:#}"),
                    _ => {}
                }
            }
        }
    };
    connections.abort_all();
    upgrades_in_flight.abort_all();
    while connections.join_next().await.is_some() {}
    while upgrades_in_flight.join_next().await.is_some() {}
    result
}

fn reap_finished(tasks: &mut JoinSet<Result<()>>) -> Result<()> {
    while let Some(result) = tasks.try_join_next() {
        match result {
            Err(error) if !error.is_cancelled() => {
                return Err(error).context("rendezvous task failed to join");
            }
            Ok(Err(error)) => {
                crate::debug::debug_log(format!("rendezvous connection ended: {error:#}"))
            }
            _ => {}
        }
    }
    Ok(())
}

struct UpgradeJob {
    upgrade: hyper::upgrade::OnUpgrade,
    local: SocketAddr,
    peer: SocketAddr,
    permit: OwnedSemaphorePermit,
}

fn handle_request(
    mut request: Request<Incoming>,
    token: &str,
    admission: &Arc<Semaphore>,
    upgrades: &mpsc::Sender<UpgradeJob>,
    local: SocketAddr,
    peer: SocketAddr,
    capacity: usize,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/") => plain_response(StatusCode::OK, "Bifrost rendezvous\n"),
        (&Method::GET, DEFAULT_HEALTH_PATH) => {
            let phase = if admission.available_permits() < capacity {
                "connected"
            } else {
                "waiting"
            };
            Response::builder()
                .header("content-type", "application/json")
                .body(Full::from(Bytes::from(
                    serde_json::json!({"phase": phase}).to_string(),
                )))
                .expect("valid health response")
        }
        (&Method::GET, DEFAULT_CONNECT_PATH) => {
            upgrade_response(&mut request, token, admission, upgrades, local, peer)
        }
        _ => plain_response(StatusCode::NOT_FOUND, "not found"),
    };
    Ok(response)
}

fn upgrade_response(
    request: &mut Request<Incoming>,
    token: &str,
    admission: &Arc<Semaphore>,
    upgrades: &mpsc::Sender<UpgradeJob>,
    local: SocketAddr,
    peer: SocketAddr,
) -> Response<Full<Bytes>> {
    if !request_matches_join_token(request, token) {
        return plain_response(StatusCode::NOT_FOUND, "not found");
    }
    let permit = match Arc::clone(admission).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return plain_response(StatusCode::CONFLICT, "a peer session is already active"),
    };
    let handshake = Request::builder()
        .method(request.method())
        .uri(request.uri())
        .version(request.version());
    let mut handshake = handshake.body(()).expect("valid request parts");
    *handshake.headers_mut() = request.headers().clone();
    let response = match create_response(&handshake) {
        Ok(response) => response,
        Err(_) => return plain_response(StatusCode::BAD_REQUEST, "invalid WebSocket upgrade"),
    };
    let job = UpgradeJob {
        upgrade: hyper::upgrade::on(request),
        local,
        peer,
        permit,
    };
    if upgrades.try_send(job).is_err() {
        return plain_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "rendezvous is shutting down",
        );
    }
    response.map(|_| Full::new(Bytes::new()))
}

fn plain_response(status: StatusCode, body: impl Into<String>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::from(Bytes::from(body.into())))
        .expect("valid plain response")
}

fn request_matches_join_token<B>(request: &Request<B>, token: &str) -> bool {
    request.uri().query().is_some_and(|query| {
        form_urlencoded::parse(query.as_bytes())
            .any(|(name, value)| name == "token" && value == token)
    })
}

pub fn websocket_endpoint(address: SocketAddr, token: &str) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("token", token)
        .finish();
    format!("ws://{address}{DEFAULT_CONNECT_PATH}?{query}")
}

pub fn generate_join_token() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{Error, Message},
    };

    async fn listener(
        limits: ListenerLimits,
    ) -> (
        SocketAddr,
        mpsc::Receiver<PeerConnection>,
        CancellationToken,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel(1);
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_listener(
            socket,
            "  shared+token&雪  ".to_string(),
            sender,
            cancellation.clone(),
            limits,
        ));
        (address, receiver, cancellation, task)
    }

    #[tokio::test]
    async fn upgrade_requires_the_complete_literal_join_token() {
        let (address, mut incoming, cancellation, task) = listener(ListenerLimits::default()).await;
        let wrong = websocket_endpoint(address, "shared+token&雪");
        let Error::Http(response) = connect_async(wrong).await.unwrap_err() else {
            panic!("expected HTTP rejection");
        };
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let (mut socket, _) = connect_async(websocket_endpoint(address, "  shared+token&雪  "))
            .await
            .unwrap();
        let mut connection = incoming.recv().await.unwrap();
        connection
            .websocket
            .send(Message::Binary(Bytes::from_static(b"approved")))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_data(),
            b"approved"[..]
        );
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn admission_lasts_until_the_established_connection_is_dropped() {
        let (address, mut incoming, cancellation, task) = listener(ListenerLimits::default()).await;
        let url = websocket_endpoint(address, "  shared+token&雪  ");
        let (_socket, _) = connect_async(&url).await.unwrap();
        let connection = incoming.recv().await.unwrap();
        let Error::Http(response) = connect_async(&url).await.unwrap_err() else {
            panic!("expected occupied admission");
        };
        assert_eq!(response.status(), StatusCode::CONFLICT);
        drop(connection);
        let (_replacement, _) = connect_async(&url).await.unwrap();
        assert!(incoming.recv().await.is_some());
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stopping_http_joins_idle_connections_and_preserves_an_owned_websocket() {
        let (address, mut incoming, cancellation, task) = listener(ListenerLimits::default()).await;
        let mut idle = TcpStream::connect(address).await.unwrap();
        idle.write_all(b"GET /healthz HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        let (mut socket, _) = connect_async(websocket_endpoint(address, "  shared+token&雪  "))
            .await
            .unwrap();
        let mut connection = incoming.recv().await.unwrap();
        cancellation.cancel();
        task.await.unwrap().unwrap();
        let mut byte = [0];
        assert_eq!(idle.read(&mut byte).await.unwrap(), 0);
        connection
            .websocket
            .send(Message::Binary(Bytes::from_static(b"alive")))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_data(),
            b"alive"[..]
        );
    }

    #[tokio::test]
    async fn partial_headers_expire_and_release_bounded_http_admission() {
        let limits = ListenerLimits {
            max_connections: 1,
            header_timeout: Duration::from_millis(100),
            ..ListenerLimits::default()
        };
        let (address, _incoming, cancellation, task) = listener(limits).await;
        let mut partial = TcpStream::connect(address).await.unwrap();
        partial.write_all(b"GET / HTTP/1.1\r\nHost:").await.unwrap();
        let mut health = TcpStream::connect(address).await.unwrap();
        health
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0; 1024];
        let count = tokio::time::timeout(Duration::from_secs(2), health.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            std::str::from_utf8(&response[..count])
                .unwrap()
                .contains("200 OK")
        );
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }
}
