//! Native peer boundary. Handles are owned by the UI thread; sessions own their async state.
//! A watch channel retains only the latest UI state, including a pending consent request.

use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Context, Result};
use bifrost::{
    AccessDecision, AccessRequest, ApprovedSession, Capability, EndpointConfig, NetworkProvider,
    PeerConfig, PeerConnection, PeerEvent, PeerHandler, PeerMetadata, Platform, ReconnectSettings,
    generate_join_token, normalize_websocket_url, run_peer, session_consent_prompt,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;

static NETWORK: LazyLock<NetworkProvider> = LazyLock::new(NetworkProvider::local);

static RUNTIME: LazyLock<Result<Runtime>> = LazyLock::new(|| {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("failed to start the networking runtime")
});

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    endpoint: NativeEndpoint,
    device_name: String,
    reconnect: bool,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum NativeEndpoint {
    Connect {
        url: String,
    },
    Listen {
        address: std::net::SocketAddr,
        join_token: String,
    },
}

impl Configuration {
    fn into_peer(self) -> Result<PeerConfig> {
        let endpoint = match self.endpoint {
            NativeEndpoint::Connect { url } => EndpointConfig::Connect {
                url: normalize_websocket_url(&url)?,
                extra_roots: Vec::new(),
            },
            NativeEndpoint::Listen {
                address,
                join_token,
            } => EndpointConfig::Listen {
                address,
                join_token,
            },
        };
        Ok(PeerConfig {
            endpoint,
            node_id: generate_join_token(),
            handshake_timeout: std::time::Duration::from_secs(30),
            metadata: PeerMetadata {
                hostname: self.device_name,
                username: "mobile-user".to_string(),
                working_directory: "/".to_string(),
                platform: Platform::current()?,
            },
            reconnect: self.reconnect.then_some(ReconnectSettings {
                interval_seconds: 5,
                timeout_seconds: 300,
            }),
        })
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Event {
    Status {
        phase: &'static str,
    },
    Offer {
        consumer: String,
        description: String,
        mode: &'static str,
    },
    Failed {
        message: String,
    },
    Closed,
}

#[derive(Clone, Serialize)]
struct UiState {
    #[serde(flatten)]
    event: Event,
    join_url: Option<String>,
}

struct NativeState {
    listener: Mutex<Option<String>>,
    events: watch::Sender<Option<UiState>>,
    decision: Mutex<Option<oneshot::Sender<bool>>>,
    unencrypted: std::sync::atomic::AtomicBool,
}

impl NativeState {
    fn emit(&self, event: Event) {
        self.events.send_replace(Some(UiState {
            event,
            join_url: self
                .listener
                .lock()
                .expect("listener mutex poisoned")
                .clone(),
        }));
    }
}

struct NativeProvider {
    state: Arc<NativeState>,
}

impl PeerHandler for NativeProvider {
    fn request(&self) -> Option<AccessRequest> {
        None
    }
    fn event(&self, event: PeerEvent) {
        let phase = match event {
            PeerEvent::Listening { join_url, .. } => {
                *self.state.listener.lock().expect("listener mutex poisoned") = Some(join_url);
                return;
            }
            PeerEvent::Connecting => "connecting",
            PeerEvent::Connected => "connected",
            PeerEvent::Reconnecting
            | PeerEvent::ConnectionLost(_)
            | PeerEvent::AttemptFailed(_) => "reconnecting",
            PeerEvent::UnencryptedTransport => {
                self.state
                    .unencrypted
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        };
        self.state.emit(Event::Status { phase });
    }

    fn refusal(&self, request: &AccessRequest) -> Option<String> {
        matches!(request.capability, Capability::Ssh { .. }).then(||
            "This iOS peer supports VPN and SOCKS network access. SSH shell sessions are unavailable.".to_string()
        )
    }

    async fn approve(&self, offer: &AccessRequest) -> Result<AccessDecision> {
        let (sender, receiver) = oneshot::channel();
        *self.state.decision.lock().expect("decision mutex poisoned") = Some(sender);
        let mut description = session_consent_prompt(&offer.consumer_name, &offer.capability);
        if self
            .state
            .unencrypted
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            description.push_str(" This connection is not encrypted. Traffic and the join token are exposed to the network between this device and the portal.");
        }
        if offer.forwarding {
            description.push_str(" This includes forwarding access for downstream Bifrost peers.");
        }
        self.state.emit(Event::Offer {
            consumer: offer.consumer_name.clone(),
            description,
            mode: match offer.capability {
                Capability::Network { .. } => "Network access",
                Capability::Ssh { .. } => unreachable!("SSH requests are refused before consent"),
            },
        });
        let allowed = receiver.await.context("session approval cancelled")?;
        Ok(AccessDecision {
            session_allowed: allowed,
            key_installed: false,
            note: (!allowed).then(|| "local user declined the support session".to_string()),
        })
    }

    async fn serve(
        &mut self,
        connection: PeerConnection,
        session: ApprovedSession,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let (websocket, lease) = connection.into_socket();
        let result = NETWORK
            .run(websocket, session.request.capability, shutdown)
            .await;
        drop(lease);
        result
    }
}

/// Owns the UI event receiver and cancellation of one native session.
pub struct NativePeer {
    handler: Arc<NativeState>,
    events: watch::Receiver<Option<UiState>>,
    cancellation: CancellationToken,
}

impl Drop for NativePeer {
    fn drop(&mut self) {
        // The task owns its handler until cancellation has torn down its sockets and flow tasks.
        self.cancellation.cancel();
    }
}

/// Starts a session and returns its UI-owned handle. Configuration errors arrive as events.
///
/// # Safety
/// `configuration` must point to a valid, NUL-terminated UTF-8 string for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bifrost_peer_create(configuration: *const c_char) -> *mut NativePeer {
    let (sender, events) = watch::channel(None);
    let handler = Arc::new(NativeState {
        listener: Mutex::new(None),
        events: sender,
        decision: Mutex::new(None),
        unencrypted: std::sync::atomic::AtomicBool::new(false),
    });
    let cancellation = CancellationToken::new();
    let peer = Box::new(NativePeer {
        handler: handler.clone(),
        events,
        cancellation: cancellation.clone(),
    });
    let config = if configuration.is_null() {
        Err(anyhow::anyhow!("missing peer configuration"))
    } else {
        // Copy caller memory before returning to Swift.
        unsafe { CStr::from_ptr(configuration) }
            .to_str()
            .context("configuration is not UTF-8")
            .and_then(|json| {
                serde_json::from_str::<Configuration>(json).context("invalid peer configuration")
            })
            .and_then(Configuration::into_peer)
    };
    match (config, RUNTIME.as_ref()) {
        (Ok(config), Ok(runtime)) => {
            // The runtime root stays on one native thread, including platform-owned state.
            runtime.spawn_blocking(move || {
                runtime.block_on(async move {
                    let mut provider = NativeProvider {
                        state: handler.clone(),
                    };
                    match run_peer(config, &mut provider, cancellation).await {
                        Ok(()) => handler.emit(Event::Closed),
                        Err(error) => handler.emit(Event::Failed {
                            message: format!("{error:#}"),
                        }),
                    }
                })
            });
        }
        (Err(error), _) => handler.emit(Event::Failed {
            message: format!("{error:#}"),
        }),
        (_, Err(error)) => handler.emit(Event::Failed {
            message: format!("{error:#}"),
        }),
    }
    Box::into_raw(peer)
}

/// Returns the latest changed JSON state or NULL. Free it with `bifrost_string_free`.
///
/// # Safety
/// `peer` must be a live handle. Calls on one handle must be serialized by the UI thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bifrost_peer_poll(peer: *mut NativePeer) -> *mut c_char {
    let peer = unsafe { &mut *peer };
    if !matches!(peer.events.has_changed(), Ok(true)) {
        return ptr::null_mut();
    }
    let event = peer.events.borrow_and_update();
    match event.as_ref() {
        Some(event) => {
            CString::new(serde_json::to_string(event).expect("event serialization failed"))
                .expect("JSON cannot contain NUL bytes")
                .into_raw()
        }
        None => ptr::null_mut(),
    }
}

/// Supplies the pending local consent decision.
///
/// # Safety
/// `peer` must be a live handle owned by the calling UI thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bifrost_peer_approve(peer: *mut NativePeer, allowed: bool) {
    let peer = unsafe { &*peer };
    if let Some(sender) = peer
        .handler
        .decision
        .lock()
        .expect("decision mutex poisoned")
        .take()
    {
        let _ = sender.send(allowed);
    }
}

/// Cancels a session and releases the handle. Outstanding events are discarded.
///
/// # Safety
/// `peer` must be a live handle, freed exactly once, with no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bifrost_peer_free(peer: *mut NativePeer) {
    if !peer.is_null() {
        drop(unsafe { Box::from_raw(peer) });
    }
}

/// Releases a JSON event returned by `bifrost_peer_poll`.
///
/// # Safety
/// `string` must be NULL or an event pointer from this library, freed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bifrost_string_free(string: *mut c_char) {
    if !string.is_null() {
        drop(unsafe { CString::from_raw(string) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_and_encrypted_websocket_urls() {
        for (input, scheme) in [
            ("http://localhost:8080?token=test", "ws"),
            ("ws://localhost:8080?token=test", "ws"),
            ("https://example.com?token=test", "wss"),
            ("wss://example.com?token=test", "wss"),
        ] {
            let config = Configuration {
                endpoint: NativeEndpoint::Connect {
                    url: input.to_string(),
                },
                device_name: "iPhone".to_string(),
                reconnect: false,
            }
            .into_peer()
            .unwrap();
            let EndpointConfig::Connect { url, .. } = config.endpoint else {
                panic!("expected connect endpoint");
            };
            assert_eq!(url.scheme(), scheme);
            assert_eq!(url.query(), Some("token=test"));
        }
    }

    #[test]
    fn native_provider_refuses_shell_requests() {
        let (events, _) = watch::channel(None);
        let handler = NativeProvider {
            state: Arc::new(NativeState {
                listener: Mutex::new(None),
                events,
                decision: Mutex::new(None),
                unencrypted: std::sync::atomic::AtomicBool::new(false),
            }),
        };
        assert!(
            handler
                .refusal(&AccessRequest {
                    protocol_version: bifrost::PROTOCOL_VERSION,
                    forwarding: false,
                    consumer_name: "consumer".to_string(),
                    capability: Capability::Ssh {
                        ssh_public_key: String::new(),
                        persist_key_requested: false
                    },
                })
                .is_some()
        );
        assert!(
            handler
                .refusal(&AccessRequest {
                    protocol_version: bifrost::PROTOCOL_VERSION,
                    forwarding: false,
                    consumer_name: "consumer".to_string(),
                    capability: Capability::Network {
                        policy: bifrost::NetworkPolicy::unrestricted()
                    }
                })
                .is_none()
        );
    }

    #[tokio::test]
    async fn consent_decision_is_owned_by_the_session() {
        let (events, mut receiver) = watch::channel(None);
        let handler = Arc::new(NativeState {
            listener: Mutex::new(None),
            events,
            decision: Mutex::new(None),
            unencrypted: std::sync::atomic::AtomicBool::new(false),
        });
        let pending = tokio::spawn({
            let handler = handler.clone();
            async move {
                NativeProvider { state: handler }
                    .approve(&AccessRequest {
                        protocol_version: bifrost::PROTOCOL_VERSION,
                        forwarding: false,
                        consumer_name: "Support".to_string(),
                        capability: Capability::Network {
                            policy: bifrost::NetworkPolicy::unrestricted(),
                        },
                    })
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(matches!(
            &receiver.borrow_and_update().as_ref().unwrap().event,
            Event::Offer { .. }
        ));
        handler
            .decision
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(false)
            .unwrap();
        assert!(!pending.await.unwrap().unwrap().session_allowed);
    }
    #[tokio::test]
    async fn plain_ws_vpn_requires_consent_and_carries_tcp() {
        use bifrost::{
            ControlPacket, NetworkPolicy, PROTOCOL_VERSION, recv_packet, run_consumer_socks_proxy,
            send_packet,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let rendezvous = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = rendezvous.local_addr().unwrap();
        let proxy = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let proxy_address = proxy.local_addr().unwrap();
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let operator = tokio::spawn(async move {
            let (socket, _) = rendezvous.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
            assert!(matches!(
                recv_packet(&mut websocket).await.unwrap(),
                ControlPacket::PeerHello(_)
            ));
            send_packet(
                &mut websocket,
                &ControlPacket::PeerHello(Box::new(bifrost::PeerHello {
                    network_policy: None,
                    role: bifrost::PeerRole::Consumer,
                    node_id: "22222222222222222222222222222222".to_string(),
                    route: Vec::new(),
                    protocol_version: PROTOCOL_VERSION,
                    reconnect: None,
                    metadata: bifrost::PeerMetadata {
                        hostname: "test".to_string(),
                        username: "test".to_string(),
                        working_directory: "/".to_string(),
                        platform: bifrost::Platform::current().unwrap(),
                    },
                })),
            )
            .await
            .unwrap();
            send_packet(
                &mut websocket,
                &ControlPacket::AccessRequest(AccessRequest {
                    protocol_version: PROTOCOL_VERSION,
                    consumer_name: "WS test".to_string(),
                    forwarding: false,
                    capability: Capability::Network {
                        policy: NetworkPolicy::unrestricted(),
                    },
                }),
            )
            .await
            .unwrap();
            let ControlPacket::AccessDecision(decision) =
                recv_packet(&mut websocket).await.unwrap()
            else {
                panic!("expected consent decision")
            };
            assert!(decision.session_allowed);
            send_packet(&mut websocket, &ControlPacket::SessionReady {})
                .await
                .unwrap();
            run_consumer_socks_proxy(websocket, proxy).await
        });
        let configuration = CString::new(format!(
            r#"{{"endpoint":{{"kind":"connect","url":"ws://{address}"}},"device_name":"iPhone","reconnect":false}}"#
        ))
        .unwrap();
        let peer = unsafe { bifrost_peer_create(configuration.as_ptr()) };
        struct PeerGuard(*mut NativePeer);
        impl Drop for PeerGuard {
            fn drop(&mut self) {
                unsafe {
                    bifrost_peer_free(self.0);
                }
            }
        }
        let _guard = PeerGuard(peer);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let pointer = unsafe { bifrost_peer_poll(peer) };
                if !pointer.is_null() {
                    let event = unsafe { CStr::from_ptr(pointer) }
                        .to_str()
                        .unwrap()
                        .to_owned();
                    unsafe {
                        bifrost_string_free(pointer);
                    }
                    let event: serde_json::Value = serde_json::from_str(&event).unwrap();
                    assert_ne!(event["kind"], "failed", "{event}");
                    if event["kind"] == "offer" {
                        assert!(
                            event["description"]
                                .as_str()
                                .unwrap()
                                .contains("not encrypted")
                        );
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        unsafe {
            bifrost_peer_approve(peer, true);
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut socket = TcpStream::connect(proxy_address).await.unwrap();
            socket.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            socket.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            let port = echo_address.port().to_be_bytes();
            socket
                .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port[0], port[1]])
                .await
                .unwrap();
            let mut reply = [0; 10];
            socket.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 0);
            socket.write_all(b"ping").await.unwrap();
            let mut response = [0; 4];
            socket.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ping");
        })
        .await
        .unwrap();
        echo_task.await.unwrap();
        operator.abort();
    }
}
