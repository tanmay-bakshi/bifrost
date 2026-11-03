//! Native client boundary. Handles are owned by the UI thread; sessions own their async state.
//! A watch channel retains only the latest UI state, including a pending consent request.

use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sshportal::{
    ClientConfig, ClientDecision, ClientEvent, ClientHandler, ClientMetadata,
    ClientWebSocketStream, OfferedSession, Platform, ReconnectSettings, ServerOffer,
    normalize_websocket_url, run_client, run_client_network_proxy, session_consent_prompt,
};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;

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
    server: String,
    device_name: String,
    reconnect: bool,
}

impl Configuration {
    fn into_client(self) -> Result<ClientConfig> {
        let server = normalize_websocket_url(&self.server)?;
        Ok(ClientConfig {
            server,
            metadata: ClientMetadata {
                hostname: self.device_name,
                username: "mobile-user".to_string(),
                working_directory: "/".to_string(),
                platform: Platform::current()?,
            },
            extra_roots: Vec::new(),
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
        operator: String,
        description: String,
        mode: &'static str,
    },
    Failed {
        message: String,
    },
    Closed,
}

struct NativeHandler {
    events: watch::Sender<Option<Event>>,
    decision: Mutex<Option<oneshot::Sender<bool>>>,
    unencrypted: std::sync::atomic::AtomicBool,
}

impl NativeHandler {
    fn emit(&self, event: Event) {
        self.events.send_replace(Some(event));
    }
}

impl ClientHandler for NativeHandler {
    fn event(&self, event: ClientEvent) {
        let phase = match event {
            ClientEvent::Connecting => "connecting",
            ClientEvent::Connected => "connected",
            ClientEvent::Reconnecting
            | ClientEvent::ConnectionLost(_)
            | ClientEvent::AttemptFailed(_) => "reconnecting",
            ClientEvent::UnencryptedTransport => {
                self.unencrypted
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        };
        self.emit(Event::Status { phase });
    }

    fn refusal(&self, session: &OfferedSession) -> Option<String> {
        matches!(session, OfferedSession::Ssh { .. }).then(||
            "This iOS client supports VPN and SOCKS network access. SSH shell sessions are unavailable.".to_string()
        )
    }

    async fn approve(&self, offer: &ServerOffer) -> Result<ClientDecision> {
        let (sender, receiver) = oneshot::channel();
        *self.decision.lock().expect("decision mutex poisoned") = Some(sender);
        let mut description = session_consent_prompt(&offer.operator_name, &offer.session);
        if self.unencrypted.load(std::sync::atomic::Ordering::Relaxed) {
            description.push_str(" This connection is not encrypted. Traffic and the join token are exposed to the network between this device and the portal.");
        }
        if let Some(reconnect) = &offer.reconnect {
            description.push_str(&format!(
                " Allow the same operator and access to reconnect for up to {} seconds after a connection drops, while this app remains open.",
                reconnect.settings.timeout_seconds
            ));
        }
        self.emit(Event::Offer {
            operator: offer.operator_name.clone(),
            description,
            mode: match offer.session {
                OfferedSession::Vpn { .. } => "VPN egress",
                OfferedSession::Socks {} => "SOCKS egress",
                OfferedSession::Ssh { .. } => unreachable!("SSH offers are refused before consent"),
            },
        });
        let allowed = receiver.await.context("session approval cancelled")?;
        Ok(ClientDecision {
            session_allowed: allowed,
            key_installed: false,
            note: (!allowed).then(|| "local user declined the support session".to_string()),
        })
    }

    async fn serve(&self, websocket: ClientWebSocketStream, session: OfferedSession) -> Result<()> {
        run_client_network_proxy(websocket, session).await
    }
}

/// Owns the UI event receiver and cancellation of one native session.
pub struct NativeClient {
    handler: Arc<NativeHandler>,
    events: watch::Receiver<Option<Event>>,
    cancellation: CancellationToken,
}

impl Drop for NativeClient {
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
pub unsafe extern "C" fn sshportal_client_create(
    configuration: *const c_char,
) -> *mut NativeClient {
    let (sender, events) = watch::channel(None);
    let handler = Arc::new(NativeHandler {
        events: sender,
        decision: Mutex::new(None),
        unencrypted: std::sync::atomic::AtomicBool::new(false),
    });
    let cancellation = CancellationToken::new();
    let client = Box::new(NativeClient {
        handler: handler.clone(),
        events,
        cancellation: cancellation.clone(),
    });
    let config = if configuration.is_null() {
        Err(anyhow::anyhow!("missing client configuration"))
    } else {
        // Copy caller memory before returning to Swift.
        unsafe { CStr::from_ptr(configuration) }
            .to_str()
            .context("configuration is not UTF-8")
            .and_then(|json| {
                serde_json::from_str::<Configuration>(json).context("invalid client configuration")
            })
            .and_then(Configuration::into_client)
    };
    match (config, RUNTIME.as_ref()) {
        (Ok(config), Ok(runtime)) => {
            runtime.spawn(async move {
                match run_client(config, handler.as_ref(), cancellation).await {
                    Ok(()) => handler.emit(Event::Closed),
                    Err(error) => handler.emit(Event::Failed {
                        message: format!("{error:#}"),
                    }),
                }
            });
        }
        (Err(error), _) => handler.emit(Event::Failed {
            message: format!("{error:#}"),
        }),
        (_, Err(error)) => handler.emit(Event::Failed {
            message: format!("{error:#}"),
        }),
    }
    Box::into_raw(client)
}

/// Returns the latest changed JSON state or NULL. Free it with `sshportal_string_free`.
///
/// # Safety
/// `client` must be a live handle. Calls on one handle must be serialized by the UI thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sshportal_client_poll(client: *mut NativeClient) -> *mut c_char {
    let client = unsafe { &mut *client };
    if !matches!(client.events.has_changed(), Ok(true)) {
        return ptr::null_mut();
    }
    let event = client.events.borrow_and_update();
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
/// `client` must be a live handle owned by the calling UI thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sshportal_client_approve(client: *mut NativeClient, allowed: bool) {
    let client = unsafe { &*client };
    if let Some(sender) = client
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
/// `client` must be a live handle, freed exactly once, with no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sshportal_client_free(client: *mut NativeClient) {
    if !client.is_null() {
        drop(unsafe { Box::from_raw(client) });
    }
}

/// Releases a JSON event returned by `sshportal_client_poll`.
///
/// # Safety
/// `string` must be NULL or an event pointer from this library, freed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sshportal_string_free(string: *mut c_char) {
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
                server: input.to_string(),
                device_name: "iPhone".to_string(),
                reconnect: false,
            }
            .into_client()
            .unwrap();
            assert_eq!(config.server.scheme(), scheme);
            assert_eq!(config.server.query(), Some("token=test"));
        }
    }

    #[test]
    fn native_client_refuses_shell_offers() {
        let (events, _) = watch::channel(None);
        let handler = NativeHandler {
            events,
            decision: Mutex::new(None),
            unencrypted: std::sync::atomic::AtomicBool::new(false),
        };
        assert!(
            handler
                .refusal(&OfferedSession::Ssh {
                    ssh_public_key: String::new(),
                    persist_key_requested: false,
                })
                .is_some()
        );
        assert!(handler.refusal(&OfferedSession::Socks {}).is_none());
    }

    #[tokio::test]
    async fn consent_decision_is_owned_by_the_session() {
        let (events, mut receiver) = watch::channel(None);
        let handler = Arc::new(NativeHandler {
            events,
            decision: Mutex::new(None),
            unencrypted: std::sync::atomic::AtomicBool::new(false),
        });
        let pending = tokio::spawn({
            let handler = handler.clone();
            async move {
                handler
                    .approve(&ServerOffer {
                        protocol_version: sshportal::PROTOCOL_VERSION,
                        reconnect: None,
                        operator_name: "Support".to_string(),
                        session: OfferedSession::Socks {},
                    })
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(matches!(
            receiver.borrow_and_update().as_ref().unwrap(),
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
        use sshportal::{
            ControlPacket, PROTOCOL_VERSION, SystemVpnPolicy, VpnScope, recv_packet,
            run_operator_socks_proxy, send_packet,
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
                ControlPacket::ClientHello(_)
            ));
            send_packet(
                &mut websocket,
                &ControlPacket::ServerOffer(ServerOffer {
                    protocol_version: PROTOCOL_VERSION,
                    operator_name: "WS test".to_string(),
                    reconnect: None,
                    session: OfferedSession::Vpn {
                        scope: VpnScope::System {
                            policy: SystemVpnPolicy::full_tunnel(),
                        },
                    },
                }),
            )
            .await
            .unwrap();
            let ControlPacket::ClientDecision(decision) =
                recv_packet(&mut websocket).await.unwrap()
            else {
                panic!("expected consent decision")
            };
            assert!(decision.session_allowed);
            send_packet(&mut websocket, &ControlPacket::SessionReady {})
                .await
                .unwrap();
            run_operator_socks_proxy(websocket, proxy).await
        });
        let configuration = CString::new(format!(
            r#"{{"server":"ws://{address}","device_name":"iPhone","reconnect":false}}"#
        ))
        .unwrap();
        let client = unsafe { sshportal_client_create(configuration.as_ptr()) };
        struct ClientGuard(*mut NativeClient);
        impl Drop for ClientGuard {
            fn drop(&mut self) {
                unsafe {
                    sshportal_client_free(self.0);
                }
            }
        }
        let _guard = ClientGuard(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let pointer = unsafe { sshportal_client_poll(client) };
                if !pointer.is_null() {
                    let event = unsafe { CStr::from_ptr(pointer) }
                        .to_str()
                        .unwrap()
                        .to_owned();
                    unsafe {
                        sshportal_string_free(pointer);
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
            sshportal_client_approve(client, true);
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
