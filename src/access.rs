use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Result, bail};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::network::{run_network_epoch, run_socks_listener, start_consumer_network_session};
use crate::{
    AccessDecision, AccessRequest, ApprovedSession, Capability, ConsumerKeyMaterial, ConsumerSsh,
    ConsumerVpn, NetworkPolicy, PROTOCOL_VERSION, PeerConnection, PeerEvent, PeerHandler,
    websocket_to_io,
};

pub enum AccessMode {
    Ssh {
        key: ConsumerKeyMaterial,
        listen: SocketAddr,
        dynamic_forward: Option<SocketAddr>,
    },
    Socks {
        listen: SocketAddr,
        policy: NetworkPolicy,
    },
    Vpn {
        policy: NetworkPolicy,
    },
}

enum Frontend {
    Ssh {
        key: ConsumerKeyMaterial,
        proxy: ConsumerSsh,
    },
    Socks(Arc<TcpListener>),
    Vpn(Option<ConsumerVpn>),
}

pub struct Consumer {
    request: AccessRequest,
    frontend: Frontend,
}

impl Consumer {
    pub async fn bind(name: String, mode: AccessMode) -> Result<Self> {
        let (session, frontend) = match mode {
            AccessMode::Ssh {
                key,
                listen,
                dynamic_forward,
            } => {
                let session = Capability::Ssh {
                    ssh_public_key: key.public_key_openssh().to_string(),
                    persist_key_requested: key.persistent(),
                };
                let proxy = ConsumerSsh::bind(listen, dynamic_forward).await?;
                (session, Frontend::Ssh { key, proxy })
            }
            AccessMode::Socks { listen, policy } => {
                let listener = Arc::new(TcpListener::bind(listen).await?);
                println!("SOCKS5 proxy requested on {}", listener.local_addr()?);
                (Capability::Network { policy }, Frontend::Socks(listener))
            }
            AccessMode::Vpn { policy } => {
                let session = Capability::Network {
                    policy: policy.clone(),
                };
                (session, Frontend::Vpn(None))
            }
        };
        Ok(Self {
            request: AccessRequest {
                protocol_version: PROTOCOL_VERSION,
                consumer_name: name,
                capability: session,
                forwarding: false,
            },
            frontend,
        })
    }
}

impl PeerHandler for Consumer {
    fn request(&self) -> Option<AccessRequest> {
        Some(self.request.clone())
    }
    fn event(&self, event: PeerEvent) {
        crate::terminal::print_peer_event(event);
    }
    async fn approve(&self, _request: &AccessRequest) -> Result<AccessDecision> {
        bail!("consumers do not grant provider access");
    }
    async fn serve(
        &mut self,
        connection: PeerConnection,
        session: ApprovedSession,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let PeerConnection {
            websocket,
            local_address,
            peer_address,
            admission: _admission,
            ..
        } = connection;
        if let Frontend::Ssh { key, proxy } = &mut self.frontend {
            return tokio::select! {
                _ = shutdown.cancelled() => Ok(()),
                result = proxy.run(websocket_to_io(websocket), &session.peer.username, Arc::clone(key.private_key())) => result,
            };
        }
        let Capability::Network { policy } = session.request.capability else {
            bail!("network frontend requires network access");
        };
        let (network, runtime) = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            result = start_consumer_network_session(websocket) => result?,
        };
        run_network_epoch(network, runtime, shutdown, |network, epoch| async move {
            match &mut self.frontend {
                Frontend::Vpn(vpn) => {
                    vpn.get_or_insert_with(|| ConsumerVpn::new(policy))
                        .run(network, local_address, peer_address, epoch)
                        .await
                }
                Frontend::Socks(listener) => {
                    run_socks_listener(network, Arc::clone(listener), epoch).await
                }
                Frontend::Ssh { .. } => unreachable!("SSH owns its own transport protocol"),
            }
        })
        .await
    }
}
