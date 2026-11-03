use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};
use tokio_util::sync::CancellationToken;

use crate::endpoint::Endpoint;
use crate::network::{run_network_epoch, start_consumer_network_session};
use crate::peer::{ProviderRegistry, serve_providers};
use crate::{
    AccessDecision, AccessRequest, ApprovedSession, Capability, EndpointConfig, NetworkPolicy,
    NetworkProvider, PROTOCOL_VERSION, PeerConfig, PeerConnection, PeerEvent, PeerHandler,
    ReconnectSecret, TerminalProvider,
};

/// One approved upstream network shared with independently approved downstream peers.
pub struct Relay {
    request: AccessRequest,
    downstream: Endpoint,
    config: PeerConfig,
    consent: TerminalProvider,
    registry: Arc<Mutex<ProviderRegistry>>,
    identity: ReconnectSecret,
}

impl Relay {
    pub async fn bind(
        config: PeerConfig,
        name: String,
        policy: NetworkPolicy,
        consent: TerminalProvider,
    ) -> Result<Self> {
        if !matches!(config.endpoint, EndpointConfig::Listen { .. }) {
            bail!("a relay requires a downstream listener");
        }
        let downstream = Endpoint::bind_with_capacity(config.endpoint.clone(), 32).await?;
        crate::peer::notify_listener(&downstream, &config, &consent);
        Ok(Self {
            request: AccessRequest {
                protocol_version: PROTOCOL_VERSION,
                consumer_name: name,
                capability: Capability::Network { policy },
                forwarding: true,
            },
            downstream,
            config,
            consent,
            registry: Arc::new(Mutex::new(ProviderRegistry::default())),
            identity: ReconnectSecret::generate(),
        })
    }

    /// Runs upstream epochs and joins the downstream listener before returning.
    pub async fn run(mut self, upstream: PeerConfig, shutdown: CancellationToken) -> Result<()> {
        let result = crate::run_peer(upstream, &mut self, shutdown).await;
        crate::shutdown::combine_results(
            result,
            self.downstream.shutdown().await,
            "relay listener cleanup also failed",
        )
    }
}

impl PeerHandler for Relay {
    fn request(&self) -> Option<AccessRequest> {
        Some(self.request.clone())
    }
    fn event(&self, event: PeerEvent) {
        crate::terminal::print_peer_event(event);
    }
    async fn approve(&self, _request: &AccessRequest) -> Result<AccessDecision> {
        bail!("relay upstream is a consumer session");
    }
    async fn serve(
        &mut self,
        connection: PeerConnection,
        session: ApprovedSession,
        shutdown: CancellationToken,
    ) -> Result<()> {
        if session.route.len() >= 16 {
            bail!("Bifrost provider route exceeds the hop limit");
        }
        let (socket, lease) = connection.into_socket();
        let (upstream, runtime) = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            result = start_consumer_network_session(socket) => result?,
        };
        let consent = self.consent.clone();
        let route = session.route;
        let policy = match session.request.capability {
            crate::Capability::Network { policy } => policy,
            _ => bail!("relay requires network access"),
        };
        let registry = self.registry.clone();
        let identity = self.identity.clone();
        let result = run_network_epoch(upstream, runtime, shutdown, |upstream, epoch| {
            let provider = ForwardingProvider {
                backend: NetworkProvider::upstream(upstream),
                consent,
                route,
                policy,
            };
            serve_providers(
                &self.config,
                &mut self.downstream,
                provider,
                registry,
                identity,
                epoch,
            )
        })
        .await;
        drop(lease);
        result
    }
}

#[derive(Clone)]
struct ForwardingProvider {
    backend: NetworkProvider,
    consent: TerminalProvider,
    route: Vec<String>,
    policy: crate::NetworkPolicy,
}

impl PeerHandler for ForwardingProvider {
    fn request(&self) -> Option<AccessRequest> {
        None
    }
    fn network_policy(&self) -> Option<crate::NetworkPolicy> {
        Some(self.policy.clone())
    }
    fn route(&self) -> Vec<String> {
        self.route.clone()
    }
    fn event(&self, event: PeerEvent) {
        self.consent.event(event);
    }
    fn refusal(&self, request: &AccessRequest) -> Option<String> {
        matches!(request.capability, Capability::Ssh { .. }).then(|| {
            "this route provides network access; SSH shell access belongs to a specific host"
                .to_string()
        })
    }
    async fn approve(&self, request: &AccessRequest) -> Result<AccessDecision> {
        self.consent.approve(request).await
    }
    async fn serve(
        &mut self,
        connection: PeerConnection,
        session: ApprovedSession,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let (websocket, lease) = connection.into_socket();
        let result = self
            .backend
            .run(websocket, session.request.capability, shutdown)
            .await;
        drop(lease);
        result
    }
}
