use std::sync::Arc;

use crate::network::resolver::NativeResolver;
use crate::network::resolver_protocol::{ResolveOutcome, ResolveRequest};
use crate::network::session::ConsumerNetworkSession;

/// The approved egress for a provider. Remote egress never falls back to local sockets or DNS.
pub(crate) enum NetworkBackend {
    Local(Arc<NativeResolver>),
    Upstream(ConsumerNetworkSession),
}

impl NetworkBackend {
    pub(crate) fn local() -> Arc<Self> {
        Arc::new(Self::Local(Arc::new(
            NativeResolver::from_system_configuration(),
        )))
    }

    pub(crate) async fn resolve(&self, request: &ResolveRequest) -> ResolveOutcome {
        match self {
            Self::Local(resolver) => resolver.resolve(request).await,
            Self::Upstream(session) => session
                .resolve(request.clone())
                .await
                .unwrap_or(ResolveOutcome::Failure { response_code: 2 }),
        }
    }
}

/// Runs approved network requests against one explicit egress.
#[derive(Clone)]
pub struct NetworkProvider {
    backend: Arc<NetworkBackend>,
}

impl NetworkProvider {
    pub fn local() -> Self {
        Self {
            backend: NetworkBackend::local(),
        }
    }

    pub(crate) fn upstream(session: ConsumerNetworkSession) -> Self {
        Self {
            backend: Arc::new(NetworkBackend::Upstream(session)),
        }
    }

    pub async fn run<S>(
        &self,
        websocket: tokio_tungstenite::WebSocketStream<S>,
        session: crate::Capability,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        crate::network::session::run_provider_network_session_with_backend(
            websocket,
            session,
            self.backend.clone(),
            std::time::Duration::from_secs(15),
            shutdown,
        )
        .await
    }
}
