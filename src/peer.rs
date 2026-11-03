use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;

use crate::endpoint::Endpoint;
use crate::{
    AccessDecision, AccessRequest, Capability, ControlPacket, EndpointConfig, PROTOCOL_VERSION,
    PeerConnection, PeerHello, PeerMetadata, PeerRole, ReconnectHello, ReconnectSecret,
    ReconnectSettings, ReconnectWindow, is_connection_loss, recv_packet, send_packet,
};

/// Configuration for a capability endpoint, independent of connection direction.
#[derive(Clone)]
pub struct PeerConfig {
    pub endpoint: EndpointConfig,
    pub metadata: PeerMetadata,
    pub node_id: String,
    pub reconnect: Option<ReconnectSettings>,
    pub handshake_timeout: Duration,
}

#[derive(Clone, Debug)]
pub enum PeerEvent {
    Listening {
        address: std::net::SocketAddr,
        join_url: String,
    },
    Connecting,
    Connected,
    Reconnecting,
    UnencryptedTransport,
    ConnectionLost(String),
    AttemptFailed(String),
}

#[derive(Clone)]
pub struct ApprovedSession {
    pub peer: PeerMetadata,
    pub route: Vec<String>,
    pub request: AccessRequest,
}

/// Supplies capability execution and local approval; the peer runtime owns the session lifecycle.
pub trait PeerHandler: Send + Sync {
    fn request(&self) -> Option<AccessRequest>;
    fn network_policy(&self) -> Option<crate::NetworkPolicy> {
        None
    }
    fn route(&self) -> Vec<String> {
        Vec::new()
    }
    fn event(&self, event: PeerEvent);
    fn refusal(&self, _request: &AccessRequest) -> Option<String> {
        None
    }
    fn approve(
        &self,
        request: &AccessRequest,
    ) -> impl Future<Output = Result<AccessDecision>> + Send;
    fn serve(
        &mut self,
        connection: PeerConnection,
        session: ApprovedSession,
        shutdown: CancellationToken,
    ) -> impl Future<Output = Result<()>>;
}

#[derive(Clone)]
pub(crate) struct Approval {
    peer: PeerHello,
    request: AccessRequest,
    decision: AccessDecision,
    granted_at: tokio::time::Instant,
}

pub async fn run_peer<H: PeerHandler>(
    config: PeerConfig,
    handler: &mut H,
    shutdown: CancellationToken,
) -> Result<()> {
    crate::install_default_rustls_crypto_provider();
    if let Some(settings) = config.reconnect {
        settings.validate()?;
    }
    if config.handshake_timeout.is_zero() {
        bail!("handshake timeout must not be zero");
    }
    let mut endpoint = Endpoint::bind(config.endpoint.clone()).await?;
    notify_listener(&endpoint, &config, handler);
    let result = run_sessions(&config, handler, &mut endpoint, shutdown).await;
    crate::shutdown::combine_results(
        result,
        endpoint.shutdown().await,
        "rendezvous cleanup also failed",
    )
}

async fn run_sessions<H: PeerHandler>(
    config: &PeerConfig,
    handler: &mut H,
    endpoint: &mut Endpoint,
    shutdown: CancellationToken,
) -> Result<()> {
    let role = if handler.request().is_some() {
        PeerRole::Consumer
    } else {
        PeerRole::Provider
    };
    let mut hello = PeerHello {
        network_policy: handler.network_policy(),
        role,
        node_id: config.node_id.clone(),
        route: if role == PeerRole::Provider {
            std::iter::once(config.node_id.clone())
                .chain(handler.route())
                .collect()
        } else {
            Vec::new()
        },
        protocol_version: PROTOCOL_VERSION,
        metadata: config.metadata.clone(),
        reconnect: config.reconnect.map(|settings| ReconnectHello {
            identity: ReconnectSecret::generate(),
            peer_identity: None,
            settings,
        }),
    };
    let mut approval = None;
    let mut window: Option<ReconnectWindow> = None;
    loop {
        handler.event(PeerEvent::Connecting);
        let attempt = async {
            let mut connection = endpoint.next().await?;
            if !connection.encrypted {
                handler.event(PeerEvent::UnencryptedTransport);
            }
            let negotiation = tokio::time::timeout(
                config.handshake_timeout,
                negotiate(&mut connection, handler, &mut hello, &mut approval),
            )
            .await
            .context("peer handshake timed out")
            .and_then(|result| result);
            let (session, settings) = match negotiation {
                Ok(session) => session,
                Err(error) => {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        send_packet(
                            &mut connection.websocket,
                            &ControlPacket::SessionRejected {
                                reason: error.to_string(),
                            },
                        ),
                    )
                    .await;
                    return Err(error);
                }
            };
            Ok::<_, anyhow::Error>((connection, session, settings))
        };
        let established = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            result = async {
                match &window {
                    Some(window) => tokio::time::timeout_at(window.deadline, attempt).await.context("automatic reconnection window expired")?,
                    None => attempt.await,
                }
            } => result,
        };
        match established {
            Ok((connection, session, settings)) => {
                handler.event(PeerEvent::Connected);
                // The connection owns listener admission until capability execution and cleanup finish.
                let result = handler.serve(connection, session, shutdown.clone()).await;
                if shutdown.is_cancelled() {
                    return result;
                }
                let Some(settings) = settings else {
                    return result;
                };
                if let Err(error) = &result {
                    if !is_connection_loss(error) {
                        return result;
                    }
                    handler.event(PeerEvent::ConnectionLost(format!("{error:#}")));
                }
                window = Some(ReconnectWindow::new(settings));
            }
            Err(error) => {
                handler.event(PeerEvent::AttemptFailed(format!("{error:#}")));
                if window
                    .as_ref()
                    .is_some_and(|window| tokio::time::Instant::now() >= window.deadline)
                {
                    return Err(error);
                }
                if endpoint.is_listener() {
                    if let Some(settings) = negotiated_settings(
                        &hello,
                        approval.as_ref().map(|approval: &Approval| &approval.peer),
                    )? {
                        window.get_or_insert_with(|| ReconnectWindow::new(settings));
                    }
                    continue;
                }
                let Some(settings) = config.reconnect else {
                    return Err(error);
                };
                if !is_connection_loss(&error) {
                    return Err(error);
                }
                window.get_or_insert_with(|| ReconnectWindow::new(settings));
            }
        }
        handler.event(PeerEvent::Reconnecting);
        if endpoint.is_listener() {
            continue;
        }
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            result = window.as_ref().expect("recovery has a deadline").wait() => result?,
        }
    }
}

fn negotiated_settings(
    hello: &PeerHello,
    peer: Option<&PeerHello>,
) -> Result<Option<ReconnectSettings>> {
    match (
        hello.reconnect.as_ref(),
        peer.and_then(|peer| peer.reconnect.as_ref()),
    ) {
        (Some(local), Some(remote)) => Ok(Some(local.settings.negotiate(remote.settings)?)),
        _ => Ok(None),
    }
}

async fn negotiate<H: PeerHandler>(
    connection: &mut PeerConnection,
    handler: &H,
    hello: &mut PeerHello,
    approval: &mut Option<Approval>,
) -> Result<(ApprovedSession, Option<ReconnectSettings>)> {
    let socket = &mut connection.websocket;
    send_packet(socket, &ControlPacket::PeerHello(Box::new(hello.clone()))).await?;
    let peer = match receive_control(socket).await? {
        ControlPacket::PeerHello(peer) => *peer,
        _ => bail!("expected peer hello"),
    };
    negotiate_received(connection, handler, hello, approval, peer).await
}

async fn negotiate_received<H: PeerHandler>(
    connection: &mut PeerConnection,
    handler: &H,
    hello: &mut PeerHello,
    approval: &mut Option<Approval>,
    peer: PeerHello,
) -> Result<(ApprovedSession, Option<ReconnectSettings>)> {
    let socket = &mut connection.websocket;
    if peer.role == hello.role {
        bail!("a session requires one provider and one consumer");
    }
    if peer.route.contains(&hello.node_id) {
        bail!("provider route would create a forwarding loop");
    }
    if let Some(approved) = approval.as_ref() {
        validate_resumed_peer(&approved.peer, &peer)?;
    }
    if let Some(expected) = hello
        .reconnect
        .as_ref()
        .and_then(|local| local.peer_identity.as_ref())
        && peer.reconnect.as_ref().map(|remote| &remote.identity) != Some(expected)
    {
        bail!("peer process identity changed; fresh approval is required");
    }
    if let Some(expected) = peer
        .reconnect
        .as_ref()
        .and_then(|remote| remote.peer_identity.as_ref())
        && hello.reconnect.as_ref().map(|local| &local.identity) != Some(expected)
    {
        bail!("resume credentials do not identify the approved peer");
    }
    let settings = negotiated_settings(hello, Some(&peer))?;
    let (request, decision) = match hello.role {
        PeerRole::Consumer => {
            let request = constrain_request(
                handler
                    .request()
                    .context("consumer has no access request")?,
                peer.network_policy.as_ref(),
            )?;
            send_packet(socket, &ControlPacket::AccessRequest(request.clone())).await?;
            let decision = match receive_control(socket).await? {
                ControlPacket::AccessDecision(decision) => decision,
                _ => bail!("expected access decision"),
            };
            (request, decision)
        }
        PeerRole::Provider => {
            let request = match receive_control(socket).await? {
                ControlPacket::AccessRequest(request) => request,
                _ => bail!("expected access request"),
            };
            if constrain_request(request.clone(), hello.network_policy.as_ref())? != request {
                bail!("requested network scope exceeds provider availability");
            }
            let decision = match approval.as_ref() {
                Some(approved) => {
                    if request != approved.request {
                        bail!("requested capability changed; fresh approval is required");
                    }
                    approved.decision.clone()
                }
                None => match handler.refusal(&request) {
                    Some(note) => AccessDecision {
                        session_allowed: false,
                        key_installed: false,
                        note: Some(note),
                    },
                    None => handler.approve(&request).await?,
                },
            };
            if decision.session_allowed && settings.is_some() {
                *approval = Some(Approval {
                    peer: peer.clone(),
                    request: request.clone(),
                    decision: decision.clone(),
                    granted_at: tokio::time::Instant::now(),
                });
            }
            send_packet(socket, &ControlPacket::AccessDecision(decision.clone())).await?;
            (request, decision)
        }
    };
    if !decision.session_allowed {
        bail!(
            "access declined: {}",
            decision.note.as_deref().unwrap_or("local user declined")
        );
    }
    if let (Some(local), Some(remote)) = (&mut hello.reconnect, &peer.reconnect) {
        local.peer_identity = Some(remote.identity.clone());
    }
    if settings.is_some() && approval.is_none() {
        *approval = Some(Approval {
            peer: peer.clone(),
            request: request.clone(),
            decision,
            granted_at: tokio::time::Instant::now(),
        });
    }
    match hello.role {
        PeerRole::Consumer => send_packet(socket, &ControlPacket::SessionReady {}).await?,
        PeerRole::Provider => {
            if !matches!(
                receive_control(socket).await?,
                ControlPacket::SessionReady {}
            ) {
                bail!("expected session readiness");
            }
        }
    }
    Ok((
        ApprovedSession {
            peer: peer.metadata,
            route: peer.route,
            request,
        },
        settings,
    ))
}

fn validate_resumed_peer(approved: &PeerHello, received: &PeerHello) -> Result<()> {
    let previous = approved
        .reconnect
        .as_ref()
        .context("approved session has no recovery identity")?;
    let current = received
        .reconnect
        .as_ref()
        .context("resume credentials are missing")?;
    if approved.role != received.role
        || approved.node_id != received.node_id
        || approved.route != received.route
        || approved.network_policy != received.network_policy
        || approved.metadata != received.metadata
        || previous.identity != current.identity
        || previous.settings != current.settings
    {
        bail!("resume credentials do not identify the approved peer and capability");
    }
    Ok(())
}

pub fn session_consent_prompt(consumer_name: &str, capability: &Capability) -> String {
    match capability {
        Capability::Ssh { .. } => format!(
            "Allow {consumer_name} to open SSH support sessions into this environment while this connection remains open?"
        ),
        Capability::Network { policy } => format!(
            "Allow {consumer_name} to {} while this connection remains open?",
            describe_network_access(policy)
        ),
    }
}

fn describe_network_access(policy: &crate::NetworkPolicy) -> String {
    if policy.is_unrestricted() {
        return "open TCP connections, send UDP datagrams, and resolve destination names through this environment"
            .to_string();
    }

    let mut selectors = Vec::new();
    if !policy.include_cidrs().is_empty() {
        selectors.push(format!(
            "IP ranges [{}]",
            policy
                .include_cidrs()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !policy.include_domains().is_empty() {
        selectors.push(format!(
            "domain suffixes [{}], including their apexes and all subdomains",
            policy.include_domains().join(", ")
        ));
    }
    format!(
        "route only the consumer's TCP and UDP traffic for {} through this environment",
        selectors.join(" and ")
    )
}

async fn receive_control(socket: &mut crate::PeerWebSocket) -> Result<ControlPacket> {
    match recv_packet(socket).await? {
        ControlPacket::SessionRejected { reason } => bail!("peer rejected access: {reason}"),
        packet => Ok(packet),
    }
}

#[derive(Default)]
pub(crate) struct ProviderRegistry {
    peers: std::collections::HashMap<String, RetainedPeer>,
}

struct RetainedPeer {
    approval: Option<Approval>,
    active: bool,
    expires: tokio::time::Instant,
}

type SharedRegistry = std::sync::Arc<std::sync::Mutex<ProviderRegistry>>;

struct PeerLease {
    registry: SharedRegistry,
    node_id: String,
    approval: Option<Approval>,
    settings: Option<ReconnectSettings>,
    recovery_deadline: Option<tokio::time::Instant>,
    established: bool,
}

impl Drop for PeerLease {
    fn drop(&mut self) {
        let mut registry = self.registry.lock().expect("provider registry poisoned");
        match (self.approval.take(), self.settings) {
            (Some(approval), Some(settings)) => {
                let expires = if self.established {
                    tokio::time::Instant::now() + Duration::from_secs(settings.timeout_seconds)
                } else {
                    self.recovery_deadline.unwrap_or(
                        approval.granted_at + Duration::from_secs(settings.timeout_seconds),
                    )
                };
                registry.peers.insert(
                    self.node_id.clone(),
                    RetainedPeer {
                        approval: Some(approval),
                        active: false,
                        expires,
                    },
                );
            }
            _ => {
                registry.peers.remove(&self.node_id);
            }
        }
    }
}

/// Serves independent downstream peers over one listener and one shared approved egress.
pub(crate) async fn serve_providers<H: PeerHandler + Clone + 'static>(
    config: &PeerConfig,
    endpoint: &mut Endpoint,
    handler: H,
    registry: SharedRegistry,
    identity: ReconnectSecret,
    shutdown: CancellationToken,
) -> Result<()> {
    tokio::task::LocalSet::new()
        .run_until(serve_provider_connections(
            config, endpoint, handler, registry, identity, shutdown,
        ))
        .await
}

async fn serve_provider_connections<H: PeerHandler + Clone + 'static>(
    config: &PeerConfig,
    endpoint: &mut Endpoint,
    handler: H,
    registry: SharedRegistry,
    identity: ReconnectSecret,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut peers = tokio::task::JoinSet::new();
    let result = 'serving: loop {
        while let Some(completed) = peers.try_join_next() {
            if let Err(error) = completed {
                break 'serving Err(error).context("downstream task failed to join");
            }
        }
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break Ok(()),
            connection = endpoint.next() => {
                let connection = match connection { Ok(connection) => connection, Err(error) => break Err(error) };
                let config = config.clone();
                let mut handler = handler.clone();
                let registry = registry.clone();
                let identity = identity.clone();
                let shutdown = shutdown.clone();
                peers.spawn_local(async move {
                    let result = serve_downstream(&config, connection, &mut handler, registry, identity, shutdown).await;
                    if let Err(error) = result { eprintln!("downstream session ended: {error:#}"); }
                });
            }
            completed = peers.join_next(), if !peers.is_empty() => {
                if let Some(Err(error)) = completed { break Err(error).context("downstream task failed to join"); }
            }
        }
    };
    // Each capability sees cancellation and finishes its cleanup before the upstream epoch ends.
    shutdown.cancel();
    while peers.join_next().await.is_some() {}
    result
}

async fn serve_downstream<H: PeerHandler>(
    config: &PeerConfig,
    mut connection: PeerConnection,
    handler: &mut H,
    registry: SharedRegistry,
    identity: ReconnectSecret,
    shutdown: CancellationToken,
) -> Result<()> {
    if !connection.encrypted {
        handler.event(PeerEvent::UnencryptedTransport);
    }
    let mut lease = None;
    let operation = async {
        let mut hello = PeerHello {
            network_policy: handler.network_policy(),
            role: PeerRole::Provider,
            node_id: config.node_id.clone(),
            route: std::iter::once(config.node_id.clone())
                .chain(handler.route())
                .collect(),
            metadata: config.metadata.clone(),
            protocol_version: PROTOCOL_VERSION,
            reconnect: config.reconnect.map(|settings| ReconnectHello {
                identity,
                peer_identity: None,
                settings,
            }),
        };
        send_packet(
            &mut connection.websocket,
            &ControlPacket::PeerHello(Box::new(hello.clone())),
        )
        .await?;
        let peer = match receive_control(&mut connection.websocket).await? {
            ControlPacket::PeerHello(peer) => *peer,
            _ => bail!("expected peer hello"),
        };
        let settings = negotiated_settings(&hello, Some(&peer))?;
        let (approval, recovery_deadline) = {
            let mut state = registry.lock().expect("provider registry poisoned");
            state
                .peers
                .retain(|_, entry| entry.active || entry.expires > tokio::time::Instant::now());
            if let Some(entry) = state.peers.get(&peer.node_id) {
                if entry.active {
                    bail!("peer already owns an active session");
                }
                if let Some(approval) = &entry.approval {
                    validate_resumed_peer(&approval.peer, &peer)?;
                }
            } else if state.peers.len() >= 128 {
                bail!("provider approval capacity reached");
            }
            let retained = state.peers.remove(&peer.node_id);
            let recovery_deadline = retained.as_ref().map(|entry| entry.expires);
            let approval = retained.and_then(|entry| entry.approval);
            state.peers.insert(
                peer.node_id.clone(),
                RetainedPeer {
                    approval: approval.clone(),
                    active: true,
                    expires: tokio::time::Instant::now(),
                },
            );
            (approval, recovery_deadline)
        };
        let claimed = lease.insert(PeerLease {
            registry,
            node_id: peer.node_id.clone(),
            approval,
            settings,
            recovery_deadline,
            established: false,
        });
        negotiate_received(
            &mut connection,
            handler,
            &mut hello,
            &mut claimed.approval,
            peer,
        )
        .await
    };
    let negotiation = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return Ok(()),
        result = tokio::time::timeout(config.handshake_timeout, operation) => result.context("downstream handshake timed out").and_then(|result| result),
    };
    let (session, _) = match negotiation {
        Ok(session) => session,
        Err(error) => {
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                send_packet(
                    &mut connection.websocket,
                    &ControlPacket::SessionRejected {
                        reason: error.to_string(),
                    },
                ),
            )
            .await;
            return Err(error);
        }
    };
    if let Some(lease) = lease.as_mut() {
        lease.established = true;
    }
    handler.event(PeerEvent::Connected);
    let result = handler.serve(connection, session, shutdown).await;
    if result
        .as_ref()
        .is_err_and(|error| !is_connection_loss(error))
        && let Some(lease) = lease.as_mut()
    {
        lease.approval = None;
    }
    result
}

/// Hosts independent approved sessions when listening, or one recoverable session when dialing.
pub async fn run_provider<H: PeerHandler + Clone + 'static>(
    config: PeerConfig,
    mut handler: H,
    shutdown: CancellationToken,
) -> Result<()> {
    if handler.request().is_some() {
        bail!("provider handler must not request consumer access");
    }
    if !matches!(config.endpoint, EndpointConfig::Listen { .. }) {
        return run_peer(config, &mut handler, shutdown).await;
    }
    crate::install_default_rustls_crypto_provider();
    if let Some(settings) = config.reconnect {
        settings.validate()?;
    }
    if config.handshake_timeout.is_zero() {
        bail!("handshake timeout must not be zero");
    }
    let mut endpoint = Endpoint::bind_with_capacity(config.endpoint.clone(), 32).await?;
    notify_listener(&endpoint, &config, &handler);
    let registry = std::sync::Arc::new(std::sync::Mutex::new(ProviderRegistry::default()));
    let result = serve_providers(
        &config,
        &mut endpoint,
        handler,
        registry,
        ReconnectSecret::generate(),
        shutdown,
    )
    .await;
    crate::shutdown::combine_results(
        result,
        endpoint.shutdown().await,
        "rendezvous cleanup also failed",
    )
}

fn constrain_request(
    mut request: AccessRequest,
    available: Option<&crate::NetworkPolicy>,
) -> Result<AccessRequest> {
    if let Capability::Network { policy } = &mut request.capability {
        if let Some(available) = available {
            *policy = policy.intersection(available);
        }
        if policy.is_empty() {
            bail!("requested and available networks have no shared destinations");
        }
    }
    Ok(request)
}

pub(crate) fn notify_listener<H: PeerHandler>(
    endpoint: &Endpoint,
    config: &PeerConfig,
    handler: &H,
) {
    if let (Some(address), EndpointConfig::Listen { join_token, .. }) =
        (endpoint.bound_address(), &config.endpoint)
    {
        handler.event(PeerEvent::Listening {
            address,
            join_url: crate::websocket_endpoint(address, join_token),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> PeerHello {
        PeerHello {
            role: PeerRole::Consumer,
            network_policy: None,
            node_id: crate::generate_join_token(),
            route: Vec::new(),
            protocol_version: PROTOCOL_VERSION,
            reconnect: Some(ReconnectHello {
                identity: ReconnectSecret::generate(),
                peer_identity: None,
                settings: ReconnectSettings {
                    interval_seconds: 1,
                    timeout_seconds: 20,
                },
            }),
            metadata: PeerMetadata {
                hostname: "host".to_string(),
                username: "user".to_string(),
                working_directory: "/".to_string(),
                platform: crate::Platform::current().unwrap(),
            },
        }
    }

    fn request(policy: crate::NetworkPolicy) -> AccessRequest {
        AccessRequest {
            protocol_version: PROTOCOL_VERSION,
            consumer_name: "consumer".to_string(),
            capability: Capability::Network { policy },
            forwarding: false,
        }
    }

    #[test]
    fn negotiated_scope_intersects_upstream_availability_and_rejects_disjoint_access() {
        let available = crate::NetworkPolicy::new(
            vec!["10.20.0.0/16".parse().unwrap()],
            vec!["example.com".to_string()],
        )
        .unwrap();
        let negotiated = constrain_request(
            request(crate::NetworkPolicy::unrestricted()),
            Some(&available),
        )
        .unwrap();
        assert_eq!(
            negotiated.capability,
            Capability::Network {
                policy: available.clone()
            }
        );
        let disjoint =
            crate::NetworkPolicy::new(vec!["192.0.2.0/24".parse().unwrap()], Vec::new()).unwrap();
        assert!(
            constrain_request(request(disjoint), Some(&available))
                .unwrap_err()
                .to_string()
                .contains("no shared destinations")
        );
    }

    #[test]
    fn recovery_pins_process_environment_route_and_available_scope() {
        let approved = hello();
        validate_resumed_peer(&approved, &approved).unwrap();
        let mut changed = approved.clone();
        changed.reconnect.as_mut().unwrap().identity = ReconnectSecret::generate();
        assert!(validate_resumed_peer(&approved, &changed).is_err());
        changed = approved.clone();
        changed.metadata.working_directory = "/other".to_string();
        assert!(validate_resumed_peer(&approved, &changed).is_err());
        changed = approved.clone();
        changed.route.push(crate::generate_join_token());
        assert!(validate_resumed_peer(&approved, &changed).is_err());
        changed = approved.clone();
        changed.network_policy = Some(crate::NetworkPolicy::unrestricted());
        assert!(validate_resumed_peer(&approved, &changed).is_err());
    }

    #[test]
    fn rejected_recovery_does_not_extend_the_existing_approval_lease() {
        let peer = hello();
        let node_id = peer.node_id.clone();
        let settings = peer.reconnect.as_ref().unwrap().settings;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let registry = std::sync::Arc::new(std::sync::Mutex::new(ProviderRegistry::default()));
        let approval = Approval {
            peer,
            request: request(crate::NetworkPolicy::unrestricted()),
            decision: AccessDecision {
                session_allowed: true,
                key_installed: false,
                note: None,
            },
            granted_at: tokio::time::Instant::now(),
        };
        let lease = PeerLease {
            registry: registry.clone(),
            node_id: node_id.clone(),
            approval: Some(approval),
            settings: Some(settings),
            recovery_deadline: Some(deadline),
            established: false,
        };
        drop(lease);
        assert_eq!(registry.lock().unwrap().peers[&node_id].expires, deadline);
    }
}
