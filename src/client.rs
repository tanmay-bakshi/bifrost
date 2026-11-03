use std::future::Future;

use anyhow::{Context, Result, bail};
use rustls::pki_types::CertificateDer;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    ClientDecision, ClientHello, ClientMetadata, ClientWebSocketStream, ControlPacket,
    OfferedSession, PROTOCOL_VERSION, ReconnectHello, ReconnectSecret, ReconnectSettings,
    ReconnectWindow, ServerOffer, VpnScope, connect_async_with_env_proxy_and_extra_roots,
    install_default_rustls_crypto_provider, is_connection_loss, recv_packet, send_packet,
};

/// Connection settings shared by native and terminal clients.
pub struct ClientConfig {
    pub server: Url,
    pub metadata: ClientMetadata,
    pub extra_roots: Vec<CertificateDer<'static>>,
    pub reconnect: Option<ReconnectSettings>,
}

#[derive(Clone, Debug)]
pub enum ClientEvent {
    Connecting,
    Connected,
    Reconnecting,
    UnencryptedTransport,
    ConnectionLost(String),
    AttemptFailed(String),
}

/// Supplies host-specific consent and execution while the shared client owns negotiation.
pub trait ClientHandler: Sync {
    fn event(&self, event: ClientEvent);
    fn refusal(&self, session: &OfferedSession) -> Option<String>;
    fn approve(&self, offer: &ServerOffer) -> impl Future<Output = Result<ClientDecision>> + Send;
    fn serve(
        &self,
        websocket: ClientWebSocketStream,
        session: OfferedSession,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// Runs a client until cancellation, terminal failure, or a session without recovery ends.
pub async fn run_client<H: ClientHandler>(
    config: ClientConfig,
    handler: &H,
    shutdown: CancellationToken,
) -> Result<()> {
    install_default_rustls_crypto_provider();
    if let Some(settings) = config.reconnect {
        settings.validate()?;
    }
    let mut hello = ClientHello {
        protocol_version: PROTOCOL_VERSION,
        reconnect: config.reconnect.map(|settings| ReconnectHello {
            client_identity: ReconnectSecret::generate(),
            server_identity: None,
            settings,
        }),
        metadata: config.metadata.clone(),
    };
    let mut approval = None;
    let mut window: Option<ReconnectWindow> = None;
    loop {
        handler.event(ClientEvent::Connecting);
        let attempt = establish_client_connection(&config, handler, &mut hello, &mut approval);
        let connection = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            result = async {
                match &window {
                    Some(window) => tokio::time::timeout_at(window.deadline, attempt)
                        .await.context("automatic reconnection window expired")?,
                    None => attempt.await,
                }
            } => result,
        };
        match connection {
            Ok((websocket, offer)) => {
                handler.event(ClientEvent::Connected);
                let negotiated = offer.reconnect.as_ref().map(|offer| offer.settings);
                let session = handler.serve(websocket, offer.session);
                let result = tokio::select! {
                    _ = shutdown.cancelled() => return Ok(()),
                    result = session => result,
                };
                if negotiated.is_none() {
                    return result;
                }
                if let Err(error) = &result {
                    if !is_connection_loss(error) {
                        return result;
                    }
                    handler.event(ClientEvent::ConnectionLost(format!("{error:#}")));
                }
                window = negotiated.map(ReconnectWindow::new);
            }
            Err(error) => {
                if config.reconnect.is_none() || !is_connection_loss(&error) {
                    return Err(error);
                }
                handler.event(ClientEvent::AttemptFailed(format!("{error:#}")));
                let retry_settings = approval
                    .as_ref()
                    .and_then(|approved: &ClientApproval| approved.offer.reconnect.as_ref())
                    .map(|offer| offer.settings)
                    .or(config.reconnect)
                    .expect("reconnection is enabled");
                window.get_or_insert_with(|| ReconnectWindow::new(retry_settings));
            }
        }
        let retry = window.as_ref().expect("recovery owns a retry window");
        handler.event(ClientEvent::Reconnecting);
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            result = retry.wait() => result?,
        }
    }
}

struct ClientApproval {
    offer: ServerOffer,
    decision: ClientDecision,
}

fn validate_resumed_offer(approved: &ServerOffer, received: &ServerOffer) -> Result<()> {
    if approved != received {
        bail!(
            "server identity or approved capability changed; restart the client to approve a new session"
        );
    }
    Ok(())
}

async fn establish_client_connection<H: ClientHandler>(
    config: &ClientConfig,
    handler: &H,
    hello: &mut ClientHello,
    approval: &mut Option<ClientApproval>,
) -> Result<(ClientWebSocketStream, ServerOffer)> {
    let server_url = &config.server;
    let (mut websocket, _) =
        connect_async_with_env_proxy_and_extra_roots(server_url, config.extra_roots.clone())
            .await
            .context("failed to connect to sshportal server")?;
    send_packet(&mut websocket, &ControlPacket::ClientHello(hello.clone())).await?;
    let packet = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        recv_packet(&mut websocket),
    )
    .await
    .context("timed out waiting for the server offer")??;
    let offer = match packet {
        ControlPacket::ServerOffer(offer) => offer,
        ControlPacket::SessionRejected { reason } => {
            bail!("server rejected the connection: {reason}")
        }
        unexpected => bail!("expected server_offer packet, received {unexpected:?}"),
    };
    let decision = if let Some(approved) = approval {
        validate_resumed_offer(&approved.offer, &offer)?;
        approved.decision.clone()
    } else {
        if !matches!(offer.session, OfferedSession::Ssh { .. }) && server_url.scheme() == "ws" {
            handler.event(ClientEvent::UnencryptedTransport);
        }
        if let Some(note) = handler.refusal(&offer.session) {
            send_packet(
                &mut websocket,
                &ControlPacket::ClientDecision(ClientDecision {
                    session_allowed: false,
                    key_installed: false,
                    note: Some(note.clone()),
                }),
            )
            .await?;
            bail!("{note}");
        }
        if let Some(reconnect) = &offer.reconnect {
            let requested = hello
                .reconnect
                .as_mut()
                .context("server offered unrequested reconnection")?;
            let expected = requested.settings.negotiate(reconnect.settings)?;
            if expected != reconnect.settings
                || requested
                    .server_identity
                    .as_ref()
                    .is_some_and(|identity| *identity != reconnect.server_identity)
            {
                bail!("server returned an invalid reconnection offer");
            }
            requested.server_identity = Some(reconnect.server_identity.clone());
        }
        let decision = handler.approve(&offer).await?;
        if !decision.session_allowed {
            send_packet(&mut websocket, &ControlPacket::ClientDecision(decision)).await?;
            bail!("support session was declined locally");
        }
        // Consent is owned by the process, so loss of the ready acknowledgement cannot lose it.
        if offer.reconnect.is_some() {
            *approval = Some(ClientApproval {
                offer: offer.clone(),
                decision: decision.clone(),
            });
        }
        decision
    };
    send_packet(&mut websocket, &ControlPacket::ClientDecision(decision)).await?;
    let packet = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        recv_packet(&mut websocket),
    )
    .await
    .context("timed out waiting for session readiness")??;
    match packet {
        ControlPacket::SessionReady {} => Ok((websocket, offer)),
        ControlPacket::SessionRejected { reason } => bail!("server rejected the session: {reason}"),
        unexpected => bail!("expected session_ready packet, received {unexpected:?}"),
    }
}

pub fn session_consent_prompt(operator_name: &str, session: &OfferedSession) -> String {
    match session {
        OfferedSession::Ssh { .. } => format!(
            "Allow {operator_name} to open SSH support sessions into this environment while this connection remains open?"
        ),
        OfferedSession::Socks {} => format!(
            "Allow {operator_name} to route TCP connections and UDP datagrams through this environment using a SOCKS5 proxy while this connection remains open?"
        ),
        OfferedSession::Vpn {
            scope: VpnScope::System { policy },
        } => format!(
            "Allow {operator_name} to {} while this connection remains open?",
            describe_system_vpn(policy)
        ),
    }
}

fn describe_system_vpn(policy: &crate::SystemVpnPolicy) -> String {
    if policy.is_full_tunnel() {
        return "route the operator's system-wide internet-bound TCP, UDP, and DNS traffic through this environment"
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
        "route only the operator's TCP and UDP traffic for {} through this environment",
        selectors.join(" and ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReconnectOffer, SystemVpnPolicy};
    #[test]
    fn continued_consent_rejects_changed_server_identity_or_capability() {
        let approved = ServerOffer {
            protocol_version: PROTOCOL_VERSION,
            operator_name: "support".to_string(),
            session: OfferedSession::Socks {},
            reconnect: Some(ReconnectOffer {
                server_identity: ReconnectSecret::generate(),
                settings: ReconnectSettings {
                    interval_seconds: 5,
                    timeout_seconds: 300,
                },
            }),
        };
        validate_resumed_offer(&approved, &approved).unwrap();
        let mut changed = approved.clone();
        changed.operator_name = "someone-else".to_string();
        assert!(validate_resumed_offer(&approved, &changed).is_err());
        let mut changed = approved.clone();
        changed.reconnect.as_mut().unwrap().server_identity = ReconnectSecret::generate();
        assert!(validate_resumed_offer(&approved, &changed).is_err());
        let mut changed = approved.clone();
        changed.session = OfferedSession::Vpn {
            scope: VpnScope::System {
                policy: SystemVpnPolicy::full_tunnel(),
            },
        };
        assert!(validate_resumed_offer(&approved, &changed).is_err());
    }
}
