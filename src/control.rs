use std::fmt;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

use crate::NetworkPolicy;
use crate::PROTOCOL_VERSION;
use crate::platform::Platform;
use crate::reconnect::ReconnectHello;

const MAX_DISPLAY_LABEL_BYTES: usize = 256;
const MAX_DECISION_NOTE_BYTES: usize = 2 * 1024;
const MAX_WEBSOCKET_CLOSE_REASON_BYTES: usize = 123;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerMetadata {
    pub hostname: String,
    pub username: String,
    pub working_directory: String,
    pub platform: Platform,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    Provider,
    Consumer,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerHello {
    pub network_policy: Option<NetworkPolicy>,
    pub role: PeerRole,
    pub node_id: String,
    pub route: Vec<String>,
    pub protocol_version: u32,
    pub reconnect: Option<ReconnectHello>,
    pub metadata: PeerMetadata,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRequest {
    pub protocol_version: u32,
    pub forwarding: bool,
    pub consumer_name: String,
    pub capability: Capability,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Capability {
    Ssh {
        ssh_public_key: String,
        persist_key_requested: bool,
    },
    Network {
        policy: NetworkPolicy,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessDecision {
    pub session_allowed: bool,
    pub key_installed: bool,
    pub note: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlPacket {
    PeerHello(Box<PeerHello>),
    AccessRequest(AccessRequest),
    AccessDecision(AccessDecision),
    SessionReady {},
    SessionRejected { reason: String },
}

impl fmt::Debug for ControlPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PeerHello(_) => "PeerHello",
            Self::AccessRequest(_) => "AccessRequest",
            Self::AccessDecision(_) => "AccessDecision",
            Self::SessionReady {} => "SessionReady",
            Self::SessionRejected { .. } => "SessionRejected",
        })
    }
}

impl ControlPacket {
    fn validate(&self) -> Result<()> {
        match self {
            Self::SessionReady {} => Ok(()),
            Self::SessionRejected { reason } => validate_terminal_text(
                "session rejection reason",
                reason,
                MAX_DECISION_NOTE_BYTES,
                true,
            ),
            Self::PeerHello(hello) => {
                validate_protocol_version(hello.protocol_version)?;
                validate_route(hello)?;
                if hello.role == PeerRole::Consumer && hello.network_policy.is_some() {
                    bail!("consumer cannot advertise provider availability");
                }
                if let Some(reconnect) = &hello.reconnect {
                    reconnect.settings.validate()?;
                }
                validate_terminal_text(
                    "peer username",
                    &hello.metadata.username,
                    MAX_DISPLAY_LABEL_BYTES,
                    true,
                )
            }
            Self::AccessRequest(offer) => {
                validate_protocol_version(offer.protocol_version)?;
                if let Capability::Network { policy } = &offer.capability
                    && policy.is_empty()
                {
                    bail!("requested network scope is empty");
                }
                if offer.forwarding && matches!(offer.capability, Capability::Ssh { .. }) {
                    bail!("SSH capability cannot grant network forwarding");
                }
                validate_terminal_text(
                    "access request consumer name",
                    &offer.consumer_name,
                    MAX_DISPLAY_LABEL_BYTES,
                    true,
                )
            }
            Self::AccessDecision(decision) => {
                if decision.key_installed && !decision.session_allowed {
                    bail!("denied access cannot report an installed consumer key");
                }
                if let Some(note) = &decision.note {
                    validate_terminal_text(
                        "client decision note",
                        note,
                        MAX_DECISION_NOTE_BYTES,
                        true,
                    )?;
                }
                Ok(())
            }
        }
    }
}

fn validate_route(hello: &PeerHello) -> Result<()> {
    let valid_id = |id: &str| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !valid_id(&hello.node_id)
        || hello.route.len() > 16
        || hello.route.iter().any(|id| !valid_id(id))
    {
        bail!("invalid peer route");
    }
    let mut seen = std::collections::HashSet::new();
    if hello.route.iter().any(|id| !seen.insert(id)) {
        bail!("peer route contains a loop");
    }
    match hello.role {
        PeerRole::Provider if hello.route.first() != Some(&hello.node_id) => {
            bail!("provider route does not begin at the peer")
        }
        PeerRole::Consumer if !hello.route.is_empty() => {
            bail!("consumer must not advertise a provider route")
        }
        _ => Ok(()),
    }
}

fn validate_terminal_text(
    field: &str,
    value: &str,
    maximum_bytes: usize,
    must_not_be_blank: bool,
) -> Result<()> {
    if value.len() > maximum_bytes {
        bail!("{field} exceeds {maximum_bytes} UTF-8 bytes");
    }
    if must_not_be_blank && value.trim().is_empty() {
        bail!("{field} must not be blank");
    }
    if value.chars().any(is_unsafe_terminal_character) {
        bail!("{field} contains a terminal control or bidirectional formatting character");
    }
    Ok(())
}

fn is_unsafe_terminal_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

pub async fn send_packet<S>(
    websocket: &mut WebSocketStream<S>,
    packet: &ControlPacket,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    packet.validate().context("invalid control packet")?;
    let bytes: Vec<u8> =
        serde_json::to_vec(packet).context("failed to serialize control packet")?;
    websocket
        .send(Message::Binary(bytes.into()))
        .await
        .context("failed to send control packet")?;
    Ok(())
}

pub async fn recv_packet<S>(websocket: &mut WebSocketStream<S>) -> Result<ControlPacket>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let next_message = websocket.next().await.ok_or_else(|| {
            anyhow::Error::new(tokio_tungstenite::tungstenite::Error::ConnectionClosed)
                .context("peer closed the websocket before completing the handshake")
        })?;
        match next_message.context("websocket read failed during handshake")? {
            Message::Binary(bytes) => {
                let packet: ControlPacket =
                    serde_json::from_slice(bytes.as_ref()).map_err(control_packet_decode_error)?;
                packet
                    .validate()
                    .context("received invalid control packet")?;
                return Ok(packet);
            }
            Message::Text(text) => {
                let packet: ControlPacket =
                    serde_json::from_str(text.as_ref()).map_err(control_packet_decode_error)?;
                packet
                    .validate()
                    .context("received invalid control packet")?;
                return Ok(packet);
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            Message::Close(frame) => {
                let Some(close_frame) = frame else {
                    return Err(anyhow::Error::new(
                        tokio_tungstenite::tungstenite::Error::ConnectionClosed,
                    )
                    .context("peer closed the websocket without a reason"));
                };
                let reason = close_frame.reason.as_ref();
                if validate_terminal_text(
                    "websocket close reason",
                    reason,
                    MAX_WEBSOCKET_CLOSE_REASON_BYTES,
                    false,
                )
                .is_err()
                {
                    bail!("peer closed the websocket with an unsafe reason");
                }
                return Err(anyhow::Error::new(
                    tokio_tungstenite::tungstenite::Error::ConnectionClosed,
                )
                .context(format!("peer closed the websocket: {reason}")));
            }
        }
    }
}

fn control_packet_decode_error(error: serde_json::Error) -> anyhow::Error {
    let detail = match error.classify() {
        serde_json::error::Category::Data => {
            "schema mismatch; ensure both peers use matching builds"
        }
        serde_json::error::Category::Syntax => "invalid JSON syntax",
        serde_json::error::Category::Eof => "incomplete JSON",
        serde_json::error::Category::Io => "JSON input could not be read",
    };
    anyhow!(
        "failed to decode control packet at line {} column {} ({detail})",
        error.line(),
        error.column()
    )
}

fn validate_protocol_version(version: u32) -> Result<()> {
    if version != PROTOCOL_VERSION {
        bail!("protocol version mismatch: local={PROTOCOL_VERSION} remote={version}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AccessDecision, AccessRequest, Capability, ControlPacket, MAX_DECISION_NOTE_BYTES,
        MAX_DISPLAY_LABEL_BYTES, PeerHello, PeerMetadata, recv_packet, send_packet,
    };
    use crate::NetworkPolicy;
    use crate::PROTOCOL_VERSION;
    use crate::platform::Platform;
    use futures_util::SinkExt;
    use tokio::io::{DuplexStream, duplex};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    async fn websocket_pair() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>) {
        let (left, right) = duplex(16 * 1024);
        tokio::join!(
            WebSocketStream::from_raw_socket(left, Role::Client, None),
            WebSocketStream::from_raw_socket(right, Role::Server, None),
        )
    }

    async fn round_trip(packet: &ControlPacket) -> ControlPacket {
        let (mut sender, mut receiver) = websocket_pair().await;
        let (send_result, receive_result) =
            tokio::join!(send_packet(&mut sender, packet), recv_packet(&mut receiver));
        send_result.unwrap();
        receive_result.unwrap()
    }

    fn network_request(consumer_name: &str) -> ControlPacket {
        ControlPacket::AccessRequest(AccessRequest {
            protocol_version: PROTOCOL_VERSION,
            forwarding: false,
            consumer_name: consumer_name.to_string(),
            capability: Capability::Network {
                policy: NetworkPolicy::default(),
            },
        })
    }

    #[test]
    fn network_request_carries_its_policy() {
        let packet = ControlPacket::AccessRequest(AccessRequest {
            protocol_version: PROTOCOL_VERSION,
            forwarding: false,
            consumer_name: "support".to_string(),
            capability: Capability::Network {
                policy: NetworkPolicy::default(),
            },
        });

        let encoded = serde_json::to_value(packet).unwrap();

        assert_eq!(encoded["type"], "access_request");
        assert_eq!(encoded["capability"]["kind"], "network");
        assert_eq!(encoded["capability"]["policy"]["kind"], "unrestricted");
    }

    #[test]
    fn unsupported_capabilities_are_rejected() {
        for kind in ["application", "unknown"] {
            let mut encoded = serde_json::to_value(network_request("consumer")).unwrap();
            encoded["capability"] = serde_json::json!({"kind": kind});
            let error = serde_json::from_value::<ControlPacket>(encoded).unwrap_err();
            assert!(error.to_string().contains("unknown variant"));
        }
    }

    #[tokio::test]
    async fn legitimate_unicode_display_text_round_trips() {
        let hello = ControlPacket::PeerHello(Box::new(PeerHello {
            network_policy: None,
            role: super::PeerRole::Provider,
            node_id: "11111111111111111111111111111111".to_string(),
            route: vec!["11111111111111111111111111111111".to_string()],
            protocol_version: PROTOCOL_VERSION,
            reconnect: None,
            metadata: PeerMetadata {
                hostname: "workstation".to_string(),
                username: "工程師".to_string(),
                working_directory: "/workspace".to_string(),
                platform: Platform::current().unwrap(),
            },
        }));
        let received_hello = round_trip(&hello).await;
        assert_eq!(
            serde_json::to_value(received_hello).unwrap(),
            serde_json::to_value(hello).unwrap()
        );

        let offer = network_request("فريق الدعم 火狐");
        let received_offer = round_trip(&offer).await;
        assert_eq!(
            serde_json::to_value(received_offer).unwrap(),
            serde_json::to_value(offer).unwrap()
        );

        let decision = ControlPacket::AccessDecision(AccessDecision {
            session_allowed: false,
            key_installed: false,
            note: Some("用户已拒绝该会话。".to_string()),
        });
        let received_decision = round_trip(&decision).await;
        assert_eq!(
            serde_json::to_value(received_decision).unwrap(),
            serde_json::to_value(decision).unwrap()
        );
    }

    #[test]
    fn display_labels_must_be_nonblank_and_bounded() {
        let blank_consumer = network_request("\u{2003}\u{2003}");
        assert!(
            blank_consumer
                .validate()
                .unwrap_err()
                .to_string()
                .contains("consumer name must not be blank")
        );

        let long_operator = "a".repeat(MAX_DISPLAY_LABEL_BYTES + 1);
        assert!(network_request(&long_operator).validate().is_err());

        let long_unicode_operator = "火".repeat(MAX_DISPLAY_LABEL_BYTES / 3 + 1);
        assert!(network_request(&long_unicode_operator).validate().is_err());
    }

    #[test]
    fn terminal_controls_and_bidirectional_formatting_are_rejected() {
        for unsafe_character in ['\n', '\u{1b}', '\u{2028}', '\u{202e}', '\u{2066}'] {
            let operator = format!("support{unsafe_character}spoof");
            assert!(network_request(&operator).validate().is_err());

            let decision = ControlPacket::AccessDecision(AccessDecision {
                session_allowed: false,
                key_installed: false,
                note: Some(format!("declined{unsafe_character}spoof")),
            });
            assert!(decision.validate().is_err());
        }
    }

    #[test]
    fn present_decision_notes_must_be_nonblank_and_bounded() {
        let blank = ControlPacket::AccessDecision(AccessDecision {
            session_allowed: false,
            key_installed: false,
            note: Some("  ".to_string()),
        });
        assert!(blank.validate().is_err());

        let long = ControlPacket::AccessDecision(AccessDecision {
            session_allowed: false,
            key_installed: false,
            note: Some("n".repeat(MAX_DECISION_NOTE_BYTES + 1)),
        });
        assert!(long.validate().is_err());
    }

    #[test]
    fn denied_decisions_cannot_report_an_installed_key() {
        let decision = ControlPacket::AccessDecision(AccessDecision {
            session_allowed: false,
            key_installed: true,
            note: Some("local user declined the support session".to_string()),
        });

        let error = decision.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("denied access cannot report an installed consumer key")
        );
    }

    #[test]
    fn hello_and_offer_versions_are_validated_at_the_packet_boundary() {
        let hello = ControlPacket::PeerHello(Box::new(PeerHello {
            network_policy: None,
            role: super::PeerRole::Provider,
            node_id: "11111111111111111111111111111111".to_string(),
            route: vec!["11111111111111111111111111111111".to_string()],
            protocol_version: PROTOCOL_VERSION + 1,
            reconnect: None,
            metadata: PeerMetadata {
                hostname: "workstation".to_string(),
                username: "engineer".to_string(),
                working_directory: "/workspace".to_string(),
                platform: Platform::current().unwrap(),
            },
        }));
        let offer = ControlPacket::AccessRequest(AccessRequest {
            protocol_version: PROTOCOL_VERSION + 1,
            forwarding: false,
            consumer_name: "support".to_string(),
            capability: Capability::Network {
                policy: crate::NetworkPolicy::unrestricted(),
            },
        });

        for packet in [hello, offer] {
            assert!(
                packet
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains("protocol version mismatch")
            );
        }
    }

    #[test]
    fn every_control_packet_layer_rejects_unknown_fields() {
        let hello = ControlPacket::PeerHello(Box::new(PeerHello {
            network_policy: None,
            role: super::PeerRole::Provider,
            node_id: "11111111111111111111111111111111".to_string(),
            route: vec!["11111111111111111111111111111111".to_string()],
            protocol_version: PROTOCOL_VERSION,
            metadata: PeerMetadata {
                hostname: "host".to_string(),
                username: "user".to_string(),
                working_directory: "/".to_string(),
                platform: Platform::current().unwrap(),
            },
            reconnect: Some(crate::ReconnectHello {
                identity: crate::ReconnectSecret::generate(),
                peer_identity: None,
                settings: crate::ReconnectSettings {
                    interval_seconds: 1,
                    timeout_seconds: 5,
                },
            }),
        }));
        for (packet, pointers) in [
            (
                hello,
                vec![
                    "",
                    "/metadata",
                    "/metadata/platform",
                    "/reconnect",
                    "/reconnect/settings",
                ],
            ),
            (
                network_request("consumer"),
                vec!["", "/capability", "/capability/policy"],
            ),
            (
                ControlPacket::AccessDecision(AccessDecision {
                    session_allowed: true,
                    key_installed: false,
                    note: None,
                }),
                vec![""],
            ),
        ] {
            let encoded = serde_json::to_value(packet).unwrap();
            assert!(serde_json::from_value::<ControlPacket>(encoded.clone()).is_ok());
            for pointer in pointers {
                let mut invalid = encoded.clone();
                invalid
                    .pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert("unexpected".to_string(), serde_json::json!(true));
                assert!(
                    serde_json::from_value::<ControlPacket>(invalid).is_err(),
                    "accepted unknown field at {pointer}"
                );
            }
        }
    }

    #[test]
    fn displayed_peer_username_must_be_nonblank_bounded_and_terminal_safe() {
        for username in [
            " ".to_string(),
            "user\nspoof".to_string(),
            "user\u{202e}spoof".to_string(),
            "u".repeat(MAX_DISPLAY_LABEL_BYTES + 1),
        ] {
            let packet = ControlPacket::PeerHello(Box::new(PeerHello {
                network_policy: None,
                role: super::PeerRole::Provider,
                node_id: "11111111111111111111111111111111".to_string(),
                route: vec!["11111111111111111111111111111111".to_string()],
                protocol_version: PROTOCOL_VERSION,
                reconnect: None,
                metadata: PeerMetadata {
                    hostname: "workstation".to_string(),
                    username,
                    working_directory: "/workspace".to_string(),
                    platform: Platform::current().unwrap(),
                },
            }));
            assert!(packet.validate().is_err());
        }
    }

    #[tokio::test]
    async fn send_packet_rejects_invalid_display_text_before_writing() {
        let (mut sender, _receiver) = websocket_pair().await;
        let packet = network_request("support\u{202e}hidden");

        let error = send_packet(&mut sender, &packet).await.unwrap_err();

        assert!(error.to_string().contains("invalid control packet"));
    }

    #[tokio::test]
    async fn recv_packet_rejects_invalid_display_text_before_returning_it() {
        let (mut sender, mut receiver) = websocket_pair().await;
        let encoded = serde_json::json!({
            "type": "access_request",
            "protocol_version": PROTOCOL_VERSION,
            "consumer_name": "support\u{001b}[2J",
            "forwarding": false,
            "capability": { "kind": "network", "policy": { "kind": "unrestricted" } },
        })
        .to_string();
        sender.send(Message::Text(encoded.into())).await.unwrap();

        let error = recv_packet(&mut receiver).await.unwrap_err();

        assert!(
            format!("{error:#}")
                .contains("access request consumer name contains a terminal control")
        );
    }

    #[tokio::test]
    async fn decode_errors_do_not_echo_attacker_controlled_values() {
        let (mut sender, mut receiver) = websocket_pair().await;
        let attacker_value = "\u{001b}[2Jattacker";
        let encoded = serde_json::json!({ "type": attacker_value }).to_string();
        sender.send(Message::Text(encoded.into())).await.unwrap();

        let error = recv_packet(&mut receiver).await.unwrap_err();
        let displayed = format!("{error:#}");

        assert!(displayed.contains("failed to decode control packet at line 1 column"));
        assert!(displayed.contains("schema mismatch; ensure both peers use matching builds"));
        assert!(!displayed.contains(attacker_value));
    }

    #[test]
    fn control_packet_debug_output_does_not_render_unvalidated_metadata() {
        let attacker_value = "workstation\u{202e}hidden";
        let packet = ControlPacket::PeerHello(Box::new(PeerHello {
            network_policy: None,
            role: super::PeerRole::Provider,
            node_id: "11111111111111111111111111111111".to_string(),
            route: vec!["11111111111111111111111111111111".to_string()],
            protocol_version: PROTOCOL_VERSION,
            reconnect: None,
            metadata: PeerMetadata {
                hostname: attacker_value.to_string(),
                username: "engineer".to_string(),
                working_directory: "/workspace".to_string(),
                platform: Platform::current().unwrap(),
            },
        }));

        let displayed = format!("{packet:?}");

        assert_eq!(displayed, "PeerHello");
        assert!(!displayed.contains(attacker_value));
    }

    #[tokio::test]
    async fn unsafe_websocket_close_reasons_are_not_echoed() {
        let (mut sender, mut receiver) = websocket_pair().await;
        let unsafe_reason = "closing\u{001b}[2Jspoof";
        sender
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: unsafe_reason.into(),
            })))
            .await
            .unwrap();

        let error = recv_packet(&mut receiver).await.unwrap_err();
        let displayed = format!("{error:#}");

        assert!(displayed.contains("peer closed the websocket with an unsafe reason"));
        assert!(!displayed.contains(unsafe_reason));
    }
    #[test]
    fn provider_routes_reject_cycles_and_consumers_cannot_advertise_egress() {
        let mut hello = PeerHello {
            role: super::PeerRole::Provider,
            network_policy: None,
            node_id: "11111111111111111111111111111111".to_string(),
            route: vec!["11111111111111111111111111111111".to_string(); 2],
            protocol_version: PROTOCOL_VERSION,
            reconnect: None,
            metadata: PeerMetadata {
                hostname: "host".to_string(),
                username: "user".to_string(),
                working_directory: "/".to_string(),
                platform: Platform::current().unwrap(),
            },
        };
        assert!(
            ControlPacket::PeerHello(Box::new(hello.clone()))
                .validate()
                .is_err()
        );
        hello.route.clear();
        hello.role = super::PeerRole::Consumer;
        hello.network_policy = Some(NetworkPolicy::unrestricted());
        assert!(
            ControlPacket::PeerHello(Box::new(hello))
                .validate()
                .is_err()
        );
    }
}
