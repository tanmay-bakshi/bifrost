#![forbid(unsafe_code)]

mod access;
mod control;
mod debug;
mod domain;
mod endpoint;
mod keys;
mod network;
mod peer;
mod platform;
mod policy;
mod reconnect;
mod relay;
mod shell;
mod shutdown;
mod socks;
mod terminal;
mod vpn;
mod websocket;

pub use access::{AccessMode, Consumer};
pub use control::{
    AccessDecision, AccessRequest, Capability, ControlPacket, PeerHello, PeerMetadata, PeerRole,
    recv_packet, send_packet,
};
pub use endpoint::{EndpointConfig, PeerConnection, generate_join_token, websocket_endpoint};
pub use keys::{
    AuthorizedKeySupport, AuthorizedKeyTarget, ConsumerKeyMaterial, authorized_key_support,
    load_consumer_key, parse_public_key,
};
pub use network::{NetworkProvider, run_consumer_socks_proxy};
pub use peer::{
    ApprovedSession, PeerConfig, PeerEvent, PeerHandler, run_peer, run_provider,
    session_consent_prompt,
};
pub use platform::{OperatingSystem, Platform, ShellLaunch};
pub use policy::NetworkPolicy;
pub use reconnect::{
    ReconnectHello, ReconnectOptions, ReconnectSecret, ReconnectSettings, ReconnectWindow,
    is_connection_loss,
};
pub use relay::Relay;
pub use shell::{ConsumerSsh, run_remote_shell_server};
pub use shutdown::Shutdown;
pub use terminal::{ProviderOptions, TerminalProvider, gather_environment};
pub use vpn::ConsumerVpn;
pub use websocket::{
    AsyncStream, PeerWebSocket, WebSocketIo, WebSocketTransport, connect_async_with_env_proxy,
    connect_async_with_env_proxy_and_extra_roots, normalize_websocket_url, websocket_config,
    websocket_to_io,
};

pub fn install_default_rustls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub const DEFAULT_CONNECT_PATH: &str = "/connect";
pub const DEFAULT_HEALTH_PATH: &str = "/healthz";
pub const PROTOCOL_VERSION: u32 = 10;
pub(crate) const NETWORK_SESSION_FLOW_LIMIT: usize = 256;
pub(crate) const MAX_NETWORK_UDP_DATAGRAM_BYTES: usize = u16::MAX as usize - 20 - 8;

/// Hardens the platform's default dynamic-library resolution before application startup.
pub fn harden_dynamic_library_search() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    wintun_security::restrict_process_dll_search_to_system32()?;
    Ok(())
}
