#![forbid(unsafe_code)]

use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Parser, Subcommand};
use ipnet::IpNet;
use rustls::pki_types::{CertificateDer, pem::PemObject};

use bifrost::{
    AccessMode, Consumer, EndpointConfig, NetworkPolicy, PeerConfig, ProviderOptions,
    ReconnectOptions, Relay, Shutdown, TerminalProvider, gather_environment, generate_join_token,
    harden_dynamic_library_search, load_consumer_key, normalize_websocket_url, run_peer,
    run_provider,
};

#[derive(Parser, Debug)]
#[command(
    name = "bifrost",
    version,
    about = "Share SSH and network access over consent-gated peer connections."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Provide access to this environment. Either connect to or listen for a consumer.
    Provide(Provide),
    /// Use access provided by another environment. Either connect to or listen for a provider.
    Access(Access),
    /// Share an approved upstream network with independently approved downstream peers.
    Relay(RelayOptions),
}

#[derive(Args, Debug)]
#[group(skip)]
struct Connection {
    /// WebSocket rendezvous URL, including its join token.
    #[arg(long, required_unless_present = "listen", conflicts_with = "listen")]
    connect: Option<String>,
    /// HTTP rendezvous address. TLS may be terminated by a reverse proxy.
    #[arg(long, required_unless_present = "connect")]
    listen: Option<SocketAddr>,
    /// Exact nonempty listener join token. A random token is generated when omitted.
    #[arg(long, requires = "listen", conflicts_with = "connect", value_parser = nonempty_token)]
    join_token: Option<String>,
    /// PEM CA bundle to add to the platform trust store for this connection.
    #[arg(
        long = "tls-ca-certificate",
        requires = "connect",
        conflicts_with = "listen"
    )]
    tls_ca_certificates: Vec<PathBuf>,
}

#[derive(Args, Debug)]
struct Lifecycle {
    #[command(flatten)]
    reconnection: ReconnectOptions,
    /// Deadline for completing capability negotiation and approval.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
    handshake_timeout_seconds: u64,
}

#[derive(Args, Debug)]
struct Provide {
    #[command(flatten)]
    connection: Connection,
    #[command(flatten)]
    lifecycle: Lifecycle,
    #[command(flatten)]
    approval: ProviderOptions,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("network_access").args(["vpn", "socks_only"])))]
struct Access {
    #[command(flatten)]
    connection: Connection,
    #[command(flatten)]
    lifecycle: Lifecycle,
    /// Consumer label presented to the provider for approval.
    #[arg(long, default_value = "Bifrost consumer")]
    consumer_name: String,
    /// Private SSH key. An ephemeral key is generated when omitted.
    #[arg(long, conflicts_with_all = ["vpn", "socks_only"])]
    consumer_key: Option<PathBuf>,
    /// Request separate approval to install the SSH key persistently.
    #[arg(long, conflicts_with_all = ["vpn", "socks_only"])]
    persist_consumer_key: bool,
    /// Local SSH proxy address.
    #[arg(long, default_value = "127.0.0.1:0", conflicts_with_all = ["vpn", "socks_only"])]
    ssh_listen: SocketAddr,
    /// SSH-backed SOCKS5 listener.
    #[arg(long, conflicts_with_all = ["vpn", "socks_only"])]
    dynamic_forward: Option<SocketAddr>,
    /// Local SOCKS5 listener for direct TCP and UDP access.
    #[arg(long, conflicts_with = "vpn")]
    socks_only: Option<SocketAddr>,
    /// Route system traffic through the provider. Requires administrator privileges on desktop.
    #[arg(long)]
    vpn: bool,
    #[arg(long, requires = "network_access")]
    include_cidr: Vec<IpNet>,
    #[arg(long, requires = "network_access")]
    include_domain: Vec<String>,
}

#[derive(Args, Debug)]
struct RelayOptions {
    #[command(flatten)]
    connection: Connection,
    #[command(flatten)]
    lifecycle: Lifecycle,
    #[command(flatten)]
    approval: ProviderOptions,
    /// Downstream HTTP rendezvous address.
    #[arg(long)]
    relay_listen: SocketAddr,
    /// Downstream listener token. Generated when omitted.
    #[arg(long, value_parser = nonempty_token)]
    relay_join_token: Option<String>,
    #[arg(long, default_value = "Bifrost relay")]
    consumer_name: String,
    #[arg(long)]
    include_cidr: Vec<IpNet>,
    #[arg(long)]
    include_domain: Vec<String>,
}

fn nonempty_token(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("join token must not be empty".to_string());
    }
    Ok(value.to_string())
}

impl Connection {
    fn resolve(self) -> Result<EndpointConfig> {
        match (self.connect, self.listen) {
            (Some(url), None) => Ok(EndpointConfig::Connect {
                url: normalize_websocket_url(&url)?,
                extra_roots: load_tls_ca_certificates(&self.tls_ca_certificates)?,
            }),
            (None, Some(address)) => Ok(EndpointConfig::Listen {
                address,
                join_token: self.join_token.unwrap_or_else(generate_join_token),
            }),
            _ => bail!("choose exactly one of --connect or --listen"),
        }
    }
}

impl Access {
    fn mode(&self) -> Result<AccessMode> {
        if self.vpn {
            return Ok(AccessMode::Vpn {
                policy: NetworkPolicy::new(self.include_cidr.clone(), self.include_domain.clone())?,
            });
        }
        if let Some(listen) = self.socks_only {
            return Ok(AccessMode::Socks {
                listen,
                policy: NetworkPolicy::new(self.include_cidr.clone(), self.include_domain.clone())?,
            });
        }
        Ok(AccessMode::Ssh {
            key: load_consumer_key(self.consumer_key.as_deref(), self.persist_consumer_key)?,
            listen: self.ssh_listen,
            dynamic_forward: self.dynamic_forward,
        })
    }
}

fn main() -> Result<()> {
    harden_dynamic_library_search()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<()> {
    let command = Cli::parse().command;
    let shutdown = Shutdown::new()?;
    let metadata = gather_environment()?;
    let node_id = generate_join_token();
    match command {
        Command::Provide(options) => {
            let reconnect = options.lifecycle.reconnection.settings()?;
            let config = PeerConfig {
                endpoint: options.connection.resolve()?,
                metadata: metadata.clone(),
                node_id,
                reconnect,
                handshake_timeout: Duration::from_secs(options.lifecycle.handshake_timeout_seconds),
            };
            let provider = TerminalProvider::new(
                options.approval,
                metadata,
                reconnect.map(|settings| Duration::from_secs(settings.timeout_seconds)),
            );
            run_provider(config, provider, shutdown.token).await
        }
        Command::Relay(options) => {
            let reconnect = options.lifecycle.reconnection.settings()?;
            let handshake_timeout =
                Duration::from_secs(options.lifecycle.handshake_timeout_seconds);
            let downstream = PeerConfig {
                endpoint: EndpointConfig::Listen {
                    address: options.relay_listen,
                    join_token: options.relay_join_token.unwrap_or_else(generate_join_token),
                },
                metadata: metadata.clone(),
                node_id: node_id.clone(),
                reconnect,
                handshake_timeout,
            };
            let consent = TerminalProvider::new(
                options.approval,
                metadata.clone(),
                reconnect.map(|settings| Duration::from_secs(settings.timeout_seconds)),
            );
            let policy = NetworkPolicy::new(options.include_cidr, options.include_domain)?;
            let relay = Relay::bind(downstream, options.consumer_name, policy, consent).await?;
            let upstream = PeerConfig {
                endpoint: options.connection.resolve()?,
                metadata,
                node_id,
                reconnect,
                handshake_timeout,
            };
            relay.run(upstream, shutdown.token).await
        }
        Command::Access(options) => {
            let mut consumer =
                Consumer::bind(options.consumer_name.clone(), options.mode()?).await?;
            let config = PeerConfig {
                endpoint: options.connection.resolve()?,
                metadata,
                node_id,
                reconnect: options.lifecycle.reconnection.settings()?,
                handshake_timeout: Duration::from_secs(options.lifecycle.handshake_timeout_seconds),
            };
            run_peer(config, &mut consumer, shutdown.token).await
        }
    }
}
fn load_tls_ca_certificates(paths: &[PathBuf]) -> Result<Vec<CertificateDer<'static>>> {
    let mut roots = Vec::new();
    for path in paths {
        let file = File::open(path).with_context(|| {
            format!("failed to open TLS CA certificate file {}", path.display())
        })?;
        let certificates = CertificateDer::pem_reader_iter(file)
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| {
                format!(
                    "failed to decode PEM certificates from TLS CA file {}",
                    path.display()
                )
            })?;
        if certificates.is_empty() {
            bail!(
                "TLS CA certificate file {} contains no PEM certificates",
                path.display()
            );
        }
        roots.extend(certificates);
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn both_capability_roles_accept_both_connection_directions() {
        for role in ["provide", "access"] {
            assert!(
                Cli::try_parse_from(["bifrost", role, "--connect", "ws://localhost:7071"]).is_ok()
            );
            assert!(Cli::try_parse_from(["bifrost", role, "--listen", "127.0.0.1:7071"]).is_ok());
            assert!(Cli::try_parse_from(["bifrost", role]).is_err());
            assert!(
                Cli::try_parse_from([
                    "bifrost",
                    role,
                    "--listen",
                    "127.0.0.1:7071",
                    "--connect",
                    "ws://localhost:7072"
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn listener_admission_preserves_explicit_tokens() {
        let token = "  shared+token&雪  ";
        let Command::Provide(options) = Cli::try_parse_from([
            "bifrost",
            "provide",
            "--listen",
            "127.0.0.1:0",
            "--join-token",
            token,
        ])
        .unwrap()
        .command
        else {
            panic!("expected provider");
        };
        let EndpointConfig::Listen { join_token, .. } = options.connection.resolve().unwrap()
        else {
            panic!("expected listener");
        };
        assert_eq!(join_token, token);
        assert!(
            Cli::try_parse_from([
                "bifrost",
                "provide",
                "--listen",
                "127.0.0.1:0",
                "--join-token",
                ""
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "bifrost",
                "provide",
                "--connect",
                "ws://localhost",
                "--join-token",
                "token"
            ])
            .is_err()
        );
    }

    #[test]
    fn selectors_apply_to_both_network_frontends_and_require_network_access() {
        for mode in [vec!["--vpn"], vec!["--socks-only", "127.0.0.1:1080"]] {
            let mut args = vec![
                "bifrost",
                "access",
                "--connect",
                "ws://localhost",
                "--include-cidr",
                "10.20.9.8/16",
                "--include-domain",
                "EXAMPLE.COM",
            ];
            args.extend(mode);
            let Command::Access(options) = Cli::try_parse_from(args).unwrap().command else {
                panic!("expected consumer");
            };
            let policy = match options.mode().unwrap() {
                AccessMode::Vpn { policy } | AccessMode::Socks { policy, .. } => policy,
                _ => panic!("expected network frontend"),
            };
            assert_eq!(
                policy.include_cidrs(),
                &["10.20.0.0/16".parse::<IpNet>().unwrap()]
            );
            assert_eq!(policy.include_domains(), &["example.com"]);
        }
        assert!(
            Cli::try_parse_from([
                "bifrost",
                "access",
                "--connect",
                "ws://localhost",
                "--include-domain",
                "example.com"
            ])
            .is_err()
        );
    }

    #[test]
    fn network_frontends_reject_ssh_configuration() {
        for mode in [vec!["--vpn"], vec!["--socks-only", "127.0.0.1:1080"]] {
            for incompatible in [
                vec!["--consumer-key", "key"],
                vec!["--persist-consumer-key"],
                vec!["--ssh-listen", "127.0.0.1:2222"],
                vec!["--dynamic-forward", "127.0.0.1:1081"],
            ] {
                let mut args = vec!["bifrost", "access", "--listen", "127.0.0.1:7071"];
                args.extend(mode.clone());
                args.extend(incompatible);
                assert!(Cli::try_parse_from(args).is_err());
            }
        }
    }

    #[test]
    fn reconnect_parameters_require_enablement_and_a_valid_window() {
        assert!(
            Cli::try_parse_from([
                "bifrost",
                "provide",
                "--listen",
                "127.0.0.1:0",
                "--reconnect-interval-seconds",
                "1"
            ])
            .is_err()
        );
        let Command::Provide(options) = Cli::try_parse_from([
            "bifrost",
            "provide",
            "--listen",
            "127.0.0.1:0",
            "--reconnect",
            "--reconnect-interval-seconds",
            "5",
            "--reconnect-timeout-seconds",
            "2",
        ])
        .unwrap()
        .command
        else {
            panic!("expected provider");
        };
        assert!(options.lifecycle.reconnection.settings().is_err());
    }
    const TEST_CA_CERTIFICATE: &str = "\
-----BEGIN CERTIFICATE-----
MIIBoTCCAUegAwIBAgIUSLG3JGtjMCN3sznKT7uznH+5py0wCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTU1NIUG9ydGFsIFRlc3QgUm9vdDAeFw0yNjA4MTQyMTMzMjVa
Fw0zNjA4MTEyMTMzMjVaMB4xHDAaBgNVBAMME1NTSFBvcnRhbCBUZXN0IFJvb3Qw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASOPkDhAY2TD+B0D92kiBrvn6DPjmcV
lFHE2Rku8t87xA21cICeSAFuK/o3GohR9AhGZ1TvMD967R0IYhUIk9xXo2MwYTAd
BgNVHQ4EFgQU0rW9+CcC0ID9PldZA6iOFCZclr0wHwYDVR0jBBgwFoAU0rW9+CcC
0ID9PldZA6iOFCZclr0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwIDSAAwRQIhAJ8xZ7GNqZbN2R8tWREOZz6eA7V+Ztr4IrB5mD8+
fn+7AiBo/pGqKkSraMBARq6fd2yOaFYPpg/ojDnhdejubqEvTw==
-----END CERTIFICATE-----
";

    #[test]
    fn loads_every_certificate_from_one_pem_bundle() {
        let temp = TempDir::new().unwrap();
        let bundle = temp.path().join("roots.pem");
        fs::write(
            &bundle,
            format!("{TEST_CA_CERTIFICATE}{TEST_CA_CERTIFICATE}"),
        )
        .unwrap();

        let roots = load_tls_ca_certificates(&[bundle]).unwrap();

        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0], roots[1]);
    }

    #[test]
    fn combines_certificates_from_repeated_ca_files() {
        let temp = TempDir::new().unwrap();
        let first = temp.path().join("first.pem");
        let second = temp.path().join("second.pem");
        fs::write(&first, TEST_CA_CERTIFICATE).unwrap();
        fs::write(&second, TEST_CA_CERTIFICATE).unwrap();

        let roots = load_tls_ca_certificates(&[first, second]).unwrap();

        assert_eq!(roots.len(), 2);
    }

    #[test]
    fn rejects_ca_files_without_certificates() {
        let temp = TempDir::new().unwrap();
        for (name, contents) in [
            ("empty.pem", ""),
            (
                "private-key.pem",
                "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
            ),
        ] {
            let path = temp.path().join(name);
            fs::write(&path, contents).unwrap();

            let error = load_tls_ca_certificates(&[path]).unwrap_err();

            assert!(error.to_string().contains("contains no PEM certificates"));
        }
    }

    #[test]
    fn rejects_malformed_ca_pem() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("malformed.pem");
        fs::write(
            &path,
            "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let error = load_tls_ca_certificates(&[path]).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("failed to decode PEM certificates")
        );
    }
}
