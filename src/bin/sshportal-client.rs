#![forbid(unsafe_code)]

use std::env;
use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use hostname::get;
use russh::keys::PublicKey;
use rustls::pki_types::{CertificateDer, pem::PemObject};

use sshportal::{
    AuthorizedKeySupport, ClientConfig, ClientDecision, ClientEvent, ClientHandler, ClientMetadata,
    ClientWebSocketStream, OfferedSession, Platform, ReconnectOptions, ServerOffer, ShellLaunch,
    Shutdown, authorized_key_support, harden_dynamic_library_search, normalize_websocket_url,
    parse_public_key, run_client, run_client_network_proxy, run_remote_shell_server,
    session_consent_prompt, websocket_to_io,
};

#[derive(Parser, Debug)]
#[command(
    name = "sshportal-client",
    about = "Connect back to an sshportal server and request local user approval.",
    long_about = "Connect to an sshportal rendezvous endpoint, complete the handshake, and serve the approved SSH, SOCKS, or VPN session back to the operator over the upgraded transport.",
    after_help = "Examples:\n  sshportal-client --server http://server-host:8080?token=<join-token>\n  sshportal-client --server https://support.example.com?token=<join-token> --approve-session"
)]
struct ClientCli {
    /// Server URL to connect to.
    ///
    /// Accepts http://, https://, ws://, or wss:// URLs. If the URL has no
    /// explicit path, the client automatically targets /connect.
    #[arg(long)]
    server: String,
    /// Add every PEM CA certificate in this file to platform TLS verification.
    ///
    /// May be repeated for private PKI roots that cannot be installed in the
    /// operating system trust store.
    #[arg(long = "tls-ca-certificate", value_name = "PATH")]
    tls_ca_certificates: Vec<PathBuf>,
    /// Skip the prompt that approves the live support session.
    #[arg(long)]
    approve_session: bool,
    /// Skip the prompt that approves persistent operator key installation.
    #[arg(long)]
    approve_key_install: bool,
    #[command(flatten)]
    reconnection: ReconnectOptions,
}

struct LocalClientEnvironment {
    metadata: ClientMetadata,
}

struct KeyInstallOutcome {
    installed: bool,
    note: Option<String>,
}

fn main() -> Result<()> {
    harden_dynamic_library_search()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to initialize the asynchronous runtime")?
        .block_on(run())
}

async fn run() -> Result<()> {
    let cli = ClientCli::parse();
    let shutdown = Shutdown::new()?;
    let environment = gather_client_environment()?;
    let server_url = normalize_websocket_url(&cli.server)?;
    let roots = load_tls_ca_certificates(&cli.tls_ca_certificates)?;
    let settings = cli.reconnection.settings()?;
    run_client(
        ClientConfig {
            server: server_url,
            metadata: environment.metadata.clone(),
            extra_roots: roots,
            reconnect: settings,
        },
        &TerminalClient {
            cli: &cli,
            environment: &environment,
        },
        shutdown.token,
    )
    .await
}

struct TerminalClient<'a> {
    cli: &'a ClientCli,
    environment: &'a LocalClientEnvironment,
}

impl ClientHandler for TerminalClient<'_> {
    fn event(&self, event: ClientEvent) {
        match event {
            ClientEvent::ConnectionLost(message) => eprintln!("support connection lost: {message}"),
            ClientEvent::AttemptFailed(message) => {
                eprintln!("connection attempt failed: {message}")
            }
            ClientEvent::Connecting => println!("connecting to server"),
            ClientEvent::Connected => println!("support session connected"),
            ClientEvent::Reconnecting => println!("waiting before reconnecting"),
            ClientEvent::UnencryptedTransport => eprintln!(
                "warning: network traffic is using an unencrypted WebSocket; use HTTPS/WSS outside a trusted network"
            ),
        }
    }

    fn refusal(&self, _session: &OfferedSession) -> Option<String> {
        None
    }

    async fn approve(&self, offer: &ServerOffer) -> Result<ClientDecision> {
        let mut prompt = session_consent_prompt(&offer.operator_name, &offer.session);
        if let Some(reconnect) = &offer.reconnect {
            prompt.push_str(&format!(
                " This approval also permits the same operator and capability to reconnect while this client stays running, for up to {} seconds after each disconnection.",
                reconnect.settings.timeout_seconds,
            ));
        }
        let allowed = self.cli.approve_session || prompt_yes_no(&prompt, false).await?;
        let key_install = match &offer.session {
            OfferedSession::Ssh {
                ssh_public_key,
                persist_key_requested,
            } if allowed => {
                maybe_install_operator_key(
                    self.cli,
                    &offer.operator_name,
                    &parse_public_key(ssh_public_key)?,
                    *persist_key_requested,
                )
                .await?
            }
            _ => KeyInstallOutcome {
                installed: false,
                note: None,
            },
        };
        Ok(ClientDecision {
            session_allowed: allowed,
            key_installed: key_install.installed,
            note: if allowed {
                key_install.note
            } else {
                Some("local user declined the support session".to_string())
            },
        })
    }

    async fn serve(&self, websocket: ClientWebSocketStream, session: OfferedSession) -> Result<()> {
        run_approved_client_session(websocket, session, self.environment).await
    }
}

async fn run_approved_client_session(
    websocket: ClientWebSocketStream,
    session: OfferedSession,
    environment: &LocalClientEnvironment,
) -> Result<()> {
    match session {
        OfferedSession::Ssh { ssh_public_key, .. } => {
            run_remote_shell_server(
                websocket_to_io(websocket),
                environment.metadata.username.clone(),
                parse_public_key(&ssh_public_key)?,
                PathBuf::from(&environment.metadata.working_directory),
                ShellLaunch::detect_for_current_platform()?,
            )
            .await
        }
        approved_session => {
            match &approved_session {
                OfferedSession::Socks {} => {
                    println!("SOCKS-only support session approved (SSH disabled)");
                }
                OfferedSession::Vpn { .. } => {
                    println!(
                        "VPN egress session approved (SSH disabled; no local privileges required)"
                    );
                }
                OfferedSession::Ssh { .. } => unreachable!("SSH sessions are handled above"),
            }
            run_client_network_proxy(websocket, approved_session).await
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

fn gather_client_environment() -> Result<LocalClientEnvironment> {
    let hostname = get()
        .context("failed to determine hostname")?
        .to_string_lossy()
        .to_string();
    let username = env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| whoami::username());
    let working_directory = env::current_dir()
        .context("failed to determine current working directory")?
        .display()
        .to_string();
    let platform = Platform::current()?;
    Ok(LocalClientEnvironment {
        metadata: ClientMetadata {
            hostname,
            username,
            working_directory,
            platform,
        },
    })
}

async fn maybe_install_operator_key(
    cli: &ClientCli,
    operator_name: &str,
    ssh_public_key: &PublicKey,
    persist_key_requested: bool,
) -> Result<KeyInstallOutcome> {
    if !persist_key_requested {
        return Ok(KeyInstallOutcome {
            installed: false,
            note: None,
        });
    }

    let target = match authorized_key_support()? {
        AuthorizedKeySupport::Supported(target) => target,
        AuthorizedKeySupport::Unsupported { reason } => {
            return Ok(KeyInstallOutcome {
                installed: false,
                note: Some(reason),
            });
        }
    };

    let install_key = if cli.approve_key_install {
        true
    } else {
        prompt_yes_no(
            &format!(
                "Persist {}'s SSH key into {} for future access?",
                operator_name,
                target.prompt_path()
            ),
            false,
        )
        .await?
    };
    if !install_key {
        return Ok(KeyInstallOutcome {
            installed: false,
            note: None,
        });
    }

    let installed = target
        .install(ssh_public_key)
        .with_context(|| format!("failed to add the operator key to {}", target.prompt_path()))?;
    Ok(KeyInstallOutcome {
        installed,
        note: None,
    })
}

struct ConsentTerminal;

impl Drop for ConsentTerminal {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

async fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    let stdin_is_terminal = io::stdin().is_terminal();
    let stdout_is_terminal = io::stdout().is_terminal();
    if !stdin_is_terminal || !stdout_is_terminal {
        bail!("{prompt} Refusing to assume consent without --approve flags.");
    }

    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    let mut stdout = io::stdout();
    write!(stdout, "{prompt} {suffix} ").context("failed to write prompt")?;
    stdout.flush().context("failed to flush prompt")?;

    crossterm::terminal::enable_raw_mode().context("failed to read terminal consent")?;
    // The guard restores canonical input when the prompt completes or its future is cancelled.
    let _terminal = ConsentTerminal;
    let mut events = EventStream::new();
    let mut answer = String::new();
    while let Some(event) = events.next().await {
        let Event::Key(key) = event.context("failed to read prompt response")? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'd'))
        {
            write!(stdout, "\r\n")?;
            bail!("support session approval cancelled");
        }
        match key.code {
            KeyCode::Enter => {
                write!(stdout, "\r\n")?;
                break;
            }
            KeyCode::Backspace if !answer.is_empty() => {
                answer.pop();
                write!(stdout, "\x08 \x08")?;
            }
            KeyCode::Char(character) if character.is_ascii_alphabetic() && answer.len() < 16 => {
                answer.push(character);
                write!(stdout, "{character}")?;
            }
            _ => {}
        }
        stdout.flush().context("failed to echo consent response")?;
    }
    let normalized = answer.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(default);
    }
    match normalized.as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => bail!("unrecognized response `{normalized}`"),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sshportal::{OfferedSession, SystemVpnPolicy, VpnScope};
    use tempfile::TempDir;

    use super::{ClientCli, load_tls_ca_certificates, session_consent_prompt};
    use clap::Parser;
    use sshportal::ReconnectOptions;

    #[test]
    fn reconnect_configuration_is_opt_in_and_validated() {
        let cli = ClientCli::try_parse_from([
            "sshportal-client",
            "--server",
            "https://example.test",
            "--reconnect",
        ])
        .unwrap();
        assert_eq!(
            cli.reconnection.settings().unwrap(),
            ReconnectOptions {
                reconnect: true,
                ..Default::default()
            }
            .settings()
            .unwrap()
        );
        assert!(
            ClientCli::try_parse_from([
                "sshportal-client",
                "--server",
                "https://example.test",
                "--reconnect-timeout-seconds",
                "0"
            ])
            .is_err()
        );
        assert!(
            ClientCli::try_parse_from([
                "sshportal-client",
                "--server",
                "https://example.test",
                "--reconnect-interval-seconds",
                "2"
            ])
            .is_err()
        );
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

    #[test]
    fn socks_consent_describes_tcp_and_udp_access() {
        let description = session_consent_prompt("support", &OfferedSession::Socks {});
        assert!(description.contains("TCP connections and UDP datagrams"));
        assert!(description.contains("while this connection remains open"));
    }

    #[test]
    fn full_vpn_consent_describes_system_wide_access() {
        let description = session_consent_prompt(
            "support",
            &OfferedSession::Vpn {
                scope: VpnScope::System {
                    policy: SystemVpnPolicy::default(),
                },
            },
        );

        assert!(description.contains("system-wide"));
        assert!(description.contains("TCP, UDP, and DNS"));
    }

    #[test]
    fn selective_vpn_consent_names_every_normalized_selector() {
        let policy = SystemVpnPolicy::new(
            vec![
                "10.20.4.7/16".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            vec!["ANTHEM.COM".to_string(), "elevancehealth.com".to_string()],
        )
        .unwrap();

        let description = session_consent_prompt(
            "support",
            &OfferedSession::Vpn {
                scope: VpnScope::System { policy },
            },
        );

        for selector in [
            "10.20.0.0/16",
            "2001:db8::/32",
            "anthem.com",
            "elevancehealth.com",
        ] {
            assert!(description.contains(selector));
        }
        assert!(description.contains("only the operator's"));
        assert!(description.contains("all subdomains"));
    }
}
