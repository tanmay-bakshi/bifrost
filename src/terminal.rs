use std::env;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use hostname::get;
use russh::keys::PublicKey;
use tokio_util::sync::CancellationToken;

use crate::{
    AccessDecision, AccessRequest, ApprovedSession, AuthorizedKeySupport, Capability,
    NetworkProvider, PeerConnection, PeerEvent, PeerHandler, PeerMetadata, PeerWebSocket, Platform,
    ShellLaunch, authorized_key_support, parse_public_key, run_remote_shell_server,
    session_consent_prompt, websocket_to_io,
};

#[derive(clap::Args, Clone, Debug, Default)]
pub struct ProviderOptions {
    /// Approve live access without prompting.
    #[arg(long)]
    pub approve_session: bool,
    /// Approve persistent SSH key installation separately.
    #[arg(long)]
    pub approve_key_install: bool,
}

#[derive(Clone)]
struct ProviderEnvironment {
    metadata: PeerMetadata,
}
struct KeyInstallOutcome {
    installed: bool,
    note: Option<String>,
}

#[derive(Clone)]
pub struct TerminalProvider {
    network: NetworkProvider,
    consent: std::sync::Arc<tokio::sync::Mutex<()>>,
    options: ProviderOptions,
    environment: ProviderEnvironment,
    reconnect_timeout: Option<Duration>,
}

impl TerminalProvider {
    pub fn new(
        options: ProviderOptions,
        metadata: PeerMetadata,
        reconnect_timeout: Option<Duration>,
    ) -> Self {
        Self {
            network: NetworkProvider::local(),
            consent: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            options,
            environment: ProviderEnvironment { metadata },
            reconnect_timeout,
        }
    }
}

pub fn print_peer_event(event: PeerEvent) {
    match event {
        PeerEvent::Listening { address, join_url } => {
            println!("Bifrost listening on http://{address}");
            println!("support websocket endpoint: {join_url}");
        }
        PeerEvent::Connecting => println!("waiting for peer connection"),
        PeerEvent::Connected => println!("support session connected"),
        PeerEvent::Reconnecting => println!("waiting for the approved peer to reconnect"),
        PeerEvent::UnencryptedTransport => {
            eprintln!("warning: transport encryption depends on WSS or the surrounding network")
        }
        PeerEvent::ConnectionLost(message) => eprintln!("connection lost: {message}"),
        PeerEvent::AttemptFailed(message) => eprintln!("connection attempt failed: {message}"),
    }
}

impl PeerHandler for TerminalProvider {
    fn request(&self) -> Option<AccessRequest> {
        None
    }
    fn event(&self, event: PeerEvent) {
        print_peer_event(event);
    }
    async fn approve(&self, offer: &AccessRequest) -> Result<AccessDecision> {
        let _consent = self.consent.lock().await;
        let mut prompt = session_consent_prompt(&offer.consumer_name, &offer.capability);
        if offer.forwarding {
            prompt.push_str(" This includes forwarding access for downstream Bifrost peers.");
        }
        if let Some(timeout) = self.reconnect_timeout {
            prompt.push_str(&format!(" Allow the same peer and capability to reconnect for up to {} seconds after a disconnection.", timeout.as_secs()));
        }
        let allowed = self.options.approve_session || prompt_yes_no(&prompt, false).await?;
        let key_install = match &offer.capability {
            Capability::Ssh {
                ssh_public_key,
                persist_key_requested,
            } if allowed => {
                maybe_install_consumer_key(
                    &self.options,
                    &offer.consumer_name,
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
        Ok(AccessDecision {
            session_allowed: allowed,
            key_installed: key_install.installed,
            note: if allowed {
                key_install.note
            } else {
                Some("local user declined access".to_string())
            },
        })
    }
    async fn serve(
        &mut self,
        connection: PeerConnection,
        session: ApprovedSession,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let PeerConnection {
            websocket,
            admission: _admission,
            ..
        } = connection;
        run_approved_provider_session(
            websocket,
            session.request.capability,
            &self.environment,
            &self.network,
            shutdown,
        )
        .await
    }
}

async fn run_approved_provider_session(
    websocket: PeerWebSocket,
    session: Capability,
    environment: &ProviderEnvironment,
    network_provider: &NetworkProvider,
    shutdown: CancellationToken,
) -> Result<()> {
    match session {
        Capability::Ssh { ssh_public_key, .. } => {
            tokio::select! {
            _ = shutdown.cancelled() => Ok(()),
            result = run_remote_shell_server(
                websocket_to_io(websocket),
                environment.metadata.username.clone(),
                parse_public_key(&ssh_public_key)?,
                PathBuf::from(&environment.metadata.working_directory),
                ShellLaunch::detect_for_current_platform()?,
            ) => result,
            }
        }
        network @ Capability::Network { .. } => {
            println!("network access approved (no local privileges required)");
            network_provider.run(websocket, network, shutdown).await
        }
    }
}

pub fn gather_environment() -> Result<PeerMetadata> {
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
    Ok(PeerMetadata {
        hostname,
        username,
        working_directory,
        platform,
    })
}

async fn maybe_install_consumer_key(
    cli: &ProviderOptions,
    consumer_name: &str,
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
                consumer_name,
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
        .with_context(|| format!("failed to add the consumer key to {}", target.prompt_path()))?;
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
