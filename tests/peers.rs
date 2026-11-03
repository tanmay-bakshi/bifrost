use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

const DEADLINE: Duration = Duration::from_secs(30);

struct Process {
    child: Child,
    output: Arc<Mutex<String>>,
    changed: Arc<Notify>,
    _readers: [AbortOnDropHandle<()>; 2],
}

impl Process {
    fn spawn(binary: &str, args: &[&str]) -> Self {
        let mut child = Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let output = Arc::new(Mutex::new(String::new()));
        let changed = Arc::new(Notify::new());
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let read = |stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>| {
            let output = Arc::clone(&output);
            let changed = Arc::clone(&changed);
            AbortOnDropHandle::new(tokio::spawn(async move {
                let mut lines = BufReader::new(stream).lines();
                while let Some(line) = lines.next_line().await.unwrap() {
                    let mut output = output.lock().unwrap();
                    output.push_str(&line);
                    output.push('\n');
                    drop(output);
                    changed.notify_waiters();
                }
            }))
        };
        Self {
            child,
            _readers: [read(Box::new(stdout)), read(Box::new(stderr))],
            output,
            changed,
        }
    }

    async fn wait_for(&self, text: &str, count: usize) -> String {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let notification = self.changed.notified();
                let output = self.output.lock().unwrap().clone();
                if output.matches(text).count() >= count {
                    return output;
                }
                notification.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing {text:?}: {}", self.output.lock().unwrap()))
    }

    async fn exit(&mut self) -> std::process::ExitStatus {
        tokio::time::timeout(DEADLINE, self.child.wait())
            .await
            .unwrap()
            .unwrap()
    }
}

struct FaultProxy {
    address: SocketAddr,
    forwarding: Arc<std::sync::atomic::AtomicBool>,
    connections: Arc<Mutex<Vec<CancellationToken>>>,
    _task: AbortOnDropHandle<()>,
}

impl FaultProxy {
    async fn start(destination: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let forwarding = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let enabled = Arc::clone(&forwarding);
        let connections = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::clone(&connections);
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                let (mut provider, _) = tokio::select! {
                    accepted = listener.accept() => accepted.unwrap(),
                    _ = tasks.join_next(), if !tasks.is_empty() => continue,
                };
                if !enabled.load(std::sync::atomic::Ordering::SeqCst) {
                    drop(provider);
                    continue;
                }
                let cancellation = CancellationToken::new();
                active.lock().unwrap().push(cancellation.clone());
                tasks.spawn(async move {
                    let mut consumer = TcpStream::connect(destination).await.unwrap();
                    tokio::select! {
                        _ = cancellation.cancelled() => {}
                        _ = tokio::io::copy_bidirectional(&mut provider, &mut consumer) => {}
                    }
                });
            }
        }));
        Self {
            address,
            forwarding,
            connections,
            _task: task,
        }
    }

    fn disconnect(&self) {
        self.forwarding
            .store(false, std::sync::atomic::Ordering::SeqCst);
        for connection in self.connections.lock().unwrap().drain(..) {
            connection.cancel();
        }
    }

    fn restore(&self) {
        self.forwarding
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn printed_address(output: &str, prefix: &str) -> SocketAddr {
    output
        .lines()
        .rev()
        .find_map(|line| {
            line.strip_prefix(prefix)
                .and_then(|tail| tail.split_whitespace().next())
                .and_then(|address| address.parse().ok())
        })
        .unwrap_or_else(|| panic!("missing address {prefix:?}: {output}"))
}

async fn socks_echo(proxy: SocketAddr, destination: SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend_from_slice(&destination.port().to_be_bytes());
        stream.write_all(&connect).await.unwrap();
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        stream.write_all(b"recovered-egress").await.unwrap();
        let mut echoed = [0; 16];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"recovered-egress");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn real_processes_recover_transport_loss_and_reject_a_different_peer() {
    tokio::time::timeout(DEADLINE, async {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let _echo_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (mut stream, _) = tokio::select! {
                    accepted = echo.accept() => accepted.unwrap(),
                    _ = connections.join_next(), if !connections.is_empty() => continue,
                };
                connections.spawn(async move {
                    let mut data = [0; 128];
                    loop {
                        let size = stream.read(&mut data).await.unwrap();
                        if size == 0 {
                            return;
                        }
                        stream.write_all(&data[..size]).await.unwrap();
                    }
                });
            }
        }));
        let mut consumer = Process::spawn(
            env!("CARGO_BIN_EXE_bifrost"),
            &[
                "access",
                "--listen",
                "127.0.0.1:0",
                "--socks-only",
                "127.0.0.1:0",
                "--join-token",
                "recovery-test",
                "--reconnect",
                "--reconnect-interval-seconds",
                "1",
                "--reconnect-timeout-seconds",
                "6",
            ],
        );
        let output = consumer.wait_for("Bifrost listening on http://", 1).await;
        let server_address = printed_address(&output, "Bifrost listening on http://");
        let proxy = FaultProxy::start(server_address).await;
        let url = format!("ws://{}/connect?token=recovery-test", proxy.address);
        let mut provider = Process::spawn(
            env!("CARGO_BIN_EXE_bifrost"),
            &[
                "provide",
                "--connect",
                &url,
                "--approve-session",
                "--reconnect",
                "--reconnect-interval-seconds",
                "1",
                "--reconnect-timeout-seconds",
                "6",
            ],
        );
        provider.wait_for("connection attempt failed", 1).await;
        proxy.restore();
        let output = consumer.wait_for("SOCKS5 proxy listening on", 1).await;
        let socks_address = printed_address(&output, "SOCKS5 proxy listening on ");
        socks_echo(socks_address, echo_address).await;

        proxy.disconnect();
        consumer
            .wait_for("for the approved peer to reconnect", 1)
            .await;
        let direct = format!("ws://{server_address}/connect?token=recovery-test");
        let mut other = Process::spawn(
            env!("CARGO_BIN_EXE_bifrost"),
            &[
                "provide",
                "--connect",
                &direct,
                "--approve-session",
                "--reconnect",
            ],
        );
        assert!(!other.exit().await.success());
        other
            .wait_for("resume credentials do not identify the approved peer", 1)
            .await;
        proxy.restore();
        let output = consumer.wait_for("SOCKS5 proxy listening on", 2).await;
        assert_eq!(
            printed_address(&output, "SOCKS5 proxy listening on "),
            socks_address
        );
        socks_echo(socks_address, echo_address).await;
        assert!(provider.child.try_wait().unwrap().is_none());
        assert!(consumer.child.try_wait().unwrap().is_none());

        proxy.disconnect();
        assert!(!provider.exit().await.success());
        assert!(!consumer.exit().await.success());
        provider.wait_for("reconnection window expired", 1).await;
        consumer.wait_for("reconnection window expired", 1).await;
    })
    .await
    .expect("reconnection processes did not complete within their bounds");
}

#[cfg(unix)]
#[tokio::test]
async fn ssh_recovery_preserves_listener_ports_and_host_key() {
    ssh_recovery(true).await;
    ssh_recovery(false).await;
}

async fn ssh_recovery(provider_connects: bool) {
    use russh::client as ssh;
    use russh::keys::PublicKey;

    struct HostKey(Arc<Mutex<Option<PublicKey>>>);

    impl ssh::Handler for HostKey {
        type Error = russh::Error;

        async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
            *self.0.lock().unwrap() = Some(key.clone());
            Ok(true)
        }
    }

    async fn execute(address: SocketAddr) -> (PublicKey, ssh::Handle<HostKey>) {
        let key = Arc::new(Mutex::new(None));
        let mut ssh = ssh::connect(
            Arc::new(ssh::Config::default()),
            address,
            HostKey(Arc::clone(&key)),
        )
        .await
        .unwrap();
        assert!(
            ssh.authenticate_none(whoami::username())
                .await
                .unwrap()
                .success()
        );
        let mut channel = ssh.channel_open_session().await.unwrap();
        channel.exec(true, "printf recovered-shell").await.unwrap();
        let mut output = Vec::new();
        let mut status = None;
        while let Some(message) = channel.wait().await {
            match message {
                russh::ChannelMsg::Data { data } => output.extend_from_slice(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(output, b"recovered-shell");
        assert_eq!(status, Some(0));
        let key = key.lock().unwrap().clone().unwrap();
        (key, ssh)
    }

    tokio::time::timeout(DEADLINE, async {
        let mut listener_args = vec![
            if provider_connects { "access" } else { "provide" },
            "--listen", "127.0.0.1:0", "--join-token", "ssh-recovery-test",
            "--reconnect", "--reconnect-interval-seconds", "1",
            "--reconnect-timeout-seconds", "6",
        ];
        if provider_connects {
            listener_args.extend(["--dynamic-forward", "127.0.0.1:0"]);
        } else {
            listener_args.push("--approve-session");
        }
        let (listener, address) = listening_peer(&listener_args).await;
        let proxy = FaultProxy::start(address).await;
        proxy.restore();
        let url = format!("ws://{}/connect?token=ssh-recovery-test", proxy.address);
        let mut dialer_args = vec![
            if provider_connects { "provide" } else { "access" },
            "--connect", &url, "--reconnect", "--reconnect-interval-seconds", "1",
            "--reconnect-timeout-seconds", "6",
        ];
        if provider_connects {
            dialer_args.push("--approve-session");
        } else {
            dialer_args.extend(["--dynamic-forward", "127.0.0.1:0"]);
        }
        let dialer = Process::spawn(env!("CARGO_BIN_EXE_bifrost"), &dialer_args);
        let (consumer, mut provider) = if provider_connects {
            (listener, dialer)
        } else {
            (dialer, listener)
        };
        let output = consumer.wait_for("SOCKS5 proxy listening on ", 1).await;
        let ssh = printed_address(&output, "SSH proxy listening on ");
        let socks = printed_address(&output, "SOCKS5 proxy listening on ");
        let (host_key, old_local_transport) = execute(ssh).await;
        proxy.disconnect();
        consumer
            .wait_for("for the approved peer to reconnect", 1)
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(2), old_local_transport)
            .await
            .expect("old local SSH transport survived epoch teardown");
        proxy.restore();
        let output = tokio::select! {
            output = consumer.wait_for("SOCKS5 proxy listening on ", 2) => output,
            status = provider.child.wait() => panic!("SSH provider exited during recovery: {status:?}: {}", provider.output.lock().unwrap()),
        };
        assert_eq!(printed_address(&output, "SSH proxy listening on "), ssh);
        assert_eq!(
            printed_address(&output, "SOCKS5 proxy listening on "),
            socks
        );
        let (recovered_key, recovered_transport) = execute(ssh).await;
        assert_eq!(recovered_key, host_key);
        recovered_transport.disconnect(russh::Disconnect::ByApplication, "test complete", "en-US")
            .await.unwrap();
    })
    .await
    .expect("SSH recovery did not restore command access");
}

#[cfg(unix)]
#[tokio::test]
async fn termination_interrupts_connection_retries_and_rendezvous_waits() {
    let mut consumer = Process::spawn(
        env!("CARGO_BIN_EXE_bifrost"),
        &[
            "access",
            "--listen",
            "127.0.0.1:0",
            "--socks-only",
            "127.0.0.1:0",
            "--reconnect",
        ],
    );
    let output = consumer.wait_for("Bifrost listening on http://", 1).await;
    let address = printed_address(&output, "Bifrost listening on http://");
    let proxy = FaultProxy::start(address).await;
    let url = format!("ws://{}/connect?token=unused", proxy.address);
    let mut provider = Process::spawn(
        env!("CARGO_BIN_EXE_bifrost"),
        &[
            "provide",
            "--connect",
            &url,
            "--reconnect",
            "--approve-session",
        ],
    );
    provider
        .wait_for("waiting for the approved peer to reconnect", 1)
        .await;
    for process in [&mut provider, &mut consumer] {
        assert!(
            Command::new("/bin/kill")
                .arg("-TERM")
                .arg(process.child.id().unwrap().to_string())
                .status()
                .await
                .unwrap()
                .success()
        );
        let status = tokio::time::timeout(Duration::from_secs(2), process.child.wait())
            .await
            .expect("termination did not interrupt the recovery wait")
            .unwrap();
        assert!(status.success());
    }
}

async fn echo_service() -> (SocketAddr, AbortOnDropHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut socket, _) = accepted.unwrap();
                    connections.spawn(async move {
                        let (mut reader, mut writer) = socket.split();
                        tokio::io::copy(&mut reader, &mut writer).await.unwrap();
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }));
    (address, task)
}

async fn listening_peer(args: &[&str]) -> (Process, SocketAddr) {
    let process = Process::spawn(env!("CARGO_BIN_EXE_bifrost"), args);
    let output = process.wait_for("Bifrost listening on http://", 1).await;
    let address = printed_address(&output, "Bifrost listening on http://");
    (process, address)
}

async fn access_network(url: &str) -> (Process, SocketAddr) {
    let process = Process::spawn(
        env!("CARGO_BIN_EXE_bifrost"),
        &["access", "--connect", url, "--socks-only", "127.0.0.1:0"],
    );
    let output = process.wait_for("SOCKS5 proxy listening on", 1).await;
    let address = printed_address(&output, "SOCKS5 proxy listening on ");
    (process, address)
}

#[tokio::test]
async fn provider_listening_preserves_network_capability() {
    let (echo, _echo) = echo_service().await;
    let (_provider, address) = listening_peer(&[
        "provide",
        "--listen",
        "127.0.0.1:0",
        "--join-token",
        "direct-test",
        "--approve-session",
    ])
    .await;
    let url = format!("ws://{address}/connect?token=direct-test");
    let (_consumer, socks) = access_network(&url).await;
    socks_echo(socks, echo).await;
}

#[tokio::test]
async fn two_relays_share_one_upstream_with_concurrent_consumers() {
    let (echo, _echo) = echo_service().await;
    let (_root, root) = listening_peer(&[
        "provide",
        "--listen",
        "127.0.0.1:0",
        "--join-token",
        "root",
        "--approve-session",
    ])
    .await;
    let root_url = format!("ws://{root}/connect?token=root");
    let (first, first_address) = listening_peer(&[
        "relay",
        "--connect",
        &root_url,
        "--relay-listen",
        "127.0.0.1:0",
        "--relay-join-token",
        "first",
        "--approve-session",
    ])
    .await;
    first.wait_for("support session connected", 1).await;
    let first_url = format!("ws://{first_address}/connect?token=first");
    let (second, second_address) = listening_peer(&[
        "relay",
        "--connect",
        &first_url,
        "--relay-listen",
        "127.0.0.1:0",
        "--relay-join-token",
        "second",
        "--approve-session",
    ])
    .await;
    second.wait_for("support session connected", 1).await;
    let second_url = format!("ws://{second_address}/connect?token=second");
    let (_one, one) = access_network(&first_url).await;
    let (_two, two) = access_network(&second_url).await;
    let (_three, three) = access_network(&second_url).await;
    tokio::join!(
        socks_echo(one, echo),
        socks_echo(two, echo),
        socks_echo(three, echo)
    );
    socks_echo(two, echo).await;
    socks_echo(one, echo).await;
}

#[tokio::test]
async fn relays_enforce_the_upstream_policy_before_opening_a_destination() {
    let (_root, root) = listening_peer(&[
        "provide",
        "--listen",
        "127.0.0.1:0",
        "--join-token",
        "root",
        "--approve-session",
    ])
    .await;
    let root_url = format!("ws://{root}/connect?token=root");
    let (relay, address) = listening_peer(&[
        "relay",
        "--connect",
        &root_url,
        "--relay-listen",
        "127.0.0.1:0",
        "--relay-join-token",
        "restricted",
        "--include-cidr",
        "192.0.2.0/24",
        "--approve-session",
    ])
    .await;
    relay.wait_for("support session connected", 1).await;
    let url = format!("ws://{address}/connect?token=restricted");
    let (_consumer, socks) = access_network(&url).await;
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut connection = TcpStream::connect(socks).await.unwrap();
    connection.write_all(&[5, 1, 0]).await.unwrap();
    let mut response = [0_u8; 2];
    connection.read_exact(&mut response).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo.local_addr().unwrap().port().to_be_bytes());
    connection.write_all(&request).await.unwrap();
    let mut response = [0_u8; 10];
    tokio::time::timeout(Duration::from_secs(3), connection.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        response[1], 2,
        "upstream policy denial must reach the consumer"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), echo.accept())
            .await
            .is_err()
    );
}

async fn socks_connection(proxy: SocketAddr, destination: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut response = [0; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&destination.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut response = [0; 10];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response[1], 0);
    stream
}

#[tokio::test]
async fn relay_preserves_udp_datagrams_and_a_large_half_closed_tcp_flow() {
    tokio::time::timeout(DEADLINE, async {
        let (echo, _echo) = echo_service().await;
        let (_root, root) = listening_peer(&[
            "provide",
            "--listen",
            "127.0.0.1:0",
            "--join-token",
            "root",
            "--approve-session",
        ])
        .await;
        let upstream = format!("ws://{root}/connect?token=root");
        let (relay, address) = listening_peer(&[
            "relay",
            "--connect",
            &upstream,
            "--relay-listen",
            "127.0.0.1:0",
            "--relay-join-token",
            "relay",
            "--approve-session",
        ])
        .await;
        relay.wait_for("support session connected", 1).await;
        let url = format!("ws://{address}/connect?token=relay");
        let (_consumer, socks) = access_network(&url).await;
        let stream = socks_connection(socks, echo).await;
        let (mut reader, mut writer) = stream.into_split();
        let payload = (0..3 * 1024 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let sent = payload.clone();
        let upload = async move {
            writer.write_all(&sent).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let download = async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            bytes
        };
        let (_, received) = tokio::join!(upload, download);
        assert_eq!(received, payload);

        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let _echo = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut bytes = vec![0; 65535];
            loop {
                let (length, peer) = echo.recv_from(&mut bytes).await.unwrap();
                echo.send_to(&bytes[..length], peer).await.unwrap();
            }
        }));
        let mut control = TcpStream::connect(socks).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut association = [0; 10];
        control.read_exact(&mut association).await.unwrap();
        assert_eq!(association[1], 0);
        let relay_port = u16::from_be_bytes([association[8], association[9]]);
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for length in [0, 1, 8192] {
            let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
            packet.extend_from_slice(&echo_address.port().to_be_bytes());
            packet.extend(vec![42; length]);
            udp.send_to(&packet, (std::net::Ipv4Addr::LOCALHOST, relay_port))
                .await
                .unwrap();
            let mut response = vec![0; 65535];
            let (count, _) = udp.recv_from(&mut response).await.unwrap();
            assert_eq!(&response[..count], &packet);
        }
    })
    .await
    .expect("relayed TCP/UDP did not complete");
}

#[tokio::test]
async fn relay_listening_upstream_uses_the_connecting_providers_network() {
    let (echo, _echo) = echo_service().await;
    let relay = Process::spawn(
        env!("CARGO_BIN_EXE_bifrost"),
        &[
            "relay",
            "--listen",
            "127.0.0.1:0",
            "--join-token",
            "upstream",
            "--relay-listen",
            "127.0.0.1:0",
            "--relay-join-token",
            "downstream",
            "--approve-session",
        ],
    );
    let output = relay.wait_for("Bifrost listening on http://", 2).await;
    let listeners = output
        .lines()
        .filter_map(|line| {
            line.strip_prefix("Bifrost listening on http://")
                .and_then(|address| address.parse::<SocketAddr>().ok())
        })
        .collect::<Vec<_>>();
    assert_eq!(listeners.len(), 2);
    let upstream = format!("ws://{}/connect?token=upstream", listeners[1]);
    let _provider = Process::spawn(
        env!("CARGO_BIN_EXE_bifrost"),
        &["provide", "--connect", &upstream, "--approve-session"],
    );
    relay.wait_for("support session connected", 1).await;
    let downstream = format!("ws://{}/connect?token=downstream", listeners[0]);
    let (_consumer, socks) = access_network(&downstream).await;
    socks_echo(socks, echo).await;
}
