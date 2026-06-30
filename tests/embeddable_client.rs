//! input: rusnel native ClientConfig/RusnelHandle, localhost TCP echo servers
//! output: end-to-end coverage for the embeddable client lifecycle API
//! pos: integration tests for library embedding without the external controller crate.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rusnel::common::quic::Congestion;
use rusnel::common::remote::RemoteRequest;
use rusnel::common::tls::{ClientTlsConfig, ServerTlsConfig};
use rusnel::{
    ClientConfig, ExitReason, LifecycleState, ReconnectConfig, RusnelEvent, RusnelHandle,
    ServerConfig, ServerEndpoint,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

/// Holds a spawned server task and aborts it when the test exits.
struct ServerGuard {
    /// The server runs forever unless the test aborts it.
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Returns an available localhost TCP port for short-lived integration tests.
fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .context("failed to reserve a local tcp port")?;
    Ok(listener
        .local_addr()
        .context("failed to read reserved local address")?
        .port())
}

/// Starts a TCP echo server and returns its listening port.
async fn spawn_echo() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind echo server")?;
    let port = listener
        .local_addr()
        .context("failed to read echo server address")?
        .port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    Ok(port)
}

/// Connects to a tunnel entry with retries because listeners come up async.
async fn tcp_roundtrip(port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_error = None;

    while Instant::now() < deadline {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(mut stream) => {
                stream
                    .write_all(payload)
                    .await
                    .context("failed to write payload through tunnel")?;
                let mut response = vec![0u8; payload.len()];
                stream
                    .read_exact(&mut response)
                    .await
                    .context("failed to read payload through tunnel")?;
                return Ok(response);
            }
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    Err(anyhow!(
        "connect to tunnel entry 127.0.0.1:{port} timed out: {last_error:?}"
    ))
}

/// Starts a local insecure Rusnel server for a handle integration test.
async fn spawn_server(port: u16) -> ServerGuard {
    let config = ServerConfig {
        host: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        allow_reverse: true,
        allow_socks: false,
        tls: ServerTlsConfig::Insecure,
        congestion: Congestion::default(),
        max_connections: None,
        admin_socket: None::<PathBuf>,
    };

    let handle = tokio::spawn(async move {
        let _ = rusnel::server::run_async(config).await;
    });
    ServerGuard { handle }
}

/// Builds the native client config used by the embeddable handle.
fn client_config(server_port: u16, remotes: Vec<RemoteRequest>) -> ClientConfig {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    ClientConfig {
        server: ServerEndpoint {
            addrs: vec![addr],
            host: addr.ip().to_string(),
        },
        remotes,
        tls: ClientTlsConfig::Insecure,
        congestion: Congestion::default(),
        reconnect: ReconnectConfig::default(),
        proxy: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_runs_forward_and_reverse_tunnels_then_stops() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let forward_target = spawn_echo().await?;
    let reverse_target = spawn_echo().await?;
    let server_port = free_port()?;
    let forward_entry = free_port()?;
    let reverse_entry = free_port()?;
    let _server = spawn_server(server_port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let forward = RemoteRequest::from_str(&format!(
        "127.0.0.1:{forward_entry}:127.0.0.1:{forward_target}"
    ))
    .context("failed to parse forward remote")?;
    let reverse = RemoteRequest::from_str(&format!(
        "R:127.0.0.1:{reverse_entry}:127.0.0.1:{reverse_target}"
    ))
    .context("failed to parse reverse remote")?;

    let handle = RusnelHandle::new();
    let mut events = handle.subscribe();
    assert_eq!(handle.state(), LifecycleState::Idle);

    handle
        .start(client_config(server_port, vec![forward, reverse]))
        .await
        .context("embedded client failed to start")?;
    assert!(handle.state().is_running());

    let forward_echo = tcp_roundtrip(forward_entry, b"hello-forward").await?;
    assert_eq!(forward_echo, b"hello-forward");

    let reverse_echo = tcp_roundtrip(reverse_entry, b"hello-reverse").await?;
    assert_eq!(reverse_echo, b"hello-reverse");

    handle
        .stop()
        .await
        .context("embedded client failed to stop")?;
    assert!(matches!(
        handle.state(),
        LifecycleState::Stopped {
            reason: ExitReason::Clean | ExitReason::UserStopped
        }
    ));

    let mut saw_stopped = false;
    while let Ok(event) = events.try_recv() {
        if matches!(
            event,
            RusnelEvent::StateChange {
                to: LifecycleState::Stopped { .. },
                ..
            }
        ) {
            saw_stopped = true;
        }
    }
    assert!(saw_stopped, "stop should publish a stopped state event");

    Ok(())
}
