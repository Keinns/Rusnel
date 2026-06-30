//! input: rusnel native ClientConfig/RusnelHandle, localhost TCP echo servers
//! output: end-to-end coverage for the embeddable client lifecycle API
//! pos: integration tests for library embedding without the external controller crate.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::OnceLock;
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
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::field::{Field, Visit};
use tracing::Subscriber;
use tracing_subscriber::layer::Context as LayerContext;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Layer;

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

/// Test-only tracing layer that extracts client-side tunnel registration specs.
struct TunnelSpecLayer;

static TUNNEL_SPEC_TX: OnceLock<mpsc::UnboundedSender<String>> = OnceLock::new();

impl<S> Layer<S> for TunnelSpecLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerContext<'_, S>) {
        if event.metadata().target() != "rusnel::client" {
            return;
        }

        let mut visitor = TunnelSpecVisitor::default();
        event.record(&mut visitor);
        if visitor.message.as_deref() == Some("tunnel registered") {
            if let Some(spec) = visitor.spec {
                if let Some(tx) = TUNNEL_SPEC_TX.get() {
                    let _ = tx.send(spec);
                }
            }
        }
    }
}

/// Minimal tracing field visitor for the fields this test needs.
#[derive(Default)]
struct TunnelSpecVisitor {
    /// Formatted tracing message field.
    message: Option<String>,
    /// Remote spec emitted by Rusnel after applying assigned ports.
    spec: Option<String>,
}

impl Visit for TunnelSpecVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let value = format!("{value:?}").trim_matches('"').to_string();
        match field.name() {
            "message" => self.message = Some(value),
            "spec" => self.spec = Some(value),
            _ => {}
        }
    }
}

/// Installs a process-wide subscriber so spawned runtime threads are covered.
fn capture_tunnel_specs() -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();
    let _ = TUNNEL_SPEC_TX.set(tx);
    let subscriber = tracing_subscriber::registry().with(TunnelSpecLayer);
    let _ = tracing::subscriber::set_global_default(subscriber);
    rx
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

/// Starts a tiny HTTP server used as the SOCKS5 target for curl.
async fn spawn_http_server() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind http test server")?;
    let port = listener
        .local_addr()
        .context("failed to read http test server address")?
        .port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer).await;
                let response = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Content-Length: 15\r\n",
                    "Connection: close\r\n",
                    "\r\n",
                    "rusnel-socks-ok"
                );
                let _ = stream.write_all(response.as_bytes()).await;
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
    spawn_server_with_socks(port, false).await
}

/// Starts a local insecure Rusnel server with explicit SOCKS policy.
async fn spawn_server_with_socks(port: u16, allow_socks: bool) -> ServerGuard {
    let config = ServerConfig {
        host: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        allow_reverse: true,
        allow_socks,
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

/// Waits for the dynamically assigned reverse SOCKS5 listener port.
async fn wait_for_socks_port(specs: &mut mpsc::UnboundedReceiver<String>) -> Result<u16> {
    let deadline = Instant::now() + Duration::from_secs(15);

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let spec = tokio::time::timeout(remaining, specs.recv())
            .await
            .context("timed out waiting for tunnel registration")?
            .context("tunnel registration channel closed")?;

        if let Some(port) = parse_socks_spec_port(&spec) {
            return Ok(port);
        }
    }

    Err(anyhow!("dynamic reverse socks port was not announced"))
}

/// Parses display specs like `R:49152=>socks`.
fn parse_socks_spec_port(spec: &str) -> Option<u16> {
    let after_prefix = spec.strip_prefix("R:").unwrap_or(spec);
    let (port, target) = after_prefix.split_once("=>")?;
    if target != "socks" {
        return None;
    }
    port.parse().ok()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reverse_socks5_zero_port_is_assigned_and_works_with_curl() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut tunnel_specs = capture_tunnel_specs();

    let target_port = spawn_http_server().await?;
    let server_port = free_port()?;
    let _server = spawn_server_with_socks(server_port, true).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let reverse_socks = RemoteRequest::from_str("R:0.0.0.0:0:socks")
        .context("failed to parse dynamic reverse socks remote")?;
    let handle = RusnelHandle::new();

    handle
        .start(client_config(server_port, vec![reverse_socks]))
        .await
        .context("embedded client failed to start dynamic reverse socks")?;

    let socks_port = wait_for_socks_port(&mut tunnel_specs).await?;
    assert_ne!(socks_port, 0, "server must announce a concrete socks port");

    let output = Command::new("curl.exe")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "10",
            "--socks5-hostname",
            &format!("127.0.0.1:{socks_port}"),
            &format!("http://127.0.0.1:{target_port}/"),
        ])
        .output()
        .context("failed to execute curl.exe")?;

    assert!(
        output.status.success(),
        "curl failed: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "rusnel-socks-ok");

    handle
        .stop()
        .await
        .context("embedded client failed to stop")?;

    Ok(())
}
