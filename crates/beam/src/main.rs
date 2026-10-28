use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use beam_core::address::{Address, NetLocation};
use beam_core::admission::IpLimiter;
use beam_core::config::{Config, LogLevel};
use beam_core::tls::{
    MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN, TlsServerConfig, handle_connection_admitted,
};
use beam_core::udp::LegacyUdpConfig;
use beam_core::xudp::XudpConfig;
use clap::Parser;
use tokio::net::{TcpListener, TcpSocket};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tokio::time::{Instant, sleep};

/// High-performance VLESS + REALITY + Vision server.
#[derive(Debug, Parser)]
#[command(name = "beam", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/beam/config.toml")]
    config: PathBuf,

    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,
}

fn main() -> anyhow::Result<()> {
    // Each Vision Direct relay can occupy up to two blocking splice tasks.
    // The default covers about 80 active relay pairs; max_connections is an
    // admission cap, not a promise of 1024 concurrent bulk relays. Operators
    // can raise the pool for a burst-heavy host without changing the
    // admission limit.
    let max_blocking_threads = std::env::var("BEAM_MAX_BLOCKING_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (1..=512).contains(value))
        .unwrap_or(160);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(max_blocking_threads)
        .enable_all()
        .build()
        .context("failed to build the Tokio runtime")?;
    let result = runtime.block_on(async_main(max_blocking_threads));
    // A blocking splice cannot be aborted once it has started. The shutdown
    // path drains normal connections briefly; this bound is the final backstop
    // for a wedged relay so systemd can restart the service.
    runtime.shutdown_timeout(Duration::from_secs(3));
    result
}

async fn async_main(max_blocking_threads: usize) -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::from_path(&cli.config)
        .with_context(|| format!("failed to load `{}`", cli.config.display()))?;

    init_logging(config.log.level);

    if cli.check {
        println!("configuration is valid: {}", cli.config.display());
        return Ok(());
    }

    let max_connections = config.limits.max_connections as usize;
    // Pre-auth slots bound ClientHello reads, not data-path relays. Keep this
    // small enough that a scanner flood cannot pin every permit, but large
    // enough for a browser's parallel connection burst.
    let max_pending_handshakes = max_connections.clamp(16, 256);
    let max_preauth_per_ip = config
        .limits
        .max_preauth_per_ip
        .min(max_pending_handshakes as u32);
    let authenticated = Arc::new(Semaphore::new(max_connections));
    let preauth = Arc::new(IpLimiter::new(max_pending_handshakes, max_preauth_per_ip));
    // Leave room in the blocking pool for cover relays, DNS resolution, and
    // destination dials. Vision directions above this cap use the async copy
    // path instead of queueing forever in `spawn_blocking`.
    let max_splice_tasks = max_blocking_threads.saturating_sub(40).max(1);
    let splice_permits = Arc::new(Semaphore::new(max_splice_tasks));
    // Legacy/packetaddr UDP is compatibility-only; keep its socket count well
    // below the XUDP cap because packetaddr binds two sockets per stream.
    let legacy_udp_permits = Arc::new(Semaphore::new(64));

    let tls_config = Arc::new(
        build_tls_config(&config)?
            .with_connection_limiter(Arc::clone(&authenticated))
            .with_splice_limiter(splice_permits)
            .with_legacy_udp_limiter(legacy_udp_permits),
    );
    let listener = bind_listener(config.server.listen, config.limits.listen_backlog)?;

    tracing::info!(
        listen = %config.server.listen,
        max_connections,
        max_pending_handshakes,
        max_preauth_per_ip,
        listen_backlog = config.limits.listen_backlog,
        "beam listening"
    );

    let mut sigterm = signal(SignalKind::terminate()).context("failed to watch SIGTERM")?;
    let mut sigint = signal(SignalKind::interrupt()).context("failed to watch SIGINT")?;
    let mut sighup = signal(SignalKind::hangup()).context("failed to watch SIGHUP")?;
    tokio::spawn(async move {
        while sighup.recv().await.is_some() {
            tracing::warn!("SIGHUP ignored; restart the service to reload configuration");
        }
    });
    let shutdown = async move {
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
    };
    tokio::pin!(shutdown);

    // A transient fd shortage must not turn into a permanent outage. `accept`
    // can fail with EMFILE/ENFILE, ECONNABORTED, or an interrupted syscall;
    // keep the listener alive and retry with a bounded backoff instead of
    // dropping the runtime (and any in-flight blocking relays) on the first
    // error.
    let mut accept_backoff = Duration::from_millis(10);
    loop {
        let accepted = tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => {
                accept_backoff = Duration::from_millis(10);
                accepted
            }
            Err(error) => {
                tracing::warn!(%error, "listener accept failed; retrying");
                tokio::select! {
                    _ = &mut shutdown => break,
                    _ = sleep(accept_backoff) => {}
                }
                accept_backoff = (accept_backoff * 2).min(Duration::from_secs(1));
                continue;
            }
        };
        // Never block the accept loop on data-path capacity. If every
        // pre-auth slot is held, drop this connection and keep draining the
        // kernel backlog; a stalled accept loop turns a handshake flood into a
        // total outage.
        let preauth_permit = match preauth.try_acquire(peer.ip()) {
            Ok(permit) => permit,
            Err(reject) => {
                tracing::debug!(%peer, ?reject, "pre-auth handshake limit reached; dropping");
                drop(stream);
                tokio::task::yield_now().await;
                continue;
            }
        };
        let tls_config = Arc::clone(&tls_config);

        tokio::spawn(async move {
            if let Err(error) = stream.set_nodelay(true) {
                tracing::debug!(%peer, %error, "could not set TCP_NODELAY");
            }
            if let Err(error) = beam_sys::set_tcp_keepalive(
                stream.as_raw_fd(),
                Duration::from_secs(60),
                Duration::from_secs(15),
            ) {
                tracing::debug!(%peer, %error, "could not set TCP keepalive");
            }

            match handle_connection_admitted(stream, tls_config, Some(preauth_permit)).await {
                Ok(outcome) => tracing::debug!(%peer, ?outcome, "connection finished"),
                Err(error) => tracing::debug!(%peer, %error, "connection failed"),
            }
        });
    }

    // Stop accepting immediately, then let established connections finish.
    // New work is not started. A relay that ignores the idle timeout is
    // bounded by the runtime shutdown deadline in `main`.
    drop(listener);
    tracing::info!("shutdown signal received; draining connections");
    let deadline = Instant::now() + Duration::from_secs(2);
    while authenticated.available_permits() < max_connections
        || preauth.available_permits() < max_pending_handshakes
    {
        if Instant::now() >= deadline {
            tracing::warn!(
                authenticated_remaining = max_connections - authenticated.available_permits(),
                preauth_remaining = max_pending_handshakes - preauth.available_permits(),
                "shutdown drain deadline reached; closing remaining connections"
            );
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    tracing::info!("shutdown complete");
    Ok(())
}

fn bind_listener(address: SocketAddr, backlog: u32) -> anyhow::Result<TcpListener> {
    let socket = match address {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .with_context(|| format!("failed to create a listener socket for `{address}`"))?;
    socket
        .set_reuseaddr(true)
        .with_context(|| format!("failed to set SO_REUSEADDR on `{address}`"))?;
    socket
        .bind(address)
        .with_context(|| format!("failed to bind `{address}`"))?;
    let listener = socket
        .listen(backlog)
        .with_context(|| format!("failed to listen on `{address}` with backlog {backlog}"))?;
    Ok(listener)
}

fn build_tls_config(config: &Config) -> anyhow::Result<TlsServerConfig> {
    let destination = &config.reality.dest;
    let address = match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => Address::Ipv4(address),
        Ok(IpAddr::V6(address)) => Address::Ipv6(address),
        Err(_) => Address::Domain(destination.host.clone()),
    };
    let cover = NetLocation {
        address,
        port: destination.port,
    };
    let user_id = *config.user.id.as_bytes();

    let max_sessions = usize::try_from(config.limits.max_udp_destinations)
        .unwrap_or(usize::MAX)
        .clamp(1, usize::from(u16::MAX) + 1);
    let xudp = XudpConfig {
        max_sessions,
        // Xray/sing-box XUDP clients generally close a flow with the TCP
        // stream, not an `End` frame. Reusing the 300 s TCP idle timeout lets
        // stale UDP sessions consume the 256-slot global cap. Cap the UDP
        // session idle clock independently; the TCP relay timeout is unchanged.
        session_idle_timeout: Duration::from_millis(config.limits.idle_timeout_ms)
            .min(Duration::from_secs(60)),
        io_timeout: Duration::from_millis(config.limits.handshake_timeout_ms),
        // A single HTTP/3 body can arrive as hundreds of UDP datagrams while
        // the outer TCP stream drains. Keep a larger bounded reply queue so a
        // short client-side pause does not turn into QUIC packet loss.
        max_queued_replies: 512,
        ..XudpConfig::default()
    };
    xudp.validate().context("invalid XUDP limits")?;

    let max_packetaddr_destinations = usize::try_from(config.limits.max_udp_destinations)
        .unwrap_or(usize::MAX)
        .clamp(1, 65_536);
    let udp = LegacyUdpConfig {
        io_timeout: Duration::from_millis(config.limits.handshake_timeout_ms),
        idle_timeout: Duration::from_millis(config.limits.idle_timeout_ms),
        max_packetaddr_destinations,
        ..LegacyUdpConfig::default()
    };
    udp.validate().context("invalid legacy UDP limits")?;

    let tls = TlsServerConfig::new(
        *config.reality.private_key,
        config.reality.short_ids.clone(),
        config.reality.server_names.clone(),
        [0, 0, 0],
        [255, 255, 255],
        None,
        cover,
        Duration::from_millis(config.limits.handshake_timeout_ms),
        TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN,
        user_id,
    )
    .context("failed to build the TLS server configuration")?;

    Ok(tls
        .with_xudp(xudp)
        .with_udp(udp)
        .with_relay_idle_timeout(Duration::from_millis(config.limits.idle_timeout_ms)))
}

fn init_logging(level: LogLevel) {
    let env_override = std::env::var_os("RUST_LOG").is_some();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level.as_str()));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .init();
    if env_override {
        tracing::warn!("RUST_LOG is set and overrides the configured log level");
    }
    if matches!(level, LogLevel::Debug | LogLevel::Trace) {
        tracing::warn!(
            "diagnostic logging is enabled; peer addresses and destinations may be recorded"
        );
    }
}
