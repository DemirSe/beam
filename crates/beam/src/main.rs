use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
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
use beam_core::xudp::{XudpConfig, XudpSessionLimiter};

use clap::Parser;
use tokio::net::{TcpListener, TcpSocket};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tokio::time::{Instant, sleep};

/// Five minutes tolerates ordinary NTP skew while closing the replay window
/// left when the cache expires.
const REALITY_TIMESTAMP_WINDOW: Duration = Duration::from_secs(300);

/// Exact-replay entries remembered per configured authenticated connection.
const REPLAY_CAPACITY_PER_CONNECTION: usize = 64;
const REPLAY_CAPACITY_MIN: usize = 4_096;
const REPLAY_CAPACITY_MAX: usize = 65_536;

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("BEAM_GIT_HASH"), ")");

/// Bounds the exact-replay cache for the configured connection pool.
///
/// The README promises `max_connections * 64` bounded to 4096..65536. A full
/// cache rejects new authenticated handshakes instead of evicting a live id.
fn replay_capacity(max_connections: u32) -> usize {
    usize::try_from(max_connections)
        .unwrap_or(usize::MAX)
        .saturating_mul(REPLAY_CAPACITY_PER_CONNECTION)
        .clamp(REPLAY_CAPACITY_MIN, REPLAY_CAPACITY_MAX)
}

/// High-performance VLESS + REALITY + Vision server.
#[derive(Debug, Parser)]
#[command(name = "beam", version = VERSION, about)]
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
    // The default covers about 60 fully spliced relay pairs (120 splice
    // permits); max_connections is an admission cap, not a promise of 1024
    // concurrent bulk relays. Directions above the splice cap use the async
    // copy path. Operators can raise the pool for a burst-heavy host without
    // changing the admission limit.
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
    // The service unit owns the runtime limit (64K). A user-shell `--check`
    // or a lab install may inherit a smaller soft limit; validate against the
    // deployment floor and make the mismatch visible instead of rejecting a
    // configuration that the service can serve.
    const DEPLOYMENT_FD_FLOOR: u64 = 65_536;
    let actual_fd_limit = beam_sys::open_file_limit().unwrap_or(DEPLOYMENT_FD_FLOOR);
    if actual_fd_limit < DEPLOYMENT_FD_FLOOR {
        tracing::warn!(
            actual_fd_limit,
            deployment_floor = DEPLOYMENT_FD_FLOOR,
            "process soft fd limit is below the deployment floor; validate the service limit"
        );
    }
    config
        .validate_fd_budget(actual_fd_limit.max(DEPLOYMENT_FD_FLOOR))
        .context("file descriptor budget")?;
    if let Ok(raw) = std::env::var("BEAM_MAX_BLOCKING_THREADS") {
        let valid = raw
            .parse::<usize>()
            .ok()
            .is_some_and(|value| (1..=512).contains(&value));
        if !valid {
            tracing::warn!(
                value = %raw,
                effective = max_blocking_threads,
                "invalid BEAM_MAX_BLOCKING_THREADS; using the default"
            );
        }
    }
    warn_if_config_permissions_are_loose(&cli.config);

    if cli.check {
        // `validate_limits` covers syntax and scalar bounds; constructing the
        // same runtime configuration catches derived failures (XUDP/legacy
        // limits, TLS material) before systemd's ExecStartPre says OK and the
        // real start crash-loops. This performs no bind or network I/O.
        build_tls_config(&config)?;
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
    if config.limits.max_preauth_per_ip != max_preauth_per_ip {
        tracing::warn!(
            configured = config.limits.max_preauth_per_ip,
            effective = max_preauth_per_ip,
            "max_preauth_per_ip clamped to the pre-auth slot count"
        );
    }
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
    let metrics = tls_config.metrics();
    let xudp_limiter = tls_config.xudp_limiter();

    tracing::info!(
        version = VERSION,
        listen = %config.server.listen,
        max_connections,
        max_pending_handshakes,
        max_preauth_per_ip,
        max_xudp_sessions = config.limits.max_xudp_sessions,
        listen_backlog = config.limits.listen_backlog,
        shutdown_drain_ms = config.limits.shutdown_drain_ms,
        "beam listening"
    );

    let metrics_task = Arc::clone(&metrics);
    let preauth_gauge = Arc::clone(&preauth);
    let authenticated_gauge = Arc::clone(&authenticated);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last = metrics_task.snapshot();
        let mut last_preauth_active =
            max_pending_handshakes.saturating_sub(preauth_gauge.available_permits());
        let mut last_authenticated_active =
            max_connections.saturating_sub(authenticated_gauge.available_permits());
        let mut last_xudp = xudp_limiter.stats();
        let mut last_pressure = pressure_counters(&last);
        loop {
            ticker.tick().await;
            let current = metrics_task.snapshot();
            let preauth_active =
                max_pending_handshakes.saturating_sub(preauth_gauge.available_permits());
            let authenticated_active =
                max_connections.saturating_sub(authenticated_gauge.available_permits());
            let xudp = xudp_limiter.stats();
            let pressure = pressure_counters(&current);
            if pressure != last_pressure {
                // Keep a visible trace at the production `warn` level. The
                // full counter line is info-only, so without this a DNS burst
                // could reject traffic without any journal entry an operator
                // sees by default.
                tracing::warn!(
                    preauth_rejected = pressure.0.saturating_sub(last_pressure.0),
                    cover_limited = pressure.1.saturating_sub(last_pressure.1),
                    connection_limited = pressure.2.saturating_sub(last_pressure.2),
                    xudp_rejected_per_stream = pressure.3.saturating_sub(last_pressure.3),
                    xudp_rejected_global = pressure.4.saturating_sub(last_pressure.4),
                    xudp_end_dropped = pressure.5.saturating_sub(last_pressure.5),
                    xudp_replies_dropped = pressure.6.saturating_sub(last_pressure.6),
                    legacy_udp_limited = pressure.7.saturating_sub(last_pressure.7),
                    xudp_high_water = xudp.high_water,
                    preauth_active,
                    authenticated_active,
                    "runtime pressure counters increased"
                );
                last_pressure = pressure;
            }
            if current != last
                || preauth_active != last_preauth_active
                || authenticated_active != last_authenticated_active
                || xudp != last_xudp
            {
                tracing::info!(
                    preauth_rejected = current.preauth_rejected,
                    cover_limited = current.cover_limited,
                    connection_limited = current.connection_limited,
                    accept_errors = current.accept_errors,
                    xudp_rejected_per_stream = current.xudp_rejected_per_stream,
                    xudp_rejected_global = current.xudp_rejected_global,
                    xudp_retained_evicted = current.xudp_retained_evicted,
                    xudp_replies_dropped = current.xudp_replies_dropped,
                    xudp_end_dropped = current.xudp_end_dropped,
                    legacy_udp_limited = current.legacy_udp_limited,
                    splice_fallback = current.splice_fallback,
                    xudp_new_frames = current.xudp_new_frames,
                    xudp_new_global_id = current.xudp_new_global_id,
                    xudp_end_frames = current.xudp_end_frames,
                    xudp_admitted_fresh = current.xudp_admitted_fresh,
                    xudp_admitted_reattach = current.xudp_admitted_reattach,
                    xudp_closed_end = current.xudp_closed_end,
                    xudp_closed_idle = current.xudp_closed_idle,
                    xudp_closed_error = current.xudp_closed_error,
                    xudp_closed_mux = current.xudp_closed_mux,
                    xudp_retained_inserted = current.xudp_retained_inserted,
                    xudp_retained_reattached = current.xudp_retained_reattached,
                    xudp_retained_expired = current.xudp_retained_expired,
                    xudp_retained_discarded = current.xudp_retained_discarded,
                    xudp_active = xudp.active,
                    xudp_retained = xudp.retained,
                    xudp_live_tables = xudp.live_tables,
                    xudp_live_handlers = xudp.live_handlers,
                    xudp_used = xudp.used,
                    xudp_available = xudp.available,
                    xudp_high_water = xudp.high_water,
                    xudp_unattributed = xudp.unattributed,
                    preauth_active,
                    authenticated_active,
                    "runtime counters"
                );
                last = current;
                last_preauth_active = preauth_active;
                last_authenticated_active = authenticated_active;
                last_xudp = xudp;
            }
        }
    });

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
                metrics.record_accept_error();
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
                metrics.record_preauth_rejection();
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
    let deadline = Instant::now() + Duration::from_millis(config.limits.shutdown_drain_ms);
    while authenticated.available_permits() < max_connections
        || preauth.available_permits() < max_pending_handshakes
        || tls_config.cover_inflight() > 0
    {
        if Instant::now() >= deadline {
            tracing::warn!(
                authenticated_remaining = max_connections - authenticated.available_permits(),
                preauth_remaining = max_pending_handshakes - preauth.available_permits(),
                cover_remaining = tls_config.cover_inflight(),
                "shutdown drain deadline reached; closing remaining connections"
            );
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    tracing::info!("shutdown complete");
    Ok(())
}

/// Warns when the secrets-bearing config is readable by unrelated users or
/// writable by a non-owner group. Production uses root:beam 0640.
fn warn_if_config_permissions_are_loose(path: &std::path::Path) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o007 != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = format!("{mode:03o}"),
            "config file is readable by other users; use root:beam 0640"
        );
    } else if mode & 0o020 != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = format!("{mode:03o}"),
            "config file is group-writable; use root:beam 0640"
        );
    }
}

/// Counters that indicate dropped or rejected traffic, in log order.
fn pressure_counters(
    snapshot: &beam_core::metrics::MetricsSnapshot,
) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        snapshot.preauth_rejected,
        snapshot.cover_limited,
        snapshot.connection_limited,
        snapshot.xudp_rejected_per_stream,
        snapshot.xudp_rejected_global,
        snapshot.xudp_end_dropped,
        snapshot.xudp_replies_dropped,
        snapshot.legacy_udp_limited,
    )
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
        // stale UDP sessions consume the process-wide global session cap. Cap the UDP
        // session idle clock independently; the TCP relay timeout is unchanged.
        session_idle_timeout: Duration::from_millis(config.limits.idle_timeout_ms)
            .min(Duration::from_secs(60)),
        io_timeout: Duration::from_millis(config.limits.handshake_timeout_ms),
        // A single HTTP/3 body can arrive as hundreds of UDP datagrams while
        // the outer TCP stream drains. Keep a larger bounded reply queue so a
        // short client-side pause does not turn into QUIC packet loss.
        max_queued_replies: 512,
        udp_recv_buffer: usize::try_from(config.limits.xudp_recv_buffer_bytes)
            .unwrap_or(usize::MAX)
            .clamp(16 * 1024, 4 * 1024 * 1024),
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
        Some(REALITY_TIMESTAMP_WINDOW),
        cover,
        Duration::from_millis(config.limits.handshake_timeout_ms),
        TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN,
        user_id,
    )
    .context("failed to build the TLS server configuration")?;
    let metrics = tls.metrics();

    Ok(tls
        .with_replay_capacity(replay_capacity(config.limits.max_connections))
        .with_xudp(xudp)
        .with_xudp_limiter(
            XudpSessionLimiter::new(
                usize::try_from(config.limits.max_xudp_sessions).unwrap_or(usize::MAX),
            )
            .with_metrics(metrics),
        )
        .with_udp(udp)
        .with_relay_idle_timeout(Duration::from_millis(config.limits.idle_timeout_ms)))
}

fn init_logging(level: LogLevel) {
    let env_override = std::env::var_os("RUST_LOG").is_some();
    let (filter, env_error) = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => (filter, None),
        Err(error) if env_override => (
            tracing_subscriber::EnvFilter::new(level.as_str()),
            Some(error),
        ),
        Err(_) => (tracing_subscriber::EnvFilter::new(level.as_str()), None),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .init();
    if let Some(error) = env_error {
        tracing::warn!(%error, "invalid RUST_LOG; using the configured log level");
    } else if env_override {
        tracing::warn!("RUST_LOG is set and overrides the configured log level");
    }
    if matches!(level, LogLevel::Debug | LogLevel::Trace) {
        tracing::warn!(
            "diagnostic logging is enabled; peer addresses and destinations may be recorded"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_capacity_bounds_the_configured_pool() {
        assert_eq!(replay_capacity(1), REPLAY_CAPACITY_MIN);
        assert_eq!(replay_capacity(1024), REPLAY_CAPACITY_MAX);
        assert_eq!(replay_capacity(2000), REPLAY_CAPACITY_MAX);
        assert_eq!(replay_capacity(64), 4096);
        assert_eq!(replay_capacity(100), 6400);
    }
}
