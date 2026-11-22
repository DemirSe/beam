use std::ffi::OsString;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

mod generate;

use anyhow::Context;
use beam_core::address::{Address, NetLocation};
use beam_core::admission::IpLimiter;
use beam_core::config::{Config, LogLevel, format_path};
use beam_core::tls::{
    MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN, TlsServerConfig, handle_connection_admitted,
};
use beam_core::udp::LegacyUdpConfig;
use beam_core::xudp::{XudpConfig, XudpSessionLimiter};

use clap::{Parser, Subcommand};
use tokio::net::{TcpListener, TcpSocket};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::Semaphore;
use tokio::time::{Instant, sleep};

/// Five minutes tolerates ordinary NTP skew while closing the replay window
/// left when the cache expires.
const REALITY_TIMESTAMP_WINDOW: Duration = Duration::from_secs(300);

/// Exact-replay entries remembered per configured authenticated connection.
const REPLAY_CAPACITY_PER_CONNECTION: usize = 128;
const REPLAY_CAPACITY_MIN: usize = 4_096;
const REPLAY_CAPACITY_MAX: usize = 131_072;

/// Accept backoff after a successful accept, and after a failure.
const ACCEPT_BACKOFF_START: Duration = Duration::from_millis(10);
const ACCEPT_BACKOFF_LIMIT: Duration = Duration::from_secs(1);

/// Upper bound for the UDP idle clock on both the XUDP and legacy paths.
///
/// Xray/sing-box clients close a UDP flow with the TCP stream, not with an `End`
/// frame, so they keep the stream open for their own UDP NAT timeout (sing-box:
/// 300 s). The TCP idle timeout therefore overstates how long a UDP flow is
/// useful, and the permit or session slot it holds outlives the traffic.
const MAX_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Upper bound for UDP bind, resolve, write, and shutdown waits.
const MAX_UDP_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Floor that keeps the shortest valid idle timeout from truncating UDP I/O.
const MIN_UDP_IO_TIMEOUT: Duration = Duration::from_secs(1);

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("BEAM_GIT_HASH"), ")");

/// Identity values published in `config.example.toml`.
///
/// Startup and `--check` name the fields that still hold them, so a copied
/// sample is not mistaken for a deployment-ready identity. Both values are
/// public test data; the warning prints field names only.
const SAMPLE_PRIVATE_KEY: [u8; 32] = [0x5a; 32];
const SAMPLE_SHORT_ID: &str = "0123456789abcdef";

/// Default Tokio blocking thread pool size when `BEAM_MAX_BLOCKING_THREADS` is
/// unset or invalid.
const DEFAULT_MAX_BLOCKING_THREADS: usize = 160;
const MIN_MAX_BLOCKING_THREADS: usize = 1;
const MAX_MAX_BLOCKING_THREADS: usize = 512;

/// Fallback soft pipe-page limit used when `/proc/sys/fs/pipe-user-pages-soft`
/// cannot be read or parsed.
const DEFAULT_PIPE_USER_PAGES_SOFT: u64 = 16_384;

/// Fallback page size used when `sysconf(_SC_PAGESIZE)` fails.
const DEFAULT_PAGE_SIZE: u64 = 4096;

/// Reason `BEAM_MAX_BLOCKING_THREADS` fell back to the default.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BlockingThreadsFallback {
    NotUtf8,
    Invalid(String),
}

/// Parses `BEAM_MAX_BLOCKING_THREADS` once so runtime creation and startup
/// diagnostics always agree, including on non-UTF-8 values.
fn parse_max_blocking_threads(raw: Option<OsString>) -> (usize, Option<BlockingThreadsFallback>) {
    let Some(raw) = raw else {
        return (DEFAULT_MAX_BLOCKING_THREADS, None);
    };
    let Ok(text) = raw.into_string() else {
        return (
            DEFAULT_MAX_BLOCKING_THREADS,
            Some(BlockingThreadsFallback::NotUtf8),
        );
    };
    match text.parse::<usize>() {
        Ok(value) if (MIN_MAX_BLOCKING_THREADS..=MAX_MAX_BLOCKING_THREADS).contains(&value) => {
            (value, None)
        }
        _ => (
            DEFAULT_MAX_BLOCKING_THREADS,
            Some(BlockingThreadsFallback::Invalid(text)),
        ),
    }
}

/// Computes the effective per-mux XUDP active session cap and identifies which
/// configured limit binds it (`max_xudp_sessions`, `max_udp_destinations`, or
/// `both`).
fn effective_xudp_per_mux_limit(
    max_xudp_sessions: u32,
    max_udp_destinations: u32,
) -> (usize, &'static str) {
    let global_half = (usize::try_from(max_xudp_sessions).unwrap_or(usize::MAX) / 2).max(1);
    let per_mux_table = usize::try_from(max_udp_destinations)
        .unwrap_or(usize::MAX)
        .clamp(1, usize::from(u16::MAX) + 1);
    let effective = global_half.min(per_mux_table);
    let binding = if per_mux_table < global_half {
        "max_udp_destinations"
    } else if global_half < per_mux_table {
        "max_xudp_sessions"
    } else {
        "both"
    };
    (effective, binding)
}

/// Computes the effective pre-auth slot count and per-IP pre-auth cap shared
/// between `--check` and server startup.
fn preauth_limits(max_connections: u32, configured_max_preauth_per_ip: u32) -> (usize, u32) {
    let max_pending_handshakes = (max_connections as usize).clamp(16, 256);
    let effective_max_preauth_per_ip =
        configured_max_preauth_per_ip.min(max_pending_handshakes as u32);
    (max_pending_handshakes, effective_max_preauth_per_ip)
}

/// Resolves the soft pipe-page limit and identifies whether it came from
/// sysctl or the fallback default.
fn resolve_pipe_pages_soft(measured: Option<u64>) -> (u64, &'static str) {
    match measured {
        Some(pages) => (pages, "sysctl"),
        None => (DEFAULT_PIPE_USER_PAGES_SOFT, "fallback"),
    }
}

/// Resolves the kernel page size and identifies whether it came from sysconf
/// or the 4 KiB fallback default.
fn resolve_page_size(measured: Option<u64>) -> (u64, &'static str) {
    match measured {
        Some(size) => (size, "sysconf"),
        None => (DEFAULT_PAGE_SIZE, "fallback"),
    }
}

/// Bounds the exact-replay cache for the configured connection pool.
///
/// The README promises `max_connections * 128` bounded to 4096..131072. A full
/// cache rejects new authenticated handshakes instead of evicting a live id.
fn replay_capacity(max_connections: u32) -> usize {
    usize::try_from(max_connections)
        .unwrap_or(usize::MAX)
        .saturating_mul(REPLAY_CAPACITY_PER_CONNECTION)
        .clamp(REPLAY_CAPACITY_MIN, REPLAY_CAPACITY_MAX)
}

/// Bounds the legacy/packetaddr VLESS UDP stream pool.
///
/// A stub resolver opens one UDP socket per query, and each socket costs one
/// VLESS stream plus one or two relay sockets, so a burst of short DNS flows is
/// ordinary traffic on this path. Size the pool from the configured UDP socket
/// budget (`max_xudp_sessions`) instead of a literal, so compatibility mode is
/// not refused while the XUDP path is idle.
fn legacy_udp_stream_limit(max_xudp_sessions: u32) -> usize {
    usize::try_from(max_xudp_sessions)
        .unwrap_or(usize::MAX)
        .max(1)
}

/// Caps the UDP idle clock without changing the TCP relay idle timeout.
fn udp_idle_clock(idle_timeout_ms: u64) -> Duration {
    Duration::from_millis(idle_timeout_ms).min(MAX_UDP_IDLE_TIMEOUT)
}

/// Derives the UDP I/O deadline independently of the TLS handshake deadline.
///
/// 30 s is half the 60 s UDP idle cap, so a stalled I/O wait cannot outlive a
/// usable flow; 1 s is the minimum valid configured idle timeout, so a short
/// idle clock cannot truncate an ordinary UDP send or shutdown.
fn udp_io_timeout(idle_timeout_ms: u64) -> Duration {
    Duration::from_millis(idle_timeout_ms)
        .min(MAX_UDP_IO_TIMEOUT)
        .max(MIN_UDP_IO_TIMEOUT)
}

#[cfg(test)]
mod udp_io_timeout_tests {
    use super::*;

    #[test]
    fn udp_io_timeout_is_bounded_for_small_and_large_idle_clocks() {
        assert_eq!(udp_io_timeout(500), MIN_UDP_IO_TIMEOUT);
        assert_eq!(udp_io_timeout(1_000), Duration::from_secs(1));
        assert_eq!(udp_io_timeout(300_000), MAX_UDP_IO_TIMEOUT);
        assert_eq!(udp_io_timeout(86_400_000), MAX_UDP_IO_TIMEOUT);
    }
}

/// High-performance VLESS + REALITY + Vision server.
#[derive(Debug, Parser)]
#[command(name = "beam", version = VERSION, about, args_conflicts_with_subcommands = true)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/beam/config.toml")]
    config: PathBuf,

    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a UUID, REALITY keypair, short id, and client VLESS link.
    Generate(generate::GenerateArgs),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(Command::Generate(args)) = &cli.command {
        return generate::run(args);
    }
    // Each Vision Direct relay can occupy up to two blocking splice tasks.
    // The default covers about 60 fully spliced relay pairs (120 splice
    // permits); max_connections is an admission cap, not a promise of 1024
    // concurrent bulk relays. Directions above the splice cap use the async
    // copy path. Operators can raise the pool for a burst-heavy host without
    // changing the admission limit.
    let (max_blocking_threads, blocking_threads_fallback) =
        parse_max_blocking_threads(std::env::var_os("BEAM_MAX_BLOCKING_THREADS"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(max_blocking_threads)
        .enable_all()
        .build()
        .context("failed to build the Tokio runtime")?;
    let result = runtime.block_on(async_main(
        cli,
        max_blocking_threads,
        blocking_threads_fallback,
    ));
    // A blocking splice cannot be aborted once it has started. The shutdown
    // path drains normal connections briefly; this bound is the final backstop
    // for a wedged relay so systemd can restart the service.
    runtime.shutdown_timeout(Duration::from_secs(3));
    result
}

async fn async_main(
    cli: Cli,
    max_blocking_threads: usize,
    blocking_threads_fallback: Option<BlockingThreadsFallback>,
) -> anyhow::Result<()> {
    // Install SIGHUP before any blocking startup work so an operator's hangup
    // cannot kill the service mid-start. SIGTERM and SIGINT keep their default
    // disposition until the accept loop can observe them, so a stuck config
    // read stays interruptible instead of swallowing the signal.
    let mut sighup = signal(SignalKind::hangup()).context("failed to watch SIGHUP")?;
    tokio::spawn(async move {
        while sighup.recv().await.is_some() {
            tracing::warn!("SIGHUP ignored; restart the service to reload configuration");
        }
    });
    let config_path = format_path(&cli.config);
    let config = Config::from_path(&cli.config)
        .with_context(|| format!("failed to load `{config_path}`"))?;

    init_logging(config.log.level);
    if let Some(fallback) = &blocking_threads_fallback {
        emit_operator_warning(|| match fallback {
            BlockingThreadsFallback::NotUtf8 => tracing::warn!(
                effective = max_blocking_threads,
                "invalid non-UTF-8 BEAM_MAX_BLOCKING_THREADS; using the default"
            ),
            BlockingThreadsFallback::Invalid(raw) => tracing::warn!(
                value = %raw,
                effective = max_blocking_threads,
                min = MIN_MAX_BLOCKING_THREADS,
                max = MAX_MAX_BLOCKING_THREADS,
                "invalid BEAM_MAX_BLOCKING_THREADS; using the default"
            ),
        });
    }
    // The service unit owns the runtime limit (64K). A user-shell `--check`
    // or a lab install may inherit a smaller soft limit; validate against the
    // deployment floor and make the mismatch visible instead of rejecting a
    // configuration that the service can serve.
    let fd_basis = resolve_fd_limit(beam_sys::open_file_limit());
    match &fd_basis.source {
        FdLimitSource::Floored { observed, floor } => {
            tracing::warn!(
                actual_fd_limit = observed,
                deployment_floor = floor,
                "process soft fd limit is below the deployment floor; validate the service limit"
            );
        }
        FdLimitSource::QueryFailed { error, floor } => {
            tracing::warn!(
                %error,
                deployment_floor = floor,
                "could not query the process fd limit; using the deployment floor"
            );
        }
        FdLimitSource::Observed(_) | FdLimitSource::Unlimited => {}
    }
    config
        .validate_fd_budget(fd_basis.effective)
        .with_context(|| format!("file descriptor budget for `{config_path}`"))?;
    warn_if_config_permissions_are_loose(&cli.config);
    // A direct start must warn too: after a successful copy of the example
    // file, the first start would otherwise serve the published sample
    // identity silently.
    warn_if_sample_identity(&config);

    let max_connections = config.limits.max_connections as usize;
    // Pre-auth slots bound ClientHello reads, not data-path relays. Keep this
    // small enough that a scanner flood cannot pin every permit, but large
    // enough for a browser's parallel connection burst.
    let (max_pending_handshakes, max_preauth_per_ip) = preauth_limits(
        config.limits.max_connections,
        config.limits.max_preauth_per_ip,
    );
    if config.limits.max_preauth_per_ip != max_preauth_per_ip {
        tracing::warn!(
            configured = config.limits.max_preauth_per_ip,
            effective = max_preauth_per_ip,
            max_pending_handshakes,
            "max_preauth_per_ip clamped to the pre-auth slot count"
        );
    }
    let (xudp_per_mux_limit, xudp_per_mux_binding) = effective_xudp_per_mux_limit(
        config.limits.max_xudp_sessions,
        config.limits.max_udp_destinations,
    );
    let host_somaxconn = beam_sys::tcp_somaxconn();
    if let Some(cap) = host_somaxconn
        && config.limits.listen_backlog > cap
    {
        tracing::warn!(
            requested = config.limits.listen_backlog,
            host_somaxconn = cap,
            "limits.listen_backlog exceeds host net.core.somaxconn; Linux will cap the active queue"
        );
    }

    if cli.check {
        // `validate_limits` covers syntax and scalar bounds; constructing the
        // same runtime configuration catches derived failures (XUDP/legacy
        // limits, TLS material) before systemd's ExecStartPre says OK and the
        // real start crash-loops. This performs no bind or network I/O.
        build_tls_config(&config)
            .with_context(|| format!("invalid runtime configuration in `{config_path}`"))?;
        let mut stdout = std::io::stdout().lock();
        writeln!(
            stdout,
            "configuration is valid: {config_path} (beam {VERSION}; listener {} not bound)",
            config.server.listen
        )
        .context("could not write configuration check result")?;
        if config.limits.max_preauth_per_ip != max_preauth_per_ip {
            writeln!(
                stdout,
                "effective limits.max_preauth_per_ip: {max_preauth_per_ip} \
                 (configured {}, clamped to {max_pending_handshakes} pre-auth slots)",
                config.limits.max_preauth_per_ip
            )
            .context("could not write configuration check result")?;
        } else {
            writeln!(
                stdout,
                "effective limits.max_preauth_per_ip: {max_preauth_per_ip} \
                 (pre-auth slots: {max_pending_handshakes})"
            )
            .context("could not write configuration check result")?;
        }
        writeln!(stdout, "effective fd budget basis: {}", fd_basis.describe())
            .context("could not write configuration check result")?;
        writeln!(
            stdout,
            "effective xudp per-mux sessions: {xudp_per_mux_limit} \
             (binding limit: {xudp_per_mux_binding}; max_xudp_sessions={}, max_udp_destinations={})",
            config.limits.max_xudp_sessions, config.limits.max_udp_destinations
        )
        .context("could not write configuration check result")?;
        match host_somaxconn {
            Some(cap) if config.limits.listen_backlog > cap => {
                writeln!(
                    stdout,
                    "listen_backlog: requested {} (host net.core.somaxconn cap: {cap}; effective: {cap})",
                    config.limits.listen_backlog
                )
                .context("could not write configuration check result")?;
            }
            Some(cap) => {
                writeln!(
                    stdout,
                    "listen_backlog: requested {} (host net.core.somaxconn cap: {cap})",
                    config.limits.listen_backlog
                )
                .context("could not write configuration check result")?;
            }
            None => {
                writeln!(
                    stdout,
                    "listen_backlog: requested {} (host net.core.somaxconn unreadable)",
                    config.limits.listen_backlog
                )
                .context("could not write configuration check result")?;
            }
        }
        return Ok(());
    }

    let authenticated = Arc::new(Semaphore::new(max_connections));
    let preauth = Arc::new(IpLimiter::new(max_pending_handshakes, max_preauth_per_ip));
    // Leave room in the blocking pool for cover relays, DNS resolution, and
    // destination dials. Vision directions above this cap use the async copy
    // path instead of queueing forever in `spawn_blocking`.
    let measured_pipe_pages_soft = beam_sys::pipe_user_pages_soft();
    let (pipe_pages_soft, soft_pages_source) = resolve_pipe_pages_soft(measured_pipe_pages_soft);
    if measured_pipe_pages_soft.is_none() {
        tracing::warn!(
            soft_pages = pipe_pages_soft,
            soft_pages_source,
            "could not read /proc/sys/fs/pipe-user-pages-soft; using fallback pipe page budget"
        );
    }
    let measured_page_size = beam_sys::query_page_size();
    let (page_size, page_size_source) = resolve_page_size(measured_page_size);
    if measured_page_size.is_none() {
        tracing::warn!(
            page_size,
            page_size_source,
            "could not query sysconf(_SC_PAGESIZE); using fallback page size"
        );
    }
    let requested_splice_tasks = splice_capacity(max_blocking_threads);
    let supported_splice_tasks =
        beam_core::relay::RelayConfig::supported_splice_tasks(pipe_pages_soft, page_size);
    let max_splice_tasks = requested_splice_tasks.min(supported_splice_tasks);
    if max_splice_tasks < requested_splice_tasks {
        tracing::warn!(
            soft_pages = pipe_pages_soft,
            soft_pages_source,
            page_size,
            page_size_source,
            tasks_requested = requested_splice_tasks,
            tasks_used = max_splice_tasks,
            "splice task count clamped by pipe budget"
        );
    }
    let splice_permits = Arc::new(Semaphore::new(max_splice_tasks));
    let relay_pipe_size =
        beam_core::relay::pipe_size_for_budget(pipe_pages_soft, max_splice_tasks, page_size);
    tracing::info!(
        soft_pages = pipe_pages_soft,
        soft_pages_source,
        page_size,
        page_size_source,
        splice_tasks = max_splice_tasks,
        pipe_size = relay_pipe_size,
        "relay pipe budget"
    );
    let tls_config = Arc::new(
        build_tls_config(&config)
            .with_context(|| format!("invalid runtime configuration in `{config_path}`"))?
            .with_connection_limiter(Arc::clone(&authenticated))
            .with_splice_limiter(splice_permits)
            .with_relay_pipe_size(relay_pipe_size),
    );
    let listener = bind_listener(config.server.listen, config.limits.listen_backlog)?;
    let ipv6_only = listener_ipv6_only_label(&listener, config.server.listen);
    let metrics = tls_config.metrics();
    let xudp_limiter = tls_config.xudp_limiter();

    tracing::info!(
        version = VERSION,
        listen = %config.server.listen,
        ipv6_only,
        max_connections,
        max_pending_handshakes,
        max_preauth_per_ip,
        max_xudp_sessions = config.limits.max_xudp_sessions,
        xudp_per_mux_limit,
        xudp_per_mux_binding,
        max_legacy_udp_streams = legacy_udp_stream_limit(config.limits.max_xudp_sessions),
        listen_backlog_requested = config.limits.listen_backlog,
        listen_backlog_host_cap = ?host_somaxconn,
        shutdown_drain_ms = config.limits.shutdown_drain_ms,
        "beam listening"
    );

    let metrics_task = Arc::clone(&metrics);
    let preauth_gauge = Arc::clone(&preauth);
    let authenticated_gauge = Arc::clone(&authenticated);
    let replay_config = Arc::clone(&tls_config);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last = metrics_task.snapshot();
        let mut last_preauth_active =
            max_pending_handshakes.saturating_sub(preauth_gauge.available_permits());
        let mut last_authenticated_active =
            max_connections.saturating_sub(authenticated_gauge.available_permits());
        let mut last_xudp = xudp_limiter.stats();
        let mut last_pressure = PressureCounters::from_snapshot(&last);
        let mut last_replay = replay_config.replay_stats();
        loop {
            ticker.tick().await;
            let current = metrics_task.snapshot();
            let preauth_active =
                max_pending_handshakes.saturating_sub(preauth_gauge.available_permits());
            let authenticated_active =
                max_connections.saturating_sub(authenticated_gauge.available_permits());
            let xudp = xudp_limiter.stats();
            let replay = replay_config.replay_stats();
            let pressure = PressureCounters::from_snapshot(&current);
            if pressure != last_pressure {
                let delta = pressure.delta(last_pressure);
                emit_pressure_warning(
                    delta,
                    replay,
                    xudp.high_water,
                    preauth_active,
                    authenticated_active,
                );
                last_pressure = pressure;
            }
            if current != last
                || preauth_active != last_preauth_active
                || authenticated_active != last_authenticated_active
                || xudp != last_xudp
                || replay != last_replay
            {
                tracing::info!(
                    preauth_rejected = current.preauth_rejected,
                    preauth_rejected_global = current.preauth_rejected_global,
                    preauth_rejected_per_ip = current.preauth_rejected_per_ip,
                    cover_limited = current.cover_limited,
                    cover_limited_global = current.cover_limited_global,
                    cover_limited_per_ip = current.cover_limited_per_ip,
                    connection_limited = current.connection_limited,
                    accept_errors = current.accept_errors,
                    accept_errors_resource = current.accept_errors_resource,
                    xudp_rejected_per_stream = current.xudp_rejected_per_stream,
                    xudp_rejected_global = current.xudp_rejected_global,
                    xudp_retained_evicted = current.xudp_retained_evicted,
                    xudp_replies_dropped = current.xudp_replies_dropped,
                    xudp_send_dropped = current.xudp_send_dropped,
                    xudp_end_dropped = current.xudp_end_dropped,
                    legacy_udp_limited = current.legacy_udp_limited,
                    replay_rejected = current.replay_rejected,
                    replay_cache_full = current.replay_cache_full,
                    replay_cache_entries = replay.entries,
                    replay_in_flight = replay.in_flight,
                    replay_capacity = replay.capacity,
                    splice_fallback = current.splice_fallback,
                    xudp_new_frames = current.xudp_new_frames,
                    xudp_new_global_id = current.xudp_new_global_id,
                    xudp_new_failed = current.xudp_new_failed,
                    xudp_resolution_rejected = current.xudp_resolution_rejected,
                    xudp_end_frames = current.xudp_end_frames,
                    xudp_admitted_fresh = current.xudp_admitted_fresh,
                    xudp_admitted_reattach = current.xudp_admitted_reattach,
                    xudp_closed_end = current.xudp_closed_end,
                    xudp_closed_replaced = current.xudp_closed_replaced,
                    xudp_closed_idle = current.xudp_closed_idle,
                    xudp_closed_error = current.xudp_closed_error,
                    xudp_closed_mux = current.xudp_closed_mux,
                    xudp_retained_inserted = current.xudp_retained_inserted,
                    xudp_retained_reattached = current.xudp_retained_reattached,
                    xudp_retained_expired = current.xudp_retained_expired,
                    xudp_retained_cleared_mux = current.xudp_retained_cleared_mux,
                    xudp_retained_replaced = current.xudp_retained_replaced,
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
                last_replay = replay;
            }
        }
    });

    // Only now, with the listener bound and the accept loop about to select on
    // them, do the termination signals become our responsibility. A signal that
    // arrives earlier keeps the default disposition and ends the process.
    let mut sigterm = signal(SignalKind::terminate()).context("failed to watch SIGTERM")?;
    let mut sigint = signal(SignalKind::interrupt()).context("failed to watch SIGINT")?;

    // A transient fd shortage must not turn into a permanent outage. `accept`
    // can fail with EMFILE/ENFILE, ECONNABORTED, or an interrupted syscall;
    // keep the listener alive and retry with a bounded backoff instead of
    // dropping the runtime (and any in-flight blocking relays) on the first
    // error.
    let mut accept_backoff = ACCEPT_BACKOFF_START;
    let first_signal = loop {
        let accepted = tokio::select! {
            biased;
            signal = termination_signal(&mut sigterm, &mut sigint) => break signal,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => {
                accept_backoff = ACCEPT_BACKOFF_START;
                accepted
            }
            Err(error) => {
                let failure = beam_sys::AcceptError::classify(&error);
                record_accept_failure(&metrics, failure);
                tracing::warn!(
                    %error,
                    reason = failure.as_str(),
                    backoff_ms = accept_backoff.as_millis(),
                    "listener accept failed; retrying"
                );
                tokio::select! {
                    biased;
                    signal = termination_signal(&mut sigterm, &mut sigint) => break signal,
                    _ = sleep(accept_backoff) => {}
                }
                accept_backoff = next_accept_backoff(accept_backoff);
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
                metrics.record_preauth_rejection(reject);
                tracing::debug!(%peer, ?reject, "pre-auth handshake limit reached; dropping");
                drop(stream);
                tokio::task::yield_now().await;
                continue;
            }
        };
        let tls_config = Arc::clone(&tls_config);

        tokio::spawn(async move {
            if let Err(error) = stream.set_nodelay(true) {
                warn_socket_option_once(&TCP_NODELAY_WARNED, &error, "TCP_NODELAY", peer);
            }
            if let Err(error) = beam_sys::set_tcp_keepalive(
                stream.as_raw_fd(),
                Duration::from_secs(60),
                Duration::from_secs(15),
            ) {
                warn_socket_option_once(&TCP_KEEPALIVE_WARNED, &error, "TCP keepalive", peer);
            }

            match handle_connection_admitted(stream, tls_config, Some(preauth_permit)).await {
                Ok(outcome) => tracing::debug!(%peer, ?outcome, "connection finished"),
                Err(error) => tracing::debug!(%peer, %error, "connection failed"),
            }
        });
    };
    // Stop accepting immediately, then let established connections finish.
    drop(listener);
    tracing::info!(
        signal = first_signal,
        "shutdown signal received; draining connections"
    );
    let deadline = Instant::now() + Duration::from_millis(config.limits.shutdown_drain_ms);
    let remaining = || {
        // A worker takes its authenticated or cover permit before it releases
        // pre-auth. Read the predecessor first to avoid missing that handoff.
        preauth.available_permits() < max_pending_handshakes
            || authenticated.available_permits() < max_connections
            || tls_config.cover_inflight() > 0
    };
    match drain_connections(
        deadline,
        remaining,
        termination_signal(&mut sigterm, &mut sigint),
    )
    .await
    {
        DrainOutcome::Complete => tracing::info!("shutdown drain complete"),
        DrainOutcome::Deadline => tracing::warn!(
            authenticated_remaining = max_connections - authenticated.available_permits(),
            preauth_remaining = max_pending_handshakes - preauth.available_permits(),
            cover_remaining = tls_config.cover_inflight(),
            "shutdown drain deadline reached; starting runtime shutdown"
        ),
        DrainOutcome::Signal(signal) => tracing::warn!(
            signal,
            "second shutdown signal received; starting runtime shutdown"
        ),
    }
    Ok(())
}

async fn termination_signal(sigterm: &mut Signal, sigint: &mut Signal) -> &'static str {
    tokio::select! {
        _ = sigterm.recv() => "SIGTERM",
        _ = sigint.recv() => "SIGINT",
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DrainOutcome {
    Complete,
    Deadline,
    Signal(&'static str),
}

async fn drain_connections(
    deadline: Instant,
    remaining: impl Fn() -> bool,
    termination: impl Future<Output = &'static str>,
) -> DrainOutcome {
    tokio::pin!(termination);
    while remaining() {
        tokio::select! {
            biased;
            signal = &mut termination => return DrainOutcome::Signal(signal),
            _ = tokio::time::sleep_until(deadline) => return DrainOutcome::Deadline,
            _ = sleep(Duration::from_millis(50)) => {}
        }
    }
    DrainOutcome::Complete
}

fn splice_capacity(blocking_threads: usize) -> usize {
    blocking_threads.saturating_sub(40)
}

const DEPLOYMENT_FD_FLOOR: u64 = 65_536;

/// How the file-descriptor budget validation limit was derived.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FdLimitSource {
    Unlimited,
    Observed(u64),
    Floored { observed: u64, floor: u64 },
    QueryFailed { error: String, floor: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FdLimitBasis {
    effective: u64,
    source: FdLimitSource,
}

impl FdLimitBasis {
    fn describe(&self) -> String {
        match &self.source {
            FdLimitSource::Unlimited => {
                "unlimited (observed process soft RLIMIT_NOFILE)".to_owned()
            }
            FdLimitSource::Observed(observed) => {
                format!("{observed} (observed process soft RLIMIT_NOFILE)")
            }
            FdLimitSource::Floored { observed, floor } => format!(
                "{floor} (deployment floor; observed process soft RLIMIT_NOFILE is {observed})"
            ),
            FdLimitSource::QueryFailed { error, floor } => format!(
                "{floor} (deployment floor; could not query process soft RLIMIT_NOFILE: {error})"
            ),
        }
    }
}

fn resolve_fd_limit(soft_limit: std::io::Result<Option<u64>>) -> FdLimitBasis {
    match soft_limit {
        Ok(None) => FdLimitBasis {
            effective: u64::MAX,
            source: FdLimitSource::Unlimited,
        },
        Ok(Some(observed)) if observed < DEPLOYMENT_FD_FLOOR => FdLimitBasis {
            effective: DEPLOYMENT_FD_FLOOR,
            source: FdLimitSource::Floored {
                observed,
                floor: DEPLOYMENT_FD_FLOOR,
            },
        },
        Ok(Some(observed)) => FdLimitBasis {
            effective: observed,
            source: FdLimitSource::Observed(observed),
        },
        Err(error) => FdLimitBasis {
            effective: DEPLOYMENT_FD_FLOOR,
            source: FdLimitSource::QueryFailed {
                error: error.to_string(),
                floor: DEPLOYMENT_FD_FLOOR,
            },
        },
    }
}

/// Emits one operator-facing startup warning on stderr using a scoped WARN
/// subscriber so a restrictive `RUST_LOG` or `[log] level = "error"` cannot
/// suppress critical startup notices. Best-effort: a closed or full stderr
/// never panics or turns into a startup failure.
fn emit_operator_warning(emit: impl FnOnce()) {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .log_internal_errors(false)
        .finish();
    tracing::subscriber::with_default(subscriber, emit);
}

fn listener_ipv6_only_label(listener: &TcpListener, address: SocketAddr) -> &'static str {
    if !address.is_ipv6() {
        return "n/a";
    }
    match beam_sys::get_ipv6_v6only(listener.as_raw_fd()) {
        Ok(true) => "true",
        Ok(false) => "false",
        Err(_) => "unknown",
    }
}

/// Returns the identity fields that still hold the published sample values.
fn sample_identity_fields(config: &Config) -> Vec<String> {
    let mut fields = Vec::new();
    if config.user.id.is_nil() {
        fields.push("user.id".to_owned());
    }
    // X25519 clamping ignores the low three bits and fixes the top two bits.
    // Compare every effective key bit without copying the secret.
    let key_difference = config
        .reality
        .private_key
        .iter()
        .zip(SAMPLE_PRIVATE_KEY)
        .enumerate()
        .fold(0u8, |difference, (index, (actual, sample))| {
            let mask = match index {
                0 => 0xf8,
                31 => 0x3f,
                _ => 0xff,
            };
            difference | ((actual ^ sample) & mask)
        });
    if key_difference == 0 {
        fields.push("reality.private_key".to_owned());
    }
    for (index, short_id) in config.reality.short_ids.iter().enumerate() {
        if short_id.eq_ignore_ascii_case(SAMPLE_SHORT_ID) {
            fields.push(format!("reality.short_ids[{index}]"));
        }
    }
    fields
}

/// Names the unchanged sample identity on stderr.
///
/// A scoped subscriber reaches stderr even under `RUST_LOG=off` or `error`,
/// without changing the process-wide logging configuration. The write stays
/// best effort: the sample identity is valid, so a closed or full stderr must
/// not turn this warning into a startup or check failure. The fmt layer's
/// failed-write fallback is `eprintln!`, which panics on such a stderr, so it
/// is disabled here.
fn warn_if_sample_identity(config: &Config) {
    let fields = sample_identity_fields(config);
    if fields.is_empty() {
        return;
    }
    emit_operator_warning(|| {
        tracing::warn!(
            fields = %fields.join(", "),
            "sample identity values are unchanged; replace them before deployment"
        );
    });
}

/// Warns when the config mode lets other users access the secrets-bearing
/// file or lets the file's group write it.
///
/// Only mode bits are inspected. Ownership is left to the operator because the
/// service unit can use a custom owner or group; this check is not proof of the
/// documented `root:beam 0640` deployment layout.
fn warn_if_config_permissions_are_loose(path: &std::path::Path) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    let mode = metadata.permissions().mode();
    let Some(reason) = loose_config_mode(mode) else {
        return;
    };
    tracing::warn!(
        path = %format_path(path),
        mode = format!("{:03o}", mode & 0o777),
        "config file {reason}; only mode bits are checked, verify the owner and group separately"
    );
}

/// Reason a config file mode is too loose for a secrets-bearing file.
///
/// Group read is not reported because group access is a deployment choice
/// (`root:beam 0640`). Other-user access covers read, write, and execute, and
/// group write is reported separately because the file's group can then change
/// the config.
///
/// `permissions().mode()` also carries the file-type bits, which the masks
/// below cannot match because they sit above the low mode bits.
fn loose_config_mode(mode: u32) -> Option<&'static str> {
    if mode & 0o007 != 0 {
        Some("is accessible to other users; use 0600, or 0640 with a trusted group")
    } else if mode & 0o020 != 0 {
        Some("is group-writable; use 0600, or 0640 with a trusted group")
    } else {
        None
    }
}

/// Returns the next accept backoff, bounded so a persistent failure keeps
/// retrying at one attempt per second instead of spinning.
fn next_accept_backoff(current: Duration) -> Duration {
    (current * 2).min(ACCEPT_BACKOFF_LIMIT)
}

/// Counts one accept failure, isolating a resource shortage from a failure
/// that applies to one connection.
fn record_accept_failure(metrics: &beam_core::metrics::Metrics, failure: beam_sys::AcceptError) {
    metrics.record_accept_error(failure == beam_sys::AcceptError::ResourceShortage);
}

/// Warns once per process about a socket option that could not be applied.
///
/// The option is tuning, not correctness, so the connection continues. Warning
/// on every connection would flood the log when the kernel or a seccomp policy
/// rejects the option for all of them. Each option has its own flag, so one
/// failing option does not demote a different option that fails later.
static TCP_NODELAY_WARNED: AtomicBool = AtomicBool::new(false);
static TCP_KEEPALIVE_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_socket_option_once(
    warned: &AtomicBool,
    error: &std::io::Error,
    option: &'static str,
    peer: SocketAddr,
) {
    if warned.swap(true, Ordering::Relaxed) {
        tracing::debug!(%peer, %error, option, "could not apply a socket option");
    } else {
        tracing::warn!(
            %peer,
            %error,
            option,
            "could not apply a socket option; relay tuning is degraded"
        );
    }
}

/// Named snapshot of counters surfaced by the periodic warn-level summary.
///
/// Using named fields prevents positional transposition between `MetricsSnapshot`
/// and the `tracing::warn!` fields. `splice_fallback` is tracked alongside
/// pressure counters so operators see fallback activity at the default `warn`
/// level, even though not every fallback indicates resource exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct PressureCounters {
    preauth_rejected: u64,
    preauth_rejected_global: u64,
    preauth_rejected_per_ip: u64,
    cover_limited: u64,
    cover_limited_global: u64,
    cover_limited_per_ip: u64,
    connection_limited: u64,
    xudp_rejected_per_stream: u64,
    xudp_rejected_global: u64,
    xudp_end_dropped: u64,
    xudp_replies_dropped: u64,
    xudp_send_dropped: u64,
    legacy_udp_limited: u64,
    replay_rejected: u64,
    replay_cache_full: u64,
    xudp_resolution_rejected: u64,
    splice_fallback: u64,
}

impl PressureCounters {
    fn from_snapshot(snapshot: &beam_core::metrics::MetricsSnapshot) -> Self {
        Self {
            preauth_rejected: snapshot.preauth_rejected,
            preauth_rejected_global: snapshot.preauth_rejected_global,
            preauth_rejected_per_ip: snapshot.preauth_rejected_per_ip,
            cover_limited: snapshot.cover_limited,
            cover_limited_global: snapshot.cover_limited_global,
            cover_limited_per_ip: snapshot.cover_limited_per_ip,
            connection_limited: snapshot.connection_limited,
            xudp_rejected_per_stream: snapshot.xudp_rejected_per_stream,
            xudp_rejected_global: snapshot.xudp_rejected_global,
            xudp_end_dropped: snapshot.xudp_end_dropped,
            xudp_replies_dropped: snapshot.xudp_replies_dropped,
            xudp_send_dropped: snapshot.xudp_send_dropped,
            legacy_udp_limited: snapshot.legacy_udp_limited,
            replay_rejected: snapshot.replay_rejected,
            replay_cache_full: snapshot.replay_cache_full,
            xudp_resolution_rejected: snapshot.xudp_resolution_rejected,
            splice_fallback: snapshot.splice_fallback,
        }
    }

    fn delta(self, previous: Self) -> Self {
        Self {
            preauth_rejected: self
                .preauth_rejected
                .saturating_sub(previous.preauth_rejected),
            preauth_rejected_global: self
                .preauth_rejected_global
                .saturating_sub(previous.preauth_rejected_global),
            preauth_rejected_per_ip: self
                .preauth_rejected_per_ip
                .saturating_sub(previous.preauth_rejected_per_ip),
            cover_limited: self.cover_limited.saturating_sub(previous.cover_limited),
            cover_limited_global: self
                .cover_limited_global
                .saturating_sub(previous.cover_limited_global),
            cover_limited_per_ip: self
                .cover_limited_per_ip
                .saturating_sub(previous.cover_limited_per_ip),
            connection_limited: self
                .connection_limited
                .saturating_sub(previous.connection_limited),
            xudp_rejected_per_stream: self
                .xudp_rejected_per_stream
                .saturating_sub(previous.xudp_rejected_per_stream),
            xudp_rejected_global: self
                .xudp_rejected_global
                .saturating_sub(previous.xudp_rejected_global),
            xudp_end_dropped: self
                .xudp_end_dropped
                .saturating_sub(previous.xudp_end_dropped),
            xudp_replies_dropped: self
                .xudp_replies_dropped
                .saturating_sub(previous.xudp_replies_dropped),
            xudp_send_dropped: self
                .xudp_send_dropped
                .saturating_sub(previous.xudp_send_dropped),
            legacy_udp_limited: self
                .legacy_udp_limited
                .saturating_sub(previous.legacy_udp_limited),
            replay_rejected: self
                .replay_rejected
                .saturating_sub(previous.replay_rejected),
            replay_cache_full: self
                .replay_cache_full
                .saturating_sub(previous.replay_cache_full),
            xudp_resolution_rejected: self
                .xudp_resolution_rejected
                .saturating_sub(previous.xudp_resolution_rejected),
            splice_fallback: self
                .splice_fallback
                .saturating_sub(previous.splice_fallback),
        }
    }
}

/// Emits the periodic warn-level summary for counter deltas and gauges.
///
/// The full counter line is info-only, so without this a DNS burst, replay
/// pressure, or splice fallback could happen without any journal entry an
/// operator sees at the default `warn` level. `splice_fallback` can also occur
/// when a descriptor cannot be duplicated and does not always mean resource
/// exhaustion.
fn emit_pressure_warning(
    delta: PressureCounters,
    replay: beam_core::tls::ReplayStats,
    xudp_high_water: usize,
    preauth_active: usize,
    authenticated_active: usize,
) {
    tracing::warn!(
        preauth_rejected = delta.preauth_rejected,
        preauth_rejected_global = delta.preauth_rejected_global,
        preauth_rejected_per_ip = delta.preauth_rejected_per_ip,
        cover_limited = delta.cover_limited,
        cover_limited_global = delta.cover_limited_global,
        cover_limited_per_ip = delta.cover_limited_per_ip,
        connection_limited = delta.connection_limited,
        xudp_rejected_per_stream = delta.xudp_rejected_per_stream,
        xudp_rejected_global = delta.xudp_rejected_global,
        xudp_end_dropped = delta.xudp_end_dropped,
        xudp_replies_dropped = delta.xudp_replies_dropped,
        xudp_send_dropped = delta.xudp_send_dropped,
        legacy_udp_limited = delta.legacy_udp_limited,
        replay_rejected = delta.replay_rejected,
        replay_cache_full = delta.replay_cache_full,
        xudp_resolution_rejected = delta.xudp_resolution_rejected,
        splice_fallback = delta.splice_fallback,
        replay_cache_entries_snapshot = replay.entries,
        replay_in_flight_snapshot = replay.in_flight,
        replay_capacity = replay.capacity,
        xudp_high_water,
        preauth_active,
        authenticated_active,
        "runtime pressure counters increased"
    );
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

    let udp_io = udp_io_timeout(config.limits.idle_timeout_ms);
    tracing::info!(udp_io_timeout = ?udp_io, "independent UDP I/O deadline");
    let max_sessions = usize::try_from(config.limits.max_udp_destinations)
        .unwrap_or(usize::MAX)
        .clamp(1, usize::from(u16::MAX) + 1);
    let xudp = XudpConfig {
        max_sessions,
        session_idle_timeout: udp_idle_clock(config.limits.idle_timeout_ms),
        io_timeout: udp_io,
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
        io_timeout: udp_io,
        // Same reasoning as XUDP: a retained idle flow must release its stream
        // permit long before the 300 s TCP idle timeout.
        idle_timeout: udp_idle_clock(config.limits.idle_timeout_ms),
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

    let legacy_udp_permits = Arc::new(Semaphore::new(legacy_udp_stream_limit(
        config.limits.max_xudp_sessions,
    )));

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
        .with_legacy_udp_limiter(legacy_udp_permits)
        .with_relay_idle_timeout(Duration::from_millis(config.limits.idle_timeout_ms)))
}

/// Outcome of resolving the logging filter from `[log] level` and `RUST_LOG`.
#[derive(Debug, PartialEq, Eq)]
enum LogFilterNotice {
    None,
    Overridden,
    EmptyFallback,
    InvalidFallback(String),
}

fn resolve_log_filter(
    level: LogLevel,
    raw_env: Option<OsString>,
) -> (tracing_subscriber::EnvFilter, LogFilterNotice) {
    let Some(raw) = raw_env else {
        return (
            tracing_subscriber::EnvFilter::new(level.as_str()),
            LogFilterNotice::None,
        );
    };
    let Ok(text) = raw.into_string() else {
        return (
            tracing_subscriber::EnvFilter::new(level.as_str()),
            LogFilterNotice::InvalidFallback("RUST_LOG is not valid UTF-8".to_owned()),
        );
    };
    if text.trim().is_empty() {
        return (
            tracing_subscriber::EnvFilter::new(level.as_str()),
            LogFilterNotice::EmptyFallback,
        );
    }
    match tracing_subscriber::EnvFilter::try_new(&text) {
        Ok(filter) => (filter, LogFilterNotice::Overridden),
        Err(error) => (
            tracing_subscriber::EnvFilter::new(level.as_str()),
            LogFilterNotice::InvalidFallback(error.to_string()),
        ),
    }
}

fn init_logging(level: LogLevel) {
    let (filter, notice) = resolve_log_filter(level, std::env::var_os("RUST_LOG"));
    let diagnostic_logging_enabled = filter
        .max_level_hint()
        .is_none_or(|max| max >= tracing::level_filters::LevelFilter::DEBUG);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .init();
    // Emit override/fallback and diagnostic-privacy notices via a scoped
    // stderr subscriber so a restrictive `RUST_LOG` cannot suppress the notice
    // about `RUST_LOG` itself, and check the *effective* filter (including
    // target-scoped directives such as `warn,beam_core=debug`) for debug/trace
    // privacy warnings.
    match notice {
        LogFilterNotice::None => {}
        LogFilterNotice::Overridden => emit_operator_warning(|| {
            tracing::warn!(
                configured_level = level.as_str(),
                "RUST_LOG is set and overrides the configured log level"
            );
        }),
        LogFilterNotice::EmptyFallback => emit_operator_warning(|| {
            tracing::warn!(
                configured_level = level.as_str(),
                "RUST_LOG is set but empty; using the configured log level"
            );
        }),
        LogFilterNotice::InvalidFallback(error) => emit_operator_warning(|| {
            tracing::warn!(
                %error,
                configured_level = level.as_str(),
                "invalid RUST_LOG; using the configured log level"
            );
        }),
    }
    if diagnostic_logging_enabled {
        emit_operator_warning(|| {
            tracing::warn!(
                "diagnostic logging is enabled; peer addresses and destinations may be recorded"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_rejects_server_only_options() {
        assert!(
            Cli::try_parse_from([
                "beam",
                "--check",
                "generate",
                "--host",
                "127.0.0.1",
                "--sni",
                "whatsapp.net",
            ])
            .is_err(),
            "--check must not silently generate a private key"
        );
        assert!(
            Cli::try_parse_from([
                "beam",
                "--config",
                "config.toml",
                "generate",
                "--host",
                "127.0.0.1",
                "--sni",
                "whatsapp.net",
            ])
            .is_err(),
            "generate reads no config file"
        );
    }

    #[test]
    fn loose_config_mode_reports_only_the_loose_bits() {
        for mode in [0o600, 0o640, 0o400, 0o440] {
            assert_eq!(loose_config_mode(mode), None, "{mode:03o}");
        }
        // 0o624 sets other-read and group-write; other-user access wins.
        for mode in [0o604, 0o606, 0o601, 0o624] {
            assert_eq!(
                loose_config_mode(mode),
                Some("is accessible to other users; use 0600, or 0640 with a trusted group"),
                "{mode:03o}"
            );
        }
        for mode in [0o620, 0o660, 0o670] {
            assert_eq!(
                loose_config_mode(mode),
                Some("is group-writable; use 0600, or 0640 with a trusted group"),
                "{mode:03o}"
            );
        }
        // Metadata mode carries the file-type bits; they never match a mask.
        assert!(loose_config_mode(0o100_644).is_some());
        assert_eq!(loose_config_mode(0o100_600), None);
    }

    #[test]
    fn sample_identity_fields_name_the_published_placeholders() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.example.toml");
        let sample = || Config::from_path(path).expect("the example config must load");
        let replaced_id = "1b4e28ba-2fa1-4d6b-8a3c-1f9d6e2b7a0c".parse().unwrap();

        assert_eq!(
            sample_identity_fields(&sample()),
            vec![
                "user.id".to_owned(),
                "reality.private_key".to_owned(),
                "reality.short_ids[0]".to_owned()
            ]
        );

        // A partly replaced identity must still name every leftover field.
        let mut only_user = sample();
        only_user.reality.private_key = zeroize::Zeroizing::new([0x11; 32]);
        only_user.reality.short_ids = vec!["deadbeef".to_owned()];
        assert_eq!(
            sample_identity_fields(&only_user),
            vec!["user.id".to_owned()]
        );

        let mut only_key = sample();
        only_key.user.id = replaced_id;
        only_key.reality.short_ids = vec!["deadbeef".to_owned()];
        assert_eq!(
            sample_identity_fields(&only_key),
            vec!["reality.private_key".to_owned()]
        );

        // The validator accepts uppercase short IDs, so the sample match must
        // not depend on the stored case, and the report must carry the slot.
        let mut later_slot = sample();
        later_slot.user.id = replaced_id;
        later_slot.reality.private_key = zeroize::Zeroizing::new([0x11; 32]);
        later_slot.reality.short_ids = vec!["deadbeef".to_owned(), "0123456789ABCDEF".to_owned()];
        assert_eq!(
            sample_identity_fields(&later_slot),
            vec!["reality.short_ids[1]".to_owned()]
        );

        let mut replaced = sample();
        replaced.user.id = replaced_id;
        replaced.reality.private_key = zeroize::Zeroizing::new([0x11; 32]);
        replaced.reality.short_ids = vec!["deadbeef".to_owned()];
        assert!(sample_identity_fields(&replaced).is_empty());
    }

    #[test]
    fn sample_identity_warning_matches_effective_x25519_key() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.example.toml");
        let mut config = Config::from_path(path).expect("example config");
        config.user.id = "1b4e28ba-2fa1-4d6b-8a3c-1f9d6e2b7a0c".parse().unwrap();
        config.reality.short_ids = vec!["deadbeef".to_owned()];
        // All 32 encodings differ only in bits discarded by X25519 clamping.
        for low in 0..8 {
            for high in 0..4 {
                *config.reality.private_key = SAMPLE_PRIVATE_KEY;
                config.reality.private_key[0] = (SAMPLE_PRIVATE_KEY[0] & 0xf8) | low;
                config.reality.private_key[31] = (SAMPLE_PRIVATE_KEY[31] & 0x3f) | (high << 6);
                assert_eq!(sample_identity_fields(&config), vec!["reality.private_key"]);
            }
        }
        // Changing any effective bit must no longer identify the sample key.
        for index in 0..32 {
            for bit in 0..8 {
                if (index == 0 && bit < 3) || (index == 31 && bit >= 6) {
                    continue;
                }
                *config.reality.private_key = SAMPLE_PRIVATE_KEY;
                config.reality.private_key[index] ^= 1 << bit;
                assert!(sample_identity_fields(&config).is_empty());
            }
        }
    }

    #[test]
    fn blocking_pool_keeps_its_non_splice_reserve() {
        for (threads, splice) in [(1, 0), (40, 0), (41, 1), (160, 120), (512, 472)] {
            assert_eq!(splice_capacity(threads), splice);
        }
    }

    #[test]
    fn fd_validation_distinguishes_unlimited_from_query_failure() {
        let unlimited = resolve_fd_limit(Ok(None));
        assert_eq!(unlimited.effective, u64::MAX);
        assert_eq!(unlimited.source, FdLimitSource::Unlimited);
        assert!(unlimited.describe().contains("unlimited"));

        let floored = resolve_fd_limit(Ok(Some(256)));
        assert_eq!(floored.effective, 65_536);
        assert_eq!(
            floored.source,
            FdLimitSource::Floored {
                observed: 256,
                floor: 65_536,
            }
        );
        assert!(floored.describe().contains("256"));
        assert!(floored.describe().contains("deployment floor"));

        let observed = resolve_fd_limit(Ok(Some(131_072)));
        assert_eq!(observed.effective, 131_072);
        assert_eq!(observed.source, FdLimitSource::Observed(131_072));
        assert!(observed.describe().contains("131072"));

        let failed = resolve_fd_limit(Err(std::io::Error::other("test")));
        assert_eq!(failed.effective, 65_536);
        assert!(matches!(failed.source, FdLimitSource::QueryFailed { .. }));
        assert!(failed.describe().contains("could not query"));
    }

    #[test]
    fn parse_max_blocking_threads_handles_valid_invalid_and_non_utf8_values() {
        use std::os::unix::ffi::OsStringExt;

        assert_eq!(
            parse_max_blocking_threads(None),
            (DEFAULT_MAX_BLOCKING_THREADS, None)
        );
        assert_eq!(
            parse_max_blocking_threads(Some(OsString::from("1"))),
            (1, None)
        );
        assert_eq!(
            parse_max_blocking_threads(Some(OsString::from("256"))),
            (256, None)
        );
        assert_eq!(
            parse_max_blocking_threads(Some(OsString::from("512"))),
            (512, None)
        );
        assert_eq!(
            parse_max_blocking_threads(Some(OsString::from("0"))),
            (
                DEFAULT_MAX_BLOCKING_THREADS,
                Some(BlockingThreadsFallback::Invalid("0".to_owned()))
            )
        );
        assert_eq!(
            parse_max_blocking_threads(Some(OsString::from("513"))),
            (
                DEFAULT_MAX_BLOCKING_THREADS,
                Some(BlockingThreadsFallback::Invalid("513".to_owned()))
            )
        );
        assert_eq!(
            parse_max_blocking_threads(Some(OsString::from("abc"))),
            (
                DEFAULT_MAX_BLOCKING_THREADS,
                Some(BlockingThreadsFallback::Invalid("abc".to_owned()))
            )
        );
        assert_eq!(
            parse_max_blocking_threads(Some(OsString::from_vec(vec![0xff, 0xfe]))),
            (
                DEFAULT_MAX_BLOCKING_THREADS,
                Some(BlockingThreadsFallback::NotUtf8)
            )
        );
    }

    #[test]
    fn resolve_log_filter_handles_empty_invalid_and_override_values() {
        use std::os::unix::ffi::OsStringExt;

        let (_, notice) = resolve_log_filter(LogLevel::Warn, None);
        assert_eq!(notice, LogFilterNotice::None);

        let (_, notice) = resolve_log_filter(LogLevel::Warn, Some(OsString::from("debug")));
        assert_eq!(notice, LogFilterNotice::Overridden);

        let (_, notice) = resolve_log_filter(LogLevel::Warn, Some(OsString::from("")));
        assert_eq!(notice, LogFilterNotice::EmptyFallback);

        let (_, notice) = resolve_log_filter(LogLevel::Warn, Some(OsString::from("   ")));
        assert_eq!(notice, LogFilterNotice::EmptyFallback);

        let (_, notice) = resolve_log_filter(LogLevel::Warn, Some(OsString::from_vec(vec![0xff])));
        assert!(matches!(notice, LogFilterNotice::InvalidFallback(_)));
    }

    #[test]
    fn effective_xudp_per_mux_limit_identifies_binding_key() {
        assert_eq!(
            effective_xudp_per_mux_limit(256, 2048),
            (128, "max_xudp_sessions")
        );
        assert_eq!(
            effective_xudp_per_mux_limit(256, 64),
            (64, "max_udp_destinations")
        );
        assert_eq!(effective_xudp_per_mux_limit(256, 128), (128, "both"));
    }

    #[tokio::test]
    async fn bind_listener_reports_effective_ipv6_v6only_mode() {
        let required = std::env::var_os("BEAM_REQUIRE_IPV6_TESTS").is_some();
        let addr: SocketAddr = "[::1]:0".parse().unwrap();
        let listener = match bind_listener(addr, 128) {
            Ok(listener) => listener,
            Err(error)
                if !required
                    && error
                        .downcast_ref::<std::io::Error>()
                        .and_then(std::io::Error::raw_os_error)
                        // Linux: EAFNOSUPPORT (97), EADDRNOTAVAIL (99)
                        .is_some_and(|code| code == 97 || code == 99) =>
            {
                return;
            }
            Err(error) => panic!("IPv6 loopback bind_listener failed: {error:#}"),
        };
        // Linux marks non-wildcard IPv6 binds (like ::1) as IPv6-only.
        assert_eq!(listener_ipv6_only_label(&listener, addr), "true");

        // Wildcard [::] inherits the host `net.ipv6.bindv6only` default.
        let wildcard_addr: SocketAddr = "[::]:0".parse().unwrap();
        if let Ok(wildcard) = bind_listener(wildcard_addr, 128) {
            let label = listener_ipv6_only_label(&wildcard, wildcard_addr);
            assert!(
                label == "true" || label == "false",
                "expected effective IPV6_V6ONLY bool label, got {label}"
            );
            if let Ok(raw) = std::fs::read_to_string("/proc/sys/net/ipv6/bindv6only")
                && let Ok(sysctl) = raw.trim().parse::<u8>()
            {
                assert_eq!(label == "true", sysctl != 0);
            }
        }
    }

    #[tokio::test]
    async fn shutdown_drain_honors_deadline_and_second_signal() {
        assert_eq!(
            drain_connections(Instant::now(), || true, std::future::ready("SIGINT")).await,
            DrainOutcome::Signal("SIGINT")
        );
        assert_eq!(
            drain_connections(Instant::now(), || true, std::future::pending()).await,
            DrainOutcome::Deadline
        );
        assert_eq!(
            drain_connections(Instant::now(), || false, std::future::pending()).await,
            DrainOutcome::Complete
        );
    }

    #[test]
    fn replay_capacity_bounds_the_configured_pool() {
        assert_eq!(replay_capacity(1), REPLAY_CAPACITY_MIN);
        assert_eq!(replay_capacity(1024), REPLAY_CAPACITY_MAX);
        assert_eq!(replay_capacity(2000), REPLAY_CAPACITY_MAX);
        assert_eq!(replay_capacity(64), 8192);
        assert_eq!(replay_capacity(100), 12800);
    }

    #[test]
    fn legacy_udp_streams_follow_the_udp_socket_budget() {
        assert_eq!(legacy_udp_stream_limit(1024), 1024);
        assert_eq!(legacy_udp_stream_limit(256), 256);
        assert_eq!(legacy_udp_stream_limit(0), 1);
    }

    #[test]
    fn legacy_pool_admits_the_p1_burst_shape_through_production_wiring() {
        // P1 regression: 200 short packetaddr flows (10 sequential plus 190
        // across 16 workers) were refused at 142/200 by the old literal pool
        // of 64 permits. Exercise `build_tls_config` directly so a missing or
        // mis-sized legacy UDP limiter wiring fails this test.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.example.toml");
        for budget in [256_u32, 1024_u32] {
            let mut config = Config::from_path(path).expect("the example config must load");
            config.limits.max_xudp_sessions = budget;
            let tls = build_tls_config(&config).expect("production TLS config must build");
            let pool = tls.legacy_udp_limiter();
            assert_eq!(pool.available_permits(), budget as usize);

            let mut held = Vec::with_capacity(200);
            for _ in 0..200 {
                held.push(
                    Arc::clone(&pool)
                        .try_acquire_owned()
                        .expect("P1 burst must fit"),
                );
            }
            assert_eq!(pool.available_permits(), budget as usize - 200);
        }

        // Verify a small configured budget actually caps acquisitions at its exact size.
        let mut small = Config::from_path(path).expect("the example config must load");
        small.limits.max_xudp_sessions = 2;
        let tls = build_tls_config(&small).expect("small budget config must build");
        let pool = tls.legacy_udp_limiter();
        let _first = Arc::clone(&pool).try_acquire_owned().expect("first permit");
        let _second = Arc::clone(&pool)
            .try_acquire_owned()
            .expect("second permit");
        assert!(
            Arc::clone(&pool).try_acquire_owned().is_err(),
            "third permit must be rejected at the configured cap"
        );
    }

    #[test]
    fn udp_idle_clock_is_capped_below_the_tcp_timeout() {
        assert_eq!(udp_idle_clock(300_000), MAX_UDP_IDLE_TIMEOUT);
        assert_eq!(udp_idle_clock(1_000), Duration::from_secs(1));
    }

    #[test]
    fn the_example_config_caps_only_the_udp_idle_clock() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.example.toml");
        let config = Config::from_path(path).expect("the example config must load");
        let tls = build_tls_config(&config).expect("the example config must build");
        assert_eq!(tls.udp.idle_timeout, MAX_UDP_IDLE_TIMEOUT);
        assert_eq!(
            tls.relay_idle_timeout,
            Duration::from_millis(config.limits.idle_timeout_ms)
        );
    }

    #[test]
    fn accept_backoff_is_bounded_and_monotonic() {
        let mut backoff = ACCEPT_BACKOFF_START;
        let mut steps = Vec::new();
        for _ in 0..12 {
            steps.push(backoff);
            backoff = next_accept_backoff(backoff);
        }
        assert_eq!(steps[0], Duration::from_millis(10));
        assert!(steps.windows(2).all(|pair| pair[1] >= pair[0]));
        assert_eq!(
            *steps.last().unwrap(),
            ACCEPT_BACKOFF_LIMIT,
            "the backoff must stop growing at the bound"
        );
        assert_eq!(
            next_accept_backoff(ACCEPT_BACKOFF_LIMIT),
            ACCEPT_BACKOFF_LIMIT
        );
    }

    #[test]
    fn a_resource_shortage_is_the_accept_error_that_feeds_the_resource_counter() {
        let metrics = beam_core::metrics::Metrics::default();
        record_accept_failure(&metrics, beam_sys::AcceptError::ResourceShortage);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.accept_errors, 1);
        assert_eq!(
            snapshot.accept_errors_resource, 1,
            "a resource shortage must feed the resource counter"
        );

        let metrics = beam_core::metrics::Metrics::default();
        record_accept_failure(&metrics, beam_sys::AcceptError::Transient);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.accept_errors, 1);
        assert_eq!(
            snapshot.accept_errors_resource, 0,
            "one bad connection is not a resource shortage"
        );
    }

    #[test]
    fn pressure_counters_maps_every_field_and_emits_distinct_warning_labels() {
        #[derive(Clone, Default)]
        struct BufferWriter(Arc<std::sync::Mutex<Vec<u8>>>);

        impl std::io::Write for BufferWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let previous = beam_core::metrics::MetricsSnapshot {
            preauth_rejected: 3,
            preauth_rejected_global: 1,
            preauth_rejected_per_ip: 2,
            cover_limited: 9,
            cover_limited_global: 4,
            cover_limited_per_ip: 5,
            connection_limited: 6,
            xudp_rejected_per_stream: 7,
            xudp_rejected_global: 8,
            xudp_end_dropped: 10,
            xudp_replies_dropped: 11,
            xudp_send_dropped: 12,
            legacy_udp_limited: 13,
            replay_rejected: 14,
            replay_cache_full: 15,
            xudp_resolution_rejected: 16,
            splice_fallback: 17,
            ..Default::default()
        };
        // Give every field a distinct delta (with totals equal to global + per_ip).
        let current = beam_core::metrics::MetricsSnapshot {
            preauth_rejected: 3 + 31,
            preauth_rejected_global: 1 + 11,
            preauth_rejected_per_ip: 2 + 20,
            cover_limited: 9 + 43,
            cover_limited_global: 4 + 19,
            cover_limited_per_ip: 5 + 24,
            connection_limited: 6 + 37,
            xudp_rejected_per_stream: 7 + 41,
            xudp_rejected_global: 8 + 47,
            xudp_end_dropped: 10 + 53,
            xudp_replies_dropped: 11 + 59,
            xudp_send_dropped: 12 + 61,
            legacy_udp_limited: 13 + 67,
            replay_rejected: 14 + 71,
            replay_cache_full: 15 + 73,
            xudp_resolution_rejected: 16 + 79,
            splice_fallback: 17 + 83,
            ..Default::default()
        };

        let prev_counters = PressureCounters::from_snapshot(&previous);
        let cur_counters = PressureCounters::from_snapshot(&current);
        assert_ne!(cur_counters, prev_counters);
        let delta = cur_counters.delta(prev_counters);
        assert_eq!(
            delta,
            PressureCounters {
                preauth_rejected: 31,
                preauth_rejected_global: 11,
                preauth_rejected_per_ip: 20,
                cover_limited: 43,
                cover_limited_global: 19,
                cover_limited_per_ip: 24,
                connection_limited: 37,
                xudp_rejected_per_stream: 41,
                xudp_rejected_global: 47,
                xudp_end_dropped: 53,
                xudp_replies_dropped: 59,
                xudp_send_dropped: 61,
                legacy_udp_limited: 67,
                replay_rejected: 71,
                replay_cache_full: 73,
                xudp_resolution_rejected: 79,
                splice_fallback: 83,
            }
        );

        let buffer = BufferWriter::default();
        let make_writer = {
            let buffer = buffer.clone();
            move || buffer.clone()
        };
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(make_writer)
            .finish();
        let replay = beam_core::tls::ReplayStats {
            entries: 89,
            in_flight: 97,
            capacity: 4096,
        };
        tracing::subscriber::with_default(subscriber, || {
            emit_pressure_warning(delta, replay, 101, 103, 107);
        });

        let rendered = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        for expected in [
            "runtime pressure counters increased",
            "preauth_rejected=31",
            "preauth_rejected_global=11",
            "preauth_rejected_per_ip=20",
            "cover_limited=43",
            "cover_limited_global=19",
            "cover_limited_per_ip=24",
            "connection_limited=37",
            "xudp_rejected_per_stream=41",
            "xudp_rejected_global=47",
            "xudp_end_dropped=53",
            "xudp_replies_dropped=59",
            "xudp_send_dropped=61",
            "legacy_udp_limited=67",
            "replay_rejected=71",
            "replay_cache_full=73",
            "xudp_resolution_rejected=79",
            "splice_fallback=83",
            "replay_cache_entries_snapshot=89",
            "replay_in_flight_snapshot=97",
            "replay_capacity=4096",
            "xudp_high_water=101",
            "preauth_active=103",
            "authenticated_active=107",
        ] {
            assert!(
                rendered.contains(expected),
                "missing `{expected}` in pressure warning: {rendered}"
            );
        }
    }

    #[test]
    fn format_path_preserves_utf8_and_distinguishes_non_utf8_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::path::Path;

        assert_eq!(
            format_path(Path::new("/etc/beam/config.toml")),
            "/etc/beam/config.toml"
        );
        let a = Path::new(OsStr::from_bytes(b"/tmp/beam-\xff.toml"));
        let b = Path::new(OsStr::from_bytes(b"/tmp/beam-\xfe.toml"));
        let literal = Path::new("/tmp/beam-\\xff.toml");
        let controls = Path::new("/tmp/beam-\n\x1b[31m.toml");
        assert_eq!(format_path(a), "/tmp/beam-\\xff.toml");
        assert_eq!(format_path(b), "/tmp/beam-\\xfe.toml");
        assert_eq!(format_path(literal), "/tmp/beam-\\\\xff.toml");
        assert_eq!(format_path(controls), "/tmp/beam-\\n\\u{1b}[31m.toml");
        assert_ne!(format_path(a), format_path(b));
        assert_ne!(format_path(a), format_path(literal));
    }

    #[test]
    fn preauth_limits_clamp_per_ip_cap_to_pending_slots() {
        assert_eq!(preauth_limits(1024, 128), (256, 128));
        assert_eq!(preauth_limits(1024, 512), (256, 256));
        assert_eq!(preauth_limits(8, 32), (16, 16));
        assert_eq!(preauth_limits(64, 100), (64, 64));
    }

    #[test]
    fn resolve_pipe_pages_soft_distinguishes_sysctl_from_fallback() {
        assert_eq!(resolve_pipe_pages_soft(Some(32_768)), (32_768, "sysctl"));
        assert_eq!(
            resolve_pipe_pages_soft(None),
            (DEFAULT_PIPE_USER_PAGES_SOFT, "fallback")
        );
    }

    #[test]
    fn resolve_page_size_distinguishes_sysconf_from_fallback() {
        assert_eq!(resolve_page_size(Some(65_536)), (65_536, "sysconf"));
        assert_eq!(resolve_page_size(None), (DEFAULT_PAGE_SIZE, "fallback"));
    }
}
