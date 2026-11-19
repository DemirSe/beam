use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

mod generate;

use anyhow::Context;
use beam_core::address::{Address, NetLocation};
use beam_core::admission::IpLimiter;
use beam_core::config::{Config, LogLevel};
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
    let result = runtime.block_on(async_main(cli, max_blocking_threads));
    // A blocking splice cannot be aborted once it has started. The shutdown
    // path drains normal connections briefly; this bound is the final backstop
    // for a wedged relay so systemd can restart the service.
    runtime.shutdown_timeout(Duration::from_secs(3));
    result
}

async fn async_main(cli: Cli, max_blocking_threads: usize) -> anyhow::Result<()> {
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
    let config = Config::from_path(&cli.config)
        .with_context(|| format!("failed to load `{}`", cli.config.display()))?;

    init_logging(config.log.level);
    // The service unit owns the runtime limit (64K). A user-shell `--check`
    // or a lab install may inherit a smaller soft limit; validate against the
    // deployment floor and make the mismatch visible instead of rejecting a
    // configuration that the service can serve.
    let validation_fd_limit = validation_fd_limit(beam_sys::open_file_limit());
    config
        .validate_fd_budget(validation_fd_limit)
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
    // A direct start must warn too: after a successful copy of the example
    // file, the first start would otherwise serve the published sample
    // identity silently.
    warn_if_sample_identity(&config);

    if cli.check {
        // `validate_limits` covers syntax and scalar bounds; constructing the
        // same runtime configuration catches derived failures (XUDP/legacy
        // limits, TLS material) before systemd's ExecStartPre says OK and the
        // real start crash-loops. This performs no bind or network I/O.
        build_tls_config(&config)?;
        writeln!(
            std::io::stdout().lock(),
            "configuration is valid: {}",
            cli.config.display()
        )
        .context("could not write configuration check result")?;
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
    let pipe_pages_soft = beam_sys::pipe_user_pages_soft().unwrap_or(16_384);
    let page_size = beam_sys::page_size();
    let requested_splice_tasks = splice_capacity(max_blocking_threads);
    let supported_splice_tasks =
        beam_core::relay::RelayConfig::supported_splice_tasks(pipe_pages_soft, page_size);
    let max_splice_tasks = requested_splice_tasks.min(supported_splice_tasks);
    if max_splice_tasks < requested_splice_tasks {
        tracing::warn!(
            soft_pages = pipe_pages_soft,
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
        splice_tasks = max_splice_tasks,
        pipe_size = relay_pipe_size,
        "relay pipe budget"
    );
    let legacy_udp_permits = Arc::new(Semaphore::new(legacy_udp_stream_limit(
        config.limits.max_xudp_sessions,
    )));

    let tls_config = Arc::new(
        build_tls_config(&config)?
            .with_connection_limiter(Arc::clone(&authenticated))
            .with_splice_limiter(splice_permits)
            .with_relay_pipe_size(relay_pipe_size)
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
        max_legacy_udp_streams = legacy_udp_stream_limit(config.limits.max_xudp_sessions),
        listen_backlog = config.limits.listen_backlog,
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
        let mut last_pressure = pressure_counters(&last);
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
                    xudp_send_dropped = pressure.7.saturating_sub(last_pressure.7),
                    legacy_udp_limited = pressure.8.saturating_sub(last_pressure.8),
                    replay_rejected = pressure.9.saturating_sub(last_pressure.9),
                    replay_cache_full = pressure.10.saturating_sub(last_pressure.10),
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
                || replay != last_replay
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
    let mut accept_backoff = Duration::from_millis(10);
    let first_signal = loop {
        let accepted = tokio::select! {
            biased;
            signal = termination_signal(&mut sigterm, &mut sigint) => break signal,
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
                    biased;
                    signal = termination_signal(&mut sigterm, &mut sigint) => break signal,
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

fn validation_fd_limit(soft_limit: std::io::Result<Option<u64>>) -> u64 {
    const DEPLOYMENT_FD_FLOOR: u64 = 65_536;
    match soft_limit {
        Ok(None) => u64::MAX,
        Ok(Some(actual_fd_limit)) => {
            if actual_fd_limit < DEPLOYMENT_FD_FLOOR {
                tracing::warn!(
                    actual_fd_limit,
                    deployment_floor = DEPLOYMENT_FD_FLOOR,
                    "process soft fd limit is below the deployment floor; validate the service limit"
                );
            }
            actual_fd_limit.max(DEPLOYMENT_FD_FLOOR)
        }
        Err(error) => {
            tracing::warn!(%error, deployment_floor = DEPLOYMENT_FD_FLOOR, "could not query the process fd limit; using the deployment floor");
            DEPLOYMENT_FD_FLOOR
        }
    }
}

/// Returns the identity fields that still hold the published sample values.
fn sample_identity_fields(config: &Config) -> Vec<String> {
    let mut fields = Vec::new();
    if config.user.id.is_nil() {
        fields.push("user.id".to_owned());
    }
    if *config.reality.private_key == SAMPLE_PRIVATE_KEY {
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
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .log_internal_errors(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!(
            fields = %fields.join(", "),
            "sample identity values are unchanged; replace them before deployment"
        );
    });
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
) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        snapshot.preauth_rejected,
        snapshot.cover_limited,
        snapshot.connection_limited,
        snapshot.xudp_rejected_per_stream,
        snapshot.xudp_rejected_global,
        snapshot.xudp_end_dropped,
        snapshot.xudp_replies_dropped,
        snapshot.xudp_send_dropped,
        snapshot.legacy_udp_limited,
        snapshot.replay_rejected,
        snapshot.replay_cache_full,
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
    fn blocking_pool_keeps_its_non_splice_reserve() {
        for (threads, splice) in [(1, 0), (40, 0), (41, 1), (160, 120), (512, 472)] {
            assert_eq!(splice_capacity(threads), splice);
        }
    }

    #[test]
    fn fd_validation_distinguishes_unlimited_from_query_failure() {
        assert_eq!(validation_fd_limit(Ok(None)), u64::MAX);
        assert_eq!(validation_fd_limit(Ok(Some(256))), 65_536);
        assert_eq!(validation_fd_limit(Ok(Some(131_072))), 131_072);
        assert_eq!(
            validation_fd_limit(Err(std::io::Error::other("test"))),
            65_536
        );
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
    fn legacy_pool_admits_the_p1_burst_shape() {
        // P1 regression: 200 short packetaddr flows (10 sequential plus 190
        // across 16 workers) were refused at 142/200 by the old literal pool
        // of 64 permits. Every supported UDP budget must admit 200
        // concurrently held streams.
        for budget in [256, 1024] {
            let pool = Arc::new(Semaphore::new(legacy_udp_stream_limit(budget)));
            let mut held = Vec::with_capacity(200);
            for _ in 0..200 {
                held.push(
                    Arc::clone(&pool)
                        .try_acquire_owned()
                        .expect("P1 burst must fit"),
                );
            }
        }
        // The pre-fix pool shape refuses the same burst after 64 streams.
        let old = Arc::new(Semaphore::new(64));
        let mut held = Vec::new();
        let mut refused = 0;
        for _ in 0..200 {
            match Arc::clone(&old).try_acquire_owned() {
                Ok(guard) => held.push(guard),
                Err(_) => refused += 1,
            }
        }
        assert_eq!(refused, 200 - 64);
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
    fn pressure_counters_includes_replay_rejections() {
        let snapshot = beam_core::metrics::MetricsSnapshot {
            replay_rejected: 5,
            ..Default::default()
        };
        assert_eq!(pressure_counters(&snapshot).9, 5);
    }

    #[test]
    fn pressure_counters_includes_replay_cache_full() {
        let snapshot = beam_core::metrics::MetricsSnapshot {
            replay_cache_full: 7,
            ..Default::default()
        };
        assert_eq!(pressure_counters(&snapshot).10, 7);
    }

    #[test]
    fn pressure_counters_includes_send_drops() {
        let snapshot = beam_core::metrics::MetricsSnapshot {
            xudp_end_dropped: 1,
            xudp_replies_dropped: 2,
            xudp_send_dropped: 3,
            legacy_udp_limited: 4,
            ..Default::default()
        };
        let counters = pressure_counters(&snapshot);
        assert_eq!((counters.5, counters.6, counters.7), (1, 2, 3));
        assert_eq!(counters.8, 4);
    }
}
