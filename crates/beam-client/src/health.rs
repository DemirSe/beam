//! Always-on network transition detector, sleep/resume watcher, bounded-backoff
//! server reachability probe, and atomic status file publisher for `linux-tray`.

use std::io::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use beam_sys::{NetlinkRouteWatcher, boottime_offset};
use beam_tun::{DropSnapshot, IpNet, RateLimiter, TunnelActivity};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::config::detect_system_local_dns_excluding;
use crate::linux_tun::{LinuxRouteGuard, PhysicalGateways, detect_physical_gateways_excluding};

/// Default runtime status file path (owned by `RuntimeDirectory=beam-client`).
pub const DEFAULT_STATUS_PATH: &str = "/run/beam-client/status";

/// First no-netlink fallback poll interval (unchanged default behavior).
const FALLBACK_POLL_TICK: Duration = Duration::from_secs(2);
/// Upper bound of the backed-off no-netlink fallback poll interval.
const FALLBACK_POLL_MAX_SECS: u64 = 30;
/// Consecutive authenticated dial failures that mark the link degraded.
const DEGRADED_DIAL_FAILURE_STREAK: u64 = 3;
const SLEEP_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const ROUTE_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const NETLINK_COALESCE_DELAY: Duration = Duration::from_millis(150);
const SLEEP_JUMP_THRESHOLD_SECS: u64 = 5;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const HEALTHY_PROBE_INTERVAL: Duration = Duration::from_secs(60);
const RECENT_ACTIVITY_WINDOW: Duration = Duration::from_secs(75);
/// Window in which a dial-failure streak keeps the link degraded. Shorter than
/// [`RECENT_ACTIVITY_WINDOW`], so a brief blip does not keep an idle client red.
const DEGRADED_WINDOW: Duration = Duration::from_secs(20);
const IDLE_PROBE_JITTER_MAX_SECS: u64 = 15;
const INITIAL_OFFLINE_BACKOFF_SECS: u64 = 2;
const MAX_OFFLINE_BACKOFF_SECS: u64 = 10;

/// At most 1 status-write warning per 30 s window.
static STATUS_WRITE_LOG: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(1, Duration::from_secs(30)));
/// At most 3 degraded-link warnings per 30 s window.
static DEGRADED_LOG: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(3, Duration::from_secs(30)));
/// At most 3 probe-failure warnings per 30 s window.
static PROBE_LOG: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(3, Duration::from_secs(30)));

/// Connection health state written to the status file for `beam-tray`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Connected,
    Reconnecting,
    WaitingNetwork,
}

impl LinkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Reconnecting => "reconnecting",
            Self::WaitingNetwork => "waiting_network",
        }
    }
}

/// Removes the status file on clean shutdown.
pub struct StatusFileGuard {
    path: PathBuf,
}

impl StatusFileGuard {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for StatusFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Spawns the always-on network monitor that:
/// 1. Watches physical IPv4/IPv6 default gateway changes and wake-from-sleep
///    jumps (running `ip` commands off Tokio worker threads via `spawn_blocking`).
/// 2. Reconciles bypass routes (including after same-Wi-Fi suspend/resume or
///    brief `<2s` link flaps) while keeping the TUN fail-closed.
/// 3. Increments `network_reset_tx` so `beam-tun` sends immediate TCP RSTs,
///    resets XUDP mux, and refreshes local DNS cache/upstream.
/// 4. Tracks liveness from live tunnel dials (`TunnelActivity`) during active
///    traffic, falling back to jittered reachability probes only when idle or
///    recovering from outages, publishing timestamped status + RTT for `beam-tray`.
#[allow(clippy::too_many_arguments)]
pub fn spawn_network_monitor(
    ifname: String,
    tun_net: IpNet,
    server_addr: SocketAddr,
    auto_route: bool,
    fixed_local_dns: Option<IpAddr>,
    routes: Arc<Mutex<LinuxRouteGuard>>,
    activity: Arc<TunnelActivity>,
    network_reset_tx: watch::Sender<u64>,
    mut shutdown: watch::Receiver<bool>,
    status_path: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _guard = StatusFileGuard::new(status_path.clone());
        let mut netlink = if auto_route {
            match NetlinkRouteWatcher::open() {
                Ok(watcher) => {
                    // `NetlinkRouteWatcher` owns its `OwnedFd` for its full lifetime.
                    #[allow(deprecated)]
                    match AsyncFd::new(watcher) {
                        Ok(fd) => Some(fd),
                        Err(err) => {
                            warn!(error = %err, "failed to register netlink watcher with Tokio; falling back to polling");
                            None
                        }
                    }
                }
                Err(err) => {
                    warn!(error = %err, "failed to open AF_NETLINK route watcher; falling back to polling");
                    None
                }
            }
        } else {
            None
        };

        let mut last_gw = if auto_route {
            let name = ifname.clone();
            tokio::task::spawn_blocking(move || detect_physical_gateways_excluding(&name))
                .await
                .unwrap_or_default()
        } else {
            PhysicalGateways::default()
        };
        let mut last_boottime_offset = boottime_offset().ok();
        let mut next_probe_at = Instant::now();
        let mut next_route_check_at = Instant::now() + ROUTE_HEALTH_CHECK_INTERVAL;
        let mut next_route_retry_at: Option<Instant> = None;
        let mut route_retry_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
        let mut offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
        let mut generation: u64 = 0;
        let mut check_routes_now = true;
        let mut is_connected = false;
        let mut last_reset_at: Option<Instant> = None;
        let mut probe_seq: u64 = u64::from(std::process::id());
        let mut fallback_poll_secs = FALLBACK_POLL_TICK.as_secs();
        let mut bypass_ok;

        loop {
            if *shutdown.borrow() {
                break;
            }

            let now_mono = Instant::now();
            let now_boottime_offset = boottime_offset().ok();
            let slept_from_suspend = match (last_boottime_offset, now_boottime_offset) {
                (Some(prev), Some(now)) => detect_boottime_sleep_jump(prev, now),
                _ => false,
            };
            if now_boottime_offset.is_some() {
                last_boottime_offset = now_boottime_offset;
            }

            // Only fork `ip` to inspect gateways/bypass routes when:
            // - initial startup or netlink reported a route/link change,
            // - a previous bypass route install failed and its backoff expired,
            // - the slow periodic route-health tick elapsed,
            // - the host woke from suspend,
            // - we are currently missing a gateway for the server, or
            // - netlink is unavailable (fallback polling mode).
            let server_currently_has_gw = match server_addr.ip() {
                IpAddr::V4(_) => last_gw.v4.is_some(),
                IpAddr::V6(_) => last_gw.v6.is_some(),
            };
            let route_retry_due = next_route_retry_at.is_some_and(|t| now_mono >= t);
            let route_periodic_due = now_mono >= next_route_check_at;
            let should_check_routes = auto_route
                && (check_routes_now
                    || slept_from_suspend
                    || route_retry_due
                    || route_periodic_due
                    || netlink.is_none()
                    || !server_currently_has_gw);
            check_routes_now = false;
            if route_periodic_due {
                next_route_check_at = now_mono + ROUTE_HEALTH_CHECK_INTERVAL;
            }

            let (current_gw, bypass_missing) = if should_check_routes {
                let name = ifname.clone();
                let gw =
                    tokio::task::spawn_blocking(move || detect_physical_gateways_excluding(&name))
                        .await
                        .unwrap_or_default();
                let routes_chk = Arc::clone(&routes);
                let missing = tokio::task::spawn_blocking(move || {
                    routes_chk
                        .lock()
                        .map(|g| !g.bypass_routes_installed())
                        .unwrap_or(false)
                })
                .await
                .unwrap_or(false);
                (gw, missing)
            } else {
                (last_gw.clone(), false)
            };

            let gw_changed = auto_route && current_gw != last_gw;
            let server_has_gw = match server_addr.ip() {
                IpAddr::V4(_) => current_gw.v4.is_some(),
                IpAddr::V6(_) => current_gw.v6.is_some(),
            };
            let any_gw = current_gw.v4.is_some() || current_gw.v6.is_some();

            if gw_changed || slept_from_suspend || (bypass_missing && any_gw) {
                info!(
                    gw_changed,
                    slept_from_suspend,
                    bypass_missing,
                    old_gw = ?last_gw,
                    new_gw = ?current_gw,
                    "network transition, resume, or missing bypass route detected"
                );
                if auto_route {
                    let routes_upd = Arc::clone(&routes);
                    let gw_clone = current_gw.clone();
                    let installed = tokio::task::spawn_blocking(move || {
                        let local_dns = fixed_local_dns.or_else(|| {
                            detect_system_local_dns_excluding(Some(tun_net)).map(|s| s.ip())
                        });
                        if let Ok(mut guard) = routes_upd.lock() {
                            let reconciled = guard.update_bypass_gateway(&gw_clone, local_dns);
                            reconciled && guard.bypass_routes_installed()
                        } else {
                            false
                        }
                    })
                    .await
                    .unwrap_or(false);
                    // Advance `last_gw` once we have reconciled for `current_gw` so
                    // `gw_changed` / `network_reset_tx` fires once per actual gateway
                    // transition; incomplete bypass routes are still retried via
                    // `next_route_retry_at`.
                    last_gw = current_gw.clone();
                    if installed || !any_gw {
                        next_route_retry_at = None;
                        route_retry_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
                    } else {
                        warn!(
                            backoff_secs = route_retry_backoff_secs,
                            "bypass routes incomplete after reconcile; scheduling retry"
                        );
                        next_route_retry_at =
                            Some(Instant::now() + Duration::from_secs(route_retry_backoff_secs));
                        route_retry_backoff_secs = next_offline_backoff(route_retry_backoff_secs);
                    }
                }
                if gw_changed || slept_from_suspend {
                    generation = generation.wrapping_add(1);
                    let _ = network_reset_tx.send(generation);
                    is_connected = false;
                    last_reset_at = Some(Instant::now());
                }
                offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
                next_probe_at = Instant::now();
            } else if should_check_routes && !bypass_missing {
                next_route_retry_at = None;
                route_retry_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
            }

            bypass_ok = !bypass_missing;
            let mut probe_failed = false;
            if Instant::now() >= next_probe_at {
                let recent_window = match last_reset_at {
                    Some(reset_at) => RECENT_ACTIVITY_WINDOW
                        .min(Instant::now().saturating_duration_since(reset_at)),
                    None => RECENT_ACTIVITY_WINDOW,
                };
                // Authenticated dials are the only trustworthy liveness signal: a
                // bare TCP connect can succeed while REALITY/VLESS dials fail (wrong
                // key, expired short id, broken server), so a consecutive failure
                // streak overrides a successful probe instead of reporting green.
                // The streak uses the shorter degraded window so one brief blip does
                // not keep an idle client red for the whole activity window.
                let degraded_window = recent_window.min(DEGRADED_WINDOW);
                let failure_streak = if degraded_window.is_zero() {
                    0
                } else {
                    activity.recent_failure_streak(degraded_window)
                };
                let recent_rtt = if is_connected && !recent_window.is_zero() {
                    activity.recent_rtt(recent_window)
                } else {
                    None
                };
                let no_gateway = auto_route && !server_has_gw && !server_addr.ip().is_loopback();
                if let Some((state, reason, rtt_ms)) =
                    probe_tick_decision(no_gateway, failure_streak, recent_rtt)
                {
                    if state == LinkState::Connected {
                        is_connected = true;
                        offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
                        probe_seq = probe_seq.wrapping_add(1);
                        next_probe_at = Instant::now() + next_healthy_probe_interval(probe_seq);
                    } else {
                        is_connected = false;
                        probe_failed = true;
                        if reason == "dial_failures"
                            && let Some(suppressed) = DEGRADED_LOG.allow()
                        {
                            let last = activity.recent_failure(degraded_window);
                            warn!(
                                streak = failure_streak,
                                stage = last.map(|f| f.stage.as_str()).unwrap_or("unknown"),
                                kind = last.map(|f| f.kind.as_str()).unwrap_or("unknown"),
                                server = %server_addr,
                                suppressed,
                                "authenticated tunnel dials keep failing; reporting a degraded link"
                            );
                        }
                        next_probe_at = Instant::now() + Duration::from_secs(offline_backoff_secs);
                        offline_backoff_secs = next_offline_backoff(offline_backoff_secs);
                    }
                    write_status_atomic(
                        &status_path,
                        &StatusInfo::new(
                            &ifname, state, rtt_ms, reason, generation, bypass_ok, &activity,
                        ),
                    );
                } else {
                    // No live dial signal: fall back to a bounded reachability probe.
                    match probe_server_rtt(server_addr).await {
                        Ok(rtt_ms) => {
                            is_connected = true;
                            write_status_atomic(
                                &status_path,
                                &StatusInfo::new(
                                    &ifname,
                                    LinkState::Connected,
                                    Some(rtt_ms),
                                    "probe_ok",
                                    generation,
                                    bypass_ok,
                                    &activity,
                                ),
                            );
                            offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
                            probe_seq = probe_seq.wrapping_add(1);
                            next_probe_at = Instant::now() + next_healthy_probe_interval(probe_seq);
                        }
                        Err(err) => {
                            is_connected = false;
                            probe_failed = true;
                            log_probe_failure(server_addr, &err);
                            debug!(%server_addr, backoff_secs = offline_backoff_secs, "retrying after probe failure");
                            write_status_atomic(
                                &status_path,
                                &StatusInfo::new(
                                    &ifname,
                                    LinkState::Reconnecting,
                                    None,
                                    "probe_failed",
                                    generation,
                                    bypass_ok,
                                    &activity,
                                ),
                            );
                            next_probe_at =
                                Instant::now() + Duration::from_secs(offline_backoff_secs);
                            offline_backoff_secs = next_offline_backoff(offline_backoff_secs);
                        }
                    }
                }
            }

            // Grow the no-netlink fallback poll while gateways, bypass routes, and
            // probes stay stable; snap back to 2 s on any instability, and reset it
            // as soon as the netlink watcher drives wakeups again.
            fallback_poll_secs = if auto_route && netlink.is_none() {
                let stable = fallback_poll_stable(
                    gw_changed,
                    slept_from_suspend,
                    bypass_missing,
                    probe_failed,
                );
                next_fallback_poll(fallback_poll_secs, stable)
            } else {
                FALLBACK_POLL_TICK.as_secs()
            };

            let wait_dur = {
                let now = Instant::now();
                next_wait_duration(
                    next_probe_at.saturating_duration_since(now),
                    next_route_check_at.saturating_duration_since(now),
                    next_route_retry_at
                        .map(|t| t.saturating_duration_since(now))
                        .unwrap_or(Duration::MAX),
                    auto_route,
                    netlink.is_some(),
                    Duration::from_secs(fallback_poll_secs),
                )
            };

            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                nl_res = async {
                    match netlink.as_ref() {
                        Some(fd) => fd.readable().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match nl_res {
                        Ok(mut guard) => {
                            match drain_netlink_guard(&mut guard) {
                                Ok(true) => {
                                    // Coalesce bursts of DHCP/NetworkManager route updates.
                                    sleep(NETLINK_COALESCE_DELAY).await;
                                    if let Ok(status) = guard.get_inner().drain_events_status()
                                        && status.exhausted
                                    {
                                        guard.clear_ready();
                                    }
                                    check_routes_now = true;
                                }
                                Ok(false) => {}
                                Err(err) => {
                                    drop(guard);
                                    warn!(error = %err, "netlink watcher error; falling back to polling");
                                    netlink = None;
                                    check_routes_now = true;
                                }
                            }
                        }
                        Err(err) => {
                            warn!(error = %err, "netlink readiness wait failed; falling back to polling");
                            netlink = None;
                            check_routes_now = true;
                        }
                    }
                }
                () = sleep(wait_dur) => {}
            }
        }
    })
}

/// Decides the link state for one probe tick without doing any I/O.
///
/// Returns `None` when the tick must fall back to a reachability probe. A
/// dial-failure streak wins over a successful probe, and a degraded or
/// waiting state never reports an RTT.
fn probe_tick_decision(
    no_gateway: bool,
    failure_streak: u64,
    recent_rtt: Option<u64>,
) -> Option<(LinkState, &'static str, Option<u64>)> {
    if no_gateway {
        return Some((LinkState::WaitingNetwork, "no_gateway", None));
    }
    if failure_streak >= DEGRADED_DIAL_FAILURE_STREAK {
        return Some((LinkState::Reconnecting, "dial_failures", None));
    }
    recent_rtt.map(|rtt| (LinkState::Connected, "dial_activity", Some(rtt)))
}

/// The no-netlink fallback poll grows only while nothing changed and no probe
/// failed.
fn fallback_poll_stable(
    gw_changed: bool,
    slept_from_suspend: bool,
    bypass_missing: bool,
    probe_failed: bool,
) -> bool {
    !gw_changed && !slept_from_suspend && !bypass_missing && !probe_failed
}

/// Computes one monitor sleep. With `auto_route` and no netlink watcher the
/// loop must poll routes, so it is capped at `fallback_poll` (see
/// [`next_fallback_poll`]); otherwise (including `auto_route = false`) it may
/// sleep up to [`SLEEP_CHECK_INTERVAL`] and still wakes for the next probe.
fn next_wait_duration(
    until_probe: Duration,
    until_route_check: Duration,
    until_route_retry: Duration,
    auto_route: bool,
    has_netlink: bool,
    fallback_poll: Duration,
) -> Duration {
    let max_sleep = if auto_route && !has_netlink {
        fallback_poll
    } else {
        SLEEP_CHECK_INTERVAL
    };
    until_probe
        .min(until_route_check)
        .min(until_route_retry)
        .min(max_sleep)
        .max(Duration::from_millis(50))
}

/// Drains queued netlink notifications and clears Tokio edge-triggered
/// readiness whenever the socket reaches `EAGAIN`/`WouldBlock`, preventing a
/// 100% CPU spin loop on an empty netlink queue.
fn drain_netlink_guard(guard: &mut AsyncFdReadyGuard<'_, NetlinkRouteWatcher>) -> io::Result<bool> {
    let status = guard.get_inner().drain_events_status()?;
    if status.exhausted {
        guard.clear_ready();
    }
    Ok(status.saw_event)
}

/// Measures a bare TCP connect RTT to the server.
///
/// The error (and its `kind()`) is returned to the caller and logged at
/// rate-limited `warn` level so a failing probe is diagnosable without
/// flooding the journal.
async fn probe_server_rtt(server_addr: SocketAddr) -> io::Result<u64> {
    let start = Instant::now();
    match timeout(PROBE_TIMEOUT, TcpStream::connect(server_addr)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            Ok(start.elapsed().as_millis() as u64)
        }
        Ok(Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "server reachability probe timed out",
        )),
    }
}

/// Logs one probe failure, rate-limited, including `error.kind()`.
fn log_probe_failure(server_addr: SocketAddr, err: &io::Error) {
    debug!(%server_addr, error = %err, kind = ?err.kind(), "server reachability probe failed");
    if let Some(suppressed) = PROBE_LOG.allow() {
        warn!(
            %server_addr,
            error = %err,
            kind = ?err.kind(),
            suppressed,
            "server reachability probe failed"
        );
    }
}

/// Detects a suspend/resume jump when `CLOCK_BOOTTIME - CLOCK_MONOTONIC`
/// advances by at least [`SLEEP_JUMP_THRESHOLD_SECS`].
///
/// Both clocks are monotonic and unaffected by NTP or wall-clock steps, so
/// forward NTP adjustments cannot trigger false network resets.
pub fn detect_boottime_sleep_jump(prev_offset: Duration, now_offset: Duration) -> bool {
    now_offset.saturating_sub(prev_offset) >= Duration::from_secs(SLEEP_JUMP_THRESHOLD_SECS)
}

/// Computes the next healthy/idle probe interval with deterministic
/// pseudo-random jitter (`HEALTHY_PROBE_INTERVAL + 0..=15 s`) so idle probes
/// do not emit a fixed-period beacon.
pub fn next_healthy_probe_interval(seed: u64) -> Duration {
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    let jitter_secs = z % (IDLE_PROBE_JITTER_MAX_SECS + 1);
    HEALTHY_PROBE_INTERVAL + Duration::from_secs(jitter_secs)
}

/// Bounded exponential backoff for offline/reconnecting probes.
pub fn next_offline_backoff(current_secs: u64) -> u64 {
    current_secs
        .saturating_mul(2)
        .clamp(INITIAL_OFFLINE_BACKOFF_SECS, MAX_OFFLINE_BACKOFF_SECS)
}

/// Backs off the no-netlink fallback poll interval while routes stay stable and
/// snaps back to [`FALLBACK_POLL_TICK`] on any instability (gateway change,
/// missing bypass route, probe failure).
pub fn next_fallback_poll(current_secs: u64, stable: bool) -> u64 {
    if !stable {
        return FALLBACK_POLL_TICK.as_secs();
    }
    current_secs
        .saturating_mul(2)
        .clamp(FALLBACK_POLL_TICK.as_secs(), FALLBACK_POLL_MAX_SECS)
}

/// One status-file snapshot consumed by `beam-tray`.
///
/// Unknown keys are ignored by the tray, so new fields are backward compatible.
#[derive(Clone, Debug)]
pub struct StatusInfo<'a> {
    /// Link state.
    pub state: LinkState,
    /// Last measured RTT in milliseconds, if any.
    pub rtt_ms: Option<u64>,
    /// TUN interface name.
    pub ifname: &'a str,
    /// Short machine-readable reason for `state` (`ok`, `probe_failed`, ...).
    pub reason: &'static str,
    /// Network generation counter (incremented on gateway changes and resume).
    pub generation: u64,
    /// Whether every required bypass route is installed.
    pub bypass_ok: bool,
    /// Total failed authenticated upstream dials since start.
    pub dial_failures: u64,
    /// Packet drop counters, when the engine has published them.
    pub drops: Option<DropSnapshot>,
}

impl<'a> StatusInfo<'a> {
    /// Builds a status snapshot from live diagnostics.
    pub fn new(
        ifname: &'a str,
        state: LinkState,
        rtt_ms: Option<u64>,
        reason: &'static str,
        generation: u64,
        bypass_ok: bool,
        activity: &TunnelActivity,
    ) -> Self {
        Self {
            state,
            rtt_ms,
            ifname,
            reason,
            generation,
            bypass_ok,
            dial_failures: activity.dial_failure_count(),
            drops: Some(activity.drop_snapshot()),
        }
    }
}

/// Formats status text consumed by `beam-tray` (includes Unix timestamp & PID
/// so the tray ignores stale files after a crash).
///
/// `beam-tray` matches single keys and ignores unknown ones, so the trailing
/// diagnostic keys (`reason`, `generation`, `bypass_ok`, `dial_failures`,
/// `drops`) are backward compatible with older trays.
pub fn format_status(info: &StatusInfo<'_>) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut out = format!(
        "state={}\nifname={}\nts={ts}\npid={pid}\nreason={}\ngeneration={}\nbypass_ok={}\ndial_failures={}\n",
        info.state.as_str(),
        info.ifname,
        info.reason,
        info.generation,
        u8::from(info.bypass_ok),
        info.dial_failures
    );
    if let Some(rtt) = info.rtt_ms {
        out.push_str(&format!("rtt_ms={rtt}\n"));
    }
    if let Some(drops) = info.drops
        && !drops.is_empty()
    {
        out.push_str(&format!("drops={}\n", drops.as_status_value()));
    }
    out
}

/// Atomically writes and fsyncs the status file if its parent directory exists.
///
/// Every failure step (missing parent, create, write, fsync, rename) is
/// reported at rate-limited `warn` level instead of being dropped silently.
pub fn write_status_atomic(path: &Path, info: &StatusInfo<'_>) {
    if let Err((stage, err)) = write_status_file(path, info)
        && let Some(suppressed) = STATUS_WRITE_LOG.allow()
    {
        warn!(
            path = %path.display(),
            stage,
            error = %err,
            kind = ?err.kind(),
            suppressed,
            "failed to publish client status file"
        );
    }
}

/// Writes the status file, returning the failing stage and error.
fn write_status_file(path: &Path, info: &StatusInfo<'_>) -> Result<(), (&'static str, io::Error)> {
    let Some(parent) = path.parent() else {
        return Err((
            "parent",
            io::Error::new(io::ErrorKind::InvalidInput, "status path has no parent"),
        ));
    };
    if !parent.is_dir() {
        return Err((
            "parent_dir",
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("status directory {} does not exist", parent.display()),
            ),
        ));
    }
    let tmp = path.with_extension("tmp");
    let body = format_status(info);
    let mut file = std::fs::File::create(&tmp).map_err(|err| ("create", err))?;
    file.write_all(body.as_bytes())
        .map_err(|err| ("write_all", err))?;
    file.sync_all().map_err(|err| ("sync_all", err))?;
    std::fs::rename(&tmp, path).map_err(|err| ("rename", err))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded() {
        assert_eq!(next_offline_backoff(2), 4);
        assert_eq!(next_offline_backoff(4), 8);
        assert_eq!(next_offline_backoff(8), 10);
        assert_eq!(next_offline_backoff(10), 10);
    }

    #[test]
    fn boottime_sleep_jump_ignores_ntp_and_detects_suspend() {
        // An NTP wall-clock step does not change `CLOCK_BOOTTIME - CLOCK_MONOTONIC`.
        let offset = Duration::from_secs(120);
        assert!(!detect_boottime_sleep_jump(offset, offset));
        assert!(!detect_boottime_sleep_jump(
            offset,
            offset + Duration::from_secs(4)
        ));
        // Backward or zero delta never triggers.
        assert!(!detect_boottime_sleep_jump(
            offset,
            offset - Duration::from_secs(10)
        ));
        // Suspend jump >= 5s triggers.
        assert!(detect_boottime_sleep_jump(
            offset,
            offset + Duration::from_secs(SLEEP_JUMP_THRESHOLD_SECS)
        ));
        assert!(detect_boottime_sleep_jump(
            offset,
            offset + Duration::from_secs(60)
        ));

        // Live kernel clocks should be readable and show no spurious jump across back-to-back reads.
        let t0 = boottime_offset().expect("read CLOCK_BOOTTIME - CLOCK_MONOTONIC");
        let t1 = boottime_offset().expect("read CLOCK_BOOTTIME - CLOCK_MONOTONIC");
        assert!(!detect_boottime_sleep_jump(t0, t1));
    }

    #[test]
    fn monitor_sleep_keeps_the_fast_poll_only_for_netlink_fallback() {
        let probe = Duration::from_secs(10);
        let far = Duration::from_secs(600);

        // No auto-route: no route work to poll, so sleep until the probe.
        assert_eq!(
            next_wait_duration(probe, far, far, false, false, FALLBACK_POLL_TICK),
            probe
        );
        assert_eq!(
            next_wait_duration(far, far, far, false, false, FALLBACK_POLL_TICK),
            SLEEP_CHECK_INTERVAL
        );

        // Auto-route without netlink needs the fallback poll.
        assert_eq!(
            next_wait_duration(probe, far, far, true, false, FALLBACK_POLL_TICK),
            FALLBACK_POLL_TICK
        );

        // A backed-off fallback poll is honored while routes stay stable.
        assert_eq!(
            next_wait_duration(
                far,
                far,
                far,
                true,
                false,
                Duration::from_secs(FALLBACK_POLL_MAX_SECS)
            ),
            Duration::from_secs(FALLBACK_POLL_MAX_SECS)
        );

        // Auto-route with netlink follows the probe schedule.
        assert_eq!(
            next_wait_duration(probe, far, far, true, true, FALLBACK_POLL_TICK),
            probe
        );
        assert_eq!(
            next_wait_duration(far, far, far, true, true, FALLBACK_POLL_TICK),
            SLEEP_CHECK_INTERVAL
        );

        // A due deadline never yields a spin loop.
        assert_eq!(
            next_wait_duration(Duration::ZERO, far, far, true, true, FALLBACK_POLL_TICK),
            Duration::from_millis(50)
        );
    }

    #[test]
    fn fallback_poll_backs_off_while_stable_and_snaps_back() {
        // Stable: 2 s -> 4 s -> ... -> 30 s ceiling.
        let mut secs = FALLBACK_POLL_TICK.as_secs();
        let mut seen = vec![secs];
        for _ in 0..6 {
            secs = next_fallback_poll(secs, true);
            seen.push(secs);
        }
        assert_eq!(seen, vec![2, 4, 8, 16, 30, 30, 30]);

        // Any instability (gateway change, missing bypass route, probe
        // failure) snaps straight back to the 2 s fallback.
        for current in [4, 16, FALLBACK_POLL_MAX_SECS] {
            assert_eq!(next_fallback_poll(current, false), 2);
        }
    }

    #[test]
    fn degraded_state_reports_dial_failures_until_a_dial_succeeds() {
        let activity = TunnelActivity::new();
        assert_eq!(activity.recent_failure_streak(RECENT_ACTIVITY_WINDOW), 0);

        for _ in 0..DEGRADED_DIAL_FAILURE_STREAK {
            activity.record_dial_failure(beam_tun::DialFailure {
                stage: beam_tun::DialFailureStage::RealityHandshake,
                kind: beam_tun::DialFailureKind::Other,
            });
        }
        assert_eq!(activity.dial_failure_count(), 3);
        assert_eq!(
            activity.recent_failure_streak(RECENT_ACTIVITY_WINDOW),
            DEGRADED_DIAL_FAILURE_STREAK,
            "consecutive authenticated dial failures must mark the link degraded"
        );

        // A successful authenticated dial resets the streak and the health state.
        activity.record_dial_success(21);
        assert_eq!(activity.recent_failure_streak(RECENT_ACTIVITY_WINDOW), 0);
        assert_eq!(activity.dial_failure_count(), 3);
        assert_eq!(activity.recent_rtt(RECENT_ACTIVITY_WINDOW), Some(21));

        // A stale failure streak must not keep the link degraded forever.
        activity.record_dial_failure(beam_tun::DialFailure {
            stage: beam_tun::DialFailureStage::TcpConnect,
            kind: beam_tun::DialFailureKind::Refused,
        });
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(activity.recent_failure_streak(Duration::from_millis(1)), 0);
        assert_eq!(activity.recent_failure_streak(RECENT_ACTIVITY_WINDOW), 1);
    }

    #[test]
    fn probe_tick_decision_maps_degraded_recovery_and_waiting_states() {
        assert_eq!(
            probe_tick_decision(false, DEGRADED_DIAL_FAILURE_STREAK, Some(30)),
            Some((LinkState::Reconnecting, "dial_failures", None)),
            "a failure streak overrides a recent RTT"
        );
        assert_eq!(
            probe_tick_decision(false, DEGRADED_DIAL_FAILURE_STREAK - 1, Some(30)),
            Some((LinkState::Connected, "dial_activity", Some(30)))
        );
        // Recovery: the streak cleared, so live dial activity reports green.
        assert_eq!(
            probe_tick_decision(false, 0, Some(21)),
            Some((LinkState::Connected, "dial_activity", Some(21)))
        );
        assert_eq!(
            probe_tick_decision(true, 0, Some(21)),
            Some((LinkState::WaitingNetwork, "no_gateway", None)),
            "a missing gateway wins over dial activity"
        );
        assert_eq!(
            probe_tick_decision(false, 0, None),
            None,
            "no live dial signal falls back to a probe"
        );

        // The status text of a degraded tick carries no RTT.
        let activity = TunnelActivity::new();
        for _ in 0..DEGRADED_DIAL_FAILURE_STREAK {
            activity.record_dial_failure(beam_tun::DialFailure {
                stage: beam_tun::DialFailureStage::TcpConnect,
                kind: beam_tun::DialFailureKind::Refused,
            });
        }
        let streak = activity.recent_failure_streak(DEGRADED_WINDOW);
        let (state, reason, rtt) = probe_tick_decision(false, streak, Some(12)).expect("decision");
        let text = format_status(&StatusInfo::new(
            "beamtun0", state, rtt, reason, 7, true, &activity,
        ));
        assert!(text.contains("state=reconnecting\n"));
        assert!(text.contains("reason=dial_failures\n"));
        assert!(!text.contains("rtt_ms="), "a degraded link reports no RTT");

        // The same status text after recovery reports green with the RTT.
        activity.record_dial_success(9);
        let streak = activity.recent_failure_streak(DEGRADED_WINDOW);
        let (state, reason, rtt) = probe_tick_decision(false, streak, Some(9)).expect("decision");
        let text = format_status(&StatusInfo::new(
            "beamtun0", state, rtt, reason, 7, true, &activity,
        ));
        assert!(text.contains("state=connected\n"));
        assert!(text.contains("reason=dial_activity\n"));
        assert!(text.contains("rtt_ms=9\n"));
    }

    #[test]
    fn a_failed_probe_snaps_the_fallback_poll_back_to_two_seconds() {
        assert!(fallback_poll_stable(false, false, false, false));
        // Any single instability clears the "stable" flag.
        assert!(!fallback_poll_stable(true, false, false, false));
        assert!(!fallback_poll_stable(false, true, false, false));
        assert!(!fallback_poll_stable(false, false, true, false));
        assert!(!fallback_poll_stable(false, false, false, true));

        // A probe failure must not leave the fallback poll backed off.
        let probe_failed = true;
        let stable = fallback_poll_stable(false, false, false, probe_failed);
        assert_eq!(
            next_fallback_poll(FALLBACK_POLL_MAX_SECS, stable),
            FALLBACK_POLL_TICK.as_secs()
        );
    }

    #[tokio::test]
    async fn probe_reports_the_underlying_error_kind() {
        // Bind and immediately drop a listener so the port is closed.
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind probe target");
        let addr = listener.local_addr().expect("probe addr");
        drop(listener);

        let err = probe_server_rtt(addr).await.expect_err("closed port");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn healthy_probe_interval_is_jittered_within_bounds() {
        let mut saw_distinct = false;
        let first = next_healthy_probe_interval(1);
        for seed in 1..=32 {
            let interval = next_healthy_probe_interval(seed);
            assert!(interval >= HEALTHY_PROBE_INTERVAL);
            assert!(
                interval
                    <= HEALTHY_PROBE_INTERVAL + Duration::from_secs(IDLE_PROBE_JITTER_MAX_SECS)
            );
            if interval != first {
                saw_distinct = true;
            }
        }
        assert!(saw_distinct, "probe intervals should vary across seeds");
    }

    #[test]
    fn atomic_status_write_and_format() {
        let dir = std::env::temp_dir().join(format!("beam-status-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("status");
        let activity = TunnelActivity::new();
        activity.record_dial_failure(beam_tun::DialFailure {
            stage: beam_tun::DialFailureStage::TcpConnect,
            kind: beam_tun::DialFailureKind::Timeout,
        });
        let info = StatusInfo::new(
            "beamtun0",
            LinkState::Connected,
            Some(37),
            "probe_ok",
            4,
            true,
            &activity,
        );
        write_status_atomic(&path, &info);
        let text = std::fs::read_to_string(&path).expect("read status");
        // Pre-existing keys stay first so an older tray keeps working.
        assert!(text.contains("state=connected\n"));
        assert!(text.contains("rtt_ms=37\n"));
        assert!(text.contains("ifname=beamtun0\n"));
        assert!(text.contains("ts="));
        assert!(text.contains("pid="));
        // New diagnostic keys (ignored by older trays).
        assert!(text.contains("reason=probe_ok\n"));
        assert!(text.contains("generation=4\n"));
        assert!(text.contains("bypass_ok=1\n"));
        assert!(text.contains("dial_failures=1\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_write_reports_the_failing_stage() {
        let dir = std::env::temp_dir().join(format!("beam-status-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("status");
        let info = StatusInfo::new(
            "beamtun0",
            LinkState::Reconnecting,
            None,
            "probe_failed",
            0,
            false,
            &TunnelActivity::new(),
        );
        let (stage, err) = write_status_file(&path, &info).expect_err("missing dir");
        assert_eq!(stage, "parent_dir");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        // `write_status_atomic` must stay silent-but-safe on the same input.
        write_status_atomic(&path, &info);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn netlink_async_fd_clears_readiness_after_drain() {
        let watcher = NetlinkRouteWatcher::open().expect("open netlink route watcher");
        #[allow(deprecated)]
        let fd = AsyncFd::new(watcher).expect("register netlink AsyncFd");

        // `AsyncFd::new` starts optimistically ready; draining an empty queue
        // must clear readiness so `readable().await` blocks instead of spinning.
        for _ in 0..4 {
            match timeout(Duration::from_millis(50), fd.readable()).await {
                Ok(Ok(mut guard)) => {
                    let _ = drain_netlink_guard(&mut guard).expect("drain netlink");
                }
                Ok(Err(err)) => panic!("netlink readable failed: {err}"),
                Err(_elapsed) => return,
            }
        }
        panic!("AsyncFd<NetlinkRouteWatcher> remained permanently ready after draining");
    }
}
