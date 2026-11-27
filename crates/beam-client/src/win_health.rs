#![cfg(windows)]

//! Windows analogue of `health.rs`: always-on network transition detection,
//! sleep/resume handling, bounded reachability probes, and the atomic status
//! file that `beam-tray` reads.
//!
//! The shape mirrors the Linux monitor, with the platform differences the
//! Windows stack requires:
//!
//! - route and interface changes arrive from `NotifyRouteChange2` /
//!   `NotifyIpInterfaceChange` ([`NetworkChangeWatcher`]) instead of netlink,
//!   and bursts are coalesced for [`NETWORK_COALESCE_DELAY`];
//! - gateways come from the IP Helper forward table instead of `ip route`;
//! - the reachability probe binds its socket to the active physical interface,
//!   so a probe can never leave through the WinTun adapter it is testing, and
//!   fails closed when no physical interface is known;
//! - suspend is detected from `GetTickCount64 - QueryUnbiasedInterruptTime`
//!   ([`boottime_offset`]) and from the SCM power-resume signal.
//!
//! The shared [`IpcStatus`] is the single source of truth for both the `STATUS`
//! reply and the status file, so the tray can never read a state the service
//! would deny.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::windows::io::AsRawSocket;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use beam_sys::boottime_offset;
use beam_sys::windows::iphelper::{
    NetworkChangeWatcher, PhysicalGateways, detect_physical_gateways, detect_system_local_dns,
};
use beam_tun::{IpNet, RateLimiter, TunnelActivity};
use tokio::net::TcpSocket;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::win_ipc::{
    IpcStatus, MAX_DROPS_CHARS, MAX_IFNAME_CHARS, MAX_KEY_CHARS, STATE_IDLE, wire_token,
    write_status_atomic,
};
use crate::win_routes::{ActivePhysicalInterface, WindowsRouteGuard};

/// `connected` state token, shared with the tray and the status file.
pub const STATE_CONNECTED: &str = "connected";
/// `reconnecting` state token.
pub const STATE_RECONNECTING: &str = "reconnecting";
/// `waiting_network` state token.
pub const STATE_WAITING_NETWORK: &str = "waiting_network";

/// Upper bound of one monitor sleep, so a suspend always wakes the loop.
const SLEEP_CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// Periodic route re-verification even without a change notification.
const ROUTE_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(60);
/// Coalescing window for bursts of route and interface notifications.
const NETWORK_COALESCE_DELAY: Duration = Duration::from_millis(150);
/// Suspend jump that forces a route reconcile and reset.
const SLEEP_JUMP_THRESHOLD_SECS: u64 = 5;
/// Deadline for one reachability probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Base interval of the idle reachability probe.
const HEALTHY_PROBE_INTERVAL: Duration = Duration::from_secs(60);
/// Window of live dial activity that suppresses probing.
const RECENT_ACTIVITY_WINDOW: Duration = Duration::from_secs(75);
/// Window in which a dial-failure streak keeps the link degraded.
const DEGRADED_WINDOW: Duration = Duration::from_secs(20);
/// Consecutive authenticated dial failures that mark the link degraded.
const DEGRADED_DIAL_FAILURE_STREAK: u64 = 3;
/// Pseudo-random spread added to the healthy probe interval.
const IDLE_PROBE_JITTER_MAX_SECS: u64 = 15;
/// First reconnect backoff.
const INITIAL_OFFLINE_BACKOFF_SECS: u64 = 2;
/// Largest reconnect backoff.
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

/// Shared live status plus the status file that mirrors it.
///
/// Every reader (IPC `STATUS`, the tray file) sees the same snapshot, and every
/// write publishes both, so a state change cannot reach one consumer only.
pub struct StatusPublisher {
    path: PathBuf,
    status: RwLock<IpcStatus>,
}

impl StatusPublisher {
    /// Creates a publisher for `path`.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            status: RwLock::new(IpcStatus::disconnected(None)),
        }
    }

    /// Returns a consistent copy of the current status.
    pub fn snapshot(&self) -> IpcStatus {
        self.lock_read().clone()
    }

    /// Replaces the status and rewrites the status file.
    pub fn publish(&self, status: IpcStatus) {
        *self.lock_write() = status;
        let snapshot = self.snapshot();
        self.write_file(&snapshot);
    }

    /// Edits the status in place and rewrites the status file.
    pub fn update(&self, edit: impl FnOnce(&mut IpcStatus)) {
        {
            let mut status = self.lock_write();
            edit(&mut status);
        }
        let snapshot = self.snapshot();
        self.write_file(&snapshot);
    }

    /// Removes the status file, so a stopped agent leaves no stale state.
    pub fn remove(&self) {
        if let Err(err) = std::fs::remove_file(&self.path)
            && err.kind() != io::ErrorKind::NotFound
        {
            debug!(
                path = %self.path.display(),
                error = %err,
                "failed to remove the status file"
            );
        }
    }

    /// Takes the write lock, recovering from a poison left by a panicking task.
    fn lock_write(&self) -> RwLockWriteGuard<'_, IpcStatus> {
        self.status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Takes the read lock, recovering from a poison left by a panicking task.
    fn lock_read(&self) -> std::sync::RwLockReadGuard<'_, IpcStatus> {
        self.status
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Writes the status file through the atomic status replace, which keeps
    /// the file readable by the unelevated tray.
    fn write_file(&self, status: &IpcStatus) {
        let text = format_status_file(status);
        if let Err(err) = write_status_atomic(&self.path, &text)
            && let Some(suppressed) = STATUS_WRITE_LOG.allow()
        {
            warn!(
                path = %self.path.display(),
                error = %err,
                suppressed,
                "failed to publish client status file"
            );
        }
    }
}

/// Formats the status file consumed by `beam-tray`.
///
/// The keys match the Linux status file, so one tray parser serves both
/// platforms, and `ts`/`pid` let the tray ignore a stale file after a crash.
/// Every value is one wire token, so an operator-controlled `tun.name` cannot
/// inject a second key into the file.
pub fn format_status_file(status: &IpcStatus) -> String {
    let state = wire_token(&status.state, MAX_KEY_CHARS);
    let ifname = wire_token(&status.ifname, MAX_IFNAME_CHARS);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let pid = std::process::id();
    let reason = wire_token(&status.reason, MAX_KEY_CHARS);
    let generation = status.generation;
    let bypass_ok = u8::from(status.bypass_ok);
    let dial_failures = status.dial_failures;
    let mut out = format!(
        "state={state}\nifname={ifname}\nts={ts}\npid={pid}\nreason={reason}\n\
         generation={generation}\nbypass_ok={bypass_ok}\ndial_failures={dial_failures}\n"
    );
    if let Some(server) = status.server {
        out.push_str(&format!("server={server}\n"));
    }
    if let Some(rtt_ms) = status.rtt_ms {
        out.push_str(&format!("rtt_ms={rtt_ms}\n"));
    }
    if let Some(drops) = status
        .drops
        .as_deref()
        .map(|drops| wire_token(drops, MAX_DROPS_CHARS))
        && !drops.is_empty()
    {
        out.push_str(&format!("drops={drops}\n"));
    }
    out
}

/// Spawns the always-on Windows network monitor that:
/// 1. Watches physical gateway and interface changes and wake-from-sleep jumps.
/// 2. Reconciles bypass routes while keeping the tunnel fail-closed, and keeps
///    [`ActivePhysicalInterface`] current so upstream sockets stay bound to the
///    physical adapter.
/// 3. Bumps `network_reset_tx` so `beam-tun` sends immediate TCP RSTs, resets
///    the XUDP mux, and refreshes the local DNS cache and upstream.
/// 4. Tracks liveness from live tunnel dials, falling back to a protected
///    reachability probe only when idle or recovering from an outage, and
///    publishes the status that `STATUS` and `beam-tray` read.
#[allow(clippy::too_many_arguments)]
pub fn spawn_windows_network_monitor(
    ifname: String,
    tun_luid: u64,
    tun_net: IpNet,
    server_addr: SocketAddr,
    auto_route: bool,
    fixed_local_dns: Option<IpAddr>,
    routes: Arc<Mutex<WindowsRouteGuard>>,
    active_if: ActivePhysicalInterface,
    activity: Arc<TunnelActivity>,
    status: Arc<StatusPublisher>,
    network_reset_tx: watch::Sender<u64>,
    mut power_resume_rx: watch::Receiver<u64>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (change_tx, mut change_rx) = watch::channel(0_u64);
        let change_seq = Arc::new(AtomicU64::new(0));
        // The watcher cancels its registrations on drop, so it must outlive the
        // loop; if registration fails the periodic route check still runs.
        let _watcher = match NetworkChangeWatcher::start(Arc::new(move || {
            let next = change_seq.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
            let _ = change_tx.send(next);
        })) {
            Ok(watcher) => Some(watcher),
            Err(err) => {
                warn!(error = %err, "route change notifications unavailable; polling routes");
                None
            }
        };

        let mut last_gw = detect_gateways(tun_luid).await;
        let mut last_offset = boottime_offset().ok();
        let mut change_alive = true;
        let mut power_alive = true;
        let mut change_woke = false;
        let mut power_woke = false;
        let mut check_routes_now = true;
        let mut next_probe_at = Instant::now();
        let mut next_route_check_at = Instant::now() + ROUTE_HEALTH_CHECK_INTERVAL;
        let mut next_route_retry_at: Option<Instant> = None;
        let mut route_retry_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
        let mut offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
        let mut generation: u64 = 0;
        let mut last_reset_at: Option<Instant> = None;
        let mut probe_seq: u64 = u64::from(std::process::id());

        loop {
            if *shutdown.borrow() {
                break;
            }

            let now_mono = Instant::now();
            let now_offset = boottime_offset().ok();
            let slept_from_offset = match (last_offset, now_offset) {
                (Some(previous), Some(now)) => detect_boottime_sleep_jump(previous, now),
                _ => false,
            };
            if now_offset.is_some() {
                last_offset = now_offset;
            }
            let slept_from_suspend = slept_from_offset || power_woke;
            power_woke = false;
            if change_woke {
                change_woke = false;
                check_routes_now = true;
            }

            let server_currently_has_gw = match server_addr.ip() {
                IpAddr::V4(_) => last_gw.v4.is_some(),
                IpAddr::V6(_) => last_gw.v6.is_some(),
            };
            let route_retry_due = next_route_retry_at.is_some_and(|due| now_mono >= due);
            let route_periodic_due = now_mono >= next_route_check_at;
            let should_check_routes = check_routes_now
                || slept_from_suspend
                || route_retry_due
                || route_periodic_due
                || !server_currently_has_gw;
            check_routes_now = false;
            if route_periodic_due {
                next_route_check_at = now_mono + ROUTE_HEALTH_CHECK_INTERVAL;
            }

            let (current_gw, bypass_missing) = if should_check_routes {
                let gateways = detect_gateways(tun_luid).await;
                let installed = reconcile_routes(
                    Arc::clone(&routes),
                    &gateways,
                    tun_luid,
                    tun_net,
                    fixed_local_dns,
                    auto_route,
                )
                .await;
                let missing = auto_route && !installed;
                (gateways, missing)
            } else {
                (last_gw.clone(), false)
            };

            let gw_changed = current_gw != last_gw;
            let server_has_gw = match server_addr.ip() {
                IpAddr::V4(_) => current_gw.v4.is_some(),
                IpAddr::V6(_) => current_gw.v6.is_some(),
            };
            let any_gw = current_gw.v4.is_some() || current_gw.v6.is_some();

            if gw_changed || slept_from_suspend || (any_gw && (bypass_missing || route_retry_due)) {
                info!(
                    ifname = %ifname,
                    gw_changed,
                    slept_from_suspend,
                    bypass_missing,
                    route_retry_due,
                    old_gw = ?last_gw,
                    new_gw = ?current_gw,
                    "network transition, resume, or missing bypass route detected"
                );
                // Advance `last_gw` once the reconcile ran for `current_gw`, so
                // the reset fires once per real gateway transition while an
                // incomplete bypass set is still retried through the backoff.
                last_gw = current_gw.clone();
                if installed_or_idle(bypass_missing, any_gw) {
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
                if gw_changed || slept_from_suspend {
                    generation = generation.wrapping_add(1);
                    let _ = network_reset_tx.send(generation);
                    last_reset_at = Some(Instant::now());
                }
                offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
                next_probe_at = Instant::now();
            } else if should_check_routes && !bypass_missing {
                next_route_retry_at = None;
                route_retry_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
            }

            let bypass_ok = !bypass_missing;
            if Instant::now() >= next_probe_at {
                let recent_window = match last_reset_at {
                    Some(reset_at) => RECENT_ACTIVITY_WINDOW
                        .min(Instant::now().saturating_duration_since(reset_at)),
                    None => RECENT_ACTIVITY_WINDOW,
                };
                // Authenticated dials are the only trustworthy liveness signal:
                // a bare TCP connect can succeed while REALITY/VLESS dials fail,
                // so a failure streak overrides a successful probe.
                let degraded_window = recent_window.min(DEGRADED_WINDOW);
                let failure_streak = if degraded_window.is_zero() {
                    0
                } else {
                    activity.recent_failure_streak(degraded_window)
                };
                let no_gateway = auto_route && !server_has_gw && !server_addr.ip().is_loopback();
                let (state, reason, rtt_ms) = if let Some(decision) =
                    activity_tick_decision(no_gateway, failure_streak, recent_window, &activity)
                {
                    decision
                } else {
                    match probe_server_rtt(server_addr, active_if.clone()).await {
                        Ok(rtt_ms) => bare_probe_tick_decision(rtt_ms),
                        Err(err) => {
                            log_probe_failure(server_addr, &err);
                            (STATE_RECONNECTING, "probe_failed", None)
                        }
                    }
                };
                let probe_ok = state == STATE_CONNECTED || state == STATE_IDLE;
                if probe_ok {
                    offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
                    probe_seq = probe_seq.wrapping_add(1);
                    next_probe_at = Instant::now() + next_healthy_probe_interval(probe_seq);
                } else {
                    if reason == "dial_failures"
                        && let Some(suppressed) = DEGRADED_LOG.allow()
                    {
                        let last = activity.recent_failure(degraded_window);
                        warn!(
                            streak = failure_streak,
                            stage = last.map(|failure| failure.stage.as_str()).unwrap_or("unknown"),
                            kind = last.map(|failure| failure.kind.as_str()).unwrap_or("unknown"),
                            server = %server_addr,
                            suppressed,
                            "authenticated tunnel dials keep failing; reporting a degraded link"
                        );
                    }
                    next_probe_at = Instant::now() + Duration::from_secs(offline_backoff_secs);
                    offline_backoff_secs = next_offline_backoff(offline_backoff_secs);
                }
                publish_state(
                    &status, state, reason, rtt_ms, generation, bypass_ok, &activity,
                );
            }

            let wait_dur = next_wait_duration(
                next_probe_at.saturating_duration_since(now_mono),
                next_route_check_at.saturating_duration_since(now_mono),
                next_route_retry_at
                    .map(|due| due.saturating_duration_since(now_mono))
                    .unwrap_or(Duration::MAX),
            );

            tokio::select! {
                biased;
                stop = shutdown.changed() => {
                    // A dropped sender means the tunnel is gone, so the monitor
                    // must end instead of spinning on a closed channel.
                    if stop.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                resumed = power_resume_rx.changed(), if power_alive => {
                    if resumed.is_err() {
                        power_alive = false;
                    } else {
                        power_woke = true;
                    }
                }
                changed = change_rx.changed(), if change_alive => {
                    if changed.is_err() {
                        change_alive = false;
                    } else {
                        // Coalesce the DHCP / route-update burst that follows a
                        // link change before reading the forward table again.
                        sleep(NETWORK_COALESCE_DELAY).await;
                        change_woke = true;
                    }
                }
                () = sleep(wait_dur) => {}
            }
        }

        info!(ifname = %ifname, "Windows network monitor stopped");
    })
}

/// Publishes one health snapshot to the shared status and the status file.
fn publish_state(
    status: &StatusPublisher,
    state: &'static str,
    reason: &'static str,
    rtt_ms: Option<u64>,
    generation: u64,
    bypass_ok: bool,
    activity: &TunnelActivity,
) {
    let drops = activity.drop_snapshot();
    let drops = if drops.is_empty() {
        None
    } else {
        Some(drops.as_status_value())
    };
    status.update(|current| {
        current.state = state.to_owned();
        current.reason = reason.to_owned();
        current.rtt_ms = rtt_ms;
        current.generation = generation;
        current.bypass_ok = bypass_ok;
        current.dial_failures = activity.dial_failure_count();
        current.drops = drops;
    });
}

/// Reads the physical default gateways, treating a failed query as "none".
///
/// A missing gateway is not an error state for the monitor: it turns into
/// `waiting_network` or a failed protected probe, and the next notification
/// re-reads the table.
async fn detect_gateways(tun_luid: u64) -> PhysicalGateways {
    match tokio::task::spawn_blocking(move || detect_physical_gateways(tun_luid)).await {
        Ok(Ok(gateways)) => gateways,
        Ok(Err(err)) => {
            debug!(error = %err, "physical gateway query failed");
            PhysicalGateways::default()
        }
        Err(err) => {
            debug!(error = %err, "physical gateway query task failed");
            PhysicalGateways::default()
        }
    }
}

/// Moves bypass routes to the current gateway and refreshes the socket binding.
///
/// Returns whether the required bypass routes are installed afterwards. With
/// `auto_route = false` no route is required, so the answer is always true and
/// only the physical interface binding is refreshed.
async fn reconcile_routes(
    routes: Arc<Mutex<WindowsRouteGuard>>,
    gateways: &PhysicalGateways,
    tun_luid: u64,
    tun_net: IpNet,
    fixed_local_dns: Option<IpAddr>,
    auto_route: bool,
) -> bool {
    let gateways = gateways.clone();
    tokio::task::spawn_blocking(move || {
        let local_dns = fixed_local_dns.or_else(|| {
            detect_system_local_dns(tun_luid, tun_v4_exclusion(tun_net))
                .ok()
                .flatten()
                .map(|server| server.ip())
        });
        match routes.lock() {
            Ok(mut guard) => {
                let reconciled = guard.update_bypass_gateway(&gateways, local_dns);
                !auto_route || (reconciled && guard.bypass_routes_installed())
            }
            Err(_) => !auto_route,
        }
    })
    .await
    .unwrap_or(false)
}

/// Converts the TUN IPv4 subnet into the exclusion pair the IP Helper DNS scan
/// takes, matching what the Linux monitor excludes.
fn tun_v4_exclusion(tun_net: IpNet) -> Option<(Ipv4Addr, u8)> {
    match tun_net {
        IpNet::V4 { net, mask } => Some((Ipv4Addr::from(net), mask.count_ones() as u8)),
        IpNet::V6 { .. } => None,
    }
}

/// Decides one probe tick from the live activity tracker and route state.
///
/// A recent authenticated dial is enough on its own; requiring a prior
/// `connected` tick here would keep a newly started client in `idle` forever.
/// Mirrors `activity_tick_decision` in `health.rs`.
fn activity_tick_decision(
    no_gateway: bool,
    failure_streak: u64,
    recent_window: Duration,
    activity: &TunnelActivity,
) -> Option<(&'static str, &'static str, Option<u64>)> {
    let recent_rtt = if recent_window.is_zero() {
        None
    } else {
        activity.recent_rtt(recent_window)
    };
    probe_tick_decision(no_gateway, failure_streak, recent_rtt)
}

/// Decides the link state for one probe tick without doing any I/O.
///
/// Returns `None` when the tick must fall back to a reachability probe. A
/// dial-failure streak wins over a successful probe, and a degraded or waiting
/// state never reports an RTT. Mirrors `probe_tick_decision` in `health.rs`.
fn probe_tick_decision(
    no_gateway: bool,
    failure_streak: u64,
    recent_rtt: Option<u64>,
) -> Option<(&'static str, &'static str, Option<u64>)> {
    if no_gateway {
        return Some((STATE_WAITING_NETWORK, "no_gateway", None));
    }
    if failure_streak >= DEGRADED_DIAL_FAILURE_STREAK {
        return Some((STATE_RECONNECTING, "dial_failures", None));
    }
    recent_rtt.map(|rtt| (STATE_CONNECTED, "dial_activity", Some(rtt)))
}

/// A bare TCP connect proves reachability, not an authenticated tunnel dial.
fn bare_probe_tick_decision(rtt_ms: u64) -> (&'static str, &'static str, Option<u64>) {
    (STATE_IDLE, "probe_ok", Some(rtt_ms))
}

/// Whether a reconcile left the routes in an acceptable state: installed, or
/// nothing to install because the host has no gateway at all.
fn installed_or_idle(bypass_missing: bool, any_gw: bool) -> bool {
    !bypass_missing || !any_gw
}

/// Computes one monitor sleep: the earliest probe, route check, or route retry,
/// capped by [`SLEEP_CHECK_INTERVAL`], never busy-spinning.
fn next_wait_duration(
    until_probe: Duration,
    until_route_check: Duration,
    until_route_retry: Duration,
) -> Duration {
    until_probe
        .min(until_route_check)
        .min(until_route_retry)
        .min(SLEEP_CHECK_INTERVAL)
        .max(Duration::from_millis(50))
}

/// Measures a TCP connect RTT to the server through the physical interface.
///
/// The protector runs before `connect` and binds the socket to the active
/// physical interface, so the probe cannot be routed back into the WinTun
/// adapter and cannot report a healthy link while the physical path is down.
async fn probe_server_rtt(
    server_addr: SocketAddr,
    active_if: ActivePhysicalInterface,
) -> io::Result<u64> {
    let socket = match server_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }?;
    let protector = active_if.make_socket_protector(server_addr.is_ipv6());
    protector(socket.as_raw_socket())?;
    let start = Instant::now();
    match timeout(PROBE_TIMEOUT, socket.connect(server_addr)).await {
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

/// Detects a suspend jump when the accumulated suspend time advances by at
/// least [`SLEEP_JUMP_THRESHOLD_SECS`].
///
/// Both inputs come from monotonic kernel clocks, so a wall-clock or NTP step
/// cannot trigger a false network reset. Mirrors `detect_boottime_sleep_jump`.
fn detect_boottime_sleep_jump(previous: Duration, now: Duration) -> bool {
    now.saturating_sub(previous) >= Duration::from_secs(SLEEP_JUMP_THRESHOLD_SECS)
}

/// Computes the next healthy/idle probe interval with deterministic
/// pseudo-random jitter, so idle probes do not emit a fixed-period beacon.
fn next_healthy_probe_interval(seed: u64) -> Duration {
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    let jitter_secs = z % (IDLE_PROBE_JITTER_MAX_SECS + 1);
    HEALTHY_PROBE_INTERVAL + Duration::from_secs(jitter_secs)
}

/// Bounded exponential backoff for reconnect probes and route retries.
fn next_offline_backoff(current_secs: u64) -> u64 {
    current_secs
        .saturating_mul(2)
        .clamp(INITIAL_OFFLINE_BACKOFF_SECS, MAX_OFFLINE_BACKOFF_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_failures_win_over_a_successful_probe() {
        assert_eq!(
            probe_tick_decision(true, 9, Some(10)),
            Some((STATE_WAITING_NETWORK, "no_gateway", None))
        );
        assert_eq!(
            probe_tick_decision(false, DEGRADED_DIAL_FAILURE_STREAK, Some(10)),
            Some((STATE_RECONNECTING, "dial_failures", None))
        );
        assert_eq!(
            probe_tick_decision(false, 1, Some(10)),
            Some((STATE_CONNECTED, "dial_activity", Some(10)))
        );
        assert_eq!(probe_tick_decision(false, 0, None), None);
    }

    #[test]
    fn fresh_dial_moves_a_startup_client_through_the_health_states() {
        let activity = TunnelActivity::new();
        let tick = |no_gateway| {
            activity_tick_decision(
                no_gateway,
                activity.recent_failure_streak(DEGRADED_WINDOW),
                RECENT_ACTIVITY_WINDOW,
                &activity,
            )
        };

        // Startup: only a bare probe can succeed, so the tick falls back to
        // reachability and must report idle, never connected.
        assert_eq!(tick(false), None);
        let (state, reason, _) = bare_probe_tick_decision(12);
        assert_eq!((state, reason), (STATE_IDLE, "probe_ok"));

        // A fresh authenticated dial after startup is enough for green; it
        // must not need a previous connected tick to open the gate.
        activity.record_dial_success(21);
        assert_eq!(
            tick(false),
            Some((STATE_CONNECTED, "dial_activity", Some(21)))
        );

        // Fresh dial failures override the still-recent RTT.
        for _ in 0..DEGRADED_DIAL_FAILURE_STREAK {
            activity.record_dial_failure(beam_tun::DialFailure {
                stage: beam_tun::DialFailureStage::TcpConnect,
                kind: beam_tun::DialFailureKind::Refused,
            });
        }
        assert_eq!(activity.recent_rtt(RECENT_ACTIVITY_WINDOW), Some(21));
        assert_eq!(
            tick(false),
            Some((STATE_RECONNECTING, "dial_failures", None))
        );

        // A missing gateway wins over every other signal.
        assert_eq!(
            tick(true),
            Some((STATE_WAITING_NETWORK, "no_gateway", None))
        );
    }

    #[test]
    fn probe_only_success_reports_idle() {
        assert_eq!(
            bare_probe_tick_decision(12),
            (STATE_IDLE, "probe_ok", Some(12))
        );
    }

    #[test]
    fn backoff_is_bounded() {
        assert_eq!(next_offline_backoff(2), 4);
        assert_eq!(next_offline_backoff(8), 10);
        assert_eq!(next_offline_backoff(10), 10);
        assert_eq!(next_offline_backoff(u64::MAX), MAX_OFFLINE_BACKOFF_SECS);
    }

    #[test]
    fn sleep_jump_ignores_clock_steps_and_detects_suspend() {
        let offset = Duration::from_secs(120);
        assert!(!detect_boottime_sleep_jump(offset, offset));
        assert!(!detect_boottime_sleep_jump(
            offset,
            offset + Duration::from_secs(4)
        ));
        assert!(!detect_boottime_sleep_jump(
            offset,
            offset - Duration::from_secs(10)
        ));
        assert!(detect_boottime_sleep_jump(
            offset,
            offset + Duration::from_secs(SLEEP_JUMP_THRESHOLD_SECS)
        ));
    }

    #[test]
    fn healthy_probe_interval_is_jittered_and_bounded() {
        let mut seen = Vec::new();
        for seed in 0..64 {
            let interval = next_healthy_probe_interval(seed);
            assert!(interval >= HEALTHY_PROBE_INTERVAL, "{interval:?}");
            assert!(
                interval
                    <= HEALTHY_PROBE_INTERVAL + Duration::from_secs(IDLE_PROBE_JITTER_MAX_SECS),
                "{interval:?}"
            );
            seen.push(interval);
        }
        assert!(seen.iter().any(|value| *value != seen[0]));
    }

    #[test]
    fn monitor_sleep_never_spins_and_is_capped() {
        let far = Duration::from_secs(3600);
        assert_eq!(
            next_wait_duration(Duration::from_secs(10), far, far),
            Duration::from_secs(10)
        );
        assert_eq!(next_wait_duration(far, far, far), SLEEP_CHECK_INTERVAL);
        assert_eq!(
            next_wait_duration(Duration::ZERO, far, far),
            Duration::from_millis(50)
        );
    }

    #[test]
    fn status_file_carries_the_documented_keys() {
        let mut status = IpcStatus::disconnected(Some("203.0.113.10:443".parse().unwrap()));
        status.state = STATE_CONNECTED.to_owned();
        status.ifname = "Beam".to_owned();
        status.reason = "dial_activity".to_owned();
        status.rtt_ms = Some(42);
        status.bypass_ok = true;
        status.dial_failures = 2;
        status.generation = 5;
        let text = format_status_file(&status);
        for key in [
            "state=connected",
            "ifname=Beam",
            "ts=",
            "pid=",
            "reason=dial_activity",
            "generation=5",
            "bypass_ok=1",
            "dial_failures=2",
            "server=203.0.113.10:443",
            "rtt_ms=42",
        ] {
            assert!(text.contains(key), "missing {key} in {text}");
        }
        assert!(!text.contains("drops="));
    }

    #[test]
    fn status_file_never_accepts_an_injected_key() {
        let mut status = IpcStatus::disconnected(None);
        status.state = "connected\nstate=error".to_owned();
        status.ifname = "Beam\nstate=error".to_owned();
        status.reason = "dial\nfailures".to_owned();
        status.drops = Some("line\rbreak".to_owned());
        let text = format_status_file(&status);
        assert!(!text.contains("\nstate=error"), "{text}");
        assert!(!text.contains('\r'), "{text}");
        assert!(text.contains("state=connected_state=error\n"), "{text}");
        assert!(text.contains("ifname=Beam_state=error\n"), "{text}");
        assert!(text.contains("reason=dial_failures\n"), "{text}");
        assert!(text.contains("drops=line_break\n"), "{text}");
    }
}
