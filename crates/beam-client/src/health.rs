//! Always-on network transition detector, sleep/resume watcher, bounded-backoff
//! server reachability probe, and atomic status file publisher for `linux-tray`.

use std::io::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use beam_sys::{NetlinkRouteWatcher, boottime_offset};
use beam_tun::{IpNet, TunnelActivity};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::config::detect_system_local_dns_excluding;
use crate::linux_tun::{LinuxRouteGuard, PhysicalGateways, detect_physical_gateways_excluding};

/// Default runtime status file path (owned by `RuntimeDirectory=beam-client`).
pub const DEFAULT_STATUS_PATH: &str = "/run/beam-client/status";

const FALLBACK_POLL_TICK: Duration = Duration::from_secs(2);
const SLEEP_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const ROUTE_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const NETLINK_COALESCE_DELAY: Duration = Duration::from_millis(150);
const SLEEP_JUMP_THRESHOLD_SECS: u64 = 5;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const HEALTHY_PROBE_INTERVAL: Duration = Duration::from_secs(60);
const RECENT_ACTIVITY_WINDOW: Duration = Duration::from_secs(75);
const IDLE_PROBE_JITTER_MAX_SECS: u64 = 15;
const INITIAL_OFFLINE_BACKOFF_SECS: u64 = 2;
const MAX_OFFLINE_BACKOFF_SECS: u64 = 10;

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
                            guard.update_bypass_gateway(&gw_clone, local_dns);
                            guard.bypass_routes_installed()
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

            if Instant::now() >= next_probe_at {
                if auto_route && !server_has_gw && !server_addr.ip().is_loopback() {
                    is_connected = false;
                    write_status_atomic(&status_path, LinkState::WaitingNetwork, None, &ifname);
                    next_probe_at = Instant::now() + Duration::from_secs(offline_backoff_secs);
                    offline_backoff_secs = next_offline_backoff(offline_backoff_secs);
                } else {
                    let recent_window = match last_reset_at {
                        Some(reset_at) => RECENT_ACTIVITY_WINDOW
                            .min(Instant::now().saturating_duration_since(reset_at)),
                        None => RECENT_ACTIVITY_WINDOW,
                    };
                    let recent_rtt = if is_connected && !recent_window.is_zero() {
                        activity.recent_rtt(recent_window)
                    } else {
                        None
                    };
                    if let Some(rtt_ms) = recent_rtt {
                        write_status_atomic(
                            &status_path,
                            LinkState::Connected,
                            Some(rtt_ms),
                            &ifname,
                        );
                        offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
                        probe_seq = probe_seq.wrapping_add(1);
                        next_probe_at = Instant::now() + next_healthy_probe_interval(probe_seq);
                    } else {
                        match probe_server_rtt(server_addr).await {
                            Some(rtt_ms) => {
                                is_connected = true;
                                write_status_atomic(
                                    &status_path,
                                    LinkState::Connected,
                                    Some(rtt_ms),
                                    &ifname,
                                );
                                offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
                                probe_seq = probe_seq.wrapping_add(1);
                                next_probe_at =
                                    Instant::now() + next_healthy_probe_interval(probe_seq);
                            }
                            None => {
                                is_connected = false;
                                debug!(%server_addr, backoff_secs = offline_backoff_secs, "server reachability probe failed");
                                write_status_atomic(
                                    &status_path,
                                    LinkState::Reconnecting,
                                    None,
                                    &ifname,
                                );
                                next_probe_at =
                                    Instant::now() + Duration::from_secs(offline_backoff_secs);
                                offline_backoff_secs = next_offline_backoff(offline_backoff_secs);
                            }
                        }
                    }
                }
            }

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

/// Computes one monitor sleep. With `auto_route` and no netlink watcher the
/// loop must poll routes, so it stays on [`FALLBACK_POLL_TICK`]; otherwise
/// (including `auto_route = false`) it may sleep up to
/// [`SLEEP_CHECK_INTERVAL`] and still wakes for the next probe.
fn next_wait_duration(
    until_probe: Duration,
    until_route_check: Duration,
    until_route_retry: Duration,
    auto_route: bool,
    has_netlink: bool,
) -> Duration {
    let max_sleep = if auto_route && !has_netlink {
        FALLBACK_POLL_TICK
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

async fn probe_server_rtt(server_addr: SocketAddr) -> Option<u64> {
    let start = Instant::now();
    match timeout(PROBE_TIMEOUT, TcpStream::connect(server_addr)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            Some(start.elapsed().as_millis() as u64)
        }
        _ => None,
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

/// Formats status text consumed by `beam-tray` (includes Unix timestamp & PID
/// so the tray ignores stale files after a crash).
pub fn format_status(state: LinkState, rtt_ms: Option<u64>, ifname: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut out = format!(
        "state={}\nifname={ifname}\nts={ts}\npid={pid}\n",
        state.as_str()
    );
    if let Some(rtt) = rtt_ms {
        out.push_str(&format!("rtt_ms={rtt}\n"));
    }
    out
}

/// Atomically writes and fsyncs the status file if its parent directory exists.
pub fn write_status_atomic(path: &Path, state: LinkState, rtt_ms: Option<u64>, ifname: &str) {
    let Some(parent) = path.parent() else {
        return;
    };
    if !parent.is_dir() {
        return;
    }
    let tmp = path.with_extension("tmp");
    let body = format_status(state, rtt_ms, ifname);
    let written = std::fs::File::create(&tmp).and_then(|mut file| {
        file.write_all(body.as_bytes())?;
        file.sync_all()
    });
    if written.is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
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
        assert_eq!(next_wait_duration(probe, far, far, false, false), probe);
        assert_eq!(
            next_wait_duration(far, far, far, false, false),
            SLEEP_CHECK_INTERVAL
        );

        // Auto-route without netlink needs the 2 s fallback poll.
        assert_eq!(
            next_wait_duration(probe, far, far, true, false),
            FALLBACK_POLL_TICK
        );

        // Auto-route with netlink follows the probe schedule.
        assert_eq!(next_wait_duration(probe, far, far, true, true), probe);
        assert_eq!(
            next_wait_duration(far, far, far, true, true),
            SLEEP_CHECK_INTERVAL
        );

        // A due deadline never yields a spin loop.
        assert_eq!(
            next_wait_duration(Duration::ZERO, far, far, true, true),
            Duration::from_millis(50)
        );
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
        write_status_atomic(&path, LinkState::Connected, Some(37), "beamtun0");
        let text = std::fs::read_to_string(&path).expect("read status");
        assert!(text.contains("state=connected\n"));
        assert!(text.contains("rtt_ms=37\n"));
        assert!(text.contains("ifname=beamtun0\n"));
        assert!(text.contains("ts="));
        assert!(text.contains("pid="));
        let _ = std::fs::remove_dir_all(&dir);
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
