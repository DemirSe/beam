//! Always-on network transition detector, sleep/resume watcher, bounded-backoff
//! server reachability probe, and atomic status file publisher for `linux-tray`.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};
use tracing::{debug, info};

use crate::config::detect_system_local_dns;
use crate::linux_tun::{LinuxRouteGuard, PhysicalGateways, detect_physical_gateways_excluding};

/// Default runtime status file path (owned by `RuntimeDirectory=beam-client`).
pub const DEFAULT_STATUS_PATH: &str = "/run/beam-client/status";

const MONITOR_TICK: Duration = Duration::from_secs(2);
const SLEEP_JUMP_THRESHOLD_SECS: u64 = 5;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const HEALTHY_PROBE_INTERVAL: Duration = Duration::from_secs(60);
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
/// 4. Probes `server_addr` with low-noise 60 s healthy cadence and bounded
///    backoff during outages, publishing timestamped status + RTT for `beam-tray`.
#[allow(clippy::too_many_arguments)]
pub fn spawn_network_monitor(
    ifname: String,
    server_addr: SocketAddr,
    auto_route: bool,
    fixed_local_dns: Option<IpAddr>,
    routes: Arc<Mutex<LinuxRouteGuard>>,
    network_reset_tx: watch::Sender<u64>,
    mut shutdown: watch::Receiver<bool>,
    status_path: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _guard = StatusFileGuard::new(status_path.clone());
        let mut last_gw = if auto_route {
            let name = ifname.clone();
            tokio::task::spawn_blocking(move || detect_physical_gateways_excluding(&name))
                .await
                .unwrap_or_default()
        } else {
            PhysicalGateways::default()
        };
        let mut last_mono = Instant::now();
        let mut last_wall = SystemTime::now();
        let mut next_probe_at = Instant::now();
        let mut offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
        let mut generation: u64 = 0;

        loop {
            if *shutdown.borrow() {
                break;
            }

            let now_mono = Instant::now();
            let now_wall = SystemTime::now();
            let slept_from_suspend = detect_sleep_jump(last_mono, now_mono, last_wall, now_wall);
            last_mono = now_mono;
            last_wall = now_wall;

            let current_gw = if auto_route {
                let name = ifname.clone();
                tokio::task::spawn_blocking(move || detect_physical_gateways_excluding(&name))
                    .await
                    .unwrap_or_default()
            } else {
                PhysicalGateways::default()
            };

            let bypass_missing = if auto_route {
                let routes_chk = Arc::clone(&routes);
                tokio::task::spawn_blocking(move || {
                    routes_chk
                        .lock()
                        .map(|g| !g.server_bypass_installed())
                        .unwrap_or(false)
                })
                .await
                .unwrap_or(false)
            } else {
                false
            };

            let gw_changed = auto_route && current_gw != last_gw;
            let has_any_gw = current_gw.v4.is_some() || current_gw.v6.is_some();

            if gw_changed || slept_from_suspend || (bypass_missing && has_any_gw) {
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
                        let local_dns =
                            fixed_local_dns.or_else(|| detect_system_local_dns().map(|s| s.ip()));
                        if let Ok(mut guard) = routes_upd.lock() {
                            guard.update_bypass_gateway(&gw_clone, local_dns);
                            guard.server_bypass_installed()
                        } else {
                            false
                        }
                    })
                    .await
                    .unwrap_or(false);
                    if installed || !has_any_gw {
                        last_gw = current_gw.clone();
                    }
                }
                if gw_changed || slept_from_suspend {
                    generation = generation.wrapping_add(1);
                    let _ = network_reset_tx.send(generation);
                }
                offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
                next_probe_at = Instant::now();
            }

            if Instant::now() >= next_probe_at {
                let server_has_gw = match server_addr.ip() {
                    IpAddr::V4(_) => current_gw.v4.is_some(),
                    IpAddr::V6(_) => current_gw.v6.is_some(),
                };
                if auto_route && !server_has_gw && !server_addr.ip().is_loopback() {
                    write_status_atomic(&status_path, LinkState::WaitingNetwork, None, &ifname);
                    next_probe_at = Instant::now() + Duration::from_secs(offline_backoff_secs);
                    offline_backoff_secs = next_offline_backoff(offline_backoff_secs);
                } else {
                    match probe_server_rtt(server_addr).await {
                        Some(rtt_ms) => {
                            write_status_atomic(
                                &status_path,
                                LinkState::Connected,
                                Some(rtt_ms),
                                &ifname,
                            );
                            offline_backoff_secs = INITIAL_OFFLINE_BACKOFF_SECS;
                            next_probe_at = Instant::now() + HEALTHY_PROBE_INTERVAL;
                        }
                        None => {
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

            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                () = sleep(MONITOR_TICK) => {}
            }
        }
    })
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

/// Detects a suspend/resume jump when wall-clock time advanced significantly
/// further than monotonic elapsed time.
pub fn detect_sleep_jump(
    prev_mono: Instant,
    now_mono: Instant,
    prev_wall: SystemTime,
    now_wall: SystemTime,
) -> bool {
    let mono_delta = now_mono.saturating_duration_since(prev_mono);
    let Ok(wall_delta) = now_wall.duration_since(prev_wall) else {
        return false;
    };
    wall_delta.saturating_sub(mono_delta) >= Duration::from_secs(SLEEP_JUMP_THRESHOLD_SECS)
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

/// Atomically writes the status file if its parent directory exists.
pub fn write_status_atomic(path: &Path, state: LinkState, rtt_ms: Option<u64>, ifname: &str) {
    let Some(parent) = path.parent() else {
        return;
    };
    if !parent.is_dir() {
        return;
    }
    let tmp = path.with_extension("tmp");
    let body = format_status(state, rtt_ms, ifname);
    if std::fs::write(&tmp, body).is_ok() {
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
    fn detects_wall_clock_sleep_jump() {
        let m0 = Instant::now();
        let w0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let w_normal = w0 + Duration::from_secs(2);
        let w_jumped = w0 + Duration::from_secs(60);
        assert!(!detect_sleep_jump(m0, m0, w0, w_normal));
        assert!(detect_sleep_jump(m0, m0, w0, w_jumped));
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
}
