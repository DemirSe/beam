//! Async Linux `/dev/net/tun` adapter implementing `beam_tun::TunDevice`,
//! plus rollback-safe Linux IPv4/IPv6 route management (`LinuxRouteGuard`).

#[cfg(test)]
use std::cell::Cell;
use std::collections::VecDeque;
use std::io::{self, Read as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{LazyLock, OnceLock};
use std::time::{Duration, Instant};

use beam_sys::LinuxTun;
use beam_tun::{IpNet, RateLimiter, TUN_V6_NET, TunDevice};
use tokio::io::unix::AsyncFd;
use tracing::{debug, info, warn};

/// Default runtime state file tracking bypass routes installed by this daemon
/// so `ExecStopPost=/usr/local/bin/beam-client --cleanup-routes` can remove
/// orphaned routes after a `SIGKILL`/OOM crash.
pub const DEFAULT_ROUTES_STATE_PATH: &str = "/run/beam-client/routes.state";

const MAX_DYNAMIC_BYPASS_IPS: usize = 256;
const DYNAMIC_BYPASS_TTL: Duration = Duration::from_secs(3600);
const MAX_PERSISTED_ROUTES: usize = 1024;
const IP_CHILD_DEADLINE: Duration = Duration::from_millis(500);
const IP_CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_IP_OUTPUT_BYTES: u64 = 64 * 1024;
/// Keep the whole shutdown/cleanup sequence below `TimeoutStopSec=45s`.
const SHUTDOWN_IP_BUDGET: Duration = Duration::from_secs(30);
/// At most one `warn!` for a full dynamic-bypass table per interval and address
/// family, so a busy host with `bypass.domains` cannot flood the journal and an
/// IPv4 warning does not silence IPv6.
const DYNAMIC_BYPASS_CAP_WARN_INTERVAL: Duration = Duration::from_secs(600);
static DYNAMIC_BYPASS_CAP_WARNED_V4_AT: std::sync::Mutex<Option<Instant>> =
    std::sync::Mutex::new(None);
static DYNAMIC_BYPASS_CAP_WARNED_V6_AT: std::sync::Mutex<Option<Instant>> =
    std::sync::Mutex::new(None);

/// At most 3 exact-route lookup warnings per 60 s window.
static ROUTE_CHECK_LOG: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(3, Duration::from_secs(60)));
/// Resolved `ip` (iproute2) path, cached only on success so a package installed
/// after startup is still picked up on the next call.
static IP_BINARY: OnceLock<&'static str> = OnceLock::new();

#[cfg(test)]
std::thread_local! {
    static TEST_IP_BINARY: Cell<Option<&'static str>> = const { Cell::new(None) };
}

/// Returns `true` when the cap warning is due, so it fires once per interval.
fn cap_warn_due(last: Option<Instant>, now: Instant) -> bool {
    last.is_none_or(|t| now.saturating_duration_since(t) >= DYNAMIC_BYPASS_CAP_WARN_INTERVAL)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }
}

fn warn_dynamic_bypass_cap(family: IpFamily) {
    let now = Instant::now();
    let slot = match family {
        IpFamily::V4 => &DYNAMIC_BYPASS_CAP_WARNED_V4_AT,
        IpFamily::V6 => &DYNAMIC_BYPASS_CAP_WARNED_V6_AT,
    };
    let Ok(mut last) = slot.lock() else {
        return;
    };
    if !cap_warn_due(*last, now) {
        return;
    }
    *last = Some(now);
    warn!(
        family = family.as_str(),
        cap = MAX_DYNAMIC_BYPASS_IPS,
        "dynamic bypass.domains route table is full; evicting the oldest route"
    );
}

/// Detected physical IPv4 and IPv6 default gateways `(optional_gw_ip, dev)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PhysicalGateways {
    pub v4: Option<(Option<String>, String)>,
    pub v6: Option<(Option<String>, String)>,
}

/// Async wrapper around [`beam_sys::LinuxTun`].
pub struct AsyncLinuxTun {
    inner: AsyncFd<LinuxTun>,
    mtu: usize,
}

impl AsyncLinuxTun {
    /// Opens a Linux TUN interface and wraps it in Tokio's `AsyncFd`.
    pub fn open(name: &str, mtu: usize) -> io::Result<Self> {
        let tun = LinuxTun::open(name)?;
        // `LinuxTun` owns its `OwnedFd` for its full lifetime, satisfying
        // Tokio's I/O safety invariant while keeping `beam-client` free of
        // `unsafe` (`AsyncFd::register` requires `unsafe`).
        #[allow(deprecated)]
        let inner = AsyncFd::new(tun)?;
        Ok(Self { inner, mtu })
    }

    /// Returns the kernel-assigned interface name.
    pub fn name(&self) -> &str {
        self.inner.get_ref().name()
    }
}

impl TunDevice for AsyncLinuxTun {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.inner.get_ref().read_packet(buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TUN device returned EOF",
                    ));
                }
                Ok(n) => return Ok(n),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err),
            }
        }
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read_packet(buf)) {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TUN device returned EOF",
                    ));
                }
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }

    fn try_recv_into(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        loop {
            match self.inner.get_ref().read_packet(buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TUN device returned EOF",
                    ));
                }
                Ok(n) => return Ok(Some(n)),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(err) => return Err(err),
            }
        }
    }

    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        loop {
            match self.inner.get_ref().write_packet(packet) {
                Ok(_) => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err),
            }
        }
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().write_packet(packet)) {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }
}

/// Configures IP address, MTU, link UP, optional default split-routes
/// (`0.0.0.0/1`, `128.0.0.0/1`, IPv6 `::/1`, `8000::/1`), bypass routes for
/// the `beam` server, local DNS upstream, and `[bypass]` CIDRs/domains on Linux.
///
/// Tracks every route it installs so both partial `setup()` failures and clean
/// shutdowns roll back **only** the routes installed by this guard.
pub struct LinuxRouteGuard {
    ifname: String,
    auto_route: bool,
    routes_state_path: PathBuf,
    tun_v4_net: Option<IpNet>,
    server_ip: IpAddr,
    local_dns_ip: Option<IpAddr>,
    configured_bypass_v4: Vec<String>,
    configured_bypass_v6: Vec<String>,
    dynamic_bypass_v4: VecDeque<(Ipv4Addr, Instant)>,
    dynamic_bypass_v6: VecDeque<(Ipv6Addr, Instant)>,
    current_gw: PhysicalGateways,
    installed_v4_low: bool,
    installed_v4_high: bool,
    installed_v6_low: bool,
    installed_v6_high: bool,
    server_bypass_route: Option<(IpAddr, Option<String>, String)>,
    server_bypass_preexisting: bool,
    local_dns_bypass_route: Option<(IpAddr, Option<String>, String)>,
    local_dns_bypass_preexisting: bool,
    extra_bypass_v4: Vec<(String, Option<String>, String)>,
    extra_bypass_v6: Vec<(String, Option<String>, String)>,
}

/// A single bypass route persisted to `/run/beam-client/routes.state` for
/// crash-recovery cleanup (`--cleanup-routes`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedRoute {
    /// Address family: `4` (IPv4) or `6` (IPv6).
    pub family: u8,
    /// Prefix in CIDR notation (e.g. `203.0.113.10/32`).
    pub prefix: String,
    /// Optional gateway IP (`via <gw>`).
    pub gateway: Option<String>,
    /// Output network device (`dev <dev>`).
    pub dev: String,
}

impl LinuxRouteGuard {
    /// Brings up `ifname` with `cidr` and `mtu`. When `auto_route` is `true`,
    /// installs bypass routes first, then routes IPv4 (`0.0.0.0/1`, `128.0.0.0/1`)
    /// and IPv6 (`::/1`, `8000::/1`) through `ifname`.
    ///
    /// Fail-closed: if no physical default gateway exists at startup, TUN split
    /// routes are still installed so traffic never leaks in the clear.
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        ifname: &str,
        cidr: &str,
        mtu: usize,
        auto_route: bool,
        server_ip: IpAddr,
        local_dns_ip: Option<IpAddr>,
        tun_dns_peer: Option<Ipv4Addr>,
        bypass_cidrs: &[String],
    ) -> io::Result<Self> {
        run_ip(&["addr", "replace", cidr, "dev", ifname])?;
        run_ip(&["link", "set", "dev", ifname, "mtu", &mtu.to_string(), "up"])?;

        let configured_bypass_v4: Vec<String> = bypass_cidrs
            .iter()
            .filter(|c| is_ipv4_cidr(c))
            .map(|c| canonical_cidr(c).unwrap_or_else(|| c.clone()))
            .collect();
        let configured_bypass_v6: Vec<String> = bypass_cidrs
            .iter()
            .filter(|c| is_ipv6_cidr(c))
            .map(|c| canonical_cidr(c).unwrap_or_else(|| c.clone()))
            .collect();

        let mut guard = Self {
            ifname: ifname.to_owned(),
            auto_route,
            routes_state_path: PathBuf::from(DEFAULT_ROUTES_STATE_PATH),
            tun_v4_net: IpNet::parse_cidr(cidr),
            server_ip,
            local_dns_ip,
            configured_bypass_v4,
            configured_bypass_v6,
            dynamic_bypass_v4: VecDeque::new(),
            dynamic_bypass_v6: VecDeque::new(),
            current_gw: PhysicalGateways::default(),
            installed_v4_low: false,
            installed_v4_high: false,
            installed_v6_low: false,
            installed_v6_high: false,
            server_bypass_route: None,
            server_bypass_preexisting: false,
            local_dns_bypass_route: None,
            local_dns_bypass_preexisting: false,
            extra_bypass_v4: Vec::new(),
            extra_bypass_v6: Vec::new(),
        };

        if auto_route {
            // Reclaim any orphaned bypass routes left behind by an unclean exit
            // outside systemd before probing pre-existing routes.
            let _ = cleanup_persisted_routes(&guard.routes_state_path);
            let detected_gw = detect_physical_gateways_excluding(ifname);
            if detected_gw.v4.is_none() && detected_gw.v6.is_none() {
                warn!(
                    "no physical default gateway detected at startup; running fail-closed until network comes up"
                );
            }
            if !guard.update_bypass_gateway(&detected_gw, local_dns_ip) {
                warn!(
                    "initial bypass route reconcile incomplete due to ip lookup error; TUN split routes stay installed and monitor will retry"
                );
            }

            run_ip(&["route", "replace", "0.0.0.0/1", "dev", ifname])?;
            guard.installed_v4_low = true;
            run_ip(&["route", "replace", "128.0.0.0/1", "dev", ifname])?;
            guard.installed_v4_high = true;
            info!(dev = %ifname, "installed IPv4 TUN split routes (0.0.0.0/1, 128.0.0.0/1)");

            // Route IPv6 into the TUN as well so dual-stack hosts do not leak
            // IPv6 outside the tunnel; ignore on IPv4-only kernels.
            match run_ip(&["-6", "addr", "replace", "fd00:be:a::1/126", "dev", ifname]) {
                Ok(()) => {
                    run_ip(&["-6", "route", "replace", "::/1", "dev", ifname])?;
                    guard.installed_v6_low = true;
                    run_ip(&["-6", "route", "replace", "8000::/1", "dev", ifname])?;
                    guard.installed_v6_high = true;
                    info!(dev = %ifname, "installed IPv6 TUN split routes (::/1, 8000::/1)");
                }
                Err(err) => {
                    debug!(
                        dev = %ifname,
                        error = %err,
                        "IPv6 TUN address unavailable; skipping IPv6 split routes"
                    );
                }
            }

            // When built-in DNS interception is enabled on a systemd-resolved
            // desktop, point per-link DNS at the TUN peer IP so queries enter
            // `beamtun0` instead of leaking over the LAN router's /24 route.
            // systemd-resolved automatically reverts per-link DNS when the TUN closes.
            if let Some(peer_ip) = tun_dns_peer {
                configure_resolved_link_dns(ifname, peer_ip);
            }
        }

        Ok(guard)
    }

    /// Returns `true` if `ip` lies inside the TUN IPv4 or IPv6 subnet.
    fn is_in_tun_subnet(&self, ip: IpAddr) -> bool {
        self.tun_v4_net.is_some_and(|net| net.contains(ip)) || TUN_V6_NET.contains(ip)
    }

    /// Returns `true` if every tracked bypass route is installed (or
    /// preserved as a pre-existing host route) and present in the kernel
    /// routing table.
    ///
    /// A lookup that cannot be completed ([`RouteCheck::Error`]) counts as
    /// missing (fail-closed): the monitor keeps retrying, while the rate-limited
    /// warning from the route snapshot carries the reason once per window.
    pub fn bypass_routes_installed(&self) -> bool {
        if !self.auto_route {
            return true;
        }
        let snapshot = RouteSnapshot::load(&self.current_gw);
        self.bypass_routes_installed_with(&self.current_gw, self.local_dns_ip, |flag, prefix| {
            snapshot.check(flag, prefix)
        })
        .is_installed()
    }

    fn bypass_routes_installed_with<F>(
        &self,
        gw: &PhysicalGateways,
        local_dns: Option<IpAddr>,
        mut check: F,
    ) -> BypassRouteState
    where
        F: FnMut(&str, &str) -> RouteCheck,
    {
        if !self.auto_route {
            return BypassRouteState::Installed;
        }
        let mut state = BypassRouteState::Installed;
        let mut checked = |flag: &str, prefix: &str| {
            let result = check(flag, prefix);
            if let Some(err) = result.error() {
                debug!(prefix = %prefix, error = %err, "bypass route lookup unresolved");
            }
            result
        };
        if !self.server_ip.is_loopback() && gateway_for_ip(gw, self.server_ip).is_some() {
            if self.server_bypass_route.is_none() && !self.server_bypass_preexisting {
                state = state.merge(BypassRouteState::Absent);
            } else {
                let (flag, prefix) = host_route_args(self.server_ip);
                state = state.merge(checked(flag, &prefix).into());
            }
        }
        if let Some(dns_ip) = local_dns
            && !dns_ip.is_loopback()
            && dns_ip != self.server_ip
            && !self.is_in_tun_subnet(dns_ip)
            && gateway_for_ip(gw, dns_ip).is_some()
        {
            if self.local_dns_bypass_route.is_none() && !self.local_dns_bypass_preexisting {
                state = state.merge(BypassRouteState::Absent);
            } else {
                let (flag, prefix) = host_route_args(dns_ip);
                state = state.merge(checked(flag, &prefix).into());
            }
        }
        if gw.v4.is_some() {
            for cidr in &self.configured_bypass_v4 {
                state = state.merge(checked("-4", cidr).into());
            }
            for &(ip, _) in &self.dynamic_bypass_v4 {
                let prefix = format!("{ip}/32");
                state = state.merge(checked("-4", &prefix).into());
            }
        }
        if gw.v6.is_some() {
            for cidr in &self.configured_bypass_v6 {
                state = state.merge(checked("-6", cidr).into());
            }
            for &(ip, _) in &self.dynamic_bypass_v6 {
                let prefix = format!("{ip}/128");
                state = state.merge(checked("-6", &prefix).into());
            }
        }
        state
    }

    /// Expires tracked dynamic bypass routes on a quiet host. DNS hits still
    /// re-stamp their timestamp; this only applies the same bounded TTL eviction.
    pub fn sweep_expired_dynamic_bypass(&mut self) {
        let now = Instant::now();
        self.evict_v4(now, false);
        self.evict_v6(now, false);
    }

    /// Migrates server, local-DNS, and bypass CIDR/domain routes to `new_gw`
    /// while keeping TUN split routes active (fail-closed kill-switch) and
    /// preserving any pre-existing exact routes in the main table.
    ///
    /// A failed exact-route lookup (`ip` missing, transient non-zero exit) is
    /// not treated as "route absent": the whole reconcile is skipped for this
    /// cycle, so every route keeps its last-known state.
    ///
    /// Returns `false` if a pre-check or recheck lookup failed, so callers keep
    /// their retry timer instead of treating the reconcile as complete.
    /// `route_check_error` logs the rate-limited warning that carries the signal.
    pub fn update_bypass_gateway(
        &mut self,
        new_gw: &PhysicalGateways,
        new_local_dns: Option<IpAddr>,
    ) -> bool {
        if !self.auto_route {
            return true;
        }
        let snapshot = RouteSnapshot::load(new_gw);
        let state = self.bypass_routes_installed_with(new_gw, new_local_dns, |flag, prefix| {
            snapshot.check(flag, prefix)
        });
        // A genuine miss authorizes the reinstall. When any route is an error,
        // keep the last-known routes and let the caller retry.
        if state == BypassRouteState::Error {
            return false;
        }

        for (prefix, maybe_gw, dev) in self.extra_bypass_v4.drain(..) {
            let _ = remove_v4_bypass(&prefix, maybe_gw.as_deref(), &dev);
        }
        for (prefix, maybe_gw, dev) in self.extra_bypass_v6.drain(..) {
            let _ = remove_v6_bypass(&prefix, maybe_gw.as_deref(), &dev);
        }
        if let Some((ip, maybe_gw, dev)) = self.local_dns_bypass_route.take() {
            let _ = remove_host_bypass(ip, maybe_gw.as_deref(), &dev);
        }
        if let Some((ip, maybe_gw, dev)) = self.server_bypass_route.take() {
            let _ = remove_host_bypass(ip, maybe_gw.as_deref(), &dev);
        }
        self.server_bypass_preexisting = false;
        self.local_dns_bypass_preexisting = false;

        let now = Instant::now();
        self.dynamic_bypass_v4
            .retain(|(_, ts)| now.saturating_duration_since(*ts) < DYNAMIC_BYPASS_TTL);
        self.dynamic_bypass_v6
            .retain(|(_, ts)| now.saturating_duration_since(*ts) < DYNAMIC_BYPASS_TTL);

        self.current_gw = new_gw.clone();
        self.local_dns_ip = new_local_dns;
        let recheck = RouteSnapshot::load(new_gw);
        let mut recheck_failed = false;

        if !self.server_ip.is_loopback()
            && let Some((maybe_gw, dev)) = gateway_for_ip(new_gw, self.server_ip)
        {
            // Re-check after removing our own route: only a route that is still
            // present here was pre-existing and must be preserved.
            let (flag, prefix) = host_route_args(self.server_ip);
            match recheck.check(flag, &prefix) {
                RouteCheck::Present => {
                    info!(ip = %self.server_ip, "preserving pre-existing exact route for beam server");
                    self.server_bypass_preexisting = true;
                }
                RouteCheck::Absent => {
                    match install_host_bypass(self.server_ip, maybe_gw.as_deref(), dev) {
                        Ok(()) => {
                            info!(ip = %self.server_ip, via = ?maybe_gw, dev = %dev, "installed server bypass route");
                            self.server_bypass_route =
                                Some((self.server_ip, maybe_gw.clone(), dev.clone()));
                        }
                        Err(err) => {
                            warn!(ip = %self.server_ip, dev = %dev, error = %err, "failed to install server bypass route");
                        }
                    }
                }
                // The lookup is unresolved or the route is linkdown: keep the
                // last-known route state and ask the caller to retry.
                RouteCheck::Unusable | RouteCheck::Error(_) => recheck_failed = true,
            }
        }

        if let Some(dns_ip) = self.local_dns_ip
            && !dns_ip.is_loopback()
            && dns_ip != self.server_ip
            && !self.is_in_tun_subnet(dns_ip)
            && let Some((maybe_gw, dev)) = gateway_for_ip(new_gw, dns_ip)
        {
            let (flag, prefix) = host_route_args(dns_ip);
            match recheck.check(flag, &prefix) {
                RouteCheck::Present => {
                    debug!(ip = %dns_ip, "preserving pre-existing exact route for local DNS");
                    self.local_dns_bypass_preexisting = true;
                }
                RouteCheck::Absent => match install_host_bypass(dns_ip, maybe_gw.as_deref(), dev) {
                    Ok(()) => {
                        debug!(ip = %dns_ip, via = ?maybe_gw, dev = %dev, "installed local DNS bypass route");
                        self.local_dns_bypass_route = Some((dns_ip, maybe_gw.clone(), dev.clone()));
                    }
                    Err(err) => {
                        warn!(ip = %dns_ip, dev = %dev, error = %err, "failed to install local DNS bypass route");
                    }
                },
                // The lookup is unresolved or the route is linkdown: keep the
                // last-known route state and ask the caller to retry.
                RouteCheck::Unusable | RouteCheck::Error(_) => recheck_failed = true,
            }
        }

        if let Some((maybe_gw, dev)) = new_gw.v4.as_ref() {
            for cidr_entry in &self.configured_bypass_v4 {
                match recheck.check("-4", cidr_entry) {
                    RouteCheck::Present => {
                        debug!(cidr = %cidr_entry, "preserving pre-existing exact IPv4 route");
                        continue;
                    }
                    RouteCheck::Absent => {}
                    RouteCheck::Unusable | RouteCheck::Error(_) => {
                        recheck_failed = true;
                        continue;
                    }
                }
                if let Err(err) = install_v4_bypass(cidr_entry, maybe_gw.as_deref(), dev) {
                    warn!(cidr = %cidr_entry, error = %err, "failed to install IPv4 bypass CIDR route");
                } else {
                    self.extra_bypass_v4
                        .push((cidr_entry.clone(), maybe_gw.clone(), dev.clone()));
                }
            }
            for &(ip, _) in &self.dynamic_bypass_v4 {
                let host = format!("{ip}/32");
                match recheck.check("-4", &host) {
                    RouteCheck::Present => {
                        debug!(prefix = %host, "preserving pre-existing exact IPv4 route");
                        continue;
                    }
                    RouteCheck::Absent => {}
                    RouteCheck::Unusable | RouteCheck::Error(_) => {
                        recheck_failed = true;
                        continue;
                    }
                }
                if install_v4_bypass(&host, maybe_gw.as_deref(), dev).is_ok() {
                    info!(prefix = %host, via = ?maybe_gw, dev = %dev, "installed dynamic bypass.domains route");
                    self.extra_bypass_v4
                        .push((host, maybe_gw.clone(), dev.clone()));
                }
            }
        }

        if let Some((maybe_gw, dev)) = new_gw.v6.as_ref() {
            for cidr_entry in &self.configured_bypass_v6 {
                match recheck.check("-6", cidr_entry) {
                    RouteCheck::Present => {
                        debug!(cidr = %cidr_entry, "preserving pre-existing exact IPv6 route");
                        continue;
                    }
                    RouteCheck::Absent => {}
                    RouteCheck::Unusable | RouteCheck::Error(_) => {
                        recheck_failed = true;
                        continue;
                    }
                }
                if let Err(err) = install_v6_bypass(cidr_entry, maybe_gw.as_deref(), dev) {
                    warn!(cidr = %cidr_entry, error = %err, "failed to install IPv6 bypass CIDR route");
                } else {
                    self.extra_bypass_v6
                        .push((cidr_entry.clone(), maybe_gw.clone(), dev.clone()));
                }
            }
            for &(ip, _) in &self.dynamic_bypass_v6 {
                let host = format!("{ip}/128");
                match recheck.check("-6", &host) {
                    RouteCheck::Present => {
                        debug!(prefix = %host, "preserving pre-existing exact IPv6 route");
                        continue;
                    }
                    RouteCheck::Absent => {}
                    RouteCheck::Unusable | RouteCheck::Error(_) => {
                        recheck_failed = true;
                        continue;
                    }
                }
                if install_v6_bypass(&host, maybe_gw.as_deref(), dev).is_ok() {
                    info!(prefix = %host, via = ?maybe_gw, dev = %dev, "installed dynamic bypass.domains route");
                    self.extra_bypass_v6
                        .push((host, maybe_gw.clone(), dev.clone()));
                }
            }
        }

        self.persist_routes_state();
        !recheck_failed
    }

    /// Dynamically installs a `/32` or `/128` bypass route for an IP resolved
    /// from a configured `bypass.domains` entry (TTL-bounded and capped at
    /// [`MAX_DYNAMIC_BYPASS_IPS`] with FIFO eviction; preserves any pre-existing
    /// exact route and logs every installed route at `info` level for auditability).
    pub fn install_dynamic_bypass_ip(&mut self, ip: IpAddr) {
        if !self.auto_route
            || ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip == self.server_ip
            || self.is_in_tun_subnet(ip)
        {
            return;
        }
        let now = Instant::now();
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_link_local() || v4.is_broadcast() {
                    return;
                }
                let was_tracked =
                    if let Some(pos) = self.dynamic_bypass_v4.iter().position(|(a, _)| *a == v4) {
                        self.dynamic_bypass_v4.remove(pos);
                        self.dynamic_bypass_v4.push_back((v4, now));
                        true
                    } else {
                        false
                    };
                // Private RFC1918 destinations are only dynamically bypassed
                // when an active physical IPv4 gateway exists (and pre-existing
                // exact routes are never overwritten).
                let Some((maybe_gw, dev)) = self.current_gw.v4.clone() else {
                    if v4.is_private() {
                        debug!(%v4, "skipping private dynamic bypass.domains IP without IPv4 gateway");
                        return;
                    }
                    if !was_tracked {
                        self.evict_v4(now, true);
                        self.dynamic_bypass_v4.push_back((v4, now));
                    }
                    return;
                };
                self.evict_v4(now, true);
                let host = format!("{v4}/32");
                match has_exact_route("-4", &host) {
                    RouteCheck::Absent => {}
                    RouteCheck::Present | RouteCheck::Unusable => {
                        debug!(prefix = %host, "preserving pre-existing exact route for bypass.domains IP");
                        return;
                    }
                    RouteCheck::Error(_) => {
                        debug!(prefix = %host, "route state unknown; deferring bypass.domains install to the retry path");
                        if !was_tracked {
                            self.dynamic_bypass_v4.push_back((v4, now));
                        }
                        return;
                    }
                }
                match install_v4_bypass(&host, maybe_gw.as_deref(), &dev) {
                    Ok(()) => {
                        info!(prefix = %host, via = ?maybe_gw, dev = %dev, "installed dynamic bypass.domains route");
                        if !was_tracked {
                            self.dynamic_bypass_v4.push_back((v4, now));
                        }
                        self.extra_bypass_v4.push((host, maybe_gw, dev));
                        self.persist_routes_state();
                    }
                    Err(err) => {
                        warn!(prefix = %host, dev = %dev, error = %err, "failed to install dynamic bypass.domains route");
                    }
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_unicast_link_local() {
                    return;
                }
                let was_tracked =
                    if let Some(pos) = self.dynamic_bypass_v6.iter().position(|(a, _)| *a == v6) {
                        self.dynamic_bypass_v6.remove(pos);
                        self.dynamic_bypass_v6.push_back((v6, now));
                        true
                    } else {
                        false
                    };
                let Some((maybe_gw, dev)) = self.current_gw.v6.clone() else {
                    if v6.is_unique_local() {
                        debug!(%v6, "skipping ULA dynamic bypass.domains IP without IPv6 gateway");
                        return;
                    }
                    if !was_tracked {
                        self.evict_v6(now, true);
                        self.dynamic_bypass_v6.push_back((v6, now));
                    }
                    return;
                };
                self.evict_v6(now, true);
                let host = format!("{v6}/128");
                match has_exact_route("-6", &host) {
                    RouteCheck::Absent => {}
                    RouteCheck::Present | RouteCheck::Unusable => {
                        debug!(prefix = %host, "preserving pre-existing exact route for bypass.domains IP");
                        return;
                    }
                    RouteCheck::Error(_) => {
                        debug!(prefix = %host, "route state unknown; deferring bypass.domains install to the retry path");
                        if !was_tracked {
                            self.dynamic_bypass_v6.push_back((v6, now));
                        }
                        return;
                    }
                }
                match install_v6_bypass(&host, maybe_gw.as_deref(), &dev) {
                    Ok(()) => {
                        info!(prefix = %host, via = ?maybe_gw, dev = %dev, "installed dynamic bypass.domains route");
                        if !was_tracked {
                            self.dynamic_bypass_v6.push_back((v6, now));
                        }
                        self.extra_bypass_v6.push((host, maybe_gw, dev));
                        self.persist_routes_state();
                    }
                    Err(err) => {
                        warn!(prefix = %host, dev = %dev, error = %err, "failed to install dynamic bypass.domains route");
                    }
                }
            }
        }
    }

    fn evict_v4(&mut self, now: Instant, enforce_cap: bool) {
        let mut evicted_prefixes = Vec::new();
        while let Some(&(ip, ts)) = self.dynamic_bypass_v4.front() {
            let evict_at_cap =
                enforce_cap && self.dynamic_bypass_v4.len() >= MAX_DYNAMIC_BYPASS_IPS;
            if evict_at_cap {
                warn_dynamic_bypass_cap(IpFamily::V4);
            }
            if now.saturating_duration_since(ts) >= DYNAMIC_BYPASS_TTL || evict_at_cap {
                self.dynamic_bypass_v4.pop_front();
                evicted_prefixes.push(format!("{ip}/32"));
            } else {
                break;
            }
        }
        if !evicted_prefixes.is_empty() {
            let configured = &self.configured_bypass_v4;
            self.extra_bypass_v4.retain(|(prefix, maybe_gw, dev)| {
                if evicted_prefixes.contains(prefix) && !configured.contains(prefix) {
                    let _ = remove_v4_bypass(prefix, maybe_gw.as_deref(), dev);
                    false
                } else {
                    true
                }
            });
            self.persist_routes_state();
        }
    }

    fn evict_v6(&mut self, now: Instant, enforce_cap: bool) {
        let mut evicted_prefixes = Vec::new();
        while let Some(&(ip, ts)) = self.dynamic_bypass_v6.front() {
            let evict_at_cap =
                enforce_cap && self.dynamic_bypass_v6.len() >= MAX_DYNAMIC_BYPASS_IPS;
            if evict_at_cap {
                warn_dynamic_bypass_cap(IpFamily::V6);
            }
            if now.saturating_duration_since(ts) >= DYNAMIC_BYPASS_TTL || evict_at_cap {
                self.dynamic_bypass_v6.pop_front();
                evicted_prefixes.push(format!("{ip}/128"));
            } else {
                break;
            }
        }
        if !evicted_prefixes.is_empty() {
            let configured = &self.configured_bypass_v6;
            self.extra_bypass_v6.retain(|(prefix, maybe_gw, dev)| {
                if evicted_prefixes.contains(prefix) && !configured.contains(prefix) {
                    let _ = remove_v6_bypass(prefix, maybe_gw.as_deref(), dev);
                    false
                } else {
                    true
                }
            });
            self.persist_routes_state();
        }
    }

    fn collect_persisted_routes(&self) -> Vec<PersistedRoute> {
        let mut out = Vec::new();
        if let Some((ip, maybe_gw, dev)) = self.server_bypass_route.as_ref() {
            out.push(host_persisted_route(*ip, maybe_gw.clone(), dev.clone()));
        }
        if let Some((ip, maybe_gw, dev)) = self.local_dns_bypass_route.as_ref() {
            out.push(host_persisted_route(*ip, maybe_gw.clone(), dev.clone()));
        }
        for (prefix, maybe_gw, dev) in &self.extra_bypass_v4 {
            out.push(PersistedRoute {
                family: 4,
                prefix: prefix.clone(),
                gateway: maybe_gw.clone(),
                dev: dev.clone(),
            });
        }
        for (prefix, maybe_gw, dev) in &self.extra_bypass_v6 {
            out.push(PersistedRoute {
                family: 6,
                prefix: prefix.clone(),
                gateway: maybe_gw.clone(),
                dev: dev.clone(),
            });
        }
        out
    }

    fn persist_routes_state(&self) {
        let routes = self.collect_persisted_routes();
        write_routes_state_atomic(&self.routes_state_path, &routes);
    }
}

impl Drop for LinuxRouteGuard {
    fn drop(&mut self) {
        // When `AsyncLinuxTun` already closed the TUN fd before this guard
        // drops, the kernel atomically purges all routes bound to `self.ifname`.
        // Skip `dev <ifname>` deletions when the interface is gone so shutdown
        // emits zero spurious `Cannot find device` errors or extra forks.
        let iface_exists = Path::new("/sys/class/net").join(&self.ifname).exists();
        let deadline = Instant::now() + SHUTDOWN_IP_BUDGET;
        let mut complete = true;
        if iface_exists {
            if self.installed_v4_low
                && run_ip_with_deadline(
                    &["route", "del", "0.0.0.0/1", "dev", &self.ifname],
                    deadline,
                )
                .is_err()
            {
                complete = false;
            }
            if self.installed_v4_high
                && run_ip_with_deadline(
                    &["route", "del", "128.0.0.0/1", "dev", &self.ifname],
                    deadline,
                )
                .is_err()
            {
                complete = false;
            }
            if self.installed_v6_low
                && run_ip_with_deadline(
                    &["-6", "route", "del", "::/1", "dev", &self.ifname],
                    deadline,
                )
                .is_err()
            {
                complete = false;
            }
            if self.installed_v6_high
                && run_ip_with_deadline(
                    &["-6", "route", "del", "8000::/1", "dev", &self.ifname],
                    deadline,
                )
                .is_err()
            {
                complete = false;
            }
        }
        for (cidr_entry, maybe_gw, dev) in &self.extra_bypass_v4 {
            if remove_v4_bypass_with_deadline(cidr_entry, maybe_gw.as_deref(), dev, deadline)
                .is_err()
            {
                complete = false;
            }
        }
        for (cidr_entry, maybe_gw, dev) in &self.extra_bypass_v6 {
            if remove_v6_bypass_with_deadline(cidr_entry, maybe_gw.as_deref(), dev, deadline)
                .is_err()
            {
                complete = false;
            }
        }
        if let Some((ip, maybe_gw, dev)) = self.local_dns_bypass_route.as_ref()
            && remove_host_bypass_with_deadline(*ip, maybe_gw.as_deref(), dev, deadline).is_err()
        {
            complete = false;
        }
        if let Some((ip, maybe_gw, dev)) = self.server_bypass_route.as_ref()
            && let Err(err) =
                remove_host_bypass_with_deadline(*ip, maybe_gw.as_deref(), dev, deadline)
        {
            warn!(%ip, error = %err, "failed to remove server bypass route on shutdown");
            complete = false;
        }
        if complete {
            let _ = std::fs::remove_file(&self.routes_state_path);
        } else {
            warn!(
                path = %self.routes_state_path.display(),
                "kept routes.state after incomplete shutdown cleanup; ExecStopPost will retry"
            );
        }
    }
}

fn host_persisted_route(ip: IpAddr, gateway: Option<String>, dev: String) -> PersistedRoute {
    match ip {
        IpAddr::V4(v4) => PersistedRoute {
            family: 4,
            prefix: format!("{v4}/32"),
            gateway,
            dev,
        },
        IpAddr::V6(v6) => PersistedRoute {
            family: 6,
            prefix: format!("{v6}/128"),
            gateway,
            dev,
        },
    }
}

/// Formats persisted bypass routes as tab-separated lines
/// (`<4|6>\t<prefix>\t<gw_or_dash>\t<dev>`).
pub fn format_routes_state(routes: &[PersistedRoute]) -> String {
    let mut out = String::new();
    for route in routes.iter().take(MAX_PERSISTED_ROUTES) {
        let gw = route.gateway.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            route.family, route.prefix, gw, route.dev
        ));
    }
    out
}

/// Parses and strictly validates persisted bypass routes from state file text.
/// Malformed lines are skipped; output is bounded to [`MAX_PERSISTED_ROUTES`].
pub fn parse_routes_state(text: &str) -> Vec<PersistedRoute> {
    let mut routes = Vec::new();
    for line in text.lines() {
        if routes.len() >= MAX_PERSISTED_ROUTES {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split('\t');
        let (Some(fam_str), Some(prefix), Some(gw_str), Some(dev), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        let family: u8 = match fam_str {
            "4" => 4,
            "6" => 6,
            _ => continue,
        };
        let Some(net) = IpNet::parse_cidr(prefix) else {
            continue;
        };
        let family_matches = matches!((family, net), (4, IpNet::V4 { .. }) | (6, IpNet::V6 { .. }));
        if !family_matches {
            continue;
        }
        let gateway = if gw_str == "-" {
            None
        } else {
            let Ok(ip) = gw_str.parse::<IpAddr>() else {
                continue;
            };
            let gw_matches = matches!((family, ip), (4, IpAddr::V4(_)) | (6, IpAddr::V6(_)));
            if !gw_matches {
                continue;
            }
            Some(gw_str.to_owned())
        };
        if dev.starts_with('-') || beam_sys::validate_ifname(dev).is_err() {
            continue;
        }
        routes.push(PersistedRoute {
            family,
            prefix: prefix.to_owned(),
            gateway,
            dev: dev.to_owned(),
        });
    }
    routes
}

/// Atomically writes `routes` to `path` when its parent directory exists.
pub fn write_routes_state_atomic(path: &Path, routes: &[PersistedRoute]) {
    let Some(parent) = path.parent() else {
        return;
    };
    if !parent.is_dir() {
        return;
    }
    let tmp = path.with_extension("state.tmp");
    let body = format_routes_state(routes);
    if let Ok(mut file) = std::fs::File::create(&tmp) {
        use std::io::Write as _;
        if file.write_all(body.as_bytes()).is_ok() && file.sync_all().is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

/// Reads `path` (if present), removes any persisted bypass routes best-effort,
/// and keeps a bounded state file for routes that still need removal. Used by
/// `beam-client --cleanup-routes` in `ExecStopPost` after a `SIGKILL`/OOM crash.
pub fn cleanup_persisted_routes(path: &Path) -> io::Result<usize> {
    let content = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    let routes = parse_routes_state(&content);
    let deadline = Instant::now() + SHUTDOWN_IP_BUDGET;
    let mut removed = 0usize;
    let mut remaining = Vec::new();
    for route in &routes {
        let res = if route.family == 4 {
            remove_v4_bypass_with_deadline(
                &route.prefix,
                route.gateway.as_deref(),
                &route.dev,
                deadline,
            )
        } else {
            remove_v6_bypass_with_deadline(
                &route.prefix,
                route.gateway.as_deref(),
                &route.dev,
                deadline,
            )
        };
        if res.is_ok() {
            removed += 1;
        } else {
            remaining.push(route.clone());
        }
    }
    if remaining.is_empty() {
        let _ = std::fs::remove_file(path);
    } else {
        warn!(
            remaining = remaining.len(),
            "kept unreached bypass routes in routes.state for retry"
        );
        write_routes_state_atomic(path, &remaining);
    }
    Ok(removed)
}

fn gateway_for_ip(gw: &PhysicalGateways, ip: IpAddr) -> Option<&(Option<String>, String)> {
    match ip {
        IpAddr::V4(_) => gw.v4.as_ref(),
        IpAddr::V6(_) => gw.v6.as_ref(),
    }
}

/// Canonicalizes a CIDR so it can be compared word-for-word with the kernel
/// routing table, which prints lowercase and compressed IPv6 prefixes.
fn canonical_cidr(cidr: &str) -> Option<String> {
    Some(match IpNet::parse_cidr(cidr)? {
        IpNet::V4 { net, mask } => format!("{}/{}", Ipv4Addr::from(net), mask.count_ones()),
        IpNet::V6 { net, mask } => format!("{}/{}", Ipv6Addr::from(net), mask.count_ones()),
    })
}

fn is_ipv4_cidr(cidr: &str) -> bool {
    cidr.split_once('/')
        .is_some_and(|(ip, _)| ip.parse::<Ipv4Addr>().is_ok())
}

fn is_ipv6_cidr(cidr: &str) -> bool {
    cidr.split_once('/')
        .is_some_and(|(ip, _)| ip.parse::<Ipv6Addr>().is_ok())
}

fn install_host_bypass(ip: IpAddr, gw: Option<&str>, dev: &str) -> io::Result<()> {
    match ip {
        IpAddr::V4(v4) => install_v4_bypass(&format!("{v4}/32"), gw, dev),
        IpAddr::V6(v6) => install_v6_bypass(&format!("{v6}/128"), gw, dev),
    }
}

fn remove_host_bypass(ip: IpAddr, gw: Option<&str>, dev: &str) -> io::Result<()> {
    remove_host_bypass_with_deadline(ip, gw, dev, Instant::now() + IP_CHILD_DEADLINE)
}

fn remove_host_bypass_with_deadline(
    ip: IpAddr,
    gw: Option<&str>,
    dev: &str,
    deadline: Instant,
) -> io::Result<()> {
    match ip {
        IpAddr::V4(v4) => remove_v4_bypass_with_deadline(&format!("{v4}/32"), gw, dev, deadline),
        IpAddr::V6(v6) => remove_v6_bypass_with_deadline(&format!("{v6}/128"), gw, dev, deadline),
    }
}

fn install_v4_bypass(prefix: &str, gw: Option<&str>, dev: &str) -> io::Result<()> {
    if let Some(gw) = gw {
        run_ip(&["-4", "route", "replace", prefix, "via", gw, "dev", dev])
    } else {
        run_ip(&["-4", "route", "replace", prefix, "dev", dev])
    }
}

fn remove_v4_bypass(prefix: &str, gw: Option<&str>, dev: &str) -> io::Result<()> {
    remove_v4_bypass_with_deadline(prefix, gw, dev, Instant::now() + IP_CHILD_DEADLINE)
}

fn remove_v4_bypass_with_deadline(
    prefix: &str,
    gw: Option<&str>,
    dev: &str,
    deadline: Instant,
) -> io::Result<()> {
    if let Some(gw) = gw {
        run_ip_with_deadline(
            &["-4", "route", "del", prefix, "via", gw, "dev", dev],
            deadline,
        )
    } else {
        run_ip_with_deadline(&["-4", "route", "del", prefix, "dev", dev], deadline)
    }
}

fn install_v6_bypass(prefix: &str, gw: Option<&str>, dev: &str) -> io::Result<()> {
    if let Some(gw) = gw {
        run_ip(&["-6", "route", "replace", prefix, "via", gw, "dev", dev])
    } else {
        run_ip(&["-6", "route", "replace", prefix, "dev", dev])
    }
}

fn remove_v6_bypass(prefix: &str, gw: Option<&str>, dev: &str) -> io::Result<()> {
    remove_v6_bypass_with_deadline(prefix, gw, dev, Instant::now() + IP_CHILD_DEADLINE)
}

fn remove_v6_bypass_with_deadline(
    prefix: &str,
    gw: Option<&str>,
    dev: &str,
    deadline: Instant,
) -> io::Result<()> {
    if let Some(gw) = gw {
        run_ip_with_deadline(
            &["-6", "route", "del", prefix, "via", gw, "dev", dev],
            deadline,
        )
    } else {
        run_ip_with_deadline(&["-6", "route", "del", prefix, "dev", dev], deadline)
    }
}

const IP_BINARY_CANDIDATES: [&str; 4] = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"];

/// Resolves `ip` (iproute2) from the fixed system paths.
///
/// Deliberately never falls back to a bare `"ip"` `PATH` lookup: a privileged
/// daemon must not run an operator-writable binary from `PATH`.
fn find_ip_binary(candidates: &[&'static str]) -> io::Result<&'static str> {
    for candidate in candidates {
        if Path::new(candidate).is_file() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "iproute2 `ip` not found in {}; install iproute2",
            candidates.join(", ")
        ),
    ))
}

fn ip_binary() -> io::Result<&'static str> {
    #[cfg(test)]
    if let Some(bin) = TEST_IP_BINARY.get() {
        return Ok(bin);
    }
    resolve_ip_binary(&IP_BINARY, &IP_BINARY_CANDIDATES)
}

/// Returns the cached `ip` path, resolving it once.
///
/// Only `Ok` results are cached: a missing `iproute2` install is retried on the
/// next call instead of being remembered forever.
fn resolve_ip_binary(
    cache: &OnceLock<&'static str>,
    candidates: &[&'static str],
) -> io::Result<&'static str> {
    if let Some(cached) = cache.get() {
        return Ok(cached);
    }
    let found = find_ip_binary(candidates)?;
    let _ = cache.set(found);
    Ok(found)
}

struct BoundedIpOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_bounded_ip_output<R: io::Read + Send + 'static>(
    reader: R,
) -> std::thread::JoinHandle<BoundedIpOutput> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = reader.take(MAX_IP_OUTPUT_BYTES + 1).read_to_end(&mut bytes);
        BoundedIpOutput {
            truncated: read.is_ok_and(|n| n as u64 > MAX_IP_OUTPUT_BYTES),
            bytes,
        }
    })
}

/// Spawns one `ip` child, polls it without spinning, and kills and reaps it
/// when `deadline` passes. Both pipes are drained by bounded reader threads.
fn spawn_ip_child(bin: &str, args: &[&str], deadline: Instant) -> io::Result<Output> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("`ip {}` deadline exhausted", args.join(" ")),
        ));
    }
    let mut busy = 0;
    let mut child = loop {
        match Command::new(bin)
            .args(args)
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => break child,
            // A concurrent write or upgrade can make the binary briefly busy.
            Err(err) if err.kind() == io::ErrorKind::ExecutableFileBusy && busy < 2 => {
                busy += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(err),
        }
    };
    let stdout = child.stdout.take().map(read_bounded_ip_output);
    let stderr = child.stderr.take().map(read_bounded_ip_output);

    let status = loop {
        let polled = match child.try_wait() {
            Ok(status) => status,
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(reader) = stdout {
                    let _ = reader.join();
                }
                if let Some(reader) = stderr {
                    let _ = reader.join();
                }
                return Err(err);
            }
        };
        match polled {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(reader) = stdout {
                    let _ = reader.join();
                }
                if let Some(reader) = stderr {
                    let _ = reader.join();
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("`ip {}` timed out", args.join(" ")),
                ));
            }
            None => std::thread::sleep(IP_CHILD_POLL_INTERVAL),
        }
    };
    let stdout = stdout.and_then(|reader| reader.join().ok());
    let stderr = stderr.and_then(|reader| reader.join().ok());
    if stdout.as_ref().is_some_and(|out| out.truncated)
        || stderr.as_ref().is_some_and(|out| out.truncated)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "`ip {}` output exceeded {MAX_IP_OUTPUT_BYTES} bytes",
                args.join(" ")
            ),
        ));
    }
    Ok(Output {
        status,
        stdout: stdout.map(|out| out.bytes).unwrap_or_default(),
        stderr: stderr.map(|out| out.bytes).unwrap_or_default(),
    })
}

fn run_ip(args: &[&str]) -> io::Result<()> {
    run_ip_with_deadline(args, Instant::now() + IP_CHILD_DEADLINE)
}

fn child_deadline(deadline: Instant) -> Instant {
    std::cmp::min(deadline, Instant::now() + IP_CHILD_DEADLINE)
}

fn ip_delete_already_removed(args: &[&str], stderr: &str) -> bool {
    if !args.contains(&"del") {
        return false;
    }
    let detail = stderr.to_ascii_lowercase();
    detail.contains("no such process")
        || detail.contains("esrch")
        || detail.contains("no such device")
        || detail.contains("enodev")
}

fn run_ip_with_deadline(args: &[&str], deadline: Instant) -> io::Result<()> {
    let deadline = child_deadline(deadline);
    let output = spawn_ip_child(ip_binary()?, args, deadline)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    // A route that is already gone is the desired end state during cleanup.
    if ip_delete_already_removed(args, detail) {
        debug!(command = %args.join(" "), detail, "route was already removed");
        return Ok(());
    }
    if detail.is_empty() {
        Err(io::Error::other(format!(
            "`ip {}` exited with {}",
            args.join(" "),
            output.status
        )))
    } else {
        Err(io::Error::other(format!(
            "`ip {}` exited with {}: {detail}",
            args.join(" "),
            output.status
        )))
    }
}

fn host_route_args(ip: IpAddr) -> (&'static str, String) {
    match ip {
        IpAddr::V4(v4) => ("-4", format!("{v4}/32")),
        IpAddr::V6(v6) => ("-6", format!("{v6}/128")),
    }
}

/// Distinguishes a known missing bypass route from an unresolved lookup, so a
/// transient `ip` failure cannot be mistaken for a real miss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BypassRouteState {
    Installed,
    Absent,
    Error,
}

impl BypassRouteState {
    fn is_installed(self) -> bool {
        matches!(self, Self::Installed)
    }

    /// An unresolved lookup wins over a known miss; otherwise a miss wins.
    fn merge(self, other: Self) -> Self {
        use BypassRouteState as State;
        match (self, other) {
            (State::Error, _) | (_, State::Error) => State::Error,
            (State::Absent, _) | (_, State::Absent) => State::Absent,
            (State::Installed, State::Installed) => State::Installed,
        }
    }
}

impl From<RouteCheck> for BypassRouteState {
    fn from(check: RouteCheck) -> Self {
        match check {
            RouteCheck::Present => Self::Installed,
            // A linkdown route belongs to the host: it must not be replaced,
            // and the monitor must keep retrying while it is unusable.
            RouteCheck::Unusable | RouteCheck::Error(_) => Self::Error,
            RouteCheck::Absent => Self::Absent,
        }
    }
}

/// One `ip route show` snapshot per family, used for all bypass checks in a
/// reconcile pass so the number of `ip` calls does not grow with table size.
enum RouteTable {
    Loaded(String),
    /// The table exceeded the bounded read; exact lookups still work.
    Truncated,
    Failed(String),
}

struct RouteSnapshot {
    v4: RouteTable,
    v6: RouteTable,
}

impl RouteSnapshot {
    fn load(gw: &PhysicalGateways) -> Self {
        Self {
            v4: if gw.v4.is_some() {
                Self::load_family("-4")
            } else {
                RouteTable::Loaded(String::new())
            },
            v6: if gw.v6.is_some() {
                Self::load_family("-6")
            } else {
                RouteTable::Loaded(String::new())
            },
        }
    }

    fn load_family(family_flag: &str) -> RouteTable {
        let bin = match ip_binary() {
            Ok(bin) => bin,
            Err(err) => return RouteTable::Failed(err.to_string()),
        };
        let output = match spawn_ip_child(
            bin,
            &[family_flag, "route", "show"],
            Instant::now() + IP_CHILD_DEADLINE,
        ) {
            Ok(output) => output,
            Err(err) if err.kind() == io::ErrorKind::InvalidData => return RouteTable::Truncated,
            Err(err) => return RouteTable::Failed(err.to_string()),
        };
        if output.status.success() {
            return RouteTable::Loaded(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        RouteTable::Failed(if detail.is_empty() {
            format!(
                "`ip {family_flag} route show` exited with {}",
                output.status
            )
        } else {
            format!(
                "`ip {family_flag} route show` exited with {}: {detail}",
                output.status
            )
        })
    }

    fn check(&self, family_flag: &str, prefix: &str) -> RouteCheck {
        let table = if family_flag == "-4" {
            &self.v4
        } else {
            &self.v6
        };
        match table {
            RouteTable::Loaded(output) => route_snapshot_check(output, prefix),
            RouteTable::Truncated => has_exact_route(family_flag, prefix),
            RouteTable::Failed(err) => route_check_error(prefix, io::Error::other(err.clone())),
        }
    }
}

fn parse_route_prefix(word: &str, family_flag: &str) -> Option<IpNet> {
    if word == "default" {
        return IpNet::parse_cidr(if family_flag == "-6" {
            "::/0"
        } else {
            "0.0.0.0/0"
        });
    }
    if word.contains('/') {
        return IpNet::parse_cidr(word);
    }
    match word.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => IpNet::parse_cidr(&format!("{word}/32")),
        Ok(IpAddr::V6(_)) => IpNet::parse_cidr(&format!("{word}/128")),
        Err(_) => None,
    }
}

fn route_snapshot_check(output: &str, prefix: &str) -> RouteCheck {
    let family_flag = if prefix.contains(':') { "-6" } else { "-4" };
    let Some(wanted) = parse_route_prefix(prefix, family_flag) else {
        return RouteCheck::Absent;
    };
    let mut saw_route = false;
    let mut any_usable = false;
    let mut matches_prefix = false;
    let mut route_usable = false;
    for line in output.lines() {
        // Indented `nexthop` lines inherit the preceding destination's prefix.
        if line.split_whitespace().next() == Some("nexthop") {
            if matches_prefix && route_line_has_linkdown(line) {
                route_usable = false;
            }
            continue;
        }
        if matches_prefix {
            saw_route = true;
            any_usable |= route_usable;
        }
        matches_prefix = false;
        route_usable = false;
        let Some(destination) = line.split_whitespace().next() else {
            continue;
        };
        if matches!(
            destination,
            "blackhole" | "unreachable" | "prohibit" | "throw" | "local" | "broadcast"
        ) {
            continue;
        }
        if parse_route_prefix(destination, family_flag).is_some_and(|net| net == wanted) {
            matches_prefix = true;
            route_usable = !route_line_has_linkdown(line);
        }
    }
    if matches_prefix {
        saw_route = true;
        any_usable |= route_usable;
    }
    if any_usable {
        RouteCheck::Present
    } else if saw_route {
        RouteCheck::Unusable
    } else {
        RouteCheck::Absent
    }
}

fn route_line_has_linkdown(line: &str) -> bool {
    line.split_whitespace().any(|word| word == "linkdown")
}

/// Result of an exact-route lookup, distinguishing a missing route from a
/// failed lookup instead of silently treating `ip` errors as absent routes.
#[derive(Debug)]
pub enum RouteCheck {
    /// The route exists in the main table.
    Present,
    /// The route exists but carries `linkdown`, so it cannot carry traffic.
    Unusable,
    /// The lookup succeeded and found no route.
    Absent,
    /// The lookup could not be completed (`ip` missing, exited non-zero, ...).
    Error(io::Error),
}

impl RouteCheck {
    /// Returns `true` only for [`RouteCheck::Present`].
    #[cfg(test)]
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present)
    }

    /// Returns `true` only for [`RouteCheck::Unusable`].
    #[cfg(test)]
    const fn is_unusable(&self) -> bool {
        matches!(self, Self::Unusable)
    }

    /// Returns the lookup error, if any.
    pub const fn error(&self) -> Option<&io::Error> {
        match self {
            Self::Error(err) => Some(err),
            _ => None,
        }
    }
}

/// Runs `ip -<family> route show exact <prefix>` and classifies the result.
fn has_exact_route(family_flag: &str, prefix: &str) -> RouteCheck {
    let ip = match ip_binary() {
        Ok(ip) => ip,
        Err(err) => return route_check_error(prefix, err),
    };
    let args = [family_flag, "route", "show", "exact", prefix];
    let output = match spawn_ip_child(ip, &args, Instant::now() + IP_CHILD_DEADLINE) {
        Ok(output) => output,
        Err(err) => return route_check_error(prefix, err),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    classify_exact_route_output(
        prefix,
        output.status.success(),
        &output.status.to_string(),
        &stdout,
    )
}

/// Classifies one completed `ip ... route show exact <prefix>` invocation.
fn classify_exact_route_output(
    prefix: &str,
    success: bool,
    status: &str,
    stdout: &str,
) -> RouteCheck {
    if !success {
        return route_check_error(
            prefix,
            io::Error::other(format!(
                "`ip route show exact {prefix}` exited with {status}"
            )),
        );
    }
    parse_exact_route_check(stdout)
}

/// Logs a failed route lookup at rate-limited `warn` level and returns it.
fn route_check_error(prefix: &str, err: io::Error) -> RouteCheck {
    debug!(prefix = %prefix, error = %err, kind = ?err.kind(), "exact route lookup failed");
    if let Some(suppressed) = ROUTE_CHECK_LOG.allow() {
        warn!(
            prefix = %prefix,
            error = %err,
            kind = ?err.kind(),
            suppressed,
            "exact route lookup failed; route state is unknown"
        );
    }
    RouteCheck::Error(err)
}

/// Classifies `ip route show exact <prefix>` output as present, unusable, or
/// absent.
fn parse_exact_route_check(stdout: &str) -> RouteCheck {
    let mut present = false;
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        present = true;
        if route_line_has_linkdown(line) {
            return RouteCheck::Unusable;
        }
    }
    if present {
        RouteCheck::Present
    } else {
        RouteCheck::Absent
    }
}

fn configure_resolved_link_dns(ifname: &str, peer_ip: Ipv4Addr) {
    let bin = if Path::new("/usr/bin/resolvectl").is_file() {
        "/usr/bin/resolvectl"
    } else if Path::new("/bin/resolvectl").is_file() {
        "/bin/resolvectl"
    } else {
        return;
    };
    let ip_str = peer_ip.to_string();
    let dns_ok = Command::new(bin)
        .args(["dns", ifname, &ip_str])
        .status()
        .is_ok_and(|s| s.success());
    let dom_ok = Command::new(bin)
        .args(["domain", ifname, "~."])
        .status()
        .is_ok_and(|s| s.success());
    if dns_ok && dom_ok {
        info!(dev = %ifname, dns = %peer_ip, "configured systemd-resolved per-link DNS on TUN");
    } else {
        debug!(dev = %ifname, "systemd-resolved per-link DNS configuration skipped or unavailable");
    }
}

/// Detects the current physical default IPv4 and IPv6 gateways, skipping
/// `exclude_ifname` and any route carrying the `linkdown` flag.
pub fn detect_physical_gateways_excluding(exclude_ifname: &str) -> PhysicalGateways {
    PhysicalGateways {
        v4: detect_default_gateway("-4", exclude_ifname),
        v6: detect_default_gateway("-6", exclude_ifname),
    }
}

fn detect_default_gateway(
    family_flag: &str,
    exclude_ifname: &str,
) -> Option<(Option<String>, String)> {
    let args = [family_flag, "route", "show", "default"];
    let output =
        spawn_ip_child(ip_binary().ok()?, &args, Instant::now() + IP_CHILD_DEADLINE).ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    parse_default_route_output(&text, exclude_ifname)
}

fn parse_default_route_output(
    text: &str,
    exclude_ifname: &str,
) -> Option<(Option<String>, String)> {
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.contains(&"linkdown") {
            continue;
        }
        let mut gw = None;
        let mut dev = None;
        let mut i = 0;
        while i < words.len() {
            match words[i] {
                "via" if i + 1 < words.len() => {
                    gw = Some(words[i + 1].to_owned());
                    i += 2;
                }
                "dev" if i + 1 < words.len() => {
                    dev = Some(words[i + 1].to_owned());
                    i += 2;
                }
                _ => i += 1,
            }
        }
        if let Some(dev_name) = dev
            && dev_name != exclude_ifname
        {
            return Some((gw, dev_name));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);
    // Fake `ip` tests fork children; running them in parallel under load can
    // make the spawn fail transiently, so serialize them.
    static FAKE_IP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct FakeIp {
        dir: PathBuf,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "beam-fake-ip-{}-{}-{}",
            std::process::id(),
            name,
            TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    impl FakeIp {
        fn new_in(dir: PathBuf, script: &str) -> Self {
            let guard = FAKE_IP_LOCK.lock().unwrap_or_else(|err| err.into_inner());
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("fake ip dir");
            let path = dir.join("ip");
            let tmp = dir.join("ip.tmp");
            std::fs::write(&tmp, script).expect("write fake ip");
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))
                .expect("make fake ip executable");
            // Publish atomically so a concurrent exec never sees a writable file.
            std::fs::rename(&tmp, &path).expect("publish fake ip");
            let leaked = Box::leak(path.to_string_lossy().into_owned().into_boxed_str());
            TEST_IP_BINARY.set(Some(leaked));
            Self { dir, _lock: guard }
        }

        fn log_path(&self) -> PathBuf {
            self.dir.join("ip.log")
        }
    }

    impl Drop for FakeIp {
        fn drop(&mut self) {
            TEST_IP_BINARY.set(None);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn read_fake_ip_log(path: &Path) -> String {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Ok(text) = std::fs::read_to_string(path) {
                return text;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::read_to_string(path).expect("read fake ip log")
    }

    fn route_guard_for_tests() -> LinuxRouteGuard {
        LinuxRouteGuard {
            ifname: "beamtun0".to_owned(),
            auto_route: true,
            routes_state_path: PathBuf::from("/nonexistent/routes.state"),
            tun_v4_net: IpNet::parse_cidr("172.19.0.1/30"),
            server_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_dns_ip: None,
            configured_bypass_v4: Vec::new(),
            configured_bypass_v6: Vec::new(),
            dynamic_bypass_v4: VecDeque::new(),
            dynamic_bypass_v6: VecDeque::new(),
            current_gw: PhysicalGateways {
                v4: Some((Some("192.168.1.1".to_owned()), "eth0".to_owned())),
                v6: None,
            },
            installed_v4_low: false,
            installed_v4_high: false,
            installed_v6_low: false,
            installed_v6_high: false,
            server_bypass_route: None,
            server_bypass_preexisting: false,
            local_dns_bypass_route: None,
            local_dns_bypass_preexisting: false,
            extra_bypass_v4: Vec::new(),
            extra_bypass_v6: Vec::new(),
        }
    }

    #[test]
    fn skips_linkdown_and_tun_default_routes() {
        let output = "\
default via 192.168.1.1 dev eth0 proto dhcp metric 100 linkdown
default via 172.19.0.2 dev beamtun0 metric 150
default via 192.168.88.1 dev wlan0 proto dhcp metric 600
";
        assert_eq!(
            parse_default_route_output(output, "beamtun0"),
            Some((Some("192.168.88.1".to_owned()), "wlan0".to_owned()))
        );
    }

    #[test]
    fn exact_route_output_detection() {
        assert!(!parse_exact_route_check("").is_present());
        assert!(!parse_exact_route_check("   \n\t\n").is_present());
        assert!(
            parse_exact_route_check(
                "172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown\n"
            )
            .is_unusable()
        );
        assert!(parse_exact_route_check("203.0.113.10 via 192.168.1.1 dev wlan0\n").is_present());
    }

    #[test]
    fn linkdown_route_is_not_overwritten_or_deleted() {
        let dir = test_dir("linkdown-route");
        let log = dir.join("ip.log");
        let _fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{}\"\n\
                 case \"$*\" in\n\
                   *\"route show\"*) printf '%s\\n' '172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown' ;;\n\
                 esac\n\
                 exit 0\n",
                log.display(),
            ),
        );
        let cidr = "172.17.0.0/16";
        let mut guard = route_guard_for_tests();
        guard.configured_bypass_v4.push(cidr.to_owned());
        guard.extra_bypass_v4.push((
            cidr.to_owned(),
            Some("192.168.1.1".to_owned()),
            "eth0".to_owned(),
        ));
        let gw = guard.current_gw.clone();

        assert!(
            !guard.bypass_routes_installed(),
            "a linkdown route is not a usable bypass route"
        );
        assert!(
            !guard.update_bypass_gateway(&gw, None),
            "a host-owned linkdown route must stop the reconcile"
        );
        let log = read_fake_ip_log(&_fake.log_path());
        assert!(!log.contains("route del"), "linkdown route deleted: {log}");
        assert!(
            !log.contains("route replace"),
            "linkdown route overwritten: {log}"
        );
        assert_eq!(guard.extra_bypass_v4.len(), 1);
    }

    #[test]
    fn routes_state_roundtrip_and_rejects_malformed_lines() {
        let routes = vec![
            PersistedRoute {
                family: 4,
                prefix: "203.0.113.10/32".to_owned(),
                gateway: Some("192.168.1.1".to_owned()),
                dev: "wlan0".to_owned(),
            },
            PersistedRoute {
                family: 4,
                prefix: "198.51.100.0/24".to_owned(),
                gateway: None,
                dev: "eth0".to_owned(),
            },
            PersistedRoute {
                family: 6,
                prefix: "2001:db8::1/128".to_owned(),
                gateway: Some("fe80::1".to_owned()),
                dev: "wlan0".to_owned(),
            },
        ];
        let encoded = format_routes_state(&routes);
        let with_noise = format!(
            "{encoded}\n\
             bad line\n\
             5\t1.2.3.4/32\t-\teth0\n\
             4\t2001:db8::/32\t-\teth0\n\
             4\t1.2.3.4/32\tfe80::1\teth0\n\
             4\t1.2.3.4/32\t-\t--bad-ifname\n"
        );
        let parsed = parse_routes_state(&with_noise);
        assert_eq!(parsed, routes);

        let dir =
            std::env::temp_dir().join(format!("beam-routes-state-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("routes.state");
        write_routes_state_atomic(&path, &routes);
        let on_disk = std::fs::read_to_string(&path).expect("read routes.state");
        assert_eq!(parse_routes_state(&on_disk), routes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bypass_routes_installed_ignores_missing_gateway_family() {
        let guard = LinuxRouteGuard {
            ifname: "beamtun0".to_owned(),
            auto_route: true,
            routes_state_path: PathBuf::from("/nonexistent/routes.state"),
            tun_v4_net: IpNet::parse_cidr("172.19.0.1/30"),
            server_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            local_dns_ip: None,
            configured_bypass_v4: Vec::new(),
            configured_bypass_v6: Vec::new(),
            dynamic_bypass_v4: VecDeque::new(),
            dynamic_bypass_v6: VecDeque::new(),
            // IPv6-only host with an IPv4 server: no matching v4 gateway exists.
            current_gw: PhysicalGateways {
                v4: None,
                v6: Some((Some("fe80::1".to_owned()), "wlan0".to_owned())),
            },
            installed_v4_low: false,
            installed_v4_high: false,
            installed_v6_low: false,
            installed_v6_high: false,
            server_bypass_route: None,
            server_bypass_preexisting: false,
            local_dns_bypass_route: None,
            local_dns_bypass_preexisting: false,
            extra_bypass_v4: Vec::new(),
            extra_bypass_v6: Vec::new(),
        };
        assert!(guard.bypass_routes_installed());
    }

    #[test]
    fn dynamic_bypass_refresh_preserves_lru_order_and_static_cidrs() {
        let mut guard = LinuxRouteGuard {
            ifname: "beamtun0".to_owned(),
            auto_route: true,
            routes_state_path: PathBuf::from("/nonexistent/routes.state"),
            tun_v4_net: IpNet::parse_cidr("172.19.0.1/30"),
            server_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            local_dns_ip: None,
            configured_bypass_v4: vec!["198.51.100.1/32".to_owned()],
            configured_bypass_v6: Vec::new(),
            dynamic_bypass_v4: VecDeque::new(),
            dynamic_bypass_v6: VecDeque::new(),
            current_gw: PhysicalGateways::default(),
            installed_v4_low: false,
            installed_v4_high: false,
            installed_v6_low: false,
            installed_v6_high: false,
            server_bypass_route: None,
            server_bypass_preexisting: false,
            local_dns_bypass_route: None,
            local_dns_bypass_preexisting: false,
            extra_bypass_v4: vec![(
                "198.51.100.1/32".to_owned(),
                Some("192.168.1.1".to_owned()),
                "eth0".to_owned(),
            )],
            extra_bypass_v6: Vec::new(),
        };

        let a = Ipv4Addr::new(198, 51, 100, 1);
        let b = Ipv4Addr::new(198, 51, 100, 2);
        let now = Instant::now();
        let old = now
            .checked_sub(DYNAMIC_BYPASS_TTL + Duration::from_secs(10))
            .unwrap_or(now);

        // Insert `a` first, then `b`, then refresh `a` so `b` is now oldest.
        guard.dynamic_bypass_v4.push_back((a, old));
        guard.dynamic_bypass_v4.push_back((b, old));
        guard.install_dynamic_bypass_ip(IpAddr::V4(a));

        assert_eq!(guard.dynamic_bypass_v4.front().map(|(ip, _)| *ip), Some(b));
        assert_eq!(guard.dynamic_bypass_v4.back().map(|(ip, _)| *ip), Some(a));

        // Evicting at `now` removes expired `b`, keeps fresh `a`.
        guard.evict_v4(now, true);
        assert_eq!(guard.dynamic_bypass_v4.len(), 1);
        assert_eq!(guard.dynamic_bypass_v4.front().map(|(ip, _)| *ip), Some(a));

        // Even when `a` expires later, static `configured_bypass_v4` entry in
        // `extra_bypass_v4` is NOT removed by dynamic eviction.
        guard.dynamic_bypass_v4[0].1 = old;
        guard.evict_v4(now, true);
        assert!(guard.dynamic_bypass_v4.is_empty());
        assert_eq!(guard.extra_bypass_v4.len(), 1);
        assert_eq!(guard.extra_bypass_v4[0].0, "198.51.100.1/32");
    }

    #[test]
    fn dynamic_bypass_lookup_error_defers_install() {
        let dir = test_dir("dynamic-lookup-error");
        let log = dir.join("ip.log");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{}\"\n\
                 case \"$*\" in\n\
                   *\"route show exact\"*) echo transient >&2; exit 2 ;;\n\
                 esac\n\
                 exit 0\n",
                log.display(),
            ),
        );
        let mut guard = route_guard_for_tests();
        let ip = Ipv4Addr::new(203, 0, 113, 77);

        guard.install_dynamic_bypass_ip(IpAddr::V4(ip));

        let log = read_fake_ip_log(&fake.log_path());
        assert!(
            !log.contains("route replace"),
            "an unknown route state must not be overwritten: {log}"
        );
        assert!(
            guard.dynamic_bypass_v4.iter().any(|(a, _)| *a == ip),
            "the unresolved IP must stay tracked for the retry path"
        );
        assert!(guard.extra_bypass_v4.is_empty());
    }

    #[test]
    fn dynamic_bypass_refresh_retries_deferred_install() {
        let dir = test_dir("dynamic-lookup-retry");
        let log = dir.join("ip.log");
        let error = dir.join("error");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{}\"\n\
                 case \"$*\" in\n\
                   *\"route show exact\"*) [ -f \"{}\" ] && {{ echo transient >&2; exit 2; }}; exit 0 ;;\n\
                 esac\n\
                 exit 0\n",
                log.display(),
                error.display(),
            ),
        );
        std::fs::write(&error, b"1").expect("mark lookup errors");
        let mut guard = route_guard_for_tests();
        let ip = Ipv4Addr::new(203, 0, 113, 77);

        guard.install_dynamic_bypass_ip(IpAddr::V4(ip));
        assert_eq!(
            guard
                .dynamic_bypass_v4
                .iter()
                .filter(|(a, _)| *a == ip)
                .count(),
            1,
            "the unresolved IP must stay tracked once"
        );

        std::fs::remove_file(&error).expect("clear lookup error");
        guard.install_dynamic_bypass_ip(IpAddr::V4(ip));

        let log = read_fake_ip_log(&fake.log_path());
        assert!(
            log.contains("route replace 203.0.113.77/32"),
            "a DNS refresh must retry the deferred install: {log}"
        );
        assert_eq!(
            guard
                .dynamic_bypass_v4
                .iter()
                .filter(|(a, _)| *a == ip)
                .count(),
            1,
            "the retry must not duplicate the tracked IP"
        );
        assert_eq!(guard.dynamic_bypass_v4.len(), 1);
    }

    #[test]
    fn all_error_tick_skips_drain_and_a_real_miss_reinstalls() {
        let dir = test_dir("route-snapshot");
        let log = dir.join("ip.log");
        let error = dir.join("error");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{}\"\n\
                 case \"$*\" in\n\
                   *\"route show\"*) [ -f \"{}\" ] && exit 2 ;;\n\
                 esac\n\
                 exit 0\n",
                log.display(),
                error.display(),
            ),
        );
        std::fs::write(&error, b"1").expect("mark lookup errors");

        let cidr = "198.51.100.0/24";
        let mut guard = route_guard_for_tests();
        guard.configured_bypass_v4.push(cidr.to_owned());
        guard.extra_bypass_v4.push((
            cidr.to_owned(),
            Some("192.168.1.1".to_owned()),
            "eth0".to_owned(),
        ));
        guard.server_bypass_route = Some((
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some("192.168.1.1".to_owned()),
            "eth0".to_owned(),
        ));
        let gw = guard.current_gw.clone();

        assert!(!guard.bypass_routes_installed(), "error is not a real miss");
        assert!(
            !guard.update_bypass_gateway(&gw, None),
            "an all-error tick must leave the retry pending"
        );
        let first = read_fake_ip_log(&fake.log_path());
        assert!(
            !first.contains("route del"),
            "all-error tick drained: {first}"
        );
        assert!(
            !first.contains("route replace 198.51.100.0/24"),
            "all-error tick reinstalled: {first}"
        );
        assert_eq!(guard.extra_bypass_v4.len(), 1);
        assert!(guard.server_bypass_route.is_some());

        std::fs::remove_file(&error).expect("clear lookup error");
        assert!(
            !guard.bypass_routes_installed(),
            "an empty snapshot is a real miss"
        );
        assert!(guard.update_bypass_gateway(&gw, None));
        let all = read_fake_ip_log(&fake.log_path());
        let reinstall = &all[first.len().min(all.len())..];
        assert!(
            reinstall.contains("route del 198.51.100.0/24"),
            "a real miss must drain the tracked route: {reinstall}"
        );
        assert!(
            reinstall.contains("route replace 198.51.100.0/24"),
            "a real miss must reinstall: {reinstall}"
        );
        assert!(
            guard
                .extra_bypass_v4
                .iter()
                .any(|(prefix, _, _)| prefix == cidr)
        );
    }

    #[test]
    fn route_snapshot_matches_canonical_prefixes() {
        assert_eq!(
            canonical_cidr("2001:0DB8:0001::/64").as_deref(),
            Some("2001:db8:1::/64")
        );
        assert_eq!(
            canonical_cidr("10.20.0.0/16").as_deref(),
            Some("10.20.0.0/16")
        );
        let table = "2001:db8:1::/64 dev eth0 proto static metric 100\n\
                     198.18.0.0/24 via 10.0.0.1 dev eth0";
        assert!(route_snapshot_check(table, "2001:db8:1::/64").is_present());
        assert!(route_snapshot_check(table, "198.18.0.0/24").is_present());
        assert!(!route_snapshot_check(table, "2001:db8:2::/64").is_present());
    }

    #[test]
    fn route_snapshot_bounds_ip_calls_for_large_tables() {
        let dir = test_dir("snapshot-bound");
        let log = dir.join("ip.log");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nexit 0\n",
                log.display()
            ),
        );
        let mut guard = route_guard_for_tests();
        guard.current_gw.v6 = Some((Some("fe80::1".to_owned()), "eth0".to_owned()));
        for i in 0..256 {
            guard.configured_bypass_v4.push(format!("198.18.{i}.0/24"));
            guard
                .configured_bypass_v6
                .push(format!("2001:db8:{i:x}::/64"));
        }

        assert!(!guard.bypass_routes_installed());
        let log = read_fake_ip_log(&fake.log_path());
        let shows = log
            .lines()
            .filter(|line| line.contains("route show"))
            .count();
        assert_eq!(shows, 2, "one snapshot per family, not per CIDR: {log}");
    }

    #[test]
    fn route_snapshot_matches_host_routes_and_ignores_non_unicast() {
        let table = "\
default via 192.168.1.1 dev eth0 proto dhcp metric 100\n\
153.56.184.142 via 10.61.135.13 dev enp0s20f0u5\n\
2001:db8:abcd::1 via fe80::1 dev eth0 proto static metric 100 src 2001:db8:abcd::2\n\
198.51.100.0/24 via 10.0.0.1 dev eth0 proto static metric 100\n\
    nexthop via 10.0.0.2 dev eth1 weight 1\n\
    nexthop via 10.0.0.3 dev eth2 weight 1\n\
blackhole 203.0.113.9/32\n\
unreachable 203.0.113.8/32\n\
prohibit 203.0.113.7/32\n\
throw 203.0.113.6/32\n\
local 127.0.0.1/32 dev lo proto kernel scope host src 127.0.0.1\n\
broadcast 192.168.1.255/32 dev eth0 proto kernel scope link src 192.168.1.10\n\
198.51.100.1/32 dev eth0 proto static linkdown\n";
        assert!(route_snapshot_check(table, "153.56.184.142/32").is_present());
        assert!(route_snapshot_check(table, "2001:db8:abcd::1/128").is_present());
        assert!(route_snapshot_check(table, "2001:0DB8:ABCD::1/128").is_present());
        assert!(route_snapshot_check(table, "198.51.100.0/24").is_present());
        assert!(!route_snapshot_check(table, "203.0.113.9/32").is_present());
        assert!(!route_snapshot_check(table, "203.0.113.8/32").is_present());
        assert!(!route_snapshot_check(table, "203.0.113.7/32").is_present());
        assert!(!route_snapshot_check(table, "203.0.113.6/32").is_present());
        assert!(!route_snapshot_check(table, "127.0.0.1/32").is_present());
        assert!(!route_snapshot_check(table, "192.168.1.255/32").is_present());
        assert!(route_snapshot_check(table, "198.51.100.1/32").is_unusable());
    }

    #[test]
    fn truncated_snapshot_is_lookup_error() {
        let dir = test_dir("truncated-snapshot");
        let fake = FakeIp::new_in(
            dir,
            "#!/bin/sh\n\
             case \"$*\" in\n\
               *\"route show\"*) yes x | head -c 70000; exit 0 ;;\n\
             esac\n\
             exit 0\n",
        );
        let snapshot = RouteSnapshot::load(&route_guard_for_tests().current_gw);
        assert!(
            matches!(
                snapshot.check("-4", "198.51.100.1/32"),
                RouteCheck::Error(_)
            ),
            "a cut table must not be read as an absent route"
        );
        drop(fake);
    }

    #[test]
    fn route_snapshot_matches_default_routes() {
        let v4 = "default via 192.168.1.1 dev eth0 proto static\n";
        let v6 = "default via fe80::1 dev eth0 proto static\n";
        assert!(route_snapshot_check(v4, "0.0.0.0/0").is_present());
        assert!(route_snapshot_check(v6, "::/0").is_present());
    }

    #[test]
    fn multipath_linkdown_nexthop_is_unusable() {
        let table = "\
198.51.100.0/24 proto static\n\
    nexthop via 10.0.0.2 dev eth1 weight 1\n\
    nexthop via 10.0.0.3 dev eth2 weight 1 linkdown\n";
        assert!(route_snapshot_check(table, "198.51.100.0/24").is_unusable());
    }

    #[test]
    fn one_up_route_makes_linkdown_sibling_prefix_present() {
        let table = "\
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown\n\
172.17.0.0/16 via 192.168.1.1 dev eth0 proto static metric 100\n";
        assert!(route_snapshot_check(table, "172.17.0.0/16").is_present());

        let all_down = "\
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown\n\
172.17.0.0/16 dev docker1 proto kernel scope link src 172.17.1.1 linkdown\n";
        assert!(route_snapshot_check(all_down, "172.17.0.0/16").is_unusable());
    }

    #[test]
    fn truncated_snapshot_falls_back_to_exact_lookup() {
        let dir = test_dir("truncated-fallback");
        let log = dir.join("ip.log");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{}\"\n\
                 case \"$*\" in\n\
                   *\"route show exact\"*) echo '198.51.100.7 via 192.168.1.1 dev eth0'; exit 0 ;;\n\
                   *\"route show\"*) yes x | head -c 70000; exit 0 ;;\n\
                 esac\n\
                 exit 0\n",
                log.display(),
            ),
        );
        let snapshot = RouteSnapshot::load(&route_guard_for_tests().current_gw);
        assert!(
            snapshot.check("-4", "198.51.100.7/32").is_present(),
            "a large table must use exact lookups instead of failing forever"
        );
        let log = read_fake_ip_log(&fake.log_path());
        assert!(log.contains("route show exact 198.51.100.7/32"), "{log}");
    }

    #[test]
    fn every_ip_child_uses_c_locale() {
        let dir = test_dir("c-locale");
        let log = dir.join("ip.log");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\nprintf 'LC_ALL=%s %s\\n' \"$LC_ALL\" \"$*\" >> \"{}\"\nexit 0\n",
                log.display(),
            ),
        );
        let gw = PhysicalGateways {
            v4: Some((Some("192.168.1.1".to_owned()), "eth0".to_owned())),
            v6: None,
        };
        let _ = RouteSnapshot::load(&gw);
        let _ = has_exact_route("-4", "203.0.113.1/32");
        let _ = run_ip(&["route", "del", "203.0.113.1/32", "dev", "eth0"]);

        let log = read_fake_ip_log(&fake.log_path());
        assert!(log.lines().count() >= 3, "unexpected ip calls: {log}");
        for line in log.lines() {
            assert!(
                line.starts_with("LC_ALL=C "),
                "no C locale on ip child: {line}"
            );
        }
    }

    #[test]
    fn enodev_delete_counts_as_removed() {
        let dir = test_dir("enodev-delete");
        let state = dir.join("routes.state");
        let fake = FakeIp::new_in(
            dir,
            "#!/bin/sh\n\
             case \"$*\" in\n\
               *\"route del\"*) echo 'RTNETLINK answers: No such device' >&2; exit 2 ;;\n\
             esac\n\
             exit 0\n",
        );
        write_routes_state_atomic(
            &state,
            &[PersistedRoute {
                family: 4,
                prefix: "203.0.113.5/32".to_owned(),
                gateway: None,
                dev: "eth0".to_owned(),
            }],
        );
        assert_eq!(cleanup_persisted_routes(&state).expect("cleanup"), 1);
        assert!(
            !state.exists(),
            "ENODEV is the desired end state, so routes.state must not be retained"
        );
        drop(fake);
    }

    #[test]
    fn snapshot_skips_family_without_gateway() {
        let dir = test_dir("snapshot-no-gw-family");
        let log = dir.join("ip.log");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nexit 0\n",
                log.display()
            ),
        );
        let gw = PhysicalGateways {
            v4: Some((Some("192.168.1.1".to_owned()), "eth0".to_owned())),
            v6: None,
        };
        let _ = RouteSnapshot::load(&gw);
        let log = read_fake_ip_log(&fake.log_path());
        assert_eq!(log.lines().count(), 1, "unexpected ip calls: {log}");
        assert!(log.contains("-4 route show"), "{log}");
        assert!(!log.contains("-6 route show"), "{log}");
        drop(fake);
    }

    #[test]
    fn error_state_blocks_reconcile_when_other_family_misses() {
        assert_eq!(
            BypassRouteState::Absent.merge(BypassRouteState::Error),
            BypassRouteState::Error
        );
        assert_eq!(
            BypassRouteState::Error.merge(BypassRouteState::Absent),
            BypassRouteState::Error
        );

        let dir = test_dir("mixed-family-error");
        let log = dir.join("ip.log");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{}\"\n\
                 case \"$*\" in\n\
                   *\"-6 route show\"*) echo transient >&2; exit 2 ;;\n\
                 esac\n\
                 exit 0\n",
                log.display()
            ),
        );
        let mut guard = route_guard_for_tests();
        let v6_cidr = "2001:db8:1::/64".to_owned();
        guard.current_gw.v6 = Some((Some("fe80::1".to_owned()), "eth0".to_owned()));
        guard.configured_bypass_v6.push(v6_cidr.clone());
        guard.extra_bypass_v4.push((
            "198.51.100.0/24".to_owned(),
            Some("192.168.1.1".to_owned()),
            "eth0".to_owned(),
        ));
        guard.extra_bypass_v6.push((
            v6_cidr.clone(),
            Some("fe80::1".to_owned()),
            "eth0".to_owned(),
        ));
        let gw = guard.current_gw.clone();

        assert!(
            !guard.update_bypass_gateway(&gw, None),
            "an IPv6 error must survive an IPv4 miss"
        );
        let log = read_fake_ip_log(&fake.log_path());
        assert!(!log.contains("route del"), "an error drained routes: {log}");
        assert_eq!(guard.extra_bypass_v4.len(), 1);
        assert_eq!(guard.extra_bypass_v6.len(), 1);
    }

    #[test]
    fn recheck_error_does_not_replace_existing_route() {
        let dir = test_dir("recheck-error");
        let log = dir.join("ip.log");
        let checked = dir.join("checked");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{}\"\n\
                 case \"$*\" in\n\
                   *\"-4 route show\"*) [ -f \"{}\" ] && {{ echo transient >&2; exit 2; }}; : > \"{}\"; exit 0 ;;\n\
                 esac\n\
                 exit 0\n",
                log.display(),
                checked.display(),
                checked.display(),
            ),
        );
        let mut guard = route_guard_for_tests();
        let cidr = "198.51.100.0/24".to_owned();
        guard.configured_bypass_v4.push(cidr.clone());
        guard.extra_bypass_v4.push((
            cidr.clone(),
            Some("192.168.1.1".to_owned()),
            "eth0".to_owned(),
        ));
        let gw = guard.current_gw.clone();

        assert!(
            !guard.update_bypass_gateway(&gw, None),
            "an unresolved recheck must keep the retry pending"
        );
        let log = read_fake_ip_log(&fake.log_path());
        assert!(
            !log.contains("route replace"),
            "an unresolved recheck must not overwrite a route: {log}"
        );
    }

    #[test]
    fn recheck_error_after_drain_returns_false() {
        let dir = test_dir("recheck-error-after-drain");
        let log = dir.join("ip.log");
        let checked = dir.join("checked");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"{}\"\n\
                 case \"$*\" in\n\
                   *\"-4 route show\"*) [ -f \"{}\" ] && {{ echo transient >&2; exit 2; }}; : > \"{}\"; exit 0 ;;\n\
                 esac\n\
                 exit 0\n",
                log.display(),
                checked.display(),
                checked.display(),
            ),
        );
        let mut guard = route_guard_for_tests();
        let cidr = "198.51.100.0/24".to_owned();
        guard.configured_bypass_v4.push(cidr.clone());
        guard.extra_bypass_v4.push((
            cidr.clone(),
            Some("192.168.1.1".to_owned()),
            "eth0".to_owned(),
        ));
        let gw = guard.current_gw.clone();

        assert!(
            !guard.update_bypass_gateway(&gw, None),
            "a failed recheck after drain must leave the retry pending"
        );
        let log = read_fake_ip_log(&fake.log_path());
        assert!(
            log.contains(&format!("route del {cidr}")),
            "the owned route should have been drained: {log}"
        );
        assert!(
            !log.contains(&format!("route replace {cidr}")),
            "an unresolved recheck must not reinstall: {log}"
        );
        assert!(guard.extra_bypass_v4.is_empty());
    }

    #[test]
    fn fresh_route_at_cap_survives_quiet_sweep() {
        let mut guard = route_guard_for_tests();
        for i in 0..MAX_DYNAMIC_BYPASS_IPS {
            guard
                .dynamic_bypass_v4
                .push_back((Ipv4Addr::new(198, 18, 0, i as u8), Instant::now()));
        }
        guard.sweep_expired_dynamic_bypass();
        assert_eq!(
            guard.dynamic_bypass_v4.len(),
            MAX_DYNAMIC_BYPASS_IPS,
            "a quiet sweep must not evict a fresh route just because the table is full"
        );
    }

    #[test]
    fn esrch_delete_counts_as_removed() {
        let dir = test_dir("esrch-delete");
        let state = dir.join("routes.state");
        let fake = FakeIp::new_in(
            dir,
            "#!/bin/sh\n\
             case \"$*\" in\n\
               *\"route del\"*) echo 'RTNETLINK answers: No such process' >&2; exit 2 ;;\n\
             esac\n\
             exit 0\n",
        );
        write_routes_state_atomic(
            &state,
            &[PersistedRoute {
                family: 4,
                prefix: "203.0.113.5/32".to_owned(),
                gateway: None,
                dev: "eth0".to_owned(),
            }],
        );
        assert_eq!(cleanup_persisted_routes(&state).expect("cleanup"), 1);
        assert!(
            !state.exists(),
            "ESRCH is the desired end state, so routes.state must not be retained"
        );
        drop(fake);
    }

    #[test]
    fn quiet_sweep_removes_only_expired_daemon_dynamic_routes() {
        let dir = test_dir("sweep");
        let log = dir.join("ip.log");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nexit 0\n",
                log.display()
            ),
        );
        let mut guard = route_guard_for_tests();
        let now = Instant::now();
        let old = now
            .checked_sub(DYNAMIC_BYPASS_TTL + Duration::from_secs(10))
            .unwrap_or(now);
        let expired = Ipv4Addr::new(198, 51, 100, 9);
        let fresh = Ipv4Addr::new(198, 51, 100, 10);
        let configured = "203.0.113.0/24".to_owned();
        guard.configured_bypass_v4.push(configured.clone());
        guard.dynamic_bypass_v4.push_back((expired, old));
        guard.dynamic_bypass_v4.push_back((fresh, now));
        guard.extra_bypass_v4 = vec![
            ("198.51.100.9/32".to_owned(), None, "eth0".to_owned()),
            (
                configured.clone(),
                Some("192.168.1.1".to_owned()),
                "eth0".to_owned(),
            ),
        ];
        guard.server_bypass_route = Some((
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            Some("192.168.1.1".to_owned()),
            "eth0".to_owned(),
        ));
        assert!(
            ip_binary().expect("fake ip").contains("beam-fake-ip"),
            "test must use the fake ip binary"
        );

        guard.sweep_expired_dynamic_bypass();

        assert_eq!(
            guard
                .dynamic_bypass_v4
                .iter()
                .map(|(ip, _)| *ip)
                .collect::<Vec<_>>(),
            vec![fresh]
        );
        assert_eq!(
            guard
                .extra_bypass_v4
                .iter()
                .map(|(prefix, _, _)| prefix.as_str())
                .collect::<Vec<_>>(),
            vec![configured.as_str()]
        );
        let log = read_fake_ip_log(&fake.log_path());
        assert!(log.contains("route del 198.51.100.9/32"), "{log}");
        assert!(!log.contains("route del 203.0.113.0/24"), "{log}");
        assert!(!log.contains("route del 198.51.100.10/32"), "{log}");
        assert!(!log.contains("route del 203.0.113.1/32"), "{log}");
    }

    #[test]
    fn hanging_ip_child_is_killed_and_reaped() {
        let dir = test_dir("deadline");
        let pid_path = dir.join("pid");
        let fake = FakeIp::new_in(
            dir,
            &format!(
                "#!/bin/sh\necho $$ > \"{}\"\nexec sleep 30\n",
                pid_path.display()
            ),
        );
        let start = Instant::now();
        let err = spawn_ip_child(
            ip_binary().expect("fake ip"),
            &["route", "show", "default"],
            Instant::now() + Duration::from_millis(200),
        )
        .expect_err("hanging ip child must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(150));
        assert!(start.elapsed() < Duration::from_secs(2));

        let pid = std::fs::read_to_string(&pid_path)
            .expect("child pid")
            .trim()
            .parse::<u32>()
            .expect("numeric pid");
        assert!(
            !Path::new("/proc").join(pid.to_string()).exists(),
            "timed-out child must be reaped"
        );
        drop(fake);
    }

    #[test]
    fn cleanup_persisted_routes_missing_file_is_noop() {
        let path = std::env::temp_dir().join(format!(
            "beam-nonexistent-routes-{}.state",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        assert_eq!(cleanup_persisted_routes(&path).expect("noop"), 0);
    }

    #[test]
    fn cleanup_child_is_capped_below_the_total_deadline() {
        let dir = test_dir("cleanup-child-cap");
        let fake = FakeIp::new_in(dir, "#!/bin/sh\nexec sleep 30\n");
        let start = Instant::now();
        let err = run_ip_with_deadline(
            &["route", "del", "198.51.100.1/32", "dev", "eth0"],
            Instant::now() + SHUTDOWN_IP_BUDGET,
        )
        .expect_err("a hung cleanup child must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "one child must not consume the whole shutdown budget: {:?}",
            start.elapsed()
        );
        drop(fake);
    }

    #[test]
    fn ip_lookup_never_falls_back_to_path() {
        let err = find_ip_binary(&["/nonexistent/beam/ip", "/nonexistent/beam/ip2"])
            .expect_err("missing candidates must fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("iproute2"), "{err}");

        // A present candidate is returned as-is, without a `PATH` search.
        let missing = find_ip_binary(&["/nonexistent/beam/ip"]).expect_err("missing");
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        assert_eq!(find_ip_binary(&["/bin/sh"]).expect("found"), "/bin/sh");
    }

    #[test]
    fn route_check_is_tri_state() {
        // Present: `ip` printed a route.
        let present = classify_exact_route_output(
            "198.51.100.1/32",
            true,
            "exit status: 0",
            "198.51.100.1 via 192.168.1.1 dev wlan0\n",
        );
        assert!(present.is_present());
        assert!(present.error().is_none());

        // Absent: `ip` succeeded but printed nothing.
        let absent = classify_exact_route_output("198.51.100.2/32", true, "exit status: 0", "\n");
        assert!(!absent.is_present());
        assert!(absent.error().is_none());

        // Error: a failing `ip` invocation is not silently treated as absent.
        let failed = classify_exact_route_output("198.51.100.3/32", false, "exit status: 2", "");
        assert!(!failed.is_present());
        let err = failed.error().expect("lookup error is reported");
        assert!(err.to_string().contains("198.51.100.3/32"), "{err}");
    }

    #[test]
    fn ip_binary_caches_only_successful_lookups() {
        let cache: OnceLock<&'static str> = OnceLock::new();
        assert!(resolve_ip_binary(&cache, &["/nonexistent/beam/ip"]).is_err());
        assert!(
            cache.get().is_none(),
            "a missing iproute2 install must not be cached, so a late install is picked up"
        );

        let found = resolve_ip_binary(&cache, &["/nonexistent/beam/ip", "/bin/sh"]).expect("found");
        assert_eq!(found, "/bin/sh");
        assert_eq!(cache.get().copied(), Some("/bin/sh"));
        // Cached: a later lookup ignores the candidate list.
        assert_eq!(
            resolve_ip_binary(&cache, &["/nonexistent/beam/other"]).expect("cached"),
            "/bin/sh"
        );
    }

    #[test]
    fn dynamic_bypass_cap_warning_is_rate_limited() {
        let now = Instant::now();
        assert!(cap_warn_due(None, now));
        assert!(!cap_warn_due(Some(now), now + Duration::from_secs(1)));
        assert!(cap_warn_due(
            Some(now),
            now + DYNAMIC_BYPASS_CAP_WARN_INTERVAL
        ));
    }
}
