//! Async Linux `/dev/net/tun` adapter implementing `beam_tun::TunDevice`,
//! plus rollback-safe Linux IPv4/IPv6 route management (`LinuxRouteGuard`).

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use beam_sys::LinuxTun;
use beam_tun::{IpNet, TunDevice};
use tokio::io::unix::AsyncFd;
use tracing::{debug, info, warn};

/// Default runtime state file tracking bypass routes installed by this daemon
/// so `ExecStopPost=/usr/local/bin/beam-client --cleanup-routes` can remove
/// orphaned routes after a `SIGKILL`/OOM crash.
pub const DEFAULT_ROUTES_STATE_PATH: &str = "/run/beam-client/routes.state";

const MAX_DYNAMIC_BYPASS_IPS: usize = 256;
const DYNAMIC_BYPASS_TTL: Duration = Duration::from_secs(3600);
const MAX_PERSISTED_ROUTES: usize = 1024;

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
            .cloned()
            .collect();
        let configured_bypass_v6: Vec<String> = bypass_cidrs
            .iter()
            .filter(|c| is_ipv6_cidr(c))
            .cloned()
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
            guard.update_bypass_gateway(&detected_gw, local_dns_ip);

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
        self.tun_v4_net.is_some_and(|net| net.contains(ip))
            || IpNet::parse_cidr("fd00:be:a::/126").is_some_and(|net| net.contains(ip))
    }

    /// Returns `true` if all required bypass routes (server and active
    /// non-loopback local DNS when a matching gateway exists) are installed
    /// (or preserved as pre-existing host routes) and present in the kernel
    /// routing table.
    pub fn bypass_routes_installed(&self) -> bool {
        if !self.auto_route {
            return true;
        }
        if !self.server_ip.is_loopback()
            && gateway_for_ip(&self.current_gw, self.server_ip).is_some()
        {
            if self.server_bypass_route.is_none() && !self.server_bypass_preexisting {
                return false;
            }
            if !has_host_route(self.server_ip) {
                return false;
            }
        }
        if let Some(dns_ip) = self.local_dns_ip
            && !dns_ip.is_loopback()
            && dns_ip != self.server_ip
            && !self.is_in_tun_subnet(dns_ip)
            && gateway_for_ip(&self.current_gw, dns_ip).is_some()
        {
            if self.local_dns_bypass_route.is_none() && !self.local_dns_bypass_preexisting {
                return false;
            }
            if !has_host_route(dns_ip) {
                return false;
            }
        }
        true
    }

    /// Migrates server, local-DNS, and bypass CIDR/domain routes to `new_gw`
    /// while keeping TUN split routes active (fail-closed kill-switch) and
    /// preserving any pre-existing exact routes in the main table.
    pub fn update_bypass_gateway(
        &mut self,
        new_gw: &PhysicalGateways,
        new_local_dns: Option<IpAddr>,
    ) {
        if !self.auto_route {
            return;
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

        if !self.server_ip.is_loopback()
            && let Some((maybe_gw, dev)) = gateway_for_ip(new_gw, self.server_ip)
        {
            if has_host_route(self.server_ip) {
                info!(ip = %self.server_ip, "preserving pre-existing exact route for beam server");
                self.server_bypass_preexisting = true;
            } else {
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
        }

        if let Some(dns_ip) = self.local_dns_ip
            && !dns_ip.is_loopback()
            && dns_ip != self.server_ip
            && !self.is_in_tun_subnet(dns_ip)
            && let Some((maybe_gw, dev)) = gateway_for_ip(new_gw, dns_ip)
        {
            if has_host_route(dns_ip) {
                debug!(ip = %dns_ip, "preserving pre-existing exact route for local DNS");
                self.local_dns_bypass_preexisting = true;
            } else {
                match install_host_bypass(dns_ip, maybe_gw.as_deref(), dev) {
                    Ok(()) => {
                        debug!(ip = %dns_ip, via = ?maybe_gw, dev = %dev, "installed local DNS bypass route");
                        self.local_dns_bypass_route = Some((dns_ip, maybe_gw.clone(), dev.clone()));
                    }
                    Err(err) => {
                        warn!(ip = %dns_ip, dev = %dev, error = %err, "failed to install local DNS bypass route");
                    }
                }
            }
        }

        if let Some((maybe_gw, dev)) = new_gw.v4.as_ref() {
            for cidr_entry in &self.configured_bypass_v4 {
                if has_exact_route("-4", cidr_entry) {
                    debug!(cidr = %cidr_entry, "preserving pre-existing exact IPv4 route");
                    continue;
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
                if has_exact_route("-4", &host) {
                    debug!(prefix = %host, "preserving pre-existing exact IPv4 route");
                    continue;
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
                if has_exact_route("-6", cidr_entry) {
                    debug!(cidr = %cidr_entry, "preserving pre-existing exact IPv6 route");
                    continue;
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
                if has_exact_route("-6", &host) {
                    debug!(prefix = %host, "preserving pre-existing exact IPv6 route");
                    continue;
                }
                if install_v6_bypass(&host, maybe_gw.as_deref(), dev).is_ok() {
                    info!(prefix = %host, via = ?maybe_gw, dev = %dev, "installed dynamic bypass.domains route");
                    self.extra_bypass_v6
                        .push((host, maybe_gw.clone(), dev.clone()));
                }
            }
        }

        self.persist_routes_state();
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
                if let Some(pos) = self.dynamic_bypass_v4.iter().position(|(a, _)| *a == v4) {
                    self.dynamic_bypass_v4.remove(pos);
                    self.dynamic_bypass_v4.push_back((v4, now));
                    return;
                }
                // Private RFC1918 destinations are only dynamically bypassed
                // when an active physical IPv4 gateway exists (and pre-existing
                // exact routes are never overwritten).
                let Some((maybe_gw, dev)) = self.current_gw.v4.clone() else {
                    if v4.is_private() {
                        debug!(%v4, "skipping private dynamic bypass.domains IP without IPv4 gateway");
                        return;
                    }
                    self.evict_v4_if_needed(now);
                    self.dynamic_bypass_v4.push_back((v4, now));
                    return;
                };
                self.evict_v4_if_needed(now);
                let host = format!("{v4}/32");
                if has_exact_route("-4", &host) {
                    debug!(prefix = %host, "preserving pre-existing exact route for bypass.domains IP");
                    return;
                }
                match install_v4_bypass(&host, maybe_gw.as_deref(), &dev) {
                    Ok(()) => {
                        info!(prefix = %host, via = ?maybe_gw, dev = %dev, "installed dynamic bypass.domains route");
                        self.dynamic_bypass_v4.push_back((v4, now));
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
                if let Some(pos) = self.dynamic_bypass_v6.iter().position(|(a, _)| *a == v6) {
                    self.dynamic_bypass_v6.remove(pos);
                    self.dynamic_bypass_v6.push_back((v6, now));
                    return;
                }
                let Some((maybe_gw, dev)) = self.current_gw.v6.clone() else {
                    if v6.is_unique_local() {
                        debug!(%v6, "skipping ULA dynamic bypass.domains IP without IPv6 gateway");
                        return;
                    }
                    self.evict_v6_if_needed(now);
                    self.dynamic_bypass_v6.push_back((v6, now));
                    return;
                };
                self.evict_v6_if_needed(now);
                let host = format!("{v6}/128");
                if has_exact_route("-6", &host) {
                    debug!(prefix = %host, "preserving pre-existing exact route for bypass.domains IP");
                    return;
                }
                match install_v6_bypass(&host, maybe_gw.as_deref(), &dev) {
                    Ok(()) => {
                        info!(prefix = %host, via = ?maybe_gw, dev = %dev, "installed dynamic bypass.domains route");
                        self.dynamic_bypass_v6.push_back((v6, now));
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

    fn evict_v4_if_needed(&mut self, now: Instant) {
        let mut evicted_prefixes = Vec::new();
        while let Some(&(ip, ts)) = self.dynamic_bypass_v4.front() {
            if now.saturating_duration_since(ts) >= DYNAMIC_BYPASS_TTL
                || self.dynamic_bypass_v4.len() >= MAX_DYNAMIC_BYPASS_IPS
            {
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

    fn evict_v6_if_needed(&mut self, now: Instant) {
        let mut evicted_prefixes = Vec::new();
        while let Some(&(ip, ts)) = self.dynamic_bypass_v6.front() {
            if now.saturating_duration_since(ts) >= DYNAMIC_BYPASS_TTL
                || self.dynamic_bypass_v6.len() >= MAX_DYNAMIC_BYPASS_IPS
            {
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
        if iface_exists {
            if self.installed_v4_low {
                let _ = run_ip(&["route", "del", "0.0.0.0/1", "dev", &self.ifname]);
            }
            if self.installed_v4_high {
                let _ = run_ip(&["route", "del", "128.0.0.0/1", "dev", &self.ifname]);
            }
            if self.installed_v6_low {
                let _ = run_ip(&["-6", "route", "del", "::/1", "dev", &self.ifname]);
            }
            if self.installed_v6_high {
                let _ = run_ip(&["-6", "route", "del", "8000::/1", "dev", &self.ifname]);
            }
        }
        for (cidr_entry, maybe_gw, dev) in &self.extra_bypass_v4 {
            let _ = remove_v4_bypass(cidr_entry, maybe_gw.as_deref(), dev);
        }
        for (cidr_entry, maybe_gw, dev) in &self.extra_bypass_v6 {
            let _ = remove_v6_bypass(cidr_entry, maybe_gw.as_deref(), dev);
        }
        if let Some((ip, maybe_gw, dev)) = self.local_dns_bypass_route.as_ref() {
            let _ = remove_host_bypass(*ip, maybe_gw.as_deref(), dev);
        }
        if let Some((ip, maybe_gw, dev)) = self.server_bypass_route.as_ref()
            && let Err(err) = remove_host_bypass(*ip, maybe_gw.as_deref(), dev)
        {
            warn!(%ip, error = %err, "failed to remove server bypass route on shutdown");
        }
        let _ = std::fs::remove_file(&self.routes_state_path);
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
/// and deletes the state file. Used by `beam-client --cleanup-routes` in
/// `ExecStopPost` to recover from `SIGKILL`/OOM crashes.
pub fn cleanup_persisted_routes(path: &Path) -> io::Result<usize> {
    let content = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    let routes = parse_routes_state(&content);
    let mut removed = 0usize;
    for route in &routes {
        let res = if route.family == 4 {
            remove_v4_bypass(&route.prefix, route.gateway.as_deref(), &route.dev)
        } else {
            remove_v6_bypass(&route.prefix, route.gateway.as_deref(), &route.dev)
        };
        if res.is_ok() {
            removed += 1;
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(removed)
}

fn gateway_for_ip(gw: &PhysicalGateways, ip: IpAddr) -> Option<&(Option<String>, String)> {
    match ip {
        IpAddr::V4(_) => gw.v4.as_ref(),
        IpAddr::V6(_) => gw.v6.as_ref(),
    }
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
    match ip {
        IpAddr::V4(v4) => remove_v4_bypass(&format!("{v4}/32"), gw, dev),
        IpAddr::V6(v6) => remove_v6_bypass(&format!("{v6}/128"), gw, dev),
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
    if let Some(gw) = gw {
        run_ip(&["-4", "route", "del", prefix, "via", gw, "dev", dev])
    } else {
        run_ip(&["-4", "route", "del", prefix, "dev", dev])
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
    if let Some(gw) = gw {
        run_ip(&["-6", "route", "del", prefix, "via", gw, "dev", dev])
    } else {
        run_ip(&["-6", "route", "del", prefix, "dev", dev])
    }
}

fn ip_binary() -> &'static str {
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"] {
        if Path::new(candidate).is_file() {
            return candidate;
        }
    }
    "ip"
}

fn run_ip(args: &[&str]) -> io::Result<()> {
    let output = Command::new(ip_binary()).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
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
}

fn has_host_route(ip: IpAddr) -> bool {
    let (flag, prefix) = match ip {
        IpAddr::V4(v4) => ("-4", format!("{v4}/32")),
        IpAddr::V6(v6) => ("-6", format!("{v6}/128")),
    };
    has_exact_route(flag, &prefix)
}

fn has_exact_route(family_flag: &str, prefix: &str) -> bool {
    let Ok(output) = Command::new(ip_binary())
        .args([family_flag, "route", "show", "exact", prefix])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_exact_route_exists(&text)
}

/// Returns `true` if `ip route show exact <prefix>` output reports an existing
/// route in the main routing table.
fn parse_exact_route_exists(stdout: &str) -> bool {
    stdout.lines().any(|line| !line.trim().is_empty())
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
    let output = Command::new(ip_binary())
        .args([family_flag, "route", "show", "default"])
        .output()
        .ok()?;
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
        assert!(!parse_exact_route_exists(""));
        assert!(!parse_exact_route_exists("   \n\t\n"));
        assert!(parse_exact_route_exists(
            "172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown\n"
        ));
        assert!(parse_exact_route_exists(
            "203.0.113.10 via 192.168.1.1 dev wlan0\n"
        ));
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
        guard.evict_v4_if_needed(now);
        assert_eq!(guard.dynamic_bypass_v4.len(), 1);
        assert_eq!(guard.dynamic_bypass_v4.front().map(|(ip, _)| *ip), Some(a));

        // Even when `a` expires later, static `configured_bypass_v4` entry in
        // `extra_bypass_v4` is NOT removed by dynamic eviction.
        guard.dynamic_bypass_v4[0].1 = old;
        guard.evict_v4_if_needed(now);
        assert!(guard.dynamic_bypass_v4.is_empty());
        assert_eq!(guard.extra_bypass_v4.len(), 1);
        assert_eq!(guard.extra_bypass_v4[0].0, "198.51.100.1/32");
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
}
