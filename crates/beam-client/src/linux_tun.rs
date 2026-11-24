//! Async Linux `/dev/net/tun` adapter implementing `beam_tun::TunDevice`,
//! plus rollback-safe Linux IPv4/IPv6 route management (`LinuxRouteGuard`).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::Command;

use beam_sys::LinuxTun;
use beam_tun::TunDevice;
use tokio::io::unix::AsyncFd;
use tracing::{debug, info, warn};

const MAX_DYNAMIC_BYPASS_IPS: usize = 256;

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
                Ok(n) => return Ok(n),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err),
            }
        }
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read_packet(buf)) {
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
    server_ip: IpAddr,
    local_dns_ip: Option<IpAddr>,
    configured_bypass_v4: Vec<String>,
    configured_bypass_v6: Vec<String>,
    dynamic_bypass_v4: Vec<Ipv4Addr>,
    dynamic_bypass_v6: Vec<Ipv6Addr>,
    current_gw: PhysicalGateways,
    installed_v4_low: bool,
    installed_v4_high: bool,
    installed_v6_low: bool,
    installed_v6_high: bool,
    server_bypass_route: Option<(IpAddr, Option<String>, String)>,
    local_dns_bypass_route: Option<(IpAddr, Option<String>, String)>,
    extra_bypass_v4: Vec<(String, Option<String>, String)>,
    extra_bypass_v6: Vec<(String, Option<String>, String)>,
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
            server_ip,
            local_dns_ip,
            configured_bypass_v4,
            configured_bypass_v6,
            dynamic_bypass_v4: Vec::new(),
            dynamic_bypass_v6: Vec::new(),
            current_gw: PhysicalGateways::default(),
            installed_v4_low: false,
            installed_v4_high: false,
            installed_v6_low: false,
            installed_v6_high: false,
            server_bypass_route: None,
            local_dns_bypass_route: None,
            extra_bypass_v4: Vec::new(),
            extra_bypass_v6: Vec::new(),
        };

        if auto_route {
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
            if run_ip(&["-6", "addr", "replace", "fd00:be:a::1/126", "dev", ifname]).is_ok() {
                if run_ip(&["-6", "route", "replace", "::/1", "dev", ifname]).is_ok() {
                    guard.installed_v6_low = true;
                }
                if run_ip(&["-6", "route", "replace", "8000::/1", "dev", ifname]).is_ok() {
                    guard.installed_v6_high = true;
                }
                if guard.installed_v6_low && guard.installed_v6_high {
                    info!(dev = %ifname, "installed IPv6 TUN split routes (::/1, 8000::/1)");
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

    /// Returns `true` if the server bypass route is not needed (loopback) or is
    /// currently installed and present in the kernel routing table.
    pub fn server_bypass_installed(&self) -> bool {
        if !self.auto_route || self.server_ip.is_loopback() {
            return true;
        }
        if self.server_bypass_route.is_none() {
            return false;
        }
        has_host_route(self.server_ip)
    }

    /// Migrates server, local-DNS, and bypass CIDR/domain routes to `new_gw`
    /// while keeping TUN split routes active (fail-closed kill-switch).
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

        self.current_gw = new_gw.clone();
        self.local_dns_ip = new_local_dns;

        if !self.server_ip.is_loopback()
            && let Some((maybe_gw, dev)) = gateway_for_ip(new_gw, self.server_ip)
        {
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

        if let Some(dns_ip) = self.local_dns_ip
            && !dns_ip.is_loopback()
            && dns_ip != self.server_ip
            && let Some((maybe_gw, dev)) = gateway_for_ip(new_gw, dns_ip)
        {
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

        if let Some((maybe_gw, dev)) = new_gw.v4.as_ref() {
            for cidr_entry in &self.configured_bypass_v4 {
                if let Err(err) = install_v4_bypass(cidr_entry, maybe_gw.as_deref(), dev) {
                    warn!(cidr = %cidr_entry, error = %err, "failed to install IPv4 bypass CIDR route");
                } else {
                    self.extra_bypass_v4
                        .push((cidr_entry.clone(), maybe_gw.clone(), dev.clone()));
                }
            }
            for &ip in &self.dynamic_bypass_v4 {
                let host = format!("{ip}/32");
                if install_v4_bypass(&host, maybe_gw.as_deref(), dev).is_ok() {
                    self.extra_bypass_v4
                        .push((host, maybe_gw.clone(), dev.clone()));
                }
            }
        }

        if let Some((maybe_gw, dev)) = new_gw.v6.as_ref() {
            for cidr_entry in &self.configured_bypass_v6 {
                if let Err(err) = install_v6_bypass(cidr_entry, maybe_gw.as_deref(), dev) {
                    warn!(cidr = %cidr_entry, error = %err, "failed to install IPv6 bypass CIDR route");
                } else {
                    self.extra_bypass_v6
                        .push((cidr_entry.clone(), maybe_gw.clone(), dev.clone()));
                }
            }
            for &ip in &self.dynamic_bypass_v6 {
                let host = format!("{ip}/128");
                if install_v6_bypass(&host, maybe_gw.as_deref(), dev).is_ok() {
                    self.extra_bypass_v6
                        .push((host, maybe_gw.clone(), dev.clone()));
                }
            }
        }
    }

    /// Dynamically installs a `/32` or `/128` bypass route for an IP resolved
    /// from a configured `bypass.domains` entry (bounded to [`MAX_DYNAMIC_BYPASS_IPS`]).
    pub fn install_dynamic_bypass_ip(&mut self, ip: IpAddr) {
        if !self.auto_route || ip.is_loopback() {
            return;
        }
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_private()
                    || self.dynamic_bypass_v4.contains(&v4)
                    || self.dynamic_bypass_v4.len() >= MAX_DYNAMIC_BYPASS_IPS
                {
                    return;
                }
                self.dynamic_bypass_v4.push(v4);
                if let Some((maybe_gw, dev)) = self.current_gw.v4.as_ref() {
                    let host = format!("{v4}/32");
                    if install_v4_bypass(&host, maybe_gw.as_deref(), dev).is_ok() {
                        self.extra_bypass_v4
                            .push((host, maybe_gw.clone(), dev.clone()));
                    }
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    || self.dynamic_bypass_v6.contains(&v6)
                    || self.dynamic_bypass_v6.len() >= MAX_DYNAMIC_BYPASS_IPS
                {
                    return;
                }
                self.dynamic_bypass_v6.push(v6);
                if let Some((maybe_gw, dev)) = self.current_gw.v6.as_ref() {
                    let host = format!("{v6}/128");
                    if install_v6_bypass(&host, maybe_gw.as_deref(), dev).is_ok() {
                        self.extra_bypass_v6
                            .push((host, maybe_gw.clone(), dev.clone()));
                    }
                }
            }
        }
    }
}

impl Drop for LinuxRouteGuard {
    fn drop(&mut self) {
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
    }
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
    let status = Command::new(ip_binary()).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "`ip {}` exited with {status}",
            args.join(" ")
        )))
    }
}

fn has_host_route(ip: IpAddr) -> bool {
    let (flag, prefix) = match ip {
        IpAddr::V4(v4) => ("-4", format!("{v4}/32")),
        IpAddr::V6(v6) => ("-6", format!("{v6}/128")),
    };
    let Ok(output) = Command::new(ip_binary())
        .args([flag, "route", "show", "exact", &prefix])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().any(|line| !line.trim().is_empty())
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
}
