//! Async Linux `/dev/net/tun` adapter implementing `beam_tun::TunDevice`,
//! plus rollback-safe Linux route management (`LinuxRouteGuard`).

use std::io;
use std::net::Ipv4Addr;
use std::process::Command;

use beam_sys::LinuxTun;
use beam_tun::TunDevice;
use tokio::io::unix::AsyncFd;
use tracing::{info, warn};

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

/// Detected physical IPv4 default gateway `(optional_gateway_ip, interface_name)`.
pub type GatewayState = Option<(Option<String>, String)>;

const MAX_DYNAMIC_BYPASS_IPS: usize = 256;

/// Configures IP address, MTU, link UP, and optional default split-routes
/// (`0.0.0.0/1`, `128.0.0.0/1`, IPv6 `::/1`, `8000::/1` + host bypass route
/// for the `beam` server) on Linux.
///
/// Tracks every route it installs so both partial `setup()` failures and clean
/// shutdowns roll back **only** the routes installed by this guard.
pub struct LinuxRouteGuard {
    ifname: String,
    auto_route: bool,
    server_ip: Option<Ipv4Addr>,
    configured_bypass_v4: Vec<String>,
    dynamic_bypass_v4: Vec<Ipv4Addr>,
    current_gw: GatewayState,
    installed_v4_low: bool,
    installed_v4_high: bool,
    installed_v6_low: bool,
    installed_v6_high: bool,
    bypass_route: Option<(Ipv4Addr, Option<String>, String)>,
    extra_bypass_v4: Vec<(String, Option<String>, String)>,
}

impl LinuxRouteGuard {
    /// Brings up `ifname` with `cidr` and `mtu`. When `auto_route` is `true`,
    /// installs a host bypass route for `server_ip` (and any user-configured
    /// IPv4 `bypass_cidrs`) first, then routes IPv4 (`0.0.0.0/1`,
    /// `128.0.0.0/1`) and IPv6 (`::/1`, `8000::/1`) through `ifname` so
    /// dual-stack hosts do not leak IPv6 traffic in the clear.
    ///
    /// Fail-closed: if no physical default gateway exists yet at startup, the
    /// TUN split routes are still installed so traffic never leaks in the clear,
    /// and bypass routes are installed automatically once a gateway appears.
    pub fn setup(
        ifname: &str,
        cidr: &str,
        mtu: usize,
        auto_route: bool,
        server_ip: Option<Ipv4Addr>,
        bypass_cidrs: &[String],
    ) -> io::Result<Self> {
        run_ip(&["addr", "replace", cidr, "dev", ifname])?;
        run_ip(&["link", "set", "dev", ifname, "mtu", &mtu.to_string(), "up"])?;

        let configured_bypass_v4: Vec<String> = bypass_cidrs
            .iter()
            .filter(|c| is_ipv4_cidr(c))
            .cloned()
            .collect();

        // Construct the guard before adding any routes so a failure mid-setup
        // automatically rolls back everything installed so far via `Drop`.
        let mut guard = Self {
            ifname: ifname.to_owned(),
            auto_route,
            server_ip,
            configured_bypass_v4,
            dynamic_bypass_v4: Vec::new(),
            current_gw: None,
            installed_v4_low: false,
            installed_v4_high: false,
            installed_v6_low: false,
            installed_v6_high: false,
            bypass_route: None,
            extra_bypass_v4: Vec::new(),
        };

        if auto_route {
            let detected_gw = detect_default_ipv4_gateway_excluding(ifname);
            if detected_gw.is_none() {
                warn!(
                    "no physical default IPv4 gateway detected at startup; running fail-closed until network comes up"
                );
            }
            guard.update_bypass_gateway(&detected_gw);

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
        }

        Ok(guard)
    }

    /// Migrates server & bypass CIDR routes to `new_gw` on network transitions
    /// (Wi-Fi <-> Ethernet, hotspot switch, or recovery after outage) while
    /// keeping TUN split routes active (fail-closed kill-switch).
    pub fn update_bypass_gateway(&mut self, new_gw: &GatewayState) {
        if !self.auto_route {
            return;
        }
        // Best-effort removal of previous bypass routes (old interface may already be down).
        for (prefix, maybe_gw, dev) in self.extra_bypass_v4.drain(..) {
            let _ = remove_v4_bypass(&prefix, maybe_gw.as_deref(), &dev);
        }
        if let Some((ip, maybe_gw, dev)) = self.bypass_route.take() {
            let host = format!("{ip}/32");
            let _ = remove_v4_bypass(&host, maybe_gw.as_deref(), &dev);
        }

        self.current_gw = new_gw.clone();
        let Some((maybe_gw, dev)) = new_gw.as_ref() else {
            return;
        };

        if let Some(ip) = self.server_ip
            && !ip.is_loopback()
        {
            let host = format!("{ip}/32");
            match install_v4_bypass(&host, maybe_gw.as_deref(), dev) {
                Ok(()) => {
                    info!(%ip, via = ?maybe_gw, dev = %dev, "installed server bypass route");
                    self.bypass_route = Some((ip, maybe_gw.clone(), dev.clone()));
                }
                Err(err) => {
                    warn!(%ip, dev = %dev, error = %err, "failed to install server bypass route");
                }
            }
        }

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

    /// Dynamically installs a `/32` bypass route for an IP resolved from a
    /// configured `bypass.domains` entry (bounded to [`MAX_DYNAMIC_BYPASS_IPS`]).
    pub fn install_dynamic_bypass_ip(&mut self, ip: Ipv4Addr) {
        if !self.auto_route || ip.is_loopback() || ip.is_private() {
            return;
        }
        if self.dynamic_bypass_v4.contains(&ip)
            || self.dynamic_bypass_v4.len() >= MAX_DYNAMIC_BYPASS_IPS
        {
            return;
        }
        self.dynamic_bypass_v4.push(ip);
        if let Some((maybe_gw, dev)) = self.current_gw.as_ref() {
            let host = format!("{ip}/32");
            if install_v4_bypass(&host, maybe_gw.as_deref(), dev).is_ok() {
                self.extra_bypass_v4
                    .push((host, maybe_gw.clone(), dev.clone()));
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
        if let Some((ip, maybe_gw, dev)) = self.bypass_route.as_ref() {
            let host = format!("{ip}/32");
            if let Err(err) = remove_v4_bypass(&host, maybe_gw.as_deref(), dev) {
                warn!(%ip, error = %err, "failed to remove server bypass route on shutdown");
            }
        }
    }
}

fn is_ipv4_cidr(cidr: &str) -> bool {
    cidr.split_once('/')
        .is_some_and(|(ip, _)| ip.parse::<Ipv4Addr>().is_ok())
}

fn install_v4_bypass(prefix: &str, gw: Option<&str>, dev: &str) -> io::Result<()> {
    if let Some(gw) = gw {
        run_ip(&["route", "replace", prefix, "via", gw, "dev", dev])
    } else {
        run_ip(&["route", "replace", prefix, "dev", dev])
    }
}

fn remove_v4_bypass(prefix: &str, gw: Option<&str>, dev: &str) -> io::Result<()> {
    if let Some(gw) = gw {
        run_ip(&["route", "del", prefix, "via", gw, "dev", dev])
    } else {
        run_ip(&["route", "del", prefix, "dev", dev])
    }
}

fn run_ip(args: &[&str]) -> io::Result<()> {
    let status = Command::new("ip").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "`ip {}` exited with {status}",
            args.join(" ")
        )))
    }
}

/// Detects the current physical default IPv4 gateway, skipping `exclude_ifname`.
pub fn detect_default_ipv4_gateway_excluding(exclude_ifname: &str) -> GatewayState {
    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        let mut gw = None;
        let mut dev = None;
        while let Some(tok) = tokens.next() {
            match tok {
                "via" => gw = tokens.next().map(str::to_owned),
                "dev" => dev = tokens.next().map(str::to_owned),
                _ => {}
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
