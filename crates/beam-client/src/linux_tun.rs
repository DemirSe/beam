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

/// Configures IP address, MTU, link UP, and optional default split-routes
/// (`0.0.0.0/1`, `128.0.0.0/1`, IPv6 `::/1`, `8000::/1` + host bypass route
/// for the `beam` server) on Linux.
///
/// Tracks every route it installs so both partial `setup()` failures and clean
/// shutdowns roll back **only** the routes installed by this guard.
pub struct LinuxRouteGuard {
    ifname: String,
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

        // Construct the guard before adding any routes so a failure mid-setup
        // automatically rolls back everything installed so far via `Drop`.
        let mut guard = Self {
            ifname: ifname.to_owned(),
            installed_v4_low: false,
            installed_v4_high: false,
            installed_v6_low: false,
            installed_v6_high: false,
            bypass_route: None,
            extra_bypass_v4: Vec::new(),
        };

        if auto_route {
            let detected_gw = detect_default_ipv4_gateway();
            if let Some(ip) = server_ip
                && !ip.is_loopback()
            {
                if let Some((maybe_gw, dev)) = detected_gw.clone() {
                    let host = format!("{ip}/32");
                    install_v4_bypass(&host, maybe_gw.as_deref(), &dev)?;
                    info!(%ip, via = ?maybe_gw, dev = %dev, "installed server bypass route");
                    guard.bypass_route = Some((ip, maybe_gw, dev));
                } else {
                    return Err(io::Error::other(
                        "could not detect default IPv4 gateway for server bypass route",
                    ));
                }
            }

            if let Some((maybe_gw, dev)) = detected_gw {
                for cidr_entry in bypass_cidrs {
                    if is_ipv4_cidr(cidr_entry) {
                        if let Err(err) = install_v4_bypass(cidr_entry, maybe_gw.as_deref(), &dev) {
                            warn!(cidr = %cidr_entry, error = %err, "failed to install IPv4 bypass CIDR route");
                        } else {
                            guard.extra_bypass_v4.push((
                                cidr_entry.clone(),
                                maybe_gw.clone(),
                                dev.clone(),
                            ));
                        }
                    }
                }
            }

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

fn detect_default_ipv4_gateway() -> Option<(Option<String>, String)> {
    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let line = text.lines().next()?;
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
    Some((gw, dev?))
}
