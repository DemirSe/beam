//! Async Linux `/dev/net/tun` adapter implementing `beam_tun::TunDevice`.

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
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read_packet(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().write_packet(packet)) {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }
}

/// Configures IP address, MTU, link UP, and optional default split-routes
/// (`0.0.0.0/1`, `128.0.0.0/1` + host bypass route for the `beam` server) on
/// Linux, cleaning up the bypass route on drop.
pub struct LinuxRouteGuard {
    ifname: String,
    server_ip: Option<Ipv4Addr>,
    default_gw: Option<(String, String)>,
}

impl LinuxRouteGuard {
    /// Brings up `ifname` with `cidr` and `mtu`. When `auto_route` is `true`,
    /// installs a host route for `server_ip` via the current default gateway
    /// first, then routes `0.0.0.0/1` and `128.0.0.0/1` through `ifname`.
    pub fn setup(
        ifname: &str,
        cidr: &str,
        mtu: usize,
        auto_route: bool,
        server_ip: Option<Ipv4Addr>,
    ) -> io::Result<Self> {
        run_ip(&["addr", "replace", cidr, "dev", ifname])?;
        run_ip(&["link", "set", "dev", ifname, "mtu", &mtu.to_string(), "up"])?;

        let mut default_gw = None;
        if auto_route {
            if let Some(ip) = server_ip
                && !ip.is_loopback()
            {
                if let Some((gw, dev)) = detect_default_ipv4_gateway() {
                    let host = format!("{ip}/32");
                    run_ip(&["route", "replace", &host, "via", &gw, "dev", &dev])?;
                    info!(%ip, via = %gw, dev = %dev, "installed server bypass route");
                    default_gw = Some((gw, dev));
                } else {
                    return Err(io::Error::other(
                        "could not detect default IPv4 gateway for server bypass route",
                    ));
                }
            }
            run_ip(&["route", "replace", "0.0.0.0/1", "dev", ifname])?;
            run_ip(&["route", "replace", "128.0.0.0/1", "dev", ifname])?;
            info!(dev = %ifname, "installed TUN default routes (0.0.0.0/1, 128.0.0.0/1)");
        }

        Ok(Self {
            ifname: ifname.to_owned(),
            server_ip,
            default_gw,
        })
    }
}

impl Drop for LinuxRouteGuard {
    fn drop(&mut self) {
        let _ = run_ip(&["route", "del", "0.0.0.0/1", "dev", &self.ifname]);
        let _ = run_ip(&["route", "del", "128.0.0.0/1", "dev", &self.ifname]);
        if let (Some(ip), Some((gw, dev))) = (self.server_ip, self.default_gw.as_ref()) {
            let host = format!("{ip}/32");
            if let Err(err) = run_ip(&["route", "del", &host, "via", gw, "dev", dev]) {
                warn!(%ip, error = %err, "failed to remove server bypass route on shutdown");
            }
        }
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

fn detect_default_ipv4_gateway() -> Option<(String, String)> {
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
    Some((gw?, dev?))
}
