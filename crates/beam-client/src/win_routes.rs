//! Windows route management: bypass routes, fail-closed split routes, WFP
//! leak protection, and the `routes.state` crash-recovery file.
//!
//! The `routes.state` format and its validators are platform independent, so
//! their unit tests also run on Linux. Everything that talks to IP Helper or
//! WFP is `#[cfg(windows)]`.

// The Windows guard consumes the state helpers; other targets build them for
// the shared `routes.state` unit tests, so unused-item warnings are expected
// there.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::IpAddr;

/// Upper bound of routes written to or read from `routes.state`, so a corrupt
/// file cannot turn cleanup into an unbounded run.
pub const MAX_PERSISTED_ROUTES: usize = 1024;

/// One route persisted to `routes.state` for crash-recovery cleanup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedWinRoute {
    /// Destination prefix in CIDR notation (`203.0.113.10/32`).
    pub prefix: String,
    /// Next hop, or the unspecified address for an on-link route.
    pub next_hop: IpAddr,
    /// LUID of the interface the route uses.
    pub interface_luid: u64,
    /// Index of the interface the route uses.
    pub interface_index: u32,
    /// Route metric offset.
    pub metric: u32,
}

/// Formats persisted routes as tab-separated lines
/// (`<prefix>\t<next_hop>\t<luid>\t<index>\t<metric>`).
pub fn format_routes_state(routes: &[PersistedWinRoute]) -> String {
    let mut out = String::new();
    for route in routes.iter().take(MAX_PERSISTED_ROUTES) {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            route.prefix, route.next_hop, route.interface_luid, route.interface_index, route.metric
        ));
    }
    out
}

/// Parses persisted routes from state file text.
///
/// Malformed lines are skipped; output is bounded to [`MAX_PERSISTED_ROUTES`].
pub fn parse_routes_state(text: &str) -> Vec<PersistedWinRoute> {
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
        let (Some(prefix), Some(next_hop), Some(luid), Some(index), Some(metric), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        let Some((destination, _prefix_len)) = split_cidr(prefix) else {
            continue;
        };
        let Ok(next_hop) = next_hop.parse::<IpAddr>() else {
            continue;
        };
        if next_hop.is_ipv4() != destination.is_ipv4() {
            continue;
        }
        let (Ok(interface_luid), Ok(interface_index), Ok(metric)) = (
            luid.parse::<u64>(),
            index.parse::<u32>(),
            metric.parse::<u32>(),
        ) else {
            continue;
        };
        if interface_luid == 0 || interface_index == 0 {
            continue;
        }
        routes.push(PersistedWinRoute {
            prefix: prefix.to_owned(),
            next_hop,
            interface_luid,
            interface_index,
            metric,
        });
    }
    routes
}

/// Splits a CIDR string into its address and prefix length.
///
/// Both parts must parse and the prefix length must fit the address family.
fn split_cidr(raw: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix_len) = raw.split_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    let prefix_len = prefix_len.parse::<u8>().ok()?;
    let limit = if address.is_ipv4() { 32 } else { 128 };
    (prefix_len <= limit).then_some((address, prefix_len))
}

#[cfg(windows)]
pub use imp::*;

#[cfg(windows)]
mod imp {
    use std::collections::VecDeque;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, LazyLock};
    use std::time::{Duration, Instant};

    use beam_core::client::SocketProtector;
    use beam_sys::bind_socket_to_interface_v4;
    use beam_sys::bind_socket_to_interface_v6;
    use beam_sys::windows::iphelper::{
        InterfaceRoute, PhysicalGateway, PhysicalGateways, add_route, delete_route,
        detect_physical_gateways, flush_dns_cache, luid_to_index, route_exists, set_interface_dns,
        set_interface_mtu_and_metric, set_interface_unicast_ip,
    };
    use beam_sys::windows::wfp::{WfpConfig, WfpGuard};
    use beam_tun::{IpNet, RateLimiter, TUN_V6_NET};
    use tracing::{debug, info, warn};

    use super::{
        MAX_PERSISTED_ROUTES, PersistedWinRoute, format_routes_state, parse_routes_state,
        split_cidr,
    };

    /// IPv4 and IPv6 address assigned to the tunnel interface
    /// (`fd00:be:a::1/126`, inside [`beam_tun::TUN_V6_NET`]).
    const TUN_V6_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x00be, 0x000a, 0, 0, 0, 0, 1);
    /// Prefix length of [`TUN_V6_ADDR`].
    const TUN_V6_PREFIX_LEN: u8 = 126;

    /// Interface and route metric of the tunnel and of its bypass routes.
    ///
    /// A low fixed metric makes the tunnel and its more specific bypass routes
    /// win against the automatic metric of the physical adapters.
    const ROUTE_METRIC: u32 = 5;

    /// Dynamic `bypass.domains` entries kept per address family.
    const MAX_DYNAMIC_BYPASS_IPS: usize = 256;
    /// Lifetime of a dynamic `bypass.domains` entry.
    const DYNAMIC_BYPASS_TTL: Duration = Duration::from_secs(3600);

    /// At most 3 route-lookup warnings per 60 s window.
    static ROUTE_CHECK_LOG: LazyLock<RateLimiter> =
        LazyLock::new(|| RateLimiter::new(3, Duration::from_secs(60)));
    /// At most 3 dynamic-bypass cap warnings per 600 s window.
    static DYNAMIC_BYPASS_CAP_LOG: LazyLock<RateLimiter> =
        LazyLock::new(|| RateLimiter::new(3, Duration::from_secs(600)));

    /// Interface indexes of the physical default gateways, shared with the
    /// socket protectors that bind upstream sockets to them.
    #[derive(Clone, Default)]
    pub struct ActivePhysicalInterface {
        indexes: Arc<(AtomicU32, AtomicU32)>,
    }

    impl ActivePhysicalInterface {
        /// Creates an empty holder: index 0 means "no gateway detected", which
        /// makes every protector fail closed until [`Self::update`] runs.
        pub fn new() -> Self {
            Self::default()
        }

        /// Records the interface indexes of `gateways`; a family without a
        /// gateway resets to 0.
        pub fn update(&self, gateways: &PhysicalGateways) {
            let v4 = gateways.v4.as_ref().map_or(0, |gw| gw.interface_index);
            let v6 = gateways.v6.as_ref().map_or(0, |gw| gw.interface_index);
            self.indexes.0.store(v4, Ordering::Relaxed);
            self.indexes.1.store(v6, Ordering::Relaxed);
        }

        /// Index of the physical IPv4 interface, or 0 when none is known.
        pub fn v4_index(&self) -> u32 {
            self.indexes.0.load(Ordering::Relaxed)
        }

        /// Index of the physical IPv6 interface, or 0 when none is known.
        pub fn v6_index(&self) -> u32 {
            self.indexes.1.load(Ordering::Relaxed)
        }

        /// Builds a protector that pins an upstream socket to the current
        /// physical interface of `family_v6`.
        ///
        /// Without a known index the hook fails with
        /// [`io::ErrorKind::NetworkUnreachable`] instead of dialing: an
        /// unbound socket would follow the default route and can loop back
        /// into the tunnel.
        pub fn make_socket_protector(&self, family_v6: bool) -> SocketProtector {
            let holder = self.clone();
            Arc::new(move |socket| {
                let index = if family_v6 {
                    holder.v6_index()
                } else {
                    holder.v4_index()
                };
                if index == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::NetworkUnreachable,
                        "no physical interface is known for the upstream socket",
                    ));
                }
                if family_v6 {
                    bind_socket_to_interface_v6(socket, index)
                } else {
                    bind_socket_to_interface_v4(socket, index)
                }
            })
        }
    }

    /// Bypass and split routes, DNS, and WFP policy of one connected session.
    ///
    /// Every route this guard installs is tracked, so both a partial [`setup`]
    /// failure and a normal shutdown roll back exactly those routes. [`Drop`]
    /// removes the WFP session, the bypass and split routes, the tunnel DNS
    /// server, and `routes.state`; closing the WinTun adapter removes the
    /// interface addresses.
    ///
    /// [`setup`]: WindowsRouteGuard::setup
    pub struct WindowsRouteGuard {
        tun_luid: u64,
        tun_index: u32,
        auto_route: bool,
        routes_state_path: PathBuf,
        tun_net: Option<IpNet>,
        server_ip: IpAddr,
        local_dns_ip: Option<IpAddr>,
        active_if: ActivePhysicalInterface,
        current_gw: PhysicalGateways,
        static_bypass: Vec<(IpAddr, u8)>,
        dynamic_bypass_v4: VecDeque<(IpAddr, Instant)>,
        dynamic_bypass_v6: VecDeque<(IpAddr, Instant)>,
        split_routes: Vec<InterfaceRoute>,
        server_route: Option<InterfaceRoute>,
        dns_route: Option<InterfaceRoute>,
        extra_routes: Vec<InterfaceRoute>,
        wfp: Option<WfpGuard>,
    }

    impl WindowsRouteGuard {
        /// Brings the tunnel interface up and, when `auto_route` is set,
        /// installs the fail-closed split routes, the bypass routes for the
        /// server, local DNS, and `bypass.cidrs`, per-interface DNS, and the WFP
        /// leak guard.
        ///
        /// Any error rolls the partially installed state back before it is
        /// returned.
        #[allow(clippy::too_many_arguments)]
        pub fn setup(
            tun_luid: u64,
            tun_cidr: &str,
            mtu: usize,
            auto_route: bool,
            strict_kill_switch: bool,
            server_ip: IpAddr,
            initial_local_dns: Option<IpAddr>,
            tun_dns_peer: Option<Ipv4Addr>,
            bypass_cidrs: &[String],
            active_if: ActivePhysicalInterface,
            state_path: PathBuf,
        ) -> io::Result<Self> {
            let (tun_ip, tun_prefix_len) = split_cidr(tun_cidr).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("tunnel address {tun_cidr:?} is not a CIDR"),
                )
            })?;
            let mut static_bypass =
                Vec::with_capacity(bypass_cidrs.len().min(MAX_PERSISTED_ROUTES));
            for raw in bypass_cidrs.iter().take(MAX_PERSISTED_ROUTES) {
                let entry = split_cidr(raw.trim()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("bypass CIDR {raw:?} is not a CIDR"),
                    )
                })?;
                static_bypass.push(entry);
            }

            let mut guard = Self {
                tun_luid,
                tun_index: luid_to_index(tun_luid)?,
                auto_route,
                routes_state_path: state_path,
                tun_net: IpNet::parse_cidr(tun_cidr),
                server_ip,
                local_dns_ip: initial_local_dns,
                active_if,
                current_gw: PhysicalGateways::default(),
                static_bypass,
                dynamic_bypass_v4: VecDeque::new(),
                dynamic_bypass_v6: VecDeque::new(),
                split_routes: Vec::new(),
                server_route: None,
                dns_route: None,
                extra_routes: Vec::new(),
                wfp: None,
            };
            if let Err(err) = guard.bring_up(
                tun_ip,
                tun_prefix_len,
                mtu,
                tun_dns_peer,
                strict_kill_switch,
            ) {
                // `Drop` deletes the addresses, routes, DNS setting, and
                // filters that were installed before the failure.
                drop(guard);
                return Err(err);
            }
            Ok(guard)
        }

        /// Installs the address, MTU, and (when routing is enabled) the bypass
        /// routes, split routes, DNS, and WFP policy.
        fn bring_up(
            &mut self,
            tun_ip: IpAddr,
            tun_prefix_len: u8,
            mtu: usize,
            tun_dns_peer: Option<Ipv4Addr>,
            strict_kill_switch: bool,
        ) -> io::Result<()> {
            let mtu = u32::try_from(mtu).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("MTU {mtu} does not fit the interface table"),
                )
            })?;
            set_interface_unicast_ip(self.tun_luid, tun_ip, tun_prefix_len)?;
            set_interface_unicast_ip(self.tun_luid, IpAddr::V6(TUN_V6_ADDR), TUN_V6_PREFIX_LEN)?;
            set_interface_mtu_and_metric(self.tun_luid, false, mtu, ROUTE_METRIC)?;
            set_interface_mtu_and_metric(self.tun_luid, true, mtu, ROUTE_METRIC)?;
            // Reclaim bypass routes left behind by an unclean exit, whether or
            // not this session routes through the tunnel.
            let _ = cleanup_persisted_routes(&self.routes_state_path);
            // The socket protectors need the physical interface index even when
            // this session installs no routes; the monitor retries detection.
            let gateways = match detect_physical_gateways(self.tun_luid) {
                Ok(gateways) => gateways,
                Err(err) if !self.auto_route => {
                    warn!(error = %err, "physical gateway detection failed; upstream sockets stay fail-closed");
                    return Ok(());
                }
                Err(err) => return Err(err),
            };
            self.active_if.update(&gateways);
            if !self.auto_route {
                return Ok(());
            }

            if gateways.v4.is_none() && gateways.v6.is_none() {
                warn!(
                    "no physical default gateway detected at startup; running fail-closed until the network comes up"
                );
            }
            self.current_gw = gateways;
            self.apply_bypass_routes();
            self.persist_routes_state();
            self.install_split_routes()?;
            if let Some(peer) = tun_dns_peer {
                set_interface_dns(self.tun_luid, &[IpAddr::V4(peer)])?;
                flush_dns_cache()?;
            }
            self.install_wfp(strict_kill_switch, tun_dns_peer.is_some())
        }

        /// Routes `0.0.0.0/1`, `128.0.0.0/1`, `::/1`, and `8000::/1` into the
        /// tunnel, which covers every global destination without replacing the
        /// physical default routes the bypass routes still need.
        fn install_split_routes(&mut self) -> io::Result<()> {
            let splits = [
                tun_route(
                    Ipv4Addr::UNSPECIFIED.into(),
                    1,
                    self.tun_luid,
                    self.tun_index,
                ),
                tun_route(
                    Ipv4Addr::new(128, 0, 0, 0).into(),
                    1,
                    self.tun_luid,
                    self.tun_index,
                ),
                tun_route(
                    Ipv6Addr::UNSPECIFIED.into(),
                    1,
                    self.tun_luid,
                    self.tun_index,
                ),
                tun_route(
                    Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0).into(),
                    1,
                    self.tun_luid,
                    self.tun_index,
                ),
            ];
            for route in splits {
                add_route(&route)?;
                self.split_routes.push(route);
            }
            info!(
                luid = self.tun_luid,
                "installed fail-closed split routes through the tunnel"
            );
            Ok(())
        }

        /// Installs the dynamic WFP session that blocks physical DNS and, when
        /// requested, every connection that leaves outside the tunnel.
        fn install_wfp(
            &mut self,
            strict_kill_switch: bool,
            block_physical_dns: bool,
        ) -> io::Result<()> {
            let mut config = WfpConfig::new(self.tun_luid)?;
            config.block_physical_dns = block_physical_dns;
            config.strict_kill_switch = strict_kill_switch;
            config.permit_cidrs = self.permit_cidrs();
            config.local_dns_ips = self.local_dns_ips();
            let guard = WfpGuard::install(config)?;
            info!(
                filters = guard.filter_count(),
                strict_kill_switch, block_physical_dns, "installed WFP leak guard"
            );
            self.wfp = Some(guard);
            Ok(())
        }

        /// Destinations that stay reachable outside the tunnel: the server and
        /// every configured or resolved bypass address.
        ///
        /// The local DNS resolver is deliberately absent: it is permitted for
        /// this executable only through the WFP local-DNS filters, so other
        /// processes cannot send plaintext port-53 queries to it.
        fn permit_cidrs(&self) -> Vec<(IpAddr, u8)> {
            let mut out = Vec::with_capacity(
                self.static_bypass.len()
                    + self.dynamic_bypass_v4.len()
                    + self.dynamic_bypass_v6.len()
                    + 1,
            );
            if !self.server_ip.is_loopback() {
                out.push((self.server_ip, host_prefix(self.server_ip)));
            }
            out.extend(self.static_bypass.iter().copied());
            out.extend(
                self.dynamic_bypass_v4
                    .iter()
                    .map(|(ip, _)| (*ip, host_prefix(*ip))),
            );
            out.extend(
                self.dynamic_bypass_v6
                    .iter()
                    .map(|(ip, _)| (*ip, host_prefix(*ip))),
            );
            out.sort_unstable();
            out.dedup();
            out
        }

        /// Pushes the current permit lists into WFP when they changed.
        fn sync_wfp_permits(&mut self) {
            let wanted = self.permit_cidrs();
            let wanted_dns = self.local_dns_ips();
            let Some(wfp) = self.wfp.as_mut() else {
                return;
            };
            if wfp.config().permit_cidrs == wanted && wfp.config().local_dns_ips == wanted_dns {
                return;
            }
            // One rebuild covers both lists when both changed; otherwise only
            // the changed list rebuilds.
            let cidrs_changed = wfp.config().permit_cidrs != wanted;
            let dns_changed = wfp.config().local_dns_ips != wanted_dns;
            if cidrs_changed && let Err(err) = wfp.update_permit_cidrs(&wanted) {
                warn!(error = %err, "failed to update the WFP permit list");
                return;
            }
            if dns_changed {
                match wfp.update_local_dns_ips(&wanted_dns) {
                    Ok(()) => debug!(
                        cidrs = wanted.len(),
                        dns = wanted_dns.len(),
                        "updated the WFP permit list"
                    ),
                    Err(err) => warn!(error = %err, "failed to update the WFP DNS list"),
                }
            } else if cidrs_changed {
                debug!(cidrs = wanted.len(), "updated the WFP permit list");
            }
        }

        /// Resolver IPs only this executable may reach on port 53.
        ///
        /// Loopback and tunnel-subnet addresses need no physical permit:
        /// loopback is always permitted and tunnel addresses stay inside the
        /// tunnel interface permit.
        fn local_dns_ips(&self) -> Vec<IpAddr> {
            self.local_dns_ip
                .filter(|ip| !ip.is_loopback() && !self.is_in_tun_subnet(*ip))
                .into_iter()
                .collect()
        }

        /// Returns `true` when `ip` lies inside the tunnel IPv4 or IPv6 subnet.
        fn is_in_tun_subnet(&self, ip: IpAddr) -> bool {
            self.tun_net.is_some_and(|net| net.contains(ip)) || TUN_V6_NET.contains(ip)
        }

        /// Removes every bypass route this guard installed, keeping the split
        /// routes in place so the tunnel stays fail-closed.
        fn clear_bypass_routes(&mut self) {
            if let Some(route) = self.server_route.take() {
                remove_route(&route);
            }
            if let Some(route) = self.dns_route.take() {
                remove_route(&route);
            }
            for route in self.extra_routes.drain(..) {
                remove_route(&route);
            }
        }

        /// Removes and reinstalls the bypass routes for the current gateways.
        fn apply_bypass_routes(&mut self) {
            self.clear_bypass_routes();
            if !self.server_ip.is_loopback() {
                self.server_route = self.install_bypass(self.server_ip);
            }
            let dns_ip = self.local_dns_ip.filter(|ip| {
                !ip.is_loopback() && *ip != self.server_ip && !self.is_in_tun_subnet(*ip)
            });
            if let Some(dns_ip) = dns_ip {
                self.dns_route = self.install_bypass(dns_ip);
            }
            for (destination, prefix_len) in self.static_bypass.clone() {
                if let Some(route) = self.install_bypass_with_prefix(destination, prefix_len) {
                    self.extra_routes.push(route);
                }
            }
            let dynamic: Vec<IpAddr> = self
                .dynamic_bypass_v4
                .iter()
                .chain(self.dynamic_bypass_v6.iter())
                .map(|(ip, _)| *ip)
                .collect();
            for ip in dynamic {
                if let Some(route) = self.install_bypass(ip) {
                    info!(ip = %ip, "installed dynamic bypass.domains route");
                    self.extra_routes.push(route);
                }
            }
        }

        /// Installs the host route for `destination` on its family's gateway.
        fn install_bypass(&mut self, destination: IpAddr) -> Option<InterfaceRoute> {
            self.install_bypass_with_prefix(destination, host_prefix(destination))
        }

        /// Installs a route for `destination/prefix_len` on its family's
        /// gateway, returning it only when the row was added.
        fn install_bypass_with_prefix(
            &mut self,
            destination: IpAddr,
            prefix_len: u8,
        ) -> Option<InterfaceRoute> {
            let gateway = gateway_for_ip(&self.current_gw, destination)?.clone();
            let route = InterfaceRoute {
                destination,
                prefix_len,
                next_hop: gateway.next_hop,
                interface_luid: gateway.interface_luid,
                interface_index: gateway.interface_index,
                metric: ROUTE_METRIC,
            };
            match add_route(&route) {
                Ok(()) => {
                    debug!(
                        destination = %destination,
                        prefix_len,
                        next_hop = %gateway.next_hop,
                        "installed bypass route"
                    );
                    Some(route)
                }
                Err(err) => {
                    warn!(
                        destination = %destination,
                        prefix_len,
                        next_hop = %gateway.next_hop,
                        error = %err,
                        "failed to install bypass route"
                    );
                    None
                }
            }
        }

        /// Installs a host route for an IP resolved from a `bypass.domains`
        /// entry, bounded to [`MAX_DYNAMIC_BYPASS_IPS`] per family with FIFO
        /// eviction and a [`DYNAMIC_BYPASS_TTL`] lifetime.
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
            match ip {
                IpAddr::V4(v4) if v4.is_link_local() || v4.is_broadcast() => return,
                IpAddr::V6(v6) if v6.is_unicast_link_local() => return,
                _ => {}
            }

            let now = Instant::now();
            let queue = match ip {
                IpAddr::V4(_) => &mut self.dynamic_bypass_v4,
                IpAddr::V6(_) => &mut self.dynamic_bypass_v6,
            };
            // A repeated resolution only refreshes the entry, which keeps it
            // newest without touching the routing table.
            if let Some(position) = queue.iter().position(|(known, _)| *known == ip) {
                queue.remove(position);
                queue.push_back((ip, now));
                return;
            }
            let mut evicted = Vec::new();
            while let Some((oldest, added_at)) = queue.front().copied() {
                let at_cap = queue.len() >= MAX_DYNAMIC_BYPASS_IPS;
                let expired = now.saturating_duration_since(added_at) >= DYNAMIC_BYPASS_TTL;
                if !at_cap && !expired {
                    break;
                }
                if at_cap && let Some(suppressed) = DYNAMIC_BYPASS_CAP_LOG.allow() {
                    warn!(
                        cap = MAX_DYNAMIC_BYPASS_IPS,
                        suppressed,
                        "dynamic bypass.domains table is full; evicting the oldest route"
                    );
                }
                queue.pop_front();
                evicted.push(oldest);
            }
            queue.push_back((ip, now));

            for oldest in evicted {
                let prefix_len = host_prefix(oldest);
                let position = self.extra_routes.iter().position(|route| {
                    route.destination == oldest && route.prefix_len == prefix_len
                });
                if let Some(position) = position {
                    let route = self.extra_routes.remove(position);
                    remove_route(&route);
                }
            }

            if let Some(route) = self.install_bypass(ip) {
                info!(ip = %ip, "installed dynamic bypass.domains route");
                self.extra_routes.push(route);
                self.sync_wfp_permits();
                self.persist_routes_state();
            }
        }

        /// Migrates every bypass route to `new_gateways`, keeping the tunnel
        /// split routes fail-closed.
        ///
        /// Returns `true` when the reconcile ran; IP Helper failures are logged
        /// per route and retried by the next monitor cycle.
        pub fn update_bypass_gateway(
            &mut self,
            new_gateways: &PhysicalGateways,
            new_local_dns: Option<IpAddr>,
        ) -> bool {
            // The socket protectors follow the physical interfaces of both
            // modes, so this update must never be skipped.
            self.active_if.update(new_gateways);
            if !self.auto_route {
                return true;
            }
            let now = Instant::now();
            let before = self.dynamic_bypass_v4.len() + self.dynamic_bypass_v6.len();
            self.dynamic_bypass_v4.retain(|(_, added_at)| {
                now.saturating_duration_since(*added_at) < DYNAMIC_BYPASS_TTL
            });
            self.dynamic_bypass_v6.retain(|(_, added_at)| {
                now.saturating_duration_since(*added_at) < DYNAMIC_BYPASS_TTL
            });
            let expired = self.dynamic_bypass_v4.len() + self.dynamic_bypass_v6.len() != before;
            // Nothing to migrate: keep the installed routes instead of tearing
            // down and re-adding them on every monitor cycle.
            if !expired
                && *new_gateways == self.current_gw
                && new_local_dns == self.local_dns_ip
                && self.bypass_routes_installed()
            {
                return true;
            }
            self.current_gw = new_gateways.clone();
            self.local_dns_ip = new_local_dns;
            self.apply_bypass_routes();
            self.sync_wfp_permits();
            self.persist_routes_state();
            true
        }

        /// Reports whether the server bypass route and every tracked DNS and
        /// static bypass route are still present in the routing table.
        ///
        /// A deleted route is detected so the next monitor cycle reinstalls it.
        /// A failed lookup counts as missing (fail-closed).
        pub fn bypass_routes_installed(&self) -> bool {
            if !self.auto_route {
                return true;
            }
            if !self.server_ip.is_loopback() {
                let Some(gateway) = gateway_for_ip(&self.current_gw, self.server_ip) else {
                    // Fail-closed: without a gateway of the server's family no
                    // bypass route can be installed.
                    return false;
                };
                if !Self::route_still_installed(
                    self.server_ip,
                    host_prefix(self.server_ip),
                    gateway.interface_luid,
                ) {
                    return false;
                }
            }
            if let Some(dns_ip) = self.local_dns_ip.filter(|ip| {
                !ip.is_loopback() && *ip != self.server_ip && !self.is_in_tun_subnet(*ip)
            }) && let Some(gateway) = gateway_for_ip(&self.current_gw, dns_ip)
                && !Self::route_still_installed(dns_ip, host_prefix(dns_ip), gateway.interface_luid)
            {
                return false;
            }
            for &(destination, prefix_len) in &self.static_bypass {
                if let Some(gateway) = gateway_for_ip(&self.current_gw, destination)
                    && !Self::route_still_installed(destination, prefix_len, gateway.interface_luid)
                {
                    return false;
                }
            }
            self.dns_route
                .iter()
                .chain(self.extra_routes.iter())
                .all(|route| {
                    Self::route_still_installed(
                        route.destination,
                        route.prefix_len,
                        route.interface_luid,
                    )
                })
        }

        /// Reports whether one route is still in the routing table.
        ///
        /// A failed lookup counts as missing (fail-closed).
        fn route_still_installed(destination: IpAddr, prefix_len: u8, luid: u64) -> bool {
            match route_exists(destination, prefix_len, luid) {
                Ok(present) => present,
                Err(err) => {
                    if let Some(suppressed) = ROUTE_CHECK_LOG.allow() {
                        warn!(
                            ip = %destination,
                            error = %err,
                            suppressed,
                            "bypass route lookup failed; treating the route as missing"
                        );
                    }
                    false
                }
            }
        }

        /// Snapshots the bypass routes this guard installed for crash recovery.
        fn collect_persisted_routes(&self) -> Vec<PersistedWinRoute> {
            let mut out = Vec::new();
            for route in self
                .server_route
                .iter()
                .chain(self.dns_route.iter())
                .chain(self.extra_routes.iter())
            {
                if out.len() >= MAX_PERSISTED_ROUTES {
                    break;
                }
                out.push(PersistedWinRoute {
                    prefix: format!("{}/{}", route.destination, route.prefix_len),
                    next_hop: route.next_hop,
                    interface_luid: route.interface_luid,
                    interface_index: route.interface_index,
                    metric: route.metric,
                });
            }
            out
        }

        /// Writes the current bypass routes to `routes.state`.
        fn persist_routes_state(&self) {
            write_routes_state_atomic(&self.routes_state_path, &self.collect_persisted_routes());
        }
    }

    impl Drop for WindowsRouteGuard {
        fn drop(&mut self) {
            // Drop the dynamic WFP session first, so no filter can outlive the
            // routes it permits.
            self.wfp = None;
            self.clear_bypass_routes();
            for route in self.split_routes.drain(..) {
                remove_route(&route);
            }
            if let Err(err) = set_interface_dns(self.tun_luid, &[]) {
                debug!(error = %err, "failed to clear the tunnel DNS server on shutdown");
            }
            if let Err(err) = flush_dns_cache() {
                debug!(error = %err, "failed to flush the DNS cache on shutdown");
            }
            let _ = std::fs::remove_file(&self.routes_state_path);
        }
    }

    /// Returns the host prefix length of `ip`.
    fn host_prefix(ip: IpAddr) -> u8 {
        if ip.is_ipv4() { 32 } else { 128 }
    }

    /// Returns the gateway that carries `ip`, or `None` when that family has no
    /// default gateway.
    fn gateway_for_ip(gateways: &PhysicalGateways, ip: IpAddr) -> Option<&PhysicalGateway> {
        if ip.is_ipv4() {
            gateways.v4.as_ref()
        } else {
            gateways.v6.as_ref()
        }
    }

    /// Builds an on-link route through the tunnel interface.
    fn tun_route(
        destination: IpAddr,
        prefix_len: u8,
        interface_luid: u64,
        interface_index: u32,
    ) -> InterfaceRoute {
        InterfaceRoute {
            destination,
            prefix_len,
            next_hop: if destination.is_ipv4() {
                Ipv4Addr::UNSPECIFIED.into()
            } else {
                Ipv6Addr::UNSPECIFIED.into()
            },
            interface_luid,
            interface_index,
            metric: ROUTE_METRIC,
        }
    }

    /// Deletes one installed route, logging a failure instead of propagating
    /// it: a stale row must not stop the rest of the rollback.
    fn remove_route(route: &InterfaceRoute) {
        if let Err(err) = delete_route(route) {
            warn!(
                destination = %route.destination,
                prefix_len = route.prefix_len,
                error = %err,
                "failed to remove route"
            );
        }
    }

    /// Atomically writes `routes` to `path` when its parent directory exists.
    fn write_routes_state_atomic(path: &Path, routes: &[PersistedWinRoute]) {
        use std::io::Write as _;

        let body = format_routes_state(routes);
        let Ok((tmp, mut file)) = crate::win_ipc::create_temp_sibling(path) else {
            return;
        };
        let written = file
            .write_all(body.as_bytes())
            .and_then(|()| file.sync_all());
        drop(file);
        if written.and_then(|()| std::fs::rename(&tmp, path)).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }

    /// Reads `path`, deletes every persisted route, and removes the file.
    ///
    /// Used at startup and by `--cleanup-routes` to recover the routes an
    /// unclean exit left behind. A missing file is not an error.
    pub fn cleanup_persisted_routes(path: &Path) -> io::Result<usize> {
        let content = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(err),
        };
        let mut removed = 0_usize;
        for route in parse_routes_state(&content) {
            let Some((destination, prefix_len)) = split_cidr(&route.prefix) else {
                continue;
            };
            let row = InterfaceRoute {
                destination,
                prefix_len,
                next_hop: route.next_hop,
                interface_luid: route.interface_luid,
                interface_index: route.interface_index,
                metric: route.metric,
            };
            if delete_route(&row).is_ok() {
                removed += 1;
            }
        }
        let _ = std::fs::remove_file(path);
        Ok(removed)
    }

    #[cfg(test)]
    mod imp_tests {
        use super::{ActivePhysicalInterface, PhysicalGateways, WindowsRouteGuard, host_prefix};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use std::path::PathBuf;

        fn guard_with_dns(server_ip: IpAddr, local_dns_ip: Option<IpAddr>) -> WindowsRouteGuard {
            WindowsRouteGuard {
                tun_luid: 0x0000_0001_0000_0001,
                tun_index: 1,
                auto_route: true,
                routes_state_path: PathBuf::from("routes.state"),
                tun_net: None,
                server_ip,
                local_dns_ip,
                active_if: ActivePhysicalInterface::new(),
                current_gw: PhysicalGateways::default(),
                static_bypass: Vec::new(),
                dynamic_bypass_v4: Default::default(),
                dynamic_bypass_v6: Default::default(),
                split_routes: Vec::new(),
                server_route: None,
                dns_route: None,
                extra_routes: Vec::new(),
                wfp: None,
            }
        }

        #[test]
        fn permit_cidrs_excludes_the_local_dns_resolver() {
            let dns_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
            let guard = guard_with_dns(server, Some(dns_v4));
            let cidrs = guard.permit_cidrs();
            assert!(
                !cidrs.iter().any(|(ip, _)| *ip == dns_v4),
                "local DNS {dns_v4} must not have a global CIDR permit"
            );
            assert!(
                cidrs.contains(&(server, host_prefix(server))),
                "the server must stay reachable outside the tunnel"
            );
            // The resolver stays reachable for this executable only.
            assert_eq!(guard.local_dns_ips(), vec![dns_v4]);
        }

        #[test]
        fn local_dns_ips_skips_loopback_and_tunnel_addresses() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
            let loopback = guard_with_dns(server, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
            assert!(loopback.local_dns_ips().is_empty());
            assert!(
                !loopback
                    .permit_cidrs()
                    .iter()
                    .any(|(ip, _)| ip.is_loopback())
            );

            let v6_tun = IpAddr::V6(Ipv6Addr::new(0xfd00, 0xbe, 0xa, 0, 0, 0, 0, 1));
            let tun_dns = guard_with_dns(server, Some(v6_tun));
            assert!(tun_dns.local_dns_ips().is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        MAX_PERSISTED_ROUTES, PersistedWinRoute, format_routes_state, parse_routes_state,
        split_cidr,
    };

    fn samples() -> Vec<PersistedWinRoute> {
        vec![
            PersistedWinRoute {
                prefix: "203.0.113.10/32".to_owned(),
                next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface_luid: 0x0000_0000_0012_0001,
                interface_index: 7,
                metric: 5,
            },
            PersistedWinRoute {
                prefix: "198.51.100.0/24".to_owned(),
                next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                interface_luid: 0x0000_0000_0013_0001,
                interface_index: 9,
                metric: 1,
            },
            PersistedWinRoute {
                prefix: "2001:db8::1/128".to_owned(),
                next_hop: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                interface_luid: 0x0000_0000_0012_0002,
                interface_index: 11,
                metric: 5,
            },
        ]
    }

    #[test]
    fn routes_state_roundtrips_and_rejects_malformed_lines() {
        let routes = samples();
        let encoded = format_routes_state(&routes);
        let with_noise = format!(
            "{encoded}\n\
             bad line\n\
             1.2.3.4/32\t192.168.1.1\t5\t7\n\
             1.2.3.4/33\t192.168.1.1\t5\t7\t5\n\
             2001:db8::/32\t192.168.1.1\t5\t7\t5\n\
             1.2.3.4/32\t192.168.1.1\t0\t7\t5\n\
             1.2.3.4/32\t192.168.1.1\t5\t0\t5\n\
             1.2.3.4/32\t192.168.1.1\t5\t7\tnot-a-metric\n\
             1.2.3.4/32\t192.168.1.1\t5\t7\t5\textra\n"
        );
        assert_eq!(parse_routes_state(&with_noise), routes);
    }

    #[test]
    fn routes_state_is_bounded_in_both_directions() {
        let route = samples().remove(0);
        let line = format_routes_state(std::slice::from_ref(&route));
        let oversized = format_routes_state(&vec![route.clone(); MAX_PERSISTED_ROUTES + 10]);
        assert_eq!(oversized.lines().count(), MAX_PERSISTED_ROUTES);

        let text = line.repeat(MAX_PERSISTED_ROUTES + 10);
        assert_eq!(parse_routes_state(&text).len(), MAX_PERSISTED_ROUTES);
    }

    #[test]
    fn split_cidr_accepts_only_valid_prefixes() {
        assert_eq!(
            split_cidr("10.0.0.0/8"),
            Some((IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8))
        );
        assert_eq!(
            split_cidr("::/1"),
            Some((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1))
        );
        for bad in [
            "10.0.0.1",
            "10.0.0.1/33",
            "fe80::/129",
            "10.0.0.1/abc",
            "/32",
            "10.0.0.1/",
        ] {
            assert!(split_cidr(bad).is_none(), "{bad} must be rejected");
        }
    }
}
