//! Minimal IPv4 + IPv6 packet routing policy for `beam-tun`.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::packet::{IP_PROTO_TCP, IP_PROTO_UDP, IpPacketView, parse_udp};

/// IPv6 TUN subnet `fd00:be:a::/126` as a compile-time constant so the hot
/// paths never parse the CIDR string.
pub const TUN_V6_NET: IpNet = IpNet::V6 {
    net: 0xfd00_00be_000a_0000_0000_0000_0000_0000,
    mask: u128::MAX << 2,
};

/// Minimal zero-dependency IPv4/IPv6 CIDR network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpNet {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl IpNet {
    /// Parses an IPv4 or IPv6 CIDR string (e.g. `10.20.0.0/16`, `2001:db8::/32`).
    pub fn parse_cidr(raw: &str) -> Option<Self> {
        let (ip_str, prefix_str) = raw.trim().split_once('/')?;
        let ip: IpAddr = ip_str.parse().ok()?;
        let prefix: u8 = prefix_str.parse().ok()?;
        match ip {
            IpAddr::V4(v4) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Some(Self::V4 {
                    net: u32::from(v4) & mask,
                    mask,
                })
            }
            IpAddr::V6(v6) if prefix <= 128 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Some(Self::V6 {
                    net: u128::from(v6) & mask,
                    mask,
                })
            }
            _ => None,
        }
    }

    /// Returns `true` when `ip` falls inside this CIDR prefix.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (Self::V4 { net, mask }, IpAddr::V4(v4)) => (u32::from(v4) & mask) == net,
            (Self::V6 { net, mask }, IpAddr::V6(v6)) => (u128::from(v6) & mask) == net,
            _ => false,
        }
    }
}

/// Sorted, merged, disjoint IPv4/IPv6 prefix index for bypass CIDRs.
///
/// Overlapping prefixes are normalized into sorted disjoint inclusive
/// `(start, end)` ranges at construction time, so a lookup is one binary search
/// per address family instead of a linear scan over every configured CIDR.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BypassCidrs {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl BypassCidrs {
    /// Builds the index from raw CIDR prefixes.
    pub fn new(nets: &[IpNet]) -> Self {
        let mut v4: Vec<(u32, u32)> = Vec::new();
        let mut v6: Vec<(u128, u128)> = Vec::new();
        for net in nets {
            match *net {
                IpNet::V4 { net, mask } => {
                    let net = net & mask;
                    v4.push((net, net | !mask));
                }
                IpNet::V6 { net, mask } => {
                    let net = net & mask;
                    v6.push((net, net | !mask));
                }
            }
        }
        Self {
            v4: merge_ranges(v4),
            v6: merge_ranges(v6),
        }
    }

    /// Returns `true` when no CIDR is configured (the hot-path fast case).
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Number of indexed prefixes after normalization (both families).
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Returns `true` when `ip` is inside any indexed prefix.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let value = u32::from(v4);
                contains_range(&self.v4, value)
            }
            IpAddr::V6(v6) => {
                let value = u128::from(v6);
                contains_range(&self.v6, value)
            }
        }
    }
}

impl From<Vec<IpNet>> for BypassCidrs {
    fn from(nets: Vec<IpNet>) -> Self {
        Self::new(&nets)
    }
}

impl From<&[IpNet]> for BypassCidrs {
    fn from(nets: &[IpNet]) -> Self {
        Self::new(nets)
    }
}

/// Sorts and merges overlapping inclusive ranges into sorted disjoint ranges.
fn merge_ranges<T: Ord + Copy>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1 => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => out.push((start, end)),
        }
    }
    out
}

fn contains_range<T: Ord + Copy>(ranges: &[(T, T)], value: T) -> bool {
    let idx = ranges.partition_point(|(start, _)| *start <= value);
    idx > 0 && value <= ranges[idx - 1].1
}

/// Explicit IP exclusions (the `beam` server IP and user entries).
///
/// A short list is scanned inline (cheaper than hashing for the typical one or
/// two entries); longer lists switch to a `HashSet`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExcludeIps {
    list: Vec<IpAddr>,
    set: Option<HashSet<IpAddr>>,
}

impl ExcludeIps {
    const HASH_THRESHOLD: usize = 8;

    /// Builds the exclusion set from raw entries.
    pub fn new(entries: &[IpAddr]) -> Self {
        Self {
            list: entries.to_vec(),
            set: (entries.len() > Self::HASH_THRESHOLD).then(|| entries.iter().copied().collect()),
        }
    }

    /// Returns `true` when `ip` is explicitly excluded.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match self.set.as_ref() {
            Some(set) => set.contains(&ip),
            None => self.list.contains(&ip),
        }
    }

    /// Number of excluded entries.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Replaces excluded address `old` with `new` in place, keeping the inline
    /// scan and the hash set consistent.
    ///
    /// Used on a server-IP handover so the new upstream endpoint is never routed
    /// back into the tunnel. A `new` that is already excluded only drops `old`,
    /// avoiding duplicate entries from repeated handovers.
    pub fn replace(&mut self, old: IpAddr, new: IpAddr) {
        if old == new {
            return;
        }
        if self.list.contains(&new) {
            self.list.retain(|ip| *ip != old);
        } else if let Some(slot) = self.list.iter_mut().find(|ip| **ip == old) {
            *slot = new;
        } else {
            self.list.push(new);
        }
        self.set =
            (self.list.len() > Self::HASH_THRESHOLD).then(|| self.list.iter().copied().collect());
    }

    /// Returns `true` when nothing is excluded.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

impl From<Vec<IpAddr>> for ExcludeIps {
    fn from(entries: Vec<IpAddr>) -> Self {
        Self::new(&entries)
    }
}

/// Routing policy applied to packets arriving from the TUN interface.
#[derive(Clone, Debug)]
pub struct RoutePolicy {
    /// Emit immediate ICMP/ICMPv6 Port Unreachable for UDP/443 so browsers
    /// fall back to HTTP/2 instead of stalling on QUIC-over-TCP.
    pub reject_quic: bool,
    /// Immediately reject IPv6 traffic (`TCP RST` for TCP, ICMPv6 Port
    /// Unreachable for UDP) while keeping IPv6 TUN split routes active to
    /// prevent leaks on IPv4-only upstream servers.
    pub reject_ipv6: bool,
    /// Drop packets destined for non-global addresses (RFC 1918, CGNAT,
    /// documentation/benchmarking/reserved IPv4 ranges, ULA, link-local,
    /// multicast, loopback) so they never enter the tunnel.
    pub drop_private_destinations: bool,
    /// Explicit IP addresses excluded from tunneling (always includes the
    /// `beam` server IP to prevent routing loops).
    pub exclude_ips: ExcludeIps,
    /// Explicit user-configured CIDR prefixes excluded from tunneling,
    /// pre-indexed for O(log N) lookup.
    pub bypass_cidrs: BypassCidrs,
    /// Intercept UDP/53 packets in the built-in DNS resolver (including
    /// queries addressed to private/TUN DNS IPs).
    pub intercept_dns: bool,
}

impl Default for RoutePolicy {
    fn default() -> Self {
        Self {
            reject_quic: true,
            reject_ipv6: false,
            drop_private_destinations: true,
            exclude_ips: ExcludeIps::default(),
            bypass_cidrs: BypassCidrs::default(),
            intercept_dns: false,
        }
    }
}

/// Decision for one IP packet read from the TUN interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    /// Forward through the TCP stack to `beam`.
    ProxyTcp,
    /// Forward through the XUDP NAT bridge to `beam`.
    ProxyUdp,
    /// Intercept UDP/53 in the built-in DNS resolver (DoH / plain / local split).
    InterceptDns,
    /// Reply immediately with a TCP `RST` (or `RST|ACK`) so Happy Eyeballs
    /// fails over without waiting for an upstream dial.
    RejectTcpRst,
    /// Reply immediately with ICMP/ICMPv6 Port Unreachable.
    RejectIcmpUnreachable,
    /// Silently drop (unsupported protocol, excluded IP, or private address).
    Drop,
}

impl RoutePolicy {
    /// Classifies an IPv4 or IPv6 packet read from the TUN interface.
    pub fn classify(&self, pkt: &IpPacketView<'_>) -> RouteDecision {
        let dst_ip = normalize_destination(pkt.dst_ip);
        if self.exclude_ips.contains(dst_ip) {
            return RouteDecision::Drop;
        }
        let udp = if pkt.protocol == IP_PROTO_UDP {
            parse_udp(pkt.payload)
        } else {
            None
        };
        if self.intercept_dns
            && let Some(ref udp) = udp
            && udp.dst_port == 53
        {
            return RouteDecision::InterceptDns;
        }
        if !self.bypass_cidrs.is_empty() && self.bypass_cidrs.contains(dst_ip) {
            return RouteDecision::Drop;
        }
        if self.drop_private_destinations && is_non_global_ip(dst_ip) {
            return RouteDecision::Drop;
        }
        if self.reject_ipv6 && pkt.dst_ip.is_ipv6() {
            return match pkt.protocol {
                IP_PROTO_TCP => RouteDecision::RejectTcpRst,
                IP_PROTO_UDP => RouteDecision::RejectIcmpUnreachable,
                _ => RouteDecision::Drop,
            };
        }

        match pkt.protocol {
            IP_PROTO_TCP => RouteDecision::ProxyTcp,
            IP_PROTO_UDP => {
                if let Some(udp) = udp {
                    if self.reject_quic && udp.dst_port == 443 {
                        return RouteDecision::RejectIcmpUnreachable;
                    }
                    if udp.dst_port == 0 {
                        return RouteDecision::Drop;
                    }
                    RouteDecision::ProxyUdp
                } else {
                    RouteDecision::Drop
                }
            }
            _ => RouteDecision::Drop,
        }
    }
}

/// Applies IPv4 policy to IPv4-mapped and RFC 4291 IPv4-compatible
/// destinations. `::1` and `::` are excluded: a blind `to_ipv4()` would turn
/// loopback into `0.0.0.1`.
fn normalize_destination(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else {
        return ip;
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }
    let octets = v6.octets();
    if !v6.is_loopback() && !v6.is_unspecified() && octets[..12].iter().all(|&b| b == 0) {
        return IpAddr::V4(Ipv4Addr::from([
            octets[12], octets[13], octets[14], octets[15],
        ]));
    }
    ip
}

/// Returns `true` for loopback, private/ULA, CGNAT, special-purpose,
/// link-local, multicast, broadcast, or unspecified IP addresses.
pub fn is_non_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_global_ipv4(v4),
        IpAddr::V6(v6) => is_non_global_ipv6(v6),
    }
}

/// Returns `true` for non-global IPv4 addresses (RFC 6890 special-purpose
/// ranges included).
pub fn is_non_global_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    // 192.0.0.9/32 (PCP anycast) and 192.0.0.10/32 (TURN anycast) are globally
    // reachable exceptions inside 192.0.0.0/24 (RFC 6890 / RFC 7723 / RFC 8155).
    if a == 192 && b == 0 && c == 0 && (d == 9 || d == 10) {
        return false;
    }
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        // 0.0.0.0/8 "this network" (RFC 1122 / RFC 6890, subsumes 0.0.0.0)
        || a == 0
        // 100.64.0.0/10 carrier-grade NAT (RFC 6598)
        || (a == 100 && (64..=127).contains(&b))
        // 192.0.0.0/24 IETF protocol assignments (RFC 6890, except .9/.10 above)
        || (a == 192 && b == 0 && c == 0)
        // 192.88.99.0/24 deprecated 6to4 relay anycast (RFC 7526)
        || (a == 192 && b == 88 && c == 99)
        // 198.18.0.0/15 benchmarking (RFC 2544)
        || (a == 198 && (18..=19).contains(&b))
        // 240.0.0.0/4 reserved for future use (RFC 1112)
        || a >= 240
        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 documentation (RFC 5737)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
}

/// Returns `true` for non-global IPv6 addresses.
pub fn is_non_global_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{build_ipv4_udp_packet, parse_ip};

    #[test]
    fn rejects_quic_udp_443_when_enabled() {
        let policy = RoutePolicy::default();
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            55555,
            Ipv4Addr::new(1, 1, 1, 1),
            443,
            b"quic",
        )
        .expect("udp");
        let ip = parse_ip(&pkt).expect("ip");
        assert_eq!(policy.classify(&ip), RouteDecision::RejectIcmpUnreachable);
    }

    #[test]
    fn allows_dns_udp_53_and_drops_private_lan() {
        let policy = RoutePolicy::default();
        let dns = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            55555,
            Ipv4Addr::new(1, 1, 1, 1),
            53,
            b"dns",
        )
        .expect("udp");
        assert_eq!(
            policy.classify(&parse_ip(&dns).expect("ip")),
            RouteDecision::ProxyUdp
        );

        let lan = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            55555,
            Ipv4Addr::new(192, 168, 1, 1),
            53,
            b"lan",
        )
        .expect("udp");
        assert_eq!(
            policy.classify(&parse_ip(&lan).expect("ip")),
            RouteDecision::Drop
        );
    }

    #[test]
    fn bypass_cidrs_and_dns_interception_work() {
        let net4 = IpNet::parse_cidr("198.51.100.0/24").expect("v4 cidr");
        assert!(net4.contains(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))));
        assert!(!net4.contains(IpAddr::V4(Ipv4Addr::new(198, 51, 101, 1))));
        let net6 = IpNet::parse_cidr("2001:db8::/32").expect("v6 cidr");
        assert!(net6.contains(IpAddr::V6("2001:db8::1".parse().expect("v6"))));
        assert!(IpNet::parse_cidr("1.2.3.4/33").is_none());

        let policy = RoutePolicy {
            reject_quic: true,
            reject_ipv6: false,
            drop_private_destinations: true,
            exclude_ips: ExcludeIps::default(),
            bypass_cidrs: BypassCidrs::from(vec![net4]),
            intercept_dns: true,
        };
        let bypassed = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            55555,
            Ipv4Addr::new(198, 51, 100, 10),
            9999,
            b"x",
        )
        .expect("udp");
        assert_eq!(
            policy.classify(&parse_ip(&bypassed).expect("ip")),
            RouteDecision::Drop
        );

        let dns_priv = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            55555,
            Ipv4Addr::new(172, 19, 0, 2),
            53,
            b"q",
        )
        .expect("udp");
        assert_eq!(
            policy.classify(&parse_ip(&dns_priv).expect("ip")),
            RouteDecision::InterceptDns
        );
    }

    #[test]
    fn drop_private_toggle_routes_lan_through_tunnel_or_drops() {
        use crate::packet::TCP_SYN;

        let lan_v4 = Ipv4Addr::new(192, 168, 1, 10);
        let pub_v4 = Ipv4Addr::new(1, 1, 1, 1);
        let src_v4 = Ipv4Addr::new(172, 19, 0, 1);
        let ula_v6: Ipv6Addr = "fd00::42".parse().expect("ula");
        let pub_v6: Ipv6Addr = "2606:4700:4700::1111".parse().expect("global v6");
        let src_v6: Ipv6Addr = "fd00:be:a::1".parse().expect("tun v6");

        for drop_private in [true, false] {
            let policy = RoutePolicy {
                drop_private_destinations: drop_private,
                ..RoutePolicy::default()
            };
            // Public traffic always tunnels in both modes.
            let pub_udp =
                build_ipv4_udp_packet(src_v4, 40000, pub_v4, 8080, b"x").expect("public udp");
            assert_eq!(
                policy.classify(&parse_ip(&pub_udp).expect("ip")),
                RouteDecision::ProxyUdp,
                "public UDP must tunnel with drop_private={drop_private}"
            );
            let pub_tcp = crate::packet::build_ip_tcp_packet_slices(
                IpAddr::V4(src_v4),
                40001,
                IpAddr::V4(pub_v4),
                8080,
                100,
                0,
                TCP_SYN,
                65535,
                &[],
                &[],
                &[],
            )
            .expect("public tcp");
            assert_eq!(
                policy.classify(&parse_ip(&pub_tcp).expect("ip")),
                RouteDecision::ProxyTcp,
                "public TCP must tunnel with drop_private={drop_private}"
            );

            // Private/LAN traffic drops by default but tunnels when opted out.
            let lan_udp =
                build_ipv4_udp_packet(src_v4, 40002, lan_v4, 8080, b"x").expect("lan udp");
            let lan_tcp = crate::packet::build_ip_tcp_packet_slices(
                IpAddr::V4(src_v4),
                40003,
                IpAddr::V4(lan_v4),
                8080,
                100,
                0,
                TCP_SYN,
                65535,
                &[],
                &[],
                &[],
            )
            .expect("lan tcp");
            let ula_udp = crate::packet::build_ip_udp_packet(
                IpAddr::V6(src_v6),
                40004,
                IpAddr::V6(ula_v6),
                8080,
                b"x",
            )
            .expect("ula udp");
            let expected = if drop_private {
                RouteDecision::Drop
            } else {
                RouteDecision::ProxyUdp
            };
            assert_eq!(
                policy.classify(&parse_ip(&lan_udp).expect("ip")),
                expected,
                "LAN UDP with drop_private={drop_private}"
            );
            assert_eq!(
                policy.classify(&parse_ip(&lan_tcp).expect("ip")),
                if drop_private {
                    RouteDecision::Drop
                } else {
                    RouteDecision::ProxyTcp
                },
                "LAN TCP with drop_private={drop_private}"
            );
            assert_eq!(
                policy.classify(&parse_ip(&ula_udp).expect("ip")),
                expected,
                "ULA UDP with drop_private={drop_private}"
            );

            // The global IPv6 twin of the ULA case is unaffected by the toggle.
            let pub_udp6 = crate::packet::build_ip_udp_packet(
                IpAddr::V6(src_v6),
                40005,
                IpAddr::V6(pub_v6),
                8080,
                b"x",
            )
            .expect("public udp6");
            assert_eq!(
                policy.classify(&parse_ip(&pub_udp6).expect("ip")),
                RouteDecision::ProxyUdp,
                "global IPv6 UDP must tunnel with drop_private={drop_private}"
            );
        }
    }

    #[test]
    fn reject_ipv6_emits_rst_for_tcp_and_icmp_for_udp() {
        let policy = RoutePolicy {
            reject_ipv6: true,
            ..RoutePolicy::default()
        };
        let src6 = IpAddr::V6("fd00:be:a::1".parse().expect("v6"));
        let dst6 = IpAddr::V6("2001:4860:4860::8888".parse().expect("v6"));
        let syn = crate::packet::build_ip_tcp_packet_slices(
            src6,
            40000,
            dst6,
            443,
            100,
            0,
            crate::packet::TCP_SYN,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("tcp v6");
        assert_eq!(
            policy.classify(&parse_ip(&syn).expect("ip")),
            RouteDecision::RejectTcpRst
        );
        let udp = crate::packet::build_ip_udp_packet(src6, 40001, dst6, 5353, b"x").expect("udp6");
        assert_eq!(
            policy.classify(&parse_ip(&udp).expect("ip")),
            RouteDecision::RejectIcmpUnreachable
        );
    }

    #[test]
    fn ipv4_compatible_and_mapped_destinations_follow_ipv4_policy() {
        let src6: IpAddr = "fd00:be:a::1".parse().expect("tun v6");
        let compatible_private: IpAddr = "::192.168.1.1".parse().expect("compatible private");
        let mapped_private: IpAddr = "::ffff:192.168.1.1".parse().expect("mapped private");
        let loopback: IpAddr = "::1".parse().expect("loopback");
        let default = RoutePolicy::default();

        for dst in [compatible_private, mapped_private, loopback] {
            let pkt =
                crate::packet::build_ip_udp_packet(src6, 40000, dst, 8080, b"x").expect("ipv6 udp");
            assert_eq!(
                default.classify(&parse_ip(&pkt).expect("ip")),
                RouteDecision::Drop,
                "{dst} must follow the private/loopback policy"
            );
        }

        let bypassed = IpNet::parse_cidr("1.1.1.0/24").expect("bypass cidr");
        let policy = RoutePolicy {
            drop_private_destinations: false,
            bypass_cidrs: BypassCidrs::from(vec![bypassed]),
            ..RoutePolicy::default()
        };
        for dst in [
            "::1.1.1.1".parse::<IpAddr>().expect("compatible bypass"),
            "::ffff:1.1.1.1".parse::<IpAddr>().expect("mapped bypass"),
        ] {
            let pkt =
                crate::packet::build_ip_udp_packet(src6, 40001, dst, 8080, b"x").expect("ipv6 udp");
            assert_eq!(
                policy.classify(&parse_ip(&pkt).expect("ip")),
                RouteDecision::Drop,
                "{dst} must match the IPv4 bypass CIDR"
            );
        }
        for dst in [
            "::8.8.8.8".parse::<IpAddr>().expect("compatible public"),
            "::ffff:8.8.8.8".parse::<IpAddr>().expect("mapped public"),
            "2001:4860:4860::8888".parse::<IpAddr>().expect("global v6"),
        ] {
            let pkt =
                crate::packet::build_ip_udp_packet(src6, 40002, dst, 8080, b"x").expect("ipv6 udp");
            assert_eq!(
                policy.classify(&parse_ip(&pkt).expect("ip")),
                RouteDecision::ProxyUdp,
                "{dst} must still tunnel"
            );
        }
    }

    #[test]
    fn non_global_ipv4_covers_documented_special_purpose_ranges() {
        for raw in [
            "0.0.0.0",         // unspecified
            "0.1.2.3",         // 0.0.0.0/8 "this network"
            "100.64.0.1",      // CGNAT start
            "100.127.255.255", // CGNAT end
            "192.0.0.8",       // IETF protocol assignments
            "192.88.99.1",     // deprecated 6to4 relay anycast
            "198.18.0.1",      // benchmarking start
            "198.19.255.255",  // benchmarking end
            "240.0.0.1",       // reserved for future use
            "255.255.255.254", // reserved, below broadcast
            "192.0.2.5",       // TEST-NET-1
            "198.51.100.7",    // TEST-NET-2
            "203.0.113.9",     // TEST-NET-3
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
        ] {
            let ip: Ipv4Addr = raw.parse().expect("ipv4");
            assert!(is_non_global_ipv4(ip), "{raw} must be non-global");
        }

        for raw in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "9.9.9.9",
            "192.0.0.9",
            "192.0.0.10",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
        ] {
            let ip: Ipv4Addr = raw.parse().expect("ipv4");
            assert!(!is_non_global_ipv4(ip), "{raw} must stay global");
        }
    }

    #[test]
    fn indexed_bypass_cidrs_match_a_linear_scan() {
        let mut nets = Vec::new();
        for cidr in [
            "10.0.0.0/8",
            "10.1.0.0/16",
            "10.1.2.0/24",
            "0.0.0.0/1",
            "100.64.0.0/10",
            "192.168.0.0/16",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "1.1.1.1/32",
            "172.16.0.0/12",
            "128.0.0.0/2",
            "2001:db8::/32",
            "2001:db8:1::/48",
            "fd00::/8",
            "2606:4700::/32",
            "::1/128",
            "fe80::/10",
        ] {
            nets.push(IpNet::parse_cidr(cidr).expect("cidr"));
        }
        let index = BypassCidrs::new(&nets);
        assert!(!index.is_empty());
        assert!(
            index.len() <= nets.len(),
            "overlapping prefixes must be merged, not duplicated"
        );

        let mut samples = Vec::new();
        for raw in [
            "0.0.0.0",
            "1.1.1.1",
            "1.1.1.2",
            "9.255.255.255",
            "10.0.0.1",
            "10.1.0.1",
            "10.1.2.3",
            "10.2.3.4",
            "100.64.0.1",
            "100.128.0.1",
            "128.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "198.51.100.42",
            "203.0.113.9",
            "223.255.255.255",
            "255.255.255.255",
        ] {
            samples.push(IpAddr::V4(raw.parse().expect("v4")));
        }
        for raw in [
            "::1",
            "::2",
            "2001:db8::1",
            "2001:db8:1::1",
            "2001:db8:2::1",
            "2606:4700::1111",
            "fd00::1",
            "fe80::1",
            "2600::1",
        ] {
            samples.push(IpAddr::V6(raw.parse().expect("v6")));
        }

        for ip in samples {
            let expected = nets.iter().any(|net| net.contains(ip));
            assert_eq!(index.contains(ip), expected, "mismatch for {ip}");
        }

        // A zero prefix matches every address of its family.
        assert!(
            IpNet::parse_cidr("0.0.0.0/0")
                .expect("v4 /0")
                .contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))
        );
        assert!(
            !IpNet::parse_cidr("0.0.0.0/0")
                .expect("v4 /0")
                .contains(IpAddr::V6("2001:db8::1".parse().expect("v6")))
        );
        let default_v4 = BypassCidrs::new(&[IpNet::parse_cidr("0.0.0.0/0").expect("v4 /0")]);
        assert!(default_v4.contains(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
        assert!(default_v4.contains(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        let default_v6 = BypassCidrs::new(&[IpNet::parse_cidr("::/0").expect("v6 /0")]);
        assert!(default_v6.contains(IpAddr::V6(Ipv6Addr::from([0xff; 16]))));
        assert!(!default_v6.contains(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));

        // A raw (unmasked) network value is normalized at construction time.
        let unmasked = BypassCidrs::new(&[
            IpNet::V4 {
                net: u32::from(Ipv4Addr::new(10, 1, 2, 3)),
                mask: 0xffff_0000,
            },
            IpNet::V6 {
                net: u128::from("2001:db8:1234::5".parse::<Ipv6Addr>().expect("v6")),
                mask: u128::MAX << 96,
            },
        ]);
        assert!(unmasked.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 200, 200))));
        assert!(!unmasked.contains(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))));
        assert!(unmasked.contains(IpAddr::V6("2001:db8:ffff::1".parse().expect("v6"))));
        assert!(!unmasked.contains(IpAddr::V6("2001:db9::1".parse().expect("v6"))));

        // The empty index is the hot-path fast case.
        let empty = BypassCidrs::default();
        assert!(empty.is_empty());
        assert!(!empty.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn exclude_ips_matches_across_the_inline_and_hashed_paths() {
        let few: Vec<IpAddr> = vec![
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            IpAddr::V6("2001:db8::10".parse().expect("v6")),
        ];
        let many: Vec<IpAddr> = (1..=16)
            .map(|i| IpAddr::V4(Ipv4Addr::new(198, 18, 0, i)))
            .collect();

        for entries in [few, many] {
            let index = ExcludeIps::new(&entries);
            assert_eq!(index.len(), entries.len());
            for ip in &entries {
                assert!(index.contains(*ip), "{ip} must be excluded");
            }
            for ip in [
                IpAddr::V4(Ipv4Addr::new(198, 18, 1, 1)),
                IpAddr::V6("2001:db8::11".parse().expect("v6")),
            ] {
                if !entries.contains(&ip) {
                    assert!(!index.contains(ip), "{ip} must not be excluded");
                }
            }
        }
        assert!(ExcludeIps::default().is_empty());
    }

    #[test]
    fn exclude_ips_switches_to_a_hash_set_above_eight_entries() {
        let entries: Vec<IpAddr> = (1..=9)
            .map(|i| IpAddr::V4(Ipv4Addr::new(198, 18, 0, i)))
            .collect();

        // Eight entries stay on the inline scan; the ninth switches to hashing.
        let inline = ExcludeIps::new(&entries[..8]);
        assert!(
            inline.set.is_none(),
            "eight entries must use the inline scan"
        );
        assert!(inline.contains(entries[7]));
        assert!(!inline.contains(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))));

        let hashed = ExcludeIps::new(&entries);
        assert!(hashed.set.is_some(), "nine entries must use the hash set");
        for ip in &entries {
            assert!(hashed.contains(*ip), "{ip} must be excluded");
        }
        assert!(!hashed.contains(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 10))));
        assert_eq!(hashed.len(), 9);
    }

    #[test]
    fn exclude_ips_replace_swaps_a_server_ip_in_the_inline_list() {
        let old = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let new = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let mut exclusions = ExcludeIps::new(&[old]);

        exclusions.replace(old, new);

        assert!(!exclusions.contains(old));
        assert!(exclusions.contains(new));
        assert_eq!(exclusions.len(), 1);
    }

    #[test]
    fn exclude_ips_replace_keeps_the_hash_set_consistent_above_the_threshold() {
        let entries: Vec<IpAddr> = (1..=9)
            .map(|i| IpAddr::V4(Ipv4Addr::new(198, 18, 0, i)))
            .collect();
        let old = entries[3];
        let new = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 99));
        let mut exclusions = ExcludeIps::new(&entries);
        assert!(exclusions.set.is_some(), "nine entries use the hash set");

        exclusions.replace(old, new);

        assert!(exclusions.set.is_some(), "the list size did not change");
        assert_eq!(exclusions.len(), 9);
        assert!(!exclusions.contains(old));
        assert!(exclusions.contains(new));
    }

    #[test]
    fn exclude_ips_replace_drops_a_duplicate_and_falls_back_below_the_threshold() {
        let entries: Vec<IpAddr> = (1..=9)
            .map(|i| IpAddr::V4(Ipv4Addr::new(198, 18, 0, i)))
            .collect();
        let old = entries[3];
        // `new` is already excluded, so only `old` is removed: the list shrinks
        // to eight entries and must fall back to the inline scan.
        let new = entries[5];
        let mut exclusions = ExcludeIps::new(&entries);
        assert!(exclusions.set.is_some(), "nine entries use the hash set");

        exclusions.replace(old, new);

        assert_eq!(exclusions.len(), 8);
        assert!(
            exclusions.set.is_none(),
            "eight entries use the inline scan"
        );
        assert!(!exclusions.contains(old));
        assert!(exclusions.contains(new));
    }

    #[test]
    fn exclude_ips_replace_adds_an_absent_entry_only_once() {
        let present = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let absent = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        let new = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let mut exclusions = ExcludeIps::new(&[present]);

        exclusions.replace(absent, new);
        assert_eq!(exclusions.len(), 2);
        assert!(exclusions.contains(present));
        assert!(exclusions.contains(new));

        // A repeated handover to the same address must not duplicate it.
        exclusions.replace(new, new);
        assert_eq!(exclusions.len(), 2);
        assert!(exclusions.contains(new));
    }

    #[test]
    fn dns_interception_wins_over_a_bypass_cidr_for_udp_53() {
        let policy = RoutePolicy {
            bypass_cidrs: BypassCidrs::from(vec![IpNet::parse_cidr("1.1.1.0/24").expect("cidr")]),
            intercept_dns: true,
            ..RoutePolicy::default()
        };
        let dns = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            55555,
            Ipv4Addr::new(1, 1, 1, 1),
            53,
            b"q",
        )
        .expect("udp");
        assert_eq!(
            policy.classify(&parse_ip(&dns).expect("ip")),
            RouteDecision::InterceptDns
        );

        // The same bypass CIDR still drops non-DNS traffic.
        let other = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            55555,
            Ipv4Addr::new(1, 1, 1, 1),
            853,
            b"q",
        )
        .expect("udp");
        assert_eq!(
            policy.classify(&parse_ip(&other).expect("ip")),
            RouteDecision::Drop
        );
    }

    #[test]
    fn tun_v6_net_constant_matches_the_documented_cidr() {
        let parsed = IpNet::parse_cidr("fd00:be:a::/126").expect("tun v6 cidr");
        assert_eq!(parsed, TUN_V6_NET);
        assert!(TUN_V6_NET.contains(IpAddr::V6("fd00:be:a::1".parse().expect("v6"))));
        assert!(TUN_V6_NET.contains(IpAddr::V6("fd00:be:a::3".parse().expect("v6"))));
        assert!(!TUN_V6_NET.contains(IpAddr::V6("fd00:be:a::4".parse().expect("v6"))));
        assert!(!TUN_V6_NET.contains(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1))));
    }
}
