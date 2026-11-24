//! Minimal IPv4 + IPv6 packet routing policy for `beam-tun`.

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
    pub exclude_ips: Vec<IpAddr>,
    /// Explicit user-configured CIDR prefixes excluded from tunneling.
    pub bypass_cidrs: Vec<IpNet>,
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
            exclude_ips: Vec::new(),
            bypass_cidrs: Vec::new(),
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
        if self.exclude_ips.contains(&pkt.dst_ip) {
            return RouteDecision::Drop;
        }
        if self.intercept_dns
            && pkt.protocol == IP_PROTO_UDP
            && let Some(udp) = parse_udp(pkt.payload)
            && udp.dst_port == 53
        {
            return RouteDecision::InterceptDns;
        }
        if self.bypass_cidrs.iter().any(|net| net.contains(pkt.dst_ip)) {
            return RouteDecision::Drop;
        }
        if self.drop_private_destinations && is_non_global_ip(pkt.dst_ip) {
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
                if let Some(udp) = parse_udp(pkt.payload) {
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
    let [a, b, c, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
        // 100.64.0.0/10 carrier-grade NAT (RFC 6598)
        || (a == 100 && (64..=127).contains(&b))
        // 192.0.0.0/24 IETF protocol assignments (RFC 6890)
        || (a == 192 && b == 0 && c == 0)
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
            exclude_ips: Vec::new(),
            bypass_cidrs: vec![net4],
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
    fn non_global_ipv4_covers_every_special_purpose_range() {
        for raw in [
            "100.64.0.1",      // CGNAT start
            "100.127.255.255", // CGNAT end
            "192.0.0.8",       // IETF protocol assignments
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
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
        ] {
            let ip: Ipv4Addr = raw.parse().expect("ipv4");
            assert!(!is_non_global_ipv4(ip), "{raw} must stay global");
        }
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
