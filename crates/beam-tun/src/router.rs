//! Minimal IPv4 + IPv6 packet routing policy for `beam-tun`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::packet::{IP_PROTO_TCP, IP_PROTO_UDP, IpPacketView, parse_udp};

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
    /// Drop packets destined for RFC 1918 / ULA / link-local / multicast /
    /// loopback addresses so they never enter the tunnel.
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

/// Returns `true` for loopback, private/ULA, link-local, multicast, broadcast,
/// or unspecified IP addresses.
pub fn is_non_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_global_ipv4(v4),
        IpAddr::V6(v6) => is_non_global_ipv6(v6),
    }
}

/// Returns `true` for non-global IPv4 addresses.
pub fn is_non_global_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
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
}
