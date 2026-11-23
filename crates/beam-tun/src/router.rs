//! Minimal packet routing policy for `beam-tun`.

use std::net::Ipv4Addr;

use crate::packet::{IP_PROTO_TCP, IP_PROTO_UDP, Ipv4PacketView, parse_udp};

/// Routing policy applied to packets arriving from the TUN interface.
#[derive(Clone, Debug)]
pub struct RoutePolicy {
    /// Emit immediate ICMP Port Unreachable for UDP/443 so browsers fall back
    /// to HTTP/2 instead of stalling on QUIC-over-TCP.
    pub reject_quic: bool,
    /// Drop packets destined for RFC 1918 / link-local / multicast / loopback
    /// addresses so they never enter the tunnel (the OS route table keeps LAN
    /// direct).
    pub drop_private_destinations: bool,
    /// Explicit IPv4 addresses excluded from tunneling (always includes the
    /// `beam` server IP to prevent routing loops).
    pub exclude_ips: Vec<Ipv4Addr>,
}

impl Default for RoutePolicy {
    fn default() -> Self {
        Self {
            reject_quic: true,
            drop_private_destinations: true,
            exclude_ips: Vec::new(),
        }
    }
}

/// Decision for one IPv4 packet read from the TUN device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    /// Forward through the TCP stack to `beam`.
    ProxyTcp,
    /// Forward through the XUDP NAT bridge to `beam`.
    ProxyUdp,
    /// Reply immediately with ICMP Port Unreachable (Type 3, Code 3).
    RejectIcmpUnreachable,
    /// Silently drop (unsupported protocol, excluded IP, or private address).
    Drop,
}

impl RoutePolicy {
    /// Classifies an IPv4 packet read from the TUN interface.
    pub fn classify(&self, pkt: &Ipv4PacketView<'_>) -> RouteDecision {
        if self.exclude_ips.contains(&pkt.dst_ip) {
            return RouteDecision::Drop;
        }
        if self.drop_private_destinations && is_non_global_ipv4(pkt.dst_ip) {
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

/// Returns `true` for loopback, RFC 1918 private, link-local, multicast,
/// broadcast, or unspecified IPv4 addresses.
pub fn is_non_global_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{build_ipv4_udp_packet, parse_ipv4};

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
        let ip = parse_ipv4(&pkt).expect("ip");
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
            policy.classify(&parse_ipv4(&dns).expect("ip")),
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
            policy.classify(&parse_ipv4(&lan).expect("ip")),
            RouteDecision::Drop
        );
    }
}
