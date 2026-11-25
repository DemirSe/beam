//! Zero-panic IPv4, IPv6, TCP, UDP, ICMPv4, and ICMPv6 packet parsing and synthesis.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP protocol / next-header numbers.
pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;
pub const IP_PROTO_ICMPV6: u8 = 58;

/// IPv6 extension header next-header values (RFC 8200).
const IPV6_NEXT_HOP_BY_HOP: u8 = 0;
const IPV6_NEXT_ROUTING: u8 = 43;
const IPV6_NEXT_FRAGMENT: u8 = 44;
const IPV6_NEXT_DEST_OPTS: u8 = 60;
const MAX_IPV6_EXT_HEADERS: usize = 8;

/// Minimum IPv4 header length in bytes.
pub const IPV4_MIN_HEADER_LEN: usize = 20;
/// Fixed IPv6 header length in bytes.
pub const IPV6_HEADER_LEN: usize = 40;
/// UDP header length in bytes.
pub const UDP_HEADER_LEN: usize = 8;
/// Minimum TCP header length in bytes.
pub const TCP_MIN_HEADER_LEN: usize = 20;

/// TCP header flag constants.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// Parsed view of an IPv4 or IPv6 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacketView<'a> {
    /// IP header length in bytes (`20..=60` for IPv4, `>= 40` for IPv6 including extension headers).
    pub header_len: usize,
    /// Transport protocol (`IP_PROTO_TCP`, `IP_PROTO_UDP`, etc.).
    pub protocol: u8,
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Complete trimmed IP packet (`..total_len`).
    pub raw: &'a [u8],
    /// L4 payload slice (`header_len..total_len`).
    pub payload: &'a [u8],
}

/// Parsed view of an IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4PacketView<'a> {
    pub header_len: usize,
    pub protocol: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub raw: &'a [u8],
    pub payload: &'a [u8],
}

/// Parsed view of a UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacketView<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Parsed view of a TCP segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegmentView<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

/// Parses an IPv4 or IPv6 packet.
pub fn parse_ip(packet: &[u8]) -> Option<IpPacketView<'_>> {
    let first = *packet.first()?;
    match first >> 4 {
        4 => {
            let v4 = parse_ipv4(packet)?;
            Some(IpPacketView {
                header_len: v4.header_len,
                protocol: v4.protocol,
                src_ip: IpAddr::V4(v4.src_ip),
                dst_ip: IpAddr::V4(v4.dst_ip),
                raw: v4.raw,
                payload: v4.payload,
            })
        }
        6 => parse_ipv6(packet),
        _ => None,
    }
}

/// Returns `true` when `packet` is a fragmented IPv4 or IPv6 packet.
///
/// [`parse_ip`] rejects fragments instead of reassembling them; this helper only
/// classifies the drop reason for diagnostics and never panics on short input.
/// The IPv6 extension-header walk is bounded by the same
/// [`MAX_IPV6_EXT_HEADERS`] limit as [`parse_ipv6`].
///
/// [`parse_ip`]: crate::packet::parse_ip
pub fn is_fragment(packet: &[u8]) -> bool {
    match packet.first().map(|first| first >> 4) {
        Some(4) => {
            if packet.len() < IPV4_MIN_HEADER_LEN {
                return false;
            }
            let flags_frag = u16::from_be_bytes([packet[6], packet[7]]);
            (flags_frag & 0x3fff) != 0
        }
        Some(6) => {
            if packet.len() < IPV6_HEADER_LEN {
                return false;
            }
            let mut next = packet[6];
            let mut offset = IPV6_HEADER_LEN;
            for _ in 0..=MAX_IPV6_EXT_HEADERS {
                match next {
                    IPV6_NEXT_FRAGMENT => return true,
                    IPV6_NEXT_HOP_BY_HOP | IPV6_NEXT_ROUTING | IPV6_NEXT_DEST_OPTS => {
                        let Some(end) = offset.checked_add(2) else {
                            return false;
                        };
                        let Some(header) = packet.get(offset..end) else {
                            return false;
                        };
                        // Byte 0 is the next header, byte 1 the length in 8-byte units.
                        next = header[0];
                        let header_len = (usize::from(header[1]) + 1) * 8;
                        offset = match offset.checked_add(header_len) {
                            Some(next_offset) => next_offset,
                            None => return false,
                        };
                    }
                    _ => return false,
                }
            }
            false
        }
        _ => false,
    }
}

/// Parses an IPv4 packet, rejecting truncated, non-IPv4, or fragmented packets.
pub fn parse_ipv4(packet: &[u8]) -> Option<Ipv4PacketView<'_>> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }
    if (packet[0] >> 4) != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || ihl > packet.len() {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl || total_len > packet.len() {
        return None;
    }
    // Reject fragmented IPv4 packets (MF flag or non-zero fragment offset).
    let flags_frag = u16::from_be_bytes([packet[6], packet[7]]);
    if (flags_frag & 0x3fff) != 0 {
        return None;
    }

    let protocol = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let raw = &packet[..total_len];
    let payload = &raw[ihl..total_len];

    Some(Ipv4PacketView {
        header_len: ihl,
        protocol,
        src_ip,
        dst_ip,
        raw,
        payload,
    })
}

/// Parses an IPv6 packet, walking standard extension headers (Hop-by-Hop,
/// Routing, Destination Options) and rejecting fragmented or malformed packets.
pub fn parse_ipv6(packet: &[u8]) -> Option<IpPacketView<'_>> {
    if packet.len() < IPV6_HEADER_LEN {
        return None;
    }
    if (packet[0] >> 4) != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN.checked_add(payload_len)?;
    if total_len > packet.len() {
        return None;
    }
    let src_bytes: [u8; 16] = packet[8..24].try_into().ok()?;
    let dst_bytes: [u8; 16] = packet[24..40].try_into().ok()?;
    let raw = &packet[..total_len];

    let mut protocol = packet[6];
    let mut offset = IPV6_HEADER_LEN;
    let mut ext_hops = 0usize;
    loop {
        match protocol {
            IPV6_NEXT_HOP_BY_HOP | IPV6_NEXT_ROUTING | IPV6_NEXT_DEST_OPTS => {
                if ext_hops >= MAX_IPV6_EXT_HEADERS {
                    return None;
                }
                let prefix_end = offset.checked_add(2)?;
                if prefix_end > total_len {
                    return None;
                }
                let next_header = raw[offset];
                let ext_len = usize::from(raw[offset + 1])
                    .checked_add(1)?
                    .checked_mul(8)?;
                offset = offset.checked_add(ext_len)?;
                if offset > total_len {
                    return None;
                }
                protocol = next_header;
                ext_hops += 1;
            }
            IPV6_NEXT_FRAGMENT => return None,
            _ => break,
        }
    }

    Some(IpPacketView {
        header_len: offset,
        protocol,
        src_ip: IpAddr::V6(Ipv6Addr::from(src_bytes)),
        dst_ip: IpAddr::V6(Ipv6Addr::from(dst_bytes)),
        raw,
        payload: &raw[offset..total_len],
    })
}

/// Parses a UDP datagram from an IP payload slice.
pub fn parse_udp(payload: &[u8]) -> Option<UdpPacketView<'_>> {
    if payload.len() < UDP_HEADER_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let udp_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    if udp_len < UDP_HEADER_LEN || udp_len > payload.len() {
        return None;
    }
    Some(UdpPacketView {
        src_port,
        dst_port,
        payload: &payload[UDP_HEADER_LEN..udp_len],
    })
}

/// Parses a TCP segment from an IP payload slice.
pub fn parse_tcp(payload: &[u8]) -> Option<TcpSegmentView<'_>> {
    if payload.len() < TCP_MIN_HEADER_LEN {
        return None;
    }
    let data_offset = usize::from(payload[12] >> 4) * 4;
    if data_offset < TCP_MIN_HEADER_LEN || data_offset > payload.len() {
        return None;
    }
    Some(TcpSegmentView {
        src_port: u16::from_be_bytes([payload[0], payload[1]]),
        dst_port: u16::from_be_bytes([payload[2], payload[3]]),
        seq: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        ack: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
        flags: payload[13],
        window: u16::from_be_bytes([payload[14], payload[15]]),
        options: &payload[TCP_MIN_HEADER_LEN..data_offset],
        payload: &payload[data_offset..],
    })
}

/// Parses MSS and RFC 7323 Window Scale from TCP SYN options.
pub fn parse_tcp_syn_options(options: &[u8]) -> (Option<u16>, Option<u8>) {
    let mut mss = None;
    let mut wscale = None;
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            0 => break,
            1 => i += 1,
            kind => {
                if i + 1 >= options.len() {
                    break;
                }
                let len = usize::from(options[i + 1]);
                if len < 2 || i + len > options.len() {
                    break;
                }
                if kind == 2 && len == 4 {
                    mss = Some(u16::from_be_bytes([options[i + 2], options[i + 3]]));
                } else if kind == 3 && len == 3 {
                    wscale = Some(options[i + 2].min(14));
                }
                i += len;
            }
        }
    }
    (mss, wscale)
}

/// Builds a complete IPv4 or IPv6 TCP packet directly from two payload slices
/// (e.g. `VecDeque::as_slices()`), avoiding intermediate payload allocations.
#[allow(clippy::too_many_arguments)]
pub fn build_ip_tcp_packet_slices(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload_a: &[u8],
    payload_b: &[u8],
) -> Option<Vec<u8>> {
    if options.len() > 40 || !options.len().is_multiple_of(4) {
        return None;
    }
    let tcp_header_len = TCP_MIN_HEADER_LEN + options.len();
    let payload_len = payload_a.len().checked_add(payload_b.len())?;
    let tcp_len = tcp_header_len.checked_add(payload_len)?;

    match (src_ip, dst_ip) {
        (IpAddr::V4(s4), IpAddr::V4(d4)) => {
            let total_len = IPV4_MIN_HEADER_LEN.checked_add(tcp_len)?;
            let total_len_u16 = u16::try_from(total_len).ok()?;
            let mut pkt = vec![0u8; total_len];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
            pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
            pkt[8] = 64;
            pkt[9] = IP_PROTO_TCP;
            pkt[12..16].copy_from_slice(&s4.octets());
            pkt[16..20].copy_from_slice(&d4.octets());
            let ip_cksum = internet_checksum(&pkt[..IPV4_MIN_HEADER_LEN]);
            pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

            let tcp = &mut pkt[IPV4_MIN_HEADER_LEN..];
            write_tcp_segment(
                tcp, src_port, dst_port, seq, ack, flags, window, options, payload_a, payload_b,
            );
            let tcp_cksum = l4_ipv4_checksum(s4, d4, IP_PROTO_TCP, tcp);
            tcp[16..18].copy_from_slice(&tcp_cksum.to_be_bytes());
            Some(pkt)
        }
        (IpAddr::V6(s6), IpAddr::V6(d6)) => {
            let tcp_len_u16 = u16::try_from(tcp_len).ok()?;
            let total_len = IPV6_HEADER_LEN.checked_add(tcp_len)?;
            let mut pkt = vec![0u8; total_len];
            pkt[0] = 0x60; // version 6
            pkt[4..6].copy_from_slice(&tcp_len_u16.to_be_bytes());
            pkt[6] = IP_PROTO_TCP;
            pkt[7] = 64; // hop limit
            pkt[8..24].copy_from_slice(&s6.octets());
            pkt[24..40].copy_from_slice(&d6.octets());

            let tcp = &mut pkt[IPV6_HEADER_LEN..];
            write_tcp_segment(
                tcp, src_port, dst_port, seq, ack, flags, window, options, payload_a, payload_b,
            );
            let tcp_cksum = l4_ipv6_checksum(s6, d6, IP_PROTO_TCP, tcp);
            tcp[16..18].copy_from_slice(&tcp_cksum.to_be_bytes());
            Some(pkt)
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn write_tcp_segment(
    tcp: &mut [u8],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload_a: &[u8],
    payload_b: &[u8],
) {
    let tcp_header_len = TCP_MIN_HEADER_LEN + options.len();
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = ((tcp_header_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    if !options.is_empty() {
        tcp[TCP_MIN_HEADER_LEN..tcp_header_len].copy_from_slice(options);
    }
    let a_end = tcp_header_len + payload_a.len();
    if !payload_a.is_empty() {
        tcp[tcp_header_len..a_end].copy_from_slice(payload_a);
    }
    if !payload_b.is_empty() {
        tcp[a_end..a_end + payload_b.len()].copy_from_slice(payload_b);
    }
}

/// Builds a complete IPv4/UDP packet with valid IPv4 header and UDP checksums.
pub fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    build_ip_udp_packet(
        IpAddr::V4(src_ip),
        src_port,
        IpAddr::V4(dst_ip),
        dst_port,
        payload,
    )
}

/// Builds a complete IPv4 or IPv6 UDP packet with valid checksums.
pub fn build_ip_udp_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    build_ip_udp_packet_patched(src_ip, src_port, dst_ip, dst_port, payload, None)
}

/// Builds a UDP/IPv4 or UDP/IPv6 packet like [`build_ip_udp_packet`], but
/// overwrites the two payload bytes at `patch.0` with `patch.1` while copying.
///
/// The DNS interceptor uses this to rewrite the 2-byte DNS `tx_id` of a cached
/// reply without cloning the shared wire buffer (#168).
pub fn build_ip_udp_packet_patched(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: &[u8],
    patch: Option<(usize, [u8; 2])>,
) -> Option<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN.checked_add(payload.len())?;
    let udp_len_u16 = u16::try_from(udp_len).ok()?;

    match (src_ip, dst_ip) {
        (IpAddr::V4(s4), IpAddr::V4(d4)) => {
            let total_len = IPV4_MIN_HEADER_LEN.checked_add(udp_len)?;
            let total_len_u16 = u16::try_from(total_len).ok()?;
            let mut pkt = vec![0u8; total_len];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
            pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
            pkt[8] = 64;
            pkt[9] = IP_PROTO_UDP;
            pkt[12..16].copy_from_slice(&s4.octets());
            pkt[16..20].copy_from_slice(&d4.octets());
            let ip_cksum = internet_checksum(&pkt[..IPV4_MIN_HEADER_LEN]);
            pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

            let udp = &mut pkt[IPV4_MIN_HEADER_LEN..];
            udp[0..2].copy_from_slice(&src_port.to_be_bytes());
            udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
            udp[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
            udp[UDP_HEADER_LEN..].copy_from_slice(payload);
            apply_payload_patch(udp, patch)?;

            let cksum = l4_ipv4_checksum(s4, d4, IP_PROTO_UDP, udp);
            let cksum = if cksum == 0 { 0xffff } else { cksum };
            udp[6..8].copy_from_slice(&cksum.to_be_bytes());
            Some(pkt)
        }
        (IpAddr::V6(s6), IpAddr::V6(d6)) => {
            let total_len = IPV6_HEADER_LEN.checked_add(udp_len)?;
            let mut pkt = vec![0u8; total_len];
            pkt[0] = 0x60;
            pkt[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
            pkt[6] = IP_PROTO_UDP;
            pkt[7] = 64;
            pkt[8..24].copy_from_slice(&s6.octets());
            pkt[24..40].copy_from_slice(&d6.octets());

            let udp = &mut pkt[IPV6_HEADER_LEN..];
            udp[0..2].copy_from_slice(&src_port.to_be_bytes());
            udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
            udp[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
            udp[UDP_HEADER_LEN..].copy_from_slice(payload);
            apply_payload_patch(udp, patch)?;

            let cksum = l4_ipv6_checksum(s6, d6, IP_PROTO_UDP, udp);
            let cksum = if cksum == 0 { 0xffff } else { cksum };
            udp[6..8].copy_from_slice(&cksum.to_be_bytes());
            Some(pkt)
        }
        _ => None,
    }
}

/// Builds a TCP `RST` (or `RST|ACK`) reply for a rejected incoming IPv4 or IPv6
/// TCP segment (RFC 793 §3.4). Returns `None` if the incoming segment already
/// has `RST` set or is not a valid TCP packet.
pub fn build_tcp_rst_for_packet(original: &IpPacketView<'_>) -> Option<Vec<u8>> {
    if original.protocol != IP_PROTO_TCP {
        return None;
    }
    let seg = parse_tcp(original.payload)?;
    if (seg.flags & TCP_RST) != 0 {
        return None;
    }
    let (seq, ack, flags) = if (seg.flags & TCP_ACK) != 0 {
        (seg.ack, 0, TCP_RST)
    } else {
        let mut seg_len = seg.payload.len() as u32;
        if (seg.flags & TCP_SYN) != 0 {
            seg_len = seg_len.wrapping_add(1);
        }
        if (seg.flags & TCP_FIN) != 0 {
            seg_len = seg_len.wrapping_add(1);
        }
        (0, seg.seq.wrapping_add(seg_len), TCP_RST | TCP_ACK)
    };
    build_ip_tcp_packet_slices(
        original.dst_ip,
        seg.dst_port,
        original.src_ip,
        seg.src_port,
        seq,
        ack,
        flags,
        0,
        &[],
        &[],
        &[],
    )
}

/// Builds an ICMPv4 (Type 3, Code 3) or ICMPv6 (Type 1, Code 4) Port
/// Unreachable reply for `original`.
pub fn build_icmp_port_unreachable(original: &IpPacketView<'_>) -> Option<Vec<u8>> {
    match (original.src_ip, original.dst_ip) {
        (IpAddr::V4(src4), IpAddr::V4(dst4)) => {
            let quote_len = original
                .raw
                .len()
                .min(original.header_len.saturating_add(8));
            let quote = &original.raw[..quote_len];
            let icmp_len = 8 + quote.len();
            let total_len = IPV4_MIN_HEADER_LEN + icmp_len;
            let total_len_u16 = u16::try_from(total_len).ok()?;

            let mut pkt = vec![0u8; total_len];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
            pkt[8] = 64;
            pkt[9] = IP_PROTO_ICMP;
            pkt[12..16].copy_from_slice(&dst4.octets());
            pkt[16..20].copy_from_slice(&src4.octets());
            let ip_cksum = internet_checksum(&pkt[..IPV4_MIN_HEADER_LEN]);
            pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

            let icmp = &mut pkt[IPV4_MIN_HEADER_LEN..];
            icmp[0] = 3; // Destination Unreachable
            icmp[1] = 3; // Port Unreachable
            icmp[8..].copy_from_slice(quote);
            let icmp_cksum = internet_checksum(icmp);
            icmp[2..4].copy_from_slice(&icmp_cksum.to_be_bytes());
            Some(pkt)
        }
        (IpAddr::V6(src6), IpAddr::V6(dst6)) => {
            let quote_len = original.raw.len().min(1232);
            let quote = &original.raw[..quote_len];
            let icmp_len = 8 + quote.len();
            let icmp_len_u16 = u16::try_from(icmp_len).ok()?;
            let total_len = IPV6_HEADER_LEN + icmp_len;

            let mut pkt = vec![0u8; total_len];
            pkt[0] = 0x60;
            pkt[4..6].copy_from_slice(&icmp_len_u16.to_be_bytes());
            pkt[6] = IP_PROTO_ICMPV6;
            pkt[7] = 64;
            pkt[8..24].copy_from_slice(&dst6.octets());
            pkt[24..40].copy_from_slice(&src6.octets());

            let icmp = &mut pkt[IPV6_HEADER_LEN..];
            icmp[0] = 1; // Destination Unreachable
            icmp[1] = 4; // Port Unreachable
            icmp[8..].copy_from_slice(quote);
            let icmp_cksum = l4_ipv6_checksum(dst6, src6, IP_PROTO_ICMPV6, icmp);
            icmp[2..4].copy_from_slice(&icmp_cksum.to_be_bytes());
            Some(pkt)
        }
        _ => None,
    }
}

/// Sums `data` as big-endian 16-bit words for the internet checksum.
///
/// The result equals the plain word sum modulo 65535, which is what the checksum
/// fold consumes. Reads two 32-bit words per 64-bit chunk into two `u64`
/// accumulators; one holds 16 GB of maximum-valued words before it could
/// overflow, far above any packet or the usual callers.
///
/// Public because the `packet_checksum` benchmark compares it with a scalar
/// reference for the same bytes; hidden so it stays out of the public docs.
#[doc(hidden)]
pub fn sum_bytes(data: &[u8]) -> u64 {
    let (chunks, remainder) = data.as_chunks::<8>();
    let mut high = 0u64;
    let mut low = 0u64;
    for chunk in chunks {
        let word = u64::from_be_bytes(*chunk);
        high += word >> 32;
        low += word & 0xffff_ffff;
    }
    let (pairs, last) = remainder.as_chunks::<2>();
    let mut sum = high + low;
    for pair in pairs {
        sum += u64::from(u16::from_be_bytes(*pair));
    }
    if let Some(&odd_byte) = last.first() {
        sum += u64::from(odd_byte) << 8;
    }
    sum
}

fn fold_checksum(mut sum: u64) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn internet_checksum(data: &[u8]) -> u16 {
    fold_checksum(sum_bytes(data))
}

/// Applies an optional `(offset, bytes)` patch inside a UDP segment, returning
/// `None` when the patch does not fit.
fn apply_payload_patch(udp: &mut [u8], patch: Option<(usize, [u8; 2])>) -> Option<()> {
    let Some((offset, bytes)) = patch else {
        return Some(());
    };
    let start = UDP_HEADER_LEN.checked_add(offset)?;
    let slot = udp.get_mut(start..start.checked_add(2)?)?;
    slot.copy_from_slice(&bytes);
    Some(())
}

fn l4_ipv4_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut sum = sum_bytes(&src.octets()) + sum_bytes(&dst.octets());
    sum += u64::from(proto);
    sum += segment.len() as u64;
    sum += sum_bytes(segment);
    fold_checksum(sum)
}

fn l4_ipv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut sum = sum_bytes(&src.octets()) + sum_bytes(&dst.octets());
    sum += segment.len() as u64;
    sum += u64::from(proto);
    sum += sum_bytes(segment);
    fold_checksum(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packet_round_trips_ipv4_and_ipv6() {
        let src4 = Ipv4Addr::new(172, 19, 0, 1);
        let dst4 = Ipv4Addr::new(1, 1, 1, 1);
        let pkt4 = build_ipv4_udp_packet(src4, 50000, dst4, 53, b"dns-v4").expect("build v4");
        assert_eq!(internet_checksum(&pkt4[..20]), 0);
        let ip4 = parse_ip(&pkt4).expect("parse v4");
        assert_eq!(ip4.src_ip, IpAddr::V4(src4));
        assert_eq!(ip4.dst_ip, IpAddr::V4(dst4));
        assert_eq!(parse_udp(ip4.payload).expect("udp4").payload, b"dns-v4");

        let src6: Ipv6Addr = "fd00:1::1".parse().expect("v6");
        let dst6: Ipv6Addr = "fd00:2::2".parse().expect("v6");
        let pkt6 = build_ip_udp_packet(IpAddr::V6(src6), 50001, IpAddr::V6(dst6), 53, b"dns-v6")
            .expect("build v6");
        let ip6 = parse_ip(&pkt6).expect("parse v6");
        assert_eq!(ip6.src_ip, IpAddr::V6(src6));
        assert_eq!(ip6.dst_ip, IpAddr::V6(dst6));
        assert_eq!(parse_udp(ip6.payload).expect("udp6").payload, b"dns-v6");
    }

    #[test]
    fn icmp_port_unreachable_quotes_ipv4_and_ipv6() {
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            40000,
            Ipv4Addr::new(142, 250, 1, 1),
            443,
            b"quic",
        )
        .expect("build udp");
        let ip = parse_ip(&pkt).expect("parse ip");
        let icmp_pkt = build_icmp_port_unreachable(&ip).expect("build icmp");
        assert_eq!(internet_checksum(&icmp_pkt[..20]), 0);
        assert_eq!(internet_checksum(&icmp_pkt[20..]), 0);
        let reply_ip = parse_ip(&icmp_pkt).expect("parse reply");
        assert_eq!(reply_ip.protocol, IP_PROTO_ICMP);
        assert_eq!(reply_ip.payload[0], 3);
        assert_eq!(reply_ip.payload[1], 3);
    }

    #[test]
    fn tcp_rst_for_ipv6_syn_sets_rst_ack_and_ignores_rst() {
        let src6 = IpAddr::V6("fd00:be:a::1".parse().expect("v6"));
        let dst6 = IpAddr::V6("2001:4860:4860::8888".parse().expect("v6"));
        let syn = build_ip_tcp_packet_slices(
            src6,
            51234,
            dst6,
            443,
            1000,
            0,
            TCP_SYN,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("syn");
        let rst = build_tcp_rst_for_packet(&parse_ip(&syn).expect("ip")).expect("rst");
        let rst_ip = parse_ip(&rst).expect("rst ip");
        assert_eq!(rst_ip.src_ip, dst6);
        assert_eq!(rst_ip.dst_ip, src6);
        let seg = parse_tcp(rst_ip.payload).expect("rst tcp");
        assert_eq!(seg.src_port, 443);
        assert_eq!(seg.dst_port, 51234);
        assert_eq!(seg.flags, TCP_RST | TCP_ACK);
        assert_eq!(seg.ack, 1001);
        // Never reply to an incoming RST.
        assert!(build_tcp_rst_for_packet(&rst_ip).is_none());
    }

    fn build_ipv6_with_headers(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        first_next_header: u8,
        body: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; IPV6_HEADER_LEN + body.len()];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
        pkt[6] = first_next_header;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&src.octets());
        pkt[24..40].copy_from_slice(&dst.octets());
        pkt[IPV6_HEADER_LEN..].copy_from_slice(body);
        pkt
    }

    #[test]
    fn ipv6_walks_valid_extension_headers() {
        let src: Ipv6Addr = "fd00:1::1".parse().expect("src");
        let dst: Ipv6Addr = "fd00:2::2".parse().expect("dst");
        let udp_payload = b"ext-hdr-ok";
        let mut udp = vec![0u8; UDP_HEADER_LEN + udp_payload.len()];
        udp[0..2].copy_from_slice(&50000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        let udp_len = udp.len() as u16;
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        udp[UDP_HEADER_LEN..].copy_from_slice(udp_payload);

        // Hop-by-Hop (8 bytes, hdr_ext_len = 0) -> Routing (16 bytes, hdr_ext_len = 1)
        // -> Destination Options (8 bytes, hdr_ext_len = 0) -> UDP (17).
        let mut body = Vec::new();
        body.extend_from_slice(&[IPV6_NEXT_ROUTING, 0, 0, 0, 0, 0, 0, 0]);
        let mut routing = vec![0u8; 16];
        routing[0] = IPV6_NEXT_DEST_OPTS;
        routing[1] = 1;
        body.extend_from_slice(&routing);
        body.extend_from_slice(&[IP_PROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&udp);

        let pkt = build_ipv6_with_headers(src, dst, IPV6_NEXT_HOP_BY_HOP, &body);
        let parsed = parse_ipv6(&pkt).expect("parse ipv6 with ext headers");
        assert_eq!(parsed.header_len, IPV6_HEADER_LEN + 8 + 16 + 8);
        assert_eq!(parsed.protocol, IP_PROTO_UDP);
        assert_eq!(parsed.src_ip, IpAddr::V6(src));
        assert_eq!(parsed.dst_ip, IpAddr::V6(dst));
        let parsed_udp = parse_udp(parsed.payload).expect("udp");
        assert_eq!(parsed_udp.payload, udp_payload);
    }

    #[test]
    fn is_fragment_walks_the_same_extension_depth_as_parse_ipv6() {
        let src: Ipv6Addr = "fd00:1::1".parse().expect("src");
        let dst: Ipv6Addr = "fd00:2::2".parse().expect("dst");

        // Five Destination Options headers before the Fragment header: deeper
        // than the old four-hop limit, still inside MAX_IPV6_EXT_HEADERS.
        let hops = 5;
        let mut body = Vec::new();
        for i in 0..hops {
            let next = if i + 1 == hops {
                IPV6_NEXT_FRAGMENT
            } else {
                IPV6_NEXT_DEST_OPTS
            };
            body.extend_from_slice(&[next, 0, 0, 0, 0, 0, 0, 0]);
        }
        body.extend_from_slice(&[IP_PROTO_UDP, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3, 4]);
        let pkt = build_ipv6_with_headers(src, dst, IPV6_NEXT_DEST_OPTS, &body);
        assert!(
            is_fragment(&pkt),
            "a fragment header behind five extension headers must be classified"
        );
        assert!(parse_ipv6(&pkt).is_none());

        // The same depth without a Fragment header is not a fragment.
        let mut clean = Vec::new();
        for i in 0..hops {
            let next = if i + 1 == hops {
                IP_PROTO_TCP
            } else {
                IPV6_NEXT_DEST_OPTS
            };
            clean.extend_from_slice(&[next, 0, 0, 0, 0, 0, 0, 0]);
        }
        let clean_pkt = build_ipv6_with_headers(src, dst, IPV6_NEXT_DEST_OPTS, &clean);
        assert!(!is_fragment(&clean_pkt));

        // Never panics on short input.
        assert!(!is_fragment(&[]));
        assert!(!is_fragment(&[0x60]));
        assert!(!is_fragment(&[0x45]));
    }

    #[test]
    fn ipv6_rejects_fragment_header() {
        let src: Ipv6Addr = "fd00:1::1".parse().expect("src");
        let dst: Ipv6Addr = "fd00:2::2".parse().expect("dst");

        // Direct Fragment header (next_header = 44).
        let frag_body = [IP_PROTO_UDP, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3, 4];
        let direct = build_ipv6_with_headers(src, dst, IPV6_NEXT_FRAGMENT, &frag_body);
        assert!(parse_ipv6(&direct).is_none());

        // Hop-by-Hop followed by Fragment header.
        let mut chained_body = vec![IPV6_NEXT_FRAGMENT, 0, 0, 0, 0, 0, 0, 0];
        chained_body.extend_from_slice(&frag_body);
        let chained = build_ipv6_with_headers(src, dst, IPV6_NEXT_HOP_BY_HOP, &chained_body);
        assert!(parse_ipv6(&chained).is_none());
    }

    #[test]
    fn ipv6_rejects_malformed_truncated_and_excessive_extension_headers() {
        let src: Ipv6Addr = "fd00:1::1".parse().expect("src");
        let dst: Ipv6Addr = "fd00:2::2".parse().expect("dst");

        // Truncated before 2-byte extension header prefix.
        let tiny = build_ipv6_with_headers(src, dst, IPV6_NEXT_HOP_BY_HOP, &[IP_PROTO_TCP]);
        assert!(parse_ipv6(&tiny).is_none());

        // Truncated extension header body (claims 16 bytes, only 8 bytes present).
        let truncated = build_ipv6_with_headers(
            src,
            dst,
            IPV6_NEXT_DEST_OPTS,
            &[IP_PROTO_TCP, 1, 0, 0, 0, 0, 0, 0],
        );
        assert!(parse_ipv6(&truncated).is_none());

        // Exceeds MAX_IPV6_EXT_HEADERS (9 chained Destination Options headers).
        let mut deep_body = Vec::new();
        for i in 0..=MAX_IPV6_EXT_HEADERS {
            let next = if i == MAX_IPV6_EXT_HEADERS {
                IP_PROTO_TCP
            } else {
                IPV6_NEXT_DEST_OPTS
            };
            deep_body.extend_from_slice(&[next, 0, 0, 0, 0, 0, 0, 0]);
        }
        let deep = build_ipv6_with_headers(src, dst, IPV6_NEXT_DEST_OPTS, &deep_body);
        assert!(parse_ipv6(&deep).is_none());
    }

    /// Byte-pair reference implementation that the checksum fold of the
    /// unrolled [`sum_bytes`] must reproduce bit for bit.
    fn scalar_sum_bytes(data: &[u8]) -> u64 {
        let mut sum = 0u64;
        let mut idx = 0;
        while idx + 1 < data.len() {
            sum += u64::from(u16::from_be_bytes([data[idx], data[idx + 1]]));
            idx += 2;
        }
        if idx < data.len() {
            sum += u64::from(data[idx]) << 8;
        }
        sum
    }

    fn scalar_checksum(data: &[u8]) -> u16 {
        let mut sum = scalar_sum_bytes(data) as u32;
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn sum_bytes_is_bit_exact_with_the_scalar_reference() {
        let mut buf = vec![0u8; 1500 + 8];
        let mut state = 0x1234_5678u32;
        for byte in buf.iter_mut() {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            *byte = (state >> 16) as u8;
        }
        for offset in 0..8 {
            for len in 0..=1500 {
                let data = &buf[offset..offset + len];
                assert_eq!(
                    sum_bytes(data) % 65_535,
                    scalar_sum_bytes(data) % 65_535,
                    "word sum diverges at offset {offset} len {len}"
                );
                assert_eq!(
                    internet_checksum(data),
                    scalar_checksum(data),
                    "checksum mismatch at offset {offset} len {len}"
                );
            }
        }
    }
}
