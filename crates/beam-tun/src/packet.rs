//! Zero-panic IPv4, TCP, UDP, and ICMPv4 packet parsing and synthesis.

use std::net::Ipv4Addr;

/// IPv4 protocol numbers.
pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

/// Minimum IPv4 header length in bytes.
pub const IPV4_MIN_HEADER_LEN: usize = 20;
/// UDP header length in bytes.
pub const UDP_HEADER_LEN: usize = 8;
/// Minimum TCP header length in bytes.
pub const TCP_MIN_HEADER_LEN: usize = 20;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

/// TCP header flag constants.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

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

/// Parses a TCP segment from an IPv4 payload slice.
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
            0 => break, // End of Option List
            1 => {
                i += 1; // NOP
            }
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

/// Builds a complete IPv4/TCP packet with valid IPv4 header and TCP checksums.
/// `options` length must be a multiple of 4 (up to 40 bytes).
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if options.len() > 40 || !options.len().is_multiple_of(4) {
        return None;
    }
    let tcp_header_len = TCP_MIN_HEADER_LEN + options.len();
    let tcp_len = tcp_header_len.checked_add(payload.len())?;
    let total_len = IPV4_MIN_HEADER_LEN.checked_add(tcp_len)?;
    let total_len_u16 = u16::try_from(total_len).ok()?;

    let mut pkt = vec![0u8; total_len];
    // IPv4 header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = IP_PROTO_TCP;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = internet_checksum(&pkt[..IPV4_MIN_HEADER_LEN]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // TCP header + options + payload
    let tcp = &mut pkt[IPV4_MIN_HEADER_LEN..];
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
    if !payload.is_empty() {
        tcp[tcp_header_len..].copy_from_slice(payload);
    }

    let tcp_cksum = tcp_ipv4_checksum(src_ip, dst_ip, tcp);
    tcp[16..18].copy_from_slice(&tcp_cksum.to_be_bytes());
    Some(pkt)
}

fn tcp_ipv4_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum = 0u32;
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
    sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
    sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
    sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
    sum += u32::from(IP_PROTO_TCP);
    sum += tcp_segment.len() as u32;

    let (chunks, remainder) = tcp_segment.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parsed view of an IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4PacketView<'a> {
    /// IPv4 header length in bytes (`20..=60`).
    pub header_len: usize,
    /// Protocol field (`IP_PROTO_TCP`, `IP_PROTO_UDP`, etc.).
    pub protocol: u8,
    /// Source IPv4 address.
    pub src_ip: Ipv4Addr,
    /// Destination IPv4 address.
    pub dst_ip: Ipv4Addr,
    /// Complete trimmed IPv4 packet (`..total_len`).
    pub raw: &'a [u8],
    /// L4 payload slice (`header_len..total_len`).
    pub payload: &'a [u8],
}

/// Parsed view of a UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacketView<'a> {
    /// Source UDP port.
    pub src_port: u16,
    /// Destination UDP port.
    pub dst_port: u16,
    /// UDP payload bytes.
    pub payload: &'a [u8],
}

/// Parses an IPv4 packet, rejecting truncated, non-IPv4, or fragmented packets.
pub fn parse_ipv4(packet: &[u8]) -> Option<Ipv4PacketView<'_>> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
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

/// Parses a UDP datagram from an IPv4 payload slice.
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

/// Returns `(src_port, dst_port)` if `payload` is a valid TCP SYN packet
/// (SYN set, ACK clear).
pub fn parse_tcp_syn(payload: &[u8]) -> Option<(u16, u16)> {
    if payload.len() < TCP_MIN_HEADER_LEN {
        return None;
    }
    let data_offset = usize::from(payload[12] >> 4) * 4;
    if data_offset < TCP_MIN_HEADER_LEN || data_offset > payload.len() {
        return None;
    }
    let flags = payload[13];
    if (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0 {
        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
        Some((src_port, dst_port))
    } else {
        None
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
    let udp_len = UDP_HEADER_LEN.checked_add(payload.len())?;
    let total_len = IPV4_MIN_HEADER_LEN.checked_add(udp_len)?;
    let total_len_u16 = u16::try_from(total_len).ok()?;
    let udp_len_u16 = u16::try_from(udp_len).ok()?;

    let mut pkt = vec![0u8; total_len];
    // IPv4 header
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = IP_PROTO_UDP;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = internet_checksum(&pkt[..IPV4_MIN_HEADER_LEN]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // UDP header + payload
    let udp = &mut pkt[IPV4_MIN_HEADER_LEN..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    udp[UDP_HEADER_LEN..].copy_from_slice(payload);

    let udp_cksum = udp_ipv4_checksum(src_ip, dst_ip, udp);
    udp[6..8].copy_from_slice(&udp_cksum.to_be_bytes());

    Some(pkt)
}

/// Builds an RFC 792 ICMPv4 Destination Unreachable / Port Unreachable (Type 3,
/// Code 3) reply for `original` (e.g. for `reject_quic` on UDP/443).
pub fn build_icmp_port_unreachable(original: &Ipv4PacketView<'_>) -> Option<Vec<u8>> {
    // Quote the original IPv4 header plus up to 8 bytes of its payload.
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
    pkt[12..16].copy_from_slice(&original.dst_ip.octets());
    pkt[16..20].copy_from_slice(&original.src_ip.octets());
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

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_ipv4_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut sum = 0u32;
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
    sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
    sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
    sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
    sum += u32::from(IP_PROTO_UDP);
    sum += udp_segment.len() as u32;

    let (chunks, remainder) = udp_segment.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let result = !(sum as u16);
    if result == 0 { 0xffff } else { result }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packet_round_trips_with_valid_checksums() {
        let src = Ipv4Addr::new(172, 19, 0, 1);
        let dst = Ipv4Addr::new(1, 1, 1, 1);
        let pkt = build_ipv4_udp_packet(src, 50000, dst, 53, b"dns-query").expect("build udp");
        assert_eq!(internet_checksum(&pkt[..20]), 0);
        let ip = parse_ipv4(&pkt).expect("parse ipv4");
        assert_eq!(ip.src_ip, src);
        assert_eq!(ip.dst_ip, dst);
        assert_eq!(ip.protocol, IP_PROTO_UDP);
        let udp = parse_udp(ip.payload).expect("parse udp");
        assert_eq!(udp.src_port, 50000);
        assert_eq!(udp.dst_port, 53);
        assert_eq!(udp.payload, b"dns-query");
    }

    #[test]
    fn icmp_port_unreachable_quotes_original_packet() {
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            40000,
            Ipv4Addr::new(142, 250, 1, 1),
            443,
            b"quic",
        )
        .expect("build udp");
        let ip = parse_ipv4(&pkt).expect("parse ipv4");
        let icmp_pkt = build_icmp_port_unreachable(&ip).expect("build icmp");
        assert_eq!(internet_checksum(&icmp_pkt[..20]), 0);
        assert_eq!(internet_checksum(&icmp_pkt[20..]), 0);
        let reply_ip = parse_ipv4(&icmp_pkt).expect("parse reply");
        assert_eq!(reply_ip.protocol, IP_PROTO_ICMP);
        assert_eq!(reply_ip.src_ip, Ipv4Addr::new(142, 250, 1, 1));
        assert_eq!(reply_ip.dst_ip, Ipv4Addr::new(172, 19, 0, 1));
        assert_eq!(reply_ip.payload[0], 3);
        assert_eq!(reply_ip.payload[1], 3);
    }
}
