#![no_main]

use beam_tun::dns::{build_servfail_response, parse_dns_query, parse_dns_response_meta};
use beam_tun::packet::{
    build_icmp_port_unreachable, parse_ip, parse_tcp, parse_tcp_syn_options, parse_udp,
};
use beam_tun::{NetStack, ProxyTcpStack, TcpStackConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(ip) = parse_ip(data) {
        let _ = build_icmp_port_unreachable(&ip);
        if let Some(udp) = parse_udp(ip.payload) {
            let _ = parse_dns_query(udp.payload);
            let _ = parse_dns_response_meta(udp.payload);
            let _ = build_servfail_response(udp.payload);
        }
        if let Some(tcp) = parse_tcp(ip.payload) {
            let _ = parse_tcp_syn_options(tcp.options);
        }
    }

    // Exercise ProxyTcpStack with raw untrusted packet slices.
    let mut stack = ProxyTcpStack::new(TcpStackConfig {
        max_connections: 4,
        socket_buffer_bytes: 64 * 1024,
        ..TcpStackConfig::default()
    });
    let mut tx = Vec::new();
    let mut accepted = Vec::new();
    stack.push_ip_tcp(data);
    stack.poll(10, &mut tx, &mut accepted);
});
