#![no_main]

use beam_tun::dns::{
    build_servfail_response, parse_dns_query, parse_dns_response_meta, try_decode_chunked_body,
};
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
    let _ = try_decode_chunked_body(data);

    // Feed a multi-packet sequence into ProxyTcpStack so stateful paths
    // (Established, OOO reassembly, FIN, ACK, timers) are fuzzed too.
    let mut stack = ProxyTcpStack::new(TcpStackConfig {
        max_connections: 4,
        socket_buffer_bytes: 64 * 1024,
        ..TcpStackConfig::default()
    });
    let mut tx = Vec::new();
    let mut accepted = Vec::new();
    let mut pos = 0usize;
    let mut now_ms = 10i64;
    let mut frames = 0usize;
    while pos + 2 <= data.len() && frames < 16 {
        let len = usize::from(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
        if len == 0 || pos + len > data.len() {
            break;
        }
        stack.push_ip_tcp(&data[pos..pos + len]);
        stack.poll(now_ms, &mut tx, &mut accepted);
        tx.clear();
        pos += len;
        now_ms += 50;
        frames += 1;
    }
});
