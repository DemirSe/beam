//! Micro-benchmark for the DNS cache-hit reply path (#168).
//!
//! Compares the previous behavior (clone the cached wire `Vec<u8>`, patch the
//! 2-byte `tx_id`, then build the reply packet) with the shared `Arc<[u8]>`
//! path that patches the `tx_id` while the packet is assembled.
//!
//! Run with: `cargo bench -p beam-tun --bench dns_cache_hit`

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use beam_tun::dns::{DnsCache, parse_dns_query};
use beam_tun::packet::{build_ip_udp_packet, build_ip_udp_packet_patched};

const ROUNDS: usize = 50_000;

fn build_query(tx_id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx_id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

fn build_a_response(query: &[u8], ip: Ipv4Addr, ttl: u32, target_len: usize) -> Vec<u8> {
    let mut out = query.to_vec();
    out[2] = 0x81;
    out[3] = 0x80;
    out[6] = 0;
    out[7] = 1;
    out.extend_from_slice(&[0xc0, 0x0c]);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip.octets());
    pad_with_edns0(&mut out, target_len);
    out
}

/// Pads `response` to `target_len` with an RFC 7830 EDNS0 padding option, the
/// shape a real 512-byte upstream answer has.
fn pad_with_edns0(response: &mut Vec<u8>, target_len: usize) {
    // Fixed OPT pseudo-RR (root name, TYPE 41, class, TTL, RDLEN) plus the
    // 4-byte padding option header.
    const OPT_OVERHEAD: usize = 11 + 4;
    if response.len() + OPT_OVERHEAD >= target_len {
        return;
    }
    let padding = target_len - response.len() - OPT_OVERHEAD;
    response[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1
    response.extend_from_slice(&[0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00]);
    response.extend_from_slice(&u16::try_from(4 + padding).expect("opt rdlen").to_be_bytes());
    response.extend_from_slice(&[0x00, 0x0c]); // option code: padding
    response.extend_from_slice(&u16::try_from(padding).expect("padding len").to_be_bytes());
    response.resize(response.len() + padding, 0);
}

fn main() {
    let name = "cache-hit.benchmark.example.test";
    let query_wire = build_query(0x4242, name);
    // A realistic full-size upstream answer (512 B, EDNS padding, one A record).
    const RESPONSE_LEN: usize = 512;
    let response = build_a_response(
        &query_wire,
        Ipv4Addr::new(203, 0, 113, 5),
        300,
        RESPONSE_LEN,
    );
    assert_eq!(response.len(), RESPONSE_LEN);
    let parsed = parse_dns_query(&query_wire).expect("query");
    let response_len = response.len();

    let src: SocketAddr = "172.19.0.1:40000".parse().expect("src");
    let dst: SocketAddr = "172.19.0.2:53".parse().expect("dst");

    let mut cache = DnsCache::new(64);
    cache.insert(
        &parsed,
        Arc::from(response.as_slice()),
        300,
        false,
        Instant::now(),
    );

    // Old path: clone the whole cached wire buffer, patch tx_id, build packet.
    let start = Instant::now();
    let mut old_bytes = 0usize;
    for round in 0..ROUNDS {
        let hit = cache
            .get(&parsed, Instant::now())
            .expect("cache hit")
            .to_vec();
        let mut wire = hit;
        let id = (round as u16).to_be_bytes();
        wire[0] = id[0];
        wire[1] = id[1];
        let pkt = build_ip_udp_packet(dst.ip(), dst.port(), src.ip(), src.port(), &wire)
            .expect("reply packet");
        old_bytes += black_box(pkt).len();
    }
    let old = start.elapsed();

    // New path: share the cached buffer, patch tx_id inside the packet builder.
    let start = Instant::now();
    let mut new_bytes = 0usize;
    for round in 0..ROUNDS {
        let hit = cache.get(&parsed, Instant::now()).expect("cache hit");
        let pkt = build_ip_udp_packet_patched(
            dst.ip(),
            dst.port(),
            src.ip(),
            src.port(),
            &hit,
            Some((0, (round as u16).to_be_bytes())),
        )
        .expect("reply packet");
        new_bytes += black_box(pkt).len();
    }
    let new = start.elapsed();
    assert_eq!(old_bytes, new_bytes);

    let old_ns = old.as_secs_f64() * 1e9 / ROUNDS as f64;
    let new_ns = new.as_secs_f64() * 1e9 / ROUNDS as f64;
    println!("dns cache-hit reply path ({response_len}-byte wire response, {ROUNDS} hits)");
    println!(
        "  clone wire + patch   {old_ns:8.1} ns/hit   {:?} total",
        old
    );
    println!(
        "  shared Arc + patch   {new_ns:8.1} ns/hit   {:?} total",
        new
    );
    println!(
        "  saved                {:8.1} ns/hit ({:.0}%)",
        old_ns - new_ns,
        (old_ns - new_ns) / old_ns * 100.0
    );

    // Isolate the allocation the change removes.
    let shared: Arc<[u8]> = Arc::from(response.as_slice());
    let start = Instant::now();
    let mut cloned = 0usize;
    for _ in 0..ROUNDS {
        let copy = black_box(shared.to_vec());
        cloned += copy.len();
    }
    let clone_only = start.elapsed().as_secs_f64() * 1e9 / ROUNDS as f64;
    println!("  (wire clone alone    {clone_only:8.1} ns/hit, {cloned} bytes)");

    let ip: IpAddr = dst.ip();
    let _ = ip;
}
