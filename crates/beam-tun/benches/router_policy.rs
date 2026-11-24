//! Micro-benchmark for the pre-indexed bypass CIDR lookup (#170).
//!
//! Compares the previous linear scan over configured prefixes with the
//! normalized `BypassCidrs` binary search for the same prefix set.
//!
//! Run with: `cargo bench -p beam-tun --bench router_policy`

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use beam_tun::{BypassCidrs, IpNet};

const PREFIX_COUNT: usize = 64;
const IP_SAMPLES: usize = 4096;
const ROUNDS: usize = 200;

fn prefixes() -> Vec<IpNet> {
    let mut nets = Vec::with_capacity(PREFIX_COUNT);
    for idx in 0..PREFIX_COUNT {
        let a = 10 + (idx % 100) as u8;
        let b = (idx * 3 % 256) as u8;
        nets.push(IpNet::parse_cidr(&format!("{a}.{b}.0.0/16")).expect("ipv4 prefix"));
    }
    for idx in 0..(PREFIX_COUNT / 2) {
        nets.push(
            IpNet::parse_cidr(&format!("2001:db8:{:x}::/48", idx % 256)).expect("ipv6 prefix"),
        );
    }
    nets
}

fn samples() -> Vec<IpAddr> {
    (0..IP_SAMPLES)
        .map(|idx| {
            let _ = idx;
            if idx % 8 == 0 {
                IpAddr::V6(Ipv6Addr::new(
                    0x2001,
                    0xdb8,
                    (idx % 128) as u16,
                    0,
                    0,
                    0,
                    0,
                    1,
                ))
            } else {
                IpAddr::V4(Ipv4Addr::new(
                    10 + (idx % 110) as u8,
                    (idx * 7 % 256) as u8,
                    (idx % 256) as u8,
                    1,
                ))
            }
        })
        .collect()
}

fn main() {
    let nets = prefixes();
    let index = BypassCidrs::new(&nets);
    let ips = samples();
    assert!(!index.is_empty());

    // Equivalence check before timing: one wrong answer invalidates the run.
    for ip in &ips {
        assert_eq!(
            index.contains(*ip),
            nets.iter().any(|net| net.contains(*ip)),
            "indexed lookup disagrees with the linear scan for {ip}"
        );
    }

    let mut linear_hits = 0usize;
    let start = Instant::now();
    for _ in 0..ROUNDS {
        for ip in &ips {
            if black_box(nets.iter().any(|net| net.contains(*ip))) {
                linear_hits += 1;
            }
        }
    }
    let linear = start.elapsed();

    let mut indexed_hits = 0usize;
    let start = Instant::now();
    for _ in 0..ROUNDS {
        for ip in &ips {
            if black_box(index.contains(*ip)) {
                indexed_hits += 1;
            }
        }
    }
    let indexed = start.elapsed();
    assert_eq!(linear_hits, indexed_hits);

    let lookups = (ROUNDS * IP_SAMPLES) as f64;
    let linear_ns = linear.as_secs_f64() * 1e9 / lookups;
    let indexed_ns = indexed.as_secs_f64() * 1e9 / lookups;
    println!(
        "router bypass-CIDR lookup ({} prefixes after merge, {} lookups/round)",
        index.len(),
        IP_SAMPLES
    );
    println!(
        "  linear scan     {linear_ns:8.2} ns/lookup   {:?} total",
        linear
    );
    println!(
        "  indexed (new)   {indexed_ns:8.2} ns/lookup   {:?} total",
        indexed
    );
    println!(
        "  speedup         {:8.2}x  (hits: {indexed_hits})",
        linear_ns / indexed_ns
    );

    // Empty policy is the hot-path fast case: the index must cost nothing.
    let empty = BypassCidrs::default();
    let start = Instant::now();
    for _ in 0..ROUNDS {
        for ip in &ips {
            let _ = black_box(empty.is_empty() || empty.contains(*ip));
        }
    }
    let empty_ns = start.elapsed().as_secs_f64() * 1e9 / lookups;
    println!("  empty fast path {empty_ns:8.3} ns/lookup");
}
