//! Micro-benchmark for the unrolled 16-bit word sum behind `internet_checksum`.
//!
//! Compares the previous byte-pair scalar loop with the 64-bit unrolled
//! `packet::sum_bytes` on a 1460-byte TCP segment.
//!
//! Run with: `cargo bench -p beam-tun --bench packet_checksum`

use std::hint::black_box;
use std::time::Instant;

use beam_tun::packet::sum_bytes;

const SEGMENT_LEN: usize = 1460;
const ROUNDS: usize = 20_000;
const TRIALS: usize = 5;

/// Byte-pair scalar sum: the implementation `sum_bytes` replaced.
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

/// Runs both variants in the same trial loop, so each round samples both
/// implementations under the same cache and frequency conditions. Returns the
/// best (scalar, unrolled) ns/segment pair.
fn measure(scalar: &mut dyn FnMut() -> u64, unrolled: &mut dyn FnMut() -> u64) -> (f64, f64) {
    black_box(scalar());
    black_box(unrolled());
    let rounds = ROUNDS / TRIALS;
    let mut best_scalar = f64::MAX;
    let mut best_unrolled = f64::MAX;
    for _ in 0..TRIALS {
        let start = Instant::now();
        for _ in 0..rounds {
            black_box(scalar());
        }
        best_scalar = best_scalar.min(start.elapsed().as_secs_f64() * 1e9 / rounds as f64);

        let start = Instant::now();
        for _ in 0..rounds {
            black_box(unrolled());
        }
        best_unrolled = best_unrolled.min(start.elapsed().as_secs_f64() * 1e9 / rounds as f64);
    }
    (best_scalar, best_unrolled)
}

fn main() {
    let mut segment = vec![0u8; SEGMENT_LEN];
    let mut state = 0x9e37_79b9u32;
    for byte in segment.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        *byte = (state >> 16) as u8;
    }

    let mut scalar = || scalar_sum_bytes(black_box(&segment));
    let mut unrolled = || sum_bytes(black_box(&segment));
    let (scalar_ns, unrolled_ns) = measure(&mut scalar, &mut unrolled);
    assert_eq!(
        scalar_sum_bytes(&segment) % 65_535,
        sum_bytes(&segment) % 65_535,
        "both implementations must agree"
    );

    println!("internet checksum word sum over {SEGMENT_LEN} B TCP segments, {ROUNDS} rounds");
    println!("  scalar byte pairs   {scalar_ns:8.2} ns/segment");
    println!("  unrolled 64-bit     {unrolled_ns:8.2} ns/segment");
    println!("  speedup             {:8.2}x", scalar_ns / unrolled_ns);
}
