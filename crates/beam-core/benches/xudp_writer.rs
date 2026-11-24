//! Micro-benchmark for the XUDP mux writer coalescing (#167).
//!
//! Compares one `write_all` per encoded frame with the new coalescing writer
//! that batches every already-queued frame up to a 64 KiB cap.
//!
//! Run with: `cargo bench -p beam-core --bench xudp_writer`

use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};

use beam_core::address::{Address, NetLocation};
use beam_core::client::xudp::run_writer;
use beam_core::xudp::frame::{FrameOption, FrameSpec, SessionStatus, TargetNetwork, encode_frame};

const FRAME_COUNT: usize = 64;
const PAYLOAD_LEN: usize = 512;
const ROUNDS: usize = 500;

fn frames() -> Vec<Vec<u8>> {
    let dest = NetLocation {
        address: Address::Ipv4(std::net::Ipv4Addr::new(9, 9, 9, 9)),
        port: 53,
    };
    let payload = vec![0x5au8; PAYLOAD_LEN];
    (0..FRAME_COUNT)
        .map(|idx| {
            let spec = FrameSpec {
                session_id: (idx as u16) + 1,
                status: SessionStatus::New,
                option: FrameOption::DATA,
                network: Some(TargetNetwork::Udp),
                destination: Some(&dest),
                global_id: None,
                payload: &payload,
            };
            let mut out = Vec::new();
            encode_frame(&mut out, spec).expect("encode frame");
            out
        })
        .collect()
}

/// Baseline: one `write_all` per frame, a single flush at the end.
async fn write_per_frame<W: AsyncWriteExt + Unpin>(sink: &mut W, frames: &[Vec<u8>]) {
    for frame in frames {
        if sink.write_all(frame).await.is_err() {
            return;
        }
    }
    let _ = sink.flush().await;
}

/// Drains a socket pair end so writes never block on a full kernel buffer.
fn spawn_drain(mut rx: UnixStream) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
}

fn main() {
    let frames = frames();
    let per_round_bytes: usize = frames.iter().map(Vec::len).sum();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()
        .expect("tokio runtime");

    // Warmup on a real socket pair so both paths pay real syscalls.
    runtime.block_on(async {
        let (mut tx, rx) = UnixStream::pair().expect("socket pair");
        let drain = spawn_drain(rx);
        write_per_frame(&mut tx, &frames).await;
        drop(tx);
        let _ = drain.await;
    });

    let start = Instant::now();
    runtime.block_on(async {
        let (mut tx, rx) = UnixStream::pair().expect("socket pair");
        let drain = spawn_drain(rx);
        for _ in 0..ROUNDS {
            write_per_frame(&mut tx, &frames).await;
        }
        drop(tx);
        let _ = drain.await;
    });
    let baseline = start.elapsed();

    let start = Instant::now();
    runtime.block_on(async {
        let (mut tx, rx) = UnixStream::pair().expect("socket pair");
        let drain = spawn_drain(rx);
        for _ in 0..ROUNDS {
            let (frame_tx, mut rx) = mpsc::channel(FRAME_COUNT + 1);
            let (_closed_tx, mut closed_rx) = watch::channel(false);
            for frame in &frames {
                frame_tx.send(frame.clone()).await.expect("queue frame");
            }
            drop(frame_tx);
            run_writer(&mut tx, &mut rx, &mut closed_rx).await;
        }
        drop(tx);
        let _ = drain.await;
    });
    let coalesced = start.elapsed();

    let frames_total = (ROUNDS * FRAME_COUNT) as f64;
    let base_ns = baseline.as_secs_f64() * 1e9 / frames_total;
    let coal_ns = coalesced.as_secs_f64() * 1e9 / frames_total;
    println!(
        "xudp mux writer over a Unix socket pair: {FRAME_COUNT} queued frames x {PAYLOAD_LEN} B payload, {ROUNDS} rounds ({per_round_bytes} B/round)"
    );
    println!(
        "  per-frame write_all  {base_ns:8.1} ns/frame   {:?} total, {FRAME_COUNT} write syscalls/round",
        baseline
    );
    println!(
        "  coalesced (new)      {coal_ns:8.1} ns/frame   {:?} total, 1 write syscall/round",
        coalesced
    );
    println!("  write syscalls       {:.0}x fewer", FRAME_COUNT as f64);
    println!("  speedup              {:8.2}x", base_ns / coal_ns);
}
