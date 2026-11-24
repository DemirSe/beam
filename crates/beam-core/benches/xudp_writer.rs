//! Micro-benchmark for the XUDP mux writer coalescing (#167).
//!
//! Compares one `write_all` per encoded frame with the new coalescing writer
//! that batches every already-queued frame up to a 64 KiB cap.
//!
//! Run with: `cargo bench -p beam-core --bench xudp_writer`

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

/// Counts completed `poll_write` calls so the reported syscall count is
/// measured instead of assumed.
struct CountingWriter<W> {
    inner: W,
    writes: usize,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, writes: 0 }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountingWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(_))) {
            this.writes += 1;
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
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
        let (tx, rx) = UnixStream::pair().expect("socket pair");
        let mut tx = CountingWriter::new(tx);
        let drain = spawn_drain(rx);
        write_per_frame(&mut tx, &frames).await;
        drop(tx);
        let _ = drain.await;
    });

    let start = Instant::now();
    let baseline_writes = runtime.block_on(async {
        let (tx, rx) = UnixStream::pair().expect("socket pair");
        let mut tx = CountingWriter::new(tx);
        let drain = spawn_drain(rx);
        for _ in 0..ROUNDS {
            write_per_frame(&mut tx, &frames).await;
        }
        let writes = tx.writes;
        drop(tx);
        let _ = drain.await;
        writes
    });
    let baseline = start.elapsed();

    let start = Instant::now();
    let coalesced_writes = runtime.block_on(async {
        let (tx, rx) = UnixStream::pair().expect("socket pair");
        let mut tx = CountingWriter::new(tx);
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
        let writes = tx.writes;
        drop(tx);
        let _ = drain.await;
        writes
    });
    let coalesced = start.elapsed();

    let frames_total = (ROUNDS * FRAME_COUNT) as f64;
    let base_ns = baseline.as_secs_f64() * 1e9 / frames_total;
    let coal_ns = coalesced.as_secs_f64() * 1e9 / frames_total;
    let base_writes_per_round = baseline_writes as f64 / ROUNDS as f64;
    let coal_writes_per_round = coalesced_writes as f64 / ROUNDS as f64;
    println!(
        "xudp mux writer over a Unix socket pair: {FRAME_COUNT} queued frames x {PAYLOAD_LEN} B payload, {ROUNDS} rounds ({per_round_bytes} B/round)"
    );
    println!(
        "  per-frame write_all  {base_ns:8.1} ns/frame   {:?} total, {base_writes_per_round:.1} write syscalls/round",
        baseline
    );
    println!(
        "  coalesced (new)      {coal_ns:8.1} ns/frame   {:?} total, {coal_writes_per_round:.1} write syscalls/round",
        coalesced
    );
    println!(
        "  write syscalls       {:.1}x fewer (measured {baseline_writes} vs {coalesced_writes})",
        base_writes_per_round / coal_writes_per_round
    );
    println!("  speedup              {:8.2}x", base_ns / coal_ns);
}
