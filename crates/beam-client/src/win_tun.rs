//! Async WinTun adapter implementing [`beam_tun::TunDevice`].
//!
//! WinTun only offers a blocking wait for received packets, so a dedicated
//! `beam-wintun-rx` thread owns the receive side and forwards packets over a
//! bounded channel. The async side writes straight into the ring: a full ring
//! is transient, and the caller counts the drop.
#![cfg(windows)]

use std::io;
use std::sync::Arc;
use std::thread::JoinHandle;

use beam_sys::windows::wintun::{
    DEFAULT_RING_CAPACITY, MAX_PACKET_LEN, WINTUN_0_14_1_AMD64_SHA256, WinTunAdapter, WinTunLib,
    WinTunSession, WinTunShutdown, decode_sha256_hex,
};
use beam_tun::TunDevice;
use beam_tun::rx_batch::{
    BatchDecoder, RX_BATCH_MAX_BYTES, RX_BATCH_MAX_PACKETS, push_frame, push_frame_forced,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Tunnel type recorded on the adapter, so Device Manager groups it under beam.
const TUNNEL_TYPE: &str = "Beam";

/// Packets queued between the reader thread and the async receiver.
///
/// Each queued item is one length-prefixed batch of up to 32 packets / 64 KiB
/// (see `beam_tun::rx_batch`), so the worst-case queue footprint is
/// `256 * 64 KiB = 16 MiB` plus framing, the same order as one max-size
/// packet per slot before batching.
const RX_QUEUE_CAPACITY: usize = 256;

/// Async handle to a WinTun adapter and its Layer 3 session.
pub struct AsyncWinTun {
    session: Arc<WinTunSession>,
    shutdown: WinTunShutdown,
    name: String,
    mtu: usize,
    /// `None` once [`Drop`] closed the queue to release a blocked reader.
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// Batch currently being decoded; empty once fully consumed.
    decoder: BatchDecoder,
    reader: Option<JoinHandle<()>>,
}

impl AsyncWinTun {
    /// Creates (or reopens) the named WinTun adapter and starts a session.
    ///
    /// `wintun.dll` is loaded from the executable directory after its pinned
    /// SHA-256 was verified, so neither `PATH` nor the current directory can
    /// supply the module.
    pub fn open(name: &str, mtu: usize) -> io::Result<Self> {
        if mtu == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WinTun MTU must be positive",
            ));
        }
        let digest = decode_sha256_hex(WINTUN_0_14_1_AMD64_SHA256)?;
        let lib = Arc::new(WinTunLib::load_from_exe_dir(Some(&digest))?);
        let adapter = Arc::new(WinTunAdapter::create(lib, name, TUNNEL_TYPE)?);
        let session = Arc::new(adapter.start_session(DEFAULT_RING_CAPACITY)?);
        let shutdown = session.shutdown_handle();
        let (tx, rx) = mpsc::channel::<Vec<u8>>(RX_QUEUE_CAPACITY);
        let reader_session = Arc::clone(&session);
        let reader = std::thread::Builder::new()
            .name("beam-wintun-rx".into())
            .spawn(move || receive_loop(&reader_session, tx))?;
        Ok(Self {
            session,
            shutdown,
            name: name.to_owned(),
            mtu,
            rx: Some(rx),
            decoder: BatchDecoder::new(),
            reader: Some(reader),
        })
    }

    /// LUID of the adapter's network interface, for IP Helper and WFP calls.
    pub fn luid(&self) -> u64 {
        self.session.luid()
    }

    /// Adapter name as passed to [`AsyncWinTun::open`].
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl TunDevice for AsyncWinTun {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(packet) = self.decoder.next_packet() {
                let len = copy_packet(packet, buf)?;
                self.decoder.release_if_empty();
                return Ok(len);
            }
            let Some(queue) = self.rx.as_mut() else {
                return Err(closed());
            };
            let Some(batch) = queue.recv().await else {
                return Err(closed());
            };
            self.decoder.push_batch(batch);
        }
    }

    fn try_recv_into(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        if let Some(packet) = self.decoder.next_packet() {
            let len = copy_packet(packet, buf)?;
            self.decoder.release_if_empty();
            return Ok(Some(len));
        }
        let Some(queue) = self.rx.as_mut() else {
            return Ok(None);
        };
        match queue.try_recv() {
            Ok(batch) => {
                self.decoder.push_batch(batch);
                match self.decoder.next_packet() {
                    Some(packet) => {
                        let len = copy_packet(packet, buf)?;
                        self.decoder.release_if_empty();
                        Ok(Some(len))
                    }
                    // Only our own encoder produces batches, so an empty one
                    // just means the next wakeup carries the packets.
                    None => Ok(None),
                }
            }
            Err(_) => Ok(None),
        }
    }

    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.session.send_packet(packet)
    }
}

impl Drop for AsyncWinTun {
    fn drop(&mut self) {
        // Signal first: a reader blocked in `recv_blocking` wakes on this event
        // or on a packet, whichever comes first.
        let _ = self.shutdown.signal();
        // Then close the queue, which releases a reader blocked in
        // `blocking_send` on a full queue. Both waits are bounded, so the join
        // below cannot hang.
        drop(self.rx.take());
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Error reported once the receive side of the device stopped.
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "WinTun receive queue closed")
}

/// Copies one received packet into `buf`, rejecting one that does not fit.
fn copy_packet(packet: &[u8], buf: &mut [u8]) -> io::Result<usize> {
    if packet.len() > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "WinTun packet of {} bytes exceeds the {}-byte receive buffer",
                packet.len(),
                buf.len()
            ),
        ));
    }
    buf[..packet.len()].copy_from_slice(packet);
    Ok(packet.len())
}

/// Forwards packets from the WinTun ring into the bounded async queue, one
/// length-prefixed batch per channel message (see `beam_tun::rx_batch`).
///
/// The thread blocks only for the first packet of a batch, then drains up to
/// 32 already-queued packets (or 64 KiB) without waiting, so one allocation
/// and one wakeup carry the whole burst. A packet that does not fit the batch
/// under construction rides in the next batch instead of being dropped.
///
/// The thread exits on shutdown, on a closed queue, or on the first receive
/// error; a dead session cannot recover, and `recv` then reports end of file.
fn receive_loop(session: &WinTunSession, tx: mpsc::Sender<Vec<u8>>) {
    let mut scratch = vec![0u8; MAX_PACKET_LEN];
    // Ring packet drained while the previous batch was full; sent first next.
    let mut carried: Option<usize> = None;
    loop {
        let mut batch = Vec::with_capacity(RX_BATCH_MAX_BYTES.min(8 * 1024));
        let mut count = 0;
        if let Some(len) = carried.take() {
            push_frame_forced(&mut batch, &scratch[..len]);
            count += 1;
        } else {
            match session.recv_blocking(&mut scratch) {
                Ok(len) => {
                    push_frame_forced(&mut batch, &scratch[..len]);
                    count += 1;
                }
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    debug!(error = %err, "WinTun session shut down; reader thread exiting");
                    return;
                }
                Err(err) => {
                    warn!(error = %err, "WinTun receive failed; reader thread exiting");
                    return;
                }
            }
        }
        while count < RX_BATCH_MAX_PACKETS {
            match session.try_recv_into(&mut scratch) {
                Ok(Some(len)) => {
                    if !push_frame(&mut batch, &scratch[..len]) {
                        carried = Some(len);
                        break;
                    }
                    count += 1;
                }
                Ok(None) => break,
                Err(err) => {
                    warn!(error = %err, "WinTun receive failed; reader thread exiting");
                    return;
                }
            }
        }
        if tx.blocking_send(batch).is_err() {
            debug!("WinTun receive queue closed; reader thread exiting");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::copy_packet;

    #[test]
    fn oversized_packet_is_rejected_instead_of_truncated() {
        let mut buf = [0u8; 4];
        assert!(copy_packet(&[0u8; 5], &mut buf).is_err());
        assert_eq!(copy_packet(&[1, 2, 3], &mut buf).expect("fits"), 3);
        assert_eq!(&buf[..3], &[1, 2, 3]);
    }
}
