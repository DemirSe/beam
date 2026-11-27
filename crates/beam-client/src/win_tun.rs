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
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Tunnel type recorded on the adapter, so Device Manager groups it under beam.
const TUNNEL_TYPE: &str = "Beam";

/// Packets queued between the reader thread and the async receiver.
const RX_QUEUE_CAPACITY: usize = 256;

/// Async handle to a WinTun adapter and its Layer 3 session.
pub struct AsyncWinTun {
    session: Arc<WinTunSession>,
    shutdown: WinTunShutdown,
    name: String,
    mtu: usize,
    /// `None` once [`Drop`] closed the queue to release a blocked reader.
    rx: Option<mpsc::Receiver<Vec<u8>>>,
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
        let Some(queue) = self.rx.as_mut() else {
            return Err(closed());
        };
        let Some(packet) = queue.recv().await else {
            return Err(closed());
        };
        copy_packet(&packet, buf)
    }

    fn try_recv_into(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(queue) = self.rx.as_mut() else {
            return Ok(None);
        };
        match queue.try_recv() {
            Ok(packet) => copy_packet(&packet, buf).map(Some),
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

/// Forwards packets from the WinTun ring into the bounded async queue.
///
/// The thread exits on shutdown, on a closed queue, or on the first receive
/// error; a dead session cannot recover, and `recv` then reports end of file.
fn receive_loop(session: &WinTunSession, tx: mpsc::Sender<Vec<u8>>) {
    let mut scratch = vec![0u8; MAX_PACKET_LEN];
    loop {
        match session.recv_blocking(&mut scratch) {
            Ok(len) => {
                if tx.blocking_send(scratch[..len].to_vec()).is_err() {
                    debug!("WinTun receive queue closed; reader thread exiting");
                    return;
                }
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
