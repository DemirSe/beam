//! Platform-independent Layer 3 TUN device abstraction.

use std::future::Future;
use std::io;

use tokio::sync::mpsc;

/// A Layer 3 IP packet interface (Linux `/dev/net/tun`, Windows `WinTun`,
/// Android `VpnService` fd, or an in-memory test channel).
pub trait TunDevice: Send + 'static {
    /// Interface MTU in bytes (typically 1500).
    fn mtu(&self) -> usize;

    /// Receives one IP packet into `buf` and returns its byte length.
    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;

    /// Sends one complete IP packet to the OS / peer.
    fn send(&mut self, packet: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}

/// An in-memory bidirectional [`TunDevice`] pair for rootless tests.
pub struct MemoryTun {
    mtu: usize,
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
}

impl MemoryTun {
    /// Creates a connected pair of in-memory TUN devices with `capacity` queued
    /// packets in each direction.
    pub fn pair(mtu: usize, capacity: usize) -> (Self, Self) {
        let cap = capacity.max(1);
        let (tx_a, rx_b) = mpsc::channel(cap);
        let (tx_b, rx_a) = mpsc::channel(cap);
        (
            Self {
                mtu,
                rx: rx_a,
                tx: tx_a,
            },
            Self {
                mtu,
                rx: rx_b,
                tx: tx_b,
            },
        )
    }

    /// Tries to receive a packet without waiting (useful in tests).
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.rx.try_recv().ok()
    }
}

impl TunDevice for MemoryTun {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(pkt) = self.rx.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "memory tun closed",
            ));
        };
        if pkt.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet exceeds receive buffer",
            ));
        }
        buf[..pkt.len()].copy_from_slice(&pkt);
        Ok(pkt.len())
    }

    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.tx
            .send(packet.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "memory tun peer closed"))
    }
}
