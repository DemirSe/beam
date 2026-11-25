//! Async [`TunDevice`] over the descriptor that `VpnService` detached.

use std::io;

use beam_sys::LinuxTun;
use beam_tun::TunDevice;
use tokio::io::unix::AsyncFd;

/// Tokio adapter around [`LinuxTun`] for a started `VpnService` tunnel.
pub struct AndroidTun {
    inner: AsyncFd<LinuxTun>,
    mtu: usize,
}

impl AndroidTun {
    /// Registers `tun` with the current Tokio runtime, which must already be
    /// running.
    pub fn new(tun: LinuxTun, mtu: usize) -> io::Result<Self> {
        // The deprecated constructor keeps this crate free of `unsafe`:
        // `LinuxTun` owns its descriptor for the wrapper's whole lifetime, so
        // the registration cannot outlive the descriptor it refers to.
        #[allow(deprecated)]
        let inner = AsyncFd::new(tun)?;
        Ok(Self { inner, mtu })
    }

    /// Returns the interface name that `VpnService.Builder` created.
    pub fn name(&self) -> &str {
        self.inner.get_ref().name()
    }
}

impl TunDevice for AndroidTun {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.inner.get_ref().read_packet(buf) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => return Ok(n),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err),
            }
        }
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read_packet(buf)) {
                Ok(Ok(0)) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }

    fn try_recv_into(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        loop {
            match self.inner.get_ref().read_packet(buf) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => return Ok(Some(n)),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(err) => return Err(err),
            }
        }
    }

    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        loop {
            match self.inner.get_ref().write_packet(packet) {
                Ok(_) => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err),
            }
        }
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().write_packet(packet)) {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(err)) => return Err(err),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    /// Builds a TUN over one end of a socket pair, standing in for the
    /// `VpnService` descriptor on host tests.
    fn socketpair_tun(mtu: usize) -> (AndroidTun, UnixStream) {
        let (local, peer) = UnixStream::pair().expect("socketpair");
        let tun =
            LinuxTun::from_detached_fd(local.into_raw_fd(), "tun0").expect("detached descriptor");
        let tun = AndroidTun::new(tun, mtu).expect("registered TUN");
        (tun, peer)
    }

    #[tokio::test]
    async fn send_writes_a_packet_to_the_descriptor() {
        let (mut tun, mut peer) = socketpair_tun(1500);
        assert_eq!(tun.mtu(), 1500);
        assert_eq!(tun.name(), "tun0");

        tun.send(b"ip-packet").await.expect("send");

        let mut received = [0_u8; 16];
        let n = peer.read(&mut received).expect("peer read");
        assert_eq!(&received[..n], b"ip-packet");
    }

    #[tokio::test]
    async fn recv_reads_a_packet_and_try_recv_is_non_blocking() {
        let (mut tun, mut peer) = socketpair_tun(1500);

        assert!(
            tun.try_recv_into(&mut [0_u8; 64])
                .expect("try_recv")
                .is_none(),
            "no packet is queued yet"
        );

        peer.write_all(b"inbound").expect("peer write");
        let mut buf = [0_u8; 64];
        let n = tun.recv(&mut buf).await.expect("recv");
        assert_eq!(&buf[..n], b"inbound");
    }
}
