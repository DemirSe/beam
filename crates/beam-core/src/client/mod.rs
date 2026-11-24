//! Client-side VLESS + REALITY + Vision + XUDP connector.
//!
//! Connects to a `beam` (or stock Xray) server over REALITY/TLS 1.3 and
//! provides:
//! - [`dial_tcp`]: Vision-framed TCP streams with raw Direct handoff.
//! - [`XudpClient`]: multiplexed UDP sessions over VLESS `Command::Mux`.

pub mod xudp;

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use rand::SeedableRng;
use rand::rngs::SmallRng;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpSocket;
use tokio::time::{Instant, timeout_at};

use crate::address::NetLocation;
use crate::reality::{RealityClientConfig, RealityClientError, build_client_connection};
use crate::tls::stream::{RawTlsHandoff, TlsStream, TlsStreamError};
use crate::vision::VisionStream;
use crate::vless::{Addons, Command, RequestHeader, ResponseHeader, VLESS_VERSION, VlessError};

pub use xudp::{XudpClient, XudpClientConfig, XudpClientError, XudpReply, XudpSession};

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const UPSTREAM_TCP_MSS: u16 = 1400;
const UPSTREAM_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const UPSTREAM_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const UPSTREAM_TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for connecting to a `beam` server.
#[derive(Clone)]
pub struct BeamClientConfig {
    /// Server TCP address (`ip:port`).
    pub server_addr: SocketAddr,
    /// REALITY client parameters (public key, short id, cover SNI).
    pub reality: RealityClientConfig,
    /// Raw 16-byte VLESS user UUID.
    pub user_id: [u8; 16],
    /// Deadline for TCP connect + REALITY TLS handshake + VLESS request write.
    pub handshake_timeout: Duration,
    /// Idle timeout for established streams and XUDP sessions.
    pub idle_timeout: Duration,
}

impl BeamClientConfig {
    /// Creates a client configuration with default timeouts (10 s handshake, 300 s idle).
    pub fn new(server_addr: SocketAddr, reality: RealityClientConfig, user_id: [u8; 16]) -> Self {
        Self {
            server_addr,
            reality,
            user_id,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

impl fmt::Debug for BeamClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BeamClientConfig")
            .field("server_addr", &self.server_addr)
            .field("reality", &self.reality)
            .field("user_id", &"<redacted>")
            .field("handshake_timeout", &self.handshake_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

/// Errors returned when dialing or operating a `beam` client connection.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A handshake stage exceeded `handshake_timeout`.
    #[error("client handshake timed out during {stage}")]
    Timeout {
        /// Handshake stage that timed out.
        stage: &'static str,
    },

    /// Underlying socket I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// REALITY ClientHello / configuration error.
    #[error("REALITY error: {0}")]
    Reality(#[from] RealityClientError),

    /// TLS handshake or record framing error.
    #[error("TLS error: {0}")]
    Tls(#[from] TlsStreamError),

    /// VLESS header encoding or response parsing error.
    #[error("VLESS error: {0}")]
    Vless(#[from] VlessError),
}

/// A Vision-framed VLESS TCP stream over a REALITY TLS connection.
pub type BeamTcpStream = VisionStream<VlessClientStream<TlsStream>>;

/// Connects to the `beam` server, performs the REALITY TLS 1.3 handshake, sends
/// a VLESS TCP + Vision request for `destination`, and returns a [`BeamTcpStream`].
pub async fn dial_tcp(
    config: &BeamClientConfig,
    destination: NetLocation,
) -> Result<BeamTcpStream, ClientError> {
    let vless = dial_vless(config, Command::Tcp, Addons::vision(), Some(destination)).await?;
    let rng = SmallRng::seed_from_u64(vision_seed());
    Ok(VisionStream::new(vless, config.user_id, Vec::new(), rng))
}

/// Connects to the `beam` server, completes the REALITY TLS 1.3 handshake, and
/// sends a VLESS request header.
pub(crate) async fn dial_vless(
    config: &BeamClientConfig,
    command: Command,
    addons: Addons<'_>,
    destination: Option<NetLocation>,
) -> Result<VlessClientStream<TlsStream>, ClientError> {
    let deadline = Instant::now() + config.handshake_timeout;

    let tcp_socket = match config.server_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    if let Err(err) = beam_sys::set_tcp_maxseg(tcp_socket.as_raw_fd(), UPSTREAM_TCP_MSS) {
        tracing::debug!(error = %err, mss = UPSTREAM_TCP_MSS, "failed to set upstream TCP_MAXSEG");
    }

    let socket = timeout_at(deadline, tcp_socket.connect(config.server_addr))
        .await
        .map_err(|_| ClientError::Timeout {
            stage: "TCP connect",
        })??;
    if let Err(err) = socket.set_nodelay(true) {
        tracing::debug!(error = %err, "failed to set upstream TCP_NODELAY");
    }
    let fd = socket.as_raw_fd();
    if let Err(err) =
        beam_sys::set_tcp_keepalive(fd, UPSTREAM_KEEPALIVE_IDLE, UPSTREAM_KEEPALIVE_INTERVAL)
    {
        tracing::debug!(error = %err, "failed to set upstream TCP keepalive");
    }
    if let Err(err) = beam_sys::set_tcp_user_timeout(fd, UPSTREAM_TCP_USER_TIMEOUT) {
        tracing::debug!(error = %err, "failed to set upstream TCP_USER_TIMEOUT");
    }

    let client_conn = build_client_connection(&config.reality)?;
    let mut tls = timeout_at(deadline, TlsStream::connect(socket, client_conn))
        .await
        .map_err(|_| ClientError::Timeout {
            stage: "REALITY TLS handshake",
        })??;

    let header = RequestHeader {
        version: VLESS_VERSION,
        user_id: config.user_id,
        addons,
        command,
        destination,
    };
    let mut encoded = Vec::with_capacity(64);
    header.encode(&mut encoded)?;

    timeout_at(deadline, tls.write_all(&encoded))
        .await
        .map_err(|_| ClientError::Timeout {
            stage: "VLESS request write",
        })??;
    timeout_at(deadline, tls.flush())
        .await
        .map_err(|_| ClientError::Timeout {
            stage: "VLESS request flush",
        })??;

    Ok(VlessClientStream::new(tls))
}

/// Strips the VLESS response header (`version(1)=0 | addons_len(1) | addons`)
/// lazily on the first read, then passes all subsequent bytes and
/// [`RawTlsHandoff`] calls directly through to the inner stream.
pub struct VlessClientStream<S> {
    inner: S,
    response_parsed: bool,
    header_buf: Vec<u8>,
    leftover: Vec<u8>,
    leftover_offset: usize,
}

impl<S> VlessClientStream<S> {
    /// Wraps `inner`, expecting a VLESS response header at the start of the
    /// read stream.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            response_parsed: false,
            header_buf: Vec::new(),
            leftover: Vec::new(),
            leftover_offset: 0,
        }
    }

    /// Returns a reference to the underlying stream.
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: AsRawFd> AsRawFd for VlessClientStream<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl<S: RawTlsHandoff> RawTlsHandoff for VlessClientStream<S> {
    fn switch_read_to_raw(&mut self) {
        self.inner.switch_read_to_raw();
    }

    fn switch_write_to_raw(&mut self) {
        self.inner.switch_write_to_raw();
    }

    fn take_plaintext(&mut self) -> Result<Vec<u8>, TlsStreamError> {
        let mut out = Vec::new();
        if self.leftover_offset < self.leftover.len() {
            out.extend_from_slice(&self.leftover[self.leftover_offset..]);
            self.leftover.clear();
            self.leftover_offset = 0;
        }
        let inner_bytes = self.inner.take_plaintext()?;
        out.extend_from_slice(&inner_bytes);
        Ok(out)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessClientStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        while !this.response_parsed {
            let mut chunk = [0u8; 258];
            let mut read_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF before VLESS response header",
                        )));
                    }
                    this.header_buf.extend_from_slice(filled);
                    match ResponseHeader::parse(&this.header_buf) {
                        Ok((_, trailing)) => {
                            if !trailing.is_empty() {
                                this.leftover.extend_from_slice(trailing);
                            }
                            this.header_buf.clear();
                            this.response_parsed = true;
                        }
                        Err(err) if err.is_truncated() => {
                            if this.header_buf.len() > 2 + 255 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "VLESS response header exceeded maximum size",
                                )));
                            }
                        }
                        Err(err) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                err,
                            )));
                        }
                    }
                }
            }
        }

        if this.leftover_offset < this.leftover.len() {
            let available = &this.leftover[this.leftover_offset..];
            let count = available.len().min(buf.remaining());
            buf.put_slice(&available[..count]);
            this.leftover_offset += count;
            if this.leftover_offset == this.leftover.len() {
                this.leftover.clear();
                this.leftover_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessClientStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn vision_seed() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    now ^ count.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}
