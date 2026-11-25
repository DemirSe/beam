//! Client-side VLESS + REALITY + Vision + XUDP connector.
//!
//! Connects to a `beam` (or stock Xray) server over REALITY/TLS 1.3 and
//! provides:
//! - [`dial_tcp`]: Vision-framed TCP streams with raw Direct handoff.
//! - [`XudpClient`]: multiplexed UDP sessions over VLESS `Command::Mux`.

pub mod link;
pub mod xudp;

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
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

pub use link::{ClientLinkError, ParsedClientLink, parse_client_link};
pub use xudp::{XudpClient, XudpClientConfig, XudpClientError, XudpReply, XudpSession};

/// Binds a socket descriptor to the VPN transport before it connects.
///
/// Android VPN services must protect every outgoing socket, or its traffic
/// loops back into the tunnel. The hook receives the raw descriptor of the
/// unconnected socket, so it can run `VpnService.protect` through JNI. Other
/// targets leave [`BeamClientConfig::socket_protector`] as `None`.
pub type SocketProtector = Arc<dyn Fn(RawFd) -> io::Result<()> + Send + Sync>;

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const UPSTREAM_TCP_MSS: u16 = 1400;
const DEFAULT_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_KEEPALIVE_COUNT: u32 = 4;
const UPSTREAM_TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

/// Handshake stage names, shared by [`ClientError::Timeout`] and
/// [`ClientError::Io`] so callers classify a failure by stage instead of by
/// guessing from the error variant.
pub const STAGE_TCP_CONNECT: &str = "TCP connect";
/// REALITY TLS handshake stage.
pub const STAGE_REALITY_HANDSHAKE: &str = "REALITY TLS handshake";
/// VLESS request write stage.
pub const STAGE_VLESS_WRITE: &str = "VLESS request write";
/// VLESS request flush stage.
pub const STAGE_VLESS_FLUSH: &str = "VLESS request flush";

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
    /// Hook that protects the socket before it connects. `None` dials directly.
    pub socket_protector: Option<SocketProtector>,
    /// TCP keepalive idle time, or `None` to leave keepalive disabled.
    pub keepalive_idle: Option<Duration>,
    /// TCP keepalive probe interval, or `None` to leave keepalive disabled.
    pub keepalive_interval: Option<Duration>,
    /// Unanswered keepalive probes before the kernel drops the connection.
    /// `None` keeps the kernel default.
    pub keepalive_count: Option<u32>,
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
            socket_protector: None,
            keepalive_idle: Some(DEFAULT_KEEPALIVE_IDLE),
            keepalive_interval: Some(DEFAULT_KEEPALIVE_INTERVAL),
            keepalive_count: Some(DEFAULT_KEEPALIVE_COUNT),
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
            .field(
                "socket_protector",
                &self.socket_protector.as_ref().map(|_| "<socket_protector>"),
            )
            .field("keepalive_idle", &self.keepalive_idle)
            .field("keepalive_interval", &self.keepalive_interval)
            .field("keepalive_count", &self.keepalive_count)
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

    /// Underlying socket I/O error in one handshake stage.
    #[error("I/O error during {stage}: {source}")]
    Io {
        /// Handshake stage that failed.
        stage: &'static str,
        /// Underlying socket error.
        #[source]
        source: io::Error,
    },

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
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|err| ClientError::Io {
        stage: STAGE_TCP_CONNECT,
        source: err,
    })?;
    if let Err(err) = beam_sys::set_tcp_maxseg(tcp_socket.as_raw_fd(), UPSTREAM_TCP_MSS) {
        tracing::debug!(error = %err, mss = UPSTREAM_TCP_MSS, "failed to set upstream TCP_MAXSEG");
    }
    // The protector must run before `connect`, or the connect leaves the VPN
    // through the tunnel it is meant to serve.
    if let Some(protector) = &config.socket_protector {
        protector(tcp_socket.as_raw_fd()).map_err(|err| ClientError::Io {
            stage: STAGE_TCP_CONNECT,
            source: err,
        })?;
    }

    let socket = timeout_at(deadline, tcp_socket.connect(config.server_addr))
        .await
        .map_err(|_| ClientError::Timeout {
            stage: STAGE_TCP_CONNECT,
        })?
        .map_err(|err| ClientError::Io {
            stage: STAGE_TCP_CONNECT,
            source: err,
        })?;
    if let Err(err) = socket.set_nodelay(true) {
        tracing::debug!(error = %err, "failed to set upstream TCP_NODELAY");
    }
    let fd = socket.as_raw_fd();
    if let Some(count) = config.keepalive_count
        && let Err(err) = beam_sys::set_tcp_keepcnt(fd, count)
    {
        tracing::debug!(error = %err, count, "failed to set upstream TCP_KEEPCNT");
    }
    if config.keepalive_idle.is_some() != config.keepalive_interval.is_some() {
        tracing::debug!(
            idle = ?config.keepalive_idle,
            interval = ?config.keepalive_interval,
            "partial TCP keepalive config; keepalive stays disabled unless idle and interval are both set",
        );
    }
    if let (Some(idle), Some(interval)) = (config.keepalive_idle, config.keepalive_interval)
        && let Err(err) = beam_sys::set_tcp_keepalive(fd, idle, interval)
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
            stage: STAGE_REALITY_HANDSHAKE,
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
            stage: STAGE_VLESS_WRITE,
        })?
        .map_err(|err| ClientError::Io {
            stage: STAGE_VLESS_WRITE,
            source: err,
        })?;
    timeout_at(deadline, tls.flush())
        .await
        .map_err(|_| ClientError::Timeout {
            stage: STAGE_VLESS_FLUSH,
        })?
        .map_err(|err| ClientError::Io {
            stage: STAGE_VLESS_FLUSH,
            source: err,
        })?;

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

/// Returns a fresh Vision padding RNG seed from the system CSPRNG, so the
/// padding of one connection does not predict the next. A failed RNG read
/// falls back to the system clock and counter instead of panicking.
fn vision_seed() -> u64 {
    static RNG: std::sync::OnceLock<&'static dyn rustls::crypto::SecureRandom> =
        std::sync::OnceLock::new();
    let rng = *RNG.get_or_init(|| rustls::crypto::aws_lc_rs::default_provider().secure_random);
    let mut buf = [0u8; 8];
    if rng.fill(&mut buf).is_ok() {
        return u64::from_be_bytes(buf);
    }
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    now ^ count.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

#[cfg(test)]
mod tests {
    use super::{
        Addons, BeamClientConfig, Command, DEFAULT_KEEPALIVE_COUNT, DEFAULT_KEEPALIVE_IDLE,
        DEFAULT_KEEPALIVE_INTERVAL, dial_vless, vision_seed,
    };
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::os::fd::AsRawFd;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use crate::reality::RealityClientConfig;

    const USER_ID: [u8; 16] = [0xaa; 16];

    fn config(server_addr: SocketAddr) -> BeamClientConfig {
        let reality = RealityClientConfig::new([0x37; 32], "0123456789abcdef", "whatsapp.net")
            .expect("test reality config");
        let mut config = BeamClientConfig::new(server_addr, reality, USER_ID);
        config.handshake_timeout = Duration::from_secs(2);
        config
    }

    async fn loopback_listener() -> TcpListener {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback listener")
    }

    #[tokio::test]
    async fn socket_protector_runs_before_connect_with_a_valid_fd() {
        let listener = loopback_listener().await;
        let server_addr = listener.local_addr().expect("listener address");

        let events = Arc::new(Mutex::new(Vec::<(&'static str, i32)>::new()));
        let accept_events = Arc::clone(&events);
        let accept_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept protected dial");
            accept_events
                .lock()
                .expect("events lock")
                .push(("accept", socket.as_raw_fd()));
            // Closing right away makes the REALITY handshake fail fast.
        });

        let protect_events = Arc::clone(&events);
        let mut client = config(server_addr);
        client.socket_protector = Some(Arc::new(move |fd| {
            assert!(
                fd > 2,
                "protector must see a live socket descriptor, got {fd}"
            );
            protect_events
                .lock()
                .expect("events lock")
                .push(("protect", fd));
            Ok(())
        }));

        let _ = dial_vless(&client, Command::Tcp, Addons::vision(), None).await;
        accept_task.await.expect("accept task join");

        let events = events.lock().expect("events lock").clone();
        // A correct implementation records `protect` synchronously before it
        // calls `connect`, and no accept can precede the connect call.
        assert_eq!(events.len(), 2, "unexpected events: {events:?}");
        assert_eq!(events[0].0, "protect", "unexpected events: {events:?}");
        assert_eq!(events[1].0, "accept", "unexpected events: {events:?}");
    }

    #[tokio::test]
    async fn protector_failure_aborts_before_connect() {
        let listener = loopback_listener().await;
        let server_addr = listener.local_addr().expect("listener address");

        let mut client = config(server_addr);
        client.socket_protector = Some(Arc::new(|_fd| {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "blocked"))
        }));

        let error = dial_vless(&client, Command::Tcp, Addons::vision(), None)
            .await
            .err()
            .expect("a failing protector must abort the dial");
        match error {
            super::ClientError::Io { stage, source } => {
                assert_eq!(stage, super::STAGE_TCP_CONNECT);
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // The protector failed before `connect`, so nothing reached the listener.
        assert!(
            timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "the dial must not connect after a failed protector"
        );
    }

    #[test]
    fn default_config_enables_keepalive_and_has_no_protector() {
        let client = config(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        assert!(client.socket_protector.is_none());
        assert_eq!(client.keepalive_idle, Some(DEFAULT_KEEPALIVE_IDLE));
        assert_eq!(client.keepalive_interval, Some(DEFAULT_KEEPALIVE_INTERVAL));
        assert_eq!(client.keepalive_count, Some(DEFAULT_KEEPALIVE_COUNT));
    }

    #[test]
    fn debug_prints_the_protector_without_its_closure() {
        let mut client = config(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        assert!(format!("{client:?}").contains("socket_protector: None"));
        client.socket_protector = Some(Arc::new(|_fd| Ok(())));
        let rendered = format!("{client:?}");
        assert!(
            rendered.contains("socket_protector: Some(\"<socket_protector>\")"),
            "{rendered}"
        );
    }

    #[test]
    fn vision_seed_is_not_constant_across_connections() {
        let first = vision_seed();
        let mut distinct = 0;
        for _ in 0..64 {
            if vision_seed() != first {
                distinct += 1;
            }
        }
        assert!(
            distinct >= 32,
            "vision seed looks constant: {distinct}/64 differ"
        );
    }
}
