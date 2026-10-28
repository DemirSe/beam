//! REALITY TLS server adapter.
//!
//! One TLS record is read before rustls is involved. The record is parsed and
//! authenticated as a REALITY ClientHello. Authenticated connections are handed
//! to rustls through a [`ReplayStream`] that replays the original record.
//! Unauthenticated connections are forwarded byte-for-byte to the configured
//! cover. The adapter implements the TLS handshake, a minimal TCP VLESS path,
//! and XTLS Vision framing, including the raw inner-TLS handoff on Vision
//! Direct. XUDP mux streams are relayed through [`crate::xudp`], legacy VLESS
//! UDP and packetaddr through [`crate::udp`], and reverse streams remain out
//! of scope.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpSocket, TcpStream, lookup_host};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::address::{Address, NetLocation};
use crate::admission::{IpLimiter, IpPermit};
use crate::prepend_stream::PrependStream;
use crate::reality::{Auth, RealityAuthConfig, authenticate};
use crate::relay::{RelayActivity, RelayConfig, copy_bidirectional, copy_one_way};
use crate::tls::stream::{TlsStream, TlsStreamError};
use crate::tls::{ClientHello, MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN};
use crate::udp::{LegacyUdpConfig, UdpError, handle_udp_stream};
use crate::vision::VisionStream;
use crate::vless::{Command, MAX_REQUEST_HEADER_LEN, RequestHeader, ResponseHeader, VlessError};
use crate::xudp::{
    DEFAULT_MAX_GLOBAL_SESSIONS, MuxError, XudpConfig, XudpSessionLimiter, handle_mux_stream,
};

/// Idle timeout for each relay read, write, and shutdown.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Idle timeout for unauthenticated cover relays.
///
/// Cover connections are not authenticated and must not pin a blocking splice
/// thread for the full VPN idle timeout. A slow cover handshake or an idle
/// probe is closed after this bound.
const COVER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of unauthenticated cover relays in flight at once.
///
/// Cover relays and authenticated Vision Direct relays share the process
/// blocking pool. A cover flood must not be able to occupy that pool and
/// starve the VPN data path. The limit is global rather than per-IP because
/// the deployment intentionally does not filter by client address.
const COVER_MAX_CONCURRENCY: usize = 32;

/// Maximum unauthenticated cover relays from one source address.
///
/// The global cap bounds the shared blocking pool; the per-source cap prevents
/// one scanner from consuming every cover slot during a probe burst.
const COVER_MAX_PER_IP: u32 = 8;

/// Maximum time a connection may hold a pre-auth slot for its ClientHello.
///
/// This is intentionally shorter than the full TLS/VLESS handshake timeout: an
/// unauthenticated peer should not be able to pin admission capacity for the
/// deployment's 10 s handshake budget.
const PREAUTH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on a destination TCP dial. The server is normally a datacenter
/// hop away from the target; a blackholed address should not hold a permit for
/// the full client handshake budget.
const MAX_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP maximum segment size used for destination connections.
///
/// The production path to some CDN prefixes has a 1460-byte PMTU but
/// advertises a 1500-byte MSS and drops larger packets without returning ICMP
/// fragmentation-needed. Setting this before connect limits both the MSS
/// advertised in our SYN and the local send size, so downloads and uploads
/// stay below that path MTU. 1400 leaves room for TCP timestamps and the
/// IP/TCP headers.
const TARGET_MSS: u16 = 1400;

/// Bound on remembered authenticated ClientHello session ids.
const REPLAY_CACHE_CAPACITY: usize = 4_096;

/// Retention for one replay-cache entry.
const REPLAY_CACHE_TTL: Duration = Duration::from_secs(60);

/// Bounded exact-replay filter for authenticated ClientHellos.
///
/// The key is the encrypted 32-byte REALITY session id. It is not a secret and
/// is not logged; the cache never stores a ClientHello, key share, or auth key.
struct ReplayCache {
    entries: HashMap<[u8; 32], Instant>,
    order: VecDeque<[u8; 32]>,
    ttl: Duration,
}

impl ReplayCache {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(REPLAY_CACHE_CAPACITY),
            order: VecDeque::with_capacity(REPLAY_CACHE_CAPACITY),
            ttl,
        }
    }

    /// Returns `true` if this id was seen within the TTL; otherwise records it.
    fn seen_before(&mut self, id: [u8; 32]) -> bool {
        let now = Instant::now();
        while let Some(front) = self.order.front().copied() {
            let expired = self
                .entries
                .get(&front)
                .is_none_or(|seen| now.duration_since(*seen) >= self.ttl);
            if !expired {
                break;
            }
            self.order.pop_front();
            self.entries.remove(&front);
        }

        if self.entries.contains_key(&id) {
            return true;
        }
        if self.entries.len() >= REPLAY_CACHE_CAPACITY
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(id, now);
        self.order.push_back(id);
        false
    }
}

/// Relay buffer large enough for one maximum-size inner TLS record, including
/// its five-byte header.
const RELAY_BUFFER_LEN: usize = 16_384 + 256 + 5;

/// Result of one accepted connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionOutcome {
    /// The connection was not authenticated and was forwarded to the cover.
    CoverForwarded,
    /// The connection was not authenticated and was closed because the cover
    /// concurrency limit was reached.
    CoverLimited,
    /// The REALITY handshake succeeded but the authenticated connection limit
    /// was already in use.
    ConnectionLimited,
    /// The REALITY handshake succeeded and the VLESS command was observed.
    Authenticated {
        /// The VLESS command from the request.
        command: Command,
    },
}

/// Errors returned by the TLS server adapter.
#[derive(Debug, thiserror::Error)]
pub enum TlsServerError {
    /// The server configuration is invalid.
    #[error("invalid TLS server configuration: {reason}")]
    InvalidConfig {
        /// Why the configuration was rejected.
        reason: &'static str,
    },

    /// A bounded buffer could not be allocated.
    #[error("TLS server buffer allocation failed")]
    Allocation,

    /// The temporary Ed25519 certificate could not be generated or parsed.
    #[error("temporary REALITY certificate generation failed")]
    Certificate,

    /// HMAC initialization or output conversion failed.
    #[error("REALITY certificate HMAC failed")]
    Hmac,

    /// A network operation timed out.
    #[error("{stage} timed out")]
    Timeout {
        /// The operation that timed out.
        stage: &'static str,
    },

    /// The declared ClientHello record exceeds the configured limit.
    #[error("ClientHello record length {length} exceeds the {max}-byte limit")]
    ClientHelloTooLarge {
        /// Total record length including the five-byte header.
        length: usize,
        /// Configured maximum.
        max: usize,
    },

    /// An authenticated TCP request had no destination.
    #[error("authenticated VLESS TCP request has no destination")]
    MissingDestination,

    /// The VLESS user id did not match the configured user.
    #[error("VLESS user id is not authorized")]
    UnauthorizedUser,

    /// rustls rejected a configuration or handshake.
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// The record-bounded TLS stream failed.
    #[error("TLS stream error: {0}")]
    TlsStream(#[from] TlsStreamError),

    /// A network or TLS stream I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The VLESS request was malformed or truncated.
    #[error("VLESS request error: {0}")]
    Vless(#[from] VlessError),

    /// The legacy UDP or packetaddr stream failed.
    #[error("VLESS UDP error: {0}")]
    Udp(#[from] UdpError),

    /// The process-wide legacy UDP stream limit is already in use.
    #[error("legacy VLESS UDP stream limit reached")]
    LegacyUdpLimited,

    /// A Vision request asked for legacy UDP.
    #[error("VLESS UDP with the Vision flow is not supported; clients must use XUDP")]
    VisionUdpUnsupported,

    /// The XUDP mux stream failed.
    #[error("XUDP mux error: {0}")]
    Xudp(#[from] MuxError),
}

/// Process-lifetime REALITY TLS server configuration.
pub struct TlsServerConfig {
    /// REALITY static X25519 private key.
    pub private_key: Zeroizing<[u8; 32]>,
    /// Configured REALITY short ids as hex strings.
    pub short_ids: Vec<String>,
    /// Accepted REALITY server names.
    pub server_names: Vec<String>,
    /// Minimum accepted client version.
    pub min_client_version: [u8; 3],
    /// Maximum accepted client version.
    pub max_client_version: [u8; 3],
    /// Optional client timestamp window.
    pub max_time_diff: Option<Duration>,
    /// Cover destination for unauthenticated connections.
    pub cover: NetLocation,
    /// Timeout for ClientHello reads, cover setup, and the TLS handshake.
    pub handshake_timeout: Duration,
    /// Inactivity timeout for authenticated TCP relays.
    pub relay_idle_timeout: Duration,
    /// Maximum total ClientHello record size, including its five-byte header.
    pub max_client_hello_bytes: usize,
    /// The only authorized VLESS user id.
    pub user_id: [u8; 16],
    /// XUDP mux/UDP relay limits.
    pub xudp: XudpConfig,
    /// Process-wide XUDP session limiter shared by every mux stream.
    xudp_limiter: XudpSessionLimiter,
    /// Legacy VLESS UDP and packetaddr limits.
    pub udp: LegacyUdpConfig,
    provider: Arc<CryptoProvider>,
    certificate: TemporaryCertificate,
    /// Global cap on authenticated connections. The accept loop bounds
    /// unauthenticated handshakes separately, so a pre-auth flood cannot
    /// exhaust this permit pool.
    connection_permits: Arc<Semaphore>,
    /// Process-wide cap on blocking Vision splice tasks.
    ///
    /// `spawn_blocking` has no queue deadline; once Tokio's blocking pool is
    /// full, a handoff waits forever and the connection silently stops
    /// forwarding. Keep a reserve for cover relays and DNS, and fall back to
    /// the async copy path when this cap is reached.
    splice_permits: Arc<Semaphore>,
    /// Global cap on legacy VLESS UDP / packetaddr streams.
    legacy_udp_permits: Arc<Semaphore>,
    /// Global and per-source cap on unauthenticated cover relays.
    cover_limiter: Arc<IpLimiter>,
    /// Bounded exact-replay filter for authenticated ClientHellos.
    replay_cache: Mutex<ReplayCache>,
}

impl TlsServerConfig {
    /// Builds a server configuration and generates the process-lifetime
    /// Ed25519 certificate.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        private_key: [u8; 32],
        short_ids: Vec<String>,
        server_names: Vec<String>,
        min_client_version: [u8; 3],
        max_client_version: [u8; 3],
        max_time_diff: Option<Duration>,
        cover: NetLocation,
        handshake_timeout: Duration,
        max_client_hello_bytes: usize,
        user_id: [u8; 16],
    ) -> Result<Self, TlsServerError> {
        if handshake_timeout.is_zero() {
            return Err(TlsServerError::InvalidConfig {
                reason: "handshake timeout must be non-zero",
            });
        }
        if !(TLS_RECORD_HEADER_LEN..=TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN)
            .contains(&max_client_hello_bytes)
        {
            return Err(TlsServerError::InvalidConfig {
                reason: "max ClientHello size is outside the TLS record bounds",
            });
        }
        if cover.port == 0 {
            return Err(TlsServerError::InvalidConfig {
                reason: "cover port must be non-zero",
            });
        }

        Ok(Self {
            private_key: Zeroizing::new(private_key),
            short_ids,
            server_names,
            min_client_version,
            max_client_version,
            max_time_diff,
            cover,
            handshake_timeout,
            relay_idle_timeout: RELAY_IDLE_TIMEOUT,
            max_client_hello_bytes,
            user_id,
            xudp: XudpConfig::default(),
            xudp_limiter: XudpSessionLimiter::new(DEFAULT_MAX_GLOBAL_SESSIONS),
            udp: LegacyUdpConfig::default(),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            certificate: TemporaryCertificate::generate()?,
            connection_permits: Arc::new(Semaphore::new(Semaphore::MAX_PERMITS)),
            splice_permits: Arc::new(Semaphore::new(Semaphore::MAX_PERMITS)),
            legacy_udp_permits: Arc::new(Semaphore::new(Semaphore::MAX_PERMITS)),
            cover_limiter: Arc::new(IpLimiter::new(COVER_MAX_CONCURRENCY, COVER_MAX_PER_IP)),
            replay_cache: Mutex::new(ReplayCache::new(REPLAY_CACHE_TTL)),
        })
    }

    /// Overrides the XUDP mux limits used for `Command::Mux` connections.
    #[must_use]
    pub fn with_xudp(mut self, xudp: XudpConfig) -> Self {
        self.xudp = xudp;
        self
    }

    /// Overrides the authenticated connection limiter.
    ///
    /// The accept loop holds a separate, smaller pre-auth permit until the
    /// REALITY ClientHello is classified. This semaphore is acquired only
    /// after authentication, so unauthenticated half-open connections cannot
    /// consume the VPN's data-path capacity.
    #[must_use]
    pub fn with_connection_limiter(mut self, permits: Arc<Semaphore>) -> Self {
        self.connection_permits = permits;
        self
    }

    /// Overrides the process-wide blocking splice task limit.
    #[must_use]
    pub fn with_splice_limiter(mut self, permits: Arc<Semaphore>) -> Self {
        self.splice_permits = permits;
        self
    }

    /// Overrides the process-wide legacy UDP stream limit.
    #[must_use]
    pub fn with_legacy_udp_limiter(mut self, permits: Arc<Semaphore>) -> Self {
        self.legacy_udp_permits = permits;
        self
    }

    /// Overrides the process-wide XUDP session limiter.
    #[must_use]
    pub fn with_xudp_limiter(mut self, limiter: XudpSessionLimiter) -> Self {
        self.xudp_limiter = limiter;
        self
    }

    /// Overrides the legacy UDP limits used for `Command::Udp` connections.
    #[must_use]
    pub fn with_udp(mut self, udp: LegacyUdpConfig) -> Self {
        self.udp = udp;
        self
    }

    /// Overrides the inactivity timeout for authenticated TCP relays.
    #[must_use]
    pub fn with_relay_idle_timeout(mut self, timeout: Duration) -> Self {
        self.relay_idle_timeout = timeout;
        self
    }

    fn reality_config(&self) -> RealityAuthConfig<'_> {
        RealityAuthConfig {
            private_key: &self.private_key,
            short_ids: &self.short_ids,
            server_names: &self.server_names,
            min_client_version: self.min_client_version,
            max_client_version: self.max_client_version,
            max_time_diff: self.max_time_diff,
        }
    }

    fn replay_seen(&self, id: [u8; 32]) -> bool {
        match self.replay_cache.lock() {
            Ok(mut cache) => cache.seen_before(id),
            Err(poisoned) => poisoned.into_inner().seen_before(id),
        }
    }

    fn signed_certificate(&self, auth_key: &[u8]) -> Result<Vec<u8>, TlsServerError> {
        let mut certificate = self.certificate.certificate_der.clone();
        let signature_offset = certificate
            .len()
            .checked_sub(64)
            .ok_or(TlsServerError::Certificate)?;
        let signature = hmac_signature(auth_key, &self.certificate.public_key)?;
        certificate[signature_offset..].copy_from_slice(&signature);
        Ok(certificate)
    }

    fn build_server_config(&self, auth_key: &[u8]) -> Result<rustls::ServerConfig, TlsServerError> {
        let certificate = self.signed_certificate(auth_key)?;
        let chain = vec![CertificateDer::from(certificate)];
        // The Ed25519 key and certificate are generated together once at
        // startup. Only the certificate signature changes per connection, so
        // reusing the parsed signing key avoids a private-key parse and an
        // Ed25519 sign/verify `keys_match` on every handshake.
        let certified = CertifiedKey::new(chain, Arc::clone(&self.certificate.signing_key));

        let mut config = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(TlsServerError::Rustls)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
        // Stock REALITY does not issue TLS 1.3 session tickets. Disabling them
        // avoids extra post-handshake records and keeps the authenticated
        // flight closer to the cover.
        config.send_tls13_tickets = 0;
        Ok(config)
    }
}

/// Ed25519 signing key that ignores the client's `signature_algorithms` list.
///
/// The stock Xray Chrome fingerprint does not offer Ed25519, but REALITY still
/// sends an Ed25519 temporary certificate and the stock client accepts its
/// CertificateVerify signature. Rustls normally rejects this with
/// `NoSignatureSchemesInCommon`, so force the scheme to match stock behavior.
#[derive(Debug)]
struct RealitySigningKey {
    inner: Arc<dyn SigningKey>,
}

impl SigningKey for RealitySigningKey {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.inner.choose_scheme(&[SignatureScheme::ED25519])
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
}

impl fmt::Debug for TlsServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsServerConfig")
            .field("private_key", &"<redacted>")
            .field("short_ids", &"<redacted>")
            .field("server_names", &self.server_names)
            .field("min_client_version", &self.min_client_version)
            .field("max_client_version", &self.max_client_version)
            .field("max_time_diff", &self.max_time_diff)
            .field("cover", &self.cover)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("relay_idle_timeout", &self.relay_idle_timeout)
            .field("max_client_hello_bytes", &self.max_client_hello_bytes)
            .field("xudp", &self.xudp)
            .field("xudp_limiter", &self.xudp_limiter)
            .field("udp", &self.udp)
            .field("cover_max_concurrency", &COVER_MAX_CONCURRENCY)
            .field("cover_max_per_ip", &COVER_MAX_PER_IP)
            .field("splice_available", &self.splice_permits.available_permits())
            .field(
                "legacy_udp_available",
                &self.legacy_udp_permits.available_permits(),
            )
            .finish()
    }
}

struct TemporaryCertificate {
    certificate_der: Vec<u8>,
    public_key: [u8; 32],
    signing_key: Arc<dyn SigningKey>,
}

impl TemporaryCertificate {
    fn generate() -> Result<Self, TlsServerError> {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|_| TlsServerError::Certificate)?;
        let params = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|_| TlsServerError::Certificate)?;
        let certificate = params
            .self_signed(&key_pair)
            .map_err(|_| TlsServerError::Certificate)?;
        let public_key = key_pair
            .public_key_raw()
            .try_into()
            .map_err(|_| TlsServerError::Certificate)?;
        let private_key_der = Zeroizing::new(key_pair.serialize_der());
        let parsed = PrivatePkcs8KeyDer::from(private_key_der.to_vec());
        let inner = rustls::crypto::aws_lc_rs::sign::any_eddsa_type(&parsed)
            .map_err(TlsServerError::Rustls)?;

        Ok(Self {
            certificate_der: certificate.der().to_vec(),
            public_key,
            signing_key: Arc::new(RealitySigningKey { inner }),
        })
    }
}

fn hmac_signature(auth_key: &[u8], public_key: &[u8; 32]) -> Result<[u8; 64], TlsServerError> {
    let mut mac = Hmac::<Sha512>::new_from_slice(auth_key).map_err(|_| TlsServerError::Hmac)?;
    mac.update(public_key);
    Ok(mac.finalize().into_bytes().into())
}

/// A stream that serves a prefix buffer before reading from the underlying
/// socket. Used to replay the already-consumed ClientHello record to rustls.
pub struct ReplayStream {
    prefix: Vec<u8>,
    offset: usize,
    stream: TcpStream,
}

impl ReplayStream {
    /// Wraps `stream` and serves `prefix` before any bytes read from the socket.
    pub fn new(stream: TcpStream, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            offset: 0,
            stream,
        }
    }
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.offset < this.prefix.len() {
            let remaining = &this.prefix[this.offset..];
            let count = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..count]);
            this.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

/// Handles one accepted TCP connection without a pre-auth permit.
///
/// This is the compatibility entry point used by tests and embedders. The
/// production accept loop uses [`handle_connection_admitted`] so a pre-auth
/// flood is bounded separately from authenticated capacity.
pub async fn handle_connection(
    stream: TcpStream,
    config: Arc<TlsServerConfig>,
) -> Result<ConnectionOutcome, TlsServerError> {
    handle_connection_admitted(stream, config, None).await
}

/// Handles one accepted TCP connection.
///
/// `preauth` is held only until the ClientHello is classified. An
/// authenticated connection then acquires a separate connection permit; an
/// unauthenticated probe releases the pre-auth permit before it is forwarded
/// to the cover, whose own concurrency cap bounds it.
pub async fn handle_connection_admitted(
    mut stream: TcpStream,
    config: Arc<TlsServerConfig>,
    preauth: Option<IpPermit>,
) -> Result<ConnectionOutcome, TlsServerError> {
    let read = read_client_hello_record(&mut stream, &config).await?;
    let record = match read {
        ClientHelloRead::Complete(record) => record,
        ClientHelloRead::Forward(prefix) => {
            drop(preauth);
            if prefix.is_empty() {
                return Ok(ConnectionOutcome::CoverForwarded);
            }
            return forward_to_cover(stream, &prefix, &config).await;
        }
    };
    let auth = match ClientHello::parse(&record) {
        Ok(hello) => match authenticate(&hello, &config.reality_config()) {
            Ok(auth) => {
                let mut session_id = [0u8; 32];
                if hello.session_id.len() != session_id.len() {
                    None
                } else {
                    session_id.copy_from_slice(hello.session_id);
                    if config.replay_seen(session_id) {
                        tracing::debug!("authenticated ClientHello replay; forwarding to cover");
                        None
                    } else {
                        Some(auth)
                    }
                }
            }
            Err(error) => {
                tracing::debug!(%error, "REALITY authentication failed; forwarding to cover");
                None
            }
        },
        Err(error) => {
            tracing::debug!(%error, "ClientHello parse failed; forwarding to cover");
            None
        }
    };

    match auth {
        Some(auth) => {
            let permit = match Arc::clone(&config.connection_permits).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    tracing::debug!("authenticated connection limit reached; closing");
                    return Ok(ConnectionOutcome::ConnectionLimited);
                }
            };
            drop(preauth);
            handle_authenticated(stream, record, auth, &config, permit).await
        }
        None => {
            drop(preauth);
            forward_to_cover(stream, &record, &config).await
        }
    }
}

/// Result of reading the initial bytes from a connection.
enum ClientHelloRead {
    /// A complete TLS record was read and should be parsed.
    Complete(Vec<u8>),
    /// The peer did not send a plausible, complete ClientHello. Forward the
    /// bytes already read (possibly only the five-byte header) to the cover,
    /// then relay the rest byte-for-byte.
    Forward(Vec<u8>),
}

fn is_plausible_tls_record_header(header: &[u8; TLS_RECORD_HEADER_LEN]) -> bool {
    header[0] == 0x16 && header[1] == 0x03 && matches!(header[2], 0x01 | 0x03)
}

/// Reads the initial TLS record.
///
/// A non-TLS prefix or an over-limit record is returned immediately so a
/// prober sees the cover respond instead of beam waiting for a body that will
/// never arrive. If the peer stalls or closes mid-record, the bytes already
/// received are forwarded to the cover too.
async fn read_client_hello_record(
    stream: &mut TcpStream,
    config: &TlsServerConfig,
) -> Result<ClientHelloRead, TlsServerError> {
    // One absolute deadline covers both the five-byte header and the declared
    // body. Per-read timeouts would let a patient peer hold a pre-auth slot for
    // twice the configured handshake budget.
    let deadline = Instant::now() + config.handshake_timeout.min(PREAUTH_HANDSHAKE_TIMEOUT);
    let mut header = [0u8; TLS_RECORD_HEADER_LEN];
    let mut filled = 0usize;

    while filled < header.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(ClientHelloRead::Forward(header[..filled].to_vec()));
        }
        let read = match timeout(remaining, stream.read(&mut header[filled..])).await {
            Err(_) => return Ok(ClientHelloRead::Forward(header[..filled].to_vec())),
            Ok(read) => read,
        };
        match read {
            Ok(0) => return Ok(ClientHelloRead::Forward(header[..filled].to_vec())),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(TlsServerError::Io(error)),
        }
    }

    // HTTP, SSH, random junk, and records too large for the configured bound
    // are not ClientHellos. Give the cover the header now; the client may
    // already have sent more bytes and the splice will carry them.
    let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let total = TLS_RECORD_HEADER_LEN.saturating_add(record_len);
    if !is_plausible_tls_record_header(&header) || total > config.max_client_hello_bytes {
        return Ok(ClientHelloRead::Forward(header.to_vec()));
    }

    let mut record = Vec::new();
    record
        .try_reserve_exact(total)
        .map_err(|_| TlsServerError::Allocation)?;
    record.extend_from_slice(&header);
    record.resize(total, 0);
    filled = TLS_RECORD_HEADER_LEN;

    while filled < total {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            record.truncate(filled);
            return Ok(ClientHelloRead::Forward(record));
        }
        let read = match timeout(remaining, stream.read(&mut record[filled..])).await {
            Err(_) => {
                record.truncate(filled);
                return Ok(ClientHelloRead::Forward(record));
            }
            Ok(read) => read,
        };
        match read {
            Ok(0) => {
                record.truncate(filled);
                return Ok(ClientHelloRead::Forward(record));
            }
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(TlsServerError::Io(error)),
        }
    }

    Ok(ClientHelloRead::Complete(record))
}

/// Returns whether a VLESS flow value is supported.
///
/// Stock accepts an absent or explicitly empty flow (no Vision) and rejects
/// unknown non-empty values.
fn is_supported_flow(flow: Option<&str>) -> bool {
    flow.is_none_or(|flow| flow.is_empty() || flow == crate::vless::VISION_FLOW)
}

/// Returns the account UUID used for lookup.
///
/// Stock Xray zeroes bytes 6-7 of the wire UUID before matching the account;
/// those bytes carry `vlessRoute` and are not part of the identity. The raw
/// bytes are still used as the Vision request prefix.
fn account_id(user_id: &[u8; 16]) -> [u8; 16] {
    let mut account = *user_id;
    account[6] = 0;
    account[7] = 0;
    account
}

async fn handle_authenticated(
    stream: TcpStream,
    record: Vec<u8>,
    auth: Auth,
    config: &TlsServerConfig,
    _connection_permit: OwnedSemaphorePermit,
) -> Result<ConnectionOutcome, TlsServerError> {
    let server_config = Arc::new(config.build_server_config(&auth.auth_key[..])?);
    let connection =
        rustls::ServerConnection::new(server_config).map_err(TlsServerError::Rustls)?;
    let mut tls = timeout(
        config.handshake_timeout,
        TlsStream::accept(stream, connection, record),
    )
    .await
    .map_err(|_| TlsServerError::Timeout {
        stage: "TLS handshake",
    })??;

    let request = timeout(
        config.handshake_timeout,
        read_vless_request(&mut tls, config.handshake_timeout),
    )
    .await
    .map_err(|_| TlsServerError::Timeout {
        stage: "VLESS request read",
    })??;
    if account_id(&request.user_id)
        .ct_eq(&account_id(&config.user_id))
        .unwrap_u8()
        == 0
    {
        return Err(TlsServerError::UnauthorizedUser);
    }
    // Stock rejects an unknown flow instead of silently treating the body as
    // unframed bytes. A typo would otherwise corrupt every destination read.
    if !is_supported_flow(request.flow.as_deref()) {
        return Err(VlessError::UnsupportedFlow.into());
    }

    match request.command {
        Command::Tcp => {
            let destination = request
                .destination
                .ok_or(TlsServerError::MissingDestination)?;
            let target = dial(&destination, config.handshake_timeout.min(MAX_DIAL_TIMEOUT)).await?;

            timeout(
                config.handshake_timeout,
                tls.write_all(&ResponseHeader::new().to_bytes()),
            )
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "VLESS response write",
            })??;

            if request.vision {
                let rng = SmallRng::seed_from_u64(vision_seed());
                let vision = VisionStream::new(tls, request.user_id, request.body, rng);
                relay_vision(
                    vision,
                    target,
                    config.relay_idle_timeout,
                    Arc::clone(&config.splice_permits),
                )
                .await?;
            } else {
                let mut target = target;
                if !request.body.is_empty() {
                    timeout(config.handshake_timeout, target.write_all(&request.body))
                        .await
                        .map_err(|_| TlsServerError::Timeout {
                            stage: "initial VLESS body write",
                        })??;
                }
                relay_bidirectional(tls, target, config.relay_idle_timeout).await?;
            }

            Ok(ConnectionOutcome::Authenticated {
                command: Command::Tcp,
            })
        }
        Command::Udp => {
            // Stock rejects Vision UDP before writing a response. Clients that
            // select the Vision flow convert UDP to XUDP instead.
            if request.vision {
                return Err(TlsServerError::VisionUdpUnsupported);
            }
            // Legacy UDP/packetaddr binds one or two sockets per VLESS stream
            // and is outside the XUDP session limiter. Bound it separately so
            // compatibility mode cannot consume the whole memory budget.
            let _legacy_permit = Arc::clone(&config.legacy_udp_permits)
                .try_acquire_owned()
                .map_err(|_| TlsServerError::LegacyUdpLimited)?;
            let destination = request
                .destination
                .ok_or(TlsServerError::MissingDestination)?;

            timeout(
                config.handshake_timeout,
                tls.write_all(&ResponseHeader::new().to_bytes()),
            )
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "VLESS response write",
            })??;

            let stream = PrependStream::new(tls, request.body);
            handle_udp_stream(stream, destination, &config.udp).await?;
            Ok(ConnectionOutcome::Authenticated {
                command: Command::Udp,
            })
        }
        Command::Mux => {
            timeout(
                config.handshake_timeout,
                tls.write_all(&ResponseHeader::new().to_bytes()),
            )
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "VLESS response write",
            })??;

            let xudp = Arc::new(config.xudp.clone());
            if request.vision {
                let rng = SmallRng::seed_from_u64(vision_seed());
                let vision = VisionStream::new(tls, request.user_id, request.body, rng);
                handle_mux_stream(vision, xudp, config.xudp_limiter.clone()).await?;
            } else {
                let stream = PrependStream::new(tls, request.body);
                handle_mux_stream(stream, xudp, config.xudp_limiter.clone()).await?;
            }

            Ok(ConnectionOutcome::Authenticated {
                command: Command::Mux,
            })
        }
        command => {
            tracing::warn!(
                command = ?command,
                "authenticated VLESS command is not implemented yet; closing"
            );
            Ok(ConnectionOutcome::Authenticated { command })
        }
    }
}

/// Returns a per-connection seed for Vision padding.
///
/// Padding lengths are traffic shaping, not authentication material. The seed
/// mixes the wall clock with a process counter so two connections do not share
/// the same padding sequence.
fn vision_seed() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    now ^ count.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

async fn forward_to_cover(
    client: TcpStream,
    record: &[u8],
    config: &TlsServerConfig,
) -> Result<ConnectionOutcome, TlsServerError> {
    // Fail fast rather than queueing an unbounded number of cover relays in
    // the shared blocking pool. The permit is held through the relay so a
    // cover connection cannot outlive the cap, and the per-source bound keeps
    // one scanner from consuming every global cover slot.
    let peer = client.peer_addr().map_err(TlsServerError::Io)?;
    let _cover_permit = match config.cover_limiter.try_acquire(peer.ip()) {
        Ok(permit) => permit,
        Err(reject) => {
            tracing::debug!(%peer, ?reject, "cover limit reached; closing probe");
            return Ok(ConnectionOutcome::CoverLimited);
        }
    };

    let mut cover = dial(&config.cover, config.handshake_timeout).await?;
    timeout(config.handshake_timeout, cover.write_all(record))
        .await
        .map_err(|_| TlsServerError::Timeout {
            stage: "cover ClientHello write",
        })??;
    relay_splice(client, cover, COVER_IDLE_TIMEOUT).await?;
    Ok(ConnectionOutcome::CoverForwarded)
}

struct OwnedRequest {
    user_id: [u8; 16],
    command: Command,
    destination: Option<NetLocation>,
    vision: bool,
    flow: Option<String>,
    body: Vec<u8>,
}

async fn read_vless_request<R>(
    stream: &mut R,
    read_timeout: Duration,
) -> Result<OwnedRequest, TlsServerError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0u8; MAX_REQUEST_HEADER_LEN];
    let mut filled = 0usize;

    loop {
        let count = timeout(read_timeout, stream.read(&mut buffer[filled..]))
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "VLESS request read",
            })??;
        if count == 0 {
            return Err(VlessError::Truncated {
                offset: filled,
                needed: 1,
                remaining: 0,
            }
            .into());
        }
        filled += count;

        match RequestHeader::parse(&buffer[..filled]) {
            Ok((header, body)) => {
                return Ok(OwnedRequest {
                    user_id: header.user_id,
                    command: header.command,
                    destination: header.destination,
                    vision: header.addons.is_vision(),
                    flow: header.addons.flow.map(str::to_owned),
                    body: body.to_vec(),
                });
            }
            Err(error) if error.is_truncated() && filled < MAX_REQUEST_HEADER_LEN => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

async fn dial(
    destination: &NetLocation,
    dial_timeout: Duration,
) -> Result<TcpStream, TlsServerError> {
    let host = match &destination.address {
        Address::Ipv4(address) => address.to_string(),
        Address::Ipv6(address) => address.to_string(),
        Address::Domain(domain) => domain.clone(),
    };
    let deadline = tokio::time::Instant::now() + dial_timeout;
    let addresses =
        tokio::time::timeout_at(deadline, lookup_host((host.as_str(), destination.port)))
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "destination dial",
            })?
            .map_err(TlsServerError::Io)?
            .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(TlsServerError::Io(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "destination resolved to no addresses",
        )));
    }

    let mut last_error = None;
    for address in addresses {
        let socket = match address.is_ipv4() {
            true => TcpSocket::new_v4(),
            false => TcpSocket::new_v6(),
        }
        .map_err(TlsServerError::Io)?;
        // This must happen before connect: Linux uses TCP_MAXSEG for both the
        // MSS option in the SYN and the local send limit only when it is set
        // while the socket is still unconnected.
        if let Err(error) = beam_sys::set_tcp_maxseg(socket.as_raw_fd(), TARGET_MSS) {
            tracing::debug!(%error, "could not set TCP_MAXSEG on the destination");
        }
        match tokio::time::timeout_at(deadline, socket.connect(address)).await {
            Ok(Ok(stream)) => {
                // Small request headers and interactive replies must not wait
                // for Nagle/delayed-ACK interaction on the outbound socket.
                // The accepted client socket already sets this in `main`.
                if let Err(error) = stream.set_nodelay(true) {
                    tracing::debug!(%error, "could not set TCP_NODELAY on the destination");
                }
                if let Err(error) = beam_sys::set_tcp_keepalive(
                    stream.as_raw_fd(),
                    Duration::from_secs(60),
                    Duration::from_secs(15),
                ) {
                    tracing::debug!(%error, "could not set TCP keepalive on the destination");
                }
                return Ok(stream);
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                return Err(TlsServerError::Timeout {
                    stage: "destination dial",
                });
            }
        }
    }

    Err(TlsServerError::Io(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, "no destination address")
    })))
}

async fn relay_bidirectional<A, B>(
    left: A,
    right: B,
    idle_timeout: Duration,
) -> Result<(), TlsServerError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut left_read, mut left_write) = tokio::io::split(left);
    let (mut right_read, mut right_write) = tokio::io::split(right);
    let activity = Arc::new(RelayActivity::new());

    // Idle is a property of the whole connection, not of each direction. A
    // download-only or upload-only transfer must not be torn down because the
    // opposite direction has nothing to send.
    let left_to_right = copy_direction(
        &mut left_read,
        &mut right_write,
        idle_timeout,
        Some(&activity),
    );
    let right_to_left = copy_direction(
        &mut right_read,
        &mut left_write,
        idle_timeout,
        Some(&activity),
    );
    tokio::try_join!(left_to_right, right_to_left)?;
    Ok(())
}

/// Relays a Vision stream, handing each raw direction to its own one-way
/// splice as soon as that direction is ready.
///
/// The upload and download halves are independent. A client can receive the
/// server's Direct block without having more upload data (download-only), or
/// send Direct upload data while the server writer is still framed. Waiting for
/// both directions before using `splice(2)` leaves one bulk direction on the
/// copy path in either case.
///
/// When both directions are raw, beam keeps two independent one-way relays
/// with one shared [`RelayActivity`] deadline. It does not switch to a single
/// bidirectional relay, so neither direction has to wait for the other to
/// finish.
async fn relay_vision(
    vision: VisionStream<TlsStream>,
    target: TcpStream,
    idle_timeout: Duration,
    splice_permits: Arc<Semaphore>,
) -> Result<(), TlsServerError> {
    let activity = Arc::new(RelayActivity::new());
    let mut write_direct = vision.write_direct_watch();
    let mut read_handoff = vision.read_handoff_watch();

    let clones = (|| -> Result<_, TlsServerError> {
        Ok((
            vision.try_clone_raw_socket()?,
            vision.try_clone_raw_socket()?,
            try_clone_tcp(&target)?,
            try_clone_tcp(&target)?,
        ))
    })();
    let (client_read, client_write, target_read_splice, target_write_splice) = match clones {
        Ok(clones) => clones,
        Err(error) => {
            tracing::debug!(
                %error,
                "could not clone raw Vision sockets; using the copy relay"
            );
            return relay_bidirectional(vision, target, idle_timeout).await;
        }
    };

    let (mut vision_read, mut vision_write) = tokio::io::split(vision);
    let (mut target_read, mut target_write) = tokio::io::split(target);

    let up_activity = Arc::clone(&activity);
    let up_splice_permits = Arc::clone(&splice_permits);
    let up = async move {
        let mut stop_guard = RelayStopGuard::new(&up_activity);
        let result = async {
            let (copied_up, raw_read) = copy_direction_until_read_handoff(
                &mut vision_read,
                &mut target_write,
                idle_timeout,
                &mut read_handoff,
                Some(&up_activity),
            )
            .await?;
            if !raw_read {
                tracing::debug!(copied_up, "Vision relay finished without a raw read");
                return Ok(());
            }

            let Some(splice_permit) = up_splice_permits.try_acquire_owned().ok() else {
                tracing::debug!(
                    copied_up,
                    "Vision splice task limit reached; using async upload copy"
                );
                copy_direction(
                    &mut vision_read,
                    &mut target_write,
                    idle_timeout,
                    Some(&up_activity),
                )
                .await?;
                return Ok(());
            };

            tracing::debug!(
                copied_up,
                "Vision read switched to raw; starting one-way upload splice"
            );
            let config = splice_config(idle_timeout);
            let relay_activity = Arc::clone(&up_activity);
            let result = tokio::task::spawn_blocking(move || {
                let _splice_permit = splice_permit;
                copy_one_way(
                    client_read.as_raw_fd(),
                    target_write_splice.as_raw_fd(),
                    &config,
                    Some(&relay_activity),
                )
            })
            .await
            .map_err(join_error)?;
            match result {
                Ok(stats) => tracing::debug!(
                    copied_up,
                    bytes = stats.bytes_a_to_b,
                    splice_calls = stats.splice_calls,
                    polls = stats.polls,
                    "one-way Vision upload splice finished"
                ),
                Err(error) if is_peer_closed(&error) => {
                    tracing::debug!(%error, copied_up, "one-way Vision upload splice peer closed");
                }
                Err(error) => return Err(TlsServerError::Io(error)),
            }
            Ok(())
        }
        .await;
        stop_guard.disarm();
        result
    };

    let down_activity = Arc::clone(&activity);
    let down_splice_permits = Arc::clone(&splice_permits);
    let down = async move {
        let mut stop_guard = RelayStopGuard::new(&down_activity);
        let result = async {
        let (copied_down, raw_write) = copy_direction_until_write_raw(
            &mut target_read,
            &mut vision_write,
            idle_timeout,
            &mut write_direct,
            Some(&down_activity),
        )
        .await?;
        if !raw_write {
            tracing::debug!(copied_down, "Vision relay finished without a raw write");
            return Ok(());
        }

        let Some(splice_permit) = down_splice_permits.try_acquire_owned().ok() else {
            tracing::debug!(
                copied_down,
                "Vision splice task limit reached; using async download copy"
            );
            copy_direction(
                &mut target_read,
                &mut vision_write,
                idle_timeout,
                Some(&down_activity),
            )
            .await?;
            return Ok(());
        };

        tracing::debug!(
            copied_down,
            "Vision write switched to raw; starting one-way download splice"
        );
        let config = splice_config(idle_timeout);
        let relay_activity = Arc::clone(&down_activity);
        let result = tokio::task::spawn_blocking(move || {
            let _splice_permit = splice_permit;
            copy_one_way(
                target_read_splice.as_raw_fd(),
                client_write.as_raw_fd(),
                &config,
                Some(&relay_activity),
            )
        })
        .await
        .map_err(join_error)?;
        match result {
            Ok(stats) => tracing::debug!(
                copied_down,
                bytes = stats.bytes_a_to_b,
                splice_calls = stats.splice_calls,
                polls = stats.polls,
                "one-way Vision download splice finished"
            ),
            Err(error) if is_peer_closed(&error) => {
                tracing::debug!(%error, copied_down, "one-way Vision download splice peer closed");
            }
            Err(error) => return Err(TlsServerError::Io(error)),
        }
        Ok(())
        }.await;
        stop_guard.disarm();
        result
    };

    tokio::try_join!(up, down)?;
    Ok(())
}

/// Copies the client-to-target direction until the reader's raw handoff is
/// safe. Returns the copied byte count and whether the read direction switched.
///
/// The watch is published only after the Vision reader has drained every
/// ordered prefix byte: block content, raw block remainder, and TLS read-ahead.
/// Those bytes are written to the target before this function returns, so the
/// blocking upload splice can start at the raw socket without a separate
/// prefix buffer.
async fn copy_direction_until_read_handoff<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
    read_handoff: &mut watch::Receiver<bool>,
    activity_clock: Option<&RelayActivity>,
) -> Result<(u64, bool), TlsServerError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; RELAY_BUFFER_LEN];
    let mut relayed = 0_u64;
    loop {
        if *read_handoff.borrow() {
            return Ok((relayed, true));
        }

        // Poll the read first. The handoff publish and a raw read can become
        // ready in the same poll; if the handoff branch won, a completed read
        // would be dropped and its bytes lost. Reading before returning is
        // safe because the handoff only happens after every framed byte has
        // been drained, so the bytes belong to the raw prefix.
        let read = tokio::select! {
            biased;
            read = timeout(idle_timeout, reader.read(&mut buffer)) => read,
            changed = read_handoff.changed() => {
                if changed.is_err() {
                    break;
                }
                if *read_handoff.borrow() {
                    return Ok((relayed, true));
                }
                continue;
            }
        };
        let count = match read {
            Ok(Ok(count)) => count,
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                // A bare TCP FIN is a half-close, not a fatal relay error.
                // Let the opposite direction finish and half-close normally.
                break;
            }
            Ok(Err(error)) => return Err(TlsServerError::Io(error)),
            Err(_) => {
                if activity_clock
                    .and_then(RelayActivity::elapsed)
                    .is_some_and(|elapsed| elapsed < idle_timeout)
                {
                    continue;
                }
                return Err(TlsServerError::Timeout {
                    stage: "relay read",
                });
            }
        };
        if count == 0 {
            break;
        }

        let write = timeout(idle_timeout, writer.write_all(&buffer[..count]))
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "relay write",
            })?;
        match write {
            Ok(()) => {
                relayed = relayed.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
                if let Some(clock) = activity_clock {
                    clock.touch();
                }
            }
            Err(error) if is_peer_closed(&error) => break,
            Err(error) => return Err(TlsServerError::Io(error)),
        }

        if *read_handoff.borrow() {
            return Ok((relayed, true));
        }
    }

    let shutdown = timeout(idle_timeout, writer.shutdown())
        .await
        .map_err(|_| TlsServerError::Timeout {
            stage: "relay shutdown",
        })?;
    match shutdown {
        Ok(()) => {}
        Err(error) if is_peer_closed(&error) => {}
        Err(error) => return Err(TlsServerError::Io(error)),
    }
    Ok((relayed, false))
}

/// Copies the target-to-client direction until the Vision writer is raw.
/// Returns the copied byte count and whether the write direction switched.
async fn copy_direction_until_write_raw<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
    write_raw: &mut watch::Receiver<bool>,
    activity_clock: Option<&RelayActivity>,
) -> Result<(u64, bool), TlsServerError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; RELAY_BUFFER_LEN];
    let mut relayed = 0_u64;
    loop {
        if *write_raw.borrow() {
            return Ok((relayed, true));
        }

        // As on the read side, prefer a completed read over a simultaneous
        // raw-write handoff. The read bytes are still part of the ordered
        // target-to-client stream and must be written before the handoff.
        let read = tokio::select! {
            biased;
            read = timeout(idle_timeout, reader.read(&mut buffer)) => read,
            changed = write_raw.changed() => {
                if changed.is_err() {
                    break;
                }
                if *write_raw.borrow() {
                    return Ok((relayed, true));
                }
                continue;
            }
        };
        let count = match read {
            Ok(Ok(count)) => count,
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                // A bare TCP FIN is a half-close, not a fatal relay error.
                // Let the opposite direction finish and half-close normally.
                break;
            }
            Ok(Err(error)) => return Err(TlsServerError::Io(error)),
            Err(_) => {
                if activity_clock
                    .and_then(RelayActivity::elapsed)
                    .is_some_and(|elapsed| elapsed < idle_timeout)
                {
                    continue;
                }
                return Err(TlsServerError::Timeout {
                    stage: "relay read",
                });
            }
        };
        if count == 0 {
            break;
        }

        let write = timeout(idle_timeout, writer.write_all(&buffer[..count]))
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "relay write",
            })?;
        match write {
            Ok(()) => {
                relayed = relayed.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
                if let Some(clock) = activity_clock {
                    clock.touch();
                }
            }
            Err(error) if is_peer_closed(&error) => break,
            Err(error) => return Err(TlsServerError::Io(error)),
        }

        if *write_raw.borrow() {
            return Ok((relayed, true));
        }
    }

    let shutdown = timeout(idle_timeout, writer.shutdown())
        .await
        .map_err(|_| TlsServerError::Timeout {
            stage: "relay shutdown",
        })?;
    match shutdown {
        Ok(()) => {}
        Err(error) if is_peer_closed(&error) => {}
        Err(error) => return Err(TlsServerError::Io(error)),
    }
    Ok((relayed, false))
}

/// Duplicates a nonblocking TCP stream for a blocking one-way relay.
fn try_clone_tcp(stream: &TcpStream) -> Result<TcpStream, TlsServerError> {
    let fd = beam_sys::try_clone_fd(stream.as_raw_fd())?;
    let stream = std::net::TcpStream::from(fd);
    stream.set_nonblocking(true)?;
    TcpStream::from_std(stream).map_err(TlsServerError::Io)
}

/// Hands two raw sockets to the blocking splice relay.
async fn relay_splice(
    left: TcpStream,
    right: TcpStream,
    idle_timeout: Duration,
) -> Result<(), TlsServerError> {
    let config = splice_config(idle_timeout);
    let result = tokio::task::spawn_blocking(move || {
        copy_bidirectional(left.as_raw_fd(), right.as_raw_fd(), &config)
    })
    .await
    .map_err(join_error)?;
    match result {
        Ok(stats) => {
            tracing::debug!(bytes = stats.total_bytes(), "cover splice relay finished");
        }
        Err(error) if is_peer_closed(&error) => {
            tracing::debug!(%error, "cover splice peer closed");
        }
        Err(error) => return Err(TlsServerError::Io(error)),
    }
    Ok(())
}

fn splice_config(idle_timeout: Duration) -> RelayConfig {
    RelayConfig::new()
        .with_idle_timeout(idle_timeout)
        // A half-closed direction no longer needs the full VPN idle budget.
        // Bound it so a finished mobile flow releases its blocking thread and
        // kernel pipe promptly instead of lingering for five minutes.
        .with_shutdown_timeout(Duration::from_secs(30))
}

fn join_error(error: tokio::task::JoinError) -> TlsServerError {
    TlsServerError::Io(io::Error::other(error))
}

/// Stops the sibling relay if this future is dropped or fails.
///
/// A `spawn_blocking` join handle cannot be aborted after the task starts, and
/// dropping it detaches the task. The guard therefore publishes a cooperative
/// stop flag before the handle is lost; the shared eventfd wakes a blocked
/// relay immediately, with the older 250 ms check as a fallback when the
/// descriptor cannot be created. A successful branch disarms the guard so the
/// other direction can continue normally.
struct RelayStopGuard<'a> {
    activity: &'a RelayActivity,
    armed: bool,
}

impl<'a> RelayStopGuard<'a> {
    fn new(activity: &'a RelayActivity) -> Self {
        Self {
            activity,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RelayStopGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.activity.stop();
        }
    }
}

async fn copy_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
    activity_clock: Option<&RelayActivity>,
) -> Result<u64, TlsServerError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; RELAY_BUFFER_LEN];
    let mut relayed = 0_u64;
    loop {
        if activity_clock.is_some_and(RelayActivity::is_stopped) {
            break;
        }
        let read = timeout(idle_timeout, reader.read(&mut buffer)).await;
        let count = match read {
            Ok(Ok(count)) => count,
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                // A bare TCP FIN is a half-close, not a fatal relay error.
                // Let the opposite direction finish and half-close normally.
                break;
            }
            Ok(Err(error)) => return Err(TlsServerError::Io(error)),
            Err(_) => {
                if activity_clock.is_some_and(RelayActivity::is_stopped) {
                    break;
                }
                if activity_clock
                    .and_then(RelayActivity::elapsed)
                    .is_some_and(|elapsed| elapsed < idle_timeout)
                {
                    continue;
                }
                return Err(TlsServerError::Timeout {
                    stage: "relay read",
                });
            }
        };
        if count == 0 {
            break;
        }
        let write = timeout(idle_timeout, writer.write_all(&buffer[..count]))
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "relay write",
            })?;
        match write {
            Ok(()) => {
                relayed = relayed.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
                if let Some(clock) = activity_clock {
                    clock.touch();
                }
            }
            Err(error) if is_peer_closed(&error) => break,
            Err(error) => return Err(TlsServerError::Io(error)),
        }
    }
    let shutdown = timeout(idle_timeout, writer.shutdown())
        .await
        .map_err(|_| TlsServerError::Timeout {
            stage: "relay shutdown",
        })?;
    match shutdown {
        Ok(()) => {}
        Err(error) if is_peer_closed(&error) => {}
        Err(error) => return Err(TlsServerError::Io(error)),
    }
    Ok(relayed)
}

fn is_peer_closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    struct UnexpectedEofReader;

    impl AsyncRead for UnexpectedEofReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
        }
    }

    #[test]
    fn empty_and_vision_flows_are_supported_but_unknown_ones_are_not() {
        assert!(is_supported_flow(None));
        assert!(is_supported_flow(Some("")));
        assert!(is_supported_flow(Some(crate::vless::VISION_FLOW)));
        assert!(!is_supported_flow(Some("xtls-rprx-vision-typo")));
    }

    #[tokio::test]
    async fn dial_limits_target_mss_and_connects() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            drop(stream);
        });
        let destination = NetLocation {
            address: Address::Ipv4(Ipv4Addr::LOCALHOST),
            port: address.port(),
        };

        let stream = dial(&destination, Duration::from_secs(2))
            .await
            .expect("dial");
        let mss = beam_sys::get_tcp_maxseg(stream.as_raw_fd()).expect("target MSS");
        assert!(
            mss <= TARGET_MSS,
            "target MSS {mss} exceeded the configured {TARGET_MSS}"
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn bare_fin_is_a_half_close_not_a_fatal_relay_error() {
        let mut reader = UnexpectedEofReader;
        let mut writer = tokio::io::sink();
        let copied = copy_direction(&mut reader, &mut writer, Duration::from_secs(1), None)
            .await
            .expect("bare FIN must be a clean half-close");
        assert_eq!(copied, 0);
    }

    fn test_config() -> TlsServerConfig {
        TlsServerConfig::new(
            [0x11; 32],
            vec!["0123456789abcdef".to_string()],
            vec!["whatsapp.net".to_string()],
            [0, 0, 0],
            [255, 255, 255],
            None,
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: 9,
            },
            Duration::from_secs(5),
            TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN,
            [0x22; 16],
        )
        .expect("test configuration")
    }

    #[test]
    fn replay_cache_rejects_duplicates_and_stays_bounded() {
        let mut cache = ReplayCache::new(Duration::from_secs(60));
        let id = [7u8; 32];
        assert!(!cache.seen_before(id));
        assert!(cache.seen_before(id));
        for index in 0..REPLAY_CACHE_CAPACITY + 32 {
            let mut next = [0u8; 32];
            next[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let _ = cache.seen_before(next);
        }
        assert!(cache.entries.len() <= REPLAY_CACHE_CAPACITY);
        assert!(cache.order.len() <= REPLAY_CACHE_CAPACITY);
    }

    #[tokio::test]
    async fn bidirectional_relay_keeps_a_one_way_transfer_alive() {
        let (left, mut left_peer) = tokio::io::duplex(1024);
        let (right, mut right_peer) = tokio::io::duplex(1024);
        let task = tokio::spawn(relay_bidirectional(left, right, Duration::from_millis(100)));

        for _ in 0..5 {
            left_peer.write_all(b"x").await.expect("left write");
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert!(
            !task.is_finished(),
            "the idle download direction must not cancel an active upload"
        );
        left_peer.shutdown().await.expect("left shutdown");
        right_peer.shutdown().await.expect("right shutdown");

        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("relay did not finish")
            .expect("relay task panicked");
        assert!(result.is_ok(), "relay failed: {result:?}");
    }

    #[tokio::test]
    async fn cover_limit_is_global_and_bounded() {
        let config = test_config();
        let mut permits = Vec::new();
        for index in 0..COVER_MAX_CONCURRENCY {
            let ip = std::net::IpAddr::from([10, 0, 0, index as u8]);
            permits.push(
                config
                    .cover_limiter
                    .try_acquire(ip)
                    .expect("cover permit must be available below the limit"),
            );
        }
        assert!(
            config
                .cover_limiter
                .try_acquire(std::net::IpAddr::from([10, 0, 1, 1]))
                .is_err(),
            "the cover limit must reject one more relay"
        );
        permits.pop();
        assert!(
            config
                .cover_limiter
                .try_acquire(std::net::IpAddr::from([10, 0, 1, 1]))
                .is_ok(),
            "a released cover permit must be reusable"
        );
    }

    #[test]
    fn cover_limit_is_bounded_per_source() {
        let config = test_config();
        let ip = std::net::IpAddr::from([10, 0, 0, 1]);
        let mut permits = Vec::new();
        for _ in 0..COVER_MAX_PER_IP {
            permits.push(
                config
                    .cover_limiter
                    .try_acquire(ip)
                    .expect("per-source cover permit must be available"),
            );
        }
        assert_eq!(
            config
                .cover_limiter
                .try_acquire(ip)
                .expect_err("per-IP cap"),
            crate::admission::IpLimitReject::PerIp
        );
        permits.pop();
        assert!(config.cover_limiter.try_acquire(ip).is_ok());
    }

    #[test]
    fn temporary_certificate_is_ed25519_and_hmac_signed() {
        let config = test_config();
        let original = config.certificate.certificate_der.clone();
        assert!(
            original
                .windows(5)
                .any(|window| window == [0x06, 0x03, 0x2b, 0x65, 0x70]),
            "certificate must use the Ed25519 OID 1.3.101.112"
        );

        let auth_key = [0x42u8; 32];
        let signed = config
            .signed_certificate(&auth_key)
            .expect("HMAC-signed certificate");
        assert_eq!(signed.len(), original.len());
        let signature_offset = signed.len() - 64;
        assert_eq!(
            &signed[..signature_offset],
            &original[..original.len() - 64]
        );
        assert_ne!(
            &signed[signature_offset..],
            &original[original.len() - 64..]
        );
        assert_eq!(
            &signed[signature_offset..],
            &hmac_signature(&auth_key, &config.certificate.public_key).expect("expected HMAC")
        );

        config
            .build_server_config(&auth_key)
            .expect("modified certificate must load into rustls");
    }

    #[test]
    fn reality_signing_key_forces_ed25519() {
        let config = test_config();
        let signer = config
            .certificate
            .signing_key
            .choose_scheme(&[])
            .expect("the stock Chrome fingerprint offers no Ed25519 scheme");
        assert_eq!(signer.scheme(), SignatureScheme::ED25519);
    }

    #[test]
    fn xudp_config_can_be_overridden() {
        let xudp = XudpConfig {
            max_sessions: 7,
            ..XudpConfig::default()
        };
        let config = test_config().with_xudp(xudp.clone());
        assert_eq!(config.xudp, xudp);
    }

    #[test]
    fn account_id_ignores_vless_route_bytes() {
        let mut configured = [0x11; 16];
        configured[6] = 6;
        configured[7] = 7;
        let mut routed = configured;
        routed[6] = 0xaa;
        routed[7] = 0xbb;
        assert_eq!(account_id(&configured), account_id(&routed));
        assert_ne!(account_id(&configured), configured);
    }

    #[test]
    fn relay_idle_timeout_can_be_overridden() {
        let config = test_config().with_relay_idle_timeout(Duration::from_secs(7));
        assert_eq!(config.relay_idle_timeout, Duration::from_secs(7));
    }

    #[test]
    fn udp_config_can_be_overridden() {
        let udp = LegacyUdpConfig {
            max_packetaddr_destinations: 7,
            ..LegacyUdpConfig::default()
        };
        let config = test_config().with_udp(udp.clone());
        assert_eq!(config.udp, udp);
    }

    #[test]
    fn rejects_invalid_record_bounds() {
        let result = TlsServerConfig::new(
            [0x11; 32],
            Vec::new(),
            Vec::new(),
            [0, 0, 0],
            [255, 255, 255],
            None,
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: 9,
            },
            Duration::from_secs(5),
            TLS_RECORD_HEADER_LEN - 1,
            [0x22; 16],
        );
        assert!(matches!(result, Err(TlsServerError::InvalidConfig { .. })));
    }

    #[tokio::test]
    async fn replay_stream_serves_prefix_then_socket() {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            stream.write_all(b"socket").await.expect("server write");
        });

        let stream = TcpStream::connect(address).await.expect("client connect");
        let mut replay = ReplayStream::new(stream, b"prefix".to_vec());
        let mut buffer = [0u8; 10];
        replay.read_exact(&mut buffer).await.expect("replay read");
        assert_eq!(&buffer, b"prefixsock");
        server.await.expect("server task");
    }
}
