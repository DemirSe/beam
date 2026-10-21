//! REALITY TLS server adapter.
//!
//! One TLS record is read before rustls is involved. The record is parsed and
//! authenticated as a REALITY ClientHello. Authenticated connections are handed
//! to rustls through a [`ReplayStream`] that replays the original record.
//! Unauthenticated connections are forwarded byte-for-byte to the configured
//! cover. The adapter implements only the TLS handshake and a minimal TCP VLESS
//! path; Vision and XUDP are deliberately out of scope.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hmac::{Hmac, Mac};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use sha2::Sha512;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use crate::address::{Address, NetLocation};
use crate::reality::{Auth, RealityAuthConfig, authenticate};
use crate::tls::{ClientHello, MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN};
use crate::vless::{Command, MAX_REQUEST_HEADER_LEN, RequestHeader, ResponseHeader, VlessError};

/// Idle timeout for each relay read, write, and shutdown.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Result of one accepted connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionOutcome {
    /// The connection was not authenticated and was forwarded to the cover.
    CoverForwarded,
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

    /// rustls rejected a configuration or handshake.
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// A network or TLS stream I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The VLESS request was malformed or truncated.
    #[error("VLESS request error: {0}")]
    Vless(#[from] VlessError),
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
    /// Maximum total ClientHello record size, including its five-byte header.
    pub max_client_hello_bytes: usize,
    provider: Arc<CryptoProvider>,
    certificate: TemporaryCertificate,
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
            max_client_hello_bytes,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            certificate: TemporaryCertificate::generate()?,
        })
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
        let key = PrivatePkcs8KeyDer::from(self.certificate.private_key_der.to_vec());
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_eddsa_type(&key)
            .map_err(TlsServerError::Rustls)?;
        let certified =
            CertifiedKey::new(chain, Arc::new(RealitySigningKey { inner: signing_key }));
        certified.keys_match().map_err(TlsServerError::Rustls)?;

        let config = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(TlsServerError::Rustls)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
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
            .field("max_client_hello_bytes", &self.max_client_hello_bytes)
            .finish()
    }
}

struct TemporaryCertificate {
    certificate_der: Vec<u8>,
    private_key_der: Zeroizing<Vec<u8>>,
    public_key: [u8; 32],
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

        Ok(Self {
            certificate_der: certificate.der().to_vec(),
            private_key_der: Zeroizing::new(key_pair.serialize_der()),
            public_key,
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

/// Handles one accepted TCP connection.
pub async fn handle_connection(
    stream: TcpStream,
    config: Arc<TlsServerConfig>,
) -> Result<ConnectionOutcome, TlsServerError> {
    let record = read_client_hello_record(&stream, &config).await?;
    let auth = match ClientHello::parse(&record) {
        Ok(hello) => match authenticate(&hello, &config.reality_config()) {
            Ok(auth) => Some(auth),
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
        Some(auth) => handle_authenticated(stream, record, auth, &config).await,
        None => forward_to_cover(stream, &record, &config).await,
    }
}

async fn read_client_hello_record(
    stream: &TcpStream,
    config: &TlsServerConfig,
) -> Result<Vec<u8>, TlsServerError> {
    let mut header = [0u8; TLS_RECORD_HEADER_LEN];
    timeout(config.handshake_timeout, read_exact(stream, &mut header))
        .await
        .map_err(|_| TlsServerError::Timeout {
            stage: "ClientHello header read",
        })??;

    let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let total = TLS_RECORD_HEADER_LEN + record_len;
    if total > config.max_client_hello_bytes {
        return Err(TlsServerError::ClientHelloTooLarge {
            length: total,
            max: config.max_client_hello_bytes,
        });
    }

    let mut record = Vec::new();
    record
        .try_reserve_exact(total)
        .map_err(|_| TlsServerError::Allocation)?;
    record.extend_from_slice(&header);
    record.resize(total, 0);
    timeout(
        config.handshake_timeout,
        read_exact(stream, &mut record[TLS_RECORD_HEADER_LEN..]),
    )
    .await
    .map_err(|_| TlsServerError::Timeout {
        stage: "ClientHello body read",
    })??;
    Ok(record)
}

async fn handle_authenticated(
    stream: TcpStream,
    record: Vec<u8>,
    auth: Auth,
    config: &TlsServerConfig,
) -> Result<ConnectionOutcome, TlsServerError> {
    let server_config = Arc::new(config.build_server_config(&auth.auth_key[..])?);
    let acceptor = TlsAcceptor::from(server_config);
    let replay = ReplayStream::new(stream, record);
    let mut tls = timeout(config.handshake_timeout, acceptor.accept(replay))
        .await
        .map_err(|_| TlsServerError::Timeout {
            stage: "rustls handshake",
        })??;

    let request = read_vless_request(&mut tls, config.handshake_timeout).await?;

    match request.command {
        Command::Tcp => {
            let destination = request
                .destination
                .ok_or(TlsServerError::MissingDestination)?;
            let mut target = dial(&destination, config.handshake_timeout).await?;

            timeout(
                config.handshake_timeout,
                tls.write_all(&ResponseHeader::new().to_bytes()),
            )
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "VLESS response write",
            })??;

            if !request.body.is_empty() {
                timeout(config.handshake_timeout, target.write_all(&request.body))
                    .await
                    .map_err(|_| TlsServerError::Timeout {
                        stage: "initial VLESS body write",
                    })??;
            }

            relay_bidirectional(tls, target, RELAY_IDLE_TIMEOUT).await?;
            Ok(ConnectionOutcome::Authenticated {
                command: Command::Tcp,
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

async fn forward_to_cover(
    client: TcpStream,
    record: &[u8],
    config: &TlsServerConfig,
) -> Result<ConnectionOutcome, TlsServerError> {
    let mut cover = dial(&config.cover, config.handshake_timeout).await?;
    timeout(config.handshake_timeout, cover.write_all(record))
        .await
        .map_err(|_| TlsServerError::Timeout {
            stage: "cover ClientHello write",
        })??;
    relay_bidirectional(client, cover, RELAY_IDLE_TIMEOUT).await?;
    Ok(ConnectionOutcome::CoverForwarded)
}

struct OwnedRequest {
    command: Command,
    destination: Option<NetLocation>,
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
                    command: header.command,
                    destination: header.destination,
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
    timeout(
        dial_timeout,
        TcpStream::connect((host.as_str(), destination.port)),
    )
    .await
    .map_err(|_| TlsServerError::Timeout {
        stage: "destination dial",
    })?
    .map_err(TlsServerError::Io)
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

    let left_to_right = copy_direction(&mut left_read, &mut right_write, idle_timeout);
    let right_to_left = copy_direction(&mut right_read, &mut left_write, idle_timeout);
    tokio::try_join!(left_to_right, right_to_left)?;
    Ok(())
}

async fn copy_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
) -> Result<(), TlsServerError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 8192];
    loop {
        let count = timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "relay read",
            })??;
        if count == 0 {
            break;
        }
        timeout(idle_timeout, writer.write_all(&buffer[..count]))
            .await
            .map_err(|_| TlsServerError::Timeout {
                stage: "relay write",
            })??;
    }
    timeout(idle_timeout, writer.shutdown())
        .await
        .map_err(|_| TlsServerError::Timeout {
            stage: "relay shutdown",
        })??;
    Ok(())
}

async fn read_exact(stream: &TcpStream, buffer: &mut [u8]) -> io::Result<()> {
    let mut read = 0usize;
    while read < buffer.len() {
        stream.readable().await?;
        match stream.try_read(&mut buffer[read..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed before the TLS record was complete",
                ));
            }
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

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
        )
        .expect("test configuration")
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
        let key = PrivatePkcs8KeyDer::from(config.certificate.private_key_der.to_vec());
        let inner =
            rustls::crypto::aws_lc_rs::sign::any_eddsa_type(&key).expect("test Ed25519 key");
        let key = RealitySigningKey { inner };
        let signer = key
            .choose_scheme(&[])
            .expect("the stock Chrome fingerprint offers no Ed25519 scheme");
        assert_eq!(signer.scheme(), SignatureScheme::ED25519);
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
