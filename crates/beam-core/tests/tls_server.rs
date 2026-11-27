//! Integration tests for the REALITY TLS server adapter.

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::io;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use beam_core::address::{Address, NetLocation};
use beam_core::tls::server::{
    ConnectionOutcome, ReplayStream, TlsServerConfig, TlsServerError, handle_connection,
};
use beam_core::tls::{ClientHello, MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN};
use beam_core::vless::Command;
use hkdf::Hkdf;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConnection, DigitallySignedStruct, NamedGroup, SignatureScheme,
    crypto::{ActiveKeyExchange, SecureRandom, SharedSecret, SupportedKxGroup},
};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[tokio::test]
async fn non_tls_probe_is_forwarded_to_cover_without_waiting_for_a_record() {
    timeout(Duration::from_secs(5), non_tls_probe_test())
        .await
        .expect("non-TLS cover fallback timed out");
}

async fn non_tls_probe_test() {
    let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind cover");
    let cover_address = cover_listener.local_addr().expect("cover address");
    let (capture_tx, capture_rx) = oneshot::channel();
    let cover_task = tokio::spawn(async move {
        let (mut stream, _) = cover_listener.accept().await.expect("accept cover");
        let mut buffer = vec![0u8; 4096];
        let count = stream.read(&mut buffer).await.expect("cover read");
        capture_tx
            .send(buffer[..count].to_vec())
            .expect("cover capture");
        stream.write_all(b"cover-http").await.expect("cover write");
        stream.shutdown().await.expect("cover shutdown");
    });

    let beam_config = Arc::new(
        TlsServerConfig::new(
            [0x11; 32],
            vec!["0123456789abcdef".to_string()],
            vec!["whatsapp.net".to_string()],
            [0, 0, 0],
            [255, 255, 255],
            None,
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: cover_address.port(),
            },
            Duration::from_secs(1),
            TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN,
            [0x22; 16],
        )
        .expect("beam config"),
    );
    let beam_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind beam");
    let beam_address = beam_listener.local_addr().expect("beam address");
    let beam_task = tokio::spawn(async move {
        let (stream, _) = beam_listener.accept().await.expect("accept beam");
        handle_connection(stream, beam_config).await
    });

    let mut client = TcpStream::connect(beam_address)
        .await
        .expect("connect to beam");
    // A real cover answers an HTTP request immediately. The old path waited
    // for the record length decoded from bytes 3-4, which is nonsense here.
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: probe\r\n\r\n")
        .await
        .expect("client write");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read cover response");
    assert_eq!(response, b"cover-http");
    // The cover has half-closed; close the client write side so the
    // bidirectional splice can finish both directions.
    drop(client);

    let captured = capture_rx.await.expect("cover capture");
    assert!(
        captured.starts_with(b"GET /"),
        "cover must receive the HTTP prefix, got {captured:?}"
    );
    let outcome = beam_task.await.expect("beam task").expect("beam handler");
    assert_eq!(outcome, ConnectionOutcome::CoverForwarded);
    cover_task.await.expect("cover task");
}

#[tokio::test]
async fn tls_server_cover_fallback_forwards_exact_client_hello() {
    timeout(Duration::from_secs(10), cover_fallback_test())
        .await
        .expect("cover fallback test timed out");
}

async fn cover_fallback_test() {
    let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind cover");
    let cover_address = cover_listener.local_addr().expect("cover address");
    let cover_config = cover_server_config();
    let (capture_tx, capture_rx) = oneshot::channel();
    let cover_task =
        tokio::spawn(async move { run_cover(cover_listener, cover_config, capture_tx).await });

    let beam_config = Arc::new(
        TlsServerConfig::new(
            [0x11; 32],
            vec!["0123456789abcdef".to_string()],
            vec!["whatsapp.net".to_string()],
            [0, 0, 0],
            [255, 255, 255],
            None,
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: cover_address.port(),
            },
            Duration::from_secs(5),
            TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN,
            [0x22; 16],
        )
        .expect("beam config"),
    );
    let beam_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind beam");
    let beam_address = beam_listener.local_addr().expect("beam address");
    let beam_task = tokio::spawn(async move {
        let (stream, _) = beam_listener.accept().await.expect("accept beam");
        handle_connection(stream, beam_config).await
    });

    let stream = TcpStream::connect(beam_address)
        .await
        .expect("connect to beam");
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let recording = RecordingStream::new(stream, Arc::clone(&recorded));
    let connector = TlsConnector::from(client_config());
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut client = connector
        .connect(server_name, recording)
        .await
        .expect("client handshake through cover");

    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read cover response");
    assert_eq!(response, b"cover response");
    let _ = client.shutdown().await;
    drop(client);

    let captured = capture_rx.await.expect("cover capture");
    let written = recorded.lock().expect("recording lock").clone();
    let first = first_tls_record(&written).expect("client wrote a TLS record");
    assert_eq!(
        first, captured,
        "the cover must receive the exact ClientHello record"
    );

    let outcome = beam_task.await.expect("beam task").expect("beam handler");
    assert_eq!(outcome, ConnectionOutcome::CoverForwarded);
    cover_task
        .await
        .expect("cover task")
        .expect("cover handler");
}

async fn run_cover(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    capture: oneshot::Sender<Vec<u8>>,
) -> Result<(), String> {
    let (mut stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
    let record = read_tls_record(&mut stream)
        .await
        .map_err(|error| error.to_string())?;
    capture
        .send(record.clone())
        .map_err(|_| "capture receiver dropped".to_string())?;

    let replay = ReplayStream::new(stream, record);
    let mut tls = TlsAcceptor::from(config)
        .accept(replay)
        .await
        .map_err(|error| error.to_string())?;
    tls.write_all(b"cover response")
        .await
        .map_err(|error| error.to_string())?;
    tls.shutdown().await.map_err(|error| error.to_string())?;
    Ok(())
}

fn cover_server_config() -> Arc<rustls::ServerConfig> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("cover key");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("cover certificate params");
    let certificate = params.self_signed(&key).expect("cover certificate");
    let certificate_der = CertificateDer::from(certificate.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 cover")
    .with_no_client_auth()
    .with_single_cert(vec![certificate_der], key_der)
    .expect("cover server certificate");
    Arc::new(config)
}

fn client_config() -> Arc<rustls::ClientConfig> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 client")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerifier))
    .with_no_client_auth();
    Arc::new(config)
}

async fn read_tls_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; TLS_RECORD_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length > MAX_RECORD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cover received an oversized TLS record",
        ));
    }
    let mut record = vec![0u8; TLS_RECORD_HEADER_LEN + length];
    record[..TLS_RECORD_HEADER_LEN].copy_from_slice(&header);
    stream
        .read_exact(&mut record[TLS_RECORD_HEADER_LEN..])
        .await?;
    Ok(record)
}

fn first_tls_record(bytes: &[u8]) -> Option<&[u8]> {
    let header = bytes.get(..TLS_RECORD_HEADER_LEN)?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    bytes.get(..TLS_RECORD_HEADER_LEN + length)
}

struct RecordingStream {
    inner: TcpStream,
    written: Arc<Mutex<Vec<u8>>>,
}

impl RecordingStream {
    fn new(inner: TcpStream, written: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { inner, written }
    }
}

impl AsyncRead for RecordingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RecordingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(count)) = &poll
            && let Ok(mut written) = this.written.lock()
        {
            let remaining = 64 * 1024usize;
            let room = remaining.saturating_sub(written.len());
            let take = room.min(*count);
            written.extend_from_slice(&buf[..take]);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}

// REALITY client harness.
//
// An authenticated handshake needs a ClientHello whose session id is an AEAD
// envelope over those same ClientHello bytes with the session id zeroed. Those
// bytes are not known until rustls has assembled the message, so each harness
// connection runs twice with pinned randomness:
//
// 1. a local capture listener receives the ClientHello with a placeholder
//    session id;
// 2. the envelope is computed from the captured bytes, and the real handshake
//    runs with the same pinned random and X25519 share.
//
// Pinning makes the two ClientHellos identical except for the session id, which
// is why the captured bytes are a valid AAD. `RealityProbe::capture` checks the
// pinned random and the placeholder on the wire, so a rustls change that moves
// random material fails loudly instead of silently weakening the test.

const REALITY_SERVER_KEY: [u8; 32] = [0x11; 32];
const REALITY_SNI: &str = "whatsapp.net";
const REALITY_SHORT_ID: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const REALITY_CLIENT_VERSION: [u8; 3] = [1, 8, 0];
/// The server zeroes the 32-byte `legacy_session_id` at these offsets of
/// `ClientHello::raw_client_hello` (the record body).
const REALITY_SESSION_ID_START: usize = 39;
const REALITY_SESSION_ID_LEN: usize = 32;

#[derive(Debug)]
struct ScriptedRandom {
    session_id: [u8; 32],
    hello_random: [u8; 32],
    fills_32: AtomicUsize,
}

impl SecureRandom for ScriptedRandom {
    fn fill(&self, buffer: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        match buffer.len() {
            32 => {
                if self.fills_32.fetch_add(1, Ordering::SeqCst) == 0 {
                    buffer.copy_from_slice(&self.session_id);
                } else {
                    buffer.copy_from_slice(&self.hello_random);
                }
            }
            // The ClientHello extension-order seed. Pinning it keeps the two
            // runs byte-identical.
            2 => buffer.copy_from_slice(&[0x3a, 0x3a]),
            _ => buffer.fill(0x5a),
        }
        Ok(())
    }
}

#[derive(Debug)]
struct FixedGroup {
    secret: [u8; 32],
}

impl SupportedKxGroup for FixedGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret = StaticSecret::from(self.secret);
        let public = X25519PublicKey::from(&secret).to_bytes();
        Ok(Box::new(FixedKeyExchange { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct FixedKeyExchange {
    secret: StaticSecret,
    public: [u8; 32],
}

impl ActiveKeyExchange for FixedKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::General("invalid X25519 peer share".into()))?;
        let shared = self.secret.diffie_hellman(&X25519PublicKey::from(peer));
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

fn reality_client_config(
    session_id: [u8; 32],
    hello_random: [u8; 32],
    secret: [u8; 32],
) -> Arc<rustls::ClientConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let group: &'static dyn SupportedKxGroup = Box::leak(Box::new(FixedGroup { secret }));
    let random: &'static dyn SecureRandom = Box::leak(Box::new(ScriptedRandom {
        session_id,
        hello_random,
        fills_32: AtomicUsize::new(0),
    }));
    provider.kx_groups = vec![group];
    provider.secure_random = random;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 client")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Arc::new(config)
}

/// Drives a rustls client record by record so a test can stop mid-handshake.
struct RealityClient {
    conn: ClientConnection,
    stream: TcpStream,
}

impl RealityClient {
    async fn connect(address: SocketAddr, config: Arc<rustls::ClientConfig>) -> io::Result<Self> {
        let name = ServerName::try_from(REALITY_SNI).expect("REALITY server name");
        let conn = ClientConnection::new(config, name).expect("client connection");
        let stream = TcpStream::connect(address).await?;
        Ok(Self { conn, stream })
    }

    async fn flush(&mut self) -> io::Result<()> {
        let mut out = Vec::new();
        while self.conn.wants_write() {
            self.conn.write_tls(&mut out)?;
        }
        if out.is_empty() {
            return Ok(());
        }
        self.stream.write_all(&out).await
    }

    async fn read_records(&mut self) -> io::Result<()> {
        let mut buffer = [0u8; 16 * 1024];
        let count = self.stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.conn.read_tls(&mut &buffer[..count])?;
        self.conn.process_new_packets().map_err(io::Error::other)?;
        Ok(())
    }

    async fn finish_handshake(&mut self) -> io::Result<()> {
        self.flush().await?;
        while self.conn.is_handshaking() {
            self.read_records().await?;
            self.flush().await?;
        }
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.conn.writer().write_all(data)?;
        self.flush().await
    }

    /// Reads application data until the peer closes the connection.
    async fn read_to_close(&mut self) -> io::Result<Vec<u8>> {
        let mut received = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match self.conn.reader().read(&mut buffer) {
                Ok(0) => return Ok(received),
                Ok(count) => received.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(received),
                Err(error) => return Err(error),
            }
            let count = self.stream.read(&mut buffer).await?;
            if count == 0 {
                return Ok(received);
            }
            self.conn.read_tls(&mut &buffer[..count])?;
            self.conn.process_new_packets().map_err(io::Error::other)?;
        }
    }
}

/// The pinned client material for one harness connection.
struct RealityProbe {
    hello_random: [u8; 32],
    secret: [u8; 32],
    record: Vec<u8>,
}

impl RealityProbe {
    /// Captures the ClientHello rustls emits for this pinned randomness.
    async fn capture(capture: &TcpListener, index: u8) -> Self {
        let mut hello_random = [0x5a; 32];
        hello_random[31] = index;
        let mut secret = [0x33; 32];
        secret[31] = index;
        let config = reality_client_config([0u8; 32], hello_random, secret);
        let address = capture.local_addr().expect("capture address");
        let mut client = RealityClient::connect(address, config)
            .await
            .expect("capture connect");
        client.flush().await.expect("capture ClientHello write");
        let (mut peer, _) = capture.accept().await.expect("capture accept");
        let record = read_tls_record(&mut peer).await.expect("capture read");
        drop(peer);

        let hello = ClientHello::parse(&record).expect("captured ClientHello parses");
        assert_eq!(
            hello.random, hello_random,
            "the pinned ClientHello random must reach the wire"
        );
        assert_eq!(
            hello.session_id, [0u8; 32],
            "the capture run must carry the placeholder session id"
        );
        assert_eq!(hello.server_name, Some(REALITY_SNI));
        let body = &record[TLS_RECORD_HEADER_LEN..];
        assert_eq!(
            &body[REALITY_SESSION_ID_START..REALITY_SESSION_ID_START + REALITY_SESSION_ID_LEN],
            &[0u8; REALITY_SESSION_ID_LEN],
            "the server's AAD offsets point at the session id"
        );

        Self {
            hello_random,
            secret,
            record,
        }
    }

    /// A client config for one connection with this probe's envelope.
    fn client_config(&self, timestamp: u32) -> Arc<rustls::ClientConfig> {
        reality_client_config(self.envelope(timestamp), self.hello_random, self.secret)
    }

    /// The captured ClientHello with this probe's envelope in the session id.
    fn authenticated_record(&self, timestamp: u32) -> Vec<u8> {
        let mut record = self.record.clone();
        let start = TLS_RECORD_HEADER_LEN + REALITY_SESSION_ID_START;
        record[start..start + REALITY_SESSION_ID_LEN].copy_from_slice(&self.envelope(timestamp));
        record
    }

    fn envelope(&self, timestamp: u32) -> [u8; 32] {
        let body = &self.record[TLS_RECORD_HEADER_LEN..];
        let random = &self.hello_random;
        let mut aad = body.to_vec();
        aad[REALITY_SESSION_ID_START..REALITY_SESSION_ID_START + REALITY_SESSION_ID_LEN].fill(0);

        let server = X25519PublicKey::from(&StaticSecret::from(REALITY_SERVER_KEY));
        let shared = StaticSecret::from(self.secret).diffie_hellman(&server);
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes())
            .expand(b"REALITY", &mut key)
            .expect("REALITY key");
        let cipher = Aes256Gcm::new_from_slice(&key).expect("REALITY cipher");

        let mut plaintext = [0u8; 16];
        plaintext[..3].copy_from_slice(&REALITY_CLIENT_VERSION);
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plaintext[8..16].copy_from_slice(&REALITY_SHORT_ID);

        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&random[20..32]),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .expect("REALITY envelope");
        sealed.try_into().expect("32-byte envelope")
    }
}

fn reality_server_config(cover_port: u16) -> TlsServerConfig {
    TlsServerConfig::new(
        REALITY_SERVER_KEY,
        vec!["0123456789abcdef".to_owned()],
        vec![REALITY_SNI.to_owned()],
        [0, 0, 0],
        [255, 255, 255],
        None,
        NetLocation {
            address: Address::Ipv4(Ipv4Addr::LOCALHOST),
            port: cover_port,
        },
        Duration::from_secs(5),
        TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN,
        [0x22; 16],
    )
    .expect("REALITY server config")
}

/// Accepts one forwarded connection, reads the expected record, and closes.
fn spawn_cover(listener: TcpListener, expected: usize) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("cover accept");
        let mut buffer = vec![0u8; expected];
        stream.read_exact(&mut buffer).await.expect("cover read");
        buffer
    })
}

/// Waits for a replay-cache count with a bounded deadline.
async fn wait_for_inflight(config: &TlsServerConfig, expected: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while config.replay_stats().in_flight != expected {
        assert!(
            tokio::time::Instant::now() < deadline,
            "replay in-flight count did not reach {expected}: {:?}",
            config.replay_stats()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn tcp_request(port: u16) -> Vec<u8> {
    let mut request = vec![0u8];
    request.extend_from_slice(&[0x22; 16]);
    request.push(0);
    request.push(Command::Tcp.as_u8());
    request.extend_from_slice(&port.to_be_bytes());
    request.push(1);
    request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    request
}

#[tokio::test]
async fn authenticated_rvs_is_answered_with_the_documented_response() {
    timeout(Duration::from_secs(10), authenticated_rvs_contract_test())
        .await
        .expect("Rvs contract test timed out");
}

async fn authenticated_rvs_contract_test() {
    let capture = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("capture listener");
    let probe = RealityProbe::capture(&capture, 1).await;
    let cover = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener");
    let cover_port = cover.local_addr().expect("cover address").port();
    let config = Arc::new(reality_server_config(cover_port));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("beam listener");
    let address = listener.local_addr().expect("beam address");
    let server = tokio::spawn({
        let config = Arc::clone(&config);
        async move {
            let (stream, _) = listener.accept().await.expect("beam accept");
            handle_connection(stream, config).await
        }
    });

    let mut client = RealityClient::connect(address, probe.client_config(7))
        .await
        .expect("client connect");
    client
        .finish_handshake()
        .await
        .expect("REALITY handshake must authenticate");

    let mut request = vec![0u8];
    request.extend_from_slice(&[0x22; 16]);
    request.push(0);
    request.push(Command::Rvs.as_u8());
    client.send(&request).await.expect("Rvs request");

    let response = client.read_to_close().await.expect("Rvs response");
    assert_eq!(
        response,
        [0x00, 0x00],
        "an authenticated Rvs must get the documented response before the close"
    );
    let outcome = timeout(Duration::from_secs(5), server)
        .await
        .expect("Rvs handler did not finish")
        .expect("Rvs handler task")
        .expect("Rvs handler");
    assert_eq!(
        outcome,
        ConnectionOutcome::Authenticated {
            command: Command::Rvs
        }
    );
    assert_eq!(
        config.replay_stats().entries,
        1,
        "the authenticated handshake must settle one replay entry"
    );
}

#[tokio::test]
async fn authenticated_handshake_settles_and_duplicate_is_forwarded() {
    timeout(
        Duration::from_secs(10),
        authenticated_handshake_settles_test(),
    )
    .await
    .expect("settled replay test timed out");
}

async fn authenticated_handshake_settles_test() {
    let capture = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("capture listener");
    let probe = RealityProbe::capture(&capture, 2).await;

    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener");
    let target_port = target.local_addr().expect("target address").port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.expect("target accept");
        stream.write_all(b"pong").await.expect("target write");
        stream.shutdown().await.expect("target shutdown");
    });

    let cover = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener");
    let cover_port = cover.local_addr().expect("cover address").port();
    let cover_task = spawn_cover(cover, probe.record.len());
    let config = Arc::new(reality_server_config(cover_port));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("beam listener");
    let address = listener.local_addr().expect("beam address");
    let serve = |config: Arc<TlsServerConfig>, listener: TcpListener| async move {
        let (stream, _) = listener.accept().await.expect("beam accept");
        handle_connection(stream, config).await
    };

    let server = tokio::spawn(serve(Arc::clone(&config), listener));
    let mut client = RealityClient::connect(address, probe.client_config(7))
        .await
        .expect("client connect");
    client
        .finish_handshake()
        .await
        .expect("REALITY handshake must authenticate");
    wait_for_inflight(&config, 0).await;
    assert_eq!(
        config.replay_stats().entries,
        1,
        "the first Finished handshake must settle one entry"
    );
    client
        .send(&tcp_request(target_port))
        .await
        .expect("VLESS request");

    let mut response = Vec::new();
    let mut buffer = [0u8; 64];
    while response.len() < 6 {
        client.read_records().await.expect("VLESS response records");
        match client.conn.reader().read(&mut buffer) {
            Ok(count) => response.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("VLESS response read failed: {error}"),
        }
    }
    assert_eq!(
        &response[..2],
        &[0x00, 0x00],
        "the VLESS response is `00 00`"
    );
    assert_eq!(&response[2..6], b"pong");
    // Closing the probe ends the relay's remaining direction.
    drop(client);

    let outcome = timeout(Duration::from_secs(5), server)
        .await
        .expect("authenticated handler did not finish")
        .expect("handler task")
        .expect("authenticated handler");
    assert_eq!(
        outcome,
        ConnectionOutcome::Authenticated {
            command: Command::Tcp
        }
    );
    let stats = config.replay_stats();
    assert_eq!(stats.entries, 1, "one settled replay entry");
    assert_eq!(stats.in_flight, 0, "no reservation may leak");
    target_task.await.expect("target task");

    // The same ClientHello is now a settled duplicate: it must be forwarded to
    // the cover and must not create a reservation or a second cache entry.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("duplicate beam listener");
    let duplicate_address = listener.local_addr().expect("duplicate address");
    let duplicate_server = tokio::spawn(serve(Arc::clone(&config), listener));
    let mut duplicate = RealityClient::connect(duplicate_address, probe.client_config(7))
        .await
        .expect("duplicate connect");
    duplicate.flush().await.expect("duplicate ClientHello");
    let outcome = timeout(Duration::from_secs(5), duplicate_server)
        .await
        .expect("duplicate handler did not finish")
        .expect("duplicate handler task")
        .expect("duplicate handler");
    assert_eq!(
        outcome,
        ConnectionOutcome::CoverForwarded,
        "a settled duplicate must go to the cover"
    );
    let forwarded = cover_task.await.expect("cover task");
    assert_eq!(
        forwarded,
        probe.authenticated_record(7),
        "the cover must receive the exact duplicate ClientHello"
    );
    let stats = config.replay_stats();
    assert_eq!(stats.entries, 1, "a duplicate must not add a cache entry");
    assert_eq!(
        stats.in_flight, 0,
        "a rejected duplicate keeps no reservation"
    );
    drop(duplicate);
}

#[tokio::test]
async fn a_peer_that_drops_before_finished_releases_the_reservation() {
    timeout(Duration::from_secs(10), peer_dropped_before_finished_test())
        .await
        .expect("peer drop test timed out");
}

async fn peer_dropped_before_finished_test() {
    let capture = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("capture listener");
    let probe = RealityProbe::capture(&capture, 3).await;
    let cover = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener");
    let cover_port = cover.local_addr().expect("cover address").port();
    let config = Arc::new(reality_server_config(cover_port));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("beam listener");
    let address = listener.local_addr().expect("beam address");
    let server = tokio::spawn({
        let config = Arc::clone(&config);
        async move {
            let (stream, _) = listener.accept().await.expect("beam accept");
            handle_connection(stream, config).await
        }
    });

    let mut client = RealityClient::connect(address, probe.client_config(7))
        .await
        .expect("client connect");
    client.flush().await.expect("ClientHello");
    wait_for_inflight(&config, 1).await;
    assert_eq!(
        config.replay_stats().entries,
        0,
        "a pending reservation is not a cache entry"
    );

    drop(client);
    let outcome = timeout(Duration::from_secs(5), server)
        .await
        .expect("handler must stop after the peer disappears")
        .expect("handler task");
    assert!(
        outcome.is_err(),
        "an unfinished TLS handshake must not authenticate: {outcome:?}"
    );
    let stats = config.replay_stats();
    assert_eq!(stats.entries, 0, "an unfinished handshake inserts nothing");
    assert_eq!(stats.in_flight, 0, "the reservation must be released");
}

#[tokio::test]
async fn concurrent_duplicates_are_first_wins() {
    timeout(Duration::from_secs(10), concurrent_duplicates_test())
        .await
        .expect("concurrent duplicate test timed out");
}

async fn concurrent_duplicates_test() {
    let capture = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("capture listener");
    let probe = RealityProbe::capture(&capture, 4).await;

    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener");
    let target_port = target.local_addr().expect("target address").port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.expect("target accept");
        stream.write_all(b"pong").await.expect("target write");
        stream.shutdown().await.expect("target shutdown");
    });

    let cover = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener");
    let cover_port = cover.local_addr().expect("cover address").port();
    let config = Arc::new(reality_server_config(cover_port));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("beam listener");
    let address = listener.local_addr().expect("beam address");

    // Both copies carry the same ClientHello, so both are admitted by the
    // reservation gate. Reading the server flight proves each copy was
    // admitted: the server starts TLS only after reserving.
    let mut first = RealityClient::connect(address, probe.client_config(7))
        .await
        .expect("first connect");
    let (first_stream, _) = listener.accept().await.expect("first accept");
    let first_server = tokio::spawn(handle_connection(first_stream, Arc::clone(&config)));
    first.flush().await.expect("first ClientHello");
    first.read_records().await.expect("first server flight");

    let mut second = RealityClient::connect(address, probe.client_config(7))
        .await
        .expect("second connect");
    let (second_stream, _) = listener.accept().await.expect("second accept");
    let second_server = tokio::spawn(handle_connection(second_stream, Arc::clone(&config)));
    second.flush().await.expect("second ClientHello");
    second.read_records().await.expect("second server flight");
    assert_eq!(
        config.replay_stats().entries,
        0,
        "two admitted copies have no settled entry yet"
    );

    // The first copy reaches Finished and settles the entry; the second keeps
    // its reservation until its own handshake finishes.
    first
        .finish_handshake()
        .await
        .expect("first REALITY handshake must authenticate");
    first
        .send(&tcp_request(target_port))
        .await
        .expect("first VLESS request");
    let mut response = Vec::new();
    let mut buffer = [0u8; 64];
    while response.len() < 6 {
        first.read_records().await.expect("first response records");
        match first.conn.reader().read(&mut buffer) {
            Ok(count) => response.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("first response read failed: {error}"),
        }
    }
    assert_eq!(&response[..2], &[0x00, 0x00]);
    assert_eq!(&response[2..6], b"pong");
    let stats = config.replay_stats();
    assert_eq!(stats.entries, 1, "the winner settles one entry");
    assert_eq!(
        stats.in_flight, 1,
        "the loser still holds its admitted reservation"
    );

    second
        .finish_handshake()
        .await
        .expect("the losing copy still completes its TLS handshake");
    let second_outcome = timeout(Duration::from_secs(5), second_server)
        .await
        .expect("second handler did not finish")
        .expect("second handler task");
    assert!(
        matches!(second_outcome, Err(TlsServerError::ReplayRejected)),
        "the second Finished handshake must be rejected: {second_outcome:?}"
    );
    let stats = config.replay_stats();
    assert_eq!(stats.entries, 1, "first-wins keeps exactly one entry");
    assert_eq!(stats.in_flight, 0, "the loser's reservation is released");

    drop(first);
    let first_outcome = timeout(Duration::from_secs(5), first_server)
        .await
        .expect("first handler did not finish")
        .expect("first handler task")
        .expect("first handler");
    assert_eq!(
        first_outcome,
        ConnectionOutcome::Authenticated {
            command: Command::Tcp
        }
    );
    target_task.await.expect("target task");
    drop(cover);
}

#[tokio::test]
async fn legacy_udp_limiter_rejects_when_pool_is_exhausted() {
    timeout(Duration::from_secs(10), legacy_udp_limiter_rejection_test())
        .await
        .expect("legacy UDP limiter test timed out");
}

async fn legacy_udp_limiter_rejection_test() {
    let capture = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("capture listener");
    let probe = RealityProbe::capture(&capture, 9).await;

    let cover = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener");
    let cover_port = cover.local_addr().expect("cover address").port();
    let config = Arc::new(
        reality_server_config(cover_port)
            .with_legacy_udp_limiter(Arc::new(tokio::sync::Semaphore::new(1))),
    );
    let _held = config
        .legacy_udp_limiter()
        .try_acquire_owned()
        .expect("initial legacy UDP permit");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("beam listener");
    let address = listener.local_addr().expect("beam address");

    let mut client = RealityClient::connect(address, probe.client_config(11))
        .await
        .expect("client connect");
    let (server_stream, _) = listener.accept().await.expect("server accept");
    let server = tokio::spawn(handle_connection(server_stream, Arc::clone(&config)));

    client
        .finish_handshake()
        .await
        .expect("REALITY handshake must authenticate");
    let mut udp_request = vec![0u8];
    udp_request.extend_from_slice(&[0x22; 16]);
    udp_request.push(0);
    udp_request.push(Command::Udp.as_u8());
    udp_request.extend_from_slice(&53_u16.to_be_bytes());
    udp_request.push(1);
    udp_request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    client.send(&udp_request).await.expect("VLESS UDP request");

    let outcome = timeout(Duration::from_secs(5), server)
        .await
        .expect("handler did not finish")
        .expect("handler task");
    assert!(
        matches!(outcome, Err(TlsServerError::LegacyUdpLimited)),
        "exhausted legacy UDP pool must reject with LegacyUdpLimited: {outcome:?}"
    );
    assert_eq!(config.metrics().snapshot().legacy_udp_limited, 1);
    drop(client);
    drop(cover);
}
