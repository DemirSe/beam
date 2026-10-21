//! Integration tests for the REALITY TLS server adapter.

use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use beam_core::address::{Address, NetLocation};
use beam_core::tls::server::{ConnectionOutcome, ReplayStream, TlsServerConfig, handle_connection};
use beam_core::tls::{MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
