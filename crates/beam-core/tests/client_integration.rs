//! End-to-end loopback tests for `beam_core::client` directly against
//! `beam_core::tls::server::handle_connection`.

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use beam_core::address::{Address, NetLocation};
use beam_core::client::{BeamClientConfig, XudpClient, XudpClientConfig, dial_tcp};
use beam_core::reality::RealityClientConfig;
use beam_core::tls::server::{ConnectionOutcome, TlsServerConfig, handle_connection};
use beam_core::tls::{MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN};
use beam_core::vless::Command;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET: [u8; 32] = [0x37; 32];
const USER_ID: [u8; 16] = [0xaa; 16];
const SHORT_ID_HEX: &str = "0123456789abcdef";
const COVER_SNI: &str = "whatsapp.net";

fn server_public_key() -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(SERVER_SECRET)).to_bytes()
}

fn server_config(cover_port: u16) -> Arc<TlsServerConfig> {
    Arc::new(
        TlsServerConfig::new(
            SERVER_SECRET,
            vec![SHORT_ID_HEX.to_string()],
            vec![COVER_SNI.to_string()],
            [0, 0, 0],
            [255, 255, 255],
            Some(Duration::from_secs(300)),
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: cover_port,
            },
            Duration::from_secs(5),
            TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN,
            USER_ID,
        )
        .expect("server config"),
    )
}

fn client_config(server_addr: SocketAddr, short_id_hex: &str) -> BeamClientConfig {
    let reality = RealityClientConfig::new(server_public_key(), short_id_hex, COVER_SNI)
        .expect("reality client config");
    BeamClientConfig::new(server_addr, reality, USER_ID)
}

#[derive(Debug)]
struct AcceptAnyInnerCert;

impl ServerCertVerifier for AcceptAnyInnerCert {
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
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn make_self_signed_tls_server() -> Arc<rustls::ServerConfig> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
    let params = rcgen::CertificateParams::new(vec!["inner.example".to_string()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self signed");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("tls 1.3")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("server cert");
    Arc::new(cfg)
}

#[tokio::test]
async fn tcp_echo_and_bulk_transfer() {
    timeout(Duration::from_secs(10), async {
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind target");
        let target_port = target_listener.local_addr().expect("target addr").port();
        let target_task = tokio::spawn(async move {
            let (mut sock, _) = target_listener.accept().await.expect("accept target");
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = sock.read(&mut buf).await.expect("target read");
                if n == 0 {
                    break;
                }
                sock.write_all(&buf[..n]).await.expect("target write");
            }
            let _ = sock.shutdown().await;
        });

        let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind cover");
        let cover_port = cover_listener.local_addr().expect("cover addr").port();

        let beam_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind beam");
        let beam_addr = beam_listener.local_addr().expect("beam addr");
        let cfg = server_config(cover_port);
        let server_task = tokio::spawn(async move {
            let (sock, _) = beam_listener.accept().await.expect("accept beam");
            handle_connection(sock, cfg).await
        });

        let client_cfg = client_config(beam_addr, SHORT_ID_HEX);
        let stream = dial_tcp(
            &client_cfg,
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: target_port,
            },
        )
        .await
        .expect("dial_tcp");

        // Send 256 KiB of patterned data and verify exact echo.
        let payload: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 251) as u8).collect();
        let write_payload = payload.clone();
        let (mut r, mut w) = tokio::io::split(stream);
        let writer = tokio::spawn(async move {
            w.write_all(&write_payload).await.expect("client write");
            w.shutdown().await.expect("client shutdown");
        });

        let mut received = Vec::with_capacity(payload.len());
        r.read_to_end(&mut received).await.expect("client read");
        writer.await.expect("writer join");
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);

        drop(r);
        let outcome = server_task
            .await
            .expect("server join")
            .expect("server outcome");
        assert_eq!(
            outcome,
            ConnectionOutcome::Authenticated {
                command: Command::Tcp
            }
        );
        target_task.await.expect("target join");
        drop(cover_listener);
    })
    .await
    .expect("tcp echo test timed out");
}

#[tokio::test]
async fn tls_in_tls_switches_client_to_vision_direct() {
    timeout(Duration::from_secs(10), async {
        let inner_acceptor = TlsAcceptor::from(make_self_signed_tls_server());
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind target");
        let target_port = target_listener.local_addr().expect("target addr").port();
        let target_task = tokio::spawn(async move {
            let (sock, _) = target_listener.accept().await.expect("accept target");
            let mut tls = inner_acceptor.accept(sock).await.expect("inner tls accept");
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                let n = tls.read(&mut buf).await.expect("inner read");
                if n == 0 {
                    break;
                }
                tls.write_all(&buf[..n]).await.expect("inner write");
            }
            let _ = tls.shutdown().await;
        });

        let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind cover");
        let cover_port = cover_listener.local_addr().expect("cover addr").port();

        let beam_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind beam");
        let beam_addr = beam_listener.local_addr().expect("beam addr");
        let cfg = server_config(cover_port);
        let server_task = tokio::spawn(async move {
            let (sock, _) = beam_listener.accept().await.expect("accept beam");
            handle_connection(sock, cfg).await
        });

        let client_cfg = client_config(beam_addr, SHORT_ID_HEX);
        let vision_stream = dial_tcp(
            &client_cfg,
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: target_port,
            },
        )
        .await
        .expect("dial_tcp");

        let inner_client_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyInnerCert))
            .with_no_client_auth(),
        );
        let connector = TlsConnector::from(inner_client_cfg);
        let sni = ServerName::try_from("inner.example").expect("inner sni");
        let mut inner_tls = connector
            .connect(sni, vision_stream)
            .await
            .expect("inner TLS 1.3 handshake over Vision");

        // Exchange enough application data to trigger Vision Direct in both directions.
        let payload = vec![0x5cu8; 64 * 1024];
        inner_tls.write_all(&payload).await.expect("inner write");
        inner_tls.flush().await.expect("inner flush");

        let mut echoed = vec![0u8; payload.len()];
        inner_tls
            .read_exact(&mut echoed)
            .await
            .expect("inner read_exact");
        assert_eq!(echoed, payload);

        let (vision_inner, _) = inner_tls.get_ref();
        assert!(
            vision_inner.write_is_raw(),
            "client Vision write side must switch to Direct on inner TLS 1.3"
        );
        assert!(
            vision_inner.read_is_raw(),
            "client Vision read side must switch to Direct on inner TLS 1.3"
        );

        let _ = inner_tls.shutdown().await;
        drop(inner_tls);

        let outcome = server_task
            .await
            .expect("server join")
            .expect("server outcome");
        assert_eq!(
            outcome,
            ConnectionOutcome::Authenticated {
                command: Command::Tcp
            }
        );
        target_task.await.expect("target join");
        drop(cover_listener);
    })
    .await
    .expect("tls-in-tls Vision Direct test timed out");
}

#[tokio::test]
async fn xudp_echo_and_alternate_source_reply() {
    timeout(Duration::from_secs(10), async {
        // Primary UDP echo socket + alternate-source socket (full-cone test).
        let primary = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind primary udp");
        let primary_port = primary.local_addr().expect("primary addr").port();
        let alt = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind alt udp");
        let alt_port = alt.local_addr().expect("alt addr").port();

        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, peer) = primary.recv_from(&mut buf).await.expect("udp recv 1");
            primary
                .send_to(&buf[..n], peer)
                .await
                .expect("udp send primary");
            // Second packet: reply from the alternate source port.
            let (n2, peer2) = primary.recv_from(&mut buf).await.expect("udp recv 2");
            alt.send_to(&buf[..n2], peer2).await.expect("udp send alt");
        });

        let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind cover");
        let cover_port = cover_listener.local_addr().expect("cover addr").port();

        let beam_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind beam");
        let beam_addr = beam_listener.local_addr().expect("beam addr");
        let cfg = server_config(cover_port);
        let server_task = tokio::spawn(async move {
            let (sock, _) = beam_listener.accept().await.expect("accept beam");
            handle_connection(sock, cfg).await
        });

        let client_cfg = client_config(beam_addr, SHORT_ID_HEX);
        let mux = XudpClient::connect(&client_cfg, XudpClientConfig::default())
            .await
            .expect("XudpClient::connect");

        let dest = NetLocation {
            address: Address::Ipv4(Ipv4Addr::LOCALHOST),
            port: primary_port,
        };
        let mut session = mux.open_session(dest).expect("open_session");

        session.send(b"hello-xudp").await.expect("send 1");
        let reply1 = session.recv().await.expect("reply 1");
        assert_eq!(reply1.payload, b"hello-xudp");
        assert_eq!(
            reply1.source,
            Some(NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: primary_port,
            })
        );

        session.send(b"alt-source").await.expect("send 2");
        let reply2 = session.recv().await.expect("reply 2");
        assert_eq!(reply2.payload, b"alt-source");
        assert_eq!(
            reply2.source,
            Some(NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: alt_port,
            })
        );

        session.close().await.expect("close session");
        mux.close().await;

        let outcome = server_task
            .await
            .expect("server join")
            .expect("server outcome");
        assert_eq!(
            outcome,
            ConnectionOutcome::Authenticated {
                command: Command::Mux
            }
        );
        udp_task.await.expect("udp task join");
        drop(cover_listener);
    })
    .await
    .expect("xudp test timed out");
}

#[tokio::test]
async fn wrong_short_id_hits_cover_and_client_rejects_cover_certificate() {
    timeout(Duration::from_secs(10), async {
        // Real TLS cover with a normal self-signed Ed25519 cert (NOT HMAC-signed).
        let cover_acceptor = TlsAcceptor::from(make_self_signed_tls_server());
        let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind cover");
        let cover_port = cover_listener.local_addr().expect("cover addr").port();
        let cover_task = tokio::spawn(async move {
            let (sock, _) = cover_listener.accept().await.expect("accept cover");
            let _ = cover_acceptor.accept(sock).await;
        });

        let beam_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind beam");
        let beam_addr = beam_listener.local_addr().expect("beam addr");
        let cfg = server_config(cover_port);
        let server_task = tokio::spawn(async move {
            let (sock, _) = beam_listener.accept().await.expect("accept beam");
            handle_connection(sock, cfg).await
        });

        let wrong_cfg = client_config(beam_addr, "fedcba9876543210");
        let err = dial_tcp(
            &wrong_cfg,
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: 80,
            },
        )
        .await;
        assert!(
            err.is_err(),
            "client must reject a non-REALITY cover certificate"
        );

        let outcome = server_task
            .await
            .expect("server join")
            .expect("server outcome");
        assert_eq!(outcome, ConnectionOutcome::CoverForwarded);
        cover_task.await.expect("cover task join");
    })
    .await
    .expect("wrong short id test timed out");
}
