//! Deterministic multiplexing client for the full-TUN harness.
//!
//! Opens exactly one TLS connection with ALPN `h2` to the local HTTP/2 origin,
//! issues `--streams` concurrent requests on it, and verifies every response
//! body byte-for-byte against the marker the origin returns. The test-only
//! verifier accepts the origin's throwaway self-signed certificate.
//!
//! The JSON result is the client half of the multiplexing evidence: one
//! connection, N completed streams, the peak number of in-flight streams and
//! the exact-body verdict. The harness cross-checks the origin log for the same
//! connection id.

use std::{
    env, fs,
    net::{SocketAddr, ToSocketAddrs},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::Barrier;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    self, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

const MARKER: &[u8] = b"beam-tun-h3-ok\n";

/// The lab origin is freshly self-signed on every run; there is no CA to pin.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
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
        _certificate: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

struct Args {
    url: String,
    streams: usize,
    out: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut args = env::args().skip(1);
    let mut url: Option<String> = None;
    let mut streams = 16usize;
    let mut out: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--url" => {
                url = Some(
                    args.next()
                        .context("--url requires an https:// URL, for example https://10.10.2.2:8443/?bytes=65536")?,
                );
            }
            "--streams" => {
                let raw = args.next().context("--streams requires a count")?;
                streams = raw
                    .parse()
                    .with_context(|| format!("invalid stream count: {raw}"))?;
                if !(1..=1024).contains(&streams) {
                    bail!("--streams must be between 1 and 1024");
                }
            }
            "--out" => {
                out = Some(args.next().context("--out requires a file path")?);
            }
            "-h" | "--help" => {
                println!("usage: h2-client --url URL [--streams N] [--out FILE]");
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    let url = url.context("--url is required")?;
    if !url.starts_with("https://") {
        bail!("--url must start with https://");
    }
    Ok(Args { url, streams, out })
}

/// Splits `https://host:port/path?query` into the authority and a socket
/// address. Bare IPv6 hosts are accepted in brackets.
fn split_url(url: &str) -> Result<(String, SocketAddr)> {
    let rest = url
        .strip_prefix("https://")
        .context("URL must start with https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        bail!("URL has no host");
    }
    let (host, port) = if let Some(remainder) = authority.strip_prefix('[') {
        let (host, tail) = remainder
            .split_once(']')
            .context("unterminated IPv6 literal in URL")?;
        let port = match tail {
            "" => 443,
            value => value
                .strip_prefix(':')
                .context("unexpected characters after the IPv6 literal")?
                .parse()
                .context("invalid port")?,
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse().context("invalid port")?),
            None => (authority.to_string(), 443),
        }
    };
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .with_context(|| format!("could not resolve {host}:{port}"))?
        .next()
        .context("host resolved to no address")?;
    Ok((host, addr))
}

/// Expected body size from the URL's `?bytes=` parameter.
fn expected_len(url: &str) -> Result<usize> {
    if let Some(query) = url.split_once('?').map(|(_, query)| query) {
        let query = query.split('#').next().unwrap_or(query);
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if key == "bytes" {
                let len: usize = value
                    .parse()
                    .with_context(|| format!("invalid bytes parameter: {value}"))?;
                if !(1..=64 * 1024 * 1024).contains(&len) {
                    bail!("bytes must be between 1 and 67108864");
                }
                return Ok(len);
            }
        }
    }
    Ok(MARKER.len())
}

fn expected_body(len: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(len);
    while body.len() < len {
        body.extend_from_slice(MARKER);
    }
    body.truncate(len);
    body
}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out
}

async fn run() -> Result<()> {
    let Args { url, streams, out } = parse_args()?;
    let (host, addr) = split_url(&url)?;
    let expected = expected_body(expected_len(&url)?);

    let mut client = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(client));
    let server_name = ServerName::try_from(host.clone())
        .with_context(|| format!("invalid server name: {host}"))?;

    let started = Instant::now();
    let mut errors: Vec<String> = Vec::new();

    let tcp = match tokio::net::TcpStream::connect(addr).await {
        Ok(stream) => stream,
        Err(error) => {
            bail!("could not connect to {addr}: {error}");
        }
    };
    let _ = tcp.set_nodelay(true);
    let tls = match connector.connect(server_name, tcp).await {
        Ok(stream) => stream,
        Err(error) => bail!("TLS handshake with {addr} failed: {error}"),
    };
    let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    if negotiated.as_deref() != Some(b"h2") {
        bail!("origin did not negotiate ALPN h2: {negotiated:?}");
    }

    let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tls))
        .await
        .context("could not start the HTTP/2 client connection")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("h2-client: connection driver ended: {error}");
        }
    });

    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(streams + 1));
    let mut handles = Vec::with_capacity(streams);

    for _ in 0..streams {
        let mut sender = sender.clone();
        let uri: http::Uri = url.parse().with_context(|| format!("invalid URL: {url}"))?;
        let expected = expected.clone();
        let active = active.clone();
        let peak = peak.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(current, Ordering::SeqCst);
            let request_started = Instant::now();
            let result = async {
                let request = Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Full::new(Bytes::new()))
                    .map_err(|error| format!("could not build the request: {error}"))?;
                let response = sender
                    .send_request(request)
                    .await
                    .map_err(|error| format!("request failed: {error}"))?;
                let status = response.status();
                if status != StatusCode::OK {
                    return Err(format!("status {status}"));
                }
                let mut body = response.into_body();
                let mut received = Vec::with_capacity(expected.len());
                let mut ttfb_ms = None;
                while let Some(frame) = body.frame().await {
                    let frame = frame.map_err(|error| format!("body error: {error}"))?;
                    if let Some(data) = frame.data_ref() {
                        if ttfb_ms.is_none() {
                            ttfb_ms = Some(request_started.elapsed().as_secs_f64() * 1000.0);
                        }
                        received.extend_from_slice(data);
                    }
                }
                if received != expected {
                    return Err(format!(
                        "body mismatch: got {} bytes, expected {}",
                        received.len(),
                        expected.len()
                    ));
                }
                Ok((received.len(), ttfb_ms.unwrap_or(0.0)))
            }
            .await;
            active.fetch_sub(1, Ordering::SeqCst);
            result
        }));
    }

    barrier.wait().await;

    let mut bytes = 0usize;
    let mut ttfb_ms = 0.0f64;
    let mut completed = 0usize;
    for handle in handles {
        match handle.await {
            Ok(Ok((len, stream_ttfb))) => {
                completed += 1;
                bytes += len;
                ttfb_ms = ttfb_ms.max(stream_ttfb);
            }
            Ok(Err(error)) => errors.push(error),
            Err(error) => errors.push(format!("stream task failed: {error}")),
        }
    }
    let total_ms = started.elapsed().as_secs_f64() * 1000.0;
    let peak_active = peak.load(Ordering::SeqCst);
    let hash_ok = completed == streams && errors.is_empty();
    let ok = hash_ok;

    let errors_json = errors
        .iter()
        .map(|error| format!("\"{}\"", json_escape(error)))
        .collect::<Vec<_>>()
        .join(",");
    let result = format!(
        "{{\"ok\":{ok},\"connections\":1,\"streams\":{streams},\"completed\":{completed},\
         \"peak_active\":{peak_active},\"bytes\":{bytes},\"hash_ok\":{hash_ok},\
         \"ttfb_ms\":{ttfb_ms:.3},\"total_ms\":{total_ms:.3},\"errors\":[{errors_json}]}}"
    );
    if let Some(path) = out {
        fs::write(&path, format!("{result}\n"))
            .with_context(|| format!("could not write {path}"))?;
    }
    println!("{result}");
    if !ok {
        bail!(
            "{completed}/{streams} streams verified, {} error(s)",
            errors.len()
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("h2-client: {error:#}");
            ExitCode::FAILURE
        }
    }
}
