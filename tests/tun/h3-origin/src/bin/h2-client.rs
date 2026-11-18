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
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::Barrier;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    self, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

const MARKER: &[u8] = b"beam-tun-h3-ok\n";
/// Per-stream response cap: the origin never emits more than this per request.
const MAX_BODY_LEN: usize = 64 * 1024 * 1024;
/// Aggregate cap over every stream in one run (documented runs total ~1 MiB).
const MAX_TOTAL_BYTES: usize = 512 * 1024 * 1024;
/// Hard cap on concurrent streams; bounds the spawned task count.
const MAX_STREAMS: usize = 1024;
// Per-stage waits: a stalled stage reports its own name instead of hanging
// on the external runner deadline. The overall bound below covers their sum.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// No single body frame may stall longer than this; steady multi-frame
/// progress of a large body is unaffected.
const FRAME_TIMEOUT: Duration = Duration::from_secs(15);
/// Whole-run bound: covers the sequential stage bounds above with margin and
/// fires inside the harness 90 s runner budget so the JSON verdict is written.
const OVERALL_TIMEOUT: Duration = Duration::from_secs(60);

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
                if !(1..=MAX_STREAMS).contains(&streams) {
                    bail!("--streams must be between 1 and {MAX_STREAMS}");
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
                if !(1..=MAX_BODY_LEN).contains(&len) {
                    bail!("bytes must be between 1 and {MAX_BODY_LEN}");
                }
                return Ok(len);
            }
        }
    }
    Ok(MARKER.len())
}

/// Rejects runs whose streams times body size would exceed the aggregate
/// budget before any socket or allocation happens.
fn check_aggregate_budget(streams: usize, per_stream: usize) -> Result<()> {
    let total = per_stream
        .checked_mul(streams)
        .context("stream byte total overflows")?;
    if total > MAX_TOTAL_BYTES {
        bail!(
            "requested {total} bytes across {streams} streams exceeds the aggregate budget of {MAX_TOTAL_BYTES} bytes; reduce --streams or ?bytes="
        );
    }
    Ok(())
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

#[derive(Default)]
struct Verdict {
    connections: usize,
    completed: usize,
    peak_active: usize,
    bytes: usize,
    ttfb_ms: f64,
    errors: Vec<String>,
}

async fn run_requests(url: &str, streams: usize) -> Result<Verdict> {
    let uri: http::Uri = url.parse().with_context(|| format!("invalid URL: {url}"))?;
    let (host, addr) = split_url(url)?;
    let per_stream = expected_len(url)?;
    check_aggregate_budget(streams, per_stream)?;
    // One shared body: cloning it per stream would multiply a large
    // allocation across every concurrent stream.
    let expected: Arc<Vec<u8>> = Arc::new(expected_body(per_stream));

    let mut client = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(client));
    let server_name = ServerName::try_from(host.clone())
        .with_context(|| format!("invalid server name: {host}"))?;

    let tcp = match timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            bail!("could not connect to {addr}: {error}");
        }
        Err(_) => {
            bail!(
                "could not connect to {addr}: timed out after {}s",
                CONNECT_TIMEOUT.as_secs()
            );
        }
    };
    let _ = tcp.set_nodelay(true);
    let tls = match timeout(TLS_TIMEOUT, connector.connect(server_name, tcp)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => bail!("TLS handshake with {addr} failed: {error}"),
        Err(_) => bail!(
            "TLS handshake with {addr} timed out after {}s",
            TLS_TIMEOUT.as_secs()
        ),
    };
    let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    if negotiated.as_deref() != Some(b"h2") {
        bail!("origin did not negotiate ALPN h2: {negotiated:?}");
    }

    let (sender, connection) = match timeout(
        HANDSHAKE_TIMEOUT,
        hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(TokioIo::new(tls)),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(error)) => {
            bail!("could not start the HTTP/2 client connection: {error:#}");
        }
        Err(_) => bail!(
            "HTTP/2 handshake timed out after {}s",
            HANDSHAKE_TIMEOUT.as_secs()
        ),
    };
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
        let uri = uri.clone();
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
                let response = match timeout(SEND_TIMEOUT, sender.send_request(request)).await {
                    Ok(Ok(response)) => response,
                    Ok(Err(error)) => return Err(format!("request failed: {error}")),
                    Err(_) => {
                        return Err(format!(
                            "request submission timed out after {}s",
                            SEND_TIMEOUT.as_secs()
                        ));
                    }
                };
                let status = response.status();
                if status != StatusCode::OK {
                    return Err(format!("status {status}"));
                }
                let mut body = response.into_body();
                // Streaming compare against the shared body: no per-stream
                // receive buffer is ever allocated.
                let mut done = 0usize;
                let mut ttfb_ms = None;
                loop {
                    let frame = match timeout(FRAME_TIMEOUT, body.frame()).await {
                        Err(_) => {
                            return Err(format!(
                                "response body stalled: no frame for {}s (got {done} of {} bytes)",
                                FRAME_TIMEOUT.as_secs(),
                                expected.len()
                            ));
                        }
                        Ok(None) => break,
                        Ok(Some(frame)) => frame.map_err(|error| format!("body error: {error}"))?,
                    };
                    if let Some(data) = frame.data_ref() {
                        if ttfb_ms.is_none() {
                            ttfb_ms = Some(request_started.elapsed().as_secs_f64() * 1000.0);
                        }
                        let Some(end) = done
                            .checked_add(data.len())
                            .filter(|end| *end <= expected.len())
                        else {
                            return Err(format!(
                                "body mismatch: got more than {} expected bytes",
                                expected.len()
                            ));
                        };
                        if expected[done..end] != data[..] {
                            return Err(format!(
                                "body mismatch at byte {done}: expected {} bytes",
                                expected.len()
                            ));
                        }
                        done = end;
                    }
                }
                if done != expected.len() {
                    return Err(format!(
                        "body mismatch: got {done} bytes, expected {}",
                        expected.len()
                    ));
                }
                Ok((done, ttfb_ms.unwrap_or(0.0)))
            }
            .await;
            active.fetch_sub(1, Ordering::SeqCst);
            result
        }));
    }

    barrier.wait().await;

    let mut verdict = Verdict {
        connections: 1,
        ..Verdict::default()
    };
    for handle in handles {
        match handle.await {
            Ok(Ok((len, stream_ttfb))) => {
                verdict.completed += 1;
                verdict.bytes += len;
                verdict.ttfb_ms = verdict.ttfb_ms.max(stream_ttfb);
            }
            Ok(Err(error)) => verdict.errors.push(error),
            Err(error) => verdict.errors.push(format!("stream task failed: {error}")),
        }
    }
    verdict.peak_active = peak.load(Ordering::SeqCst);
    Ok(verdict)
}

fn write_verdict(mut stdout: impl Write, out: Option<&str>, result: &str) -> Result<()> {
    let console = writeln!(stdout, "{result}")
        .and_then(|()| stdout.flush())
        .context("could not write verdict to stdout");
    let file = out.map_or(Ok(()), |path| {
        fs::write(path, format!("{result}\n")).with_context(|| format!("could not write {path}"))
    });
    console.and(file)
}

async fn run() -> Result<()> {
    let Args { url, streams, out } = parse_args()?;
    let started = Instant::now();
    let Verdict {
        connections,
        completed,
        peak_active,
        bytes,
        ttfb_ms,
        errors,
    } = match timeout(OVERALL_TIMEOUT, run_requests(&url, streams)).await {
        Ok(Ok(verdict)) => verdict,
        Ok(Err(error)) => Verdict {
            errors: vec![format!("{error:#}")],
            ..Verdict::default()
        },
        Err(_) => Verdict {
            errors: vec![format!(
                "run exceeded the overall {}s bound; stages stalled",
                OVERALL_TIMEOUT.as_secs()
            )],
            ..Verdict::default()
        },
    };
    let total_ms = started.elapsed().as_secs_f64() * 1000.0;
    let hash_ok = completed == streams && errors.is_empty();
    let ok = hash_ok;
    let errors_json = errors
        .iter()
        .map(|error| format!("\"{}\"", json_escape(error)))
        .collect::<Vec<_>>()
        .join(",");
    let result = format!(
        "{{\"ok\":{ok},\"connections\":{connections},\"streams\":{streams},\"completed\":{completed},\
         \"peak_active\":{peak_active},\"bytes\":{bytes},\"hash_ok\":{hash_ok},\
         \"ttfb_ms\":{ttfb_ms:.3},\"total_ms\":{total_ms:.3},\"errors\":[{errors_json}]}}"
    );
    write_verdict(io::stdout().lock(), out.as_deref(), &result)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_budget_accepts_the_documented_run() {
        // The harness runs 16 streams of 64 KiB: ~1 MiB total.
        assert!(check_aggregate_budget(16, 65536).is_ok());
    }

    #[test]
    fn aggregate_budget_rejects_streams_times_bytes_overflow() {
        // 16 streams of 64 MiB would allocate ~1 GiB across tasks.
        let error = check_aggregate_budget(16, 64 * 1024 * 1024).unwrap_err();
        assert!(format!("{error:#}").contains("aggregate budget"));
    }

    #[test]
    fn expected_len_rejects_over_max_body() {
        assert!(expected_len("https://example.com/?bytes=67108865").is_err());
    }
}
