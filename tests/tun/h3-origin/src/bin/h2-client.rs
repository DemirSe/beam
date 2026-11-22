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
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Write},
    net::{Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
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
/// Upper bound on resolved addresses attempted per run.
const MAX_RESOLVED_ADDRS: usize = 16;
// Per-stage waits: a stalled stage reports its own name instead of hanging
// on the external runner deadline. The overall bound below covers their sum.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-address TCP connect cap when alternate resolved addresses remain.
const PER_ADDR_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TLS_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounded wait for clean HTTP/2 connection-driver teardown after streams end.
const DRIVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
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

#[derive(Debug)]
struct Args {
    url: String,
    streams: usize,
    out: Option<PathBuf>,
}

/// Validates the `https://` scheme case-insensitively and normalizes it to
/// lowercase `https://`.
fn normalize_https_url(raw: &str) -> Result<String> {
    if !raw
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    {
        bail!("--url must start with https://");
    }
    Ok(format!("https://{}", &raw[8..]))
}

fn parse_args() -> Result<Args> {
    parse_args_from(env::args_os().skip(1))
}

fn parse_args_from(args: impl IntoIterator<Item = OsString>) -> Result<Args> {
    let mut args = args.into_iter();
    let mut url: Option<String> = None;
    let mut streams = 16usize;
    let mut out: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        let Some(flag) = arg.to_str() else {
            bail!("invalid non-UTF-8 argument: {arg:?}");
        };
        match flag {
            "--url" => {
                let raw = args.next().context(
                    "--url requires an https:// URL, for example https://10.10.2.2:8443/?bytes=65536",
                )?;
                url = Some(
                    raw.to_str()
                        .context("--url value must be valid UTF-8")?
                        .to_owned(),
                );
            }
            "--streams" => {
                let raw = args.next().context("--streams requires a count")?;
                let raw = raw
                    .to_str()
                    .with_context(|| format!("--streams value must be valid UTF-8: {raw:?}"))?;
                streams = raw
                    .parse()
                    .with_context(|| format!("invalid stream count: {raw}"))?;
                if !(1..=MAX_STREAMS).contains(&streams) {
                    bail!("--streams must be between 1 and {MAX_STREAMS}");
                }
            }
            "--out" => {
                out = Some(PathBuf::from(
                    args.next().context("--out requires a file path")?,
                ));
            }
            "-h" | "--help" => {
                println!("usage: h2-client --url URL [--streams N] [--out FILE]");
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    let url = normalize_https_url(&url.context("--url is required")?)?;
    Ok(Args { url, streams, out })
}

/// Parses and validates the `https://` authority before any DNS lookup or
/// connection work. Bare IPv6 literals must be enclosed in brackets.
fn parse_https_authority(url: &str) -> Result<(String, u16)> {
    let normalized = normalize_https_url(url)?;
    let rest = normalized
        .strip_prefix("https://")
        .context("URL must start with https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        bail!("URL has no host");
    }
    if authority.contains('@') {
        bail!("URL authority must not contain userinfo (`user@`)");
    }
    let (host, port) = if let Some(remainder) = authority.strip_prefix('[') {
        let (host, tail) = remainder
            .split_once(']')
            .context("unterminated IPv6 literal in URL")?;
        host.parse::<Ipv6Addr>()
            .with_context(|| format!("invalid IPv6 literal in URL: [{host}]"))?;
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
        if authority.matches(':').count() > 1 {
            bail!(
                "unbracketed IPv6 literal in URL authority `{authority}`; enclose IPv6 addresses in brackets, for example https://[::1]:8443/"
            );
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                if host.is_empty() {
                    bail!("URL has no host");
                }
                (host.to_string(), port.parse().context("invalid port")?)
            }
            None => (authority.to_string(), 443),
        }
    };
    Ok((host, port))
}

fn resolve_authority(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("could not resolve {host}:{port}"))?
        .take(MAX_RESOLVED_ADDRS)
        .collect();
    if addrs.is_empty() {
        bail!("host resolved to no address");
    }
    Ok(addrs)
}

/// Attempts TCP connections across resolved addresses in order within a bounded
/// total budget so a dual-stack hostname can fall back when the first address
/// is unreachable.
async fn connect_any(
    addresses: &[SocketAddr],
    total_budget: Duration,
    per_addr_cap: Duration,
) -> Result<(tokio::net::TcpStream, SocketAddr)> {
    let deadline = Instant::now() + total_budget;
    let mut errors = Vec::new();
    for (index, &addr) in addresses.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            errors.push(format!(
                "{addr}: overall connect budget ({}s) exhausted",
                total_budget.as_secs()
            ));
            break;
        }
        let is_last = index + 1 == addresses.len();
        let attempt_budget = if is_last {
            remaining
        } else {
            remaining.min(per_addr_cap)
        };
        match timeout(attempt_budget, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok((stream, addr)),
            Ok(Err(error)) => errors.push(format!("{addr}: {error}")),
            Err(_) => errors.push(format!(
                "{addr}: timed out after {}ms",
                attempt_budget.as_millis()
            )),
        }
    }
    bail!(
        "could not connect to any resolved address: {}",
        errors.join("; ")
    );
}

/// Default body size when `?bytes=` is omitted, matching `h3-origin`'s
/// `H3_BODY_BYTES` convention.
fn default_body_len_from(raw: Option<&OsStr>) -> Result<usize> {
    let Some(raw) = raw else {
        return Ok(MARKER.len());
    };
    let raw = raw.to_str().context("H3_BODY_BYTES must be valid UTF-8")?;
    let len: usize = raw
        .parse()
        .with_context(|| format!("invalid H3_BODY_BYTES: {raw}"))?;
    if !(1..=MAX_BODY_LEN).contains(&len) {
        bail!("H3_BODY_BYTES must be between 1 and {MAX_BODY_LEN}");
    }
    Ok(len)
}

/// Expected body size from the URL's `?bytes=` parameter, falling back to
/// `H3_BODY_BYTES` or `MARKER.len()` so client and origin agree by default.
fn expected_len(url: &str) -> Result<usize> {
    expected_len_with_default(url, env::var_os("H3_BODY_BYTES").as_deref())
}

fn expected_len_with_default(url: &str, default_env: Option<&OsStr>) -> Result<usize> {
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
    default_body_len_from(default_env)
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
    let url = normalize_https_url(url)?;
    let (host, port) = parse_https_authority(&url)?;
    let uri: http::Uri = url.parse().with_context(|| format!("invalid URL: {url}"))?;
    let per_stream = expected_len(&url)?;
    check_aggregate_budget(streams, per_stream)?;
    let server_name = ServerName::try_from(host.clone())
        .with_context(|| format!("invalid server name: {host}"))?;
    let addresses = resolve_authority(&host, port)?;
    // One shared body: cloning it per stream would multiply a large
    // allocation across every concurrent stream.
    let expected: Arc<Vec<u8>> = Arc::new(expected_body(per_stream));

    let mut client = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(client));

    let (tcp, addr) = connect_any(&addresses, CONNECT_TIMEOUT, PER_ADDR_CONNECT_TIMEOUT).await?;
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
    let mut driver_handle = tokio::spawn(async move {
        connection.await.map_err(|error| {
            eprintln!("h2-client: connection driver ended: {error}");
            format!("connection driver failed: {error}")
        })
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
    // Drop the template sender once every stream task owns its clone so that
    // finishing all streams lets the HTTP/2 driver observe clean shutdown.
    drop(sender);

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
    collect_driver_outcome(
        &mut driver_handle,
        DRIVER_SHUTDOWN_TIMEOUT,
        &mut verdict.errors,
    )
    .await;
    verdict.peak_active = peak.load(Ordering::SeqCst);
    Ok(verdict)
}

/// Awaits bounded HTTP/2 connection-driver teardown and records any driver
/// failure or stalled shutdown in `errors` so it surfaces in the verdict.
async fn collect_driver_outcome(
    driver_handle: &mut tokio::task::JoinHandle<std::result::Result<(), String>>,
    shutdown_budget: Duration,
    errors: &mut Vec<String>,
) {
    match timeout(shutdown_budget, &mut *driver_handle).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => errors.push(error),
        Ok(Err(error)) => errors.push(format!("connection driver task failed: {error}")),
        Err(_) => {
            driver_handle.abort();
            errors.push(format!(
                "connection driver teardown timed out after {}s",
                shutdown_budget.as_secs()
            ));
        }
    }
}

fn write_verdict(mut stdout: impl Write, out: Option<&Path>, result: &str) -> Result<()> {
    let console = writeln!(stdout, "{result}")
        .and_then(|()| stdout.flush())
        .context("could not write verdict to stdout");
    let file = out.map_or(Ok(()), |path| {
        fs::write(path, format!("{result}\n"))
            .with_context(|| format!("could not write {}", path.display()))
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

    #[test]
    fn normalize_https_url_handles_case_insensitive_scheme() {
        assert_eq!(
            normalize_https_url("HTTPS://127.0.0.1:8443/path").unwrap(),
            "https://127.0.0.1:8443/path"
        );
        assert_eq!(
            normalize_https_url("Https://[::1]:8443/").unwrap(),
            "https://[::1]:8443/"
        );
        assert!(normalize_https_url("http://127.0.0.1:8443/").is_err());
    }

    #[test]
    fn parse_https_authority_rejects_unbracketed_ipv6_and_accepts_bracketed() {
        for bad in [
            "https://fd00:2::2/",
            "https://::1/",
            "https://2001:db8::1:8443/",
            "HTTPS://fd00:2::2:8443/?bytes=64",
        ] {
            let err = parse_https_authority(bad).expect_err("unbracketed IPv6 must fail");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("unbracketed IPv6") && msg.contains("brackets"),
                "unexpected error for {bad}: {msg}"
            );
        }
        assert_eq!(
            parse_https_authority("https://[fd00:2::2]:8443/").unwrap(),
            ("fd00:2::2".to_string(), 8443)
        );
        assert_eq!(
            parse_https_authority("HTTPS://[::1]/").unwrap(),
            ("::1".to_string(), 443)
        );
        let userinfo_err = parse_https_authority("https://user:dummy@lab.invalid:8443/")
            .expect_err("userinfo must be rejected");
        let userinfo_msg = format!("{userinfo_err:#}");
        assert!(
            userinfo_msg.contains("userinfo")
                && !userinfo_msg.contains("user:dummy")
                && !userinfo_msg.contains("dummy"),
            "userinfo error must not leak credentials: {userinfo_msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_args_preserves_non_utf8_out_path_and_rejects_non_utf8_url() {
        use std::os::unix::ffi::OsStringExt;

        let raw_out = OsString::from_vec(b"/tmp/h2-out-\xff.json".to_vec());
        let parsed = parse_args_from([
            OsString::from("--url"),
            OsString::from("https://127.0.0.1:8443/"),
            OsString::from("--out"),
            raw_out.clone(),
        ])
        .expect("non-UTF-8 --out path must be accepted");
        assert_eq!(parsed.out, Some(PathBuf::from(raw_out)));

        let raw_url = OsString::from_vec(b"https://user:dummy@127.0.0.1/\xff".to_vec());
        let err = parse_args_from([OsString::from("--url"), raw_url])
            .expect_err("non-UTF-8 --url must fail without panicking");
        let msg = format!("{err:#}");
        assert!(msg.contains("valid UTF-8"), "unexpected error: {msg}");
        assert!(
            !msg.contains("dummy") && !msg.contains("user:dummy"),
            "non-UTF-8 --url error leaked credentials: {msg}"
        );
    }

    #[test]
    fn expected_len_honors_h3_body_bytes_default_and_explicit_query_override() {
        assert_eq!(
            expected_len_with_default("https://127.0.0.1:8443/", None).unwrap(),
            MARKER.len()
        );
        assert_eq!(
            expected_len_with_default("https://127.0.0.1:8443/", Some(OsStr::new("4096"))).unwrap(),
            4096
        );
        assert_eq!(
            expected_len_with_default(
                "https://127.0.0.1:8443/?bytes=128",
                Some(OsStr::new("4096"))
            )
            .unwrap(),
            128
        );
        assert!(
            expected_len_with_default("https://127.0.0.1:8443/", Some(OsStr::new("0"))).is_err()
        );
    }

    #[tokio::test]
    async fn connect_any_falls_back_to_second_resolved_address() {
        // Reserve and immediately close a loopback listener so the first
        // address refuses connection while the second accepts.
        let refused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_addr = refused.local_addr().unwrap();
        drop(refused);

        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        let accept_task = tokio::spawn(async move { live.accept().await });

        let (_stream, chosen) = connect_any(
            &[refused_addr, live_addr],
            Duration::from_secs(5),
            Duration::from_secs(1),
        )
        .await
        .expect("must fall back to second usable address");
        assert_eq!(chosen, live_addr);
        accept_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn collect_driver_outcome_surfaces_errors_and_accepts_clean_teardown() {
        let mut clean = tokio::spawn(async { Ok::<(), String>(()) });
        let mut errors = Vec::new();
        collect_driver_outcome(&mut clean, Duration::from_secs(1), &mut errors).await;
        assert!(errors.is_empty());

        let mut failed = tokio::spawn(async {
            Err::<(), String>("connection driver failed: protocol error".to_string())
        });
        collect_driver_outcome(&mut failed, Duration::from_secs(1), &mut errors).await;
        assert_eq!(errors, vec!["connection driver failed: protocol error"]);

        let mut stalled = tokio::spawn(async {
            std::future::pending::<()>().await;
            Ok::<(), String>(())
        });
        let mut stall_errors = Vec::new();
        collect_driver_outcome(&mut stalled, Duration::from_millis(50), &mut stall_errors).await;
        assert_eq!(stall_errors.len(), 1);
        assert!(stall_errors[0].contains("timed out"));
    }
}
