//! Minimal local HTTP/3 and HTTP/2 origin for the full-TUN harness.
//!
//! The server listens on one UDP address (HTTP/3) and, when `--h2-listen` is
//! given, one TCP address (HTTP/2). Both listeners share one self-signed
//! certificate generated in memory and answer every request with HTTP 200 and
//! the marker `beam-tun-h3-ok\n`, repeated up to `?bytes=N` on the request (or
//! `H3_BODY_BYTES` when the query has no `bytes` parameter). It never talks to
//! an external network.
//!
//! Every accepted connection and every request is logged with a connection id,
//! a per-connection request id and the number of active requests, so the
//! harness can prove multiplexing from the origin's point of view.
//!
//! This binary is test-only and deliberately lives outside the beam workspace.

use std::{
    convert::Infallible,
    env,
    net::SocketAddr,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use bytes::{Buf, Bytes};
use http::{Response, StatusCode};
use http_body_util::Full;
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::rustls;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::TlsAcceptor;

const MARKER: &[u8] = b"beam-tun-h3-ok\n";
const MAX_BODY: usize = 64 * 1024 * 1024;

/// Monotonic connection id shared by the HTTP/3 and HTTP/2 listeners.
static CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

/// Per-connection request counters. The `active` counter is the multiplexing
/// evidence: the harness takes the peak of the values logged at request start.
struct ConnState {
    label: &'static str,
    id: u64,
    requests: AtomicU64,
    active: AtomicU64,
}

impl ConnState {
    fn new(label: &'static str, peer: SocketAddr) -> Arc<Self> {
        let id = CONNECTION_ID.fetch_add(1, Ordering::Relaxed) + 1;
        eprintln!("{label}: connection conn={id} peer={peer}");
        Arc::new(Self {
            label,
            id,
            requests: AtomicU64::new(0),
            active: AtomicU64::new(0),
        })
    }

    fn start(&self, path: &str) -> u64 {
        let request = self.requests.fetch_add(1, Ordering::Relaxed) + 1;
        let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        eprintln!(
            "{}: request conn={} req={request} active={active} start path={path}",
            self.label, self.id
        );
        request
    }

    fn end(&self, request: u64, path: &str, status: u16, bytes: usize) {
        eprintln!(
            "{}: request conn={} req={request} end path={path} status={status} bytes={bytes}",
            self.label, self.id
        );
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Args {
    listen: SocketAddr,
    h2_listen: Option<SocketAddr>,
}

fn parse_args() -> Result<Args> {
    let mut args = env::args().skip(1);
    let mut listen = "10.10.2.2:4443".to_string();
    let mut h2_listen: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen = args
                    .next()
                    .context("--listen requires an address, for example 10.10.2.2:4443")?;
            }
            "--h2-listen" => {
                h2_listen = Some(
                    args.next()
                        .context("--h2-listen requires an address, for example 10.10.2.2:8443")?,
                );
            }
            "-h" | "--help" => {
                println!("usage: h3-origin [--listen ADDR] [--h2-listen ADDR]");
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    let listen = listen
        .parse()
        .with_context(|| format!("invalid listen address: {listen}"))?;
    let h2_listen = match h2_listen {
        Some(value) => Some(
            value
                .parse()
                .with_context(|| format!("invalid HTTP/2 listen address: {value}"))?,
        ),
        None => None,
    };
    Ok(Args { listen, h2_listen })
}

struct TlsMaterial {
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn tls_material() -> Result<TlsMaterial> {
    // A fresh self-signed certificate is generated on every run; no private
    // key is ever written to disk or committed.
    let certified = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "10.10.2.2".to_string(),
        "fd00:2::2".to_string(),
    ])
    .context("could not generate the self-signed certificate")?;
    Ok(TlsMaterial {
        certificate: CertificateDer::from(certified.cert.der().to_vec()),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        )),
    })
}

fn server_config(material: &TlsMaterial, alpn: &[u8]) -> Result<rustls::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![material.certificate.clone()], material.key.clone_key())
        .context("could not build the rustls server config")?;
    tls.alpn_protocols = vec![alpn.to_vec()];
    Ok(tls)
}

/// Body size when the request carries no `?bytes=` parameter. The historical
/// `H3_BODY_BYTES` environment variable stays the default.
fn default_body_len() -> Result<usize> {
    let Some(raw) = env::var_os("H3_BODY_BYTES") else {
        return Ok(MARKER.len());
    };
    let raw = raw.to_str().context("H3_BODY_BYTES must be valid UTF-8")?;
    let len: usize = raw
        .parse()
        .with_context(|| format!("invalid H3_BODY_BYTES: {raw}"))?;
    if !(1..=MAX_BODY).contains(&len) {
        bail!("H3_BODY_BYTES must be between 1 and {MAX_BODY}");
    }
    Ok(len)
}

/// Response body size for one request: `?bytes=N` wins, `H3_BODY_BYTES` is the
/// fallback. The range is bounded so a client cannot ask for an unbounded body.
fn requested_body_len(uri: &http::Uri) -> Result<usize> {
    if let Some(query) = uri.query() {
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if key == "bytes" {
                let len: usize = value
                    .parse()
                    .with_context(|| format!("invalid bytes parameter: {value}"))?;
                if !(1..=MAX_BODY).contains(&len) {
                    bail!("bytes must be between 1 and {MAX_BODY}");
                }
                return Ok(len);
            }
        }
    }
    default_body_len()
}

fn marker_body(len: usize) -> Bytes {
    let mut body = Vec::with_capacity(len);
    while body.len() < len {
        body.extend_from_slice(MARKER);
    }
    body.truncate(len);
    Bytes::from(body)
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("h3-origin: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let args = parse_args()?;
    let material = tls_material()?;

    let crypto = QuicServerConfig::try_from(server_config(&material, b"h3")?)
        .context("could not create the QUIC server crypto config")?;
    let quic_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(quic_config, args.listen)
        .with_context(|| format!("could not bind HTTP/3 origin on {}", args.listen))?;
    eprintln!(
        "h3-origin: READY on {} (HTTP/3, self-signed certificate)",
        args.listen
    );

    if let Some(addr) = args.h2_listen {
        let config = Arc::new(server_config(&material, b"h2")?);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("could not bind HTTP/2 origin on {addr}"))?;
        eprintln!("h2-origin: READY on {addr} (HTTP/2, self-signed certificate)");
        tokio::spawn(serve_h2(listener, config));
    }

    serve_h3(endpoint).await
}

async fn serve_h3(endpoint: quinn::Endpoint) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let state = ConnState::new("h3-origin", connection.remote_address());
                    if let Err(error) = serve_h3_connection(connection, state.clone()).await {
                        eprintln!("h3-origin: connection conn={} ended: {error:#}", state.id);
                    }
                }
                Err(error) => eprintln!("h3-origin: QUIC handshake failed: {error}"),
            }
        });
    }
    Ok(())
}

async fn serve_h2(listener: tokio::net::TcpListener, config: Arc<rustls::ServerConfig>) {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("h2-origin: accept failed: {error}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(socket).await {
                Ok(stream) => stream,
                Err(error) => {
                    eprintln!("h2-origin: TLS handshake from {peer} failed: {error}");
                    return;
                }
            };
            let state = ConnState::new("h2-origin", peer);
            let connection_id = state.id;
            let service =
                hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                    let state = state.clone();
                    async move { Ok::<_, Infallible>(handle_h2_request(state, request)) }
                });
            if let Err(error) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                eprintln!("h2-origin: connection conn={connection_id} ended: {error}");
            }
        });
    }
}

fn handle_h2_request(
    state: Arc<ConnState>,
    request: http::Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    let path = request.uri().path().to_string();
    let request_id = state.start(&path);
    let body = match requested_body_len(request.uri()) {
        Ok(len) => marker_body(len),
        Err(error) => {
            let text = format!("bad request: {error:#}\n");
            state.end(request_id, &path, 400, text.len());
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("content-type", "text/plain")
                .header("content-length", text.len())
                .body(Full::new(Bytes::from(text)))
                .expect("static response is always valid");
        }
    };
    state.end(request_id, &path, 200, body.len());
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .header("content-length", body.len())
        .body(Full::new(body))
        .expect("static response is always valid")
}

async fn serve_h3_connection(connection: quinn::Connection, state: Arc<ConnState>) -> Result<()> {
    let mut h3 = h3::server::Connection::<h3_quinn::Connection, Bytes>::new(
        h3_quinn::Connection::new(connection),
    )
    .await
    .context("could not start the HTTP/3 connection")?;

    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_h3_request(resolver, state.clone()).await {
                        eprintln!("h3-origin: request failed on conn={}: {error:#}", state.id);
                    }
                });
            }
            Ok(None) => return Ok(()),
            Err(error) => {
                eprintln!(
                    "h3-origin: HTTP/3 connection conn={} ended: {error}",
                    state.id
                );
                return Ok(());
            }
        }
    }
}

async fn serve_h3_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    state: Arc<ConnState>,
) -> Result<()> {
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .context("could not read the request headers")?;
    let path = request.uri().path().to_string();
    let request_id = state.start(&path);
    let len = requested_body_len(request.uri())?;
    let body = marker_body(len);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .header("content-length", body.len())
        .body(())
        .context("could not build the response")?;

    stream
        .send_response(response)
        .await
        .context("could not send the response headers")?;
    // Send bounded chunks so the h3 layer can apply QUIC stream flow control.
    // A single multi-megabyte `send_data` is not a valid large-body test: it
    // makes the origin reset the stream before the tunnel is exercised.
    const CHUNK: usize = 1024;
    let mut offset = 0;
    while offset < body.len() {
        let end = (offset + CHUNK).min(body.len());
        stream
            .send_data(body.slice(offset..end))
            .await
            .context("could not send the response body")?;
        offset = end;
    }
    stream
        .finish()
        .await
        .context("could not finish the stream")?;
    state.end(request_id, &path, 200, len);
    // The harness only sends bodyless GETs. Read the request receive half to
    // EOF before dropping it: an open receive half dropped without reading
    // sends QUIC STOP_SENDING, which clients report as "stream reset by
    // server" even though the response arrived complete.
    let mut drained = 0usize;
    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) => {
                drained += Buf::remaining(&chunk);
                if drained > 1024 * 1024 {
                    eprintln!(
                        "h3-origin: request body on conn={} exceeded 1 MiB; dropping the rest",
                        state.id
                    );
                    break;
                }
            }
            Ok(None) => break,
            Err(error) => {
                eprintln!(
                    "h3-origin: request body on conn={} ended: {error:#}",
                    state.id
                );
                break;
            }
        }
    }
    Ok(())
}
