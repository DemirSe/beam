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
    ffi::{OsStr, OsString},
    net::SocketAddr,
    pin::Pin,
    process::ExitCode,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use bytes::{Buf, Bytes};
use http::{Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Body, Frame, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::rustls;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::{Semaphore, watch};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

const MARKER: &[u8] = b"beam-tun-h3-ok\n";
const MAX_BODY: usize = 64 * 1024 * 1024;
/// Aggregate cap on response bytes still owned by a response body or by the
/// connection that is sending it (documented runs emit ~1 MiB; the
/// per-request MAX_BODY stays).
const MAX_INFLIGHT_BYTES: u64 = 512 * 1024 * 1024;
/// Cap on concurrent request handlers; matches the H2 load client's own max.
const MAX_CONCURRENT_REQUESTS: usize = 1024;
/// Request-body drain byte cap (unchanged behavior, now named).
const MAX_REQUEST_BODY_DRAIN: usize = 1024 * 1024;
// Stage bounds: a stalled peer must fail a stage, never pin a worker.
// The bulk cases move 8 MiB in up to ~85 s under loss, so the connection
// bound stays generous while the per-chunk bounds stay tight.
const H2_TLS_TIMEOUT: Duration = Duration::from_secs(10);
const H2_MAX_CONNECTION: Duration = Duration::from_secs(300);
const H3_RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);
const H3_SEND_TIMEOUT: Duration = Duration::from_secs(30);
const H3_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const H3_IDLE_ACCEPT: Duration = Duration::from_secs(120);
const H2_ACCEPT_BACKOFF_START: Duration = Duration::from_millis(10);
const H2_ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Bytes currently owned by response bodies and by HTTP/2 send queues.
static INFLIGHT_BYTES: LazyLock<Arc<ByteBudget>> =
    LazyLock::new(|| ByteBudget::new(MAX_INFLIGHT_BYTES));
/// Bounds concurrent request-handler work across both listeners.
static REQUEST_SEMAPHORE: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_REQUESTS));

/// Aggregate byte budget for response bodies.
struct ByteBudget {
    limit: u64,
    used: AtomicU64,
}

impl ByteBudget {
    fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicU64::new(0),
        })
    }

    /// Reserves `len` bytes of the budget, failing instead of allocating past
    /// it.
    fn try_reserve(self: &Arc<Self>, len: usize) -> Result<ByteReservation> {
        let len = u64::try_from(len).context("response size overflows the counter")?;
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            let next = current
                .checked_add(len)
                .context("inflight byte total overflows")?;
            if next > self.limit {
                bail!(
                    "server busy: {next} inflight response bytes would exceed the {}-byte budget; retry with fewer concurrent requests or smaller ?bytes=",
                    self.limit
                );
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(ByteReservation {
                        budget: Arc::clone(self),
                        bytes: len,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }
}

/// Reservation against a byte budget; released on drop.
struct ByteReservation {
    budget: Arc<ByteBudget>,
    bytes: u64,
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// A response buffer that keeps its budget reservation until the last
/// `Bytes` handle drops.
///
/// HTTP/2 can hold yielded `Bytes` in its send queue after the body wrapper is
/// gone. The reservation therefore travels with the byte allocation, not with
/// the `Full` body: dropping the body never releases memory the connection
/// still owns.
struct BudgetedBody {
    data: Vec<u8>,
    _reservation: ByteReservation,
}

impl AsRef<[u8]> for BudgetedBody {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

fn busy_response(message: String, guard: RequestGuard) -> Response<TrackedBody> {
    let len = message.len();
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "text/plain")
        .header("content-length", len)
        .body(TrackedBody::new(Full::new(Bytes::from(message)), guard))
        .expect("static response is always valid")
}

/// Monotonic connection id shared by the HTTP/3 and HTTP/2 listeners.
static CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

/// Per-connection request counters. The `active` counter is the multiplexing
/// evidence: the harness takes the peak of the values logged at request start.
///
/// Both HTTP/2 and HTTP/3 hold a [`RequestGuard`] until the response body has
/// finished delivering (or the request fails/cancels early), so `active`
/// reflects live in-flight response delivery symmetrically on both protocols.
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

    fn start(self: &Arc<Self>, path: String) -> RequestGuard {
        let request = self.requests.fetch_add(1, Ordering::Relaxed) + 1;
        let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        eprintln!(
            "{}: request conn={} req={request} active={active} start path={path}",
            self.label, self.id
        );
        RequestGuard {
            state: Arc::clone(self),
            request,
            path,
            status: 500,
            bytes: 0,
            finished: false,
        }
    }

    fn finish_request(&self, request: u64, path: &str, status: u16, bytes: usize) {
        eprintln!(
            "{}: request conn={} req={request} end path={path} status={status} bytes={bytes}",
            self.label, self.id
        );
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII guard that keeps `ConnState::active` balanced across normal delivery,
/// early errors, timeouts, and stream cancellation.
struct RequestGuard {
    state: Arc<ConnState>,
    request: u64,
    path: String,
    status: u16,
    bytes: usize,
    finished: bool,
}

impl RequestGuard {
    fn set_outcome(&mut self, status: u16, bytes: usize) {
        self.status = status;
        self.bytes = bytes;
    }

    fn finish(mut self, status: u16, bytes: usize) {
        self.status = status;
        self.bytes = bytes;
        self.complete_once();
    }

    fn complete_once(&mut self) {
        if !self.finished {
            self.finished = true;
            self.state
                .finish_request(self.request, &self.path, self.status, self.bytes);
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.complete_once();
    }
}

/// Wraps an HTTP/2 response body so `RequestGuard` completes only once hyper
/// finishes streaming the body (or drops the stream on cancellation), matching
/// HTTP/3's post-delivery completion semantics.
struct TrackedBody {
    inner: Full<Bytes>,
    guard: Option<RequestGuard>,
}

impl TrackedBody {
    fn new(inner: Full<Bytes>, guard: RequestGuard) -> Self {
        Self {
            inner,
            guard: Some(guard),
        }
    }
}

impl Body for TrackedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(result, Poll::Ready(None))
            && let Some(mut guard) = self.guard.take()
        {
            guard.complete_once();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[derive(Debug)]
struct Args {
    listen: SocketAddr,
    h2_listen: Option<SocketAddr>,
}

fn parse_args() -> Result<Args> {
    parse_args_from(env::args_os().skip(1))
}

fn parse_args_from(args: impl IntoIterator<Item = OsString>) -> Result<Args> {
    let mut args = args.into_iter();
    let mut listen = "10.10.2.2:4443".to_string();
    let mut h2_listen: Option<String> = None;
    while let Some(arg) = args.next() {
        let Some(flag) = arg.to_str() else {
            bail!("invalid non-UTF-8 argument: {arg:?}");
        };
        match flag {
            "--listen" => {
                let raw = args
                    .next()
                    .context("--listen requires an address, for example 10.10.2.2:4443")?;
                listen = raw
                    .to_str()
                    .with_context(|| format!("--listen value must be valid UTF-8: {raw:?}"))?
                    .to_owned();
            }
            "--h2-listen" => {
                let raw = args
                    .next()
                    .context("--h2-listen requires an address, for example 10.10.2.2:8443")?;
                h2_listen = Some(
                    raw.to_str()
                        .with_context(|| format!("--h2-listen value must be valid UTF-8: {raw:?}"))?
                        .to_owned(),
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
    default_body_len_from(env::var_os("H3_BODY_BYTES").as_deref())
}

fn default_body_len_from(raw: Option<&OsStr>) -> Result<usize> {
    let Some(raw) = raw else {
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

fn marker_bytes(len: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(len);
    while body.len() < len {
        body.extend_from_slice(MARKER);
    }
    body.truncate(len);
    body
}

fn marker_body(len: usize) -> Bytes {
    Bytes::from(marker_bytes(len))
}

/// Builds a response body whose budget reservation lives with its bytes.
fn budgeted_marker_body(budget: &Arc<ByteBudget>, len: usize) -> Result<Bytes> {
    let reservation = budget.try_reserve(len)?;
    Ok(Bytes::from_owner(BudgetedBody {
        data: marker_bytes(len),
        _reservation: reservation,
    }))
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

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    if let Some(addr) = args.h2_listen {
        let config = Arc::new(server_config(&material, b"h2")?);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("could not bind HTTP/2 origin on {addr}"))?;
        eprintln!("h2-origin: READY on {addr} (HTTP/2, self-signed certificate)");
        let h2_shutdown = shutdown_rx.clone();
        let mut h2_task = tokio::spawn(serve_h2(listener, config, h2_shutdown));
        let h3_task = serve_h3(endpoint, shutdown_rx);
        tokio::select! {
            h3_result = h3_task => {
                h2_task.abort();
                return h3_result;
            }
            h2_result = &mut h2_task => {
                match h2_result {
                    Ok(Ok(())) => bail!("HTTP/2 origin listener stopped unexpectedly"),
                    Ok(Err(error)) => return Err(error).context("HTTP/2 origin listener failed"),
                    Err(error) => bail!("HTTP/2 origin listener task failed: {error}"),
                }
            }
        }
    }

    serve_h3(endpoint, shutdown_rx).await
}

async fn serve_h3(endpoint: quinn::Endpoint, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    if *shutdown.borrow() {
                        return Ok(());
                    }
                    bail!("HTTP/3 endpoint accept loop terminated unexpectedly");
                };
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
        }
    }
}

fn next_accept_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(H2_ACCEPT_BACKOFF_MAX)
}

fn is_fatal_accept_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::PermissionDenied
    ) || matches!(
        error.raw_os_error(),
        // Linux: EBADF (9), EINVAL (22), ENOTSOCK (88)
        Some(9 | 22 | 88)
    )
}

async fn serve_h2(
    listener: tokio::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(config);
    let mut backoff = H2_ACCEPT_BACKOFF_START;
    loop {
        let accepted = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (socket, peer) = match accepted {
            Ok(accepted) => {
                backoff = H2_ACCEPT_BACKOFF_START;
                accepted
            }
            Err(error) => {
                if is_fatal_accept_error(&error) {
                    return Err(error).context("h2-origin: unrecoverable accept error");
                }
                eprintln!(
                    "h2-origin: accept failed: {error} (backing off {}ms)",
                    backoff.as_millis()
                );
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return Ok(());
                        }
                    }
                    _ = sleep(backoff) => {}
                }
                backoff = next_accept_backoff(backoff);
                continue;
            }
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let stream = match timeout(H2_TLS_TIMEOUT, acceptor.accept(socket)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    eprintln!("h2-origin: TLS handshake from {peer} failed: {error}");
                    return;
                }
                Err(_) => {
                    eprintln!(
                        "h2-origin: TLS handshake from {peer} timed out after {}s; closing",
                        H2_TLS_TIMEOUT.as_secs()
                    );
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
            let connection = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service);
            match timeout(H2_MAX_CONNECTION, connection).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    eprintln!("h2-origin: connection conn={connection_id} ended: {error}");
                }
                Err(_) => {
                    eprintln!(
                        "h2-origin: connection conn={connection_id} exceeded the {}s servicing bound; closing",
                        H2_MAX_CONNECTION.as_secs()
                    );
                }
            }
        });
    }
}

fn handle_h2_request(
    state: Arc<ConnState>,
    request: http::Request<hyper::body::Incoming>,
) -> Response<TrackedBody> {
    let path = request.uri().path().to_string();
    let mut guard = state.start(path);
    // Bound concurrent handler work and aggregate allocations before asking
    // for memory: excess load gets 503, never an unbounded allocation.
    let _permit = match REQUEST_SEMAPHORE.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            let message = format!(
                "server busy: too many concurrent requests (cap {MAX_CONCURRENT_REQUESTS})\n"
            );
            guard.set_outcome(503, message.len());
            return busy_response(message, guard);
        }
    };
    let body = match requested_body_len(request.uri()) {
        Ok(len) => match budgeted_marker_body(&INFLIGHT_BYTES, len) {
            Ok(body) => body,
            Err(error) => {
                let message = format!("server busy: {error:#}\n");
                guard.set_outcome(503, message.len());
                return busy_response(message, guard);
            }
        },
        Err(error) => {
            let text = format!("bad request: {error:#}\n");
            let len = text.len();
            guard.set_outcome(400, len);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("content-type", "text/plain")
                .header("content-length", len)
                .body(TrackedBody::new(Full::new(Bytes::from(text)), guard))
                .expect("static response is always valid");
        }
    };
    let len = body.len();
    guard.set_outcome(200, len);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .header("content-length", len)
        .body(TrackedBody::new(Full::new(body), guard))
        .expect("static response is always valid")
}

async fn serve_h3_connection(connection: quinn::Connection, state: Arc<ConnState>) -> Result<()> {
    let mut h3 = h3::server::Connection::<h3_quinn::Connection, Bytes>::new(
        h3_quinn::Connection::new(connection),
    )
    .await
    .context("could not start the HTTP/3 connection")?;

    loop {
        // An idle peer that never sends must not pin this worker: close the
        // connection after the bound instead of awaiting a request forever.
        match timeout(H3_IDLE_ACCEPT, h3.accept()).await {
            Ok(Ok(Some(resolver))) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_h3_request(resolver, state.clone()).await {
                        eprintln!("h3-origin: request failed on conn={}: {error:#}", state.id);
                    }
                });
            }
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(error)) => {
                eprintln!(
                    "h3-origin: HTTP/3 connection conn={} ended: {error}",
                    state.id
                );
                return Ok(());
            }
            Err(_) => {
                eprintln!(
                    "h3-origin: HTTP/3 connection conn={} idle for {}s with no request; closing",
                    state.id,
                    H3_IDLE_ACCEPT.as_secs()
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
    let (request, mut stream) = match timeout(H3_RESOLVE_TIMEOUT, resolver.resolve_request()).await
    {
        Ok(Ok(resolved)) => resolved,
        Ok(Err(error)) => {
            return Err(error).context("could not read the request headers");
        }
        Err(_) => {
            bail!(
                "request headers stalled: no request for {}s",
                H3_RESOLVE_TIMEOUT.as_secs()
            );
        }
    };
    let path = request.uri().path().to_string();
    let mut guard = state.start(path);
    let _permit = REQUEST_SEMAPHORE.try_acquire().map_err(|_| {
        guard.set_outcome(503, 0);
        anyhow::anyhow!("server busy: too many concurrent requests (cap {MAX_CONCURRENT_REQUESTS})")
    })?;
    let len = requested_body_len(request.uri()).inspect_err(|_| guard.set_outcome(400, 0))?;
    // Held across every send below, so live response bytes count exactly.
    let _reservation = INFLIGHT_BYTES
        .try_reserve(len)
        .inspect_err(|_| guard.set_outcome(503, 0))?;
    let body = marker_body(len);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .header("content-length", body.len())
        .body(())
        .context("could not build the response")?;

    match timeout(H3_SEND_TIMEOUT, stream.send_response(response)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return Err(error).context("could not send the response headers");
        }
        Err(_) => {
            bail!(
                "response headers stalled: no progress for {}s",
                H3_SEND_TIMEOUT.as_secs()
            );
        }
    }
    // Send bounded chunks so the h3 layer can apply QUIC stream flow control.
    // A single multi-megabyte `send_data` is not a valid large-body test: it
    // makes the origin reset the stream before the tunnel is exercised.
    // Each chunk has its own bound, so slow-but-moving transfers survive
    // while a stalled peer fails the send stage instead of pinning the worker.
    const CHUNK: usize = 1024;
    let mut offset = 0;
    while offset < body.len() {
        let end = (offset + CHUNK).min(body.len());
        match timeout(H3_SEND_TIMEOUT, stream.send_data(body.slice(offset..end))).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(error).context("could not send the response body");
            }
            Err(_) => {
                bail!(
                    "response body stalled: no progress for {}s at byte {offset} of {}",
                    H3_SEND_TIMEOUT.as_secs(),
                    body.len()
                );
            }
        }
        offset = end;
    }
    match timeout(H3_SEND_TIMEOUT, stream.finish()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return Err(error).context("could not finish the stream");
        }
        Err(_) => {
            bail!(
                "response finish stalled: no progress for {}s",
                H3_SEND_TIMEOUT.as_secs()
            );
        }
    }
    guard.finish(200, len);
    // The harness only sends bodyless GETs. Read the request receive half to
    // EOF before dropping it: an open receive half dropped without reading
    // sends QUIC STOP_SENDING, which clients report as "stream reset by
    // server" even though the response arrived complete.
    let mut drained = 0usize;
    loop {
        // The byte cap alone does not bound time: each receive waits at most
        // the drain bound, so a trickling peer cannot hold the worker.
        match timeout(H3_DRAIN_TIMEOUT, stream.recv_data()).await {
            Ok(Ok(Some(chunk))) => {
                drained += Buf::remaining(&chunk);
                if drained > MAX_REQUEST_BODY_DRAIN {
                    eprintln!(
                        "h3-origin: request body on conn={} exceeded {MAX_REQUEST_BODY_DRAIN} bytes; dropping the rest",
                        state.id
                    );
                    break;
                }
            }
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                eprintln!(
                    "h3-origin: request body on conn={} ended: {error:#}",
                    state.id
                );
                break;
            }
            Err(_) => {
                eprintln!(
                    "h3-origin: request body drain on conn={} stalled for {}s; dropping the rest",
                    state.id,
                    H3_DRAIN_TIMEOUT.as_secs()
                );
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[test]
    fn byte_budget_rejects_past_the_cap_and_releases() {
        let budget = ByteBudget::new(150);
        let first = budget.try_reserve(100).expect("fits the budget");
        assert!(budget.try_reserve(100).is_err());
        drop(first);
        assert!(budget.try_reserve(100).is_ok());
    }

    #[tokio::test]
    async fn h2_body_keeps_the_budget_until_its_bytes_drop() {
        let budget = ByteBudget::new(150);
        let first = budgeted_marker_body(&budget, 100).expect("first body fits");
        let second = budgeted_marker_body(&budget, 40).expect("second body fits");
        assert!(budget.try_reserve(20).is_err(), "the budget is exhausted");

        // A partially consumed response keeps the same allocation: slicing
        // and dropping the original `Bytes` must not release the reservation.
        let slice = first.slice(10..20);
        drop(first);
        assert!(
            budget.try_reserve(20).is_err(),
            "a retained slice still owns the body bytes"
        );

        // Hyper may hold a yielded data frame after the body wrapper is gone.
        // The reservation must follow the `Bytes` in that frame.
        let mut full = Full::new(second);
        let frame = full.frame().await.expect("the body has one data frame");
        drop(full);
        assert!(
            budget.try_reserve(20).is_err(),
            "a queued HTTP/2 data frame still owns the body bytes"
        );

        drop(frame);
        assert!(
            budget.try_reserve(60).is_err(),
            "the retained slice still owns its bytes"
        );
        drop(slice);
        assert!(
            budget.try_reserve(150).is_ok(),
            "dropping the last byte owner releases the whole budget"
        );
    }

    #[test]
    fn requested_body_len_still_bounds_per_request() {
        let uri: http::Uri = "https://example.com/?bytes=67108865".parse().expect("URI");
        assert!(requested_body_len(&uri).is_err());
        let uri: http::Uri = "https://example.com/?bytes=1024".parse().expect("URI");
        assert_eq!(requested_body_len(&uri).expect("valid"), 1024);
    }

    #[cfg(unix)]
    #[test]
    fn parse_args_rejects_non_utf8_without_panicking() {
        use std::os::unix::ffi::OsStringExt;

        let bad_flag = OsString::from_vec(vec![b'-', b'-', 0xff]);
        let err = parse_args_from([bad_flag]).expect_err("non-UTF-8 flag must fail");
        assert!(format!("{err:#}").contains("non-UTF-8"));

        let bad_addr = OsString::from_vec(vec![b'1', b'2', b'7', 0xff]);
        let err = parse_args_from([OsString::from("--listen"), bad_addr])
            .expect_err("non-UTF-8 listen addr must fail");
        assert!(format!("{err:#}").contains("valid UTF-8"));
    }

    #[tokio::test]
    async fn tracked_body_and_guard_keep_active_counts_balanced() {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let state = ConnState::new("h2-origin", peer);

        // Request remains active until the H2 response body finishes streaming.
        let mut guard = state.start("/body".to_string());
        guard.set_outcome(200, 4);
        assert_eq!(state.active.load(Ordering::Relaxed), 1);
        let mut body = TrackedBody::new(Full::new(Bytes::from_static(b"test")), guard);
        assert_eq!(state.active.load(Ordering::Relaxed), 1);
        let frame = body.frame().await.expect("data frame").expect("ok");
        assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"test"));
        assert!(body.frame().await.is_none());
        assert_eq!(state.active.load(Ordering::Relaxed), 0);

        // Early drop (for example, an H3 error or cancelled H2 stream) still
        // decrements active back to zero.
        let early = state.start("/early-error".to_string());
        assert_eq!(state.active.load(Ordering::Relaxed), 1);
        drop(early);
        assert_eq!(state.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn h2_accept_backoff_is_bounded_and_classifies_fatal_errors() {
        let mut backoff = H2_ACCEPT_BACKOFF_START;
        for _ in 0..16 {
            let next = next_accept_backoff(backoff);
            assert!(next >= backoff);
            backoff = next;
        }
        assert_eq!(backoff, H2_ACCEPT_BACKOFF_MAX);
        assert!(is_fatal_accept_error(&std::io::Error::from_raw_os_error(9)));
        assert!(is_fatal_accept_error(&std::io::Error::from_raw_os_error(
            22
        )));
        assert!(!is_fatal_accept_error(&std::io::Error::from_raw_os_error(
            24
        )));
    }

    #[tokio::test]
    async fn serve_h3_distinguishes_unexpected_closure_from_shutdown() {
        let material = tls_material().unwrap();
        let crypto = QuicServerConfig::try_from(server_config(&material, b"h3").unwrap()).unwrap();
        let quic = quinn::ServerConfig::with_crypto(Arc::new(crypto));

        // Closing the endpoint without signalling shutdown must return Err.
        let endpoint =
            quinn::Endpoint::server(quic.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let (_tx, rx) = watch::channel(false);
        endpoint.close(0u32.into(), b"unexpected");
        let err = serve_h3(endpoint, rx)
            .await
            .expect_err("unexpected endpoint close must fail");
        assert!(format!("{err:#}").contains("terminated unexpectedly"));

        // Signalling shutdown returns Ok(()).
        let endpoint = quinn::Endpoint::server(quic, "127.0.0.1:0".parse().unwrap()).unwrap();
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(serve_h3(endpoint, rx));
        tx.send(true).unwrap();
        task.await.unwrap().expect("expected shutdown returns Ok");
    }

    #[test]
    fn default_body_len_from_reads_override_and_falls_back_to_marker() {
        assert_eq!(default_body_len_from(None).unwrap(), MARKER.len());
        assert_eq!(
            default_body_len_from(Some(OsStr::new("4096"))).unwrap(),
            4096
        );
        assert!(default_body_len_from(Some(OsStr::new("0"))).is_err());
    }
}
