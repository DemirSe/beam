//! XUDP mux stream server.
//!
//! [`handle_mux_stream`] decodes XUDP frames from one VLESS mux stream and
//! relays their datagrams over per-session unconnected UDP sockets. Replies are
//! `Keep + Data` frames carrying the actual source address. A single writer
//! task serializes every frame, so concurrent reply tasks can never interleave
//! bytes, and its bounded queue caps pending replies.
//!
//! A malformed frame closes the stream. A per-session failure (`New` with an
//! unreachable destination, a failed send, or a socket read error) is reported
//! as `End + Error` for that session and does not take down unrelated sessions.
//! A process-wide limiter bounds active plus retained sockets across all mux
//! streams; the per-stream [`XudpConfig::max_sessions`] limit alone is not an
//! aggregate memory bound.
//!
//! The TLS adapter calls [`handle_mux_stream`] for an authenticated VLESS
//! `Command::Mux`, after writing the VLESS response header.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, interval, sleep, timeout};

use super::session::{
    ActiveSession, DEFAULT_STREAM_REPLY_BUDGET, ExpiringSession, QueuedFrame, ReplyQueueBudget,
    ResolveError, RetainedLookup, Session, SessionTable, SlotGuard, SocketFamily, XudpConfig,
    XudpConfigError, XudpSessionLimiter, encode_end_frame, resolve_destination,
    socket_addr_to_location, spawn_reply_task,
};
use crate::address::{Address, NetLocation};
use crate::metrics::Metrics;
use crate::xudp::frame::{
    self, Frame, FrameOption, FrameSpec, GLOBAL_ID_LEN, MAX_METADATA_LEN, MAX_PAYLOAD_LEN,
    METADATA_PREFIX_LEN, SessionStatus, TargetNetwork, XudpError,
};

/// Largest valid frame: metadata prefix, metadata, payload prefix, payload.
const PAYLOAD_PREFIX_LEN: usize = 2;
const MAX_FRAME_LEN: usize =
    METADATA_PREFIX_LEN + MAX_METADATA_LEN + PAYLOAD_PREFIX_LEN + MAX_PAYLOAD_LEN;

/// One read from the mux stream. Two frames can arrive coalesced.
const READ_CHUNK_LEN: usize = 8192;

/// Hard bound for the reassembly buffer: one full frame plus one read.
const MAX_BUFFERED_LEN: usize = MAX_FRAME_LEN + READ_CHUNK_LEN;

/// Upper bound on one domain resolution in the per-mux resolver task.
///
/// Domain lookups no longer run on the shared read loop. A small bounded pool
/// prevents one slow lookup from blocking unrelated domain sessions.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum concurrent DNS lookups for one mux stream.
const MAX_CONCURRENT_RESOLUTIONS: usize = 4;

/// Upper bound on mux read inactivity.
///
/// Sessions expire independently, so this is only a backstop for a stream
/// whose peer never sends another frame. A stream with no sessions is closed
/// sooner by the idle sweeper. Stock Xray keeps an active mux stream alive
/// indefinitely; this bound is a deliberate resource-safety deviation.
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// Bound on the whole stream teardown.
///
/// The reply-task joins and the writer/sender joins share one deadline, so a
/// broken task cannot multiply the shutdown budget. Timed-out tasks are
/// aborted without waiting for their cancellation to complete.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Bound on a send that could not be completed immediately.
const SEND_WAIT: Duration = Duration::from_millis(100);

/// Bound on datagrams waiting for kernel send-buffer space per mux.
const SEND_QUEUE_CAPACITY: usize = 128;

/// One datagram waiting for a congested session socket.
struct OutboundDatagram {
    /// The session that queued the datagram. A failure must not be reported by
    /// id alone: the client can end a session and reuse its 16-bit id while the
    /// datagram is still queued.
    session: Arc<Session>,
    destination: SocketAddr,
    payload: Vec<u8>,
}

/// Bound on stopping a reply task before close queues its End.
const CLOSE_JOIN_TIMEOUT: Duration = Duration::from_millis(100);

/// Bound on concurrently pending DNS resolutions per mux stream.
const MAX_PENDING_RESOLUTIONS: usize = 64;

/// Bound on queued frames for one destination still being resolved.
const MAX_PENDING_FRAMES: usize = 64;

/// Bound on the per-mux resolved-destination cache.
const MAX_RESOLUTION_CACHE: usize = 256;

/// How long a resolved domain can be reused by one mux stream.
const RESOLUTION_CACHE_TTL: Duration = Duration::from_secs(300);

/// Owned form of a parsed frame, used only while a domain is resolving.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnedFrame {
    session_id: u16,
    status: SessionStatus,
    option: FrameOption,
    network: Option<TargetNetwork>,
    destination: Option<NetLocation>,
    global_id: Option<[u8; GLOBAL_ID_LEN]>,
    payload: Vec<u8>,
}

impl OwnedFrame {
    fn from_borrowed(frame: &Frame<'_>) -> Self {
        Self {
            session_id: frame.session_id,
            status: frame.status,
            option: frame.option,
            network: frame.network,
            destination: frame.destination.clone(),
            global_id: frame.global_id,
            payload: frame.payload.to_vec(),
        }
    }

    fn as_borrowed(&self) -> Frame<'_> {
        Frame {
            session_id: self.session_id,
            status: self.status,
            option: self.option,
            network: self.network,
            destination: self.destination.clone(),
            global_id: self.global_id,
            payload: &self.payload,
        }
    }

    /// Approximate retained cost of this queued frame.
    ///
    /// The payload budget alone lets an authenticated peer queue many
    /// zero-payload domain frames without charging their metadata, address,
    /// and allocation overhead. Charge a floor for every frame as well.
    fn budget_len(&self) -> usize {
        let domain_len = match &self.destination {
            Some(location) => match &location.address {
                Address::Domain(domain) => domain.len(),
                Address::Ipv4(_) | Address::Ipv6(_) => 0,
            },
            None => 0,
        };
        self.payload
            .len()
            .saturating_add(domain_len)
            .saturating_add(std::mem::size_of::<Self>())
            .max(1)
    }

    fn rewrite_destination(&mut self, address: SocketAddr) {
        // Preserve the original network. A TCP New with a domain must still
        // reach handle_new's network check and be rejected, not silently
        // become a UDP flow.
        self.destination = Some(socket_addr_to_location(address));
    }
}

struct ResolutionRequest {
    id: u16,
    generation: u64,
    destination: NetLocation,
    family: Option<SocketFamily>,
}

struct ResolutionResult {
    id: u16,
    generation: u64,
    destination: NetLocation,
    result: Result<SocketAddr, ResolveError>,
}

struct PendingFrame {
    frame: OwnedFrame,
    _budget: tokio::sync::OwnedSemaphorePermit,
}

impl PendingFrame {
    fn new(frame: OwnedFrame, limiter: &XudpSessionLimiter) -> Option<Self> {
        let budget = limiter.try_reserve_resolution(frame.budget_len())?;
        Some(Self {
            frame,
            _budget: budget,
        })
    }
}

struct PendingResolution {
    /// The frame whose destination owns this lookup. It is kept separate so
    /// cancellation can invalidate the lookup without changing queue order.
    owner: Option<PendingFrame>,
    frames: VecDeque<PendingFrame>,
    generation: u64,
}

/// Moves domain lookups off the shared mux read loop.
///
/// IP destinations never enter this state. Domain frames are queued in arrival
/// order per session id, while the resolver task performs the bounded lookup.
/// Once the result arrives the read loop rewrites those frames to the resolved
/// IP and dispatches them normally. Unrelated IP sessions continue immediately.
struct ResolutionState {
    cache: HashMap<(String, u16), (SocketAddr, Instant)>,
    pending: HashMap<u16, PendingResolution>,
    requests: mpsc::Sender<ResolutionRequest>,
    results: mpsc::Receiver<ResolutionResult>,
    task: tokio::task::JoinHandle<()>,
    limiter: XudpSessionLimiter,
    next_generation: u64,
}

impl ResolutionState {
    fn new(limiter: XudpSessionLimiter) -> Self {
        let (requests, mut request_rx) =
            mpsc::channel::<ResolutionRequest>(MAX_PENDING_RESOLUTIONS);
        let (result_tx, results) = mpsc::channel(MAX_PENDING_RESOLUTIONS);
        let task = tokio::spawn(async move {
            let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_RESOLUTIONS));
            while let Some(request) = request_rx.recv().await {
                let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                    break;
                };
                let result_tx = result_tx.clone();
                tokio::spawn(async move {
                    let result =
                        resolve_destination(&request.destination, request.family, RESOLVE_TIMEOUT)
                            .await;
                    // Hold the lookup slot until the result is queued. A full
                    // result channel must apply backpressure to the request
                    // queue instead of spawning unbounded tasks that wait to
                    // send after releasing their permit.
                    let _ = result_tx
                        .send(ResolutionResult {
                            id: request.id,
                            generation: request.generation,
                            destination: request.destination,
                            result,
                        })
                        .await;
                    drop(permit);
                });
            }
        });
        Self {
            cache: HashMap::new(),
            pending: HashMap::new(),
            requests,
            results,
            task,
            limiter,
            next_generation: 0,
        }
    }

    fn cache_key(destination: &NetLocation) -> Option<(String, u16)> {
        match &destination.address {
            Address::Domain(domain) => Some((domain.clone(), destination.port)),
            Address::Ipv4(_) | Address::Ipv6(_) => None,
        }
    }

    fn cache_get(
        &mut self,
        destination: &NetLocation,
        family: Option<SocketFamily>,
    ) -> Option<SocketAddr> {
        let key = Self::cache_key(destination)?;
        let (address, inserted) = self.cache.get(&key)?;
        if inserted.elapsed() > RESOLUTION_CACHE_TTL {
            self.cache.remove(&key);
            return None;
        }
        if family.is_some_and(|family| !family.matches(*address)) {
            return None;
        }
        Some(*address)
    }

    fn cache_insert(&mut self, destination: &NetLocation, address: SocketAddr) {
        let Some(key) = Self::cache_key(destination) else {
            return;
        };
        if self.cache.len() >= MAX_RESOLUTION_CACHE {
            self.cache.clear();
        }
        self.cache.insert(key, (address, Instant::now()));
    }

    fn has_pending(&self, id: u16) -> bool {
        self.pending.contains_key(&id)
    }

    fn push_frame(&mut self, id: u16, frame: OwnedFrame) -> bool {
        let Some(frame) = PendingFrame::new(frame, &self.limiter) else {
            return false;
        };
        let Some(pending) = self.pending.get_mut(&id) else {
            return false;
        };
        if pending.frames.len() >= MAX_PENDING_FRAMES {
            return false;
        }
        pending.frames.push_back(frame);
        true
    }

    fn start(
        &mut self,
        id: u16,
        destination: NetLocation,
        family: Option<SocketFamily>,
        frames: VecDeque<PendingFrame>,
    ) -> bool {
        if self.pending.len() >= MAX_PENDING_RESOLUTIONS || frames.is_empty() {
            return false;
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        if self
            .requests
            .try_send(ResolutionRequest {
                id,
                generation,
                destination,
                family,
            })
            .is_err()
        {
            return false;
        }
        let mut frames = frames;
        let Some(owner) = frames.pop_front() else {
            return false;
        };
        self.pending.insert(
            id,
            PendingResolution {
                owner: Some(owner),
                frames,
                generation,
            },
        );
        true
    }

    fn cancel_global(&mut self, global_id: [u8; GLOBAL_ID_LEN]) {
        let mut remove = Vec::new();
        for (id, pending) in &mut self.pending {
            if pending.owner.as_ref().is_some_and(|frame| {
                frame.frame.status == SessionStatus::New && frame.frame.global_id == Some(global_id)
            }) {
                pending.owner = None;
            }
            pending.frames.retain(|frame| {
                !(frame.frame.status == SessionStatus::New
                    && frame.frame.global_id == Some(global_id))
            });
            if pending.owner.is_none() && pending.frames.is_empty() {
                remove.push(*id);
            }
        }
        for id in remove {
            self.pending.remove(&id);
        }
    }

    fn take(&mut self, id: u16, generation: u64) -> Option<PendingResolution> {
        if self
            .pending
            .get(&id)
            .is_some_and(|pending| pending.generation == generation)
        {
            self.pending.remove(&id)
        } else {
            None
        }
    }
}

impl Drop for ResolutionState {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Applies one completed resolution and drains the frames queued behind it.
///
/// If a later queued frame names a different uncached domain, it and the rest
/// of the queue are moved to a new pending entry instead of blocking here.
async fn apply_resolution(
    state: &MuxState,
    resolutions: &mut ResolutionState,
    result: ResolutionResult,
) -> Result<bool, MuxError> {
    let Some(pending) = resolutions.take(result.id, result.generation) else {
        return Ok(false);
    };
    let PendingResolution {
        mut owner, frames, ..
    } = pending;
    let ResolutionResult {
        id,
        destination,
        result,
        ..
    } = result;
    let mut session_activity = false;

    match result {
        Ok(address) => {
            resolutions.cache_insert(&destination, address);
            if let Some(mut frame) = owner.take() {
                if frame.frame.status == SessionStatus::New
                    && let Some(global_id) = frame.frame.global_id
                {
                    resolutions.cancel_global(global_id);
                }
                frame.frame.rewrite_destination(address);
                session_activity |= state
                    .handle_frame_with_session_transition(&frame.frame.as_borrowed())
                    .await?;
            }
        }
        Err(error) => {
            tracing::debug!(
                session_id = id,
                %error,
                "XUDP domain resolution failed"
            );
            if let Some(frame) = owner.take() {
                match frame.frame.status {
                    SessionStatus::New => state.try_send_end(id, true),
                    SessionStatus::Keep if state.session(id).is_none() => {
                        // Match handle_keep's clean End for an unknown session.
                        state.try_send_end(id, false);
                    }
                    _ => {}
                }
            }
        }
    }

    session_activity |= process_pending_frames(state, resolutions, frames).await?;
    Ok(session_activity)
}

/// Dispatches queued frames after the lookup owner has been handled.
///
/// A suffix may start with another uncached domain; that frame and the rest of
/// the queue become a new pending operation instead of blocking the read loop.
async fn process_pending_frames(
    state: &MuxState,
    resolutions: &mut ResolutionState,
    mut frames: VecDeque<PendingFrame>,
) -> Result<bool, MuxError> {
    let mut session_activity = false;
    while let Some(mut frame) = frames.pop_front() {
        if let Some(location) = frame.frame.destination.clone()
            && matches!(location.address, Address::Domain(_))
        {
            let family = if frame.frame.status == SessionStatus::New {
                None
            } else {
                state
                    .session(frame.frame.session_id)
                    .map(|session| session.family)
            };
            if let Some(cached) = resolutions.cache_get(&location, family) {
                frame.frame.rewrite_destination(cached);
            } else {
                frames.push_front(frame);
                let next_id = frames
                    .front()
                    .map(|frame| frame.frame.session_id)
                    .expect("queue is non-empty");
                let reject = frames
                    .front()
                    .is_some_and(|frame| frame.frame.status == SessionStatus::New);
                if !resolutions.start(next_id, location, family, frames) {
                    state.try_send_end(next_id, reject);
                }
                return Ok(session_activity);
            }
        }
        session_activity |= state
            .handle_frame_with_session_transition(&frame.frame.as_borrowed())
            .await?;
    }
    Ok(session_activity)
}

/// Errors returned by [`handle_mux_stream`].
#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    /// The supplied configuration is invalid.
    #[error("invalid XUDP configuration: {0}")]
    Config(#[from] XudpConfigError),

    /// The peer sent a frame that can never be valid.
    #[error("malformed XUDP frame: {0}")]
    Frame(#[from] XudpError),

    /// A stream or socket operation failed.
    #[error("XUDP stream I/O error: {0}")]
    Io(#[from] io::Error),

    /// The stream ended in the middle of a frame.
    #[error("XUDP stream ended with {buffered} buffered bytes of an incomplete frame")]
    TruncatedFrame {
        /// Number of bytes that were waiting for more input.
        buffered: usize,
    },

    /// The frame reassembly buffer exceeded its invariant bound.
    #[error("XUDP frame reassembly buffer exceeded its bound at {buffered} bytes")]
    FrameTooLarge {
        /// Buffered byte count.
        buffered: usize,
    },

    /// A bounded network operation timed out.
    #[error("XUDP {stage} timed out")]
    Timeout {
        /// Operation that timed out.
        stage: &'static str,
    },

    /// The reply writer ended, so no further frames can be sent.
    #[error("XUDP mux stream writer is closed")]
    WriterClosed,

    /// An internally constructed frame could not be encoded.
    #[error("could not encode an XUDP frame")]
    Encode,
}

/// Why a session is being closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseReason {
    /// The client sent `End`.
    ClientEnd,
    /// The idle timeout elapsed.
    Idle,
    /// The UDP relay failed.
    RelayError,
}

impl CloseReason {
    /// Returns `true` when the close must set the error option.
    const fn is_error(self) -> bool {
        matches!(self, Self::RelayError)
    }

    /// Returns `true` when a GlobalID socket may be retained.
    const fn retains_socket(self) -> bool {
        !self.is_error()
    }
}

/// Shared state for one mux stream.
struct MuxState {
    config: Arc<XudpConfig>,
    table: Arc<Mutex<SessionTable>>,
    outbound: mpsc::Sender<QueuedFrame>,
    /// Counted reply-queue reservations shared by data and control frames.
    queued: Arc<AtomicUsize>,
    /// Byte budget shared by every session of this mux.
    stream_reply_budget: ReplyQueueBudget,
    limiter: XudpSessionLimiter,
    /// Bounded outbound queue for congested session sockets.
    send_tx: mpsc::Sender<OutboundDatagram>,
    /// Queued plus in-flight outbound datagrams.
    send_inflight: Arc<AtomicUsize>,
}

/// Handles one XUDP mux stream until EOF or a protocol error.
///
/// `stream` is the VLESS body after the mux request has been authenticated.
/// The function owns the stream for its lifetime and returns when the peer
/// closes it, a malformed frame arrives, an I/O or timeout error occurs, or an
/// empty stream has been idle for `session_idle_timeout`. Every session and
/// reply task is stopped before it returns. A 24-hour read-inactivity backstop
/// also bounds a stream that keeps sessions active but never sends a frame.
///
/// `limiter` is process-wide; the per-stream `max_sessions` count does not
/// bound aggregate memory when several mux streams are open.
pub async fn handle_mux_stream<S>(
    stream: S,
    config: Arc<XudpConfig>,
    limiter: XudpSessionLimiter,
) -> Result<(), MuxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    config.validate()?;
    let metrics = limiter.metrics();
    let _live = limiter.handler_guard();

    let (mut reader, writer) = tokio::io::split(stream);
    let (outbound, inbound) = mpsc::channel(config.max_queued_replies);
    let queued = Arc::new(AtomicUsize::new(0));
    let (send_tx, send_rx) = mpsc::channel(SEND_QUEUE_CAPACITY);
    let send_inflight = Arc::new(AtomicUsize::new(0));
    let (send_failed, mut send_failed_rx) = mpsc::channel(16);
    let (writer_failed, mut writer_failed_rx) = watch::channel(false);
    let mut writer_task = tokio::spawn(write_loop(
        writer,
        inbound,
        config.io_timeout,
        writer_failed,
    ));
    let mut send_task = tokio::spawn(send_loop(
        send_rx,
        Arc::clone(&send_inflight),
        limiter.metrics(),
        send_failed,
    ));

    let table = Arc::new(Mutex::new(SessionTable::default()));
    limiter.register_table(&table);
    let state = MuxState {
        config: config.clone(),
        table: Arc::clone(&table),
        outbound,
        queued,
        stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
        limiter,
        send_tx,
        send_inflight,
    };

    let result = read_loop(
        &mut reader,
        &state,
        &mut writer_failed_rx,
        &mut send_failed_rx,
    )
    .await;

    // The stream is gone or unusable; no End frames can reach the peer. Stop
    // every reply task and release every socket. Signal every task first, then
    // join them under one shared deadline so a broken task cannot multiply the
    // shutdown budget by the session limit.
    let active = lock_table(&table).drain_active();
    for entry in &active {
        // A reply task may have claimed the close just before the drain. Only
        // the first close owner records a reason, so admitted/closed counters
        // reconcile instead of double-counting that race.
        if entry.session.mark_closed() {
            metrics.record_xudp_closed_mux();
        }
        // A spawned reply task may not have been polled yet. Marking the
        // session closed makes its initial check fail even if the watch
        // notification is missed; `send_replace` also stores the stop value
        // when no receiver has subscribed.
        entry.session.stop();
    }
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    for entry in active {
        if let Some(mut task) = entry.reply_task {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if timeout(remaining, &mut task).await.is_err() {
                task.abort();
            }
        }
    }
    let cleared = lock_table(&table).clear_expiring();
    if cleared > 0 {
        metrics.record_xudp_retained_expired(cleared);
    }

    drop(state);
    // The writer and sender reuse the reply-join deadline, so the whole
    // teardown is bounded by one `SHUTDOWN_TIMEOUT` instead of one per task.
    // A timed-out task is aborted without awaiting its cancellation.
    let remaining = deadline.saturating_duration_since(Instant::now());
    if timeout(remaining, &mut writer_task).await.is_err() {
        writer_task.abort();
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if timeout(remaining, &mut send_task).await.is_err() {
        send_task.abort();
    }

    result
}

/// Maximum frames coalesced into one stream write.
///
/// A DNS or QUIC burst often reaches the reply queue as several small frames.
/// Coalescing them avoids one Vision block, TLS record, and socket write per
/// datagram without waiting for more input: `try_recv` only takes frames that
/// are already queued, so a lone frame keeps its normal latency.
const MAX_WRITE_BATCH_FRAMES: usize = 32;

/// Soft byte target for one coalesced stream write. One extra frame can cross
/// the target, so the hard bound is this plus one maximum-size frame.
const MAX_WRITE_BATCH_BYTES: usize = 64 * 1024;

/// Serializes frames from the reply tasks and the read loop.
async fn write_loop<W>(
    mut writer: W,
    mut inbound: mpsc::Receiver<QueuedFrame>,
    io_timeout: Duration,
    writer_failed: watch::Sender<bool>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // Allocate lazily: a mux stream that never carries a reply should not pay
    // for a 64 KiB batch buffer. Capacity grows to the frame/batch bound on
    // first use and is then reused.
    let mut batch = Vec::new();
    // Keep the frames alive until the write completes so their aggregate
    // reply-budget permits are held for exactly as long as the bytes wait.
    let mut frames: Vec<QueuedFrame> = Vec::new();

    while let Some(frame) = inbound.recv().await {
        batch.clear();
        frames.clear();
        append_frame(&mut batch, &frame)?;
        frames.push(frame);

        while frames.len() < MAX_WRITE_BATCH_FRAMES && batch.len() < MAX_WRITE_BATCH_BYTES {
            match inbound.try_recv() {
                Ok(frame) => {
                    append_frame(&mut batch, &frame)?;
                    frames.push(frame);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        if let Err(error) = write_frame(&mut writer, &batch, io_timeout).await {
            let _ = writer_failed.send(true);
            return Err(error);
        }
        // Release the reply-budget permits before waiting for the next frame.
        // Holding them across `recv().await` would let idle mux streams pin the
        // process-wide budget indefinitely.
        frames.clear();
        batch.clear();
    }

    timeout(io_timeout, writer.shutdown())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XUDP stream shutdown timed out"))??;
    Ok(())
}

/// Encodes one queued frame into the writer's reusable batch.
fn append_frame(batch: &mut Vec<u8>, frame: &QueuedFrame) -> io::Result<()> {
    match &frame.reply {
        Some(reply) => {
            let spec = FrameSpec {
                session_id: reply.session_id,
                status: SessionStatus::Keep,
                option: FrameOption::DATA,
                network: Some(TargetNetwork::Udp),
                destination: Some(&reply.destination),
                global_id: None,
                payload: &reply.payload,
            };
            frame::encode_frame(batch, spec)
                .map_err(|error| io::Error::other(format!("XUDP reply encode failed: {error}")))
        }
        None => {
            batch.extend_from_slice(&frame.bytes);
            Ok(())
        }
    }
}

/// Writes and flushes one complete frame.
async fn write_frame<W>(writer: &mut W, frame: &[u8], io_timeout: Duration) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(io_timeout, async {
        writer.write_all(frame).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XUDP stream write timed out"))?
}

/// Reads, parses, and dispatches frames until the stream ends.
async fn read_loop<R>(
    reader: &mut R,
    state: &MuxState,
    writer_failed: &mut watch::Receiver<bool>,
    send_failed: &mut mpsc::Receiver<Arc<Session>>,
) -> Result<(), MuxError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(MAX_FRAME_LEN);
    let mut chunk = vec![0u8; READ_CHUNK_LEN];
    let mut empty_since = Some(Instant::now());
    let mut resolutions = ResolutionState::new(state.limiter.clone());
    let mut sweep = interval(state.config.sweep_interval());
    sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The first interval tick is immediate; use the first real sweep later.
    sweep.tick().await;

    // Arm the read backstop once. Rebuilding it per `select!` iteration would
    // let any ready branch (the sweep tick, in particular) restart the window.
    let read_deadline = sleep(STREAM_IDLE_TIMEOUT);
    tokio::pin!(read_deadline);

    loop {
        // Consume every complete frame before waiting for more input. This
        // handles coalesced frames and a frame split across reads equally.
        // Track a cursor and compact once: draining after every frame would
        // repeatedly move the remaining batch, which is quadratic for small
        // coalesced frames.
        let mut consumed = 0;
        let mut batch_session_activity = false;
        loop {
            match frame::parse_frame(&buffer[consumed..]) {
                Ok(Some((parsed, used))) => {
                    let id = parsed.session_id;
                    if parsed.status == SessionStatus::New
                        && let Some(global_id) = parsed.global_id
                    {
                        // A newer attachment for the same GlobalID supersedes
                        // any older pending domain New. Otherwise the delayed
                        // old lookup could migrate the flow backwards.
                        resolutions.cancel_global(global_id);
                    }
                    if resolutions.has_pending(id) {
                        if parsed.option.has_data()
                            && !parsed.payload.is_empty()
                            && let Some(session) = state.session(id)
                        {
                            session.touch();
                        }
                        if !resolutions.push_frame(id, OwnedFrame::from_borrowed(&parsed)) {
                            tracing::debug!(
                                session_id = id,
                                "XUDP pending-resolution queue is full; dropping frame"
                            );
                            if parsed.status == SessionStatus::New {
                                state.try_send_end(id, true);
                            }
                        }
                        consumed += used;
                        debug_assert!(consumed <= buffer.len());
                        continue;
                    }

                    if matches!(parsed.status, SessionStatus::New | SessionStatus::Keep)
                        && let Some(destination) = parsed.destination.as_ref()
                        && matches!(destination.address, Address::Domain(_))
                    {
                        let family = if parsed.status == SessionStatus::New {
                            None
                        } else {
                            state.session(id).map(|session| session.family)
                        };
                        if let Some(cached) = resolutions.cache_get(destination, family) {
                            let mut owned = OwnedFrame::from_borrowed(&parsed);
                            owned.rewrite_destination(cached);
                            batch_session_activity |= state
                                .handle_frame_with_session_transition(&owned.as_borrowed())
                                .await?;
                        } else {
                            if parsed.status == SessionStatus::Keep
                                && parsed.option.has_data()
                                && !parsed.payload.is_empty()
                                && let Some(session) = state.session(id)
                            {
                                session.touch();
                            }
                            let Some(frame) = PendingFrame::new(
                                OwnedFrame::from_borrowed(&parsed),
                                &state.limiter,
                            ) else {
                                if parsed.status == SessionStatus::New {
                                    state.try_send_end(id, true);
                                }
                                consumed += used;
                                debug_assert!(consumed <= buffer.len());
                                continue;
                            };
                            let frames = VecDeque::from([frame]);
                            if !resolutions.start(id, destination.clone(), family, frames) {
                                tracing::debug!(
                                    session_id = id,
                                    "XUDP pending-resolution limit reached; rejecting frame"
                                );
                                if parsed.status == SessionStatus::New {
                                    state.try_send_end(id, true);
                                }
                            }
                        }
                    } else {
                        batch_session_activity |=
                            state.handle_frame_with_session_transition(&parsed).await?;
                    }
                    debug_assert!(used > 0);
                    consumed += used;
                    debug_assert!(consumed <= buffer.len());
                }
                Ok(None) => break,
                Err(error) => return Err(MuxError::Frame(error)),
            }
        }

        // Compact before the bounds check and the read arm below. Those paths
        // must observe only bytes that are still part of an incomplete frame.
        if consumed > 0 {
            // One table check per read batch is equivalent to the old
            // per-frame check for the empty-stream timer: the timer only
            // needs to know whether the batch left any session behind.
            // A session created and closed inside the same batch must restart
            // the deadline; otherwise a coalesced New+End near the old
            // deadline closes the mux early. KeepAlive-only batches leave
            // this false and cannot extend the timer.
            if state.has_active_sessions() {
                empty_since = None;
            } else if batch_session_activity {
                empty_since = Some(Instant::now());
            } else {
                empty_since.get_or_insert_with(Instant::now);
            }
            buffer.drain(..consumed);
        }

        if buffer.len() > MAX_BUFFERED_LEN {
            return Err(MuxError::FrameTooLarge {
                buffered: buffer.len(),
            });
        }

        tokio::select! {
            changed = writer_failed.changed() => {
                let _ = changed;
                return Err(MuxError::WriterClosed);
            }
            Some(session) = send_failed.recv() => {
                state.close_if_same(&session).await?;
            }
            resolved = resolutions.results.recv() => {
                let Some(result) = resolved else {
                    return Err(MuxError::Timeout {
                        stage: "XUDP resolution task",
                    });
                };
                let session_activity =
                    apply_resolution(state, &mut resolutions, result).await?;
                if state.has_active_sessions() {
                    empty_since = None;
                } else if session_activity {
                    empty_since = Some(Instant::now());
                }
            }
            _ = sweep.tick() => {
                let had_sessions = state.has_active_sessions();
                state.sweep().await?;
                // A mux stream that has stayed empty for the session idle
                // timeout cannot carry a live session. Stock closes such a
                // worker after 60 s; match the intent without cutting an
                // active one-way flow. Losing the last session in this sweep
                // starts the clock now instead of reusing an older one.
                if state.has_active_sessions() {
                    empty_since = None;
                } else if had_sessions {
                    empty_since = Some(Instant::now());
                } else {
                    let since = *empty_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= state.config.session_idle_timeout {
                        return Ok(());
                    }
                }
            }
            _ = &mut read_deadline => {
                return Err(MuxError::Timeout {
                    stage: "mux stream read",
                });
            }
            received = reader.read(&mut chunk) => {
                match received {
                    Err(error) => return Err(MuxError::Io(error)),
                    Ok(0) => {
                        return if buffer.is_empty() {
                            Ok(())
                        } else {
                            Err(MuxError::TruncatedFrame {
                                buffered: buffer.len(),
                            })
                        };
                    }
                    Ok(count) => {
                        // Only bytes from the peer extend the window; timer,
                        // resolution, and failure branches must not.
                        read_deadline
                            .as_mut()
                            .reset(Instant::now() + STREAM_IDLE_TIMEOUT);
                        if buffer.len().saturating_add(count) > MAX_BUFFERED_LEN {
                            return Err(MuxError::FrameTooLarge {
                                buffered: buffer.len() + count,
                            });
                        }
                        buffer.extend_from_slice(&chunk[..count]);
                    }
                }
            }
        }
    }
}

/// Sends one UDP datagram without waiting on the shared mux read loop.
fn try_send_now(socket: &UdpSocket, payload: &[u8], destination: SocketAddr) -> io::Result<bool> {
    match socket.try_send_to(payload, destination) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error),
    }
}

/// Drains congested datagrams without holding the mux read loop.
async fn send_loop(
    mut inbound: mpsc::Receiver<OutboundDatagram>,
    inflight: Arc<AtomicUsize>,
    metrics: Arc<Metrics>,
    failures: mpsc::Sender<Arc<Session>>,
) {
    while let Some(datagram) = inbound.recv().await {
        let socket = &datagram.session.socket;
        let result = match socket.try_send_to(&datagram.payload, datagram.destination) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                match timeout(
                    SEND_WAIT,
                    socket.send_to(&datagram.payload, datagram.destination),
                )
                .await
                {
                    Ok(result) => result.map(|_| ()),
                    // The send buffer stayed full for the short bound. UDP
                    // congestion is expected to drop datagrams, not stall the
                    // mux.
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "XUDP send buffer stayed full",
                    )),
                }
            }
            Err(error) => Err(error),
        };
        let fatal = match &result {
            Ok(()) => false,
            Err(error) => !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
        };
        if result.is_err() {
            metrics.record_xudp_send_dropped();
        }
        if fatal {
            let _ = failures.send(Arc::clone(&datagram.session)).await;
        }
        inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl MuxState {
    /// Sends a datagram now, or queues it without blocking the read loop.
    fn dispatch_datagram(
        &self,
        session: &Arc<Session>,
        payload: &[u8],
        destination: SocketAddr,
    ) -> io::Result<()> {
        // Always try the socket first. Gating this on an empty queue sends
        // every datagram through the allocation/channel path under sustained
        // load, which costs more than the UDP ordering that the fast path
        // could disturb (UDP does not guarantee ordering anyway).
        match try_send_now(&session.socket, payload, destination) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => return Err(error),
        }
        let datagram = OutboundDatagram {
            session: Arc::clone(session),
            destination,
            payload: payload.to_vec(),
        };
        self.send_inflight.fetch_add(1, Ordering::AcqRel);
        match self.send_tx.try_send(datagram) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.send_inflight.fetch_sub(1, Ordering::AcqRel);
                self.limiter.metrics().record_xudp_send_dropped();
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.send_inflight.fetch_sub(1, Ordering::AcqRel);
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "XUDP send queue closed",
                ))
            }
        }
    }

    /// Dispatches one parsed frame.
    async fn handle_frame(&self, parsed: &Frame<'_>) -> Result<(), MuxError> {
        if parsed.payload.len() > self.config.max_datagram_size {
            tracing::debug!(
                session_id = parsed.session_id,
                length = parsed.payload.len(),
                "XUDP datagram exceeds the configured limit; closing the session"
            );
            return self.close_with_error(parsed.session_id).await;
        }

        match parsed.status {
            SessionStatus::New => self.handle_new(parsed).await,
            SessionStatus::Keep => self.handle_keep(parsed).await,
            SessionStatus::End => self.handle_end(parsed.session_id).await,
            SessionStatus::KeepAlive => Ok(()),
        }
    }

    /// Dispatches a frame that may create or close an active session.
    ///
    /// Data frames are deliberately excluded: the batch-end active check
    /// already covers a session that stays alive, and adding a table lookup
    /// to every datagram would put the lock back on the reply hot path.
    async fn handle_frame_with_session_transition(
        &self,
        parsed: &Frame<'_>,
    ) -> Result<bool, MuxError> {
        match parsed.status {
            SessionStatus::New => {
                self.handle_frame(parsed).await?;
                Ok(self.session(parsed.session_id).is_some())
            }
            SessionStatus::End => {
                let had_session = self.session(parsed.session_id).is_some();
                self.handle_frame(parsed).await?;
                Ok(had_session)
            }
            _ => {
                self.handle_frame(parsed).await?;
                Ok(false)
            }
        }
    }

    /// Handles `New`: create or reattach a UDP session.
    async fn handle_new(&self, parsed: &Frame<'_>) -> Result<(), MuxError> {
        let id = parsed.session_id;
        self.limiter
            .metrics()
            .record_xudp_new(parsed.global_id.is_some());

        if parsed.network != Some(TargetNetwork::Udp) {
            tracing::debug!(session_id = id, "XUDP New is not a UDP target; rejecting");
            return self.send_end(id, true).await;
        }
        let Some(destination) = parsed.destination.as_ref() else {
            return self.send_end(id, true).await;
        };

        // Resolution happens before touching any session state: a domain that
        // cannot be resolved must not evict a retained socket.
        let resolved = match resolve_destination(
            destination,
            None,
            self.config.io_timeout.min(RESOLVE_TIMEOUT),
        )
        .await
        {
            Ok(address) => address,
            Err(error) => {
                tracing::debug!(
                    session_id = id,
                    %error,
                    "XUDP New destination resolution failed"
                );
                return self.send_end(id, true).await;
            }
        };
        let family = SocketFamily::of(resolved);
        let global_id = parsed.global_id;

        match self.duplicate_status(id, global_id) {
            DuplicateStatus::DifferentGlobalId => {
                tracing::debug!(
                    session_id = id,
                    "XUDP duplicate session id with a different GlobalID; rejecting"
                );
                return self.send_end(id, true).await;
            }
            DuplicateStatus::SameGlobalId => {
                let taken = { lock_table(&self.table).take(id) };
                if let Some(active) = taken {
                    self.close_active(active, CloseReason::ClientEnd).await?;
                }
            }
            DuplicateStatus::None => {}
        }

        // Stock migrates a GlobalID to a new mux session id instead of leaving
        // two active attachments for one logical UDP flow.
        if let Some(global_id) = global_id {
            let old = { lock_table(&self.table).take_by_global_id(global_id) };
            if let Some(old) = old {
                self.close_active(old, CloseReason::ClientEnd).await?;
            }
        }

        // Every transition from retained to active must respect the same
        // per-stream active cap. Check before taking the retained socket so a
        // rejected reattach leaves it available for a later attempt.
        let active_limit = self
            .limiter
            .stream_active_limit()
            .min(self.config.max_sessions);
        if lock_table(&self.table).active_len() >= active_limit {
            self.limiter.metrics().record_xudp_rejected_per_stream();
            tracing::debug!(
                session_id = id,
                "XUDP per-stream active limit reached; rejecting New"
            );
            return self.send_end(id, true).await;
        }

        // A clean close with a nonzero GlobalID retains its socket. Reattach
        // only while the retention deadline has not passed; `take_expiring`
        // removes the entry either way and drops an expired entry (and its
        // permit) before the slot is requested again. The deadline is sampled
        // inside the lock so a descheduled caller cannot reattach an entry
        // whose deadline passed while it waited.
        let retained = match global_id.and_then(|global_id| {
            let mut table = lock_table(&self.table);
            table.take_expiring(global_id, Instant::now())
        }) {
            Some(RetainedLookup::Live(entry)) => Some(entry),
            Some(RetainedLookup::Expired) => {
                self.limiter.metrics().record_xudp_retained_expired(1);
                None
            }
            None => None,
        };
        let reattached = matches!(&retained, Some(entry) if entry.family == family);
        let (socket, permit) = match retained {
            Some(retained) if retained.family == family => (retained.socket, retained.permit),
            retained => {
                // A family change cannot reuse the retained socket; it was
                // removed from the table and is dropped here. Release its
                // permit before asking the global limiter for a fresh slot.
                if retained.is_some() {
                    self.limiter.metrics().record_xudp_retained_discarded();
                }
                drop(retained);
                if !self.reserve_session_slot() {
                    self.limiter.metrics().record_xudp_rejected_per_stream();
                    tracing::debug!(session_id = id, "XUDP session limit reached; rejecting New");
                    return self.send_end(id, true).await;
                }
                let Some(permit) = self.limiter.try_acquire_or_evict() else {
                    self.limiter.metrics().record_xudp_rejected_global();
                    if self.limiter.pressure_log_due() {
                        let (active, retained) = {
                            let table = lock_table(&self.table);
                            (table.active_len(), table.retained_len())
                        };
                        let stats = self.limiter.stats();
                        tracing::info!(
                            session_id = id,
                            global_limit = self.limiter.max(),
                            stream_active = active,
                            stream_retained = retained,
                            xudp_active = stats.active,
                            xudp_retained = stats.retained,
                            xudp_used = stats.used,
                            xudp_available = stats.available,
                            xudp_high_water = stats.high_water,
                            xudp_live_tables = stats.live_tables,
                            xudp_live_handlers = stats.live_handlers,
                            xudp_unattributed = stats.unattributed,
                            "XUDP global session limit pressure"
                        );
                    }
                    tracing::debug!(
                        session_id = id,
                        global_limit = self.limiter.max(),
                        "global XUDP session limit reached; rejecting New"
                    );
                    return self.send_end(id, true).await;
                };
                let socket = match timeout(
                    self.config.io_timeout,
                    UdpSocket::bind(family.bind_address()),
                )
                .await
                {
                    Ok(Ok(socket)) => {
                        if let Err(error) = beam_sys::set_udp_recv_buffer(
                            socket.as_raw_fd(),
                            self.config.udp_recv_buffer,
                        ) {
                            tracing::debug!(
                                session_id = id,
                                %error,
                                "could not enlarge the XUDP socket receive buffer"
                            );
                        }
                        Arc::new(socket)
                    }
                    Ok(Err(error)) => {
                        tracing::debug!(
                            session_id = id,
                            %error,
                            "XUDP session socket bind failed"
                        );
                        return self.send_end(id, true).await;
                    }
                    Err(_) => {
                        tracing::debug!(session_id = id, "XUDP session socket bind timed out");
                        return self.send_end(id, true).await;
                    }
                };
                (socket, Some(permit))
            }
        };

        let session = Arc::new(Session::new(
            id, global_id, socket, family, resolved, permit,
        ));
        let session_handle = Arc::clone(&session);
        let reply_task = spawn_reply_task(
            Arc::clone(&session),
            self.outbound.clone(),
            Arc::clone(&self.queued),
            Arc::clone(&self.table),
            Arc::clone(&self.config),
            self.limiter.clone(),
            self.stream_reply_budget.clone(),
        );
        let replaced = lock_table(&self.table).insert(ActiveSession {
            session,
            reply_task: Some(reply_task),
        });
        if reattached {
            self.limiter.metrics().record_xudp_admitted_reattach();
            self.limiter.metrics().record_xudp_retained_reattached();
        } else {
            self.limiter.metrics().record_xudp_admitted_fresh();
        }
        if let Some(replaced) = replaced {
            // No other path can leave an entry with this id, but never leak a
            // task or socket if the invariant is broken.
            replaced.session.stop();
            if let Some(task) = replaced.reply_task {
                task.abort();
            }
        }

        if parsed.option.has_data()
            && !parsed.payload.is_empty()
            && let Err(error) = self.dispatch_datagram(&session_handle, parsed.payload, resolved)
        {
            tracing::debug!(
                session_id = id,
                %error,
                "XUDP first datagram send failed"
            );
            if reattached {
                self.limiter.metrics().record_xudp_retained_discarded();
            }
            return self.close_if_same(&session_handle).await;
        }

        Ok(())
    }

    /// Handles `Keep`: append a datagram to an existing session.
    async fn handle_keep(&self, parsed: &Frame<'_>) -> Result<(), MuxError> {
        let id = parsed.session_id;
        let Some(session) = self.session(id) else {
            // Stock replies with a clean End for an unknown session.
            return self.send_end(id, false).await;
        };
        if !parsed.option.has_data() || parsed.payload.is_empty() {
            return Ok(());
        }

        let destination = match parsed.destination.as_ref() {
            Some(location) => {
                match resolve_destination(
                    location,
                    Some(session.family),
                    self.config.io_timeout.min(RESOLVE_TIMEOUT),
                )
                .await
                {
                    Ok(address) => {
                        session.set_destination(address);
                        address
                    }
                    Err(error) => {
                        // A per-datagram destination that cannot be used by
                        // this socket family is dropped, like a bad UDP route.
                        tracing::debug!(
                            session_id = id,
                            %error,
                            "XUDP Keep destination rejected; dropping the datagram"
                        );
                        return Ok(());
                    }
                }
            }
            // Xray clients omit the address on later frames. Fall back to the
            // last destination this session used.
            None => session.destination(),
        };

        if let Err(error) = self.dispatch_datagram(&session, parsed.payload, destination) {
            tracing::debug!(session_id = id, %error, "XUDP relay send failed");
            if session.is_closed() {
                Ok(())
            } else {
                self.close_if_same(&session).await
            }
        } else {
            session.touch();
            Ok(())
        }
    }

    /// Handles `End`: close a session. Unknown ids are ignored, like stock.
    async fn handle_end(&self, id: u16) -> Result<(), MuxError> {
        self.limiter.metrics().record_xudp_end();
        let taken = { lock_table(&self.table).take(id) };
        if let Some(active) = taken {
            self.close_active(active, CloseReason::ClientEnd).await
        } else {
            Ok(())
        }
    }

    /// Looks up an active session without holding the table lock.
    fn session(&self, id: u16) -> Option<Arc<Session>> {
        lock_table(&self.table)
            .active(id)
            .map(|entry| Arc::clone(&entry.session))
    }

    /// Returns `true` while any active session exists.
    ///
    /// Retained (`expiring`) sockets deliberately do not count: a GlobalID
    /// kept for reattachment must not keep an otherwise empty mux alive.
    fn has_active_sessions(&self) -> bool {
        lock_table(&self.table).active_len() > 0
    }

    /// Returns the duplicate-ID classification for a `New`.
    fn duplicate_status(&self, id: u16, global_id: Option<[u8; GLOBAL_ID_LEN]>) -> DuplicateStatus {
        match lock_table(&self.table).active(id) {
            None => DuplicateStatus::None,
            Some(entry) if entry.session.global_id == global_id => DuplicateStatus::SameGlobalId,
            Some(_) => DuplicateStatus::DifferentGlobalId,
        }
    }

    /// Reserves a slot for a new active session.
    ///
    /// Retained GlobalID sockets are evicted first; they are optional state and
    /// must never prevent a live session from being accepted.
    fn reserve_session_slot(&self) -> bool {
        let mut table = lock_table(&self.table);
        // Do not let one mux stream consume every global session. The cap
        // leaves at least half of the global slots for other streams; retained
        // sockets are still evicted before a live flow is rejected.
        let active_limit = self
            .limiter
            .stream_active_limit()
            .min(self.config.max_sessions);
        if table.active_len() >= active_limit {
            return false;
        }
        if table.total() < self.config.max_sessions {
            return true;
        }
        let evicted = table.evict_oldest_expiring();
        if evicted {
            self.limiter.metrics().record_xudp_retained_evicted();
        }
        evicted
    }

    /// Closes a session and sends `End`.
    ///
    /// Close marks the session closed, fences the reply-enqueue gate, waits at
    /// most [`CLOSE_JOIN_TIMEOUT`] for the reply task, and aborts on timeout.
    /// A socket is retained only when the old reader stopped, so no data can
    /// follow the End and no second reader can share a retained socket.
    async fn close_active(
        &self,
        active: ActiveSession,
        reason: CloseReason,
    ) -> Result<(), MuxError> {
        let ActiveSession {
            session,
            reply_task,
        } = active;
        let first = session.mark_closed();
        session.stop();
        // Fence any reply enqueue that was already in flight, then wait only
        // briefly for the reply task. If it does not stop, abort and do not
        // retain the socket; a retained socket must never have two readers.
        {
            let _gate = session.enqueue_guard();
        }
        let mut reply_stopped = true;
        if let Some(mut task) = reply_task
            && timeout(CLOSE_JOIN_TIMEOUT, &mut task).await.is_err()
        {
            task.abort();
            reply_stopped = false;
        }

        if !first {
            return Ok(());
        }

        // The reply task may have observed a socket error just before this
        // close claimed the session; report it as an error even when the
        // close itself was clean.
        let error = reason.is_error() || session.failed();
        match reason {
            CloseReason::Idle => self.limiter.metrics().record_xudp_closed_idle(),
            CloseReason::RelayError => self.limiter.metrics().record_xudp_closed_error(),
            CloseReason::ClientEnd => self.limiter.metrics().record_xudp_closed_end(),
        }
        if reason == CloseReason::Idle {
            // A sweep can expire many sessions at once. Waiting for each idle
            // End would block the mux read loop when the peer is not reading.
            // Idle End is best-effort: the client learns the flow is gone on
            // its next Keep, while a full queue already signals pressure.
            self.try_send_end(session.id, error);
        } else {
            self.send_end(session.id, error).await?;
        }

        let permit = session.take_permit();
        if reason.retains_socket()
            && reply_stopped
            && !session.failed()
            && drain_retained_socket(&session.socket)
            && let Some(global_id) = session.global_id
        {
            let now = Instant::now();
            let retained = ExpiringSession {
                socket: Arc::clone(&session.socket),
                family: session.family,
                // A pathological Duration must not panic on overflow; an
                // immediately expired entry only loses optional retention.
                expires_at: now.checked_add(self.config.close_expiry).unwrap_or(now),
                permit,
            };
            let replaced = lock_table(&self.table).insert_expiring(global_id, retained);
            self.limiter.metrics().record_xudp_retained_inserted();
            if replaced.is_some() {
                self.limiter.metrics().record_xudp_retained_expired(1);
            }
            drop(replaced);
        }

        Ok(())
    }

    /// Closes a session because its relay failed.
    async fn close_with_error(&self, id: u16) -> Result<(), MuxError> {
        let taken = { lock_table(&self.table).take(id) };
        if let Some(active) = taken {
            self.close_active(active, CloseReason::RelayError).await
        } else {
            self.send_end(id, true).await
        }
    }

    /// Closes the session only when it still owns its id.
    ///
    /// A queued datagram can fail after the client ended that session and
    /// reused the 16-bit id. Reporting the failure by id alone would close, and
    /// queue an error `End` for, an unrelated newer session; identity is the
    /// `Arc<Session>` instance, so the guard is `take_if_same`.
    async fn close_if_same(&self, session: &Arc<Session>) -> Result<(), MuxError> {
        let taken = { lock_table(&self.table).take_if_same(session.id, session) };
        match taken {
            Some(active) => self.close_active(active, CloseReason::RelayError).await,
            None => Ok(()),
        }
    }

    /// Queues one `End` frame without waiting for writer capacity.
    ///
    /// A slow client must not turn a close burst into a read-loop stall. End
    /// is control information for one flow; dropping it under queue pressure
    /// is preferable to blocking unrelated DNS and QUIC sessions on the same
    /// mux.
    async fn send_end(&self, id: u16, error: bool) -> Result<(), MuxError> {
        self.enqueue_end(id, error)
    }

    fn enqueue_end(&self, id: u16, error: bool) -> Result<(), MuxError> {
        let frame = encode_end_frame(id, error);
        if frame.is_empty() {
            self.limiter.metrics().record_xudp_end_dropped();
            return Err(MuxError::Encode);
        }
        let Some(slot) = SlotGuard::try_acquire(&self.queued, self.config.max_queued_replies)
        else {
            self.limiter.metrics().record_xudp_end_dropped();
            tracing::debug!(
                session_id = id,
                "XUDP End frame dropped because the control reserve is exhausted"
            );
            return Ok(());
        };
        match self
            .outbound
            .try_send(QueuedFrame::new(frame, None, Some(slot)))
        {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.limiter.metrics().record_xudp_end_dropped();
                tracing::debug!(
                    session_id = id,
                    "XUDP End frame dropped because the write queue is full"
                );
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.limiter.metrics().record_xudp_end_dropped();
                Err(MuxError::WriterClosed)
            }
        }
    }

    /// Queues one `End` if capacity is immediately available.
    ///
    /// Used by idle sweeps so one slow reader cannot multiply close-path work
    /// by the number of expired sessions.
    fn try_send_end(&self, id: u16, error: bool) {
        let _ = self.enqueue_end(id, error);
    }

    /// Expires idle sessions and retained sockets.
    ///
    /// This runs once per sweep interval, not on the per-packet path.
    #[cold]
    async fn sweep(&self) -> Result<(), MuxError> {
        let now = Instant::now();
        let idle = {
            let mut table = lock_table(&self.table);
            let idle = table.take_idle(now, self.config.session_idle_timeout);
            let retained = table.expire_retained(now);
            if retained > 0 {
                self.limiter
                    .metrics()
                    .record_xudp_retained_expired(retained);
                tracing::trace!(count = retained, "XUDP retained sockets expired");
            }
            idle
        };

        let mut idle = idle.into_iter();
        while let Some(active) = idle.next() {
            tracing::debug!(session_id = active.session.id, "XUDP session expired");
            if let Err(error) = self.close_active(active, CloseReason::Idle).await {
                // The table no longer owns these sessions, so an early return
                // would detach their reply tasks and leak the sockets and
                // global permits. Stop and abort every remaining task before
                // propagating the first close error.
                tracing::debug!(
                    %error,
                    "XUDP idle-session close failed; stopping remaining sessions"
                );
                abort_sessions(idle);
                return Err(error);
            }
        }
        Ok(())
    }
}

/// Duplicate session-id classification for `New`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DuplicateStatus {
    /// No active session has this id.
    None,
    /// The active session has the same GlobalID and is replaced.
    SameGlobalId,
    /// The id is in use by a different GlobalID and must not be overwritten.
    DifferentGlobalId,
}

/// Drains a closed GlobalID socket before it is retained.
///
/// A retained socket has no reader for up to `close_expiry`; datagrams still
/// queued would otherwise consume the kernel receive buffer and be delivered
/// to a future session as stale replies. Return `false` when the socket still
/// has more than the bounded drain budget, in which case retaining it is not
/// worth the stale state.
fn drain_retained_socket(socket: &UdpSocket) -> bool {
    const DRAIN_BUDGET: usize = 64;
    let mut buffer = [0u8; 2048];
    for _ in 0..DRAIN_BUDGET {
        match socket.try_recv_from(&mut buffer) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return true,
            Err(_) => return false,
        }
    }
    matches!(
        socket.try_recv_from(&mut buffer),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    )
}

/// Stops reply tasks that were removed from the table but not closed.
///
/// This is only reached after a sweep close fails. Keeping it out of the hot
/// sweep path also keeps the normal expiry loop compact.
#[cold]
#[inline(never)]
fn abort_sessions(remaining: impl Iterator<Item = ActiveSession>) {
    for remaining in remaining {
        remaining.session.stop();
        if let Some(task) = remaining.reply_task {
            task.abort();
        }
    }
}

/// Locks the session table, recovering from a poisoned mutex.
fn lock_table(table: &Mutex<SessionTable>) -> MutexGuard<'_, SessionTable> {
    match table.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MuxError, MuxState, OutboundDatagram, OwnedFrame, SEND_QUEUE_CAPACITY, handle_mux_stream,
    };
    use crate::address::{Address, NetLocation};
    use crate::xudp::frame::{
        FrameOption, FrameSpec, GLOBAL_ID_LEN, MAX_PAYLOAD_LEN, SessionStatus, TargetNetwork,
        XudpError, encode_frame, parse_frame,
    };
    use crate::xudp::session::{
        ActiveSession, DEFAULT_STREAM_REPLY_BUDGET, QueuedFrame, ReplyQueueBudget, Session,
        SessionTable, SlotGuard, SocketFamily, XudpConfig, XudpConfigError, XudpSessionLimiter,
        spawn_reply_task,
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio::time::{Instant, sleep, timeout};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn test_send_sender() -> mpsc::Sender<OutboundDatagram> {
        let (tx, mut rx) = mpsc::channel(SEND_QUEUE_CAPACITY);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        tx
    }

    #[tokio::test]
    async fn send_queue_drops_when_full_without_blocking() {
        let config = test_config();
        let limiter = XudpSessionLimiter::default();
        let metrics = limiter.metrics();
        let table = Arc::new(Mutex::new(SessionTable::default()));
        let (outbound, _outbound_rx) = mpsc::channel(1);
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let inflight = Arc::new(AtomicUsize::new(1));
        let state = MuxState {
            config: Arc::clone(&config),
            table,
            outbound,
            queued: Arc::new(AtomicUsize::new(0)),
            stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            limiter,
            send_tx,
            send_inflight: Arc::clone(&inflight),
        };
        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("socket"),
        );
        let destination = socket.local_addr().expect("local address");
        let session = Arc::new(Session::new(
            1,
            None,
            Arc::clone(&socket),
            SocketFamily::V4,
            destination,
            None,
        ));
        state
            .send_tx
            .try_send(OutboundDatagram {
                session: Arc::clone(&session),
                destination,
                payload: vec![1],
            })
            .expect("prefill queue");
        let before = metrics.snapshot().xudp_send_dropped;
        state
            .dispatch_datagram(&session, b"second", destination)
            .expect("a full queue drops rather than fails the session");
        assert_eq!(metrics.snapshot().xudp_send_dropped, before + 1);
        assert_eq!(inflight.load(Ordering::Acquire), 1);
        assert!(send_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn stale_send_failure_does_not_close_the_replacement() {
        let config = test_config();
        let limiter = XudpSessionLimiter::default();
        let metrics = limiter.metrics();
        let table = Arc::new(Mutex::new(SessionTable::default()));
        let (outbound, mut outbound_rx) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let state = MuxState {
            config,
            table: Arc::clone(&table),
            outbound,
            queued: Arc::new(AtomicUsize::new(0)),
            stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            limiter,
            send_tx: test_send_sender(),
            send_inflight: Arc::new(AtomicUsize::new(0)),
        };

        // Two distinct sessions share id 7, so an id-based close would hit the
        // replacement instead of the session that reported the failure.
        let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let stale = Arc::new(Session::new(
            7,
            None,
            Arc::new(
                UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                    .await
                    .expect("stale session socket"),
            ),
            SocketFamily::V4,
            destination,
            None,
        ));
        let current = Arc::new(Session::new(
            7,
            None,
            Arc::new(
                UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                    .await
                    .expect("current session socket"),
            ),
            SocketFamily::V4,
            destination,
            None,
        ));

        table.lock().expect("table").insert(ActiveSession {
            session: Arc::clone(&stale),
            reply_task: None,
        });
        let replaced = table
            .lock()
            .expect("table")
            .insert(ActiveSession {
                session: Arc::clone(&current),
                reply_task: None,
            })
            .expect("the reused id must replace the stale session");
        drop(replaced);

        state
            .close_if_same(&stale)
            .await
            .expect("a stale failure is a no-op");
        {
            let table = table.lock().expect("table");
            let entry = table.active(7).expect("the replacement must stay resident");
            assert!(Arc::ptr_eq(&entry.session, &current));
            assert_eq!(table.total(), 1);
        }
        assert!(
            outbound_rx.try_recv().is_err(),
            "a stale failure must not queue an End"
        );
        assert_eq!(metrics.snapshot().xudp_closed_error, 0);

        state
            .close_if_same(&current)
            .await
            .expect("the current owner closes");
        assert!(table.lock().expect("table").active(7).is_none());
        let queued = outbound_rx.try_recv().expect("exactly one error End");
        let encoded = queued.encoded();
        let (frame, used) = parse_frame(&encoded)
            .expect("valid End")
            .expect("complete End");
        assert_eq!(used, encoded.len());
        assert_eq!(frame.session_id, 7);
        assert_eq!(frame.status, SessionStatus::End);
        assert_eq!(frame.option, FrameOption::ERROR);
        assert!(
            outbound_rx.try_recv().is_err(),
            "the close must queue exactly one End"
        );
        assert_eq!(metrics.snapshot().xudp_closed_error, 1);
    }

    #[tokio::test]
    async fn wouldblock_datagram_is_queued_instead_of_stalling() {
        let receiver = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("receiver");
        let destination = receiver.local_addr().expect("receiver address");
        let sender = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("sender");
        let payload = vec![0u8; 60_000];
        let mut filled = false;
        for _ in 0..10_000 {
            match sender.try_send_to(&payload, destination) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    filled = true;
                    break;
                }
                Err(error) => panic!("unexpected send error: {error}"),
            }
        }
        assert!(filled, "the UDP send buffer did not fill");

        let config = test_config();
        let limiter = XudpSessionLimiter::default();
        let (outbound, _outbound_rx) = mpsc::channel(1);
        let (send_tx, mut send_rx) = mpsc::channel(1);
        let inflight = Arc::new(AtomicUsize::new(0));
        let state = MuxState {
            config,
            table: Arc::new(Mutex::new(SessionTable::default())),
            outbound,
            queued: Arc::new(AtomicUsize::new(0)),
            stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            limiter,
            send_tx,
            send_inflight: Arc::clone(&inflight),
        };
        let socket = Arc::new(sender);
        let session = Arc::new(Session::new(
            1,
            None,
            Arc::clone(&socket),
            SocketFamily::V4,
            destination,
            None,
        ));
        state
            .dispatch_datagram(&session, b"queued", destination)
            .expect("a full send buffer queues instead of failing");
        assert_eq!(inflight.load(Ordering::Acquire), 1);
        let queued = send_rx.try_recv().expect("datagram is queued");
        assert_eq!(queued.destination, destination);
        assert_eq!(queued.payload, b"queued");
        assert!(Arc::ptr_eq(&queued.session, &session));
    }

    #[tokio::test]
    async fn end_enqueue_is_bounded_when_the_queue_is_full() {
        let config = Arc::new(XudpConfig {
            max_queued_replies: 2,
            io_timeout: Duration::from_secs(10),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::default();
        let (outbound, _inbound) = mpsc::channel(config.max_queued_replies);
        outbound
            .send(QueuedFrame::new(vec![1], None, None))
            .await
            .expect("first slot");
        outbound
            .send(QueuedFrame::new(vec![2], None, None))
            .await
            .expect("second slot");
        let state = MuxState {
            config: Arc::clone(&config),
            table: Arc::new(Mutex::new(SessionTable::default())),
            outbound,
            queued: Arc::new(AtomicUsize::new(0)),
            stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            limiter: limiter.clone(),
            send_tx: test_send_sender(),
            send_inflight: Arc::new(AtomicUsize::new(0)),
        };

        let started = Instant::now();
        state
            .send_end(7, true)
            .await
            .expect("a full queue must drop End without failing the mux");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "End waited for the full io_timeout"
        );
        assert_eq!(limiter.metrics().snapshot().xudp_end_dropped, 1);
    }

    #[tokio::test]
    async fn data_pressure_cannot_consume_the_control_reserve() {
        // Drive the real reply task: a sender floods the session socket while
        // the writer channel is not drained. Data may fill only
        // `max_queued_replies - reserve`, so the End must still fit.
        let config = Arc::new(XudpConfig {
            max_datagram_size: 64,
            max_queued_replies: 16,
            io_timeout: Duration::from_secs(1),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::default();
        let (outbound, mut inbound) = mpsc::channel(config.max_queued_replies);
        let queued = Arc::new(AtomicUsize::new(0));
        let table = Arc::new(Mutex::new(SessionTable::default()));
        let state = MuxState {
            config: Arc::clone(&config),
            table: Arc::clone(&table),
            outbound: outbound.clone(),
            queued: Arc::clone(&queued),
            stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            limiter: limiter.clone(),
            send_tx: test_send_sender(),
            send_inflight: Arc::new(AtomicUsize::new(0)),
        };

        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("session socket"),
        );
        let address = socket.local_addr().expect("session address");
        let session = Arc::new(Session::new(
            1,
            None,
            Arc::clone(&socket),
            SocketFamily::V4,
            address,
            None,
        ));
        let task = spawn_reply_task(
            Arc::clone(&session),
            outbound,
            Arc::clone(&queued),
            Arc::clone(&table),
            Arc::clone(&config),
            limiter.clone(),
            ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
        );

        let sender = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("sender socket");
        for byte in 0..20u8 {
            sender.send_to(&[byte], address).await.expect("flood send");
        }
        let mut waited = Duration::ZERO;
        while limiter.metrics().snapshot().xudp_replies_dropped < 12 {
            assert!(waited < TEST_TIMEOUT, "the flood was not admitted");
            sleep(Duration::from_millis(5)).await;
            waited += Duration::from_millis(5);
        }

        // Eight data replies hold the data class; the End uses the reserve.
        state.try_send_end(7, false);
        for _ in 0..8 {
            let queued_frame = timeout(TEST_TIMEOUT, inbound.recv())
                .await
                .expect("data reply timed out")
                .expect("data frame");
            let encoded = queued_frame.encoded();
            let (frame, _) = parse_frame(&encoded)
                .expect("data parse")
                .expect("complete data frame");
            assert_eq!(frame.status, SessionStatus::Keep);
        }
        let queued_frame = timeout(TEST_TIMEOUT, inbound.recv())
            .await
            .expect("end frame timed out")
            .expect("end frame");
        let encoded = queued_frame.encoded();
        let (frame, _) = parse_frame(&encoded)
            .expect("end parse")
            .expect("complete end frame");
        assert_eq!(frame.session_id, 7);
        assert_eq!(frame.status, SessionStatus::End);
        assert_eq!(limiter.metrics().snapshot().xudp_end_dropped, 0);

        session.stop();
        timeout(TEST_TIMEOUT, task)
            .await
            .expect("reply task must stop")
            .expect("reply task panicked");
    }

    #[tokio::test]
    async fn control_reserve_bounds_concurrent_ends() {
        let config = Arc::new(XudpConfig {
            max_queued_replies: 16,
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::default();
        let (outbound, mut inbound) = mpsc::channel(config.max_queued_replies);
        let queued = Arc::new(AtomicUsize::new(0));
        let state = MuxState {
            config: Arc::clone(&config),
            table: Arc::new(Mutex::new(SessionTable::default())),
            outbound: outbound.clone(),
            queued: Arc::clone(&queued),
            stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            limiter: limiter.clone(),
            send_tx: test_send_sender(),
            send_inflight: Arc::new(AtomicUsize::new(0)),
        };

        let mut held = Vec::new();
        for _ in 0..config.max_queued_replies {
            held.push(
                SlotGuard::try_acquire(&queued, config.max_queued_replies).expect("control slot"),
            );
        }
        state.try_send_end(7, false);
        assert_eq!(limiter.metrics().snapshot().xudp_end_dropped, 1);
        assert!(
            inbound.try_recv().is_err(),
            "a dropped End must not reach the queue"
        );

        drop(held);
        state.try_send_end(7, false);
        assert!(
            inbound.try_recv().is_ok(),
            "a released slot must admit the next End"
        );
    }

    /// UDP echo that prefixes every reply with `tag`, so a test can tell which
    /// destination the server actually used. The task ends when the caller
    /// aborts it.
    async fn tagged_echo(tag: u8) -> (SocketAddr, JoinHandle<()>) {
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("tagged echo");
        let address = socket.local_addr().expect("echo address");
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_PAYLOAD_LEN];
            while let Ok((len, peer)) = socket.recv_from(&mut buffer).await {
                let mut reply = Vec::with_capacity(len + 1);
                reply.push(tag);
                reply.extend_from_slice(&buffer[..len]);
                let _ = socket.send_to(&reply, peer).await;
            }
        });
        (address, task)
    }

    #[tokio::test]
    async fn keep_destination_is_applied_when_the_payload_is_not_empty() {
        let (first_addr, first_task) = tagged_echo(b'A').await;
        let (second_addr, second_task) = tagged_echo(b'B').await;
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();
        let (first_loc, second_loc) = (net_location(first_addr), net_location(second_addr));

        write_frame(&mut client, new_spec(7, &first_loc, b"hello", None)).await;
        let first = read_frame(&mut client, &mut buffer)
            .await
            .expect("first reply");
        assert_eq!(first.payload, b"Ahello", "session starts on A");

        // A Data Keep with a destination retargets the session.
        write_frame(&mut client, keep_spec(7, Some(&second_loc), b"x")).await;
        let retargeted = read_frame(&mut client, &mut buffer)
            .await
            .expect("retarget reply");
        assert_eq!(retargeted.payload, b"Bx");

        // Address-less Keeps reuse the destination the retarget accepted.
        write_frame(&mut client, keep_spec(7, None, b"next")).await;
        let second = read_frame(&mut client, &mut buffer)
            .await
            .expect("second reply");
        assert_eq!(second.payload, b"Bnext");

        finish(client, task).await;
        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn empty_keep_does_not_retarget_the_session() {
        let (first_addr, first_task) = tagged_echo(b'A').await;
        let (second_addr, second_task) = tagged_echo(b'B').await;
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();
        let (first_loc, second_loc) = (net_location(first_addr), net_location(second_addr));

        write_frame(&mut client, new_spec(7, &first_loc, b"hello", None)).await;
        let first = read_frame(&mut client, &mut buffer)
            .await
            .expect("first reply");
        assert_eq!(first.payload, b"Ahello", "session starts on A");

        // Documented rule: a Data Keep with an empty payload is dropped and does
        // not update the remembered destination.
        write_frame(&mut client, keep_spec(7, Some(&second_loc), b"")).await;

        write_frame(&mut client, keep_spec(7, None, b"next")).await;
        let still_first = read_frame(&mut client, &mut buffer)
            .await
            .expect("address-less reply");
        assert_eq!(
            still_first.payload, b"Anext",
            "an empty Keep must not retarget the session"
        );

        // A later Data Keep with a payload still retargets it.
        write_frame(&mut client, keep_spec(7, Some(&second_loc), b"x")).await;
        let retargeted = read_frame(&mut client, &mut buffer)
            .await
            .expect("retarget reply");
        assert_eq!(retargeted.payload, b"Bx");

        finish(client, task).await;
        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn non_data_keep_does_not_retarget_the_session() {
        let (first_addr, first_task) = tagged_echo(b'A').await;
        let (second_addr, second_task) = tagged_echo(b'B').await;
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();
        let (first_loc, second_loc) = (net_location(first_addr), net_location(second_addr));

        write_frame(&mut client, new_spec(7, &first_loc, b"hello", None)).await;
        let first = read_frame(&mut client, &mut buffer)
            .await
            .expect("first reply");
        assert_eq!(first.payload, b"Ahello");

        // A control-only Keep (no Data option) carrying a destination updates
        // nothing, matching the documented rule.
        let control_only = FrameSpec {
            session_id: 7,
            status: SessionStatus::Keep,
            option: FrameOption::new(0),
            network: Some(TargetNetwork::Udp),
            destination: Some(&second_loc),
            global_id: None,
            payload: b"",
        };
        write_frame(&mut client, control_only).await;

        write_frame(&mut client, keep_spec(7, None, b"next")).await;
        let still_first = read_frame(&mut client, &mut buffer)
            .await
            .expect("address-less reply");
        assert_eq!(
            still_first.payload, b"Anext",
            "a non-Data Keep must not retarget the session"
        );

        finish(client, task).await;
        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn empty_keep_with_an_unusable_family_keeps_the_session() {
        let (first_addr, first_task) = tagged_echo(b'A').await;
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();
        let first_loc = net_location(first_addr);
        let ipv6_loc = NetLocation {
            address: Address::Ipv6(Ipv6Addr::LOCALHOST),
            port: first_addr.port(),
        };

        write_frame(&mut client, new_spec(7, &first_loc, b"hello", None)).await;
        let first = read_frame(&mut client, &mut buffer)
            .await
            .expect("first reply");
        assert_eq!(first.payload, b"Ahello");

        // The frame cannot be used by this V4 socket, but an empty payload means
        // nothing is sent, nothing is resolved, and the session survives.
        write_frame(&mut client, keep_spec(7, Some(&ipv6_loc), b"")).await;

        write_frame(&mut client, keep_spec(7, None, b"next")).await;
        let still_first = read_frame(&mut client, &mut buffer)
            .await
            .expect("session must survive an unusable empty Keep");
        assert_eq!(still_first.payload, b"Anext");

        finish(client, task).await;
        first_task.abort();
    }

    #[tokio::test]
    async fn aborting_the_mux_handler_releases_sessions_and_permits() {
        // D8e: when the handler future is dropped (runtime shutdown, a
        // cancelled task), nothing runs the teardown, so the reply tasks keep
        // the sessions, their sockets, and their global permits alive.
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        // The per-stream active cap is max(global / 2, 1), so a global limit of
        // 8 admits the three sessions this test needs.
        let max = 8;
        let limiter = XudpSessionLimiter::new(max);
        let (mut client, task) = start_mux_with_limiter(test_config(), limiter.clone());

        for id in 1..=3u16 {
            write_frame(&mut client, new_spec(id, &destination, b"hello", None)).await;
        }
        for _ in 0..200 {
            if limiter.stats().active >= 3 {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
        let admitted = limiter.stats();
        assert_eq!(admitted.active, 3, "sessions did not admit: {admitted:?}");
        assert_eq!(
            admitted.available,
            max - 3,
            "permits did not account: {admitted:?}"
        );

        task.abort();
        let joined = task.await;
        assert!(joined.is_err(), "the handler task must be cancelled");
        // Let the aborted future finish dropping its locals.
        sleep(Duration::from_millis(200)).await;

        let after = limiter.stats();
        assert_eq!(
            after.active, 0,
            "aborted mux left sessions registered: {after:?}"
        );
        assert_eq!(
            after.available, 4,
            "aborted mux leaked session permits: {after:?}"
        );
        drop(client);
    }

    fn test_config() -> Arc<XudpConfig> {
        Arc::new(XudpConfig {
            session_idle_timeout: Duration::from_secs(30),
            close_expiry: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        })
    }

    fn start_mux(config: Arc<XudpConfig>) -> (DuplexStream, JoinHandle<Result<(), MuxError>>) {
        start_mux_with_limiter(config, XudpSessionLimiter::default())
    }

    fn start_mux_with_limiter(
        config: Arc<XudpConfig>,
        limiter: XudpSessionLimiter,
    ) -> (DuplexStream, JoinHandle<Result<(), MuxError>>) {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let task = tokio::spawn(handle_mux_stream(server, config, limiter));
        (client, task)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolver_churn_stays_bounded() {
        let config = Arc::new(XudpConfig {
            io_timeout: Duration::from_millis(200),
            session_idle_timeout: Duration::from_secs(30),
            close_expiry: Duration::from_secs(5),
            ..XudpConfig::default()
        });
        let (mut client, task) = start_mux(config);
        let baseline = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let sampler = tokio::spawn(async move {
            let mut peak = baseline;
            for _ in 0..50 {
                sleep(Duration::from_millis(20)).await;
                peak = peak.max(
                    tokio::runtime::Handle::current()
                        .metrics()
                        .num_alive_tasks(),
                );
            }
            peak
        });
        for round in 0..150u16 {
            for lane in 0..64u16 {
                let destination = NetLocation {
                    address: Address::Domain("localhost".to_owned()),
                    port: 20_000 + round * 64 + lane,
                };
                write_frame(
                    &mut client,
                    new_spec(lane, &destination, b"x", Some([0x55; GLOBAL_ID_LEN])),
                )
                .await;
            }
        }
        let peak = sampler.await.expect("sampler panicked");
        let delta = peak.saturating_sub(baseline);
        assert!(
            delta < 100,
            "resolver churn spawned {delta} extra tasks (peak {peak}, baseline {baseline})"
        );
        finish(client, task).await;
    }

    async fn insert_test_session(state: &MuxState, id: u16) {
        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("test session socket must bind"),
        );
        let permit = state
            .limiter
            .try_acquire()
            .expect("test session permit must be available");
        let session = Arc::new(Session::new(
            id,
            None,
            socket,
            SocketFamily::V4,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            Some(permit),
        ));
        let reply_task = spawn_reply_task(
            Arc::clone(&session),
            state.outbound.clone(),
            Arc::clone(&state.queued),
            Arc::clone(&state.table),
            Arc::clone(&state.config),
            state.limiter.clone(),
            state.stream_reply_budget.clone(),
        );
        let replaced = state
            .table
            .lock()
            .expect("test session table")
            .insert(ActiveSession {
                session,
                reply_task: Some(reply_task),
            });
        assert!(replaced.is_none(), "test session id must be unique");
    }

    async fn read_frame(client: &mut DuplexStream, buffer: &mut Vec<u8>) -> Option<OwnedFrame> {
        loop {
            match parse_frame(buffer) {
                Ok(Some((frame, used))) => {
                    let owned = OwnedFrame::from_borrowed(&frame);
                    buffer.drain(..used);
                    return Some(owned);
                }
                Ok(None) => {}
                Err(error) => panic!("server wrote a malformed frame: {error}"),
            }

            let mut chunk = [0u8; 8192];
            let count = timeout(TEST_TIMEOUT, client.read(&mut chunk))
                .await
                .expect("timed out waiting for a frame")
                .expect("stream read failed");
            if count == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..count]);
        }
    }

    async fn write_frame(client: &mut DuplexStream, spec: FrameSpec<'_>) {
        let mut bytes = Vec::new();
        encode_frame(&mut bytes, spec).expect("test frame must encode");
        timeout(TEST_TIMEOUT, client.write_all(&bytes))
            .await
            .expect("timed out writing a frame")
            .expect("stream write failed");
    }

    fn net_location(address: SocketAddr) -> NetLocation {
        match address {
            SocketAddr::V4(address) => NetLocation {
                address: Address::Ipv4(*address.ip()),
                port: address.port(),
            },
            SocketAddr::V6(address) => NetLocation {
                address: Address::Ipv6(*address.ip()),
                port: address.port(),
            },
        }
    }

    fn new_spec<'a>(
        session_id: u16,
        destination: &'a NetLocation,
        payload: &'a [u8],
        global_id: Option<[u8; GLOBAL_ID_LEN]>,
    ) -> FrameSpec<'a> {
        FrameSpec {
            session_id,
            status: SessionStatus::New,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(destination),
            global_id,
            payload,
        }
    }

    fn keep_spec<'a>(
        session_id: u16,
        destination: Option<&'a NetLocation>,
        payload: &'a [u8],
    ) -> FrameSpec<'a> {
        FrameSpec {
            session_id,
            status: SessionStatus::Keep,
            option: FrameOption::DATA,
            network: destination.map(|_| TargetNetwork::Udp),
            destination,
            global_id: None,
            payload,
        }
    }

    struct Echo {
        address: SocketAddr,
        task: JoinHandle<()>,
    }

    impl Drop for Echo {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn try_spawn_echo(bind: SocketAddr) -> Option<Echo> {
        let socket = UdpSocket::bind(bind).await.ok()?;
        let address = socket.local_addr().ok()?;
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_PAYLOAD_LEN];
            while let Ok((len, peer)) = socket.recv_from(&mut buffer).await {
                let _ = socket.send_to(&buffer[..len], peer).await;
            }
        });
        Some(Echo { address, task })
    }

    async fn spawn_echo(bind: SocketAddr) -> Echo {
        try_spawn_echo(bind)
            .await
            .expect("test echo socket must bind")
    }

    async fn spawn_ipv4_echo() -> Echo {
        spawn_echo(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await
    }

    async fn finish(client: DuplexStream, task: JoinHandle<Result<(), MuxError>>) {
        drop(client);
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("mux handler did not finish")
            .expect("mux handler panicked");
        assert!(result.is_ok(), "mux handler failed: {result:?}");
    }

    #[tokio::test]
    async fn full_queue_end_does_not_starve_a_live_session() {
        let echo = spawn_ipv4_echo().await;
        let config = Arc::new(XudpConfig {
            max_queued_replies: 4,
            io_timeout: Duration::from_secs(10),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::new(2);
        let table = Arc::new(Mutex::new(SessionTable::default()));
        let (outbound, mut inbound) = mpsc::channel(config.max_queued_replies);
        let queued = Arc::new(AtomicUsize::new(0));

        // Victim session: closed while the writer queue is full.
        let victim_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("victim socket"),
        );
        let victim_permit = limiter.try_acquire().expect("victim permit");
        let victim = Arc::new(Session::new(
            1,
            None,
            victim_socket,
            SocketFamily::V4,
            echo.address,
            Some(victim_permit),
        ));
        assert!(
            table
                .lock()
                .expect("table")
                .insert(ActiveSession {
                    session: victim,
                    reply_task: None,
                })
                .is_none()
        );

        // Live session: its reply task must keep working after the victim's
        // bounded End and the queue drain.
        let live_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("live socket"),
        );
        let live_permit = limiter.try_acquire().expect("live permit");
        let live = Arc::new(Session::new(
            2,
            None,
            Arc::clone(&live_socket),
            SocketFamily::V4,
            echo.address,
            Some(live_permit),
        ));
        let live_task = spawn_reply_task(
            Arc::clone(&live),
            outbound.clone(),
            Arc::clone(&queued),
            Arc::clone(&table),
            Arc::clone(&config),
            limiter.clone(),
            ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
        );
        assert!(
            table
                .lock()
                .expect("table")
                .insert(ActiveSession {
                    session: live,
                    reply_task: Some(live_task),
                })
                .is_none()
        );

        // Fill the writer queue, then close the victim. Both sessions hold
        // permits; the victim's End must time out and its permit must return.
        for byte in 0..4u8 {
            outbound
                .send(QueuedFrame::new(vec![byte], None, None))
                .await
                .expect("queue slot");
        }
        let state = MuxState {
            config: Arc::clone(&config),
            table: Arc::clone(&table),
            outbound: outbound.clone(),
            queued,
            stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            limiter: limiter.clone(),
            send_tx: test_send_sender(),
            send_inflight: Arc::new(AtomicUsize::new(0)),
        };
        let active = table
            .lock()
            .expect("table")
            .take(1)
            .expect("victim session");
        let started = Instant::now();
        state
            .close_active(active, super::CloseReason::ClientEnd)
            .await
            .expect("victim close");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "close waited for the full io_timeout"
        );
        assert_eq!(limiter.metrics().snapshot().xudp_end_dropped, 1);
        drop(
            limiter
                .try_acquire()
                .expect("victim permit must be reusable"),
        );

        // Drain the queue, then prove the live session can still echo.
        while inbound.try_recv().is_ok() {}
        live_socket
            .send_to(b"live", echo.address)
            .await
            .expect("live send");
        let queued = timeout(TEST_TIMEOUT, inbound.recv())
            .await
            .expect("live reply timed out")
            .expect("live reply channel closed");
        let encoded = queued.encoded();
        let (frame, used) = parse_frame(&encoded)
            .expect("live reply parse")
            .expect("complete live reply");
        assert_eq!(used, encoded.len());
        let reply = OwnedFrame::from_borrowed(&frame);
        assert_eq!(reply.session_id, 2);
        assert_eq!(reply.status, SessionStatus::Keep);
        assert_eq!(reply.payload, b"live");
    }

    #[tokio::test]
    async fn empty_stream_closes_after_the_idle_timeout() {
        let config = Arc::new(XudpConfig {
            session_idle_timeout: Duration::from_millis(200),
            close_expiry: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let (_client, task) = start_mux(config);
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("empty stream did not close")
            .expect("mux handler panicked");
        assert!(result.is_ok(), "empty stream close failed: {result:?}");
    }

    #[tokio::test]
    async fn empty_mux_keepalive_does_not_extend_idle() {
        let config = Arc::new(XudpConfig {
            session_idle_timeout: Duration::from_millis(300),
            close_expiry: Duration::from_secs(1),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let (mut client, task) = start_mux(config);
        let mut bytes = Vec::new();
        encode_frame(
            &mut bytes,
            FrameSpec {
                option: FrameOption::DATA,
                ..FrameSpec::new(1, SessionStatus::KeepAlive)
            },
        )
        .expect("keepalive must encode");

        // Keep transmitting for the whole observation window. If a KeepAlive
        // resets the empty-stream deadline, this writer prevents closure and
        // the timeout below fails; the old test stopped writing first and
        // could not detect that regression.
        let writer = tokio::spawn(async move {
            loop {
                if client.write_all(&bytes).await.is_err() {
                    return;
                }
                sleep(Duration::from_millis(25)).await;
            }
        });

        let result = timeout(Duration::from_secs(2), task).await;
        writer.abort();
        let result = result
            .expect("keepalive-only mux stayed open while KeepAlive continued")
            .expect("mux handler panicked");
        assert!(result.is_ok(), "keepalive-only mux failed: {result:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn mux_read_deadline_is_not_extended_by_sweeps() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            // Longer than the read backstop, so a session stays active and the
            // empty-mux timer cannot close the stream first.
            session_idle_timeout: Duration::from_secs(25 * 3600),
            close_expiry: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::default();
        let (mut client, task) = start_mux_with_limiter(config, limiter.clone());

        // Empty payload: session 1 is created but no datagram is relayed, so
        // only sweep ticks and the read deadline run.
        write_frame(&mut client, new_spec(1, &destination, b"", None)).await;
        // The handler is spawned but not yet polled, and `advance` moves the
        // clock before yielding. Wait for admission so the pinned deadline is
        // armed at 0 h and the New read cannot reset it at 23 h.
        for _ in 0..64 {
            if limiter.metrics().snapshot().xudp_admitted_fresh == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(limiter.metrics().snapshot().xudp_admitted_fresh, 1);

        tokio::time::advance(Duration::from_secs(23 * 3600)).await;
        assert!(
            !task.is_finished(),
            "23 h of peer silence must not close the mux"
        );
        tokio::time::advance(Duration::from_secs(2 * 3600)).await;
        let result = timeout(Duration::from_secs(10), task)
            .await
            .expect("the 24 h read deadline did not fire");
        assert!(
            matches!(
                result,
                Ok(Err(MuxError::Timeout {
                    stage: "mux stream read"
                }))
            ),
            "unexpected mux result: {result:?}"
        );
    }

    #[tokio::test]
    async fn coalesced_new_end_restarts_the_empty_timer() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            session_idle_timeout: Duration::from_millis(500),
            close_expiry: Duration::from_secs(2),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let (mut client, task) = start_mux(config);
        let global_id = Some([0x44; GLOBAL_ID_LEN]);

        let mut batch = Vec::new();
        encode_frame(&mut batch, new_spec(1, &destination, b"", global_id))
            .expect("New must encode");
        encode_frame(&mut batch, FrameSpec::new(1, SessionStatus::End)).expect("End must encode");
        sleep(Duration::from_millis(300)).await;
        timeout(TEST_TIMEOUT, client.write_all(&batch))
            .await
            .expect("coalesced New+End write timed out")
            .expect("coalesced New+End write failed");

        let mut buffer = Vec::new();
        let end = read_frame(&mut client, &mut buffer).await.expect("End ack");
        assert_eq!(end.session_id, 1);
        assert_eq!(end.status, SessionStatus::End);

        // The old deadline was five hundred milliseconds from mux creation.
        // Reattach after it, but before a full idle interval from the End.
        sleep(Duration::from_millis(250)).await;
        write_frame(
            &mut client,
            new_spec(2, &destination, b"reattach", global_id),
        )
        .await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("reattached session must echo");
        assert_eq!(reply.session_id, 2);
        assert_eq!(reply.payload, b"reattach");

        write_frame(&mut client, FrameSpec::new(2, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("second End ack");
        assert_eq!(end.session_id, 2);
        assert_eq!(end.status, SessionStatus::End);

        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("mux did not close after the reattached session ended")
            .expect("mux handler panicked");
        assert!(result.is_ok(), "mux handler failed: {result:?}");
    }

    #[tokio::test]
    async fn short_globalid_flow_does_not_wait_for_retention() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            session_idle_timeout: Duration::from_millis(300),
            close_expiry: Duration::from_secs(30),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::new(1);
        let (mut client, task) = start_mux_with_limiter(config, limiter.clone());
        let mut buffer = Vec::new();

        write_frame(
            &mut client,
            new_spec(7, &destination, b"data", Some([0x33; GLOBAL_ID_LEN])),
        )
        .await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("global-id session must echo");
        assert_eq!(reply.payload, b"data");
        write_frame(&mut client, FrameSpec::new(7, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);

        let started = Instant::now();
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("retained global id kept the empty mux alive")
            .expect("mux handler panicked");
        assert!(result.is_ok(), "mux handler failed: {result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "mux waited {:?} for close_expiry",
            started.elapsed()
        );
        assert_eq!(
            limiter.stats().available,
            1,
            "shutdown must release the retained session permit"
        );
    }

    #[tokio::test]
    async fn slow_mux_does_not_starve_an_unrelated_reply() {
        let echo = spawn_ipv4_echo().await;
        let limiter = XudpSessionLimiter::default();
        let config = Arc::new(XudpConfig {
            max_datagram_size: 8192,
            max_queued_replies: 512,
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let mut stalled = Vec::new();
        for id in 0..10u16 {
            let socket = Arc::new(
                UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                    .await
                    .expect("stalled session socket"),
            );
            let address = socket.local_addr().expect("stalled address");
            let session = Arc::new(Session::new(
                id,
                None,
                Arc::clone(&socket),
                SocketFamily::V4,
                address,
                None,
            ));
            let (outbound, inbound) = mpsc::channel(config.max_queued_replies);
            let task = spawn_reply_task(
                Arc::clone(&session),
                outbound,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(Mutex::new(SessionTable::default())),
                Arc::clone(&config),
                limiter.clone(),
                ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            );
            stalled.push((session, task, inbound, address));
        }

        let sender = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("flood sender");
        let payload = vec![0x5a; 8192];
        for (_, _, _, address) in &stalled {
            for index in 0..1_200 {
                sender
                    .send_to(&payload, *address)
                    .await
                    .expect("flood send");
                if index % 32 == 31 {
                    sleep(Duration::from_millis(1)).await;
                }
            }
        }
        sleep(Duration::from_secs(2)).await;

        let (mut client, mux) = start_mux_with_limiter(Arc::clone(&config), limiter.clone());
        let mut buffer = Vec::new();
        let probe = vec![0x61; 8192];
        write_frame(
            &mut client,
            new_spec(7, &net_location(echo.address), &probe, None),
        )
        .await;
        let reply = timeout(
            Duration::from_millis(700),
            read_frame(&mut client, &mut buffer),
        )
        .await
        .expect("an unrelated mux was starved by the reply budget")
        .expect("unrelated reply failed");
        assert_eq!(reply.session_id, 7);
        assert_eq!(reply.payload, probe);
        assert!(
            limiter.metrics().snapshot().xudp_replies_dropped > 0,
            "the stalled muxes must have hit the per-stream budget"
        );

        finish(client, mux).await;
        for (session, task, inbound, _) in stalled {
            session.stop();
            let _ = timeout(TEST_TIMEOUT, task).await;
            drop(inbound);
        }
    }

    #[tokio::test]
    async fn shutdown_releases_a_session_whose_reply_task_has_not_run() {
        // A spawned task is not polled until the current task yields. If the
        // mux closes in that window, `watch::Sender::send` would drop the stop
        // value and the reply task would keep the socket and global permit
        // forever. Use a one-slot limiter so a leaked permit is visible.
        let limiter = XudpSessionLimiter::new(1);
        let (mut client, task) = start_mux_with_limiter(test_config(), limiter.clone());
        let destination = NetLocation {
            address: Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 9,
        };

        // An empty New binds the socket but performs no send, so the handler
        // can reach EOF without yielding to the reply task.
        write_frame(&mut client, new_spec(1, &destination, b"", None)).await;
        drop(client);

        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("mux handler did not finish")
            .expect("mux handler panicked");
        assert!(result.is_ok(), "mux handler failed: {result:?}");
        sleep(Duration::from_millis(20)).await;
        assert!(
            limiter.try_acquire().is_some(),
            "shutdown leaked the session's global permit"
        );
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_before_reading() {
        let (_client, server) = tokio::io::duplex(1024);
        let config = Arc::new(XudpConfig {
            max_sessions: 0,
            ..XudpConfig::default()
        });
        let result = handle_mux_stream(server, config, XudpSessionLimiter::default()).await;
        assert!(matches!(
            result,
            Err(MuxError::Config(XudpConfigError::MaxSessions))
        ));
    }

    #[tokio::test]
    async fn new_keep_end_round_trip() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(1, &destination, b"hello", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("New must produce an echo reply");
        assert_eq!(reply.session_id, 1);
        assert_eq!(reply.status, SessionStatus::Keep);
        assert_eq!(reply.option, FrameOption::DATA);
        assert_eq!(reply.network, Some(TargetNetwork::Udp));
        assert_eq!(reply.destination, Some(destination.clone()));
        assert_eq!(reply.payload, b"hello");

        // Xray omits the address on later frames; the session remembers it.
        write_frame(&mut client, keep_spec(1, None, b"more")).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("Keep must produce an echo reply");
        assert_eq!(reply.session_id, 1);
        assert_eq!(reply.status, SessionStatus::Keep);
        assert_eq!(reply.destination, Some(destination));
        assert_eq!(reply.payload, b"more");

        write_frame(
            &mut client,
            FrameSpec {
                option: FrameOption::DATA,
                ..FrameSpec::new(1, SessionStatus::End)
            },
        )
        .await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.session_id, 1);
        assert_eq!(end.status, SessionStatus::End);
        assert!(!end.option.has_error());

        finish(client, task).await;
    }

    #[tokio::test]
    async fn global_session_limit_rejects_new() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let limiter = XudpSessionLimiter::new(2);
        let (mut first, first_task) = start_mux_with_limiter(test_config(), limiter.clone());
        let (mut second, second_task) = start_mux_with_limiter(test_config(), limiter.clone());
        let (mut third, third_task) = start_mux_with_limiter(test_config(), limiter);
        let mut buffer = Vec::new();

        write_frame(&mut first, new_spec(1, &destination, b"first", None)).await;
        let reply = read_frame(&mut first, &mut buffer)
            .await
            .expect("the first session must be admitted");
        assert_eq!(reply.payload, b"first");

        write_frame(&mut second, new_spec(2, &destination, b"second", None)).await;
        let reply = read_frame(&mut second, &mut buffer)
            .await
            .expect("the second stream must be admitted");
        assert_eq!(reply.payload, b"second");

        write_frame(&mut third, new_spec(3, &destination, b"third", None)).await;
        let end = read_frame(&mut third, &mut buffer)
            .await
            .expect("the globally rejected New must receive End");
        assert_eq!(end.session_id, 3);
        assert_eq!(end.status, SessionStatus::End);
        assert!(end.option.has_error());

        finish(first, first_task).await;
        finish(second, second_task).await;
        finish(third, third_task).await;
    }

    #[tokio::test]
    async fn burst_of_short_muxes_releases_every_global_permit() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let limiter = XudpSessionLimiter::new(64);

        for _ in 0..16 {
            let (mut client, task) = start_mux_with_limiter(test_config(), limiter.clone());
            let mut buffer = Vec::new();
            write_frame(&mut client, new_spec(1, &destination, b"q", None)).await;
            let reply = read_frame(&mut client, &mut buffer)
                .await
                .expect("short mux must echo");
            assert_eq!(reply.payload, b"q");
            // No End frame: teardown must release the session and its permit.
            finish(client, task).await;
        }

        let stats = limiter.stats();
        assert_eq!(
            (stats.used, stats.active, stats.retained, stats.unattributed),
            (0, 0, 0, 0)
        );
        assert_eq!(stats.available, 64);
        let metrics = limiter.metrics().snapshot();
        assert_eq!(metrics.xudp_admitted_fresh, 16);
        assert_eq!(metrics.xudp_closed_mux, 16);
        assert_eq!(metrics.xudp_rejected_global, 0);
    }

    #[tokio::test]
    async fn one_stream_cannot_take_all_global_sessions() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let limiter = XudpSessionLimiter::new(4);
        let (mut first, first_task) = start_mux_with_limiter(test_config(), limiter.clone());
        let (mut second, second_task) = start_mux_with_limiter(test_config(), limiter);
        let mut buffer = Vec::new();

        for id in 1..=2 {
            write_frame(&mut first, new_spec(id, &destination, b"first", None)).await;
            let reply = read_frame(&mut first, &mut buffer)
                .await
                .expect("first stream must admit half the global slots");
            assert_eq!(reply.session_id, id);
        }
        write_frame(&mut first, new_spec(3, &destination, b"reject", None)).await;
        let end = read_frame(&mut first, &mut buffer)
            .await
            .expect("fair-share rejection must receive End");
        assert_eq!(end.session_id, 3);
        assert_eq!(end.status, SessionStatus::End);
        assert!(end.option.has_error());

        write_frame(&mut second, new_spec(4, &destination, b"second", None)).await;
        let reply = read_frame(&mut second, &mut buffer)
            .await
            .expect("the other stream must still be admitted");
        assert_eq!(reply.session_id, 4);
        assert_eq!(reply.payload, b"second");

        finish(first, first_task).await;
        finish(second, second_task).await;
    }

    #[tokio::test]
    async fn global_id_migrates_to_a_new_session_id() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            session_idle_timeout: Duration::from_secs(30),
            close_expiry: Duration::from_secs(30),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::new(4);
        let (mut client, task) = start_mux_with_limiter(config, limiter.clone());
        let mut buffer = Vec::new();
        let global_id = Some([0x55; GLOBAL_ID_LEN]);

        write_frame(&mut client, new_spec(1, &destination, b"first", global_id)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("first session must echo");
        assert_eq!(reply.payload, b"first");

        write_frame(&mut client, new_spec(2, &destination, b"second", global_id)).await;
        let old_end = read_frame(&mut client, &mut buffer)
            .await
            .expect("migrated session must receive End");
        assert_eq!(old_end.session_id, 1);
        assert_eq!(old_end.status, SessionStatus::End);
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("new session must echo");
        assert_eq!(reply.session_id, 2);
        assert_eq!(reply.payload, b"second");
        assert_eq!(
            limiter.metrics().snapshot().xudp_closed_end,
            1,
            "migration must count the replaced client session"
        );

        write_frame(&mut client, keep_spec(1, None, b"stale")).await;
        let stale_end = read_frame(&mut client, &mut buffer)
            .await
            .expect("old session id must be gone");
        assert_eq!(stale_end.session_id, 1);
        assert_eq!(stale_end.status, SessionStatus::End);

        write_frame(&mut client, keep_spec(2, None, b"still")).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("migrated session must still echo");
        assert_eq!(reply.session_id, 2);
        assert_eq!(reply.payload, b"still");

        write_frame(&mut client, FrameSpec::new(2, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(limiter.metrics().snapshot().xudp_closed_end, 2);
        finish(client, task).await;
    }

    #[tokio::test]
    async fn global_limit_evicts_retained_socket_from_another_stream() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            max_sessions: 2,
            session_idle_timeout: Duration::from_secs(30),
            close_expiry: Duration::from_secs(30),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::new(1);
        let (mut first, first_task) = start_mux_with_limiter(Arc::clone(&config), limiter.clone());
        let (mut second, second_task) = start_mux_with_limiter(config, limiter);
        let mut buffer = Vec::new();

        write_frame(
            &mut first,
            new_spec(1, &destination, b"retained", Some([0x44; GLOBAL_ID_LEN])),
        )
        .await;
        let reply = read_frame(&mut first, &mut buffer)
            .await
            .expect("first session must echo");
        assert_eq!(reply.payload, b"retained");

        write_frame(&mut first, FrameSpec::new(1, SessionStatus::End)).await;
        let end = read_frame(&mut first, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);

        // The first stream's clean GlobalID close retains its socket and holds
        // the only global permit. A new session in another stream must evict
        // that optional state instead of failing the live flow.
        write_frame(&mut second, new_spec(2, &destination, b"fresh", None)).await;
        let reply = read_frame(&mut second, &mut buffer)
            .await
            .expect("a retained socket must not reject a live session");
        assert_eq!(reply.session_id, 2);
        assert_eq!(reply.payload, b"fresh");

        write_frame(&mut second, FrameSpec::new(2, SessionStatus::End)).await;
        let _ = read_frame(&mut second, &mut buffer)
            .await
            .expect("End must be acknowledged");

        finish(first, first_task).await;
        finish(second, second_task).await;
    }

    #[tokio::test]
    async fn global_limit_does_not_evict_an_active_session_in_another_stream() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            max_sessions: 2,
            session_idle_timeout: Duration::from_secs(30),
            close_expiry: Duration::from_secs(30),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::new(1);
        let (mut first, first_task) = start_mux_with_limiter(Arc::clone(&config), limiter.clone());
        let (mut second, second_task) = start_mux_with_limiter(config, limiter);
        let mut buffer = Vec::new();

        write_frame(&mut first, new_spec(1, &destination, b"active", None)).await;
        let reply = read_frame(&mut first, &mut buffer)
            .await
            .expect("first session must echo");
        assert_eq!(reply.payload, b"active");

        write_frame(&mut second, new_spec(2, &destination, b"rejected", None)).await;
        let end = read_frame(&mut second, &mut buffer)
            .await
            .expect("the rejected New must receive End");
        assert_eq!(end.session_id, 2);
        assert_eq!(end.status, SessionStatus::End);
        assert!(end.option.has_error());

        // The active session in the first stream still owns the permit.
        write_frame(&mut first, keep_spec(1, None, b"still")).await;
        let reply = read_frame(&mut first, &mut buffer)
            .await
            .expect("active session must survive global pressure");
        assert_eq!(reply.payload, b"still");

        write_frame(&mut first, FrameSpec::new(1, SessionStatus::End)).await;
        let _ = read_frame(&mut first, &mut buffer)
            .await
            .expect("End must be acknowledged");

        finish(first, first_task).await;
        finish(second, second_task).await;
    }

    #[tokio::test]
    async fn sweep_with_a_full_queue_does_not_stall_the_mux() {
        let config = Arc::new(XudpConfig {
            max_sessions: 16,
            session_idle_timeout: Duration::from_millis(30),
            close_expiry: Duration::from_secs(1),
            max_queued_replies: 1,
            io_timeout: Duration::from_millis(200),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::new(16);
        let table = Arc::new(Mutex::new(SessionTable::default()));
        let (outbound, _inbound) = mpsc::channel(1);
        let state = MuxState {
            config: Arc::clone(&config),
            table: Arc::clone(&table),
            outbound: outbound.clone(),
            queued: Arc::new(AtomicUsize::new(0)),
            stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            limiter: limiter.clone(),
            send_tx: test_send_sender(),
            send_inflight: Arc::new(AtomicUsize::new(0)),
        };
        outbound
            .try_send(QueuedFrame::new(vec![0], None, None))
            .expect("fill the only queue slot");

        for id in 0..10 {
            insert_test_session(&state, id).await;
        }
        sleep(Duration::from_millis(60)).await;

        let started = Instant::now();
        state.sweep().await.expect("full queue must not fail sweep");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "ten idle closes must not each wait for the End deadline"
        );
        assert_eq!(
            table.lock().expect("test session table").total(),
            0,
            "sweep must remove every expired session"
        );
        assert_eq!(
            limiter.metrics().snapshot().xudp_end_dropped,
            10,
            "each idle End should be dropped and counted"
        );
        timeout(TEST_TIMEOUT, async {
            loop {
                let Some(first) = limiter.try_acquire() else {
                    sleep(Duration::from_millis(10)).await;
                    continue;
                };
                if let Some(second) = limiter.try_acquire() {
                    drop((first, second));
                    break;
                }
                drop(first);
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sweep leaked global session permits");
    }

    #[tokio::test]
    async fn new_domain_destination() {
        let v4 = spawn_ipv4_echo().await;
        let port = v4.address.port();
        // A dual-stack localhost fixture: whichever family the resolver picks
        // first echoes on the same port and payload.
        let _v6 = try_spawn_echo(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await;

        let destination = NetLocation {
            address: Address::Domain("localhost".to_owned()),
            port,
        };
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(2, &destination, b"domain", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("domain destination must echo");
        assert_eq!(reply.session_id, 2);
        assert_eq!(reply.status, SessionStatus::Keep);
        assert_eq!(reply.payload, b"domain");
        assert_eq!(reply.network, Some(TargetNetwork::Udp));
        let source = reply.destination.expect("reply source");
        assert_eq!(source.port, port);
        assert!(
            source.address == Address::Ipv4(Ipv4Addr::LOCALHOST)
                || source.address == Address::Ipv6(Ipv6Addr::LOCALHOST)
        );

        write_frame(&mut client, FrameSpec::new(2, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);

        finish(client, task).await;
    }

    #[tokio::test]
    async fn domain_new_and_keep_are_applied_in_order() {
        let echo = spawn_ipv4_echo().await;
        let port = echo.address.port();
        let destination = NetLocation {
            address: Address::Domain("localhost".to_owned()),
            port,
        };
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(9, &destination, b"first", None)).await;
        write_frame(&mut client, keep_spec(9, Some(&destination), b"second")).await;
        let first = read_frame(&mut client, &mut buffer)
            .await
            .expect("New must echo after domain resolution");
        let second = read_frame(&mut client, &mut buffer)
            .await
            .expect("Keep must echo after the same resolution");
        assert_eq!(first.payload, b"first");
        assert_eq!(second.payload, b"second");
        assert_eq!(first.session_id, 9);
        assert_eq!(second.session_id, 9);

        write_frame(&mut client, FrameSpec::new(9, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);
        finish(client, task).await;
    }

    #[tokio::test]
    async fn slow_domain_does_not_block_an_unrelated_session() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let slow = NetLocation {
            address: Address::Domain("slow.test".to_owned()),
            port: echo.address.port(),
        };
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(1, &destination, b"seed", None)).await;
        let seed = read_frame(&mut client, &mut buffer)
            .await
            .expect("seed echo");
        assert_eq!(seed.payload, b"seed");

        let started = Instant::now();
        write_frame(&mut client, new_spec(2, &slow, b"slow", None)).await;
        write_frame(&mut client, keep_spec(1, None, b"probe")).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("unrelated Keep must not wait for the slow domain");
        assert_eq!(reply.session_id, 1);
        assert_eq!(reply.payload, b"probe");
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "slow domain blocked an unrelated session for {:?}",
            started.elapsed()
        );

        write_frame(&mut client, FrameSpec::new(1, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);
        finish(client, task).await;
    }

    #[tokio::test]
    async fn failed_domain_keep_does_not_drop_later_frames() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let bad = NetLocation {
            address: Address::Domain("slow.test".to_owned()),
            port: echo.address.port(),
        };
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(1, &destination, b"seed", None)).await;
        let seed = read_frame(&mut client, &mut buffer)
            .await
            .expect("seed echo");
        assert_eq!(seed.payload, b"seed");

        write_frame(&mut client, keep_spec(1, Some(&bad), b"bad")).await;
        write_frame(&mut client, keep_spec(1, None, b"after")).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("later Keep must survive a failed domain lookup");
        assert_eq!(reply.session_id, 1);
        assert_eq!(reply.payload, b"after");

        write_frame(&mut client, FrameSpec::new(1, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);
        finish(client, task).await;
    }

    #[tokio::test]
    async fn failed_domain_new_does_not_drop_a_replacement_new() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let bad = NetLocation {
            address: Address::Domain("slow.test".to_owned()),
            port: echo.address.port(),
        };
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(1, &bad, b"bad", None)).await;
        write_frame(&mut client, new_spec(1, &destination, b"good", None)).await;
        let first = read_frame(&mut client, &mut buffer)
            .await
            .expect("failed New must produce an End");
        assert_eq!(first.status, SessionStatus::End);
        assert!(first.option.has_error());
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("replacement New must still be processed");
        assert_eq!(reply.session_id, 1);
        assert_eq!(reply.payload, b"good");

        write_frame(&mut client, FrameSpec::new(1, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);
        finish(client, task).await;
    }

    #[tokio::test]
    async fn stale_resolution_does_not_consume_same_id_replacement() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let slow = NetLocation {
            address: Address::Domain("slow.test".to_owned()),
            port: echo.address.port(),
        };
        let local = NetLocation {
            address: Address::Domain("localhost".to_owned()),
            port: echo.address.port(),
        };
        let global = [9_u8; GLOBAL_ID_LEN];
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(1, &slow, b"old", Some(global))).await;
        write_frame(&mut client, new_spec(2, &destination, b"new", Some(global))).await;
        let newer = read_frame(&mut client, &mut buffer)
            .await
            .expect("newer attachment echo");
        assert_eq!(newer.session_id, 2);

        // Reuse id 1 with a different GlobalID while the first lookup is still
        // in flight. The stale slow.test failure must not consume this queue.
        write_frame(&mut client, new_spec(1, &local, b"replacement", None)).await;
        let replacement = read_frame(&mut client, &mut buffer)
            .await
            .expect("replacement New must not be consumed by stale result");
        assert_eq!(replacement.session_id, 1);
        assert_eq!(replacement.payload, b"replacement");

        sleep(Duration::from_millis(650)).await;
        write_frame(&mut client, keep_spec(1, None, b"alive")).await;
        let alive = read_frame(&mut client, &mut buffer)
            .await
            .expect("replacement session must survive stale completion");
        assert_eq!(alive.session_id, 1);
        assert_eq!(alive.payload, b"alive");

        write_frame(&mut client, FrameSpec::new(1, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);
        finish(client, task).await;
    }

    #[tokio::test]
    async fn newer_global_id_attachment_removes_a_queued_older_new() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let slow = NetLocation {
            address: Address::Domain("slow.test".to_owned()),
            port: echo.address.port(),
        };
        let global = [11_u8; GLOBAL_ID_LEN];
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(1, &destination, b"seed", None)).await;
        let seed = read_frame(&mut client, &mut buffer)
            .await
            .expect("seed echo");
        assert_eq!(seed.payload, b"seed");

        write_frame(&mut client, keep_spec(1, Some(&slow), b"pending")).await;
        write_frame(&mut client, FrameSpec::new(1, SessionStatus::End)).await;
        write_frame(&mut client, new_spec(1, &destination, b"old", Some(global))).await;
        write_frame(&mut client, new_spec(2, &destination, b"new", Some(global))).await;
        let mut newer = None;
        for _ in 0..4 {
            let frame = read_frame(&mut client, &mut buffer)
                .await
                .expect("reply while waiting for the newer attachment");
            if frame.session_id == 2 && frame.payload == b"new" {
                newer = Some(frame);
                break;
            }
        }
        assert!(
            newer.is_some(),
            "newer GlobalID attachment did not echo before the old reply drained"
        );

        sleep(Duration::from_millis(650)).await;
        write_frame(&mut client, keep_spec(2, None, b"alive")).await;
        let mut alive = None;
        for _ in 0..4 {
            let frame = read_frame(&mut client, &mut buffer)
                .await
                .expect("reply while draining old attachment data");
            if frame.session_id == 2 && frame.payload == b"alive" {
                alive = Some(frame);
                break;
            }
        }
        assert!(
            alive.is_some(),
            "newer attachment must survive the old queued New"
        );

        write_frame(&mut client, FrameSpec::new(2, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);
        finish(client, task).await;
    }

    #[tokio::test]
    async fn canceled_lookup_owner_does_not_reject_the_suffix() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let slow = NetLocation {
            address: Address::Domain("slow.test".to_owned()),
            port: echo.address.port(),
        };
        let original = [13_u8; GLOBAL_ID_LEN];
        let replacement = [14_u8; GLOBAL_ID_LEN];
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(1, &slow, b"slow", Some(original))).await;
        write_frame(
            &mut client,
            new_spec(1, &destination, b"suffix", Some(replacement)),
        )
        .await;
        write_frame(
            &mut client,
            new_spec(2, &destination, b"newer", Some(original)),
        )
        .await;

        // The newer G attachment is accepted immediately.
        let mut newer = None;
        for _ in 0..4 {
            let frame = read_frame(&mut client, &mut buffer)
                .await
                .expect("reply while draining the newer attachment");
            if frame.session_id == 2 && frame.payload == b"newer" {
                newer = Some(frame);
                break;
            }
        }
        assert!(newer.is_some(), "newer G attachment must be accepted");

        // After the stale slow lookup fails, the H New suffix must run.
        sleep(Duration::from_millis(650)).await;
        write_frame(&mut client, keep_spec(1, None, b"alive")).await;
        let mut alive = None;
        for _ in 0..5 {
            let frame = read_frame(&mut client, &mut buffer)
                .await
                .expect("reply while waiting for the suffix New");
            if frame.session_id == 1 && frame.payload == b"alive" {
                alive = Some(frame);
                break;
            }
        }
        assert!(
            alive.is_some(),
            "canceled lookup owner must not reject the H New suffix"
        );

        write_frame(&mut client, FrameSpec::new(1, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);
        finish(client, task).await;
    }

    #[tokio::test]
    async fn newer_global_id_attachment_supersedes_pending_domain_new() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let slow = NetLocation {
            address: Address::Domain("slow-ok.test".to_owned()),
            port: echo.address.port(),
        };
        let global = [7_u8; GLOBAL_ID_LEN];
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(1, &slow, b"old", Some(global))).await;
        write_frame(&mut client, new_spec(2, &destination, b"new", Some(global))).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("newer GlobalID attachment must echo");
        assert_eq!(reply.session_id, 2);
        assert_eq!(reply.payload, b"new");

        sleep(Duration::from_millis(650)).await;
        write_frame(&mut client, keep_spec(2, None, b"still")).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("newer attachment must remain active");
        assert_eq!(reply.session_id, 2);
        assert_eq!(reply.payload, b"still");

        write_frame(&mut client, FrameSpec::new(2, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);
        finish(client, task).await;
    }

    #[tokio::test]
    async fn domain_tcp_new_is_rejected_without_becoming_udp() {
        let echo = spawn_ipv4_echo().await;
        let destination = NetLocation {
            address: Address::Domain("localhost".to_owned()),
            port: echo.address.port(),
        };
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(
            &mut client,
            FrameSpec {
                session_id: 4,
                status: SessionStatus::New,
                option: FrameOption::DATA,
                network: Some(TargetNetwork::Tcp),
                destination: Some(&destination),
                global_id: None,
                payload: b"tcp",
            },
        )
        .await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("TCP domain New must be rejected");
        assert_eq!(end.session_id, 4);
        assert_eq!(end.status, SessionStatus::End);
        assert!(end.option.has_error());

        finish(client, task).await;
    }

    #[tokio::test]
    async fn new_ipv6_destination() {
        let Some(echo) = try_spawn_echo(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).await else {
            // Loops without IPv6 support skip the loopback case; IPv4 and the
            // codec still cover the frame path.
            return;
        };
        let destination = net_location(echo.address);
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(3, &destination, b"v6", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("IPv6 destination must echo");
        assert_eq!(reply.session_id, 3);
        assert_eq!(reply.payload, b"v6");
        assert_eq!(reply.destination, Some(destination));

        write_frame(&mut client, FrameSpec::new(3, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);

        finish(client, task).await;
    }

    #[tokio::test]
    async fn multiple_destinations_from_one_session() {
        let first = spawn_ipv4_echo().await;
        let second = spawn_ipv4_echo().await;
        let first_destination = net_location(first.address);
        let second_destination = net_location(second.address);
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(4, &first_destination, b"one", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("first destination must echo");
        assert_eq!(reply.payload, b"one");
        assert_eq!(reply.destination, Some(first_destination.clone()));

        write_frame(&mut client, keep_spec(4, Some(&second_destination), b"two")).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("second destination must echo");
        assert_eq!(reply.payload, b"two");
        assert_eq!(reply.destination, Some(second_destination.clone()));

        // Without an address the session reuses its most recent destination.
        write_frame(&mut client, keep_spec(4, None, b"three")).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("last destination must echo");
        assert_eq!(reply.payload, b"three");
        assert_eq!(reply.destination, Some(second_destination));

        write_frame(&mut client, FrameSpec::new(4, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);

        finish(client, task).await;
    }

    #[tokio::test]
    async fn replies_carry_the_actual_source_address() {
        // The destination socket never answers. A different socket sends the
        // reply, so the forwarded source must be the responder, not the
        // original destination.
        let destination = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("destination socket");
        let responder = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("responder socket");
        let destination_address = destination.local_addr().expect("destination address");
        let responder_address = responder.local_addr().expect("responder address");
        let responder_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (len, peer) = destination
                .recv_from(&mut buffer)
                .await
                .expect("destination receive");
            responder
                .send_to(&buffer[..len], peer)
                .await
                .expect("responder send");
        });

        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(
            &mut client,
            new_spec(5, &net_location(destination_address), b"source", None),
        )
        .await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("responder must reach the client");
        assert_eq!(reply.payload, b"source");
        assert_eq!(reply.destination, Some(net_location(responder_address)));

        write_frame(&mut client, FrameSpec::new(5, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);

        responder_task.await.expect("responder task");
        finish(client, task).await;
    }

    #[tokio::test]
    async fn unknown_keep_gets_a_clean_end() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, keep_spec(7, None, b"orphan")).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("unknown Keep must get End");
        assert_eq!(end.session_id, 7);
        assert_eq!(end.status, SessionStatus::End);
        assert!(!end.option.has_error());

        // The stream remains usable for unrelated sessions.
        write_frame(&mut client, new_spec(8, &destination, b"alive", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("new session after unknown Keep must work");
        assert_eq!(reply.session_id, 8);
        assert_eq!(reply.payload, b"alive");

        write_frame(&mut client, FrameSpec::new(8, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");

        finish(client, task).await;
    }

    #[tokio::test]
    async fn keep_alive_is_accepted_and_discarded() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(9, &destination, b"first", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("echo reply");
        assert_eq!(reply.payload, b"first");

        write_frame(
            &mut client,
            FrameSpec {
                option: FrameOption::DATA,
                ..FrameSpec::new(9, SessionStatus::KeepAlive)
            },
        )
        .await;
        // No reply is expected for KeepAlive; a following Keep proves the
        // stream and session are still healthy.
        write_frame(&mut client, keep_spec(9, None, b"second")).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("Keep after KeepAlive must echo");
        assert_eq!(reply.payload, b"second");

        write_frame(&mut client, FrameSpec::new(9, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");

        finish(client, task).await;
    }

    #[tokio::test]
    async fn malformed_frame_closes_the_stream() {
        let (mut client, task) = start_mux(test_config());
        // Metadata length 3 is below the four-byte minimum.
        timeout(TEST_TIMEOUT, client.write_all(&[0x00, 0x03]))
            .await
            .expect("write")
            .expect("write failed");
        drop(client);
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("mux handler did not finish")
            .expect("mux handler panicked");
        assert!(matches!(
            result,
            Err(MuxError::Frame(XudpError::InvalidMetadataLength(3)))
        ));
    }

    #[tokio::test]
    async fn unknown_status_closes_the_stream() {
        let (mut client, task) = start_mux(test_config());
        let frame = [0x00, 0x04, 0x00, 0x01, 0x05, 0x00];
        timeout(TEST_TIMEOUT, client.write_all(&frame))
            .await
            .expect("write")
            .expect("write failed");
        drop(client);
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("mux handler did not finish")
            .expect("mux handler panicked");
        assert!(matches!(
            result,
            Err(MuxError::Frame(XudpError::UnknownStatus(0x05)))
        ));
    }

    #[tokio::test]
    async fn truncated_frame_at_eof_is_reported() {
        let (mut client, task) = start_mux(test_config());
        // A four-byte prefix of a six-byte End frame.
        timeout(TEST_TIMEOUT, client.write_all(&[0x00, 0x04, 0x00, 0x01]))
            .await
            .expect("write")
            .expect("write failed");
        drop(client);
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("mux handler did not finish")
            .expect("mux handler panicked");
        assert!(matches!(
            result,
            Err(MuxError::TruncatedFrame { buffered: 4 })
        ));
    }

    #[tokio::test]
    async fn sweep_releases_sessions_when_writer_is_closed() {
        let config = Arc::new(XudpConfig {
            max_sessions: 2,
            session_idle_timeout: Duration::from_millis(30),
            close_expiry: Duration::from_secs(1),
            max_queued_replies: 4,
            io_timeout: Duration::from_millis(200),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::new(2);
        let table = Arc::new(Mutex::new(SessionTable::default()));
        let (outbound, inbound) = mpsc::channel(4);
        drop(inbound);
        let state = MuxState {
            config: Arc::clone(&config),
            table: Arc::clone(&table),
            outbound: outbound.clone(),
            queued: Arc::new(AtomicUsize::new(0)),
            stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            limiter: limiter.clone(),
            send_tx: test_send_sender(),
            send_inflight: Arc::new(AtomicUsize::new(0)),
        };

        insert_test_session(&state, 21).await;
        insert_test_session(&state, 22).await;
        sleep(Duration::from_millis(60)).await;

        // Idle End is best-effort: a closed writer must not turn a sweep into
        // a fatal read-loop error, because the session is already being
        // removed and its permits must still be released.
        state
            .sweep()
            .await
            .expect("a closed writer must not fail the idle sweep");
        assert_eq!(
            table.lock().expect("test session table").total(),
            0,
            "sweep must remove every expired session"
        );
        assert_eq!(
            limiter.metrics().snapshot().xudp_end_dropped,
            2,
            "both idle End frames should be counted as dropped"
        );

        timeout(TEST_TIMEOUT, async {
            loop {
                let Some(first) = limiter.try_acquire() else {
                    sleep(Duration::from_millis(10)).await;
                    continue;
                };
                if let Some(second) = limiter.try_acquire() {
                    drop((first, second));
                    break;
                }
                drop(first);
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sweep leaked a global session permit");
    }

    #[tokio::test]
    async fn sweep_queues_one_end_for_every_idle_session() {
        let config = Arc::new(XudpConfig {
            max_sessions: 2,
            session_idle_timeout: Duration::from_millis(30),
            close_expiry: Duration::from_secs(1),
            max_queued_replies: 4,
            io_timeout: Duration::from_millis(200),
            ..XudpConfig::default()
        });
        let limiter = XudpSessionLimiter::new(2);
        let table = Arc::new(Mutex::new(SessionTable::default()));
        let (outbound, mut inbound) = mpsc::channel(8);
        let state = MuxState {
            config: Arc::clone(&config),
            table: Arc::clone(&table),
            outbound: outbound.clone(),
            queued: Arc::new(AtomicUsize::new(0)),
            stream_reply_budget: ReplyQueueBudget::new(DEFAULT_STREAM_REPLY_BUDGET),
            limiter: limiter.clone(),
            send_tx: test_send_sender(),
            send_inflight: Arc::new(AtomicUsize::new(0)),
        };

        insert_test_session(&state, 31).await;
        insert_test_session(&state, 32).await;
        sleep(Duration::from_millis(60)).await;

        state.sweep().await.expect("healthy sweep must succeed");

        let mut ended = Vec::new();
        for _ in 0..2 {
            let queued = timeout(TEST_TIMEOUT, inbound.recv())
                .await
                .expect("sweep did not queue both End frames")
                .expect("sweep closed the outbound queue");
            let encoded = queued.encoded();
            let (frame, used) = parse_frame(&encoded)
                .expect("sweep queued a malformed frame")
                .expect("sweep queued an incomplete frame");
            assert_eq!(used, encoded.len());
            assert_eq!(frame.status, SessionStatus::End);
            ended.push(frame.session_id);
        }
        ended.sort_unstable();
        assert_eq!(ended, [31, 32]);
        assert!(
            inbound.try_recv().is_err(),
            "sweep must queue exactly one End per expired session"
        );
        assert_eq!(
            table.lock().expect("test session table").total(),
            0,
            "healthy sweep must remove every expired session"
        );
    }

    #[tokio::test]
    async fn keepalive_does_not_extend_session_idle() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            session_idle_timeout: Duration::from_millis(300),
            close_expiry: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let (mut client, task) = start_mux(config);
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(21, &destination, b"before", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("echo reply before expiry");
        assert_eq!(reply.payload, b"before");

        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            write_frame(
                &mut client,
                FrameSpec {
                    option: FrameOption::DATA,
                    ..FrameSpec::new(21, SessionStatus::KeepAlive)
                },
            )
            .await;
            write_frame(&mut client, FrameSpec::new(21, SessionStatus::Keep)).await;
        }

        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("empty keepalives must not refresh idle");
        assert_eq!(end.session_id, 21);
        assert_eq!(end.status, SessionStatus::End);
        finish(client, task).await;
    }

    #[tokio::test]
    async fn idle_session_expires_with_a_clean_end() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            session_idle_timeout: Duration::from_millis(500),
            close_expiry: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let (mut client, task) = start_mux(config);
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(10, &destination, b"before", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("echo reply before expiry");
        assert_eq!(reply.payload, b"before");

        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("expiry must send End");
        assert_eq!(end.session_id, 10);
        assert_eq!(end.status, SessionStatus::End);
        assert!(!end.option.has_error());

        // The session is gone, so a later Keep is unknown and gets a clean End.
        write_frame(&mut client, keep_spec(10, None, b"late")).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("late Keep must get End");
        assert_eq!(end.status, SessionStatus::End);
        assert!(!end.option.has_error());

        finish(client, task).await;
    }

    #[tokio::test]
    async fn max_sessions_limit_rejects_extra_new() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            max_sessions: 1,
            session_idle_timeout: Duration::from_secs(30),
            close_expiry: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let (mut client, task) = start_mux(config);
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(11, &destination, b"one", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("first session must work");
        assert_eq!(reply.payload, b"one");

        write_frame(&mut client, new_spec(12, &destination, b"two", None)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("session limit must send End");
        assert_eq!(end.session_id, 12);
        assert_eq!(end.status, SessionStatus::End);
        assert!(end.option.has_error());

        // The rejected New must not disturb the live session.
        write_frame(&mut client, keep_spec(11, None, b"still")).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("live session must still work");
        assert_eq!(reply.session_id, 11);
        assert_eq!(reply.payload, b"still");

        write_frame(&mut client, FrameSpec::new(11, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);

        // The slot is free again.
        write_frame(&mut client, new_spec(12, &destination, b"retry", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("slot reuse must work");
        assert_eq!(reply.session_id, 12);
        assert_eq!(reply.payload, b"retry");

        write_frame(&mut client, FrameSpec::new(12, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");

        finish(client, task).await;
    }

    #[tokio::test]
    async fn dense_frames_are_parsed_across_reads() {
        let (mut client, task) = start_mux(test_config());
        let mut frames = Vec::with_capacity(1365 * 6 + 6);
        for id in 0..1365 {
            encode_frame(&mut frames, FrameSpec::new(id, SessionStatus::KeepAlive))
                .expect("KeepAlive must encode");
        }
        timeout(TEST_TIMEOUT, client.write_all(&frames))
            .await
            .expect("write")
            .expect("write failed");

        // A second write forces the next read to start from a fully consumed
        // buffer instead of an incomplete tail.
        let mut extra = Vec::new();
        encode_frame(&mut extra, FrameSpec::new(65_535, SessionStatus::KeepAlive))
            .expect("KeepAlive must encode");
        timeout(TEST_TIMEOUT, client.write_all(&extra))
            .await
            .expect("write")
            .expect("write failed");

        drop(client);
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("mux handler did not finish")
            .expect("mux handler panicked");
        assert!(result.is_ok(), "dense frames failed: {result:?}");
    }

    #[tokio::test]
    async fn dense_frames_keep_an_incomplete_tail() {
        let (mut client, task) = start_mux(test_config());
        let mut frames = Vec::with_capacity(1360 * 6 + 4);
        for id in 0..1360 {
            encode_frame(&mut frames, FrameSpec::new(id, SessionStatus::KeepAlive))
                .expect("KeepAlive must encode");
        }
        // Metadata prefix plus two bytes of the session id: a genuinely
        // incomplete frame that must survive the single compaction.
        frames.extend_from_slice(&[0x00, 0x04, 0x00, 0x07]);
        timeout(TEST_TIMEOUT, client.write_all(&frames))
            .await
            .expect("write")
            .expect("write failed");
        drop(client);

        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("mux handler did not finish")
            .expect("mux handler panicked");
        assert!(
            matches!(result, Err(MuxError::TruncatedFrame { buffered: 4 })),
            "dense frame tail was not preserved: {result:?}"
        );
    }

    #[tokio::test]
    async fn back_to_back_frames_and_maximum_payload() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();
        let payload = vec![0x5a; MAX_PAYLOAD_LEN];

        // Two frames in one write, each at the 8192-byte payload boundary.
        let mut frames = Vec::new();
        encode_frame(&mut frames, new_spec(13, &destination, &payload, None))
            .expect("New must encode");
        encode_frame(&mut frames, keep_spec(13, None, &payload)).expect("Keep must encode");
        timeout(TEST_TIMEOUT, client.write_all(&frames))
            .await
            .expect("write")
            .expect("write failed");

        for _ in 0..2 {
            let reply = read_frame(&mut client, &mut buffer)
                .await
                .expect("coalesced frame must get a reply");
            assert_eq!(reply.session_id, 13);
            assert_eq!(reply.status, SessionStatus::Keep);
            assert_eq!(reply.payload.len(), MAX_PAYLOAD_LEN);
            assert!(reply.payload.iter().all(|&byte| byte == 0x5a));
        }

        write_frame(&mut client, FrameSpec::new(13, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);

        finish(client, task).await;
    }

    #[tokio::test]
    async fn frame_split_across_reads_is_reassembled() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        let mut frame = Vec::new();
        encode_frame(&mut frame, new_spec(14, &destination, b"split", None))
            .expect("New must encode");
        for byte in &frame {
            timeout(TEST_TIMEOUT, client.write_all(std::slice::from_ref(byte)))
                .await
                .expect("write")
                .expect("write failed");
            tokio::task::yield_now().await;
        }

        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("split frame must echo");
        assert_eq!(reply.payload, b"split");

        write_frame(&mut client, FrameSpec::new(14, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");

        finish(client, task).await;
    }

    #[tokio::test]
    async fn datagram_above_the_configured_limit_is_rejected() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            max_datagram_size: 4,
            session_idle_timeout: Duration::from_secs(30),
            close_expiry: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let (mut client, task) = start_mux(config);
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(15, &destination, b"hello", None)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("oversize datagram must send End");
        assert_eq!(end.session_id, 15);
        assert_eq!(end.status, SessionStatus::End);
        assert!(end.option.has_error());

        finish(client, task).await;
    }

    #[tokio::test]
    async fn replied_frames_are_serialized_across_sessions() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();
        let payloads: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];

        let mut frames = Vec::new();
        for (index, payload) in payloads.iter().enumerate() {
            let session_id = 20 + u16::try_from(index).expect("small index");
            encode_frame(
                &mut frames,
                new_spec(session_id, &destination, payload, None),
            )
            .expect("New must encode");
        }
        timeout(TEST_TIMEOUT, client.write_all(&frames))
            .await
            .expect("write")
            .expect("write failed");

        let mut seen = Vec::new();
        for _ in 0..payloads.len() {
            let reply = read_frame(&mut client, &mut buffer)
                .await
                .expect("each session must get a reply");
            assert_eq!(reply.status, SessionStatus::Keep);
            assert!(reply.session_id >= 20 && reply.session_id < 24);
            seen.push(reply.payload);
        }
        seen.sort();
        let mut expected: Vec<Vec<u8>> = payloads.iter().map(|payload| payload.to_vec()).collect();
        expected.sort();
        assert_eq!(seen, expected);

        for session_id in 20..24 {
            write_frame(&mut client, FrameSpec::new(session_id, SessionStatus::End)).await;
        }
        for _ in 20..24 {
            let end = read_frame(&mut client, &mut buffer)
                .await
                .expect("End must be acknowledged");
            assert_eq!(end.status, SessionStatus::End);
        }

        finish(client, task).await;
    }

    #[tokio::test]
    async fn retained_socket_is_evicted_before_a_new_session_is_rejected() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let config = Arc::new(XudpConfig {
            max_sessions: 1,
            session_idle_timeout: Duration::from_secs(30),
            close_expiry: Duration::from_secs(30),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let (mut client, task) = start_mux(config);
        let mut buffer = Vec::new();

        write_frame(
            &mut client,
            new_spec(32, &destination, b"retained", Some([0x44; GLOBAL_ID_LEN])),
        )
        .await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("first session must echo");
        assert_eq!(reply.payload, b"retained");

        write_frame(&mut client, FrameSpec::new(32, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);
        // The clean close retains the GlobalID socket and uses the only slot.

        write_frame(&mut client, new_spec(33, &destination, b"fresh", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("a retained socket must not reject a live session");
        assert_eq!(reply.session_id, 33);
        assert_eq!(reply.payload, b"fresh");

        write_frame(&mut client, FrameSpec::new(33, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");

        finish(client, task).await;
    }

    #[tokio::test]
    async fn new_send_failure_reports_an_error_end_and_keeps_the_stream() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        // An unconnected UDP socket cannot send to the limited broadcast
        // address without SO_BROADCAST, so the first datagram fails.
        let unroutable = NetLocation {
            address: Address::Ipv4(Ipv4Addr::BROADCAST),
            port: 9,
        };
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(17, &unroutable, b"drop", None)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("failed New must send End");
        assert_eq!(end.session_id, 17);
        assert_eq!(end.status, SessionStatus::End);
        assert!(end.option.has_error());

        // A per-session failure must not close the stream.
        write_frame(&mut client, new_spec(18, &destination, b"works", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("unrelated New must still work");
        assert_eq!(reply.session_id, 18);
        assert_eq!(reply.payload, b"works");

        write_frame(&mut client, FrameSpec::new(18, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");

        finish(client, task).await;
    }

    #[tokio::test]
    async fn keep_with_another_family_is_dropped_without_closing_the_session() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let other_family = NetLocation {
            address: Address::Ipv6(Ipv6Addr::LOCALHOST),
            port: echo.address.port(),
        };
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(&mut client, new_spec(19, &destination, b"v4", None)).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("IPv4 session must echo");
        assert_eq!(reply.payload, b"v4");

        // The IPv6 destination cannot use the IPv4 socket; it is discarded
        // and produces no frame.
        write_frame(&mut client, keep_spec(19, Some(&other_family), b"v6")).await;
        write_frame(&mut client, keep_spec(19, None, b"still-v4")).await;

        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("the session must survive a family-mismatched Keep");
        assert_eq!(reply.payload, b"still-v4");
        assert_eq!(reply.destination, Some(destination));

        write_frame(&mut client, FrameSpec::new(19, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");

        finish(client, task).await;
    }

    #[tokio::test]
    async fn oversize_reply_is_dropped_without_losing_the_session() {
        let destination = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("destination socket");
        let destination_address = destination.local_addr().expect("destination address");
        let responder_task = tokio::spawn(async move {
            let mut buffer = [0u8; 16];
            let (_, peer) = destination
                .recv_from(&mut buffer)
                .await
                .expect("destination receive");
            let oversize = vec![0x5a; MAX_PAYLOAD_LEN + 1];
            let _ = destination.send_to(&oversize, peer).await;
            let _ = destination.send_to(b"ok", peer).await;
        });

        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(
            &mut client,
            new_spec(16, &net_location(destination_address), b"go", None),
        )
        .await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("normal reply must survive a dropped oversize datagram");
        assert_eq!(reply.payload, b"ok");

        write_frame(&mut client, FrameSpec::new(16, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");

        responder_task.await.expect("responder task");
        finish(client, task).await;
    }

    #[tokio::test]
    async fn global_id_reattaches_within_close_expiry() {
        // The responder prepends the server's observed source port, so the
        // test can see whether the retained socket was reused.
        let responder = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("responder socket");
        let responder_address = responder.local_addr().expect("responder address");
        let responder_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            while let Ok((len, peer)) = responder.recv_from(&mut buffer).await {
                let mut reply = peer.port().to_be_bytes().to_vec();
                reply.extend_from_slice(&buffer[..len]);
                let _ = responder.send_to(&reply, peer).await;
            }
        });

        let destination = net_location(responder_address);
        let config = Arc::new(XudpConfig {
            session_idle_timeout: Duration::from_secs(30),
            close_expiry: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        });
        let (mut client, task) = start_mux(config);
        let mut buffer = Vec::new();
        let global_id = Some([0x11; GLOBAL_ID_LEN]);

        write_frame(&mut client, new_spec(30, &destination, b"first", global_id)).await;
        let first = read_frame(&mut client, &mut buffer)
            .await
            .expect("first session must echo");
        assert_eq!(first.payload.len(), 2 + 5);
        let first_port = u16::from_be_bytes([first.payload[0], first.payload[1]]);

        write_frame(&mut client, FrameSpec::new(30, SessionStatus::End)).await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");
        assert_eq!(end.status, SessionStatus::End);

        write_frame(
            &mut client,
            new_spec(31, &destination, b"second", global_id),
        )
        .await;
        let second = read_frame(&mut client, &mut buffer)
            .await
            .expect("reattached session must echo");
        assert_eq!(second.payload.len(), 2 + 6);
        let second_port = u16::from_be_bytes([second.payload[0], second.payload[1]]);
        assert_eq!(first_port, second_port, "GlobalID must reuse the socket");

        write_frame(&mut client, FrameSpec::new(31, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");

        responder_task.abort();
        finish(client, task).await;
    }

    #[tokio::test]
    async fn duplicate_session_id_with_another_global_id_is_rejected() {
        let echo = spawn_ipv4_echo().await;
        let destination = net_location(echo.address);
        let (mut client, task) = start_mux(test_config());
        let mut buffer = Vec::new();

        write_frame(
            &mut client,
            new_spec(40, &destination, b"original", Some([0x22; GLOBAL_ID_LEN])),
        )
        .await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("first session must echo");
        assert_eq!(reply.payload, b"original");

        write_frame(
            &mut client,
            new_spec(40, &destination, b"intruder", Some([0x33; GLOBAL_ID_LEN])),
        )
        .await;
        let end = read_frame(&mut client, &mut buffer)
            .await
            .expect("conflicting duplicate must get End");
        assert_eq!(end.session_id, 40);
        assert_eq!(end.status, SessionStatus::End);
        assert!(end.option.has_error());

        // The original session is untouched.
        write_frame(&mut client, keep_spec(40, None, b"still-original")).await;
        let reply = read_frame(&mut client, &mut buffer)
            .await
            .expect("original session must survive");
        assert_eq!(reply.payload, b"still-original");

        write_frame(&mut client, FrameSpec::new(40, SessionStatus::End)).await;
        let _ = read_frame(&mut client, &mut buffer)
            .await
            .expect("End must be acknowledged");

        finish(client, task).await;
    }
}
