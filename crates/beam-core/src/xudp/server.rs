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

use std::io;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior, interval, timeout};

use super::session::{
    ActiveSession, END_ENQUEUE_TIMEOUT, ExpiringSession, QueuedFrame, Session, SessionTable,
    SocketFamily, XudpConfig, XudpConfigError, XudpSessionLimiter, encode_end_frame,
    resolve_destination, spawn_reply_task,
};
use crate::xudp::frame::{
    self, Frame, GLOBAL_ID_LEN, MAX_METADATA_LEN, MAX_PAYLOAD_LEN, METADATA_PREFIX_LEN,
    SessionStatus, TargetNetwork, XudpError,
};

/// Largest valid frame: metadata prefix, metadata, payload prefix, payload.
const PAYLOAD_PREFIX_LEN: usize = 2;
const MAX_FRAME_LEN: usize =
    METADATA_PREFIX_LEN + MAX_METADATA_LEN + PAYLOAD_PREFIX_LEN + MAX_PAYLOAD_LEN;

/// One read from the mux stream. Two frames can arrive coalesced.
const READ_CHUNK_LEN: usize = 8192;

/// Hard bound for the reassembly buffer: one full frame plus one read.
const MAX_BUFFERED_LEN: usize = MAX_FRAME_LEN + READ_CHUNK_LEN;

/// Upper bound on one domain resolution inside the mux read loop.
///
/// The read loop is shared by every flow on the mux. The generic I/O timeout
/// is 10 s in production, which is long enough for one slow resolver to stall
/// DNS and QUIC frames for unrelated sessions.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Upper bound on mux read inactivity.
///
/// Sessions expire independently, so this is only a backstop for a stream
/// whose peer never sends another frame. A stream with no sessions is closed
/// sooner by the idle sweeper. Stock Xray keeps an active mux stream alive
/// indefinitely; this bound is a deliberate resource-safety deviation.
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// Bound on waiting for tasks to stop during stream shutdown.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

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
    limiter: XudpSessionLimiter,
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
    let (writer_failed, mut writer_failed_rx) = watch::channel(false);
    let mut writer_task = tokio::spawn(write_loop(
        writer,
        inbound,
        config.io_timeout,
        writer_failed,
    ));

    let table = Arc::new(Mutex::new(SessionTable::default()));
    limiter.register_table(&table);
    let state = MuxState {
        config: config.clone(),
        table: Arc::clone(&table),
        outbound,
        limiter,
    };

    let result = read_loop(&mut reader, &state, &mut writer_failed_rx).await;

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
    if timeout(SHUTDOWN_TIMEOUT, &mut writer_task).await.is_err() {
        writer_task.abort();
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
        batch.extend_from_slice(&frame.bytes);
        frames.push(frame);

        while frames.len() < MAX_WRITE_BATCH_FRAMES {
            match inbound.try_recv() {
                Ok(frame) => {
                    batch.extend_from_slice(&frame.bytes);
                    frames.push(frame);
                    if batch.len() >= MAX_WRITE_BATCH_BYTES {
                        break;
                    }
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
) -> Result<(), MuxError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(MAX_FRAME_LEN);
    let mut chunk = vec![0u8; READ_CHUNK_LEN];
    let mut empty_since = Some(Instant::now());
    let mut sweep = interval(state.config.sweep_interval());
    sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The first interval tick is immediate; use the first real sweep later.
    sweep.tick().await;

    loop {
        // Consume every complete frame before waiting for more input. This
        // handles coalesced frames and a frame split across reads equally.
        // Track a cursor and compact once: draining after every frame would
        // repeatedly move the remaining batch, which is quadratic for small
        // coalesced frames.
        let mut consumed = 0;
        loop {
            match frame::parse_frame(&buffer[consumed..]) {
                Ok(Some((parsed, used))) => {
                    state.handle_frame(&parsed).await?;
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
            empty_since = if state.has_sessions() {
                None
            } else {
                Some(Instant::now())
            };
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
            _ = sweep.tick() => {
                let had_sessions = state.has_sessions();
                state.sweep().await?;
                // A mux stream that has stayed empty for the session idle
                // timeout cannot carry a live session. Stock closes such a
                // worker after 60 s; match the intent without cutting an
                // active one-way flow. Losing the last session in this sweep
                // starts the clock now instead of reusing an older one.
                if state.has_sessions() {
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
            received = timeout(STREAM_IDLE_TIMEOUT, reader.read(&mut chunk)) => {
                match received {
                    Err(_) => {
                        return Err(MuxError::Timeout {
                            stage: "mux stream read",
                        });
                    }
                    Ok(Err(error)) => return Err(MuxError::Io(error)),
                    Ok(Ok(0)) => {
                        return if buffer.is_empty() {
                            Ok(())
                        } else {
                            Err(MuxError::TruncatedFrame {
                                buffered: buffer.len(),
                            })
                        };
                    }
                    Ok(Ok(count)) => {
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

impl MuxState {
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
            SessionStatus::KeepAlive => {
                if let Some(session) = self.session(parsed.session_id) {
                    session.touch();
                }
                Ok(())
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
        // when this New names the same identifier within the stream.
        let retained =
            global_id.and_then(|global_id| lock_table(&self.table).take_expiring(global_id));
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

        if parsed.option.has_data() && !parsed.payload.is_empty() {
            match timeout(
                self.config.io_timeout,
                socket.send_to(parsed.payload, resolved),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    tracing::debug!(
                        session_id = id,
                        %error,
                        "XUDP first datagram send failed"
                    );
                    if reattached {
                        self.limiter.metrics().record_xudp_retained_discarded();
                    }
                    return self.send_end(id, true).await;
                }
                Err(_) => {
                    tracing::debug!(session_id = id, "XUDP first datagram send timed out");
                    if reattached {
                        self.limiter.metrics().record_xudp_retained_discarded();
                    }
                    return self.send_end(id, true).await;
                }
            }
        }

        let session = Arc::new(Session::new(
            id, global_id, socket, family, resolved, permit,
        ));
        let reply_task = spawn_reply_task(
            Arc::clone(&session),
            self.outbound.clone(),
            Arc::clone(&self.table),
            Arc::clone(&self.config),
            self.limiter.clone(),
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

        Ok(())
    }

    /// Handles `Keep`: append a datagram to an existing session.
    async fn handle_keep(&self, parsed: &Frame<'_>) -> Result<(), MuxError> {
        let id = parsed.session_id;
        let Some(session) = self.session(id) else {
            // Stock replies with a clean End for an unknown session.
            return self.send_end(id, false).await;
        };
        session.touch();

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

        match timeout(
            self.config.io_timeout,
            session.socket.send_to(parsed.payload, destination),
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => {
                tracing::debug!(session_id = id, %error, "XUDP relay send failed");
                if session.is_closed() {
                    Ok(())
                } else {
                    self.close_with_error(id).await
                }
            }
            Err(_) => {
                tracing::debug!(session_id = id, "XUDP relay send timed out");
                if session.is_closed() {
                    Ok(())
                } else {
                    self.close_with_error(id).await
                }
            }
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

    /// Returns `true` while any active or retained session exists.
    fn has_sessions(&self) -> bool {
        lock_table(&self.table).total() > 0
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
    /// The reply task is stopped and joined before `End` is queued, so no data
    /// frame can follow the close. A reply task that already claimed the close
    /// owns the `End`; this function then only performs cleanup.
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
        if let Some(mut task) = reply_task
            && timeout(self.config.io_timeout, &mut task).await.is_err()
        {
            task.abort();
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
            // A sweep can expire many sessions at once. Waiting up to
            // END_ENQUEUE_TIMEOUT for each idle End would block the mux read
            // loop for seconds when the peer is not reading. Idle End is
            // best-effort: the client learns the flow is gone on its next
            // Keep, while a full queue already signals pressure.
            self.try_send_end(session.id, error);
        } else {
            self.send_end(session.id, error).await?;
        }

        let permit = session.take_permit();
        if reason.retains_socket()
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

    /// Queues one `End` frame behind every data frame already accepted.
    async fn send_end(&self, id: u16, error: bool) -> Result<(), MuxError> {
        let frame = encode_end_frame(id, error);
        if frame.is_empty() {
            return Err(MuxError::Encode);
        }
        match timeout(
            self.config.io_timeout.min(END_ENQUEUE_TIMEOUT),
            self.outbound.send(QueuedFrame::new(frame, None)),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => {
                self.limiter.metrics().record_xudp_end_dropped();
                Err(MuxError::WriterClosed)
            }
            Err(_) => {
                // The peer is not reading. A missing End only affects this
                // flow; tearing down the whole mux would kill unrelated DNS
                // and QUIC sessions.
                self.limiter.metrics().record_xudp_end_dropped();
                tracing::debug!(
                    session_id = id,
                    "XUDP End frame could not be queued before the write deadline"
                );
                Ok(())
            }
        }
    }

    /// Queues one `End` if capacity is immediately available.
    ///
    /// Used by idle sweeps so one slow reader cannot multiply the bounded
    /// enqueue delay by the number of expired sessions.
    fn try_send_end(&self, id: u16, error: bool) {
        let frame = encode_end_frame(id, error);
        if frame.is_empty() {
            self.limiter.metrics().record_xudp_end_dropped();
            return;
        }
        if self
            .outbound
            .try_send(QueuedFrame::new(frame, None))
            .is_err()
        {
            self.limiter.metrics().record_xudp_end_dropped();
            tracing::debug!(
                session_id = id,
                "XUDP idle End frame dropped because the write queue is full"
            );
        }
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
    use super::{MuxError, MuxState, handle_mux_stream};
    use crate::address::{Address, NetLocation};
    use crate::xudp::frame::{
        Frame, FrameOption, FrameSpec, GLOBAL_ID_LEN, MAX_PAYLOAD_LEN, SessionStatus,
        TargetNetwork, XudpError, encode_frame, parse_frame,
    };
    use crate::xudp::session::{
        ActiveSession, QueuedFrame, Session, SessionTable, SocketFamily, XudpConfig,
        XudpConfigError, XudpSessionLimiter, spawn_reply_task,
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio::time::{Instant, sleep, timeout};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

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
            .send(QueuedFrame::new(vec![1], None))
            .await
            .expect("first slot");
        outbound
            .send(QueuedFrame::new(vec![2], None))
            .await
            .expect("second slot");
        let state = MuxState {
            config: Arc::clone(&config),
            table: Arc::new(Mutex::new(SessionTable::default())),
            outbound,
            limiter: limiter.clone(),
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
            Arc::clone(&state.table),
            Arc::clone(&state.config),
            state.limiter.clone(),
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

    #[derive(Debug, PartialEq, Eq)]
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
            Arc::clone(&table),
            Arc::clone(&config),
            limiter.clone(),
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
                .send(QueuedFrame::new(vec![byte], None))
                .await
                .expect("queue slot");
        }
        let state = MuxState {
            config: Arc::clone(&config),
            table: Arc::clone(&table),
            outbound: outbound.clone(),
            limiter: limiter.clone(),
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
        let (frame, used) = parse_frame(&queued.bytes)
            .expect("live reply parse")
            .expect("complete live reply");
        assert_eq!(used, queued.bytes.len());
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
            limiter: limiter.clone(),
        };
        outbound
            .try_send(QueuedFrame::new(vec![0], None))
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
            limiter: limiter.clone(),
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
            limiter: limiter.clone(),
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
            let (frame, used) = parse_frame(&queued.bytes)
                .expect("sweep queued a malformed frame")
                .expect("sweep queued an incomplete frame");
            assert_eq!(used, queued.bytes.len());
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
