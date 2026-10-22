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
    ActiveSession, ExpiringSession, Session, SessionTable, SocketFamily, XudpConfig,
    XudpConfigError, encode_end_frame, resolve_destination, spawn_reply_task,
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

/// Best-effort receive buffer for a session UDP socket. The kernel clamps this
/// to `net.core.rmem_max`; the production host raises that limit.
const UDP_RECV_BUFFER_BYTES: usize = 1024 * 1024;

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
    outbound: mpsc::Sender<Vec<u8>>,
}

/// Handles one XUDP mux stream until EOF or a protocol error.
///
/// `stream` is the VLESS body after the mux request has been authenticated.
/// The function owns the stream for its lifetime and returns when the peer
/// closes it, a malformed frame arrives, an I/O or timeout error occurs, or an
/// empty stream has been idle for `session_idle_timeout`. Every session and
/// reply task is stopped before it returns. A 24-hour read-inactivity backstop
/// also bounds a stream that keeps sessions active but never sends a frame.
pub async fn handle_mux_stream<S>(stream: S, config: Arc<XudpConfig>) -> Result<(), MuxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    config.validate()?;

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
    let state = MuxState {
        config: config.clone(),
        table: Arc::clone(&table),
        outbound,
    };

    let result = read_loop(&mut reader, &state, &mut writer_failed_rx).await;

    // The stream is gone or unusable; no End frames can reach the peer. Stop
    // every reply task and release every socket. Signal every task first, then
    // join them under one shared deadline so a broken task cannot multiply the
    // shutdown budget by the session limit.
    let active = lock_table(&table).drain_active();
    for entry in &active {
        entry.session.stop();
    }
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    for entry in active {
        if let Some(task) = entry.reply_task {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = timeout(remaining, task).await;
        }
    }
    lock_table(&table).clear_expiring();

    drop(state);
    if timeout(SHUTDOWN_TIMEOUT, &mut writer_task).await.is_err() {
        writer_task.abort();
    }

    result
}

/// Serializes frames from the reply tasks and the read loop.
async fn write_loop<W>(
    mut writer: W,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    io_timeout: Duration,
    writer_failed: watch::Sender<bool>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = inbound.recv().await {
        if let Err(error) = write_frame(&mut writer, &frame, io_timeout).await {
            let _ = writer_failed.send(true);
            return Err(error);
        }
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
        loop {
            match frame::parse_frame(&buffer) {
                Ok(Some((parsed, used))) => {
                    state.handle_frame(&parsed).await?;
                    buffer.drain(..used);
                    empty_since = if state.has_sessions() {
                        None
                    } else {
                        Some(Instant::now())
                    };
                }
                Ok(None) => break,
                Err(error) => return Err(MuxError::Frame(error)),
            }
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

        if parsed.network != Some(TargetNetwork::Udp) {
            tracing::debug!(session_id = id, "XUDP New is not a UDP target; rejecting");
            return self.send_end(id, true).await;
        }
        let Some(destination) = parsed.destination.as_ref() else {
            return self.send_end(id, true).await;
        };

        // Resolution happens before touching any session state: a domain that
        // cannot be resolved must not evict a retained socket.
        let resolved = match resolve_destination(destination, None, self.config.io_timeout).await {
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

        // A clean close with a nonzero GlobalID retains its socket. Reattach
        // when this New names the same identifier within the stream.
        let retained =
            global_id.and_then(|global_id| lock_table(&self.table).take_expiring(global_id));
        let reusable = retained
            .as_ref()
            .is_some_and(|retained| retained.family == family);
        let socket = if let Some(retained) = retained
            && reusable
        {
            retained.socket
        } else {
            // A family change cannot reuse the retained socket; it was removed
            // from the table and is dropped here. Treat this as a fresh New.
            if !self.reserve_session_slot() {
                tracing::debug!(session_id = id, "XUDP session limit reached; rejecting New");
                return self.send_end(id, true).await;
            }
            match timeout(
                self.config.io_timeout,
                UdpSocket::bind(family.bind_address()),
            )
            .await
            {
                Ok(Ok(socket)) => {
                    if let Err(error) =
                        beam_sys::set_udp_recv_buffer(socket.as_raw_fd(), UDP_RECV_BUFFER_BYTES)
                    {
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
                    return self.send_end(id, true).await;
                }
                Err(_) => {
                    tracing::debug!(session_id = id, "XUDP first datagram send timed out");
                    return self.send_end(id, true).await;
                }
            }
        }

        let session = Arc::new(Session::new(id, global_id, socket, family, resolved));
        let reply_task = spawn_reply_task(
            Arc::clone(&session),
            self.outbound.clone(),
            Arc::clone(&self.table),
            Arc::clone(&self.config),
        );
        let replaced = lock_table(&self.table).insert(ActiveSession {
            session,
            reply_task: Some(reply_task),
        });
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

        let destination = match parsed.destination.as_ref() {
            Some(location) => {
                match resolve_destination(location, Some(session.family), self.config.io_timeout)
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

        if !parsed.option.has_data() || parsed.payload.is_empty() {
            return Ok(());
        }

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
        if table.total() < self.config.max_sessions {
            return true;
        }
        table.evict_oldest_expiring()
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
        if let Some(task) = reply_task {
            let _ = timeout(self.config.io_timeout, task).await;
        }

        if !first {
            return Ok(());
        }

        // The reply task may have observed a socket error just before this
        // close claimed the session; report it as an error even when the
        // close itself was clean.
        let error = reason.is_error() || session.failed();
        self.send_end(session.id, error).await?;

        if reason.retains_socket()
            && let Some(global_id) = session.global_id
        {
            let now = Instant::now();
            let retained = ExpiringSession {
                socket: Arc::clone(&session.socket),
                family: session.family,
                // A pathological Duration must not panic on overflow; an
                // immediately expired entry only loses optional retention.
                expires_at: now.checked_add(self.config.close_expiry).unwrap_or(now),
            };
            let replaced = lock_table(&self.table).insert_expiring(global_id, retained);
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
        match timeout(self.config.io_timeout, self.outbound.send(frame)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(MuxError::WriterClosed),
            Err(_) => Err(MuxError::Timeout {
                stage: "frame write",
            }),
        }
    }

    /// Expires idle sessions and retained sockets.
    async fn sweep(&self) -> Result<(), MuxError> {
        let now = Instant::now();
        let idle = {
            let mut table = lock_table(&self.table);
            let idle = table.take_idle(now, self.config.session_idle_timeout);
            let retained = table.expire_retained(now);
            if retained > 0 {
                tracing::trace!(count = retained, "XUDP retained sockets expired");
            }
            idle
        };

        for active in idle {
            tracing::debug!(session_id = active.session.id, "XUDP session expired");
            self.close_active(active, CloseReason::Idle).await?;
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

/// Locks the session table, recovering from a poisoned mutex.
fn lock_table(table: &Mutex<SessionTable>) -> MutexGuard<'_, SessionTable> {
    match table.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::{MuxError, handle_mux_stream};
    use crate::address::{Address, NetLocation};
    use crate::xudp::frame::{
        Frame, FrameOption, FrameSpec, GLOBAL_ID_LEN, MAX_PAYLOAD_LEN, SessionStatus,
        TargetNetwork, XudpError, encode_frame, parse_frame,
    };
    use crate::xudp::session::{XudpConfig, XudpConfigError};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::UdpSocket;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn test_config() -> Arc<XudpConfig> {
        Arc::new(XudpConfig {
            session_idle_timeout: Duration::from_secs(30),
            close_expiry: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
            ..XudpConfig::default()
        })
    }

    fn start_mux(config: Arc<XudpConfig>) -> (DuplexStream, JoinHandle<Result<(), MuxError>>) {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let task = tokio::spawn(handle_mux_stream(server, config));
        (client, task)
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
    async fn invalid_config_is_rejected_before_reading() {
        let (_client, server) = tokio::io::duplex(1024);
        let config = Arc::new(XudpConfig {
            max_sessions: 0,
            ..XudpConfig::default()
        });
        let result = handle_mux_stream(server, config).await;
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
