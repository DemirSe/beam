//! XUDP session state, sockets, and reply tasks.
//!
//! One [`Session`] owns one unconnected UDP socket and one reply task. The
//! [`SessionTable`] is scoped to a single mux stream: a GlobalID is stored and
//! retained within that stream, but it is never looked up across mux
//! connections. Cross-connection continuity is therefore out of scope for v1.
//!
//! # Socket model
//!
//! A session socket is bound to `0.0.0.0:0` or `[::]:0` at `New`, based on the
//! first destination. It stays unconnected: every request uses `send_to` and
//! every reply is stamped with the actual `recv_from` source. This matches
//! stock Xray's freedom outbound.
//!
//! # Deliberate trade-offs
//!
//! - **No source allowlist.** The unconnected socket accepts a datagram from
//!   any sender and forwards its source, exactly like stock Xray. A future
//!   option could restrict replies to destinations this session contacted, or
//!   to the same host, but neither stock Xray nor this version does.
//! - **GlobalID is per stream.** The identifier is accepted, stored, and used
//!   only to reattach a socket that was closed within this same stream. It is
//!   not identity, routing, or policy, and a different authenticated client
//!   cannot attach to it because the table dies with the stream.
//! - **`close_expiry` retains a closed socket.** A cleanly closed session with
//!   a nonzero GlobalID is kept for [`XudpConfig::close_expiry`] so a later
//!   `New` with the same identifier can reattach without a new ephemeral port.
//!   The retention still counts toward the session limit; when the limit is
//!   reached, the oldest retained socket is evicted before an active session.
//! - **One socket family per session.** A `Keep` whose destination has another
//!   family is dropped; a session does not silently gain a second socket.
//! - **Domains are resolved per frame.** A `Keep` that carries a domain is
//!   looked up again; stock Xray caches a domain's address per outbound. The
//!   wire behavior is the same, but a per-session cache is a future
//!   optimization. All lookups are bounded by [`XudpConfig::io_timeout`].

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use crate::address::{Address, NetLocation};
use crate::metrics::Metrics;
use crate::xudp::frame::{
    self, FrameOption, FrameSpec, GLOBAL_ID_LEN, MAX_PAYLOAD_LEN, SessionStatus, TargetNetwork,
};

/// Default maximum number of sessions (active and retained) per mux stream.
pub const DEFAULT_MAX_SESSIONS: usize = 2048;

/// Process-wide maximum number of XUDP sessions (active and retained).
///
/// Each session owns one UDP socket. The per-stream limit is not an aggregate
/// bound because one process can have many mux streams. Keep this below the
/// per-stream limit and size it with the kernel receive buffer in mind; on the
/// 1 GiB production host the socket buffers, not the Rust heap, are the
/// dominant cost.
pub const DEFAULT_MAX_GLOBAL_SESSIONS: usize = 256;

/// Default maximum UDP payload accepted from a frame or queued for a reply.
pub const DEFAULT_MAX_DATAGRAM_SIZE: usize = MAX_PAYLOAD_LEN;

/// Default idle timeout for a UDP session.
pub const DEFAULT_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Default retention period for a cleanly closed GlobalID socket.
pub const DEFAULT_CLOSE_EXPIRY: Duration = Duration::from_secs(60);

/// Default number of reply frames that may wait for the stream writer.
pub const DEFAULT_MAX_QUEUED_REPLIES: usize = 64;

/// Process-wide budget for reply bytes waiting in mux queues.
///
/// The per-stream frame count alone lets 256 streams accumulate roughly a
/// gigabyte of 8 KiB frames. This budget bounds the aggregate Rust-side queue
/// while still leaving room for large HTTP/3 bursts on a single stream.
pub const DEFAULT_REPLY_QUEUE_BUDGET: usize = 32 * 1024 * 1024;

/// Default timeout for one socket send, receive, or stream write.
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Smallest sweep interval, so a tiny configured timeout cannot busy-loop.
const MIN_SWEEP_INTERVAL: Duration = Duration::from_millis(10);

/// Largest sweep interval, so the table is inspected at least once a second.
const MAX_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Limits for the XUDP session layer.
///
/// Every value is validated by [`Self::validate`] before
/// [`crate::xudp::handle_mux_stream`] uses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XudpConfig {
    /// Maximum active plus retained sessions for one mux stream.
    pub max_sessions: usize,
    /// Maximum UDP payload in either direction, at most
    /// [`MAX_PAYLOAD_LEN`] (8192).
    pub max_datagram_size: usize,
    /// Close a session after this long without a request or reply.
    ///
    /// An empty mux stream is also closed after this long; an active session
    /// keeps the stream open.
    pub session_idle_timeout: Duration,
    /// Retain a cleanly closed GlobalID socket for this long.
    pub close_expiry: Duration,
    /// Bound on reply frames waiting for the stream writer; excess replies are
    /// dropped like packets on a congested UDP path.
    pub max_queued_replies: usize,
    /// Timeout for a single UDP send/receive or stream write.
    pub io_timeout: Duration,
}

impl Default for XudpConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl XudpConfig {
    /// Creates the production defaults.
    pub const fn new() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
            session_idle_timeout: DEFAULT_SESSION_IDLE_TIMEOUT,
            close_expiry: DEFAULT_CLOSE_EXPIRY,
            max_queued_replies: DEFAULT_MAX_QUEUED_REPLIES,
            io_timeout: DEFAULT_IO_TIMEOUT,
        }
    }

    /// Validates every limit and timeout.
    pub fn validate(&self) -> Result<(), XudpConfigError> {
        if self.max_sessions == 0 || self.max_sessions > usize::from(u16::MAX) + 1 {
            return Err(XudpConfigError::MaxSessions);
        }
        if self.max_datagram_size == 0 || self.max_datagram_size > MAX_PAYLOAD_LEN {
            return Err(XudpConfigError::MaxDatagramSize);
        }
        if self.session_idle_timeout.is_zero() {
            return Err(XudpConfigError::SessionIdleTimeout);
        }
        if self.close_expiry.is_zero() {
            return Err(XudpConfigError::CloseExpiry);
        }
        if self.max_queued_replies == 0 || self.max_queued_replies > usize::from(u16::MAX) + 1 {
            return Err(XudpConfigError::MaxQueuedReplies);
        }
        if self.io_timeout.is_zero() {
            return Err(XudpConfigError::IoTimeout);
        }
        Ok(())
    }

    /// Returns how often the session table is swept.
    pub(crate) fn sweep_interval(&self) -> Duration {
        let mut interval = MAX_SWEEP_INTERVAL;
        if self.session_idle_timeout < interval {
            interval = self.session_idle_timeout;
        }
        if self.close_expiry < interval {
            interval = self.close_expiry;
        }
        interval.max(MIN_SWEEP_INTERVAL)
    }
}

/// An invalid [`XudpConfig`] value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum XudpConfigError {
    /// `max_sessions` was zero or too large for a 16-bit session id space.
    #[error("XUDP max_sessions must be between 1 and 65536")]
    MaxSessions,
    /// `max_datagram_size` was zero or above [`MAX_PAYLOAD_LEN`].
    #[error("XUDP max_datagram_size must be between 1 and {MAX_PAYLOAD_LEN}")]
    MaxDatagramSize,
    /// `session_idle_timeout` was zero.
    #[error("XUDP session_idle_timeout must be non-zero")]
    SessionIdleTimeout,
    /// `close_expiry` was zero.
    #[error("XUDP close_expiry must be non-zero")]
    CloseExpiry,
    /// `max_queued_replies` was zero or unreasonably large.
    #[error("XUDP max_queued_replies must be between 1 and 65536")]
    MaxQueuedReplies,
    /// `io_timeout` was zero.
    #[error("XUDP io_timeout must be non-zero")]
    IoTimeout,
}

/// Process-wide XUDP session limiter.
///
/// A permit is held by each active session and by each retained GlobalID
/// socket. Permits therefore cover both the live and the close-expiry states,
/// which are the states that keep a kernel UDP socket alive.
#[derive(Clone)]
pub struct XudpSessionLimiter {
    max: usize,
    permits: Arc<Semaphore>,
    /// Weak references to every mux-stream session table that may retain a
    /// closed GlobalID socket. Retained sockets hold a global permit; the
    /// registry lets a new active session evict that optional state before it
    /// is rejected for a global-limit condition.
    retained_tables: Arc<Mutex<Vec<Weak<Mutex<SessionTable>>>>>,
    /// Process-wide byte budget for reply frames waiting on stream writers.
    reply_budget: Arc<Semaphore>,
    /// Process-wide counters for XUDP decisions.
    metrics: Arc<Metrics>,
}

impl fmt::Debug for XudpSessionLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XudpSessionLimiter")
            .field("max", &self.max)
            .field("available", &self.permits.available_permits())
            .finish()
    }
}

impl XudpSessionLimiter {
    /// Creates a limiter with at least one permit.
    #[must_use]
    pub fn new(max: usize) -> Self {
        let max = max.max(1);
        Self {
            max,
            permits: Arc::new(Semaphore::new(max)),
            retained_tables: Arc::new(Mutex::new(Vec::new())),
            reply_budget: Arc::new(Semaphore::new(DEFAULT_REPLY_QUEUE_BUDGET)),
            metrics: Arc::new(Metrics::default()),
        }
    }

    /// Uses the process-wide metrics instance.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Returns the process-wide metrics instance.
    #[must_use]
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Returns the configured global session limit.
    #[must_use]
    pub const fn max(&self) -> usize {
        self.max
    }

    /// Leaves half of the global slots for other mux streams.
    #[must_use]
    pub(crate) fn stream_active_limit(&self) -> usize {
        (self.max / 2).max(1)
    }

    /// Registers one mux stream's session table for global retained eviction.
    pub(crate) fn register_table(&self, table: &Arc<Mutex<SessionTable>>) {
        let mut tables = lock(&self.retained_tables);
        tables.retain(|table| table.strong_count() > 0);
        tables.push(Arc::downgrade(table));
    }

    /// Tries to reserve one global session slot without waiting.
    #[cfg(test)]
    pub(crate) fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    /// Reserves a slot, evicting optional retained sockets when the limit is
    /// full.
    ///
    /// Active sessions are never evicted. Retained GlobalID sockets are
    /// optional reattachment state, so a new live flow wins over them. If the
    /// limit consists only of active sessions, this returns `None` and the
    /// caller must reject the new flow.
    pub(crate) fn try_acquire_or_evict(&self) -> Option<OwnedSemaphorePermit> {
        loop {
            if let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() {
                return Some(permit);
            }
            if !self.evict_one_retained() {
                return None;
            }
        }
    }

    /// Reserves aggregate queue bytes for one reply frame.
    pub(crate) fn try_reserve_reply(&self, bytes: usize) -> Option<OwnedSemaphorePermit> {
        let bytes = u32::try_from(bytes).ok()?;
        Arc::clone(&self.reply_budget)
            .try_acquire_many_owned(bytes)
            .ok()
    }

    /// Returns the configured aggregate reply-byte budget.
    #[must_use]
    pub const fn reply_budget_bytes(&self) -> usize {
        DEFAULT_REPLY_QUEUE_BUDGET
    }

    /// Evicts the globally oldest retained socket from any registered stream.
    fn evict_one_retained(&self) -> bool {
        let tables: Vec<Arc<Mutex<SessionTable>>> = {
            let mut tables = lock(&self.retained_tables);
            tables.retain(|table| table.strong_count() > 0);
            tables.iter().filter_map(Weak::upgrade).collect()
        };

        // Inspect each table under its own lock, then evict from the single
        // table holding the earliest expiry. Do not hold two table locks.
        let mut victim: Option<(Instant, Arc<Mutex<SessionTable>>)> = None;
        for table in tables {
            let Some(expiry) = lock(&table).oldest_expiring_at() else {
                continue;
            };
            let replace = match &victim {
                None => true,
                Some((best, _)) => expiry < *best,
            };
            if replace {
                victim = Some((expiry, table));
            }
        }

        let Some((_, table)) = victim else {
            return false;
        };
        if lock(&table).evict_oldest_expiring() {
            self.metrics.record_xudp_retained_evicted();
            return true;
        }
        false
    }
}

impl Default for XudpSessionLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_GLOBAL_SESSIONS)
    }
}

/// Address family of a session socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketFamily {
    /// IPv4 socket.
    V4,
    /// IPv6 socket.
    V6,
}

impl SocketFamily {
    /// Returns the family of `address`.
    pub(crate) fn of(address: SocketAddr) -> Self {
        if address.is_ipv4() {
            Self::V4
        } else {
            Self::V6
        }
    }

    /// Returns `true` when `address` belongs to this family.
    pub(crate) fn matches(self, address: SocketAddr) -> bool {
        match self {
            Self::V4 => address.is_ipv4(),
            Self::V6 => address.is_ipv6(),
        }
    }

    /// Returns the wildcard bind address for this family.
    pub(crate) fn bind_address(self) -> SocketAddr {
        match self {
            Self::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            Self::V6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        }
    }
}

/// Errors returned while resolving a destination.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveError {
    /// Port zero is never a valid UDP destination.
    #[error("XUDP destination port must be non-zero")]
    Port,
    /// Domain resolution exceeded the configured I/O timeout.
    #[error("XUDP destination resolution timed out")]
    Timeout,
    /// The platform resolver failed.
    #[error("XUDP destination resolution failed: {0}")]
    Io(#[from] io::Error),
    /// No result matched the session socket family.
    #[error("XUDP destination has no address for this session socket family")]
    FamilyMismatch,
}

/// Resolves `destination` to a single socket address.
///
/// `family` is `None` for a `New` frame, where the socket family is chosen by
/// the destination. Otherwise it is the existing session's family and a
/// mismatching result is rejected. Domains prefer an IPv4 result when no
/// family is given, then fall back to IPv6; this keeps `localhost` test
/// fixtures deterministic without preferring one family at the socket level.
pub(crate) async fn resolve_destination(
    destination: &NetLocation,
    family: Option<SocketFamily>,
    resolve_timeout: Duration,
) -> Result<SocketAddr, ResolveError> {
    if destination.port == 0 {
        return Err(ResolveError::Port);
    }

    match &destination.address {
        Address::Ipv4(address) => {
            let resolved = SocketAddr::from((*address, destination.port));
            if family.is_some_and(|family| !family.matches(resolved)) {
                return Err(ResolveError::FamilyMismatch);
            }
            Ok(resolved)
        }
        Address::Ipv6(address) => {
            let resolved = SocketAddr::from((*address, destination.port));
            if family.is_some_and(|family| !family.matches(resolved)) {
                return Err(ResolveError::FamilyMismatch);
            }
            Ok(resolved)
        }
        Address::Domain(domain) => {
            let addresses = timeout(
                resolve_timeout,
                tokio::net::lookup_host((domain.as_str(), destination.port)),
            )
            .await
            .map_err(|_| ResolveError::Timeout)??;

            let mut chosen = None;
            for address in addresses {
                match family {
                    Some(family) if family.matches(address) => {
                        chosen = Some(address);
                        break;
                    }
                    Some(_) => {}
                    None if address.is_ipv4() => {
                        chosen = Some(address);
                        break;
                    }
                    None => {
                        chosen.get_or_insert(address);
                    }
                }
            }
            chosen.ok_or(ResolveError::FamilyMismatch)
        }
    }
}

/// One encoded frame waiting for the mux writer.
///
/// `budget` is held until the writer has written (or dropped) the frame, so
/// aggregate queued bytes stay bounded even when many streams are slow.
pub(crate) struct QueuedFrame {
    pub(crate) bytes: Vec<u8>,
    _budget: Option<OwnedSemaphorePermit>,
}

impl QueuedFrame {
    pub(crate) fn new(bytes: Vec<u8>, budget: Option<OwnedSemaphorePermit>) -> Self {
        Self {
            bytes,
            _budget: budget,
        }
    }
}

/// One UDP relay session.
pub(crate) struct Session {
    /// Mux session id.
    pub(crate) id: u16,
    /// Optional GlobalID from `New`.
    pub(crate) global_id: Option<[u8; GLOBAL_ID_LEN]>,
    /// The unconnected UDP socket shared with a reattached session.
    pub(crate) socket: Arc<UdpSocket>,
    /// Socket family selected at creation.
    pub(crate) family: SocketFamily,
    destination: Mutex<SocketAddr>,
    last_activity: Mutex<Instant>,
    stop: watch::Sender<bool>,
    closed: AtomicBool,
    failed: AtomicBool,
    /// Global session slot, released when the socket is finally dropped.
    permit: Mutex<Option<OwnedSemaphorePermit>>,
}

impl Session {
    /// Creates a session and starts its idle clock.
    pub(crate) fn new(
        id: u16,
        global_id: Option<[u8; GLOBAL_ID_LEN]>,
        socket: Arc<UdpSocket>,
        family: SocketFamily,
        destination: SocketAddr,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        let (stop, _) = watch::channel(false);
        Self {
            id,
            global_id,
            socket,
            family,
            destination: Mutex::new(destination),
            last_activity: Mutex::new(Instant::now()),
            stop,
            closed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            permit: Mutex::new(permit),
        }
    }

    /// Takes the global session slot so it can move to a retained socket.
    pub(crate) fn take_permit(&self) -> Option<OwnedSemaphorePermit> {
        lock(&self.permit).take()
    }

    /// Marks request or reply activity.
    pub(crate) fn touch(&self) {
        *lock(&self.last_activity) = Instant::now();
    }

    /// Returns how long the session has been idle at `now`.
    pub(crate) fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(*lock(&self.last_activity))
    }

    /// Returns the last destination used for a datagram.
    pub(crate) fn destination(&self) -> SocketAddr {
        *lock(&self.destination)
    }

    /// Records the last destination used for a datagram.
    pub(crate) fn set_destination(&self, destination: SocketAddr) {
        *lock(&self.destination) = destination;
    }

    /// Stops the reply task. Sending is idempotent.
    ///
    /// `send_replace` stores the value even when the reply task has not yet
    /// subscribed. `send` returns an error in that window and leaves the
    /// value at `false`, so a task spawned just before mux shutdown would
    /// miss the stop and keep its socket and global permit forever.
    pub(crate) fn stop(&self) {
        self.stop.send_replace(true);
    }

    /// Returns a receiver that observes [`Self::stop`].
    pub(crate) fn stop_receiver(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }

    /// Returns `true` when a closer already claimed this session.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Claims the close responsibility. Returns `true` for the first caller.
    pub(crate) fn mark_closed(&self) -> bool {
        !self.closed.swap(true, Ordering::AcqRel)
    }

    /// Records that the UDP relay failed.
    pub(crate) fn mark_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }

    /// Returns `true` when the UDP relay failed.
    pub(crate) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
}

/// An active session plus the handle of its reply task.
pub(crate) struct ActiveSession {
    /// Session state.
    pub(crate) session: Arc<Session>,
    /// Reply task, if it has been attached.
    pub(crate) reply_task: Option<JoinHandle<()>>,
}

/// A cleanly closed GlobalID socket waiting for a same-stream reattach.
pub(crate) struct ExpiringSession {
    /// Retained socket.
    pub(crate) socket: Arc<UdpSocket>,
    /// Socket family, checked before a reattach.
    pub(crate) family: SocketFamily,
    /// Absolute expiry instant.
    pub(crate) expires_at: Instant,
    /// Global session slot held while the socket is retained.
    pub(crate) permit: Option<OwnedSemaphorePermit>,
}

/// Per-mux-stream session table.
#[derive(Default)]
pub(crate) struct SessionTable {
    active: HashMap<u16, ActiveSession>,
    expiring: HashMap<[u8; GLOBAL_ID_LEN], ExpiringSession>,
}

impl SessionTable {
    /// Returns active plus retained sessions.
    pub(crate) fn total(&self) -> usize {
        self.active.len() + self.expiring.len()
    }

    /// Returns the number of active sessions.
    pub(crate) fn active_len(&self) -> usize {
        self.active.len()
    }

    /// Looks up an active session without removing it.
    pub(crate) fn active(&self, id: u16) -> Option<&ActiveSession> {
        self.active.get(&id)
    }

    /// Removes and returns an active session.
    pub(crate) fn take(&mut self, id: u16) -> Option<ActiveSession> {
        self.active.remove(&id)
    }

    /// Removes and returns the active session attached to `global_id`.
    ///
    /// Xray treats a GlobalID as one logical UDP flow and migrates it when a
    /// new `New` arrives on another session id. Keeping both attachments would
    /// duplicate replies and leak a socket.
    pub(crate) fn take_by_global_id(
        &mut self,
        global_id: [u8; GLOBAL_ID_LEN],
    ) -> Option<ActiveSession> {
        let id = self
            .active
            .iter()
            .find_map(|(id, entry)| (entry.session.global_id == Some(global_id)).then_some(*id))?;
        self.active.remove(&id)
    }

    /// Removes `id` only when it still holds `session`.
    ///
    /// A reply task uses this so a stale task cannot remove a newer session
    /// that reused the same 16-bit id.
    pub(crate) fn take_if_same(
        &mut self,
        id: u16,
        session: &Arc<Session>,
    ) -> Option<ActiveSession> {
        match self.active.get(&id) {
            Some(entry) if Arc::ptr_eq(&entry.session, session) => self.active.remove(&id),
            _ => None,
        }
    }

    /// Inserts an active session, returning any previous entry.
    pub(crate) fn insert(&mut self, active: ActiveSession) -> Option<ActiveSession> {
        self.active.insert(active.session.id, active)
    }

    /// Removes a retained GlobalID socket for reattachment.
    pub(crate) fn take_expiring(
        &mut self,
        global_id: [u8; GLOBAL_ID_LEN],
    ) -> Option<ExpiringSession> {
        self.expiring.remove(&global_id)
    }

    /// Retains a closed GlobalID socket, returning any previous entry.
    pub(crate) fn insert_expiring(
        &mut self,
        global_id: [u8; GLOBAL_ID_LEN],
        session: ExpiringSession,
    ) -> Option<ExpiringSession> {
        self.expiring.insert(global_id, session)
    }

    /// Removes every retained entry whose deadline has passed.
    pub(crate) fn expire_retained(&mut self, now: Instant) -> usize {
        let before = self.expiring.len();
        self.expiring.retain(|_, entry| entry.expires_at > now);
        before - self.expiring.len()
    }

    /// Returns the earliest retained expiry in this table.
    pub(crate) fn oldest_expiring_at(&self) -> Option<Instant> {
        self.expiring.values().map(|entry| entry.expires_at).min()
    }

    /// Evicts the retained entry that expires first.
    ///
    /// Retained sockets are optional state; an active session must never be
    /// rejected while one can be dropped instead.
    pub(crate) fn evict_oldest_expiring(&mut self) -> bool {
        let Some(global_id) = self
            .expiring
            .iter()
            .min_by_key(|(_, entry)| entry.expires_at)
            .map(|(global_id, _)| *global_id)
        else {
            return false;
        };
        self.expiring.remove(&global_id).is_some()
    }

    /// Removes every active session idle for at least `idle_timeout`.
    pub(crate) fn take_idle(&mut self, now: Instant, idle_timeout: Duration) -> Vec<ActiveSession> {
        let ids: Vec<u16> = self
            .active
            .iter()
            .filter(|(_, entry)| entry.session.idle_for(now) >= idle_timeout)
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter()
            .filter_map(|id| self.active.remove(&id))
            .collect()
    }

    /// Removes and returns every active session.
    pub(crate) fn drain_active(&mut self) -> Vec<ActiveSession> {
        self.active.drain().map(|(_, entry)| entry).collect()
    }

    /// Drops every retained socket.
    pub(crate) fn clear_expiring(&mut self) {
        self.expiring.clear();
    }
}

/// Spawns the task that reads replies from one session socket.
pub(crate) fn spawn_reply_task(
    session: Arc<Session>,
    outbound: mpsc::Sender<QueuedFrame>,
    table: Arc<Mutex<SessionTable>>,
    config: Arc<XudpConfig>,
    limiter: XudpSessionLimiter,
) -> JoinHandle<()> {
    tokio::spawn(reply_loop(session, outbound, table, config, limiter))
}

/// Largest number of reply-queue slots held back for control frames.
const MAX_CONTROL_QUEUE_RESERVE: usize = 8;

/// Longest an `End` frame may wait for queue space.
pub(crate) const END_ENQUEUE_TIMEOUT: Duration = Duration::from_millis(250);

/// Slots data replies must leave free for `End` frames.
pub(crate) fn control_queue_reserve(max_queued_replies: usize) -> usize {
    max_queued_replies
        .saturating_sub(1)
        .min(MAX_CONTROL_QUEUE_RESERVE)
}

/// Reads datagrams until the session stops or the socket fails.
///
/// Replies are `Keep + Data` frames carrying the actual source address. They
/// are queued with `try_send`: a full bounded queue drops the datagram rather
/// than applying backpressure to the socket, which matches UDP semantics and
/// keeps the reply task unblockable.
async fn reply_loop(
    session: Arc<Session>,
    outbound: mpsc::Sender<QueuedFrame>,
    table: Arc<Mutex<SessionTable>>,
    config: Arc<XudpConfig>,
    limiter: XudpSessionLimiter,
) {
    let mut stop = session.stop_receiver();
    if *stop.borrow() || session.is_closed() {
        return;
    }

    // One byte above the limit lets `recv_from` reveal an oversize datagram
    // instead of silently truncating it to the configured maximum.
    let mut buffer = vec![0u8; config.max_datagram_size.saturating_add(1)];
    let mut failed = false;
    let metrics = limiter.metrics();

    loop {
        tokio::select! {
            changed = stop.changed() => {
                match changed {
                    Ok(()) if *stop.borrow() => break,
                    Ok(()) => {}
                    Err(_) => break,
                }
            }
            received = timeout(config.io_timeout, session.socket.recv_from(&mut buffer)) => {
                match received {
                    Ok(Ok((len, source))) => {
                        session.touch();
                        if len == 0 {
                            // Stock XUDP writers drop zero-length datagrams.
                            metrics.record_xudp_reply_dropped();
                            continue;
                        }
                        if len > config.max_datagram_size {
                            tracing::trace!(
                                session_id = session.id,
                                length = len,
                                "XUDP reply exceeds the configured limit; dropping a datagram"
                            );
                            metrics.record_xudp_reply_dropped();
                            continue;
                        }
                        let Some(frame_len) = reply_frame_len(source, len) else {
                            tracing::trace!(
                                session_id = session.id,
                                length = len,
                                "XUDP reply size overflows; dropping a datagram"
                            );
                            metrics.record_xudp_reply_dropped();
                            continue;
                        };

                        // Keep a small FIFO reserve for End control frames.
                        // Data stops before the queue is completely full, so a
                        // closing session does not wait behind the last burst.
                        if outbound.capacity() <= control_queue_reserve(config.max_queued_replies) {
                            tracing::trace!(
                                session_id = session.id,
                                "XUDP reply queue is reserving control capacity; dropping a datagram"
                            );
                            metrics.record_xudp_reply_dropped();
                            continue;
                        }

                        // Reserve the queue slot and the aggregate byte budget
                        // before allocating or encoding. A reply that cannot be
                        // admitted is dropped without paying for its frame.
                        let permit = match outbound.try_reserve() {
                            Ok(permit) => permit,
                            Err(mpsc::error::TrySendError::Full(())) => {
                                tracing::trace!(
                                    session_id = session.id,
                                    "XUDP reply queue is full; dropping a datagram"
                                );
                                metrics.record_xudp_reply_dropped();
                                continue;
                            }
                            // The stream writer is gone; the main loop is
                            // shutting the mux stream down.
                            Err(mpsc::error::TrySendError::Closed(())) => break,
                        };
                        let Some(budget) = limiter.try_reserve_reply(frame_len) else {
                            tracing::trace!(
                                session_id = session.id,
                                "XUDP aggregate reply budget is full; dropping a datagram"
                            );
                            metrics.record_xudp_reply_dropped();
                            continue;
                        };

                        let mut frame = Vec::new();
                        if frame.try_reserve_exact(frame_len).is_err() {
                            tracing::trace!(
                                session_id = session.id,
                                length = frame_len,
                                "XUDP reply allocation failed; dropping a datagram"
                            );
                            metrics.record_xudp_reply_dropped();
                            continue;
                        }
                        let source = socket_addr_to_location(source);
                        let spec = FrameSpec {
                            session_id: session.id,
                            status: SessionStatus::Keep,
                            option: FrameOption::DATA,
                            network: Some(TargetNetwork::Udp),
                            destination: Some(&source),
                            global_id: None,
                            payload: &buffer[..len],
                        };
                        if frame::encode_frame(&mut frame, spec).is_err() {
                            metrics.record_xudp_reply_dropped();
                            continue;
                        }
                        permit.send(QueuedFrame::new(frame, Some(budget)));
                    }
                    Ok(Err(error)) => {
                        tracing::debug!(
                            session_id = session.id,
                            %error,
                            "XUDP reply receive failed"
                        );
                        session.mark_failed();
                        failed = true;
                        break;
                    }
                    Err(_) => {
                        // A receive timeout only wakes the task; the session
                        // table sweep decides whether the session expired.
                    }
                }
            }
        }
    }

    if failed && session.mark_closed() {
        // Remove ourselves so the next Keep for this id gets an End.
        let removed = lock(&table).take_if_same(session.id, &session);
        drop(removed);

        let end = encode_end_frame(session.id, true);
        if !end.is_empty() {
            // Best effort with a short bound. The queue may be full, but this
            // is the only place that reports a failed relay.
            match timeout(
                config.io_timeout.min(END_ENQUEUE_TIMEOUT),
                outbound.send(QueuedFrame::new(end, None)),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => metrics.record_xudp_end_dropped(),
            }
        }
    }
}

/// Returns the exact encoded size of a UDP reply frame.
///
/// A reply always carries a `Keep + Data` frame with an IP source address, so
/// the metadata size is fixed for a given address family. Reserving this exact
/// size avoids a hidden growth when an IPv6 source needs 28 overhead bytes
/// rather than the 24 that fit an IPv4 source.
pub(crate) fn reply_frame_len(source: SocketAddr, payload_len: usize) -> Option<usize> {
    let address_len = match source {
        SocketAddr::V4(_) => 4,
        SocketAddr::V6(_) => 16,
    };
    let overhead = frame::METADATA_PREFIX_LEN
        + 2 // session id
        + 1 // status
        + 1 // option
        + 1 // network
        + 2 // port
        + 1 // address type
        + address_len
        + 2; // payload length
    payload_len.checked_add(overhead)
}

/// Encodes an `End` frame. An empty vector means encoding failed, which cannot
/// happen for a metadata-only frame with a 16-bit session id.
pub(crate) fn encode_end_frame(session_id: u16, error: bool) -> Vec<u8> {
    let option = if error {
        FrameOption::ERROR
    } else {
        FrameOption(0)
    };
    let mut out = Vec::with_capacity(8);
    match frame::encode_frame(
        &mut out,
        FrameSpec::new(session_id, SessionStatus::End).with_option(option),
    ) {
        Ok(()) => out,
        Err(_) => Vec::new(),
    }
}

/// Converts a socket address to the address form used in a reply frame.
pub(crate) fn socket_addr_to_location(address: SocketAddr) -> NetLocation {
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

/// Locks a mutex, recovering the value if a previous holder panicked.
///
/// A poisoned lock means another task panicked; continuing to release sockets
/// is safer than panicking a second time on a network path.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_MAX_GLOBAL_SESSIONS, ExpiringSession, ResolveError, Session, SessionTable,
        SocketFamily, XudpConfig, XudpConfigError, XudpSessionLimiter, encode_end_frame,
        reply_frame_len, resolve_destination, socket_addr_to_location,
    };
    use crate::address::{Address, NetLocation};
    use crate::xudp::frame::{
        FrameOption, FrameSpec, SessionStatus, TargetNetwork, encode_frame, parse_frame,
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::Instant;

    fn ipv4(port: u16) -> NetLocation {
        NetLocation {
            address: Address::Ipv4(Ipv4Addr::LOCALHOST),
            port,
        }
    }

    #[test]
    fn defaults_are_valid() {
        let config = XudpConfig::default();
        assert_eq!(config.max_sessions, 2048);
        assert_eq!(config.max_datagram_size, 8192);
        assert_eq!(config.session_idle_timeout, Duration::from_secs(300));
        assert_eq!(config.close_expiry, Duration::from_secs(60));
        assert!(config.max_queued_replies > 0);
        config.validate().expect("defaults must be valid");
    }

    #[test]
    fn rejects_invalid_limits() {
        let cases = [
            (
                XudpConfig {
                    max_sessions: 0,
                    ..XudpConfig::default()
                },
                XudpConfigError::MaxSessions,
            ),
            (
                XudpConfig {
                    max_sessions: usize::from(u16::MAX) + 2,
                    ..XudpConfig::default()
                },
                XudpConfigError::MaxSessions,
            ),
            (
                XudpConfig {
                    max_datagram_size: 0,
                    ..XudpConfig::default()
                },
                XudpConfigError::MaxDatagramSize,
            ),
            (
                XudpConfig {
                    max_datagram_size: 8193,
                    ..XudpConfig::default()
                },
                XudpConfigError::MaxDatagramSize,
            ),
            (
                XudpConfig {
                    session_idle_timeout: Duration::ZERO,
                    ..XudpConfig::default()
                },
                XudpConfigError::SessionIdleTimeout,
            ),
            (
                XudpConfig {
                    close_expiry: Duration::ZERO,
                    ..XudpConfig::default()
                },
                XudpConfigError::CloseExpiry,
            ),
            (
                XudpConfig {
                    max_queued_replies: 0,
                    ..XudpConfig::default()
                },
                XudpConfigError::MaxQueuedReplies,
            ),
            (
                XudpConfig {
                    io_timeout: Duration::ZERO,
                    ..XudpConfig::default()
                },
                XudpConfigError::IoTimeout,
            ),
        ];

        for (config, expected) in cases {
            assert_eq!(config.validate(), Err(expected));
        }
    }

    #[test]
    fn global_session_limiter_is_bounded() {
        let limiter = XudpSessionLimiter::new(1);
        let permit = limiter.try_acquire().expect("first slot must be available");
        assert!(
            limiter.try_acquire().is_none(),
            "the limit must reject a second slot"
        );
        drop(permit);
        assert!(
            limiter.try_acquire().is_some(),
            "a released slot must be reusable"
        );
        assert_eq!(limiter.max(), 1);
        assert_eq!(
            XudpSessionLimiter::default().max(),
            DEFAULT_MAX_GLOBAL_SESSIONS
        );
    }

    #[test]
    fn reply_frame_len_is_exact_for_both_families() {
        let sources = [
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 1234)),
        ];

        for source in sources {
            for payload_len in [0, 1, 64, 1200, 8192] {
                let frame_len = reply_frame_len(source, payload_len)
                    .expect("a bounded payload must have a frame length");
                let mut frame = Vec::new();
                frame
                    .try_reserve_exact(frame_len)
                    .expect("the test frame must fit in memory");
                let capacity = frame.capacity();
                let payload = vec![0_u8; payload_len];
                let source = socket_addr_to_location(source);
                let spec = FrameSpec {
                    session_id: 7,
                    status: SessionStatus::Keep,
                    option: FrameOption::DATA,
                    network: Some(TargetNetwork::Udp),
                    destination: Some(&source),
                    global_id: None,
                    payload: &payload,
                };

                encode_frame(&mut frame, spec).expect("a reply frame must encode");
                assert_eq!(
                    frame.len(),
                    frame_len,
                    "reply_frame_len must match encode_frame for {source:?} and {payload_len} bytes"
                );
                assert_eq!(
                    frame.capacity(),
                    capacity,
                    "an exact reservation must not grow while encoding"
                );
            }
        }

        assert!(reply_frame_len(SocketAddr::from(([127, 0, 0, 1], 1)), usize::MAX).is_none());
    }

    #[test]
    fn reply_queue_budget_is_process_wide() {
        let limiter = XudpSessionLimiter::new(1);
        let budget = limiter.reply_budget_bytes();
        let permit = limiter
            .try_reserve_reply(budget)
            .expect("the whole budget must be reservable");
        assert!(
            limiter.try_reserve_reply(1).is_none(),
            "the byte budget must reject one more byte"
        );
        drop(permit);
        assert!(
            limiter.try_reserve_reply(1).is_some(),
            "released reply bytes must be reusable"
        );
    }

    #[test]
    fn sweep_interval_is_bounded() {
        let config = XudpConfig {
            session_idle_timeout: Duration::from_micros(1),
            close_expiry: Duration::from_micros(1),
            ..XudpConfig::default()
        };
        assert!(config.sweep_interval() >= Duration::from_millis(10));

        let config = XudpConfig::default();
        assert_eq!(config.sweep_interval(), Duration::from_secs(1));
    }

    #[test]
    fn socket_family_binds_the_wildcard() {
        assert!(SocketFamily::V4.bind_address().is_ipv4());
        assert!(SocketFamily::V6.bind_address().is_ipv6());
        assert_eq!(SocketFamily::V4.bind_address().port(), 0);
        assert_eq!(SocketFamily::V6.bind_address().port(), 0);
        assert!(
            SocketFamily::of(SocketAddr::from((Ipv6Addr::LOCALHOST, 1)))
                .matches(SocketAddr::from((Ipv6Addr::LOCALHOST, 2)))
        );
    }

    #[test]
    fn converts_both_socket_families() {
        let v4 = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
        assert_eq!(
            socket_addr_to_location(v4),
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                port: 53,
            }
        );

        let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 443));
        assert_eq!(
            socket_addr_to_location(v6),
            NetLocation {
                address: Address::Ipv6(Ipv6Addr::LOCALHOST),
                port: 443,
            }
        );
    }

    #[test]
    fn end_frame_layout_is_clean_or_error() {
        let clean = encode_end_frame(7, false);
        assert_eq!(clean, [0x00, 0x04, 0x00, 0x07, 0x03, 0x00]);
        let (frame, used) = parse_frame(&clean)
            .expect("clean End must parse")
            .expect("clean End must be complete");
        assert_eq!(used, clean.len());
        assert_eq!(frame.status, SessionStatus::End);
        assert_eq!(frame.option, FrameOption(0));

        let error = encode_end_frame(7, true);
        assert_eq!(error, [0x00, 0x04, 0x00, 0x07, 0x03, 0x02]);
        let (frame, used) = parse_frame(&error)
            .expect("error End must parse")
            .expect("error End must be complete");
        assert_eq!(used, error.len());
        assert!(frame.option.has_error());
    }

    #[tokio::test]
    async fn resolves_ip_literals_and_rejects_port_zero() {
        assert_eq!(
            resolve_destination(&ipv4(53), None, Duration::from_secs(1))
                .await
                .expect("IPv4 literal"),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53))
        );

        assert!(matches!(
            resolve_destination(&ipv4(0), None, Duration::from_secs(1)).await,
            Err(ResolveError::Port)
        ));
        assert!(matches!(
            resolve_destination(&ipv4(53), Some(SocketFamily::V6), Duration::from_secs(1)).await,
            Err(ResolveError::FamilyMismatch)
        ));
    }

    #[tokio::test]
    async fn resolves_localhost_to_a_matching_family() {
        let any = resolve_destination(
            &NetLocation {
                address: Address::Domain("localhost".to_owned()),
                port: 9,
            },
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("localhost must resolve");
        assert_eq!(any.port(), 9);

        // The same domain can be resolved for an explicit family when the
        // system has an address of that family.
        let v4 = resolve_destination(
            &NetLocation {
                address: Address::Domain("localhost".to_owned()),
                port: 9,
            },
            Some(SocketFamily::V4),
            Duration::from_secs(5),
        )
        .await;
        if let Ok(address) = v4 {
            assert!(address.is_ipv4());
        }
    }

    #[tokio::test]
    async fn table_counts_active_and_retained_sessions() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("test socket"));
        let address = socket.local_addr().expect("test address");
        let session = Arc::new(Session::new(
            1,
            Some([7; 8]),
            Arc::clone(&socket),
            SocketFamily::V4,
            address,
            None,
        ));
        let mut table = SessionTable::default();
        assert_eq!(table.total(), 0);

        table.insert(super::ActiveSession {
            session: Arc::clone(&session),
            reply_task: None,
        });
        assert_eq!(table.total(), 1);
        assert!(!table.evict_oldest_expiring());

        let entry = super::ExpiringSession {
            socket,
            family: SocketFamily::V4,
            expires_at: tokio::time::Instant::now() + Duration::from_secs(1),
            permit: None,
        };
        table.insert_expiring([7; 8], entry);
        assert_eq!(table.total(), 2);
        assert!(table.take_expiring([7; 8]).is_some());
        assert_eq!(table.total(), 1);
    }

    #[tokio::test]
    async fn global_eviction_picks_the_oldest_retained_socket_across_streams() {
        let limiter = XudpSessionLimiter::new(2);
        let first = Arc::new(std::sync::Mutex::new(SessionTable::default()));
        let second = Arc::new(std::sync::Mutex::new(SessionTable::default()));
        limiter.register_table(&first);
        limiter.register_table(&second);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("test socket"));
        let now = Instant::now();
        first.lock().expect("first table").insert_expiring(
            [1; 8],
            ExpiringSession {
                socket: Arc::clone(&socket),
                family: SocketFamily::V4,
                expires_at: now + Duration::from_secs(20),
                permit: limiter.try_acquire(),
            },
        );
        second.lock().expect("second table").insert_expiring(
            [2; 8],
            ExpiringSession {
                socket,
                family: SocketFamily::V4,
                expires_at: now + Duration::from_secs(5),
                permit: limiter.try_acquire(),
            },
        );
        let permit = limiter
            .try_acquire_or_evict()
            .expect("evicting retained state must admit a live slot");
        drop(permit);
        assert_eq!(first.lock().expect("first table").total(), 1);
        assert_eq!(second.lock().expect("second table").total(), 0);
    }

    #[tokio::test]
    async fn idle_and_retained_sessions_expire() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("test socket"));
        let address = socket.local_addr().expect("test address");
        let session = Arc::new(Session::new(
            3,
            None,
            Arc::clone(&socket),
            SocketFamily::V4,
            address,
            None,
        ));
        let mut table = SessionTable::default();
        table.insert(super::ActiveSession {
            session: Arc::clone(&session),
            reply_task: None,
        });

        let now = tokio::time::Instant::now() + Duration::from_secs(10);
        let idle = table.take_idle(now, Duration::from_secs(5));
        assert_eq!(idle.len(), 1);
        assert_eq!(table.total(), 0);

        let entry = super::ExpiringSession {
            socket,
            family: SocketFamily::V4,
            expires_at: now,
            permit: None,
        };
        table.insert_expiring([9; 8], entry);
        assert_eq!(table.expire_retained(now), 1);
        assert_eq!(table.total(), 0);
    }
}
