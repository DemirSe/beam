//! Non-blocking UDP NAT bridge translating TUN IPv4/IPv6 UDP packets into
//! `beam-core` XUDP sessions and synthesizing IPv4/IPv6 UDP reply packets
//! (preserving full-cone source addresses).
//!
//! XUDP mux (re)connection runs in a background task so it never blocks the
//! main TUN packet loop or stalls active TCP flows.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use beam_core::address::{Address, NetLocation};
use beam_core::client::{
    BeamClientConfig, XudpClient, XudpClientConfig, XudpClientError, XudpSession,
};
use beam_core::xudp::MAX_PAYLOAD_LEN;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::packet::build_ip_udp_packet;
use crate::stats::DropCounters;

const DEFAULT_MAX_UDP_SESSIONS: usize = 256;
const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const PER_SESSION_SEND_QUEUE: usize = 32;
const MAX_PENDING_CONNECT_DATAGRAMS: usize = 64;
const INITIAL_CONNECT_BACKOFF_MS: u64 = 250;
const MAX_CONNECT_BACKOFF_MS: u64 = 10_000;

/// Tuning parameters for [`UdpNatBridge`].
#[derive(Clone, Copy, Debug)]
pub struct UdpBridgeConfig {
    /// Maximum concurrent `(src_ip, src_port)` NAT entries.
    pub max_sessions: usize,
    /// Idle expiry for a NAT session with no outbound or inbound traffic.
    pub idle_timeout: Duration,
}

impl Default for UdpBridgeConfig {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_UDP_SESSIONS,
            idle_timeout: DEFAULT_UDP_IDLE_TIMEOUT,
        }
    }
}

impl UdpBridgeConfig {
    /// Low-RAM always-on profile for Android `VpnService`: 128 NAT sessions
    /// with a 60 s idle expiry, so an idle phone holds no UDP timer wakeups.
    pub fn mobile() -> Self {
        Self {
            max_sessions: 128,
            idle_timeout: Duration::from_secs(60),
        }
    }
}

#[cfg(test)]
mod mobile_tests {
    use super::*;

    #[test]
    fn mobile_profile_bounds_sessions_and_expiry() {
        let cfg = UdpBridgeConfig::mobile();
        assert_eq!(cfg.max_sessions, 128);
        assert_eq!(cfg.idle_timeout, Duration::from_secs(60));
    }

    #[test]
    fn active_udp_session_guard_tracks_lifecycle() {
        let counter = Arc::new(AtomicU64::new(0));
        {
            let _g1 = ActiveUdpSessionGuard::enter(Some(&counter));
            assert_eq!(counter.load(Ordering::Relaxed), 1);
            {
                let _g2 = ActiveUdpSessionGuard::enter(Some(&counter));
                assert_eq!(counter.load(Ordering::Relaxed), 2);
            }
            assert_eq!(counter.load(Ordering::Relaxed), 1);
        }
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}

struct NatEntry {
    tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    last_active_ms: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

struct ActiveUdpSessionGuard {
    counter: Option<Arc<AtomicU64>>,
}

impl ActiveUdpSessionGuard {
    fn enter(counter: Option<&Arc<AtomicU64>>) -> Self {
        let counter = counter.map(|c| {
            c.fetch_add(1, Ordering::Relaxed);
            Arc::clone(c)
        });
        Self { counter }
    }
}

impl Drop for ActiveUdpSessionGuard {
    fn drop(&mut self) {
        if let Some(counter) = self.counter.as_ref() {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Bridges TUN UDP packets (IPv4 and IPv6) over a shared [`XudpClient`] mux,
/// reconnecting the mux asynchronously in the background if it closes.
pub struct UdpNatBridge {
    start: Instant,
    client_config: BeamClientConfig,
    bridge_config: UdpBridgeConfig,
    tun_tx: mpsc::Sender<Vec<u8>>,
    waker: Arc<Notify>,
    mux: Option<Arc<XudpClient>>,
    connecting: Option<oneshot::Receiver<Option<Arc<XudpClient>>>>,
    connect_task: Option<JoinHandle<()>>,
    connect_backoff_ms: u64,
    next_connect_allowed_ms: u64,
    pending_initial: VecDeque<(SocketAddr, SocketAddr, Vec<u8>)>,
    sessions: HashMap<SocketAddr, NatEntry>,
    drops: Arc<DropCounters>,
    active_sessions: Option<Arc<AtomicU64>>,
}

impl UdpNatBridge {
    /// Creates a new UDP NAT bridge that writes synthesized IPv4/IPv6 UDP reply
    /// packets into `tun_tx` and notifies `waker` when a background XUDP mux
    /// connect finishes.
    pub fn new(
        client_config: BeamClientConfig,
        bridge_config: UdpBridgeConfig,
        tun_tx: mpsc::Sender<Vec<u8>>,
        waker: Arc<Notify>,
        drops: Arc<DropCounters>,
    ) -> Self {
        Self::with_session_counter(client_config, bridge_config, tun_tx, waker, drops, None)
    }

    /// Creates a new UDP NAT bridge with an optional lock-free active session
    /// counter updated via an RAII guard on each session task.
    pub fn with_session_counter(
        client_config: BeamClientConfig,
        bridge_config: UdpBridgeConfig,
        tun_tx: mpsc::Sender<Vec<u8>>,
        waker: Arc<Notify>,
        drops: Arc<DropCounters>,
        active_sessions: Option<Arc<AtomicU64>>,
    ) -> Self {
        Self {
            start: Instant::now(),
            client_config,
            bridge_config,
            tun_tx,
            waker,
            mux: None,
            connecting: None,
            connect_task: None,
            connect_backoff_ms: 0,
            next_connect_allowed_ms: 0,
            pending_initial: VecDeque::with_capacity(MAX_PENDING_CONNECT_DATAGRAMS),
            sessions: HashMap::new(),
            drops,
            active_sessions,
        }
    }

    /// Aborts active XUDP mux & NAT sessions and clears reconnect backoff
    /// (called on network/gateway transitions or wake-from-sleep).
    pub fn reset(&mut self) {
        if let Some(handle) = self.connect_task.take() {
            handle.abort();
        }
        self.connecting = None;
        self.mux = None;
        self.connect_backoff_ms = 0;
        self.next_connect_allowed_ms = 0;
        if !self.pending_initial.is_empty() {
            self.drops
                .udp_pending_full
                .add(self.pending_initial.len() as u64);
            self.pending_initial.clear();
        }
        for (_, entry) in self.sessions.drain() {
            entry.task.abort();
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Polls any in-flight background XUDP mux connection, triggers a new
    /// connect attempt once reconnect backoff elapses while datagrams are
    /// queued, and flushes queued initial datagrams once connected.
    /// Non-blocking.
    pub fn poll_connect(&mut self) {
        if self.connecting.is_none() {
            if !self.pending_initial.is_empty() && self.mux.as_ref().is_none_or(|m| !m.is_open()) {
                self.mux = None;
                self.start_background_connect();
            }
            return;
        }
        let Some(rx) = self.connecting.as_mut() else {
            return;
        };
        match rx.try_recv() {
            Ok(Some(client)) => {
                self.mux = Some(client);
                self.connecting = None;
                self.connect_task = None;
                self.connect_backoff_ms = 0;
                self.next_connect_allowed_ms = 0;
                let queued = std::mem::take(&mut self.pending_initial);
                for (src, dst, payload) in queued {
                    self.handle_datagram(src, dst, &payload);
                }
            }
            Ok(None) | Err(oneshot::error::TryRecvError::Closed) => {
                self.connecting = None;
                self.connect_task = None;
                if !self.pending_initial.is_empty() {
                    self.drops
                        .udp_pending_full
                        .add(self.pending_initial.len() as u64);
                    self.pending_initial.clear();
                }
                let next_backoff = if self.connect_backoff_ms == 0 {
                    INITIAL_CONNECT_BACKOFF_MS
                } else {
                    (self.connect_backoff_ms * 2).min(MAX_CONNECT_BACKOFF_MS)
                };
                self.connect_backoff_ms = next_backoff;
                self.next_connect_allowed_ms = self.now_ms().saturating_add(next_backoff);
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
    }

    /// Handles one outbound UDP datagram from `src` to `dst` without blocking
    /// the TUN event loop.
    pub fn handle_datagram(&mut self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_LEN {
            self.drops.udp_payload_invalid.incr();
            return;
        }
        self.poll_connect();

        let now_ms = self.now_ms();
        if let Some(entry) = self.sessions.get_mut(&src) {
            if !entry.tx.is_closed() && !entry.task.is_finished() {
                entry.last_active_ms.store(now_ms, Ordering::Release);
                if entry.tx.try_send((dst, queued_payload(payload))).is_err() {
                    self.drops.udp_session_queue_full.incr();
                }
                return;
            }
            if let Some(dead) = self.sessions.remove(&src) {
                dead.task.abort();
            }
        }

        if self.sessions.len() >= self.bridge_config.max_sessions {
            self.sweep_idle();
            if self.sessions.len() >= self.bridge_config.max_sessions {
                self.drops.udp_session_table_full.incr();
                debug!(%src, "UDP NAT session table full; dropping datagram");
                return;
            }
        }

        let mux = match self.mux.as_ref() {
            Some(existing) if existing.is_open() => Arc::clone(existing),
            _ => {
                self.mux = None;
                self.start_background_connect();
                self.queue_pending(src, dst, payload);
                return;
            }
        };

        let first_dest = socket_to_netloc(dst);
        let mut session = match mux.open_session(first_dest) {
            Ok(session) => session,
            Err(err) => {
                debug!(%src, error = %err, "failed to open XUDP session");
                if !mux.is_open() {
                    self.mux = None;
                    self.start_background_connect();
                    self.queue_pending(src, dst, payload);
                } else if matches!(err, XudpClientError::OutboundQueueFull) {
                    self.drops.udp_mux_q.incr();
                } else {
                    self.drops.udp_session_table_full.incr();
                }
                return;
            }
        };

        let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(PER_SESSION_SEND_QUEUE);
        if tx.try_send((dst, queued_payload(payload))).is_err() {
            // The channel was just created with capacity, so this only happens
            // if it is already closed; count it like any other queue drop.
            self.drops.udp_session_queue_full.incr();
        }

        let tun_tx = self.tun_tx.clone();
        let task_drops = Arc::clone(&self.drops);
        let last_active_ms = Arc::new(AtomicU64::new(now_ms));
        let task_active = Arc::clone(&last_active_ms);
        let start = self.start;
        let session_guard = ActiveUdpSessionGuard::enter(self.active_sessions.as_ref());

        let task = tokio::spawn(async move {
            let _session_guard = session_guard;
            let mut last_dst = dst;
            // No idle timer here: `sweep_idle` expires the session and aborts
            // this task, so per-datagram timer churn is not needed.
            loop {
                tokio::select! {
                    maybe_out = rx.recv() => {
                        let Some((target, data)) = maybe_out else {
                            break;
                        };
                        if data.is_empty() || data.len() > MAX_PAYLOAD_LEN {
                            continue;
                        }
                        last_dst = target;
                        task_active.store(start.elapsed().as_millis() as u64, Ordering::Release);
                        // Never await the shared mux queue here: a full outbound
                        // queue would stop this task from draining inbound replies.
                        match session.try_send_owned(socket_to_netloc(target), data) {
                            Ok(()) => {}
                            Err(XudpClientError::OutboundQueueFull) => task_drops.udp_mux_q.incr(),
                            Err(err) => {
                                warn!(%target, error = %err, "xudp session send_to failed");
                                break;
                            }
                        }
                    }
                    maybe_reply = session.recv() => {
                        let Some(reply) = maybe_reply else {
                            break;
                        };
                        task_active.store(start.elapsed().as_millis() as u64, Ordering::Release);
                        let (src_ip, src_port) = match reply.source {
                            Some(NetLocation { address: Address::Ipv4(ip), port }) => (IpAddr::V4(ip), port),
                            Some(NetLocation { address: Address::Ipv6(ip), port }) => (IpAddr::V6(ip), port),
                            _ => (last_dst.ip(), last_dst.port()),
                        };
                        if let Some(pkt) = build_ip_udp_packet(
                            src_ip,
                            src_port,
                            src.ip(),
                            src.port(),
                            &reply.payload,
                        ) && tun_tx.try_send(pkt).is_err()
                        {
                            task_drops.tun_tx_full.incr();
                        }
                        sync_mux_drops(&session, &task_drops);
                    }
                }
            }
            sync_mux_drops(&session, &task_drops);
            let _ = session.close().await;
        });

        self.sessions.insert(
            src,
            NatEntry {
                tx,
                last_active_ms,
                task,
            },
        );
    }

    /// Queues one datagram for the next mux connect, dropping it (and counting
    /// the drop) when the bounded queue is full.
    fn queue_pending(&mut self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        if self.pending_initial.len() < MAX_PENDING_CONNECT_DATAGRAMS {
            self.pending_initial
                .push_back((src, dst, queued_payload(payload)));
        } else {
            self.drops.udp_pending_full.incr();
        }
    }

    /// Removes expired or finished NAT entries (checking both outbound and
    /// inbound activity timestamps).
    pub fn sweep_idle(&mut self) {
        let now_ms = self.now_ms();
        let idle_ms = self.bridge_config.idle_timeout.as_millis() as u64;
        self.sessions.retain(|_, entry| {
            let last = entry.last_active_ms.load(Ordering::Acquire);
            let alive = !entry.task.is_finished() && now_ms.saturating_sub(last) < idle_ms;
            if !alive {
                entry.task.abort();
            }
            alive
        });
        // Drop the shared XUDP mux as soon as all NAT sessions have expired
        // and nothing is queued so its reader/writer tasks and upstream socket
        // close at the NAT idle boundary instead of holding an idle timer.
        // A graceful close flushes queued frames and sends `close_notify` with
        // its own timeout; if another task still holds the Arc or no Tokio
        // runtime is active, dropping our ref falls back cleanly.
        if self.sessions.is_empty()
            && self.pending_initial.is_empty()
            && let Some(mux) = self.mux.take()
            && let Ok(client) = Arc::try_unwrap(mux)
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                client.close().await;
            });
        }
    }

    /// Runs one bounded idle sweep when a session is already finished or
    /// expired. The engine calls this once per tick before its biased select,
    /// so continuous TUN traffic cannot starve NAT cleanup.
    pub fn sweep_if_due(&mut self) -> bool {
        if self.next_sweep_delay_ms() == Some(0) {
            self.sweep_idle();
            return true;
        }
        false
    }

    /// Returns the next timer delay needed for idle UDP session sweeping or
    /// XUDP reconnect backoff retry when datagrams are queued, or `None` when
    /// idle (allowing the TUN engine to sleep with zero idle wakeups).
    pub fn next_sweep_delay_ms(&self) -> Option<u64> {
        let now_ms = self.now_ms();
        let idle_ms = self.bridge_config.idle_timeout.as_millis() as u64;
        // Single pass: a finished session task is reaped by the next sweep,
        // so it forces delay 0 instead of keeping its slot until idle
        // timeout. Otherwise track the earliest real expiry.
        let mut session_delay: Option<u64> = None;
        for entry in self.sessions.values() {
            if entry.task.is_finished() {
                return Some(0);
            }
            let last = entry.last_active_ms.load(Ordering::Acquire);
            let remaining = last.saturating_add(idle_ms).saturating_sub(now_ms);
            session_delay = Some(session_delay.map_or(remaining, |min| min.min(remaining)));
        }
        let backoff_delay = if !self.pending_initial.is_empty()
            && self.connecting.is_none()
            && self.mux.as_ref().is_none_or(|m| !m.is_open())
        {
            Some(self.next_connect_allowed_ms.saturating_sub(now_ms))
        } else {
            None
        };
        match (session_delay, backoff_delay) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        }
    }

    fn start_background_connect(&mut self) {
        if self.connecting.is_some() {
            return;
        }
        if self.now_ms() < self.next_connect_allowed_ms {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let client_cfg = self.client_config.clone();
        let xudp_cfg = XudpClientConfig {
            max_sessions: self.bridge_config.max_sessions,
            ..XudpClientConfig::default()
        };
        let waker = Arc::clone(&self.waker);
        let handle = tokio::spawn(async move {
            let result = match XudpClient::connect(&client_cfg, xudp_cfg).await {
                Ok(client) => Some(Arc::new(client)),
                Err(err) => {
                    warn!(error = %err, "failed to connect XUDP mux to beam server");
                    None
                }
            };
            let _ = tx.send(result);
            waker.notify_one();
        });
        self.connecting = Some(rx);
        self.connect_task = Some(handle);
    }
}

impl Drop for UdpNatBridge {
    fn drop(&mut self) {
        if let Some(handle) = self.connect_task.take() {
            handle.abort();
        }
        for (_, entry) in self.sessions.drain() {
            entry.task.abort();
        }
    }
}

/// Copies one datagram into a queue buffer with XUDP frame-header headroom so
/// `XudpSession::send_owned` can prepend the header without a second allocation.
fn queued_payload(payload: &[u8]) -> Vec<u8> {
    let mut buf = XudpSession::alloc_payload(payload.len());
    buf.extend_from_slice(payload);
    buf
}

/// Moves the mux-level reply drops observed for this session into `udp_mux_q`.
fn sync_mux_drops(session: &XudpSession, drops: &DropCounters) {
    let dropped = session.take_dropped_replies();
    if dropped > 0 {
        drops.udp_mux_q.add(dropped);
    }
}

fn socket_to_netloc(addr: SocketAddr) -> NetLocation {
    let address = match addr.ip() {
        IpAddr::V4(v4) => Address::Ipv4(v4),
        IpAddr::V6(v6) => Address::Ipv6(v6),
    };
    NetLocation {
        address,
        port: addr.port(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn dummy_drops() -> Arc<DropCounters> {
        Arc::new(DropCounters::default())
    }

    fn dummy_client_config() -> BeamClientConfig {
        let reality = beam_core::reality::RealityClientConfig::new(
            [1u8; 32],
            "0123456789abcdef",
            "whatsapp.net",
        )
        .expect("reality");
        BeamClientConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            reality,
            [2u8; 16],
        )
    }

    fn insert_fake_entry(
        bridge: &mut UdpNatBridge,
        src: SocketAddr,
        last_active_ms: u64,
    ) -> mpsc::Receiver<(SocketAddr, Vec<u8>)> {
        let (tx, rx) = mpsc::channel(PER_SESSION_SEND_QUEUE);
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        bridge.sessions.insert(
            src,
            NatEntry {
                tx,
                last_active_ms: Arc::new(AtomicU64::new(last_active_ms)),
                task,
            },
        );
        rx
    }

    #[tokio::test]
    async fn next_sweep_delay_reaps_a_finished_session_task_at_once() {
        let (tun_tx, _tun_rx) = mpsc::channel(8);
        let mut bridge = UdpNatBridge::new(
            dummy_client_config(),
            UdpBridgeConfig {
                max_sessions: 4,
                idle_timeout: Duration::from_secs(60),
            },
            tun_tx,
            Arc::new(Notify::new()),
            dummy_drops(),
        );

        // A session task that already exited must not linger for 60s.
        let task = tokio::spawn(async {});
        for _ in 0..8 {
            if task.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            task.is_finished(),
            "short-lived session task did not finish"
        );
        let (tx, _rx) = mpsc::channel(PER_SESSION_SEND_QUEUE);
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 40_100);
        bridge.sessions.insert(
            src,
            NatEntry {
                tx,
                last_active_ms: Arc::new(AtomicU64::new(bridge.now_ms())),
                task,
            },
        );
        assert_eq!(
            bridge.next_sweep_delay_ms(),
            Some(0),
            "a finished session task must schedule an immediate sweep"
        );
        bridge.sweep_idle();
        assert!(bridge.sessions.is_empty(), "the finished session is reaped");
    }

    #[tokio::test]
    async fn zero_delay_sweep_runs_inline_even_when_the_device_stays_ready() {
        let (tun_tx, _tun_rx) = mpsc::channel(8);
        let mut bridge = UdpNatBridge::new(
            dummy_client_config(),
            UdpBridgeConfig::default(),
            tun_tx,
            Arc::new(Notify::new()),
            dummy_drops(),
        );
        let task = tokio::spawn(async {});
        for _ in 0..8 {
            if task.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(task.is_finished(), "the fake session task must finish");
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_100);
        let (tx, _rx) = mpsc::channel(PER_SESSION_SEND_QUEUE);
        bridge.sessions.insert(
            src,
            NatEntry {
                tx,
                last_active_ms: Arc::new(AtomicU64::new(bridge.now_ms())),
                task,
            },
        );
        assert_eq!(bridge.next_sweep_delay_ms(), Some(0));

        let mut sweeps = 0;
        for _ in 0..3 {
            if bridge.sweep_if_due() {
                sweeps += 1;
            }
            // A continuously ready device branch wins this biased select, as
            // it does on a busy tunnel; cleanup already ran before it.
            tokio::select! {
                biased;
                _ = std::future::ready(()) => {}
            }
        }
        assert_eq!(sweeps, 1, "one tick may sweep at most once");
        assert!(bridge.sessions.is_empty(), "finished session was reaped");
    }

    #[tokio::test]
    async fn next_sweep_delay_ms_tracks_the_earliest_session_expiry() {
        let (tun_tx, _tun_rx) = mpsc::channel(8);
        let waker = Arc::new(Notify::new());
        let mut bridge = UdpNatBridge::new(
            dummy_client_config(),
            UdpBridgeConfig {
                max_sessions: 4,
                idle_timeout: Duration::from_secs(60),
            },
            tun_tx,
            Arc::clone(&waker),
            dummy_drops(),
        );
        assert_eq!(
            bridge.next_sweep_delay_ms(),
            None,
            "idle bridge must not wake"
        );

        // A fresh session must schedule its real 60s expiry, not a 10s clamp.
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 40_000);
        // Pretend the bridge has been up for 70s so session ages are meaningful.
        bridge.start = Instant::now() - Duration::from_secs(70);
        let now_ms = bridge.now_ms();
        let _rx = insert_fake_entry(&mut bridge, src, now_ms);
        let delay = bridge
            .next_sweep_delay_ms()
            .expect("an active session schedules a sweep");
        assert!(
            (59_000..=60_000).contains(&delay),
            "expected about 60000ms (unclamped), got {delay}ms"
        );

        // An older session shortens the delay to its own expiry.
        let older = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 40_001);
        let _rx_older = insert_fake_entry(&mut bridge, older, now_ms.saturating_sub(5_000));
        let delay = bridge
            .next_sweep_delay_ms()
            .expect("the earliest expiry wins");
        assert!(
            (54_000..=55_000).contains(&delay),
            "expected about 55000ms, got {delay}ms"
        );

        // A session that is already past its idle timeout reports zero delay so
        // the sweep runs on the next engine iteration.
        let expired = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 40_002);
        let _rx_expired = insert_fake_entry(&mut bridge, expired, 0);
        assert_eq!(bridge.next_sweep_delay_ms(), Some(0));
    }

    #[tokio::test]
    async fn handle_datagram_skips_sweep_on_fast_path_and_sweeps_lazily_at_capacity() {
        let (tun_tx, _tun_rx) = mpsc::channel(8);
        let waker = Arc::new(Notify::new());
        let mut bridge = UdpNatBridge::new(
            dummy_client_config(),
            UdpBridgeConfig {
                max_sessions: 2,
                idle_timeout: Duration::from_millis(20),
            },
            tun_tx,
            waker,
            dummy_drops(),
        );

        let src_active = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 50_001);
        let src_expired = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 50_002);
        let src_new = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 50_003);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);

        // Ensure `now_ms()` exceeds `idle_timeout` so `last_active_ms = 0` is expired.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let now_ms = bridge.now_ms();
        let mut rx_active = insert_fake_entry(&mut bridge, src_active, now_ms);
        let _rx_expired = insert_fake_entry(&mut bridge, src_expired, 0);
        assert_eq!(bridge.sessions.len(), 2);

        // Steady-state packet for an existing session stays O(1) and does NOT sweep.
        bridge.handle_datagram(src_active, dst, b"ping");
        let (got_dst, got_payload) = rx_active.try_recv().expect("forwarded to existing session");
        assert_eq!(got_dst, dst);
        assert_eq!(got_payload, b"ping");
        assert_eq!(
            bridge.sessions.len(),
            2,
            "fast path must not run O(N) sweep_idle on every datagram"
        );

        // New source at capacity triggers lazy sweep, reclaiming `src_expired`
        // and allowing the new datagram past the capacity gate.
        bridge.handle_datagram(src_new, dst, b"new-flow");
        assert_eq!(
            bridge.sessions.len(),
            1,
            "lazy sweep at capacity must reclaim expired entry"
        );
        assert!(bridge.sessions.contains_key(&src_active));
        assert!(!bridge.sessions.contains_key(&src_expired));
        assert_eq!(
            bridge.pending_initial.len(),
            1,
            "new datagram should be queued after reclaiming expired slot"
        );

        // When all slots are genuinely active (non-expired), a new source is dropped.
        let src_active2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 50_004);
        let src_dropped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 50_005);
        let active2_ms = bridge.now_ms();
        let _rx_active2 = insert_fake_entry(&mut bridge, src_active2, active2_ms);
        bridge.pending_initial.clear();
        bridge.handle_datagram(src_dropped, dst, b"overflow");
        assert_eq!(bridge.sessions.len(), 2);
        assert!(
            bridge.pending_initial.is_empty(),
            "datagram must be dropped when table remains full after lazy sweep"
        );
    }

    #[tokio::test]
    async fn backoff_queues_datagrams_reports_remaining_delay_and_retries_after_expiry() {
        let (tun_tx, _tun_rx) = mpsc::channel(8);
        let waker = Arc::new(Notify::new());
        let mut bridge = UdpNatBridge::new(
            dummy_client_config(),
            UdpBridgeConfig {
                max_sessions: 4,
                idle_timeout: Duration::from_secs(5),
            },
            tun_tx,
            waker,
            dummy_drops(),
        );

        // Simulate a failed initial XUDP connect to enter reconnect backoff.
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(None);
        bridge.connecting = Some(rx);
        bridge.poll_connect();
        assert_eq!(bridge.connect_backoff_ms, INITIAL_CONNECT_BACKOFF_MS);
        assert!(bridge.next_connect_allowed_ms > bridge.now_ms());
        assert_eq!(
            bridge.next_sweep_delay_ms(),
            None,
            "idle bridge in backoff with no queued datagrams must not wake"
        );

        // Incoming datagram during backoff must be queued rather than dropped.
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 51_001);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        bridge.handle_datagram(src, dst, b"queued-during-backoff");
        assert!(bridge.connecting.is_none());
        assert_eq!(bridge.pending_initial.len(), 1);
        let delay = bridge
            .next_sweep_delay_ms()
            .expect("queued datagram during backoff must schedule retry wakeup");
        assert!(
            delay <= INITIAL_CONNECT_BACKOFF_MS,
            "delay {delay}ms should not exceed backoff window"
        );

        // With an active session whose sweep interval is 5_000ms, the shorter
        // backoff delay must still win.
        let active_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 51_002);
        let now_ms = bridge.now_ms();
        let _rx = insert_fake_entry(&mut bridge, active_src, now_ms);
        let combined_delay = bridge
            .next_sweep_delay_ms()
            .expect("active session + backoff delay");
        assert!(
            combined_delay <= INITIAL_CONNECT_BACKOFF_MS,
            "backoff delay ({combined_delay}ms) must take precedence over 5000ms session sweep"
        );

        // Once backoff elapses, `poll_connect()` must automatically start a
        // background reconnect while keeping the queued datagram for flushing.
        bridge.next_connect_allowed_ms = bridge.now_ms();
        bridge.poll_connect();
        assert!(
            bridge.connecting.is_some(),
            "poll_connect must trigger background connect after backoff expires"
        );
        assert_eq!(bridge.pending_initial.len(), 1);
    }

    #[tokio::test]
    async fn drop_counters_track_payload_queue_table_and_pending_drops() {
        let (tun_tx, _tun_rx) = mpsc::channel(8);
        let waker = Arc::new(Notify::new());
        let drops = dummy_drops();
        let mut bridge = UdpNatBridge::new(
            dummy_client_config(),
            UdpBridgeConfig {
                max_sessions: 1,
                idle_timeout: Duration::from_secs(60),
            },
            tun_tx,
            waker,
            Arc::clone(&drops),
        );

        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 60_001);

        // Empty and oversize payloads are rejected and counted.
        bridge.handle_datagram(src, dst, b"");
        bridge.handle_datagram(src, dst, &vec![0u8; MAX_PAYLOAD_LEN + 1]);
        assert_eq!(drops.snapshot().udp_payload_invalid, 2);

        // A session whose queue is already full drops the datagram.
        let (tx, _rx) = mpsc::channel(1);
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        tx.try_send((dst, vec![1u8])).expect("fill session queue");
        bridge.sessions.insert(
            src,
            NatEntry {
                tx,
                last_active_ms: Arc::new(AtomicU64::new(bridge.now_ms())),
                task,
            },
        );
        bridge.handle_datagram(src, dst, b"queue-full");
        assert_eq!(drops.snapshot().udp_session_queue_full, 1);

        // The table is bounded: a second source with no mux is dropped after the
        // lazy sweep cannot reclaim the live session.
        let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 60_002);
        bridge.handle_datagram(other, dst, b"table-full");
        assert_eq!(drops.snapshot().udp_session_table_full, 1);

        // Clearing the pending queue during a failed reconnect is counted.
        bridge.sessions.clear();
        bridge.handle_datagram(other, dst, b"pending");
        let queued = bridge.pending_initial.len();
        assert_eq!(queued, 1, "a datagram queued while offline stays pending");
        let pending_drops_before = drops.snapshot().udp_pending_full;
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(None);
        bridge.connecting = Some(rx);
        bridge.poll_connect();
        assert!(
            bridge.pending_initial.is_empty(),
            "a failed connect must clear the pending queue"
        );
        assert!(
            drops.snapshot().udp_pending_full >= pending_drops_before + queued as u64,
            "every cleared pending datagram must be counted"
        );
    }

    #[tokio::test]
    async fn backoff_queue_is_bounded_by_max_pending_connect_datagrams() {
        let (tun_tx, _tun_rx) = mpsc::channel(8);
        let waker = Arc::new(Notify::new());
        let mut bridge = UdpNatBridge::new(
            dummy_client_config(),
            UdpBridgeConfig::default(),
            tun_tx,
            waker,
            dummy_drops(),
        );

        // Hold bridge in backoff so no background connect spawns.
        bridge.connect_backoff_ms = MAX_CONNECT_BACKOFF_MS;
        bridge.next_connect_allowed_ms = bridge.now_ms().saturating_add(60_000);

        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        for i in 0..(MAX_PENDING_CONNECT_DATAGRAMS + 25) {
            let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)), 52_000 + i as u16);
            bridge.handle_datagram(src, dst, format!("pkt-{i}").as_bytes());
        }

        assert!(bridge.connecting.is_none());
        assert_eq!(bridge.pending_initial.len(), MAX_PENDING_CONNECT_DATAGRAMS);
        assert_eq!(bridge.pending_initial[0].2, b"pkt-0");
        assert_eq!(
            bridge.pending_initial[MAX_PENDING_CONNECT_DATAGRAMS - 1].2,
            format!("pkt-{}", MAX_PENDING_CONNECT_DATAGRAMS - 1).as_bytes()
        );
    }
}
