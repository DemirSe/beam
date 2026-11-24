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
use beam_core::client::{BeamClientConfig, XudpClient, XudpClientConfig};
use beam_core::xudp::MAX_PAYLOAD_LEN;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::packet::build_ip_udp_packet;

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

struct NatEntry {
    tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    last_active_ms: Arc<AtomicU64>,
    task: JoinHandle<()>,
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
        self.pending_initial.clear();
        for (_, entry) in self.sessions.drain() {
            entry.task.abort();
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Polls any in-flight background XUDP mux connection and flushes queued
    /// initial datagrams once connected. Non-blocking.
    pub fn poll_connect(&mut self) {
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
                self.pending_initial.clear();
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
            return;
        }
        self.poll_connect();
        self.sweep_idle();

        let now_ms = self.now_ms();
        if let Some(entry) = self.sessions.get_mut(&src) {
            if !entry.tx.is_closed() && !entry.task.is_finished() {
                entry.last_active_ms.store(now_ms, Ordering::Release);
                let _ = entry.tx.try_send((dst, payload.to_vec()));
                return;
            }
            if let Some(dead) = self.sessions.remove(&src) {
                dead.task.abort();
            }
        }

        if self.sessions.len() >= self.bridge_config.max_sessions {
            debug!(%src, "UDP NAT session table full; dropping datagram");
            return;
        }

        let mux = match self.mux.as_ref() {
            Some(existing) if existing.is_open() => Arc::clone(existing),
            _ => {
                self.mux = None;
                self.start_background_connect();
                if self.connecting.is_some()
                    && self.pending_initial.len() < MAX_PENDING_CONNECT_DATAGRAMS
                {
                    self.pending_initial.push_back((src, dst, payload.to_vec()));
                }
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
                    if self.pending_initial.len() < MAX_PENDING_CONNECT_DATAGRAMS {
                        self.pending_initial.push_back((src, dst, payload.to_vec()));
                    }
                }
                return;
            }
        };

        let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(PER_SESSION_SEND_QUEUE);
        let _ = tx.try_send((dst, payload.to_vec()));

        let tun_tx = self.tun_tx.clone();
        let idle = self.bridge_config.idle_timeout;
        let last_active_ms = Arc::new(AtomicU64::new(now_ms));
        let task_active = Arc::clone(&last_active_ms);
        let start = self.start;

        let task = tokio::spawn(async move {
            let mut last_dst = dst;
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
                        if let Err(err) = session.send_to(socket_to_netloc(target), &data).await {
                            warn!(%target, error = %err, "xudp session send_to failed");
                            break;
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
                        ) {
                            let _ = tun_tx.try_send(pkt);
                        }
                    }
                    () = tokio::time::sleep(idle) => {
                        break;
                    }
                }
            }
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
