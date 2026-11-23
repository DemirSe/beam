//! UDP NAT bridge translating TUN IPv4/IPv6 UDP packets into `beam-core` XUDP
//! sessions and synthesizing IPv4/IPv6 UDP reply packets (preserving full-cone
//! source addresses).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use beam_core::address::{Address, NetLocation};
use beam_core::client::{BeamClientConfig, XudpClient, XudpClientConfig};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::packet::build_ip_udp_packet;

const DEFAULT_MAX_UDP_SESSIONS: usize = 256;
const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const PER_SESSION_SEND_QUEUE: usize = 32;

/// Tuning parameters for [`UdpNatBridge`].
#[derive(Clone, Copy, Debug)]
pub struct UdpBridgeConfig {
    /// Maximum concurrent `(src_ip, src_port)` NAT entries.
    pub max_sessions: usize,
    /// Idle expiry for a NAT session with no traffic.
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
    last_active: Instant,
    task: JoinHandle<()>,
}

/// Bridges TUN UDP packets (IPv4 and IPv6) over a shared [`XudpClient`] mux,
/// reconnecting the mux automatically if it closes.
pub struct UdpNatBridge {
    client_config: BeamClientConfig,
    bridge_config: UdpBridgeConfig,
    tun_tx: mpsc::Sender<Vec<u8>>,
    mux: Option<Arc<XudpClient>>,
    sessions: HashMap<SocketAddr, NatEntry>,
}

impl UdpNatBridge {
    /// Creates a new UDP NAT bridge that writes synthesized IPv4/IPv6 UDP reply
    /// packets into `tun_tx`.
    pub fn new(
        client_config: BeamClientConfig,
        bridge_config: UdpBridgeConfig,
        tun_tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            client_config,
            bridge_config,
            tun_tx,
            mux: None,
            sessions: HashMap::new(),
        }
    }

    /// Handles one outbound UDP datagram from `src` to `dst`.
    pub async fn handle_datagram(&mut self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        self.sweep_idle();

        if let Some(entry) = self.sessions.get_mut(&src) {
            if !entry.tx.is_closed() {
                entry.last_active = Instant::now();
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

        let mux = match self.ensure_mux().await {
            Some(mux) => mux,
            None => return,
        };

        let first_dest = socket_to_netloc(dst);
        let mut session = match mux.open_session(first_dest) {
            Ok(session) => session,
            Err(err) => {
                debug!(%src, error = %err, "failed to open XUDP session");
                return;
            }
        };

        let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(PER_SESSION_SEND_QUEUE);
        let _ = tx.try_send((dst, payload.to_vec()));

        let tun_tx = self.tun_tx.clone();
        let idle = self.bridge_config.idle_timeout;
        let task = tokio::spawn(async move {
            let mut last_dst = dst;
            loop {
                tokio::select! {
                    maybe_out = rx.recv() => {
                        let Some((target, data)) = maybe_out else {
                            break;
                        };
                        last_dst = target;
                        if session.send_to(socket_to_netloc(target), &data).await.is_err() {
                            break;
                        }
                    }
                    maybe_reply = session.recv() => {
                        let Some(reply) = maybe_reply else {
                            break;
                        };
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
                last_active: Instant::now(),
                task,
            },
        );
    }

    /// Removes expired or finished NAT entries.
    pub fn sweep_idle(&mut self) {
        let now = Instant::now();
        let idle = self.bridge_config.idle_timeout;
        self.sessions.retain(|_, entry| {
            let alive = !entry.task.is_finished() && now.duration_since(entry.last_active) < idle;
            if !alive {
                entry.task.abort();
            }
            alive
        });
    }

    async fn ensure_mux(&mut self) -> Option<Arc<XudpClient>> {
        if let Some(existing) = self.mux.as_ref()
            && existing.is_open()
        {
            return Some(Arc::clone(existing));
        }

        let xudp_cfg = XudpClientConfig {
            max_sessions: self.bridge_config.max_sessions,
            ..XudpClientConfig::default()
        };
        match XudpClient::connect(&self.client_config, xudp_cfg).await {
            Ok(client) => {
                let arc = Arc::new(client);
                self.mux = Some(Arc::clone(&arc));
                Some(arc)
            }
            Err(err) => {
                warn!(error = %err, "failed to connect XUDP mux to beam server");
                self.mux = None;
                None
            }
        }
    }
}

impl Drop for UdpNatBridge {
    fn drop(&mut self) {
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
