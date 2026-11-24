//! Main async TUN engine loop connecting [`TunDevice`], [`RoutePolicy`],
//! [`NetStack`], `beam_core::client::dial_tcp`, and [`UdpNatBridge`].

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use beam_core::address::{Address, NetLocation};
use beam_core::client::{BeamClientConfig, dial_tcp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::{sleep, timeout};
use tracing::{debug, info};

use crate::device::TunDevice;
use crate::dns::{DnsConfig, DnsInterceptor};
use crate::packet::{build_icmp_port_unreachable, build_tcp_rst_for_packet, parse_ip, parse_udp};
use crate::router::{RouteDecision, RoutePolicy};
use crate::stack::{AcceptedTcpStream, NetStack};
use crate::udp::{UdpBridgeConfig, UdpNatBridge};

const MAX_PACKET_BUF: usize = 65_536;
const TUN_TX_CHANNEL_CAP: usize = 512;
const RX_BATCH_MAX: usize = 128;
const C2S_COALESCE_TARGET: usize = 64 * 1024;
const S2C_READ_BUF_BYTES: usize = 64 * 1024;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Configuration for [`run_tun_engine`].
#[derive(Clone, Debug)]
pub struct TunEngineConfig {
    /// Upstream `beam` server client configuration.
    pub client: BeamClientConfig,
    /// Packet routing policy (LAN bypass, `reject_quic`, excluded server IP).
    pub route: RoutePolicy,
    /// Maximum concurrent proxied TCP connections.
    pub max_tcp_connections: usize,
    /// UDP NAT bridge configuration.
    pub udp: UdpBridgeConfig,
    /// Optional built-in DNS interceptor (DoH / plain DNS + local suffix split).
    pub dns: Option<DnsConfig>,
    /// Optional generation counter incremented on network/gateway switches or
    /// wake-from-sleep to reset active TCP flows (`RST`), XUDP mux, and local DNS.
    pub network_reset: Option<watch::Receiver<u64>>,
}

/// Lock-free tracker of recent tunnel dial liveness and RTT.
///
/// Updated on every successful upstream `dial_tcp` handshake so health
/// monitors can observe live tunnel liveness without extra probes.
#[derive(Debug)]
pub struct TunnelActivity {
    origin: Instant,
    /// Elapsed milliseconds since `origin` + 1 (`0` means no dial recorded yet).
    last_success_ms_plus_one: AtomicU64,
    /// Last recorded dial RTT in milliseconds.
    last_rtt_ms: AtomicU64,
}

impl TunnelActivity {
    /// Creates an empty [`TunnelActivity`] tracker with no recorded dials.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_success_ms_plus_one: AtomicU64::new(0),
            last_rtt_ms: AtomicU64::new(0),
        }
    }

    /// Records a successful upstream tunnel dial with its observed RTT in ms.
    pub fn record_dial_success(&self, rtt_ms: u64) {
        let elapsed_ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        self.last_rtt_ms.store(rtt_ms, Ordering::Relaxed);
        self.last_success_ms_plus_one
            .store(elapsed_ms.saturating_add(1), Ordering::Release);
    }

    /// Returns the most recently recorded dial RTT in ms if a dial succeeded
    /// within `max_age`, or `None` otherwise.
    pub fn recent_rtt(&self, max_age: Duration) -> Option<u64> {
        let recorded = self.last_success_ms_plus_one.load(Ordering::Acquire);
        if recorded == 0 {
            return None;
        }
        let recorded_ms = recorded - 1;
        let now_ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let age_ms = now_ms.saturating_sub(recorded_ms);
        let max_age_ms = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
        if age_ms <= max_age_ms {
            Some(self.last_rtt_ms.load(Ordering::Relaxed))
        } else {
            None
        }
    }
}

impl Default for TunnelActivity {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors returned by [`run_tun_engine`].
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Underlying TUN device I/O error.
    #[error("TUN device I/O error: {0}")]
    Device(#[from] io::Error),
}

/// Runs the TUN packet engine until `shutdown` becomes `true` or the TUN device
/// returns an error/EOF.
pub async fn run_tun_engine<D, S>(
    device: D,
    stack: S,
    config: TunEngineConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<(), EngineError>
where
    D: TunDevice,
    S: NetStack,
{
    run_tun_engine_with_activity(device, stack, config, shutdown, None).await
}

/// Runs the TUN packet engine with an optional [`TunnelActivity`] tracker that
/// records upstream dial RTTs on every successful `dial_tcp`.
pub async fn run_tun_engine_with_activity<D, S>(
    mut device: D,
    mut stack: S,
    config: TunEngineConfig,
    mut shutdown: watch::Receiver<bool>,
    activity: Option<Arc<TunnelActivity>>,
) -> Result<(), EngineError>
where
    D: TunDevice,
    S: NetStack,
{
    let start = Instant::now();
    let stack_waker = stack.waker();
    let tcp_permits = Arc::new(Semaphore::new(config.max_tcp_connections.max(1)));
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(TUN_TX_CHANNEL_CAP);
    let mut udp_bridge = UdpNatBridge::new(
        config.client.clone(),
        config.udp,
        tun_tx.clone(),
        Arc::clone(&stack_waker),
    );
    let dns_interceptor = config
        .dns
        .as_ref()
        .map(|dns_cfg| DnsInterceptor::new(config.client.clone(), dns_cfg.clone(), tun_tx.clone()));
    let mut network_reset = config.network_reset.clone();

    let mut recv_buf = vec![0u8; device.mtu().clamp(2048, MAX_PACKET_BUF)];
    let mut tx_batch: Vec<Vec<u8>> = Vec::with_capacity(64);
    let mut accepted: Vec<AcceptedTcpStream> = Vec::with_capacity(16);
    let mut next_udp_sweep_at: Option<Instant> = None;

    info!(
        mtu = device.mtu(),
        max_tcp = config.max_tcp_connections,
        max_udp = config.udp.max_sessions,
        reject_quic = config.route.reject_quic,
        "beam-tun engine started"
    );

    loop {
        if *shutdown.borrow() {
            break;
        }

        let now_ms = start.elapsed().as_millis() as i64;
        udp_bridge.poll_connect();
        stack.poll(now_ms, &mut tx_batch, &mut accepted);

        for pkt in tx_batch.drain(..) {
            if let Err(err) = device.send(&pkt).await {
                return Err(EngineError::Device(err));
            }
        }

        for conn in accepted.drain(..) {
            spawn_tcp_relay(
                conn,
                config.client.clone(),
                Arc::clone(&tcp_permits),
                network_reset.clone(),
                activity.clone(),
            );
        }

        // Drain any pending UDP/ICMP reply packets immediately.
        while let Ok(pkt) = tun_rx.try_recv() {
            if let Err(err) = device.send(&pkt).await {
                return Err(EngineError::Device(err));
            }
        }

        let tcp_delay = stack.poll_delay_ms(start.elapsed().as_millis() as i64);
        let udp_delay = match udp_bridge.next_sweep_delay_ms() {
            Some(interval_ms) => {
                let now = Instant::now();
                let deadline = *next_udp_sweep_at
                    .get_or_insert_with(|| now + Duration::from_millis(interval_ms));
                Some(deadline.saturating_duration_since(now).as_millis() as u64)
            }
            None => {
                next_udp_sweep_at = None;
                None
            }
        };
        let next_timer_ms = match (tcp_delay, udp_delay) {
            (Some(a), Some(b)) => Some(a.min(b).max(1)),
            (Some(a), None) | (None, Some(a)) => Some(a.max(1)),
            (None, None) => None,
        };

        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            Ok(()) = async {
                match network_reset.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                let generation = network_reset.as_ref().map(|rx| *rx.borrow()).unwrap_or(0);
                info!(generation, "network transition detected; resetting TCP flows, XUDP mux, and local DNS cache");
                stack.reset_all(&mut tx_batch);
                for pkt in tx_batch.drain(..) {
                    if let Err(err) = device.send(&pkt).await {
                        return Err(EngineError::Device(err));
                    }
                }
                udp_bridge.reset();
                if let Some(dns) = dns_interceptor.as_ref() {
                    dns.on_network_change();
                }
            }
            Some(reply_pkt) = tun_rx.recv() => {
                device.send(&reply_pkt).await?;
            }
            read_res = device.recv(&mut recv_buf) => {
                let mut n = read_res?;
                for batch_idx in 0..RX_BATCH_MAX {
                    if n > 0 {
                        let raw = &recv_buf[..n];
                        if let Some(ip) = parse_ip(raw) {
                            match config.route.classify(&ip) {
                                RouteDecision::ProxyTcp => {
                                    stack.push_ip_tcp(ip.raw);
                                }
                                RouteDecision::ProxyUdp => {
                                    if let Some(udp) = parse_udp(ip.payload) {
                                        let src = SocketAddr::new(ip.src_ip, udp.src_port);
                                        let dst = SocketAddr::new(ip.dst_ip, udp.dst_port);
                                        udp_bridge.handle_datagram(src, dst, udp.payload);
                                    }
                                }
                                RouteDecision::InterceptDns => {
                                    if let Some(udp) = parse_udp(ip.payload) {
                                        let src = SocketAddr::new(ip.src_ip, udp.src_port);
                                        let dst = SocketAddr::new(ip.dst_ip, udp.dst_port);
                                        if let Some(dns) = dns_interceptor.as_ref() {
                                            dns.handle_query(src, dst, udp.payload);
                                        } else {
                                            udp_bridge.handle_datagram(src, dst, udp.payload);
                                        }
                                    }
                                }
                                RouteDecision::RejectTcpRst => {
                                    if let Some(rst) = build_tcp_rst_for_packet(&ip) {
                                        let _ = tun_tx.try_send(rst);
                                    }
                                }
                                RouteDecision::RejectIcmpUnreachable => {
                                    if let Some(icmp) = build_icmp_port_unreachable(&ip) {
                                        let _ = tun_tx.try_send(icmp);
                                    }
                                }
                                RouteDecision::Drop => {}
                            }
                        }
                    }
                    if batch_idx + 1 == RX_BATCH_MAX {
                        break;
                    }
                    match device.try_recv_into(&mut recv_buf) {
                        Ok(Some(next_n)) => n = next_n,
                        Ok(None) => break,
                        Err(err) => return Err(EngineError::Device(err)),
                    }
                }
            }
            () = stack_waker.notified() => {}
            () = async {
                match next_timer_ms {
                    Some(ms) => sleep(Duration::from_millis(ms)).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                if next_udp_sweep_at.is_some_and(|deadline| Instant::now() >= deadline) {
                    udp_bridge.sweep_idle();
                    next_udp_sweep_at = None;
                }
            }
        }
    }

    info!("beam-tun engine stopped");
    Ok(())
}

fn spawn_tcp_relay(
    mut conn: AcceptedTcpStream,
    client_config: BeamClientConfig,
    permits: Arc<Semaphore>,
    mut network_reset: Option<watch::Receiver<u64>>,
    activity: Option<Arc<TunnelActivity>>,
) {
    let Ok(permit) = permits.try_acquire_owned() else {
        debug!(dst = %conn.dst, "TCP connection limit reached; aborting with RST");
        conn.stream.abort();
        return;
    };

    tokio::spawn(async move {
        let _permit = permit;
        let address = match conn.dst.ip() {
            IpAddr::V4(v4) => Address::Ipv4(v4),
            IpAddr::V6(v6) => Address::Ipv6(v6),
        };
        let dest = NetLocation {
            address,
            port: conn.dst.port(),
        };
        let dial_start = Instant::now();
        let upstream = tokio::select! {
            biased;
            Ok(()) = async {
                match network_reset.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                conn.stream.abort();
                return;
            }
            res = dial_tcp(&client_config, dest) => match res {
                Ok(stream) => {
                    if let Some(tracker) = activity.as_ref() {
                        let rtt_ms = u64::try_from(dial_start.elapsed().as_millis())
                            .unwrap_or(u64::MAX);
                        tracker.record_dial_success(rtt_ms);
                    }
                    stream
                }
                Err(err) => {
                    debug!(dst = %conn.dst, error = %err, "dial_tcp failed");
                    conn.stream.abort();
                    return;
                }
            }
        };

        let idle = client_config.idle_timeout;
        let (mut tun_r, mut tun_w) = conn.stream.into_split();
        let (mut up_r, mut up_w) = tokio::io::split(upstream);

        let c2s = async {
            loop {
                let mut chunk = match timeout(idle, tun_r.recv_chunk()).await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => {
                        let _ = timeout(SHUTDOWN_TIMEOUT, up_w.shutdown()).await;
                        break;
                    }
                    Err(_) => break,
                };
                // Coalesce immediately-queued small chunks up to C2S_COALESCE_TARGET
                // so multi-flow uploads write full TLS records with fewer syscalls.
                while chunk.len() < C2S_COALESCE_TARGET {
                    let Some(next) = tun_r.try_recv_chunk() else {
                        break;
                    };
                    chunk.extend_from_slice(&next);
                }
                if !matches!(timeout(idle, up_w.write_all(&chunk)).await, Ok(Ok(()))) {
                    break;
                }
                // Flush only when no further chunk is already queued, preserving
                // 0 ms interactive latency while avoiding per-chunk flush stalls
                // during bulk uploads.
                if !tun_r.has_queued() && !matches!(timeout(idle, up_w.flush()).await, Ok(Ok(()))) {
                    break;
                }
            }
        };

        let s2c = async {
            let mut buf = vec![0u8; S2C_READ_BUF_BYTES];
            loop {
                let read_res = tokio::select! {
                    biased;
                    () = tun_w.closed() => break,
                    res = timeout(idle, up_r.read(&mut buf)) => res,
                };
                let n = match read_res {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                };
                if !matches!(
                    timeout(idle, tun_w.send_chunk(buf[..n].to_vec())).await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
            tun_w.shutdown();
        };

        tokio::select! {
            biased;
            Ok(()) = async {
                match network_reset.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {}
            _ = async { tokio::join!(c2s, s2c) } => {}
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_activity_tracks_recent_dial_rtt_and_expires() {
        let activity = TunnelActivity::new();
        assert_eq!(activity.recent_rtt(Duration::from_secs(10)), None);

        activity.record_dial_success(42);
        assert_eq!(activity.recent_rtt(Duration::from_secs(10)), Some(42));

        activity.record_dial_success(17);
        assert_eq!(activity.recent_rtt(Duration::from_secs(10)), Some(17));

        std::thread::sleep(Duration::from_millis(15));
        assert_eq!(activity.recent_rtt(Duration::from_millis(5)), None);
        assert_eq!(activity.recent_rtt(Duration::from_secs(10)), Some(17));
    }
}
