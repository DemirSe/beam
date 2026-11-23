//! Main async TUN engine loop connecting [`TunDevice`], [`RoutePolicy`],
//! [`NetStack`], `beam_core::client::dial_tcp`, and [`UdpNatBridge`].

use std::io;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::{Duration, Instant};

use beam_core::address::{Address, NetLocation};
use beam_core::client::{BeamClientConfig, dial_tcp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::{sleep, timeout};
use tracing::{debug, info};

use crate::device::TunDevice;
use crate::packet::{build_icmp_port_unreachable, parse_ipv4, parse_udp};
use crate::router::{RouteDecision, RoutePolicy};
use crate::stack::{AcceptedTcpStream, NetStack};
use crate::udp::{UdpBridgeConfig, UdpNatBridge};

const MAX_PACKET_BUF: usize = 65_536;
const TUN_TX_CHANNEL_CAP: usize = 512;
const DEFAULT_IDLE_POLL_MS: u64 = 100;

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
    mut device: D,
    mut stack: S,
    config: TunEngineConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), EngineError>
where
    D: TunDevice,
    S: NetStack,
{
    let start = Instant::now();
    let stack_waker = stack.waker();
    let tcp_permits = Arc::new(Semaphore::new(config.max_tcp_connections.max(1)));
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(TUN_TX_CHANNEL_CAP);
    let mut udp_bridge = UdpNatBridge::new(config.client.clone(), config.udp, tun_tx.clone());

    let mut recv_buf = vec![0u8; device.mtu().clamp(2048, MAX_PACKET_BUF)];
    let mut tx_batch: Vec<Vec<u8>> = Vec::with_capacity(64);
    let mut accepted: Vec<AcceptedTcpStream> = Vec::with_capacity(16);

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
        stack.poll(now_ms, &mut tx_batch, &mut accepted);

        for pkt in tx_batch.drain(..) {
            if let Err(err) = device.send(&pkt).await {
                return Err(EngineError::Device(err));
            }
        }

        for conn in accepted.drain(..) {
            spawn_tcp_relay(conn, config.client.clone(), Arc::clone(&tcp_permits));
        }

        // Drain any pending UDP/ICMP reply packets immediately.
        while let Ok(pkt) = tun_rx.try_recv() {
            if let Err(err) = device.send(&pkt).await {
                return Err(EngineError::Device(err));
            }
        }

        let delay_ms = stack
            .poll_delay_ms(start.elapsed().as_millis() as i64)
            .unwrap_or(DEFAULT_IDLE_POLL_MS)
            .clamp(1, DEFAULT_IDLE_POLL_MS);

        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            Some(reply_pkt) = tun_rx.recv() => {
                device.send(&reply_pkt).await?;
            }
            read_res = device.recv(&mut recv_buf) => {
                let n = read_res?;
                if n == 0 {
                    continue;
                }
                let raw = &recv_buf[..n];
                let Some(ip) = parse_ipv4(raw) else {
                    continue;
                };
                match config.route.classify(&ip) {
                    RouteDecision::ProxyTcp => {
                        stack.push_ipv4_tcp(ip.raw);
                    }
                    RouteDecision::ProxyUdp => {
                        if let Some(udp) = parse_udp(ip.payload) {
                            let src = SocketAddrV4::new(ip.src_ip, udp.src_port);
                            let dst = SocketAddrV4::new(ip.dst_ip, udp.dst_port);
                            udp_bridge.handle_datagram(src, dst, udp.payload).await;
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
            () = stack_waker.notified() => {}
            () = sleep(Duration::from_millis(delay_ms)) => {
                udp_bridge.sweep_idle();
            }
        }
    }

    info!("beam-tun engine stopped");
    Ok(())
}

fn spawn_tcp_relay(
    conn: AcceptedTcpStream,
    client_config: BeamClientConfig,
    permits: Arc<Semaphore>,
) {
    let Ok(permit) = permits.try_acquire_owned() else {
        debug!(dst = %conn.dst, "TCP connection limit reached; dropping");
        return;
    };

    tokio::spawn(async move {
        let _permit = permit;
        let dest = NetLocation {
            address: Address::Ipv4(*conn.dst.ip()),
            port: conn.dst.port(),
        };
        let upstream = match dial_tcp(&client_config, dest).await {
            Ok(stream) => stream,
            Err(err) => {
                debug!(dst = %conn.dst, error = %err, "dial_tcp failed");
                return;
            }
        };

        let idle = client_config.idle_timeout;
        let (mut tun_r, mut tun_w) = tokio::io::split(conn.stream);
        let (mut up_r, mut up_w) = tokio::io::split(upstream);

        let c2s = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = match timeout(idle, tun_r.read(&mut buf)).await {
                    Ok(Ok(0)) => {
                        let _ = up_w.shutdown().await;
                        break;
                    }
                    Ok(Ok(n)) => n,
                    _ => break,
                };
                if !matches!(timeout(idle, up_w.write_all(&buf[..n])).await, Ok(Ok(()))) {
                    break;
                }
                if !matches!(timeout(idle, up_w.flush()).await, Ok(Ok(()))) {
                    break;
                }
            }
        };

        let s2c = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = match timeout(idle, up_r.read(&mut buf)).await {
                    Ok(Ok(0)) => {
                        let _ = tun_w.shutdown().await;
                        break;
                    }
                    Ok(Ok(n)) => n,
                    _ => break,
                };
                if !matches!(timeout(idle, tun_w.write_all(&buf[..n])).await, Ok(Ok(()))) {
                    break;
                }
                if !matches!(timeout(idle, tun_w.flush()).await, Ok(Ok(()))) {
                    break;
                }
            }
        };

        let _ = tokio::join!(c2s, s2c);
    });
}
