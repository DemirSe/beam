//! Rootless release-mode micro-benchmark for `beam-tun` (`ProxyTcpStack` +
//! `UdpNatBridge`) through `beam_core::client` and `beam` server on loopback.
//!
//! Measures:
//! 1. TCP bulk download throughput through `SmoltcpStack` + REALITY/VLESS/Vision
//! 2. UDP echo p50/p95/p99 RTT through `UdpNatBridge` + XUDP
//! 3. Process peak RSS (`VmHWM` from `/proc/self/status`)

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use beam_core::address::{Address, NetLocation};
use beam_core::client::BeamClientConfig;
use beam_core::reality::RealityClientConfig;
use beam_core::tls::server::{TlsServerConfig, handle_connection};
use beam_core::tls::{MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN};
use beam_tun::device::{MemoryTun, TunDevice};
use beam_tun::packet::{build_ipv4_udp_packet, parse_ipv4, parse_udp};
use beam_tun::{
    ProxyTcpStack, RoutePolicy, TcpStackConfig, TunEngineConfig, UdpBridgeConfig, run_tun_engine,
};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET: [u8; 32] = [0x55; 32];
const USER_ID: [u8; 16] = [0xbb; 16];
const SHORT_ID_HEX: &str = "0123456789abcdef";
const COVER_SNI: &str = "whatsapp.net";
const BULK_BYTES: usize = 32 * 1024 * 1024; // 32 MiB
const UDP_PROBES: usize = 200;

struct BenchVirtDev {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct BenchRx(Vec<u8>);
impl RxToken for BenchRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct BenchTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for BenchTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for BenchVirtDev {
    type RxToken<'a> = BenchRx;
    type TxToken<'a> = BenchTx<'a>;

    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((BenchRx(pkt), BenchTx(&mut self.tx)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(BenchTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

fn read_vm_hwm_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn make_server_config(cover_port: u16) -> Arc<TlsServerConfig> {
    Arc::new(
        TlsServerConfig::new(
            SERVER_SECRET,
            vec![SHORT_ID_HEX.to_string()],
            vec![COVER_SNI.to_string()],
            [0, 0, 0],
            [255, 255, 255],
            Some(Duration::from_secs(300)),
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::LOCALHOST),
                port: cover_port,
            },
            Duration::from_secs(5),
            TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN,
            USER_ID,
        )
        .expect("server config"),
    )
}

fn make_client_config(beam_addr: SocketAddr) -> BeamClientConfig {
    let pub_key = PublicKey::from(&StaticSecret::from(SERVER_SECRET)).to_bytes();
    let reality = RealityClientConfig::new(pub_key, SHORT_ID_HEX, COVER_SNI).expect("reality cfg");
    BeamClientConfig::new(beam_addr, reality, USER_ID)
}

#[tokio::main]
async fn main() {
    let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind cover");
    let cover_port = cover_listener.local_addr().expect("cover addr").port();

    let beam_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind beam");
    let beam_addr = beam_listener.local_addr().expect("beam addr");
    let srv_cfg = make_server_config(cover_port);

    // Accept loop for beam server.
    let server_accept = tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = beam_listener.accept().await else {
                break;
            };
            let cfg = Arc::clone(&srv_cfg);
            tokio::spawn(async move {
                let _ = handle_connection(sock, cfg).await;
            });
        }
    });

    // Target TCP bulk sender (streams BULK_BYTES as fast as possible).
    let tcp_target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind tcp target");
    let tcp_target_port = tcp_target.local_addr().expect("tcp target addr").port();
    let tcp_target_task = tokio::spawn(async move {
        let (mut sock, _) = tcp_target.accept().await.expect("accept tcp target");
        let chunk = vec![0xab_u8; 64 * 1024];
        let mut remaining = BULK_BYTES;
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            sock.write_all(&chunk[..n]).await.expect("target write");
            remaining -= n;
        }
        let _ = sock.shutdown().await;
    });

    // Target UDP echo socket.
    let udp_target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind udp target");
    let udp_target_port = udp_target.local_addr().expect("udp target addr").port();
    let udp_target_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        for _ in 0..UDP_PROBES {
            let (n, peer) = udp_target.recv_from(&mut buf).await.expect("udp recv");
            udp_target.send_to(&buf[..n], peer).await.expect("udp send");
        }
    });

    // Start beam-tun engine.
    let (engine_tun, mut host_tun) = MemoryTun::pair(1500, 512);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let engine_cfg = TunEngineConfig {
        client: make_client_config(beam_addr),
        route: RoutePolicy {
            reject_quic: true,
            reject_ipv6: false,
            drop_private_destinations: false,
            exclude_ips: Default::default(),
            bypass_cidrs: Default::default(),
            intercept_dns: false,
        },
        max_tcp_connections: 32,
        udp: UdpBridgeConfig::default(),
        dns: None,
        network_reset: None,
    };
    let stack = ProxyTcpStack::new(TcpStackConfig::default());
    let engine_task = tokio::spawn(run_tun_engine(engine_tun, stack, engine_cfg, shutdown_rx));

    // --- 1. TCP bulk download through SmoltcpStack ---
    let mut dev = BenchVirtDev {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut iface = Interface::new(
        IfaceConfig::new(HardwareAddress::Ip),
        &mut dev,
        SmolInstant::from_millis(0),
    );
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::v4(172, 19, 0, 1), 30));
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(172, 19, 0, 2));

    let mut sockets = SocketSet::new(Vec::new());
    let tcp_sock = TcpSocket::new(
        SocketBuffer::new(vec![0u8; 256 * 1024]),
        SocketBuffer::new(vec![0u8; 64 * 1024]),
    );
    let handle = sockets.add(tcp_sock);
    let remote = IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), tcp_target_port);
    sockets
        .get_mut::<TcpSocket<'_>>(handle)
        .connect(iface.context(), remote, 46_000)
        .expect("connect");

    let tcp_start = Instant::now();
    let mut total_received = 0usize;
    let mut recv_buf = vec![0u8; 2048];
    while total_received < BULK_BYTES {
        let now = SmolInstant::from_millis(tcp_start.elapsed().as_millis() as i64);
        iface.poll(now, &mut dev, &mut sockets);
        while let Some(pkt) = dev.tx.pop_front() {
            host_tun.send(&pkt).await.expect("send");
        }
        {
            let sock = sockets.get_mut::<TcpSocket<'_>>(handle);
            while sock.can_recv() {
                let _ = sock.recv(|data| {
                    total_received += data.len();
                    (data.len(), ())
                });
            }
        }
        if total_received >= BULK_BYTES {
            break;
        }
        // Drain all immediately available packets before waiting.
        let mut drained = false;
        while let Some(pkt) = host_tun.try_recv() {
            dev.rx.push_back(pkt);
            drained = true;
        }
        if !drained
            && let Ok(Ok(n)) = timeout(Duration::from_millis(5), host_tun.recv(&mut recv_buf)).await
        {
            dev.rx.push_back(recv_buf[..n].to_vec());
        }
    }
    let tcp_elapsed = tcp_start.elapsed();
    let mib_s = (BULK_BYTES as f64 / (1024.0 * 1024.0)) / tcp_elapsed.as_secs_f64();
    let mbps = (BULK_BYTES as f64 * 8.0 / 1_000_000.0) / tcp_elapsed.as_secs_f64();

    // --- 2. UDP XUDP RTT probes ---
    let mut rtts_us = Vec::with_capacity(UDP_PROBES);
    for i in 0..UDP_PROBES {
        let payload = format!("probe-{i:04}");
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            53_000,
            Ipv4Addr::LOCALHOST,
            udp_target_port,
            payload.as_bytes(),
        )
        .expect("udp pkt");
        let t0 = Instant::now();
        host_tun.send(&pkt).await.expect("send udp");
        loop {
            let n = host_tun.recv(&mut recv_buf).await.expect("recv udp");
            if let Some(ip) = parse_ipv4(&recv_buf[..n])
                && let Some(udp) = parse_udp(ip.payload)
                && udp.dst_port == 53_000
            {
                assert_eq!(udp.payload, payload.as_bytes());
                rtts_us.push(t0.elapsed().as_micros() as u64);
                break;
            }
        }
    }
    rtts_us.sort_unstable();
    let p50 = rtts_us[rtts_us.len() / 2];
    let p95 = rtts_us[(rtts_us.len() * 95) / 100];
    let p99 = rtts_us[(rtts_us.len() * 99) / 100];

    let hwm_kib = read_vm_hwm_kib().unwrap_or(0);
    println!("=== beam-tun (ProxyTcpStack) rootless loopback micro-bench ===");
    println!(
        "TCP bulk ({} MiB): {:.2} s -> {:.1} MiB/s ({:.0} Mbps)",
        BULK_BYTES / (1024 * 1024),
        tcp_elapsed.as_secs_f64(),
        mib_s,
        mbps
    );
    println!(
        "UDP XUDP ({} probes): p50={:.2} ms  p95={:.2} ms  p99={:.2} ms",
        UDP_PROBES,
        p50 as f64 / 1000.0,
        p95 as f64 / 1000.0,
        p99 as f64 / 1000.0
    );
    println!(
        "Process peak RSS (VmHWM, client + server + targets combined): {:.1} MiB ({} KiB)",
        hwm_kib as f64 / 1024.0,
        hwm_kib
    );

    let _ = shutdown_tx.send(true);
    let _ = engine_task.await;
    drop(host_tun);
    let _ = tcp_target_task.await;
    let _ = udp_target_task.await;
    server_accept.abort();
    drop(cover_listener);
}
