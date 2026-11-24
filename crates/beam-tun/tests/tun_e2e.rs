//! Rootless end-to-end tests for `beam-tun`:
//! raw IPv4 packets -> `MemoryTun` -> `TunEngine` (`ProxyTcpStack` / `UdpNatBridge`)
//! -> `beam_core::client` (REALITY + VLESS + Vision / XUDP)
//! -> `beam_core::tls::server::handle_connection`
//! -> loopback TCP / UDP target.

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
use beam_tun::packet::{IP_PROTO_ICMP, IP_PROTO_UDP, build_ipv4_udp_packet, parse_ipv4, parse_udp};
use beam_tun::{
    ProxyTcpStack, RoutePolicy, TcpStackConfig, TunEngineConfig, UdpBridgeConfig, run_tun_engine,
};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET: [u8; 32] = [0x55; 32];
const USER_ID: [u8; 16] = [0xbb; 16];
const SHORT_ID_HEX: &str = "0123456789abcdef";
const COVER_SNI: &str = "whatsapp.net";

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
    let reality =
        RealityClientConfig::new(pub_key, SHORT_ID_HEX, COVER_SNI).expect("reality client cfg");
    BeamClientConfig::new(beam_addr, reality, USER_ID)
}

/// Minimal virtual IP device for the test client side of `MemoryTun`.
struct ClientVirtDev {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct ClientRx(Vec<u8>);
impl RxToken for ClientRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct ClientTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for ClientTx<'_> {
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

impl Device for ClientVirtDev {
    type RxToken<'a> = ClientRx;
    type TxToken<'a> = ClientTx<'a>;

    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((ClientRx(pkt), ClientTx(&mut self.tx)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(ClientTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

#[tokio::test]
async fn tun_tcp_through_beam_server() {
    timeout(Duration::from_secs(10), async {
        // 1. Target TCP echo server on 127.0.0.1:<port>
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind target");
        let target_port = target_listener.local_addr().expect("target addr").port();
        let target_task = tokio::spawn(async move {
            let (mut sock, _) = target_listener.accept().await.expect("accept target");
            let mut buf = [0u8; 4096];
            loop {
                let n = sock.read(&mut buf).await.expect("target read");
                if n == 0 {
                    break;
                }
                sock.write_all(&buf[..n]).await.expect("target write");
            }
            let _ = sock.shutdown().await;
        });

        // 2. Real `beam` server
        let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind cover");
        let cover_port = cover_listener.local_addr().expect("cover addr").port();
        let beam_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind beam");
        let beam_addr = beam_listener.local_addr().expect("beam addr");
        let srv_cfg = make_server_config(cover_port);
        let server_task = tokio::spawn(async move {
            let (sock, _) = beam_listener.accept().await.expect("accept beam");
            handle_connection(sock, srv_cfg).await
        });

        // 3. `beam-tun` engine over `MemoryTun` (allow loopback dst for test)
        let (engine_tun, mut host_tun) = MemoryTun::pair(1500, 128);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let engine_cfg = TunEngineConfig {
            client: make_client_config(beam_addr),
            route: RoutePolicy {
                reject_quic: true,
                drop_private_destinations: false,
                exclude_ips: Vec::new(),
                bypass_cidrs: Vec::new(),
                intercept_dns: false,
            },
            max_tcp_connections: 16,
            udp: UdpBridgeConfig::default(),
            dns: None,
        };
        let stack = ProxyTcpStack::new(TcpStackConfig::default());
        let engine_task = tokio::spawn(run_tun_engine(engine_tun, stack, engine_cfg, shutdown_rx));

        // 4. Virtual host TCP client speaking raw IPv4 packets into `host_tun`
        let mut dev = ClientVirtDev {
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
            SocketBuffer::new(vec![0u8; 64 * 1024]),
            SocketBuffer::new(vec![0u8; 64 * 1024]),
        );
        let handle = sockets.add(tcp_sock);
        let remote = IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), target_port);
        sockets
            .get_mut::<TcpSocket<'_>>(handle)
            .connect(iface.context(), remote, 45_000)
            .expect("virtual tcp connect");

        let payload = b"hello from beam-tun over REALITY+Vision!";
        let mut sent = false;
        let mut received = Vec::new();
        let start = Instant::now();
        let mut recv_buf = vec![0u8; 2048];

        let mut tx_count = 0usize;
        let mut rx_count = 0usize;
        while received.len() < payload.len() && start.elapsed() < Duration::from_secs(2) {
            let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
            iface.poll(now, &mut dev, &mut sockets);

            while let Some(pkt) = dev.tx.pop_front() {
                tx_count += 1;
                host_tun.send(&pkt).await.expect("host_tun send");
            }

            {
                let sock = sockets.get_mut::<TcpSocket<'_>>(handle);
                if !sent && sock.can_send() {
                    let n = sock.send_slice(payload).expect("send_slice");
                    assert_eq!(n, payload.len());
                    sent = true;
                }
                if sock.can_recv() {
                    let _ = sock.recv(|data| {
                        received.extend_from_slice(data);
                        (data.len(), ())
                    });
                }
            }

            if received.len() >= payload.len() {
                break;
            }

            match timeout(Duration::from_millis(20), host_tun.recv(&mut recv_buf)).await {
                Ok(Ok(n)) => {
                    rx_count += 1;
                    dev.rx.push_back(recv_buf[..n].to_vec());
                }
                Ok(Err(err)) => panic!("host_tun recv error: {err}"),
                Err(_) => {}
            }
        }

        let final_state = sockets.get::<TcpSocket<'_>>(handle).state();
        assert_eq!(
            received, payload,
            "TCP echo incomplete: sent={sent}, state={final_state:?}, tx={tx_count}, rx={rx_count}, received_len={}",
            received.len()
        );

        let _ = shutdown_tx.send(true);
        let _ = engine_task.await;
        drop(host_tun);
        let _ = timeout(Duration::from_secs(3), server_task).await;
        let _ = timeout(Duration::from_secs(3), target_task).await;
        drop(cover_listener);
    })
    .await
    .expect("tun_tcp_through_beam_server timed out");
}

#[tokio::test]
async fn tun_udp_and_reject_quic_work_end_to_end() {
    timeout(Duration::from_secs(10), async {
        // 1. Target UDP echo socket
        let target_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind udp target");
        let target_port = target_udp.local_addr().expect("udp addr").port();
        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, peer) = target_udp.recv_from(&mut buf).await.expect("udp recv");
            target_udp.send_to(&buf[..n], peer).await.expect("udp send");
        });

        // 2. Real `beam` server
        let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind cover");
        let cover_port = cover_listener.local_addr().expect("cover addr").port();
        let beam_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind beam");
        let beam_addr = beam_listener.local_addr().expect("beam addr");
        let srv_cfg = make_server_config(cover_port);
        let server_task = tokio::spawn(async move {
            let (sock, _) = beam_listener.accept().await.expect("accept beam");
            handle_connection(sock, srv_cfg).await
        });

        // 3. `beam-tun` engine
        let (engine_tun, mut host_tun) = MemoryTun::pair(1500, 128);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let engine_cfg = TunEngineConfig {
            client: make_client_config(beam_addr),
            route: RoutePolicy {
                reject_quic: true,
                drop_private_destinations: false,
                exclude_ips: Vec::new(),
                bypass_cidrs: Vec::new(),
                intercept_dns: false,
            },
            max_tcp_connections: 16,
            udp: UdpBridgeConfig::default(),
            dns: None,
        };
        let stack = ProxyTcpStack::new(TcpStackConfig::default());
        let engine_task = tokio::spawn(run_tun_engine(engine_tun, stack, engine_cfg, shutdown_rx));

        // 4a. Test `reject_quic`: UDP/443 must immediately return ICMP Port Unreachable.
        let quic_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            51_000,
            Ipv4Addr::new(142, 250, 1, 1),
            443,
            b"quic-init",
        )
        .expect("quic pkt");
        host_tun.send(&quic_pkt).await.expect("send quic");

        let mut buf = vec![0u8; 2048];
        let n = host_tun.recv(&mut buf).await.expect("recv icmp");
        let icmp_ip = parse_ipv4(&buf[..n]).expect("parse icmp ip");
        assert_eq!(icmp_ip.protocol, IP_PROTO_ICMP);
        assert_eq!(icmp_ip.payload[0], 3, "ICMP Destination Unreachable");
        assert_eq!(icmp_ip.payload[1], 3, "ICMP Port Unreachable");

        // 4b. Test UDP echo through XUDP -> beam server -> loopback UDP target.
        let udp_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            52_000,
            Ipv4Addr::LOCALHOST,
            target_port,
            b"hello-tun-xudp",
        )
        .expect("udp pkt");
        host_tun.send(&udp_pkt).await.expect("send udp");

        let n = host_tun.recv(&mut buf).await.expect("recv udp reply");
        let reply_ip = parse_ipv4(&buf[..n]).expect("parse reply ip");
        assert_eq!(reply_ip.protocol, IP_PROTO_UDP);
        assert_eq!(reply_ip.src_ip, Ipv4Addr::LOCALHOST);
        assert_eq!(reply_ip.dst_ip, Ipv4Addr::new(172, 19, 0, 1));
        let reply_udp = parse_udp(reply_ip.payload).expect("parse reply udp");
        assert_eq!(reply_udp.src_port, target_port);
        assert_eq!(reply_udp.dst_port, 52_000);
        assert_eq!(reply_udp.payload, b"hello-tun-xudp");

        let _ = shutdown_tx.send(true);
        let _ = engine_task.await;
        drop(host_tun);
        let _ = timeout(Duration::from_secs(3), udp_task).await;
        let _ = timeout(Duration::from_secs(3), server_task).await;
        drop(cover_listener);
    })
    .await
    .expect("tun_udp_and_reject_quic_work_end_to_end timed out");
}

fn build_dns_query(tx_id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx_id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // A
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out
}

fn build_dns_a_reply(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let mut out = query.to_vec();
    out[2] = 0x81;
    out[3] = 0x80;
    out[6] = 0;
    out[7] = 1;
    out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    out.extend_from_slice(&ip.octets());
    out
}

#[tokio::test]
async fn tun_dns_split_and_tunneled_tcp_dns_end_to_end() {
    timeout(Duration::from_secs(10), async {
        // 1. Local mock UDP DNS server (must receive `.lan` queries directly).
        let local_dns = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind local dns");
        let local_dns_addr = local_dns.local_addr().expect("local dns addr");
        let local_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = local_dns.recv_from(&mut buf).await.expect("local recv");
            let reply = build_dns_a_reply(&buf[..n], Ipv4Addr::new(192, 168, 1, 77));
            local_dns.send_to(&reply, peer).await.expect("local send");
        });

        // 2. Remote mock TCP DNS server (must receive public queries via `beam`).
        let remote_dns = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind remote dns");
        let remote_dns_addr = remote_dns.local_addr().expect("remote dns addr");
        let remote_task = tokio::spawn(async move {
            let (mut sock, _) = remote_dns.accept().await.expect("accept remote dns");
            let mut len_buf = [0u8; 2];
            sock.read_exact(&mut len_buf).await.expect("read len");
            let qlen = usize::from(u16::from_be_bytes(len_buf));
            let mut q = vec![0u8; qlen];
            sock.read_exact(&mut q).await.expect("read query");
            let reply = build_dns_a_reply(&q, Ipv4Addr::new(93, 184, 216, 34));
            let rlen = (reply.len() as u16).to_be_bytes();
            sock.write_all(&rlen).await.expect("write rlen");
            sock.write_all(&reply).await.expect("write reply");
        });

        // 3. Real `beam` server
        let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind cover");
        let cover_port = cover_listener.local_addr().expect("cover addr").port();
        let beam_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind beam");
        let beam_addr = beam_listener.local_addr().expect("beam addr");
        let srv_cfg = make_server_config(cover_port);
        let server_task = tokio::spawn(async move {
            let (sock, _) = beam_listener.accept().await.expect("accept beam");
            handle_connection(sock, srv_cfg).await
        });

        // 4. `beam-tun` engine with built-in DNS split enabled
        let (engine_tun, mut host_tun) = MemoryTun::pair(1500, 128);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let dns_cfg = beam_tun::DnsConfig::new(
            beam_tun::DnsUpstream::PlainTcp(remote_dns_addr),
            Some(local_dns_addr),
        );
        let engine_cfg = TunEngineConfig {
            client: make_client_config(beam_addr),
            route: RoutePolicy {
                reject_quic: true,
                drop_private_destinations: true,
                exclude_ips: Vec::new(),
                bypass_cidrs: Vec::new(),
                intercept_dns: true,
            },
            max_tcp_connections: 16,
            udp: UdpBridgeConfig::default(),
            dns: Some(dns_cfg),
        };
        let stack = ProxyTcpStack::new(TcpStackConfig::default());
        let engine_task = tokio::spawn(run_tun_engine(engine_tun, stack, engine_cfg, shutdown_rx));

        let mut buf = vec![0u8; 2048];

        // 4a. `.lan` query -> bypassed to local mock DNS
        let lan_q = build_dns_query(0x1001, "printer.lan");
        let lan_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            54_001,
            Ipv4Addr::new(172, 19, 0, 2),
            53,
            &lan_q,
        )
        .expect("lan pkt");
        host_tun.send(&lan_pkt).await.expect("send lan dns");
        let n = host_tun.recv(&mut buf).await.expect("recv lan dns");
        let lan_udp = parse_udp(parse_ipv4(&buf[..n]).expect("ip").payload).expect("udp");
        let (_, lan_ips) = beam_tun::dns::parse_dns_response_meta(lan_udp.payload);
        assert_eq!(
            lan_ips,
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 77))]
        );

        // 4b. Public domain -> tunneled via `beam` to remote mock TCP DNS
        let pub_q = build_dns_query(0x1002, "example.com");
        let pub_pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(172, 19, 0, 1),
            54_002,
            Ipv4Addr::new(172, 19, 0, 2),
            53,
            &pub_q,
        )
        .expect("pub pkt");
        host_tun.send(&pub_pkt).await.expect("send pub dns");
        let n = host_tun.recv(&mut buf).await.expect("recv pub dns");
        let pub_udp = parse_udp(parse_ipv4(&buf[..n]).expect("ip").payload).expect("udp");
        let (_, pub_ips) = beam_tun::dns::parse_dns_response_meta(pub_udp.payload);
        assert_eq!(
            pub_ips,
            vec![std::net::IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );

        let _ = shutdown_tx.send(true);
        let _ = engine_task.await;
        drop(host_tun);
        let _ = timeout(Duration::from_secs(3), local_task).await;
        let _ = timeout(Duration::from_secs(3), remote_task).await;
        let _ = timeout(Duration::from_secs(3), server_task).await;
        drop(cover_listener);
    })
    .await
    .expect("tun_dns_split_and_tunneled_tcp_dns_end_to_end timed out");
}
