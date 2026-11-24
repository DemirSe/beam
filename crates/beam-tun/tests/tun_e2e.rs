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
                reject_ipv6: false,
                drop_private_destinations: false,
                exclude_ips: Vec::new(),
                bypass_cidrs: Vec::new(),
                intercept_dns: false,
            },
            max_tcp_connections: 16,
            udp: UdpBridgeConfig::default(),
            dns: None,
            network_reset: None,
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
                reject_ipv6: false,
                drop_private_destinations: false,
                exclude_ips: Vec::new(),
                bypass_cidrs: Vec::new(),
                intercept_dns: false,
            },
            max_tcp_connections: 16,
            udp: UdpBridgeConfig::default(),
            dns: None,
            network_reset: None,
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
                reject_ipv6: false,
                drop_private_destinations: true,
                exclude_ips: Vec::new(),
                bypass_cidrs: Vec::new(),
                intercept_dns: true,
            },
            max_tcp_connections: 16,
            udp: UdpBridgeConfig::default(),
            dns: Some(dns_cfg),
            network_reset: None,
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

#[tokio::test]
async fn tun_ipv6_quic_reject_end_to_end() {
    use beam_tun::packet::{IP_PROTO_ICMPV6, build_ip_udp_packet, parse_ip};
    use std::net::IpAddr;

    timeout(Duration::from_secs(10), async {
        let (engine_tun, mut host_tun) = MemoryTun::pair(1500, 128);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let engine_cfg = TunEngineConfig {
            client: make_client_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 1))),
            route: RoutePolicy {
                reject_quic: true,
                reject_ipv6: false,
                drop_private_destinations: false,
                exclude_ips: Vec::new(),
                bypass_cidrs: Vec::new(),
                intercept_dns: false,
            },
            max_tcp_connections: 16,
            udp: UdpBridgeConfig::default(),
            dns: None,
            network_reset: None,
        };
        let stack = ProxyTcpStack::new(TcpStackConfig::default());
        let engine_task = tokio::spawn(run_tun_engine(engine_tun, stack, engine_cfg, shutdown_rx));

        let src_v6 = IpAddr::V6("fd00:be:a::1".parse().expect("src v6"));
        let quic_v6 = build_ip_udp_packet(
            src_v6,
            51_111,
            IpAddr::V6("2606:4700:4700::1111".parse().expect("v6")),
            443,
            b"quic-v6",
        )
        .expect("quic v6");
        host_tun.send(&quic_v6).await.expect("send quic v6");

        let mut buf = vec![0u8; 2048];
        let n = timeout(Duration::from_secs(2), host_tun.recv(&mut buf))
            .await
            .expect("icmpv6 timed out")
            .expect("recv icmpv6");
        let icmp6_ip = parse_ip(&buf[..n]).expect("parse icmpv6 ip");
        assert_eq!(icmp6_ip.protocol, IP_PROTO_ICMPV6);
        assert_eq!(icmp6_ip.payload[0], 1, "ICMPv6 Destination Unreachable");
        assert_eq!(icmp6_ip.payload[1], 4, "ICMPv6 Port Unreachable");

        let _ = shutdown_tx.send(true);
        let _ = engine_task.await;
    })
    .await
    .expect("tun_ipv6_quic_reject_end_to_end timed out");
}

#[tokio::test]
async fn tun_tcp_recovers_after_network_reset() {
    use beam_tun::packet::{
        IP_PROTO_TCP, TCP_ACK, TCP_PSH, TCP_RST, TCP_SYN, build_ip_tcp_packet_slices, parse_ip,
        parse_tcp,
    };
    use std::net::IpAddr;

    timeout(Duration::from_secs(10), async {
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind target");
        let target_port = target_listener.local_addr().expect("target addr").port();
        let target_task = tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((mut sock, _)) = target_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = sock.read(&mut buf).await
                        && n > 0
                    {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                    let _ = sock.shutdown().await;
                });
            }
        });

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
            for _ in 0..2 {
                let Ok((sock, _)) = beam_listener.accept().await else {
                    break;
                };
                let cfg = Arc::clone(&srv_cfg);
                tokio::spawn(async move {
                    let _ = handle_connection(sock, cfg).await;
                });
            }
        });

        let (engine_tun, mut host_tun) = MemoryTun::pair(1500, 128);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (reset_tx, reset_rx) = watch::channel(0u64);
        let engine_cfg = TunEngineConfig {
            client: make_client_config(beam_addr),
            route: RoutePolicy {
                reject_quic: true,
                reject_ipv6: false,
                drop_private_destinations: false,
                exclude_ips: Vec::new(),
                bypass_cidrs: Vec::new(),
                intercept_dns: false,
            },
            max_tcp_connections: 16,
            udp: UdpBridgeConfig::default(),
            dns: None,
            network_reset: Some(reset_rx),
        };
        let stack = ProxyTcpStack::new(TcpStackConfig::default());
        let engine_task = tokio::spawn(run_tun_engine(engine_tun, stack, engine_cfg, shutdown_rx));

        let src = IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut buf = vec![0u8; 2048];

        // 1. Open flow #1 (stays established while we trigger a network transition).
        let syn1 = build_ip_tcp_packet_slices(
            src,
            41_001,
            dst,
            target_port,
            1000,
            0,
            TCP_SYN,
            65535,
            &[2, 4, 0x05, 0xb4],
            &[],
            &[],
        )
        .expect("syn1");
        host_tun.send(&syn1).await.expect("send syn1");
        let n = host_tun.recv(&mut buf).await.expect("recv syn-ack1");
        let sa1 = parse_tcp(parse_ip(&buf[..n]).expect("ip").payload).expect("tcp");
        assert_eq!(sa1.flags, TCP_SYN | TCP_ACK);
        let ack1 = build_ip_tcp_packet_slices(
            src,
            41_001,
            dst,
            target_port,
            1001,
            sa1.seq.wrapping_add(1),
            TCP_ACK,
            65535,
            &[],
            &[],
            &[],
        )
        .expect("ack1");
        host_tun.send(&ack1).await.expect("send ack1");
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 2. Trigger network_reset -> flow #1 must receive TCP RST.
        reset_tx.send(1).expect("send reset");
        let n = timeout(Duration::from_secs(2), host_tun.recv(&mut buf))
            .await
            .expect("rst timeout")
            .expect("recv rst");
        let rst = parse_tcp(parse_ip(&buf[..n]).expect("ip").payload).expect("tcp");
        assert_ne!(
            rst.flags & TCP_RST,
            0,
            "expected TCP RST after network_reset"
        );

        // 3. New flow #2 after network_reset MUST connect and echo data cleanly.
        let syn2 = build_ip_tcp_packet_slices(
            src,
            41_002,
            dst,
            target_port,
            2000,
            0,
            TCP_SYN,
            65535,
            &[2, 4, 0x05, 0xb4],
            &[],
            &[],
        )
        .expect("syn2");
        host_tun.send(&syn2).await.expect("send syn2");
        let n = timeout(Duration::from_secs(2), host_tun.recv(&mut buf))
            .await
            .expect("syn-ack2 timeout")
            .expect("recv syn-ack2");
        let sa2 = parse_tcp(parse_ip(&buf[..n]).expect("ip").payload).expect("tcp");
        assert_eq!(sa2.flags, TCP_SYN | TCP_ACK);

        let payload = b"post-reset-ok";
        let data2 = build_ip_tcp_packet_slices(
            src,
            41_002,
            dst,
            target_port,
            2001,
            sa2.seq.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            65535,
            &[],
            payload,
            &[],
        )
        .expect("data2");
        host_tun.send(&data2).await.expect("send data2");

        let mut echoed = Vec::new();
        while echoed.len() < payload.len() {
            let n = timeout(Duration::from_secs(2), host_tun.recv(&mut buf))
                .await
                .expect("post-reset echo timeout")
                .expect("recv data2");
            let ip = parse_ip(&buf[..n]).expect("ip");
            if ip.protocol == IP_PROTO_TCP
                && let Some(seg) = parse_tcp(ip.payload)
                && !seg.payload.is_empty()
            {
                echoed.extend_from_slice(seg.payload);
            }
        }
        assert_eq!(echoed, payload);

        let _ = shutdown_tx.send(true);
        let _ = engine_task.await;
        drop(host_tun);
        server_task.abort();
        target_task.abort();
        drop(cover_listener);
    })
    .await
    .expect("tun_tcp_recovers_after_network_reset timed out");
}

#[tokio::test]
#[ignore = "requires unfirewalled host IPv6 ::1 loopback; run explicitly in CI"]
async fn tun_ipv6_tcp_and_udp_loopback_end_to_end() {
    use beam_tun::packet::{
        IP_PROTO_TCP, TCP_ACK, TCP_PSH, TCP_SYN, build_ip_tcp_packet_slices, build_ip_udp_packet,
        parse_ip, parse_tcp,
    };
    use std::net::{IpAddr, Ipv6Addr};

    timeout(Duration::from_secs(10), async {
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
            for _ in 0..2 {
                let Ok((sock, _)) = beam_listener.accept().await else {
                    break;
                };
                let cfg = Arc::clone(&srv_cfg);
                tokio::spawn(async move {
                    let _ = handle_connection(sock, cfg).await;
                });
            }
        });

        let (engine_tun, mut host_tun) = MemoryTun::pair(1500, 128);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let engine_cfg = TunEngineConfig {
            client: make_client_config(beam_addr),
            route: RoutePolicy {
                reject_quic: true,
                reject_ipv6: false,
                drop_private_destinations: false,
                exclude_ips: Vec::new(),
                bypass_cidrs: Vec::new(),
                intercept_dns: false,
            },
            max_tcp_connections: 16,
            udp: UdpBridgeConfig::default(),
            dns: None,
            network_reset: None,
        };
        let stack = ProxyTcpStack::new(TcpStackConfig::default());
        let engine_task = tokio::spawn(run_tun_engine(engine_tun, stack, engine_cfg, shutdown_rx));

        let src_v6 = IpAddr::V6("fd00:be:a::1".parse().expect("src v6"));
        let dst_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut buf = vec![0u8; 2048];

        let tcp_target = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
            .await
            .expect("bind v6 tcp");
        let udp_target = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            .await
            .expect("bind v6 udp");
        let tcp_target_port = tcp_target.local_addr().expect("v6 tcp addr").port();
        let udp_target_port = udp_target.local_addr().expect("v6 udp addr").port();

        let tcp_task = tokio::spawn(async move {
            let (mut sock, _) = tcp_target.accept().await.expect("accept v6 tcp");
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.expect("v6 tcp read");
            sock.write_all(&buf[..n]).await.expect("v6 tcp write");
            let _ = sock.shutdown().await;
        });

        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, peer) = udp_target.recv_from(&mut buf).await.expect("v6 udp recv");
            udp_target
                .send_to(&buf[..n], peer)
                .await
                .expect("v6 udp send");
        });

        // 1. IPv6 UDP echo through XUDP
        let udp_v6 = build_ip_udp_packet(src_v6, 52_222, dst_v6, udp_target_port, b"v6-udp-ok")
            .expect("udp v6");
        host_tun.send(&udp_v6).await.expect("send udp v6");
        let n = timeout(Duration::from_secs(2), host_tun.recv(&mut buf))
            .await
            .expect("v6 udp timed out")
            .expect("recv udp v6");
        let reply_ip = parse_ip(&buf[..n]).expect("parse v6 udp reply");
        assert_eq!(reply_ip.protocol, IP_PROTO_UDP);
        assert_eq!(reply_ip.src_ip, dst_v6);
        let reply_udp = parse_udp(reply_ip.payload).expect("v6 udp");
        assert_eq!(reply_udp.payload, b"v6-udp-ok");

        // 2. IPv6 TCP handshake + data echo through ProxyTcpStack -> beam server
        let syn = build_ip_tcp_packet_slices(
            src_v6,
            45_678,
            dst_v6,
            tcp_target_port,
            1000,
            0,
            TCP_SYN,
            65535,
            &[2, 4, 0x05, 0xa0],
            &[],
            &[],
        )
        .expect("v6 syn");
        host_tun.send(&syn).await.expect("send v6 syn");

        let n = timeout(Duration::from_secs(2), host_tun.recv(&mut buf))
            .await
            .expect("v6 syn-ack timed out")
            .expect("recv v6 syn-ack");
        let syn_ack_ip = parse_ip(&buf[..n]).expect("v6 syn-ack ip");
        assert_eq!(syn_ack_ip.protocol, IP_PROTO_TCP);
        let syn_ack = parse_tcp(syn_ack_ip.payload).expect("v6 syn-ack");
        assert_eq!(syn_ack.flags, TCP_SYN | TCP_ACK);

        let payload = b"ipv6-tcp-echo-works";
        let ack_data = build_ip_tcp_packet_slices(
            src_v6,
            45_678,
            dst_v6,
            tcp_target_port,
            1001,
            syn_ack.seq.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            65535,
            &[],
            payload,
            &[],
        )
        .expect("v6 data");
        host_tun.send(&ack_data).await.expect("send v6 data");

        let mut echoed = Vec::new();
        while echoed.len() < payload.len() {
            let n = timeout(Duration::from_secs(2), host_tun.recv(&mut buf))
                .await
                .expect("v6 tcp data timed out")
                .expect("recv v6 tcp");
            let ip = parse_ip(&buf[..n]).expect("v6 tcp ip");
            if ip.protocol == IP_PROTO_TCP
                && let Some(seg) = parse_tcp(ip.payload)
                && !seg.payload.is_empty()
            {
                echoed.extend_from_slice(seg.payload);
            }
        }
        assert_eq!(echoed, payload);

        let _ = shutdown_tx.send(true);
        let _ = engine_task.await;
        drop(host_tun);
        let _ = timeout(Duration::from_secs(3), tcp_task).await;
        let _ = timeout(Duration::from_secs(3), udp_task).await;
        server_task.abort();
        drop(cover_listener);
    })
    .await
    .expect("tun_ipv6_tcp_and_udp_loopback_end_to_end timed out");
}
