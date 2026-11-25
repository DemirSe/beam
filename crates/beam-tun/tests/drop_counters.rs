//! Rootless drop-counter tests for the `beam-tun` engine loop.
//!
//! Feeds hostile/malformed packets into a `MemoryTun` and asserts that the
//! lock-free counters classify each silent drop by reason (#165).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use beam_core::address::{Address, NetLocation};
use beam_core::client::BeamClientConfig;
use beam_core::reality::RealityClientConfig;
use beam_tun::device::{MemoryTun, TunDevice};
use beam_tun::{
    AcceptedTcpStream, BypassCidrs, DropCounters, ExcludeIps, IpNet, NetStack, ProxyTcpStack,
    RoutePolicy, TcpStackConfig, TunEngineConfig, TunnelActivity, UdpBridgeConfig,
    run_tun_engine_with_activity,
};
use tokio::sync::{Notify, watch};
use tokio::time::timeout;

/// Sends one raw packet into the virtual host side of the TUN pair.
async fn host_tun_send(tun: &mut MemoryTun, packet: &[u8]) {
    tun.send(packet).await.expect("send packet");
}

fn client_config() -> BeamClientConfig {
    let reality =
        RealityClientConfig::new([1u8; 32], "0123456789abcdef", "whatsapp.net").expect("reality");
    BeamClientConfig::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
        reality,
        [2u8; 16],
    )
}

fn engine_config() -> TunEngineConfig {
    TunEngineConfig {
        client: client_config(),
        route: RoutePolicy {
            reject_quic: false,
            reject_ipv6: false,
            drop_private_destinations: true,
            exclude_ips: ExcludeIps::from(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77))]),
            bypass_cidrs: BypassCidrs::from(vec![
                IpNet::parse_cidr("198.51.100.0/24").expect("cidr"),
            ]),
            intercept_dns: false,
        },
        max_tcp_connections: 4,
        tcp_relay_idle_timeout: None,
        udp: UdpBridgeConfig::default(),
        dns: None,
        network_reset: None,
    }
}

/// Builds an IPv4 fragment (`MF=1`, offset 0) so `parse_ip` rejects it.
fn fragment_packet() -> Vec<u8> {
    let mut pkt = beam_tun::packet::build_ip_udp_packet(
        IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)),
        40_000,
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        53,
        b"frag",
    )
    .expect("udp packet");
    pkt[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // MF=1
    pkt
}

#[tokio::test]
async fn engine_counts_parse_fragment_and_route_drops() {
    let (engine_tun, mut host_tun) = MemoryTun::pair(1500, 32);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let activity = Arc::new(TunnelActivity::new());
    let engine_task = tokio::spawn(run_tun_engine_with_activity(
        engine_tun,
        ProxyTcpStack::new(TcpStackConfig::default()),
        engine_config(),
        shutdown_rx,
        Some(Arc::clone(&activity)),
    ));

    // A truncated packet: fewer than 20 bytes, no parseable IP header.
    host_tun_send(&mut host_tun, &[0x45; 8]).await;
    // A fragmented IPv4 packet.
    host_tun_send(&mut host_tun, &fragment_packet()).await;
    // A UDP/9999 packet inside a configured bypass CIDR.
    let bypassed = beam_tun::packet::build_ip_udp_packet(
        IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)),
        40_001,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        9999,
        b"x",
    )
    .expect("bypassed udp");
    host_tun_send(&mut host_tun, &bypassed).await;
    // An explicitly excluded IP.
    let excluded = beam_tun::packet::build_ip_udp_packet(
        IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)),
        40_002,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)),
        9999,
        b"y",
    )
    .expect("excluded udp");
    host_tun_send(&mut host_tun, &excluded).await;
    // A private destination dropped by policy.
    let private = beam_tun::packet::build_ip_udp_packet(
        IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)),
        40_003,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        9999,
        b"z",
    )
    .expect("private udp");
    host_tun_send(&mut host_tun, &private).await;

    let deadline = Duration::from_secs(5);
    let snapshot = timeout(deadline, async {
        loop {
            let snap = activity.drop_snapshot();
            if snap.route >= 3 && snap.ip_parse >= 1 && snap.fragment >= 1 {
                break snap;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("drop counters must classify every silent drop");

    assert_eq!(snapshot.ip_parse, 1, "truncated packet");
    assert_eq!(snapshot.fragment, 1, "fragmented packet");
    assert_eq!(
        snapshot.route, 3,
        "bypass CIDR, excluded IP, and private destination"
    );
    assert!(!snapshot.is_empty());

    let _ = shutdown_tx.send(true);
    engine_task.await.expect("engine task").expect("engine ok");
}

#[tokio::test]
async fn tcp_connection_limit_drops_are_counted_separately_from_route_drops() {
    // A listening socket with no `accept` keeps the first relay's upstream dial
    // blocked in its TLS handshake, so its connection permit stays taken.
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
    let server_addr = listener.local_addr().expect("listener addr");

    let (engine_tun, mut host_tun) = MemoryTun::pair(1500, 64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let activity = Arc::new(TunnelActivity::new());
    let mut config = engine_config();
    config.max_tcp_connections = 1;
    config.client = BeamClientConfig::new(
        server_addr,
        RealityClientConfig::new([1u8; 32], "0123456789abcdef", "whatsapp.net").expect("reality"),
        [2u8; 16],
    );
    let engine_task = tokio::spawn(run_tun_engine_with_activity(
        engine_tun,
        ProxyTcpStack::new(TcpStackConfig::default()),
        config,
        shutdown_rx,
        Some(Arc::clone(&activity)),
    ));

    // First flow takes the only permit and blocks on the upstream handshake.
    open_tcp_flow(&mut host_tun, 41_001, 1_001).await;
    // Give the relay task time to take the permit before the second flow.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let deadline = Duration::from_secs(5);

    // Second flow is accepted by the local stack but cannot get a permit.
    open_tcp_flow(&mut host_tun, 41_002, 2_001).await;
    let snapshot = timeout(deadline, async {
        loop {
            let snap = activity.drop_snapshot();
            if snap.tcp_limit >= 1 {
                break snap;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("connection-limit drops must be counted");

    assert!(snapshot.tcp_limit >= 1);
    assert_eq!(
        snapshot.route, 0,
        "a connection-limit drop must not be counted as a route drop"
    );

    let _ = shutdown_tx.send(true);
    engine_task.await.expect("engine task").expect("engine ok");
    drop(listener);
}

/// Runs a full handshake (SYN, SYN-ACK, ACK) for one flow through the engine.
async fn open_tcp_flow(host_tun: &mut MemoryTun, src_port: u16, iss: u32) {
    let src = IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let segment = |seq: u32, ack: u32, flags: u8| {
        beam_tun::packet::build_ip_tcp_packet_slices(
            src,
            src_port,
            dst,
            443,
            seq,
            ack,
            flags,
            65_535,
            &[],
            &[],
            &[],
        )
        .expect("tcp segment")
    };

    host_tun_send(host_tun, &segment(iss, 0, beam_tun::packet::TCP_SYN)).await;

    let mut buf = vec![0u8; 2048];
    let n = timeout(Duration::from_secs(2), host_tun.recv(&mut buf))
        .await
        .expect("syn-ack timeout")
        .expect("syn-ack");
    let ip = beam_tun::packet::parse_ip(&buf[..n]).expect("syn-ack ip");
    let syn_ack = beam_tun::packet::parse_tcp(ip.payload).expect("syn-ack tcp");
    assert_ne!(syn_ack.flags & beam_tun::packet::TCP_SYN, 0);

    host_tun_send(
        host_tun,
        &segment(
            iss.wrapping_add(1),
            syn_ack.seq.wrapping_add(1),
            beam_tun::packet::TCP_ACK,
        ),
    )
    .await;
}

#[tokio::test]
async fn engine_shares_its_drop_counters_with_the_tcp_stack() {
    /// Stack that keeps the counters the engine attaches.
    struct CounterProbeStack {
        attached: Arc<AtomicBool>,
        shared: Arc<Mutex<Option<Arc<DropCounters>>>>,
        waker: Arc<Notify>,
    }

    impl NetStack for CounterProbeStack {
        fn push_ip_tcp(&mut self, _packet: &[u8]) {}

        fn poll(
            &mut self,
            _now_ms: i64,
            _tx_out: &mut Vec<Vec<u8>>,
            _accepted: &mut Vec<AcceptedTcpStream>,
        ) {
        }

        fn poll_delay_ms(&mut self, _now_ms: i64) -> Option<u64> {
            Some(1_000)
        }

        fn waker(&self) -> Arc<Notify> {
            Arc::clone(&self.waker)
        }

        fn set_drop_counters(&mut self, drops: Arc<DropCounters>) {
            if let Ok(mut slot) = self.shared.lock() {
                *slot = Some(drops);
            }
            self.attached.store(true, Ordering::SeqCst);
        }
    }

    let (engine_tun, _host_tun) = MemoryTun::pair(1500, 8);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let activity = Arc::new(TunnelActivity::new());
    let shared: Arc<Mutex<Option<Arc<DropCounters>>>> = Arc::new(Mutex::new(None));
    let attached = Arc::new(AtomicBool::new(false));
    let engine_task = tokio::spawn(run_tun_engine_with_activity(
        engine_tun,
        CounterProbeStack {
            attached: Arc::clone(&attached),
            shared: Arc::clone(&shared),
            waker: Arc::new(Notify::new()),
        },
        engine_config(),
        shutdown_rx,
        Some(Arc::clone(&activity)),
    ));

    timeout(Duration::from_secs(5), async {
        while !attached.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the engine must attach drop counters to the stack");

    // The stack and the activity tracker must share one counter set, so a stack
    // level drop is visible in the status snapshot.
    let counters = {
        let guard = shared.lock().expect("shared counters");
        Arc::clone(guard.as_ref().expect("counters attached"))
    };
    counters.tcp_rx_overflow.incr();
    counters.udp_mux_q.add(2);
    let snapshot = activity.drop_snapshot();
    assert_eq!(snapshot.tcp_rx_overflow, 1);
    assert_eq!(snapshot.udp_mux_q, 2);
    assert!(snapshot.as_status_value().contains("tcp_rx_ovf:1"));
    assert!(snapshot.as_status_value().contains("udp_mux_q:2"));

    let _ = shutdown_tx.send(true);
    engine_task.await.expect("engine task").expect("engine ok");
}

#[tokio::test]
async fn activity_reports_dial_failures_by_stage() {
    let activity = TunnelActivity::new();
    assert_eq!(activity.dial_failure_count(), 0);
    assert!(activity.recent_failure(Duration::from_secs(60)).is_none());

    activity.record_dial_failure(beam_tun::DialFailure {
        stage: beam_tun::DialFailureStage::TcpConnect,
        kind: beam_tun::DialFailureKind::Refused,
    });
    activity.record_dial_failure(beam_tun::DialFailure {
        stage: beam_tun::DialFailureStage::RealityHandshake,
        kind: beam_tun::DialFailureKind::Other,
    });
    let failure = activity
        .recent_failure(Duration::from_secs(60))
        .expect("recent failure");
    assert_eq!(failure.stage, beam_tun::DialFailureStage::RealityHandshake);
    assert_eq!(failure.kind, beam_tun::DialFailureKind::Other);
    assert_eq!(activity.dial_failure_count(), 2);
    assert_eq!(activity.consecutive_failure_count(), 2);

    // A success resets only the streak, not the lifetime failure count.
    activity.record_dial_success(12);
    assert_eq!(activity.consecutive_failure_count(), 0);
    assert_eq!(activity.dial_failure_count(), 2);
    assert_eq!(
        activity
            .recent_failure(Duration::from_secs(60))
            .map(|f| f.stage),
        Some(beam_tun::DialFailureStage::RealityHandshake),
        "the last failure stays visible for diagnostics"
    );
    assert_eq!(activity.recent_failure_streak(Duration::from_secs(60)), 0);

    // NetLocation is only used above to prove the config type is untouched.
    let _ = NetLocation {
        address: Address::Ipv4(Ipv4Addr::LOCALHOST),
        port: 1,
    };
}
