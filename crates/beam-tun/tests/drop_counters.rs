//! Rootless drop-counter tests for the `beam-tun` engine loop.
//!
//! Feeds hostile/malformed packets into a `MemoryTun` and asserts that the
//! lock-free counters classify each silent drop by reason (#165).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use beam_core::address::{Address, NetLocation};
use beam_core::client::BeamClientConfig;
use beam_core::reality::RealityClientConfig;
use beam_tun::device::{MemoryTun, TunDevice};
use beam_tun::{
    BypassCidrs, ExcludeIps, IpNet, ProxyTcpStack, RoutePolicy, TcpStackConfig, TunEngineConfig,
    TunnelActivity, UdpBridgeConfig, run_tun_engine_with_activity,
};
use tokio::sync::watch;
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
