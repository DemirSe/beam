//! Main async TUN engine loop connecting [`TunDevice`], [`RoutePolicy`],
//! [`NetStack`], `beam_core::client::dial_tcp`, and [`UdpNatBridge`].

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};

use beam_core::address::{Address, NetLocation};
use beam_core::client::{BeamClientConfig, ClientError, dial_tcp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::device::TunDevice;
use crate::dns::{DnsConfig, DnsInterceptor};
use crate::packet::{
    build_icmp_port_unreachable, build_tcp_rst_for_packet, is_fragment, parse_ip, parse_udp,
};
use crate::ratelimit::RateLimiter;
use crate::router::{RouteDecision, RoutePolicy};
use crate::stack::{AcceptedTcpStream, NetStack};
use crate::stats::{DropCounters, DropSnapshot};
use crate::udp::{UdpBridgeConfig, UdpNatBridge};

const MAX_PACKET_BUF: usize = 65_536;
const TUN_TX_CHANNEL_CAP: usize = 512;
const RX_BATCH_MAX: usize = 128;
const C2S_COALESCE_TARGET: usize = 64 * 1024;
const S2C_READ_BUF_BYTES: usize = 64 * 1024;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// Gap after which a new dial failure starts a fresh streak instead of reviving
/// an ancient one, so one blip never keeps the link degraded for minutes.
pub const FAILURE_STREAK_WINDOW: Duration = Duration::from_secs(30);

/// At most 3 upstream dial-failure warnings per 10 s window.
static DIAL_FAILURE_LOG: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(3, Duration::from_secs(10)));
/// At most 3 relay I/O warnings per 10 s window.
static RELAY_IO_LOG: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(3, Duration::from_secs(10)));
/// At most 2 connection-limit RST warnings per 10 s window.
static TCP_LIMIT_LOG: LazyLock<RateLimiter> =
    LazyLock::new(|| RateLimiter::new(2, Duration::from_secs(10)));

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

/// Stage of a failed upstream `dial_tcp`, used to tell a bare TCP connect
/// failure from a REALITY handshake or VLESS/upstream failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialFailureStage {
    /// TCP connect to the server failed or timed out.
    TcpConnect,
    /// REALITY TLS 1.3 handshake failed after TCP connected.
    RealityHandshake,
    /// VLESS request/response handling failed after the TLS session was up.
    Upstream,
}

impl DialFailureStage {
    /// Stable short name for logs and the status file.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TcpConnect => "tcp_connect",
            Self::RealityHandshake => "reality_handshake",
            Self::Upstream => "upstream",
        }
    }

    const fn code(self) -> u64 {
        match self {
            Self::TcpConnect => 1,
            Self::RealityHandshake => 2,
            Self::Upstream => 3,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::TcpConnect),
            2 => Some(Self::RealityHandshake),
            3 => Some(Self::Upstream),
            _ => None,
        }
    }

    /// Maps a [`beam_core::client`] stage name to the failing dial stage.
    /// Anything after the TLS handshake counts as upstream, never as a connect
    /// failure.
    fn from_client_stage(stage: &str) -> Self {
        match stage {
            beam_core::client::STAGE_TCP_CONNECT => Self::TcpConnect,
            beam_core::client::STAGE_REALITY_HANDSHAKE => Self::RealityHandshake,
            _ => Self::Upstream,
        }
    }
}

/// Coarse classification of the most recent dial failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialFailureKind {
    /// TCP connect or handshake deadline elapsed.
    Timeout,
    /// Connection refused by the server.
    Refused,
    /// Connection reset or aborted mid-handshake.
    Reset,
    /// Network or host unreachable.
    Unreachable,
    /// Address not available for the configured family.
    AddrNotAvailable,
    /// Any other error (TLS/VLESS protocol, permission, ...).
    Other,
}

impl DialFailureKind {
    /// Stable short name for logs and the status file.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Refused => "refused",
            Self::Reset => "reset",
            Self::Unreachable => "unreachable",
            Self::AddrNotAvailable => "addr_not_available",
            Self::Other => "other",
        }
    }

    fn from_io_error(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::Timeout,
            io::ErrorKind::ConnectionRefused => Self::Refused,
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => Self::Reset,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => Self::Unreachable,
            io::ErrorKind::AddrNotAvailable => Self::AddrNotAvailable,
            _ => Self::Other,
        }
    }

    const fn code(self) -> u64 {
        match self {
            Self::Timeout => 1,
            Self::Refused => 2,
            Self::Reset => 3,
            Self::Unreachable => 4,
            Self::AddrNotAvailable => 5,
            Self::Other => 6,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Timeout),
            2 => Some(Self::Refused),
            3 => Some(Self::Reset),
            4 => Some(Self::Unreachable),
            5 => Some(Self::AddrNotAvailable),
            6 => Some(Self::Other),
            _ => None,
        }
    }
}

/// Last recorded dial failure (stage plus coarse error kind).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialFailure {
    /// Failing handshake stage.
    pub stage: DialFailureStage,
    /// Coarse error classification.
    pub kind: DialFailureKind,
}

impl DialFailure {
    fn from_client_error(err: &ClientError) -> Self {
        match err {
            ClientError::Timeout { stage } => Self {
                stage: DialFailureStage::from_client_stage(stage),
                kind: DialFailureKind::Timeout,
            },
            ClientError::Io { stage, source } => Self {
                stage: DialFailureStage::from_client_stage(stage),
                kind: DialFailureKind::from_io_error(source),
            },
            ClientError::Reality(_) | ClientError::Tls(_) => Self {
                stage: DialFailureStage::RealityHandshake,
                kind: DialFailureKind::Other,
            },
            ClientError::Vless(_) => Self {
                stage: DialFailureStage::Upstream,
                kind: DialFailureKind::Other,
            },
        }
    }
}

/// Lock-free tracker of recent tunnel dial liveness, dial failures, and packet
/// drop counters.
///
/// Updated on every upstream `dial_tcp` attempt so health monitors can observe
/// live tunnel liveness without extra probes, and can distinguish "the server
/// accepts TCP but authenticated dials fail" from a healthy tunnel.
#[derive(Debug)]
pub struct TunnelActivity {
    origin: Instant,
    /// Elapsed milliseconds since `origin` + 1 (`0` means no dial recorded yet).
    last_success_ms_plus_one: AtomicU64,
    /// Last recorded dial RTT in milliseconds.
    last_rtt_ms: AtomicU64,
    /// Total failed upstream dials since process start.
    dial_failures: AtomicU64,
    /// Consecutive failed dials since the last success.
    consecutive_failures: AtomicU64,
    /// Elapsed milliseconds since `origin` + 1 of the last failure (`0` = none).
    last_failure_ms_plus_one: AtomicU64,
    /// [`DialFailureStage::code`] of the last failure (`0` = none).
    last_failure_stage: AtomicU64,
    /// [`DialFailureKind::code`] of the last failure (`0` = none).
    last_failure_kind: AtomicU64,
    /// Drop counters shared with the TUN engine, attached once at start.
    drops: OnceLock<Arc<DropCounters>>,
}

impl TunnelActivity {
    /// Creates an empty [`TunnelActivity`] tracker with no recorded dials.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_success_ms_plus_one: AtomicU64::new(0),
            last_rtt_ms: AtomicU64::new(0),
            dial_failures: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
            last_failure_ms_plus_one: AtomicU64::new(0),
            last_failure_stage: AtomicU64::new(0),
            last_failure_kind: AtomicU64::new(0),
            drops: OnceLock::new(),
        }
    }

    /// Records a successful upstream tunnel dial with its observed RTT in ms.
    pub fn record_dial_success(&self, rtt_ms: u64) {
        let elapsed_ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        self.last_rtt_ms.store(rtt_ms, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.last_success_ms_plus_one
            .store(elapsed_ms.saturating_add(1), Ordering::Release);
    }

    /// Records a failed upstream tunnel dial and its failing stage.
    pub fn record_dial_failure(&self, failure: DialFailure) {
        let elapsed_ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        let previous = self.last_failure_ms_plus_one.load(Ordering::Relaxed);
        self.dial_failures.fetch_add(1, Ordering::Relaxed);
        // A failure long after the previous one starts a fresh streak instead of
        // adding to an ancient one, so a brief blip never stays "degraded".
        if failure_streak_is_stale(previous, elapsed_ms, FAILURE_STREAK_WINDOW) {
            self.consecutive_failures.store(1, Ordering::Relaxed);
        } else {
            self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        }
        self.last_failure_stage
            .store(failure.stage.code(), Ordering::Relaxed);
        self.last_failure_kind
            .store(failure.kind.code(), Ordering::Relaxed);
        self.last_failure_ms_plus_one
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

    /// Total failed upstream dials since process start.
    pub fn dial_failure_count(&self) -> u64 {
        self.dial_failures.load(Ordering::Relaxed)
    }

    /// Consecutive failed upstream dials since the last success.
    pub fn consecutive_failure_count(&self) -> u64 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Returns the most recent [`DialFailure`] if it happened within `max_age`.
    pub fn recent_failure(&self, max_age: Duration) -> Option<DialFailure> {
        // Load the timestamp first with `Acquire`: the writer publishes stage and
        // kind before its `Release` store, so a fresh timestamp is never paired
        // with a stale stage or kind.
        let recorded = self.last_failure_ms_plus_one.load(Ordering::Acquire);
        if recorded == 0 {
            return None;
        }
        let stage = DialFailureStage::from_code(self.last_failure_stage.load(Ordering::Relaxed))?;
        let kind = DialFailureKind::from_code(self.last_failure_kind.load(Ordering::Relaxed))?;
        let now_ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let age_ms = now_ms.saturating_sub(recorded - 1);
        let max_age_ms = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
        (age_ms <= max_age_ms).then_some(DialFailure { stage, kind })
    }

    /// Returns the consecutive failure streak when the last failure is no older
    /// than `max_age`, or `0` when the tunnel recovered or the streak is stale.
    ///
    /// A non-zero result means authenticated dials are failing, so a bare TCP
    /// connect probe must not report the link as healthy.
    pub fn recent_failure_streak(&self, max_age: Duration) -> u64 {
        if self.recent_failure(max_age).is_none() {
            return 0;
        }
        self.consecutive_failure_count()
    }

    /// Attaches the engine drop counters so diagnostics can read them later.
    pub fn attach_drop_counters(&self, counters: Arc<DropCounters>) {
        let _ = self.drops.set(counters);
    }

    /// Returns a drop-counter snapshot, or an all-zero snapshot when the engine
    /// has not attached its counters yet.
    pub fn drop_snapshot(&self) -> DropSnapshot {
        self.drops
            .get()
            .map(|counters| counters.snapshot())
            .unwrap_or_default()
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
    let drops = Arc::new(DropCounters::default());
    stack.set_drop_counters(Arc::clone(&drops));
    if let Some(tracker) = activity.as_ref() {
        tracker.attach_drop_counters(Arc::clone(&drops));
    }
    let mut udp_bridge = UdpNatBridge::new(
        config.client.clone(),
        config.udp,
        tun_tx.clone(),
        Arc::clone(&stack_waker),
        Arc::clone(&drops),
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
                Arc::clone(&drops),
            );
        }

        // Drain any pending UDP/ICMP reply packets immediately.
        while let Ok(pkt) = tun_rx.try_recv() {
            if let Err(err) = device.send(&pkt).await {
                return Err(EngineError::Device(err));
            }
        }

        let tcp_delay = stack.poll_delay_ms(start.elapsed().as_millis() as i64);
        let udp_delay = update_udp_sweep_deadline(
            &mut next_udp_sweep_at,
            udp_bridge.next_sweep_delay_ms(),
            Instant::now(),
        );
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
                                    if let Some(rst) = build_tcp_rst_for_packet(&ip)
                                        && tun_tx.try_send(rst).is_err()
                                    {
                                        drops.tun_tx_full.incr();
                                    }
                                }
                                RouteDecision::RejectIcmpUnreachable => {
                                    if let Some(icmp) = build_icmp_port_unreachable(&ip)
                                        && tun_tx.try_send(icmp).is_err()
                                    {
                                        drops.tun_tx_full.incr();
                                    }
                                }
                                RouteDecision::Drop => drops.route.incr(),
                            }
                        } else if is_fragment(raw) {
                            drops.fragment.incr();
                        } else {
                            drops.ip_parse.incr();
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

/// Emits a rate-limited warning for an upstream relay I/O failure while the
/// per-connection detail stays at `debug` level.
fn warn_relay_io(dst: SocketAddr, op: &'static str, err: &io::Error) {
    debug!(%dst, op, error = %err, kind = ?err.kind(), "upstream relay I/O error");
    if let Some(suppressed) = RELAY_IO_LOG.allow() {
        warn!(
            %dst,
            op,
            error = %err,
            kind = ?err.kind(),
            suppressed,
            "upstream relay I/O error; closing flow"
        );
    }
}

/// Emits a rate-limited warning for an upstream relay I/O timeout.
fn warn_relay_timeout(dst: SocketAddr, op: &'static str, idle: Duration) {
    debug!(%dst, op, ?idle, "upstream relay I/O timed out");
    if let Some(suppressed) = RELAY_IO_LOG.allow() {
        warn!(
            %dst,
            op,
            idle_ms = idle.as_millis(),
            suppressed,
            "upstream relay I/O timed out; closing flow"
        );
    }
}

fn spawn_tcp_relay(
    mut conn: AcceptedTcpStream,
    client_config: BeamClientConfig,
    permits: Arc<Semaphore>,
    mut network_reset: Option<watch::Receiver<u64>>,
    activity: Option<Arc<TunnelActivity>>,
    drops: Arc<DropCounters>,
) {
    let Ok(permit) = permits.try_acquire_owned() else {
        debug!(dst = %conn.dst, "TCP connection limit reached; aborting with RST");
        if let Some(suppressed) = TCP_LIMIT_LOG.allow() {
            warn!(
                dst = %conn.dst,
                suppressed,
                "TCP connection limit reached; resetting new flow"
            );
        }
        drops.tcp_limit.incr();
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
                    let failure = DialFailure::from_client_error(&err);
                    if let Some(tracker) = activity.as_ref() {
                        tracker.record_dial_failure(failure);
                    }
                    debug!(
                        dst = %conn.dst,
                        error = %err,
                        stage = failure.stage.as_str(),
                        kind = failure.kind.as_str(),
                        "dial_tcp failed"
                    );
                    if let Some(suppressed) = DIAL_FAILURE_LOG.allow() {
                        warn!(
                            dst = %conn.dst,
                            server = %client_config.server_addr,
                            error = %err,
                            stage = failure.stage.as_str(),
                            kind = failure.kind.as_str(),
                            consecutive = activity
                                .as_ref()
                                .map(|t| t.consecutive_failure_count())
                                .unwrap_or(0),
                            suppressed,
                            "upstream dial failed; resetting local flow"
                        );
                    }
                    conn.stream.abort();
                    return;
                }
            }
        };

        let idle = client_config.idle_timeout;
        let (mut tun_r, mut tun_w) = conn.stream.into_split();
        let (mut up_r, mut up_w) = tokio::io::split(upstream);

        let c2s = async {
            // Reused across iterations so coalescing never grows a fresh Vec per
            // write; stays empty (zero allocation) when no coalescing is needed.
            let mut scratch: Vec<u8> = Vec::new();
            loop {
                let chunk = match timeout(idle, tun_r.recv_chunk()).await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => {
                        let _ = timeout(SHUTDOWN_TIMEOUT, up_w.shutdown()).await;
                        break;
                    }
                    Err(_) => break,
                };
                // Coalesce immediately-queued small chunks up to C2S_COALESCE_TARGET
                // so multi-flow uploads write full TLS records with fewer syscalls.
                let coalesced = coalesce_c2s(&chunk, &mut scratch, || tun_r.try_recv_chunk());
                let out: &[u8] = if coalesced { &scratch } else { &chunk };
                match timeout(idle, up_w.write_all(out)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn_relay_io(conn.dst, "write", &err);
                        break;
                    }
                    Err(_) => {
                        warn_relay_timeout(conn.dst, "write", idle);
                        break;
                    }
                }
                // Do not retain more than one coalescing window after an oversize
                // chunk grew the scratch buffer.
                if scratch.capacity() > C2S_COALESCE_TARGET {
                    scratch.shrink_to(C2S_COALESCE_TARGET);
                }
                // Flush only when no further chunk is already queued, preserving
                // 0 ms interactive latency while avoiding per-chunk flush stalls
                // during bulk uploads.
                if tun_r.has_queued() {
                    continue;
                }
                match timeout(idle, up_w.flush()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn_relay_io(conn.dst, "flush", &err);
                        break;
                    }
                    Err(_) => {
                        warn_relay_timeout(conn.dst, "flush", idle);
                        break;
                    }
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
                    Ok(Err(err)) => {
                        warn_relay_io(conn.dst, "read", &err);
                        break;
                    }
                    Err(_) => {
                        warn_relay_timeout(conn.dst, "read", idle);
                        break;
                    }
                };
                match timeout(idle, tun_w.send_chunk_pooled(&buf[..n])).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn_relay_io(conn.dst, "send_chunk", &err);
                        break;
                    }
                    Err(_) => {
                        warn_relay_timeout(conn.dst, "send_chunk", idle);
                        break;
                    }
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

/// Appends already-queued chunks to `scratch` until it reaches
/// [`C2S_COALESCE_TARGET`].
///
/// Returns `false` and leaves `scratch` empty when `first` alone already fills
/// a whole window or no second chunk is queued, so single-chunk writes go out
/// directly from the caller's buffer without an extra copy. The bound is
/// checked on the accumulated length, never on `first` alone.
fn coalesce_c2s<F>(first: &[u8], scratch: &mut Vec<u8>, mut next: F) -> bool
where
    F: FnMut() -> Option<Vec<u8>>,
{
    scratch.clear();
    if first.len() >= C2S_COALESCE_TARGET {
        return false;
    }
    let Some(second) = next() else {
        return false;
    };
    scratch.extend_from_slice(first);
    scratch.extend_from_slice(&second);
    while scratch.len() < C2S_COALESCE_TARGET {
        let Some(chunk) = next() else {
            break;
        };
        scratch.extend_from_slice(&chunk);
    }
    true
}

/// Returns `true` when a failure recorded at `previous_ms_plus_one` is too old
/// to extend the current streak, so the new failure must start a fresh one.
fn failure_streak_is_stale(previous_ms_plus_one: u64, now_ms: u64, window: Duration) -> bool {
    if previous_ms_plus_one == 0 {
        return true;
    }
    now_ms.saturating_sub(previous_ms_plus_one - 1)
        > u64::try_from(window.as_millis()).unwrap_or(u64::MAX)
}

/// Updates the sticky UDP sweep deadline, shortening it whenever a more urgent
/// wakeup interval (such as an XUDP reconnect backoff retry) is requested.
fn update_udp_sweep_deadline(
    next_udp_sweep_at: &mut Option<Instant>,
    interval_ms: Option<u64>,
    now: Instant,
) -> Option<u64> {
    match interval_ms {
        Some(interval_ms) => {
            let candidate = now + Duration::from_millis(interval_ms);
            let deadline = match *next_udp_sweep_at {
                Some(existing) => existing.min(candidate),
                None => candidate,
            };
            *next_udp_sweep_at = Some(deadline);
            Some(deadline.saturating_duration_since(now).as_millis() as u64)
        }
        None => {
            *next_udp_sweep_at = None;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn test_failure() -> DialFailure {
        DialFailure {
            stage: DialFailureStage::TcpConnect,
            kind: DialFailureKind::Refused,
        }
    }

    #[test]
    fn c2s_coalescing_stops_once_the_target_is_reached() {
        let chunk_len = C2S_COALESCE_TARGET / 2;
        let mut queue: VecDeque<Vec<u8>> = (0..4).map(|_| vec![0xab; chunk_len]).collect();
        let first = vec![0x11u8; 1024];
        let mut scratch = Vec::new();

        let coalesced = coalesce_c2s(&first, &mut scratch, || queue.pop_front());

        assert!(coalesced);
        assert!(scratch.starts_with(&first));
        assert_eq!(
            scratch.len(),
            1024 + 2 * chunk_len,
            "the bound must be checked on the accumulated length, not on the first chunk"
        );
        assert_eq!(
            queue.len(),
            2,
            "coalescing must stop once the target is reached"
        );

        // A chunk that already fills a window is written without a copy or a pull.
        let mut scratch = Vec::new();
        let big = vec![7u8; C2S_COALESCE_TARGET];
        let coalesced = coalesce_c2s(&big, &mut scratch, || -> Option<Vec<u8>> {
            panic!("an oversize chunk must not pull more data")
        });
        assert!(!coalesced);
        assert!(scratch.is_empty());

        // An empty queue leaves the first chunk alone without copying into `scratch`.
        let mut scratch = Vec::new();
        assert!(!coalesce_c2s(&first, &mut scratch, || None));
        assert!(scratch.is_empty());
    }

    #[test]
    fn dial_failure_classifies_every_client_stage() {
        // Every stage a `ClientError` can carry, pinned to its dial stage.
        let stages = [
            (
                beam_core::client::STAGE_TCP_CONNECT,
                DialFailureStage::TcpConnect,
            ),
            (
                beam_core::client::STAGE_REALITY_HANDSHAKE,
                DialFailureStage::RealityHandshake,
            ),
            (
                beam_core::client::STAGE_VLESS_WRITE,
                DialFailureStage::Upstream,
            ),
            (
                beam_core::client::STAGE_VLESS_FLUSH,
                DialFailureStage::Upstream,
            ),
        ];
        for (stage, expected) in stages {
            let timeout = DialFailure::from_client_error(&ClientError::Timeout { stage });
            assert_eq!(timeout.stage, expected, "timeout at {stage}");
            assert_eq!(timeout.kind, DialFailureKind::Timeout);

            // A post-connect I/O failure keeps its stage instead of being
            // reported as a TCP connect failure.
            let io = DialFailure::from_client_error(&ClientError::Io {
                stage,
                source: io::Error::from(io::ErrorKind::ConnectionReset),
            });
            assert_eq!(io.stage, expected, "I/O error at {stage}");
            assert_eq!(io.kind, DialFailureKind::Reset);
        }

        // A connect-refused I/O error stays a connect failure with its kind.
        let refused = DialFailure::from_client_error(&ClientError::Io {
            stage: beam_core::client::STAGE_TCP_CONNECT,
            source: io::Error::from(io::ErrorKind::ConnectionRefused),
        });
        assert_eq!(refused.stage, DialFailureStage::TcpConnect);
        assert_eq!(refused.kind, DialFailureKind::Refused);

        // REALITY/VLESS protocol errors are stage-fixed.
        let reality = DialFailure::from_client_error(&ClientError::Reality(
            beam_core::reality::RealityClientError::Clock,
        ));
        assert_eq!(reality.stage, DialFailureStage::RealityHandshake);
        let vless = DialFailure::from_client_error(&ClientError::Vless(
            beam_core::vless::VlessError::UnsupportedVersion(1),
        ));
        assert_eq!(vless.stage, DialFailureStage::Upstream);
    }

    #[test]
    fn failure_streak_ages_out_after_the_window() {
        let window = FAILURE_STREAK_WINDOW;
        // No previous failure always starts a fresh streak.
        assert!(failure_streak_is_stale(0, 5_000, window));
        // Within the window the streak keeps growing (boundary included).
        assert!(!failure_streak_is_stale(1_001, 2_000, window));
        assert!(!failure_streak_is_stale(1_001, 31_000, window));
        assert!(failure_streak_is_stale(1_001, 31_001, window));

        // An aged activity resets the counter instead of reviving the old streak.
        let aged = TunnelActivity {
            origin: Instant::now() - window - Duration::from_secs(1),
            ..TunnelActivity::new()
        };
        aged.record_dial_failure(test_failure());
        assert_eq!(aged.consecutive_failure_count(), 1);
        // Pretend the last failure was the very first millisecond of the process.
        aged.last_failure_ms_plus_one.store(1, Ordering::Relaxed);
        aged.record_dial_failure(test_failure());
        assert_eq!(
            aged.consecutive_failure_count(),
            1,
            "a failure over the streak window old must not extend the streak"
        );
        assert_eq!(aged.dial_failure_count(), 2);

        // Back-to-back failures still accumulate and report the latest stage.
        let activity = TunnelActivity::new();
        activity.record_dial_failure(test_failure());
        activity.record_dial_failure(DialFailure {
            stage: DialFailureStage::RealityHandshake,
            kind: DialFailureKind::Other,
        });
        assert_eq!(activity.consecutive_failure_count(), 2);
        assert_eq!(
            activity.recent_failure(Duration::from_secs(5)),
            Some(DialFailure {
                stage: DialFailureStage::RealityHandshake,
                kind: DialFailureKind::Other,
            })
        );
    }

    #[test]
    fn udp_sweep_deadline_shrinks_when_backoff_interval_is_shorter() {
        let now = Instant::now();
        let mut deadline = None;

        // Initial idle session sweep sets a 5s deadline.
        let d1 = update_udp_sweep_deadline(&mut deadline, Some(5_000), now);
        assert_eq!(d1, Some(5_000));

        // A 250ms XUDP reconnect backoff arrives 10ms later; deadline must shrink.
        let t1 = now + Duration::from_millis(10);
        let d2 = update_udp_sweep_deadline(&mut deadline, Some(250), t1);
        assert_eq!(d2, Some(250));
        assert_eq!(deadline, Some(t1 + Duration::from_millis(250)));

        // A later larger interval must not push an earlier deadline forward.
        let t2 = t1 + Duration::from_millis(50);
        let d3 = update_udp_sweep_deadline(&mut deadline, Some(5_000), t2);
        assert_eq!(d3, Some(200));

        // Clearing when idle resets the sticky deadline.
        assert_eq!(update_udp_sweep_deadline(&mut deadline, None, t2), None);
        assert_eq!(deadline, None);
    }

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
