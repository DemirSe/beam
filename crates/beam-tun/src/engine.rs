//! Main async TUN engine loop connecting [`TunDevice`], [`RoutePolicy`],
//! [`NetStack`], `beam_core::client::dial_tcp`, and [`UdpNatBridge`].

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};

use beam_core::address::{Address, NetLocation};
use beam_core::client::{BeamClientConfig, ClientError, dial_tcp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, Semaphore, mpsc, watch};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::device::TunDevice;
use crate::dns::{DnsConfig, DnsInterceptor};
use crate::packet::{
    IP_PROTO_TCP, IpPacketView, build_icmp_port_unreachable, build_tcp_rst_for_packet, is_fragment,
    parse_ip, parse_tcp, parse_udp,
};
use crate::ratelimit::RateLimiter;
use crate::router::{RouteDecision, RoutePolicy};
use crate::stack::{AcceptedTcpStream, NetStack};
use crate::stats::{DnsCounters, DnsSnapshot, DropCounters, DropSnapshot};
use crate::udp::{UdpBridgeConfig, UdpNatBridge};

const MAX_PACKET_BUF: usize = 65_536;
const TUN_TX_CHANNEL_CAP: usize = 512;
const RX_BATCH_MAX: usize = 128;
/// Pending UDP/DNS/ICMP replies drained per loop iteration before the engine
/// returns to `device.recv`. Match the inbound batch limit so a synchronous
/// reject flood cannot enqueue more replies than one drain removes.
const TUN_RX_DRAIN_MAX: usize = RX_BATCH_MAX;
const _: () = assert!(TUN_RX_DRAIN_MAX >= RX_BATCH_MAX);
const _: () = assert!(TUN_RX_DRAIN_MAX <= TUN_TX_CHANNEL_CAP);
const C2S_COALESCE_TARGET: usize = 64 * 1024;
// Android uses 16 KiB (one max TLS 1.3 record) to cut worst-case 128-flow
// transient RSS by 4x without hurting TLS throughput.
#[cfg(target_os = "android")]
const S2C_READ_BUF_BYTES: usize = 16 * 1024;
#[cfg(not(target_os = "android"))]
const S2C_READ_BUF_BYTES: usize = 64 * 1024;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// Upper bound on simultaneous upstream REALITY handshakes so an outage or
/// burst of new flows cannot starve active relay tasks on small worker pools.
const MAX_CONCURRENT_DIALS: usize = 16;
/// Queue budget for excess dials, independent of the whole handshake timeout.
const DIAL_QUEUE_WAIT: Duration = Duration::from_secs(2);
/// Consecutive dial failures within [`FAILURE_STREAK_WINDOW`] that engage
/// outage fast-fail backoff (probing with exponential delay 1 s -> 5 s).
const OUTAGE_BACKOFF_STREAK: u64 = 5;
const OUTAGE_PROBE_INITIAL_MS: u64 = 1_000;
const OUTAGE_PROBE_MAX_MS: u64 = 5_000;
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
/// At most 2 transient TUN send warnings per 10 s window.
static TUN_SEND_LOG: LazyLock<RateLimiter> =
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
    /// Optional idle timeout for the *reads* of the established TCP relay loops.
    ///
    /// `None` removes only the relay read cap, so 15-minute FCM/MTalk push
    /// sockets stay alive under `ProxyTcpStack::idle_timeout_ms` plus upstream
    /// keepalive/`TCP_USER_TIMEOUT`. Relay writes always keep a bounded
    /// deadline: `None` falls back to
    /// [`BeamClientConfig::idle_timeout`](beam_core::client::BeamClientConfig::idle_timeout),
    /// so a peer that stops draining can never wedge a relay task. `Some(dur)`
    /// bounds reads and writes with `dur`, the classic per-direction cap.
    pub tcp_relay_idle_timeout: Option<Duration>,
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
    /// Number of currently active proxied TCP relay tasks.
    active_tcp_flows: AtomicU64,
    /// Number of currently active proxied UDP NAT sessions.
    active_udp_sessions: Arc<AtomicU64>,
    /// Total proxied TCP payload bytes written upstream (client -> server).
    bytes_tx: AtomicU64,
    /// Total proxied TCP payload bytes read from upstream (server -> client).
    bytes_rx: AtomicU64,
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
            active_tcp_flows: AtomicU64::new(0),
            active_udp_sessions: Arc::new(AtomicU64::new(0)),
            bytes_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
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

    /// Forgets the last successful dial so a pre-reset success cannot be read
    /// as a fresh signal after a network change.
    pub fn clear_dial_success(&self) {
        self.last_success_ms_plus_one.store(0, Ordering::Release);
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

    /// Clears the consecutive failure streak (e.g. after a network handoff so
    /// a dead previous network does not throttle dials on the new network).
    pub fn reset_failure_streak(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    /// Number of currently active proxied TCP relay flows.
    pub fn active_tcp_flows(&self) -> u64 {
        self.active_tcp_flows.load(Ordering::Relaxed)
    }

    /// Number of currently active proxied UDP NAT sessions.
    pub fn active_udp_sessions(&self) -> u64 {
        self.active_udp_sessions.load(Ordering::Relaxed)
    }

    pub(crate) fn udp_session_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.active_udp_sessions)
    }

    /// Total proxied TCP payload bytes sent upstream (client -> server).
    pub fn bytes_tx(&self) -> u64 {
        self.bytes_tx.load(Ordering::Relaxed)
    }

    /// Total proxied TCP payload bytes received from upstream (server -> client).
    pub fn bytes_rx(&self) -> u64 {
        self.bytes_rx.load(Ordering::Relaxed)
    }

    /// Adds `n` upstream-sent payload bytes.
    pub fn record_bytes_tx(&self, n: u64) {
        self.bytes_tx.fetch_add(n, Ordering::Relaxed);
    }

    /// Adds `n` upstream-received payload bytes.
    pub fn record_bytes_rx(&self, n: u64) {
        self.bytes_rx.fetch_add(n, Ordering::Relaxed);
    }

    /// Increments the active TCP flow counter; returns an RAII guard that
    /// decrements it when the relay task finishes or is cancelled.
    fn enter_tcp_flow(self: &Arc<Self>) -> ActiveTcpFlowGuard {
        self.active_tcp_flows.fetch_add(1, Ordering::Relaxed);
        ActiveTcpFlowGuard {
            activity: Arc::clone(self),
        }
    }

    /// Returns the most recent [`DialFailure`] regardless of age, or `None`
    /// when no dial ever failed.
    pub fn last_failure(&self) -> Option<DialFailure> {
        // Load the timestamp first with `Acquire`: the writer publishes stage
        // and kind before its `Release` store, so a fresh timestamp is never
        // paired with a stale stage or kind.
        if self.last_failure_ms_plus_one.load(Ordering::Acquire) == 0 {
            return None;
        }
        let stage = DialFailureStage::from_code(self.last_failure_stage.load(Ordering::Relaxed))?;
        let kind = DialFailureKind::from_code(self.last_failure_kind.load(Ordering::Relaxed))?;
        Some(DialFailure { stage, kind })
    }

    /// Returns the most recent [`DialFailure`] if it happened within `max_age`.
    pub fn recent_failure(&self, max_age: Duration) -> Option<DialFailure> {
        // One `Acquire` load of the timestamp: the writer publishes stage and
        // kind before its `Release` store, so a fresh timestamp is never
        // paired with a stale stage or kind. Stage/kind follow with `Relaxed`
        // loads under that `Acquire`, with no second timestamp load.
        let recorded = self.last_failure_ms_plus_one.load(Ordering::Acquire);
        if recorded == 0 {
            return None;
        }
        let stage = DialFailureStage::from_code(self.last_failure_stage.load(Ordering::Relaxed))?;
        let kind = DialFailureKind::from_code(self.last_failure_kind.load(Ordering::Relaxed))?;
        let failure = DialFailure { stage, kind };
        let now_ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let age_ms = now_ms.saturating_sub(recorded - 1);
        let max_age_ms = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
        (age_ms <= max_age_ms).then_some(failure)
    }

    /// Returns how long ago the last dial succeeded, or `None` when no dial
    /// ever succeeded.
    pub fn last_success_age(&self) -> Option<Duration> {
        let recorded = self.last_success_ms_plus_one.load(Ordering::Acquire);
        if recorded == 0 {
            return None;
        }
        Some(
            self.origin
                .elapsed()
                .saturating_sub(Duration::from_millis(recorded - 1)),
        )
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
    device: D,
    stack: S,
    config: TunEngineConfig,
    shutdown: watch::Receiver<bool>,
    activity: Option<Arc<TunnelActivity>>,
) -> Result<(), EngineError>
where
    D: TunDevice,
    S: NetStack,
{
    let drops = Arc::new(DropCounters::default());
    run_engine_inner(device, stack, config, shutdown, activity, drops, None).await
}

/// Pure-Rust live health handle for Android UI and notification polling.
///
/// Clone the handle before [`run_tun_engine_with_telemetry`] and call
/// [`EngineTelemetry::snapshot`] from any thread. It reads the same lock-free
/// counters the engine updates, so polling never touches the Linux
/// `/run/beam-client/status` file.
#[derive(Clone, Debug)]
pub struct EngineTelemetry {
    /// Upstream dial liveness tracker shared with the engine relay tasks.
    pub activity: Arc<TunnelActivity>,
    /// Packet drop counters shared with the engine, stack, and UDP bridge.
    pub drops: Arc<DropCounters>,
    /// DNS outcome counters shared with the DNS interceptor when the engine
    /// runs with DNS enabled. Build the handle with
    /// [`EngineTelemetry::with_dns`] so the snapshot carries DNS health.
    pub dns: Option<Arc<DnsCounters>>,
}

impl EngineTelemetry {
    /// Creates a telemetry handle without DNS counters.
    pub fn new() -> Self {
        Self {
            activity: Arc::new(TunnelActivity::new()),
            drops: Arc::new(DropCounters::default()),
            dns: None,
        }
    }

    /// Creates a telemetry handle with DNS counters attached.
    pub fn with_dns() -> Self {
        Self {
            activity: Arc::new(TunnelActivity::new()),
            drops: Arc::new(DropCounters::default()),
            dns: Some(Arc::new(DnsCounters::default())),
        }
    }

    /// Takes a point-in-time health snapshot for UI display.
    pub fn snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            drops: self.drops.snapshot(),
            dns: self.dns.as_ref().map(|counters| counters.snapshot()),
            last_dial_success_age: self.activity.last_success_age(),
            consecutive_dial_failures: self.activity.consecutive_failure_count(),
            last_dial_failure: self.activity.last_failure(),
        }
    }
}

impl Default for EngineTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time tunnel health for Android UI and notification display.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TelemetrySnapshot {
    /// Packet drop counters.
    pub drops: DropSnapshot,
    /// DNS outcome counters, present whenever the handle was built with
    /// [`EngineTelemetry::with_dns`]. The counters stay at zero when the engine
    /// ran with `dns: None`.
    pub dns: Option<DnsSnapshot>,
    /// Age of the last successful upstream dial, if any dial succeeded.
    pub last_dial_success_age: Option<Duration>,
    /// Consecutive failed upstream dials since the last success.
    pub consecutive_dial_failures: u64,
    /// Most recent dial failure, if any dial ever failed.
    pub last_dial_failure: Option<DialFailure>,
}

/// Runs the TUN packet engine with a shared [`EngineTelemetry`] handle.
///
/// Behaves exactly like [`run_tun_engine_with_activity`] with the handle's
/// activity tracker attached, and additionally shares the handle's drop and
/// DNS counters with the engine instead of allocating fresh ones, so
/// [`EngineTelemetry::snapshot`] observes live values while the engine runs.
pub async fn run_tun_engine_with_telemetry<D, S>(
    device: D,
    stack: S,
    config: TunEngineConfig,
    shutdown: watch::Receiver<bool>,
    telemetry: EngineTelemetry,
) -> Result<(), EngineError>
where
    D: TunDevice,
    S: NetStack,
{
    run_engine_inner(
        device,
        stack,
        config,
        shutdown,
        Some(Arc::clone(&telemetry.activity)),
        Arc::clone(&telemetry.drops),
        telemetry.dns.clone(),
    )
    .await
}

async fn run_engine_inner<D, S>(
    mut device: D,
    mut stack: S,
    mut config: TunEngineConfig,
    mut shutdown: watch::Receiver<bool>,
    activity: Option<Arc<TunnelActivity>>,
    drops: Arc<DropCounters>,
    dns_counters: Option<Arc<DnsCounters>>,
) -> Result<(), EngineError>
where
    D: TunDevice,
    S: NetStack,
{
    let start = Instant::now();
    if dns_counters.is_some() && config.dns.is_none() {
        debug!(
            "telemetry DNS counters are attached but the engine runs without DNS; the UI DNS section stays at zero",
        );
    }
    let stack_waker = stack.waker();
    let tcp_permits = Arc::new(Semaphore::new(config.max_tcp_connections.max(1)));
    let dial_gate = Arc::new(DialGate::new(
        config.max_tcp_connections.clamp(1, MAX_CONCURRENT_DIALS),
        start,
    ));
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(TUN_TX_CHANNEL_CAP);
    stack.set_drop_counters(Arc::clone(&drops));
    if let Some(tracker) = activity.as_ref() {
        tracker.attach_drop_counters(Arc::clone(&drops));
    }
    let mut udp_bridge = UdpNatBridge::with_session_counter(
        config.client.clone(),
        config.udp,
        tun_tx.clone(),
        Arc::clone(&stack_waker),
        Arc::clone(&drops),
        activity
            .as_ref()
            .map(|tracker| tracker.udp_session_counter()),
    );
    let dns_interceptor = config
        .dns
        .as_ref()
        .map(|dns_cfg| match dns_counters.as_ref() {
            Some(counters) => DnsInterceptor::with_counters(
                config.client.clone(),
                dns_cfg.clone(),
                tun_tx.clone(),
                Arc::clone(counters),
            ),
            None => DnsInterceptor::new(config.client.clone(), dns_cfg.clone(), tun_tx.clone()),
        })
        .map(Arc::new);
    let tun_dns_peer = config.dns.as_ref().and_then(|dns| dns.tun_dns_peer);
    let mut network_reset = config.network_reset.clone();
    // The server IP currently excluded from tunneling; a handover swaps it so
    // the new endpoint is never routed back into the tunnel.
    let mut active_server_ip = config.client.server_addr.ip();
    let client_config = Arc::new(config.client);

    let mut recv_buf = vec![0u8; device.mtu().clamp(2048, MAX_PACKET_BUF)];
    let mut tx_batch: Vec<Vec<u8>> = Vec::with_capacity(64);
    let mut accepted: Vec<AcceptedTcpStream> = Vec::with_capacity(16);
    let mut next_udp_sweep_at: Option<Instant> = None;
    // One pinned timer for the whole engine loop: resetting it is much cheaper
    // than registering and dropping a fresh `sleep` on every iteration.
    let mut timer_deadline: Option<Instant> = None;
    let mut timer_sleep = std::pin::pin!(tokio::time::sleep_until(tokio::time::Instant::now()));

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

        // Drain interactive UDP/DNS/ICMP reply packets before bulk TCP segments
        // so voice/gaming/DNS traffic does not wait behind a full download burst,
        // bounded so a sustained reply stream cannot postpone TUN reads.
        drain_reply_queue(&mut device, &mut tun_rx, &drops).await?;

        for pkt in tx_batch.drain(..) {
            send_tun_packet(&mut device, &pkt, &drops).await?;
            stack.recycle_tx_buf(pkt);
        }

        for conn in accepted.drain(..) {
            if is_tun_dns_tcp_target(conn.dst, tun_dns_peer)
                && let Some(dns) = dns_interceptor.clone()
            {
                spawn_dns_tcp_stream(
                    conn,
                    dns,
                    Arc::clone(&tcp_permits),
                    network_reset.clone(),
                    shutdown.clone(),
                );
                continue;
            }
            spawn_tcp_relay(
                conn,
                Arc::clone(&client_config),
                Arc::clone(&tcp_permits),
                Arc::clone(&dial_gate),
                network_reset.clone(),
                activity.clone(),
                Arc::clone(&drops),
                config.tcp_relay_idle_timeout,
                shutdown.clone(),
            );
        }

        let tcp_delay = stack.poll_delay_ms(start.elapsed().as_millis() as i64);
        // Sweep due NAT entries before the biased select: a continuously ready
        // device branch would otherwise starve the timer branch below it.
        let (swept, udp_delay_ms) = udp_bridge.sweep_if_due();
        let udp_delay = update_udp_sweep_after_scan(
            &mut next_udp_sweep_at,
            swept,
            udp_delay_ms,
            Instant::now(),
        );
        let next_timer_ms = match (tcp_delay, udp_delay) {
            (Some(a), Some(b)) => Some(a.min(b).max(1)),
            (Some(a), None) | (None, Some(a)) => Some(a.max(1)),
            (None, None) => None,
        };

        let now = Instant::now();
        if timer_deadline.is_some_and(|deadline| deadline <= now) {
            timer_deadline = None;
        }
        if let Some(deadline) = rearm_deadline(timer_deadline, now, next_timer_ms) {
            timer_sleep
                .as_mut()
                .reset(tokio::time::Instant::from_std(deadline));
            timer_deadline = Some(deadline);
        }

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
                if let Some(override_lock) = client_config.server_addr_override.as_ref() {
                    let new_ip = override_lock
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .ip();
                    if new_ip != active_server_ip {
                        config.route.exclude_ips.replace(active_server_ip, new_ip);
                        active_server_ip = new_ip;
                    }
                }
                info!(generation, "network transition detected; resetting TCP flows, XUDP mux, and local DNS cache");
                stack.reset_all(&mut tx_batch);
                for pkt in tx_batch.drain(..) {
                    send_tun_packet(&mut device, &pkt, &drops).await?;
                    stack.recycle_tx_buf(pkt);
                }
                udp_bridge.reset();
                dial_gate.record_success();
                if let Some(tracker) = activity.as_ref() {
                    tracker.reset_failure_streak();
                }
                if let Some(dns) = dns_interceptor.as_ref() {
                    dns.on_network_change();
                }
            }
            read_res = device.recv(&mut recv_buf) => {
                let mut n = read_res?;
                for batch_idx in 0..RX_BATCH_MAX {
                    if n > 0 {
                        let raw = &recv_buf[..n];
                        if let Some(ip) = parse_ip(raw) {
                            let decision = if is_tun_dns_tcp_packet(&ip, tun_dns_peer) {
                                // The peer is a private address, so the normal
                                // private-drop policy would blackhole the
                                // stub's TCP retry before the stack sees it.
                                RouteDecision::ProxyTcp
                            } else {
                                config.route.classify(&ip)
                            };
                            match decision {
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
                                RouteDecision::RejectTcpRst => match tun_tx.try_reserve() {
                                    Ok(permit) => {
                                        if let Some(rst) = build_tcp_rst_for_packet(&ip) {
                                            permit.send(rst);
                                        }
                                    }
                                    Err(_) => drops.tun_tx_full.incr(),
                                },
                                RouteDecision::RejectIcmpUnreachable => match tun_tx.try_reserve() {
                                    Ok(permit) => {
                                        if let Some(icmp) = build_icmp_port_unreachable(&ip) {
                                            permit.send(icmp);
                                        }
                                    }
                                    Err(_) => drops.tun_tx_full.incr(),
                                },
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
            // Kept below `device.recv` so queued replies never starve TUN reads.
            Some(reply_pkt) = tun_rx.recv() => {
                send_tun_packet(&mut device, &reply_pkt, &drops).await?;
            }
            () = stack_waker.notified() => {}
            () = async {
                match timer_deadline {
                    Some(_) => (&mut timer_sleep).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                timer_deadline = None;
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

/// Drains at most [`TUN_RX_DRAIN_MAX`] queued replies before the engine reads
/// more packets, keeping the loop bounded by [`TUN_TX_CHANNEL_CAP`].
async fn drain_reply_queue<D: TunDevice>(
    device: &mut D,
    tun_rx: &mut mpsc::Receiver<Vec<u8>>,
    drops: &DropCounters,
) -> Result<(), EngineError> {
    for _ in 0..TUN_RX_DRAIN_MAX {
        let Ok(pkt) = tun_rx.try_recv() else {
            break;
        };
        send_tun_packet(device, &pkt, drops).await?;
    }
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

/// Runs `fut` with a deadline when `Some`, or awaits it directly when `None`.
///
/// Relay writes pass `Some` in both modes so a peer that stops draining can
/// never wedge a task. Relay reads use [`RelayIdle`] instead; see
/// [`spawn_tcp_relay`].
async fn with_relay_idle<T>(
    idle: Option<Duration>,
    fut: impl std::future::Future<Output = T>,
) -> Result<T, ()> {
    match idle {
        Some(budget) => timeout(budget, fut).await.map_err(|_| ()),
        None => Ok(fut.await),
    }
}

/// Relay write deadline: always bounded, so `None` falls back to the client
/// idle timeout.
fn relay_write_idle(relay_idle: Option<Duration>, client_idle: Duration) -> Duration {
    relay_idle.unwrap_or(client_idle)
}

/// One idle timestamp shared by both directions of a TCP relay. Any successful
/// read or write in either direction refreshes it, so a quiet download does not
/// kill a flow whose upload is still active. `touch` does not wake the idle
/// direction; each read checks the timestamp only when its sleep expires.
#[derive(Clone)]
struct RelayIdle {
    idle_ms: u64,
    origin: tokio::time::Instant,
    last_activity_ms: Arc<AtomicU64>,
}

impl RelayIdle {
    fn new(idle: Duration) -> Self {
        Self {
            idle_ms: u64::try_from(idle.as_millis()).unwrap_or(u64::MAX),
            origin: tokio::time::Instant::now(),
            last_activity_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn touch(&self) {
        self.last_activity_ms
            .store(self.now_ms(), Ordering::Release);
    }

    async fn read<T>(&self, fut: impl std::future::Future<Output = T>) -> Result<T, ()> {
        let mut fut = std::pin::pin!(fut);
        loop {
            let last = self.last_activity_ms.load(Ordering::Acquire);
            let wait_ms = last
                .saturating_add(self.idle_ms)
                .saturating_sub(self.now_ms());
            tokio::select! {
                biased;
                out = &mut fut => return Ok(out),
                _ = tokio::time::sleep(Duration::from_millis(wait_ms)) => {
                    if self.last_activity_ms.load(Ordering::Acquire) == last {
                        return Err(());
                    }
                }
            }
        }
    }
}

/// Sends one bounded upstream half-close, even when several relay exits race.
#[derive(Default)]
struct UpstreamShutdown {
    done: bool,
}

impl UpstreamShutdown {
    async fn once<W: AsyncWriteExt + Unpin>(&mut self, up_w: &mut W) {
        if self.done {
            return;
        }
        // Claim the shutdown before awaiting it so cancellation cannot leave a
        // second shutdown behind.
        self.done = true;
        let _ = timeout(SHUTDOWN_TIMEOUT, up_w.shutdown()).await;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TcpRelayExit {
    Complete,
    Shutdown,
    NetworkReset,
}

/// Releases the flow permit before any best-effort upstream half-close.
async fn finish_tcp_relay<W: AsyncWriteExt + Unpin>(
    permit: tokio::sync::OwnedSemaphorePermit,
    exit: TcpRelayExit,
    upstream_shutdown: &mut UpstreamShutdown,
    up_w: &mut W,
) {
    drop(permit);
    if exit == TcpRelayExit::Complete {
        upstream_shutdown.once(up_w).await;
    }
}

fn touch_relay(clock: Option<&RelayIdle>) {
    if let Some(clock) = clock {
        clock.touch();
    }
}

/// Applies the shared relay idle clock to a read when one is configured.
async fn relay_read<T>(
    clock: Option<&RelayIdle>,
    fut: impl std::future::Future<Output = T>,
) -> Result<T, ()> {
    match clock {
        Some(clock) => clock.read(fut).await,
        None => Ok(fut.await),
    }
}

/// Returns `true` when a TUN write error means the interface or descriptor is
/// permanently gone (`EBADF`, `ENXIO`, `ENODEV`, broken pipe, EOF). Transient
/// errors such as `ENOMEM`, `ENOBUFS`, or `EAGAIN` are counted and dropped so
/// brief memory/queue pressure cannot kill the whole tunnel.
fn is_fatal_tun_send_error(err: &io::Error) -> bool {
    if matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof | io::ErrorKind::NotConnected
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        const ENXIO: i32 = 6;
        const EBADF: i32 = 9;
        const ENODEV: i32 = 19;
        if matches!(err.raw_os_error(), Some(ENXIO | EBADF | ENODEV)) {
            return true;
        }
    }
    #[cfg(windows)]
    {
        // A WinTun session handle that closed or detached surfaces as one of
        // these codes; nothing but a new adapter recovers from them.
        // `ERROR_NO_MORE_ITEMS` (259) is deliberately excluded: WinTun returns
        // it when the TX ring is transiently full (backpressure, like ENOBUFS).
        const ERROR_INVALID_HANDLE: i32 = 6;
        const ERROR_HANDLE_EOF: i32 = 38;
        const ERROR_BROKEN_PIPE: i32 = 109;
        const ERROR_DEVICE_NOT_CONNECTED: i32 = 1167;
        if matches!(
            err.raw_os_error(),
            Some(
                ERROR_INVALID_HANDLE
                    | ERROR_HANDLE_EOF
                    | ERROR_BROKEN_PIPE
                    | ERROR_DEVICE_NOT_CONNECTED
            )
        ) {
            return true;
        }
    }
    false
}

async fn send_tun_packet<D: TunDevice>(
    device: &mut D,
    pkt: &[u8],
    drops: &DropCounters,
) -> Result<(), EngineError> {
    match device.send(pkt).await {
        Ok(()) => Ok(()),
        Err(err) if is_fatal_tun_send_error(&err) => Err(EngineError::Device(err)),
        Err(err) => {
            drops.tun_tx_full.incr();
            if let Some(suppressed) = TUN_SEND_LOG.allow() {
                warn!(
                    error = %err,
                    kind = ?err.kind(),
                    suppressed,
                    "transient TUN send error; dropping packet"
                );
            }
            Ok(())
        }
    }
}

struct ActiveTcpFlowGuard {
    activity: Arc<TunnelActivity>,
}

impl Drop for ActiveTcpFlowGuard {
    fn drop(&mut self) {
        self.activity
            .active_tcp_flows
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Bounds concurrent upstream handshakes (queuing normal bursts rather than
/// RSTing them) and fast-fails excess dials during sustained server outages.
struct DialGate {
    permits: Arc<Semaphore>,
    next_probe_ms: AtomicU64,
    engine_start: Instant,
}

impl DialGate {
    fn new(max_concurrent: usize, engine_start: Instant) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent.max(1))),
            next_probe_ms: AtomicU64::new(0),
            engine_start,
        }
    }

    fn outage_backoff_ms(streak: u64) -> u64 {
        let shift = streak.saturating_sub(OUTAGE_BACKOFF_STREAK).min(3) as u32;
        OUTAGE_PROBE_INITIAL_MS
            .saturating_mul(1_u64 << shift)
            .min(OUTAGE_PROBE_MAX_MS)
    }

    /// Acquires a dial concurrency permit. Normal bursts above
    /// `MAX_CONCURRENT_DIALS` queue cleanly (bounded by `wait_budget`). During
    /// a sustained outage, only one probe per backoff interval is permitted and
    /// excess flows fast-fail without piling up REALITY handshakes.
    async fn acquire(
        &self,
        activity: Option<&TunnelActivity>,
        wait_budget: Duration,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let streak = activity
            .map(|tracker| tracker.recent_failure_streak(FAILURE_STREAK_WINDOW))
            .unwrap_or(0);
        if streak >= OUTAGE_BACKOFF_STREAK {
            let now_ms = self.engine_start.elapsed().as_millis() as u64;
            let next = self.next_probe_ms.load(Ordering::Relaxed);
            if now_ms < next {
                return None;
            }
            // Acquire the semaphore permit before advancing `next_probe_ms` so
            // an exhausted pool cannot burn the outage-probe slot.
            let permit = Arc::clone(&self.permits).try_acquire_owned().ok()?;
            let next_deadline = now_ms.saturating_add(Self::outage_backoff_ms(streak));
            if self
                .next_probe_ms
                .compare_exchange(next, next_deadline, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                drop(permit);
                return None;
            }
            return Some(permit);
        }
        timeout(wait_budget, Arc::clone(&self.permits).acquire_owned())
            .await
            .ok()?
            .ok()
    }

    fn record_success(&self) {
        self.next_probe_ms.store(0, Ordering::Relaxed);
    }
}

/// Acquires a dial permit with the short queue budget and counts only queue
/// rejections here, separately from the local TCP connection limit.
async fn acquire_dial_permit(
    gate: &DialGate,
    activity: Option<&TunnelActivity>,
    drops: &DropCounters,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    let permit = gate.acquire(activity, DIAL_QUEUE_WAIT).await;
    if permit.is_none() {
        drops.dial_throttled.incr();
    }
    permit
}

/// Resolves when the engine shuts down, or when its shutdown channel is gone
/// (nothing can ever signal a graceful stop then), so a detached relay task
/// never outlives the engine that spawned it.
pub(crate) async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Returns `true` only for the derived TUN DNS peer on port 53.
fn is_tun_dns_tcp_target(dst: SocketAddr, peer: Option<Ipv4Addr>) -> bool {
    dst.port() == 53 && peer.is_some_and(|peer| dst.ip() == IpAddr::V4(peer))
}

/// Returns `true` only for TCP packets addressed to the derived DNS peer on
/// port 53, so the local TCP stack can complete the stub's handshake.
fn is_tun_dns_tcp_packet(ip: &IpPacketView<'_>, peer: Option<Ipv4Addr>) -> bool {
    ip.protocol == IP_PROTO_TCP
        && parse_tcp(ip.payload).is_some_and(|tcp| {
            is_tun_dns_tcp_target(SocketAddr::new(ip.dst_ip, tcp.dst_port), peer)
        })
}

/// Serves an accepted local stream on the DNS interceptor instead of dialing
/// the tunnel. The stream still takes one TCP connection permit.
fn spawn_dns_tcp_stream(
    mut conn: AcceptedTcpStream,
    dns: Arc<DnsInterceptor>,
    permits: Arc<Semaphore>,
    mut network_reset: Option<watch::Receiver<u64>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let Ok(permit) = permits.try_acquire_owned() else {
        debug!(dst = %conn.dst, "TUN DNS TCP connection limit reached; aborting with RST");
        conn.stream.abort();
        return;
    };

    tokio::spawn(async move {
        let _permit = permit;
        if *shutdown.borrow() {
            conn.stream.abort();
            return;
        }
        let mut serve = std::pin::pin!(dns.serve_tcp_stream(conn.src, conn.dst, conn.stream));
        tokio::select! {
            biased;
            () = wait_shutdown(&mut shutdown) => {}
            Ok(()) = async {
                match network_reset.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {}
            () = &mut serve => {}
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn spawn_tcp_relay(
    mut conn: AcceptedTcpStream,
    client_config: Arc<BeamClientConfig>,
    permits: Arc<Semaphore>,
    dial_gate: Arc<DialGate>,
    mut network_reset: Option<watch::Receiver<u64>>,
    activity: Option<Arc<TunnelActivity>>,
    drops: Arc<DropCounters>,
    relay_idle: Option<Duration>,
    mut shutdown: watch::Receiver<bool>,
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
        let permit = permit;
        // The engine can stop between the spawn and this first poll; abort the
        // local flow instead of leaving a detached task behind.
        if *shutdown.borrow() {
            conn.stream.abort();
            return;
        }
        let dial_permit = tokio::select! {
            biased;
            () = wait_shutdown(&mut shutdown) => {
                conn.stream.abort();
                return;
            }
            Ok(()) = async {
                match network_reset.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                conn.stream.abort();
                return;
            }
            slot = acquire_dial_permit(&dial_gate, activity.as_deref(), &drops) => {
                match slot {
                    Some(slot) => slot,
                    None => {
                        debug!(
                            dst = %conn.dst,
                            "upstream dial throttled by outage backoff or timeout; resetting flow"
                        );
                        conn.stream.abort();
                        return;
                    }
                }
            }
        };
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
            () = wait_shutdown(&mut shutdown) => {
                drop(dial_permit);
                conn.stream.abort();
                return;
            }
            Ok(()) = async {
                match network_reset.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                drop(dial_permit);
                conn.stream.abort();
                return;
            }
            res = dial_tcp(&client_config, dest) => {
                drop(dial_permit);
                match res {
                    Ok(stream) => {
                        dial_gate.record_success();
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
                                server = %client_config.resolved_server_addr(),
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
            }
        };

        let _flow_guard = activity.as_ref().map(TunnelActivity::enter_tcp_flow);
        let c2s_tracker = activity.clone();
        let s2c_tracker = activity.clone();

        // Push-safe mode unbounds reads only; otherwise one clock covers both
        // directions. Writes keep a bounded deadline in both modes.
        let relay_activity = relay_idle.map(RelayIdle::new);
        let write_idle = relay_write_idle(relay_idle, client_config.idle_timeout);
        let (mut tun_r, mut tun_w) = conn.stream.into_split();
        let (mut up_r, mut up_w) = tokio::io::split(upstream);

        // Fires only on an abnormal client-to-server exit (write/flush error or
        // write timeout), so a normal client EOF still drains the download
        // direction and keeps TCP half-close working.
        let c2s_aborted = Notify::new();
        let mut upstream_shutdown = UpstreamShutdown::default();

        let c2s = async {
            // Reused across iterations so coalescing never grows a fresh Vec per
            // write; stays empty (zero allocation) when no coalescing is needed.
            let mut scratch: Vec<u8> = Vec::new();
            loop {
                let chunk = match relay_read(relay_activity.as_ref(), tun_r.recv_chunk()).await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => {
                        upstream_shutdown.once(&mut up_w).await;
                        break;
                    }
                    Err(_) => {
                        if let Some(budget) = relay_idle {
                            warn_relay_timeout(conn.dst, "read", budget);
                        }
                        upstream_shutdown.once(&mut up_w).await;
                        break;
                    }
                };
                touch_relay(relay_activity.as_ref());
                // Coalesce immediately-queued small chunks up to C2S_COALESCE_TARGET
                // so multi-flow uploads write full TLS records with fewer syscalls.
                let coalesced = coalesce_c2s(&chunk, &mut scratch, || tun_r.try_recv_chunk());
                let out: &[u8] = if coalesced { &scratch } else { &chunk };
                match with_relay_idle(Some(write_idle), up_w.write_all(out)).await {
                    Ok(Ok(())) => {
                        if let Some(tracker) = c2s_tracker.as_ref() {
                            tracker.record_bytes_tx(out.len() as u64);
                        }
                        touch_relay(relay_activity.as_ref());
                    }
                    Ok(Err(err)) => {
                        warn_relay_io(conn.dst, "write", &err);
                        c2s_aborted.notify_one();
                        upstream_shutdown.once(&mut up_w).await;
                        break;
                    }
                    Err(_) => {
                        warn_relay_timeout(conn.dst, "write", write_idle);
                        c2s_aborted.notify_one();
                        upstream_shutdown.once(&mut up_w).await;
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
                match with_relay_idle(Some(write_idle), up_w.flush()).await {
                    Ok(Ok(())) => touch_relay(relay_activity.as_ref()),
                    Ok(Err(err)) => {
                        warn_relay_io(conn.dst, "flush", &err);
                        c2s_aborted.notify_one();
                        upstream_shutdown.once(&mut up_w).await;
                        break;
                    }
                    Err(_) => {
                        warn_relay_timeout(conn.dst, "flush", write_idle);
                        c2s_aborted.notify_one();
                        upstream_shutdown.once(&mut up_w).await;
                        break;
                    }
                }
            }
        };

        let s2c = async {
            loop {
                // Read directly into a pooled buffer's uninitialized spare
                // capacity (`read_buf`) and move it into the stack channel so
                // high-throughput downloads avoid both an extra memcpy and a
                // per-read zero-fill memset.
                let mut buf = tun_w.take_buf(S2C_READ_BUF_BYTES);
                let read_res = tokio::select! {
                    biased;
                    () = tun_w.closed() => {
                        tun_w.return_buf(buf);
                        break;
                    }
                    // The upload direction failed for good: no reply can reach
                    // the peer any more, so stop waiting for one.
                    () = c2s_aborted.notified() => {
                        tun_w.return_buf(buf);
                        break;
                    }
                    res = relay_read(relay_activity.as_ref(), up_r.read_buf(&mut buf)) => res,
                };
                let n = match read_res {
                    Ok(Ok(0)) => {
                        tun_w.return_buf(buf);
                        break;
                    }
                    Ok(Ok(n)) => {
                        touch_relay(relay_activity.as_ref());
                        n
                    }
                    Ok(Err(err)) => {
                        tun_w.return_buf(buf);
                        warn_relay_io(conn.dst, "read", &err);
                        break;
                    }
                    Err(_) => {
                        tun_w.return_buf(buf);
                        if let Some(budget) = relay_idle {
                            warn_relay_timeout(conn.dst, "read", budget);
                        }
                        break;
                    }
                };
                match with_relay_idle(Some(write_idle), tun_w.send_chunk(buf)).await {
                    Ok(Ok(())) => {
                        if let Some(tracker) = s2c_tracker.as_ref() {
                            tracker.record_bytes_rx(n as u64);
                        }
                        touch_relay(relay_activity.as_ref());
                    }
                    Ok(Err(err)) => {
                        warn_relay_io(conn.dst, "send_chunk", &err);
                        break;
                    }
                    Err(_) => {
                        warn_relay_timeout(conn.dst, "send_chunk", write_idle);
                        break;
                    }
                }
            }
            tun_w.shutdown();
        };

        let exit = tokio::select! {
            biased;
            () = wait_shutdown(&mut shutdown) => TcpRelayExit::Shutdown,
            Ok(()) = async {
                match network_reset.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => TcpRelayExit::NetworkReset,
            _ = async { tokio::join!(c2s, s2c) } => TcpRelayExit::Complete,
        };
        finish_tcp_relay(permit, exit, &mut upstream_shutdown, &mut up_w).await;
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

/// Returns the absolute deadline the engine timer must be reset to, or `None`
/// while the armed timer is already the earliest wakeup.
fn rearm_deadline(armed: Option<Instant>, now: Instant, delay_ms: Option<u64>) -> Option<Instant> {
    let deadline = now + Duration::from_millis(delay_ms?);
    match armed {
        Some(armed) if armed <= deadline => None,
        _ => Some(deadline),
    }
}

/// Applies one UDP scan result to the sticky sweep deadline.
fn update_udp_sweep_after_scan(
    next_udp_sweep_at: &mut Option<Instant>,
    swept: bool,
    interval_ms: Option<u64>,
    now: Instant,
) -> Option<u64> {
    if swept {
        *next_udp_sweep_at = None;
    }
    update_udp_sweep_deadline(next_udp_sweep_at, interval_ms, now)
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
    use crate::device::MemoryTun;
    use crate::packet::build_ip_tcp_packet_slices;
    use std::collections::VecDeque;

    fn test_failure() -> DialFailure {
        DialFailure {
            stage: DialFailureStage::TcpConnect,
            kind: DialFailureKind::Refused,
        }
    }

    struct PollCounter(Arc<AtomicU64>);

    impl std::future::Future for PollCounter {
        type Output = ();

        fn poll(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            std::task::Poll::Pending
        }
    }

    struct PendingShutdownSink {
        calls: Arc<AtomicU64>,
        armed: Arc<AtomicU64>,
    }

    impl PendingShutdownSink {
        fn new(calls: Arc<AtomicU64>) -> Self {
            Self {
                calls,
                armed: Arc::new(AtomicU64::new(1)),
            }
        }

        fn arm(&self) {
            self.armed.store(1, Ordering::Release);
        }
    }

    impl tokio::io::AsyncWrite for PendingShutdownSink {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if self.armed.swap(0, Ordering::AcqRel) == 1 {
                self.calls.fetch_add(1, Ordering::Relaxed);
            }
            std::task::Poll::Pending
        }
    }

    #[test]
    fn tun_dns_tcp_predicate_matches_only_the_configured_peer_port() {
        let peer = Ipv4Addr::new(172, 19, 0, 2);
        let other = Ipv4Addr::new(172, 19, 0, 3);
        assert!(is_tun_dns_tcp_target(
            SocketAddr::new(IpAddr::V4(peer), 53),
            Some(peer)
        ));
        assert!(!is_tun_dns_tcp_target(
            SocketAddr::new(IpAddr::V4(peer), 54),
            Some(peer)
        ));
        assert!(!is_tun_dns_tcp_target(
            SocketAddr::new(IpAddr::V4(other), 53),
            Some(peer)
        ));
        assert!(!is_tun_dns_tcp_target(
            SocketAddr::new(IpAddr::V4(peer), 53),
            None
        ));
    }

    #[test]
    fn tun_dns_tcp_packet_predicate_allows_only_the_peer_syn() {
        let peer = Ipv4Addr::new(172, 19, 0, 2);
        let src = IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1));
        let packet = |dst: Ipv4Addr, port: u16| {
            build_ip_tcp_packet_slices(
                src,
                54_000,
                IpAddr::V4(dst),
                port,
                1,
                0,
                0x02,
                65_535,
                &[],
                &[],
                &[],
            )
            .expect("test TCP packet")
        };
        let raw = packet(peer, 53);
        assert!(is_tun_dns_tcp_packet(
            &parse_ip(&raw).expect("test IP packet"),
            Some(peer)
        ));
        let raw = packet(peer, 54);
        assert!(!is_tun_dns_tcp_packet(
            &parse_ip(&raw).expect("test IP packet"),
            Some(peer)
        ));
        let raw = packet(Ipv4Addr::new(172, 19, 0, 3), 53);
        assert!(!is_tun_dns_tcp_packet(
            &parse_ip(&raw).expect("test IP packet"),
            Some(peer)
        ));
        let raw = packet(peer, 53);
        assert!(!is_tun_dns_tcp_packet(
            &parse_ip(&raw).expect("test IP packet"),
            None
        ));
    }

    #[tokio::test]
    async fn reply_drain_matches_a_sustained_reject_enqueue_rate() {
        let (_peer, mut device) = MemoryTun::pair(1500, TUN_TX_CHANNEL_CAP * 2);
        let (tx, mut rx) = mpsc::channel(TUN_TX_CHANNEL_CAP);
        let iterations = 8;
        let drops = DropCounters::default();
        for tick in 0..iterations {
            for i in 0..RX_BATCH_MAX {
                tx.try_send(vec![(tick * RX_BATCH_MAX + i) as u8])
                    .expect("one inbound batch fits the bounded reply queue");
            }
            drain_reply_queue(&mut device, &mut rx, &drops)
                .await
                .expect("drain");
        }

        assert!(
            rx.try_recv().is_err(),
            "one drain per inbound batch must empty the reply queue"
        );
        assert_eq!(drops.snapshot().tun_tx_full, 0, "no reply may drop");
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
    fn udp_sweep_deadline_is_not_stale_after_a_sweep() {
        let now = Instant::now();
        let mut deadline = Some(now - Duration::from_secs(1));

        assert_eq!(
            update_udp_sweep_after_scan(&mut deadline, true, Some(5_000), now),
            Some(5_000),
            "a swept flow must not re-arm the old deadline every tick"
        );
        assert_eq!(deadline, Some(now + Duration::from_secs(5)));
    }

    #[test]
    fn rearm_deadline_keeps_the_armed_timer_and_only_resets_for_earlier_wakeups() {
        let now = Instant::now();
        assert_eq!(rearm_deadline(None, now, None), None, "no wakeup, no arm");

        let armed = rearm_deadline(None, now, Some(5)).expect("armed");
        assert_eq!(armed, now + Duration::from_millis(5));

        // Time passing re-computes a later deadline: keep the armed timer.
        assert_eq!(
            rearm_deadline(Some(armed), now + Duration::from_millis(1), Some(5)),
            None
        );

        // A shrinking deadline must re-arm to the earlier instant.
        let sooner =
            rearm_deadline(Some(armed), now + Duration::from_millis(1), Some(2)).expect("re-armed");
        assert_eq!(sooner, now + Duration::from_millis(3));
    }

    #[test]
    fn clearing_dial_success_hides_a_pre_reset_dial() {
        let activity = TunnelActivity::new();
        activity.record_dial_success(21);
        assert_eq!(activity.recent_rtt(Duration::from_secs(1)), Some(21));
        activity.clear_dial_success();
        assert_eq!(activity.recent_rtt(Duration::from_secs(1)), None);
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

    #[test]
    fn relay_write_deadline_is_always_bounded() {
        let client_idle = Duration::from_secs(300);
        assert_eq!(relay_write_idle(None, client_idle), client_idle);
        assert_eq!(
            relay_write_idle(Some(Duration::from_secs(45)), client_idle),
            Duration::from_secs(45)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn relay_idle_clock_resets_from_either_direction_and_reaps_dead_flows() {
        let clock = RelayIdle::new(Duration::from_millis(50));
        let (_upload_tx, mut upload_rx) = mpsc::channel::<u8>(1);
        let (download_tx, mut download_rx) = mpsc::channel::<u8>(1);
        let upload_clock = clock.clone();
        let upload =
            tokio::spawn(async move { relay_read(Some(&upload_clock), upload_rx.recv()).await });
        let download_clock = clock.clone();
        let download =
            tokio::spawn(
                async move { relay_read(Some(&download_clock), download_rx.recv()).await },
            );

        tokio::time::advance(Duration::from_millis(40)).await;
        // Traffic in one direction resets the deadline seen by both reads.
        clock.touch();
        download_tx.send(7u8).await.expect("download frame");
        let got = timeout(Duration::from_millis(20), download)
            .await
            .expect("download must arrive within the shared deadline")
            .expect("download task");
        assert_eq!(got, Ok(Some(7)));
        assert!(
            !upload.is_finished(),
            "one-way traffic must keep the other direction alive"
        );

        let idle = timeout(Duration::from_millis(60), upload)
            .await
            .expect("a dead flow must still be reaped")
            .expect("upload task");
        assert_eq!(idle, Err(()));
    }

    #[tokio::test(start_paused = true)]
    async fn relay_idle_touch_does_not_wake_the_idle_direction() {
        let clock = RelayIdle::new(Duration::from_millis(50));
        let (active_tx, mut active_rx) = mpsc::channel::<u8>(1);
        let idle_polls = Arc::new(AtomicU64::new(0));
        let idle_polls_in_task = Arc::clone(&idle_polls);
        let idle_clock = clock.clone();
        let idle = tokio::spawn(async move {
            relay_read(Some(&idle_clock), PollCounter(idle_polls_in_task)).await
        });
        let active_clock = clock.clone();
        let active =
            tokio::spawn(async move { relay_read(Some(&active_clock), active_rx.recv()).await });

        tokio::time::advance(Duration::from_millis(40)).await;
        clock.touch();
        active_tx.send(7u8).await.expect("active frame");
        let got = timeout(Duration::from_millis(20), active)
            .await
            .expect("active frame must arrive")
            .expect("active task");
        assert_eq!(got, Ok(Some(7)));

        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            idle_polls.load(Ordering::Relaxed),
            1,
            "touch must not wake the idle direction"
        );
        assert!(
            !idle.is_finished(),
            "one-way traffic must keep the flow alive"
        );

        let expired = timeout(Duration::from_millis(60), idle)
            .await
            .expect("idle direction must still be reaped")
            .expect("idle task");
        assert_eq!(expired, Err(()));
    }

    #[tokio::test]
    async fn relay_idle_none_never_times_out_an_idle_flow() {
        // An idle wait longer than the classic 300 s relay cap still completes.
        let slow = with_relay_idle(None, async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            7u32
        })
        .await;
        assert_eq!(slow, Ok(7));

        // With an explicit budget the same wait fails fast instead of hanging.
        let capped = with_relay_idle(Some(Duration::from_millis(20)), async {
            tokio::time::sleep(Duration::from_millis(200)).await;
        })
        .await;
        assert_eq!(capped, Err(()));
    }

    #[test]
    fn telemetry_snapshot_reports_dial_health_and_drops() {
        let telemetry = EngineTelemetry::with_dns();
        assert!(telemetry.snapshot().last_dial_success_age.is_none());
        assert!(telemetry.snapshot().last_dial_failure.is_none());

        telemetry.activity.record_dial_success(9);
        let snap = telemetry.snapshot();
        assert!(snap.last_dial_success_age.is_some());
        assert_eq!(snap.consecutive_dial_failures, 0);

        telemetry.activity.record_dial_failure(test_failure());
        let snap = telemetry.snapshot();
        assert_eq!(snap.consecutive_dial_failures, 1);
        assert_eq!(snap.last_dial_failure, Some(test_failure()));
        assert!(snap.dns.is_some());
        assert!(snap.drops.is_empty());

        // Without DNS counters the snapshot carries no DNS section.
        assert!(EngineTelemetry::new().snapshot().dns.is_none());
    }

    #[test]
    fn fatal_tun_send_error_classifies_transient_vs_permanent() {
        assert!(is_fatal_tun_send_error(&io::Error::from(
            io::ErrorKind::BrokenPipe
        )));
        assert!(is_fatal_tun_send_error(&io::Error::from(
            io::ErrorKind::UnexpectedEof
        )));
        assert!(!is_fatal_tun_send_error(&io::Error::from(
            io::ErrorKind::WouldBlock
        )));
        assert!(!is_fatal_tun_send_error(&io::Error::from(
            io::ErrorKind::OutOfMemory
        )));
        #[cfg(unix)]
        {
            assert!(is_fatal_tun_send_error(&io::Error::from_raw_os_error(9))); // EBADF
            assert!(is_fatal_tun_send_error(&io::Error::from_raw_os_error(19))); // ENODEV
            assert!(!is_fatal_tun_send_error(&io::Error::from_raw_os_error(12))); // ENOMEM
        }
        #[cfg(windows)]
        {
            // Fatal: ERROR_INVALID_HANDLE, ERROR_HANDLE_EOF, ERROR_BROKEN_PIPE,
            // ERROR_DEVICE_NOT_CONNECTED. Transient: ERROR_NOT_ENOUGH_MEMORY (8)
            // and ERROR_NO_MORE_ITEMS (259, WinTun full ring backpressure).
            assert!(is_fatal_tun_send_error(&io::Error::from_raw_os_error(6)));
            assert!(is_fatal_tun_send_error(&io::Error::from_raw_os_error(38)));
            assert!(is_fatal_tun_send_error(&io::Error::from_raw_os_error(109)));
            assert!(is_fatal_tun_send_error(&io::Error::from_raw_os_error(1167)));
            assert!(!is_fatal_tun_send_error(&io::Error::from_raw_os_error(8)));
            assert!(!is_fatal_tun_send_error(&io::Error::from_raw_os_error(259)));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dial_queue_budget_is_short_and_counted_separately() {
        let gate = Arc::new(DialGate::new(1, Instant::now()));
        let held = gate
            .acquire(None, DIAL_QUEUE_WAIT)
            .await
            .expect("first dial holds the only permit");
        let drops = Arc::new(DropCounters::default());
        let started = tokio::time::Instant::now();

        let queued = timeout(
            Duration::from_secs(5),
            acquire_dial_permit(&gate, None, &drops),
        )
        .await
        .expect("queue wait must be bounded")
        .is_none();

        assert!(
            queued,
            "a stalled dial must fail rather than wait indefinitely"
        );
        assert!(
            started.elapsed() >= DIAL_QUEUE_WAIT,
            "the short queue budget must actually elapse"
        );
        assert_eq!(drops.snapshot().dial_throttled, 1);
        assert_eq!(
            drops.snapshot().tcp_limit,
            0,
            "dial throttling must not be reported as a local connection-limit RST"
        );
        drop(held);
    }

    #[tokio::test]
    async fn dial_gate_queues_normal_bursts_and_throttles_during_outage() {
        let gate = Arc::new(DialGate::new(2, Instant::now()));
        let p1 = gate
            .acquire(None, Duration::from_millis(200))
            .await
            .expect("first permit");
        let p2 = gate
            .acquire(None, Duration::from_millis(200))
            .await
            .expect("second permit");

        // A 3rd normal burst dial queues instead of immediately failing, and
        // succeeds as soon as one of the first two releases.
        let gate_clone = Arc::clone(&gate);
        let waiter =
            tokio::spawn(async move { gate_clone.acquire(None, Duration::from_millis(500)).await });
        tokio::time::sleep(Duration::from_millis(15)).await;
        drop(p1);
        let p3 = waiter.await.expect("join").expect("queued burst permit");
        drop(p2);
        drop(p3);

        let activity = TunnelActivity::new();
        for _ in 0..OUTAGE_BACKOFF_STREAK {
            activity.record_dial_failure(test_failure());
        }
        assert_eq!(DialGate::outage_backoff_ms(OUTAGE_BACKOFF_STREAK), 1_000);
        assert_eq!(
            DialGate::outage_backoff_ms(OUTAGE_BACKOFF_STREAK + 1),
            2_000
        );
        assert_eq!(
            DialGate::outage_backoff_ms(OUTAGE_BACKOFF_STREAK + 3),
            5_000
        );

        // First call during outage gets the single probe permit; immediate second fast-fails.
        let probe = gate
            .acquire(Some(&activity), Duration::from_millis(200))
            .await
            .expect("initial outage probe");
        assert!(
            gate.acquire(Some(&activity), Duration::from_millis(200))
                .await
                .is_none(),
            "subsequent dials fast-fail during outage backoff window"
        );
        drop(probe);

        // Once a dial succeeds, backoff clears immediately.
        activity.record_dial_success(15);
        gate.record_success();
        assert!(
            gate.acquire(Some(&activity), Duration::from_millis(200))
                .await
                .is_some()
        );

        // Network reset clears outage backoff and consecutive failure streak
        // without waiting for an old outage probe window to expire.
        for _ in 0..OUTAGE_BACKOFF_STREAK {
            activity.record_dial_failure(test_failure());
        }
        let probe2 = gate
            .acquire(Some(&activity), Duration::from_millis(200))
            .await
            .expect("second outage probe");
        assert!(
            gate.acquire(Some(&activity), Duration::from_millis(200))
                .await
                .is_none()
        );
        drop(probe2);

        activity.reset_failure_streak();
        gate.record_success();
        assert_eq!(activity.consecutive_failure_count(), 0);
        assert!(
            gate.acquire(Some(&activity), Duration::from_millis(200))
                .await
                .is_some(),
            "network reset must immediately allow dials on the new network"
        );
    }

    #[test]
    fn tunnel_activity_tracks_active_flows_and_bytes() {
        let activity = Arc::new(TunnelActivity::new());
        assert_eq!(activity.active_tcp_flows(), 0);
        assert_eq!(activity.bytes_tx(), 0);
        assert_eq!(activity.bytes_rx(), 0);

        {
            let _g1 = activity.enter_tcp_flow();
            let _g2 = activity.enter_tcp_flow();
            assert_eq!(activity.active_tcp_flows(), 2);
            activity.record_bytes_tx(1_500);
            activity.record_bytes_rx(4_096);
        }
        assert_eq!(activity.active_tcp_flows(), 0);
        assert_eq!(activity.bytes_tx(), 1_500);
        assert_eq!(activity.bytes_rx(), 4_096);
    }

    #[tokio::test]
    async fn upstream_half_close_runs_once_on_relay_exit() {
        struct ShutdownRecorder(Arc<AtomicU64>);

        impl tokio::io::AsyncWrite for ShutdownRecorder {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                std::task::Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                std::task::Poll::Ready(Ok(()))
            }
        }

        let calls = Arc::new(AtomicU64::new(0));
        let mut sink = ShutdownRecorder(Arc::clone(&calls));
        let mut shutdown = UpstreamShutdown::default();
        shutdown.once(&mut sink).await;
        shutdown.once(&mut sink).await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "an EOF half-close must not be repeated at the common exit"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_upstream_shutdown_is_not_retried() {
        let calls = Arc::new(AtomicU64::new(0));
        let mut sink = PendingShutdownSink::new(Arc::clone(&calls));
        let mut shutdown = UpstreamShutdown::default();

        tokio::select! {
            () = shutdown.once(&mut sink) => panic!("mock shutdown must hang"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        sink.arm();
        timeout(Duration::from_millis(1), shutdown.once(&mut sink))
            .await
            .expect("a second call must not wait for the shutdown timeout");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "a cancelled shutdown must not be attempted twice"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn network_reset_releases_tcp_permit_without_upstream_shutdown() {
        let permits = Arc::new(Semaphore::new(1));
        let permit = permits.clone().acquire_owned().await.expect("test permit");
        let calls = Arc::new(AtomicU64::new(0));
        let mut sink = PendingShutdownSink::new(Arc::clone(&calls));
        let mut shutdown = UpstreamShutdown::default();

        let cleanup = tokio::spawn(async move {
            finish_tcp_relay(permit, TcpRelayExit::NetworkReset, &mut shutdown, &mut sink).await;
        });
        let acquired = timeout(Duration::from_millis(1), permits.clone().acquire_owned())
            .await
            .expect("network reset must not hold the permit during shutdown")
            .expect("permit must be available");
        timeout(Duration::from_millis(1), cleanup)
            .await
            .expect("network reset cleanup must finish promptly")
            .expect("cleanup task");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "network reset must skip the best-effort upstream shutdown"
        );
        drop(acquired);
    }

    #[tokio::test]
    async fn relay_shutdown_wakes_promptly_without_waiting_for_an_idle_timeout() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let relay = tokio::spawn(async move {
            // Stands in for a relay parked on a 30-minute idle timeout.
            tokio::select! {
                biased;
                () = wait_shutdown(&mut shutdown_rx) => "shutdown",
                () = tokio::time::sleep(Duration::from_secs(1_800)) => "idle",
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !relay.is_finished(),
            "shutdown must not fire while the engine is running"
        );
        let _ = shutdown_tx.send(true);
        let won = timeout(Duration::from_millis(200), relay)
            .await
            .expect("relay must observe shutdown at once")
            .expect("relay task");
        assert_eq!(won, "shutdown");
    }

    #[tokio::test]
    async fn wait_shutdown_returns_for_an_already_stopped_engine_or_a_dropped_sender() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(true);
        timeout(Duration::from_millis(50), wait_shutdown(&mut shutdown_rx))
            .await
            .expect("an already-true flag returns at once");
        drop(shutdown_tx);

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        drop(shutdown_tx);
        timeout(Duration::from_millis(50), wait_shutdown(&mut shutdown_rx))
            .await
            .expect("a dropped shutdown sender must not hang the relay task");
    }
}
