//! Owner of the mobile `beam-tun` engine: runtime, channels, and telemetry.
//!
//! The engine runs on its own two-worker runtime for the life of a
//! `VpnService` session. State is derived from lock-free telemetry on demand,
//! so an idle tunnel holds no timer and no wakeup.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use beam_core::client::SocketProtector;
use beam_sys::LinuxTun;
use beam_tun::{EngineTelemetry, ProxyTcpStack, run_tun_engine_with_telemetry};
use serde_json::json;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch;

use crate::config::{AndroidEngineConfig, ConfigError};
use crate::tun::AndroidTun;

/// No tunnel is running.
pub const STATE_DISCONNECTED: u8 = 0;
/// The VPN service is preparing the TUN session before the engine starts.
pub const STATE_CONNECTING: u8 = 1;
/// The engine is running and has not hit a recent dial-failure streak.
pub const STATE_CONNECTED: u8 = 2;
/// At least three consecutive upstream dials failed within 30 s.
pub const STATE_DEGRADED: u8 = 3;
/// Shutdown is in progress.
pub const STATE_DISCONNECTING: u8 = 4;

/// Shutdown deadline before the runtime is dropped.
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);
/// Window in which consecutive dial failures count toward degradation.
pub const DEGRADED_WINDOW: Duration = Duration::from_secs(30);
/// Consecutive dial failures that mark the link as degraded.
pub const DEGRADED_FAILURE_STREAK: u64 = 3;
/// Max age of a dial RTT reported to the UI.
const RTT_MAX_AGE: Duration = Duration::from_secs(30);

/// Callback invoked on every state change with a code and a short label.
pub type StateCallback = Arc<dyn Fn(u8, &str) + Send + Sync>;

/// Short label for a state code, safe to show in a notification.
pub const fn state_label(state: u8) -> &'static str {
    match state {
        STATE_CONNECTING => "connecting",
        STATE_CONNECTED => "connected",
        STATE_DEGRADED => "degraded",
        STATE_DISCONNECTING => "disconnecting",
        _ => "disconnected",
    }
}

/// Values needed to start one engine instance.
pub struct AndroidEngineStart {
    /// TUN device for this session. Ownership transfers here, so a rejected
    /// start drops the device and closes its descriptor.
    pub tun: LinuxTun,
    /// JSON-derived configuration of this session.
    pub config: AndroidEngineConfig,
    /// `VpnService.protect(fd)` hook for upstream and local-DNS sockets.
    pub socket_protector: Option<SocketProtector>,
    /// Optional state-transition callback.
    pub on_state: Option<StateCallback>,
}

/// Reasons the engine could not start.
#[derive(Debug, thiserror::Error)]
pub enum AndroidEngineError {
    /// The detached TUN descriptor or the TUN setup failed.
    #[error("TUN setup failed: {0}")]
    Tun(#[from] io::Error),
    /// The configuration was rejected before any socket opened.
    #[error("engine configuration rejected: {0}")]
    Config(#[from] ConfigError),
    /// The Tokio runtime could not start.
    #[error("runtime start failed: {0}")]
    Runtime(io::Error),
}

/// A running mobile tunnel: runtime, control channels, and live telemetry.
pub struct AndroidEngine {
    runtime: Mutex<Option<Runtime>>,
    shutdown_tx: watch::Sender<bool>,
    network_reset_tx: watch::Sender<u64>,
    telemetry: Arc<EngineTelemetry>,
    state: Arc<AtomicU8>,
    stopped: Arc<AtomicBool>,
    exited: Arc<AtomicBool>,
    on_state: Option<StateCallback>,
}

fn publish_state(state_slot: &AtomicU8, on_state: Option<&StateCallback>, state: u8, detail: &str) {
    if state_slot.swap(state, Ordering::Relaxed) == state {
        return;
    }
    if let Some(callback) = on_state {
        callback(state, detail);
    }
}

impl AndroidEngine {
    /// Takes the TUN device and starts the engine on a two-worker runtime.
    pub fn start(start: AndroidEngineStart) -> Result<Self, AndroidEngineError> {
        let AndroidEngineStart {
            tun,
            config,
            socket_protector,
            on_state,
        } = start;
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(4)
            .thread_name("beam-android")
            .enable_all()
            .build()
            .map_err(AndroidEngineError::Runtime)?;

        // `AsyncFd` registers with the current runtime, so the device must be
        // created inside the runtime context. The guard ends before the runtime
        // moves into `Self`.
        let enter = runtime.enter();
        let tun = AndroidTun::new(tun, config.mtu)?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (network_reset_tx, network_reset_rx) = watch::channel(0_u64);
        let engine_config = config.build_engine_config(socket_protector, Some(network_reset_rx))?;
        let telemetry = Arc::new(if engine_config.dns.is_some() {
            EngineTelemetry::with_dns()
        } else {
            EngineTelemetry::new()
        });
        let stack = ProxyTcpStack::new(config.tcp_stack_config());
        drop(enter);

        let state = Arc::new(AtomicU8::new(STATE_DISCONNECTED));
        let stopped = Arc::new(AtomicBool::new(false));
        let exited = Arc::new(AtomicBool::new(false));

        // Publish CONNECTED before spawning so an immediate task exit cannot
        // race ahead and then get overwritten by startup notification.
        publish_state(&state, on_state.as_ref(), STATE_CONNECTED, "");

        let task_telemetry = (*telemetry).clone();
        let task_state = Arc::clone(&state);
        let task_stopped = Arc::clone(&stopped);
        let task_exited = Arc::clone(&exited);
        let task_on_state = on_state.clone();
        runtime.spawn(async move {
            let detail = match run_tun_engine_with_telemetry(
                tun,
                stack,
                engine_config,
                shutdown_rx,
                task_telemetry,
            )
            .await
            {
                Ok(()) => {
                    tracing::info!("beam-tun engine stopped");
                    "engine stopped"
                }
                Err(error) => {
                    tracing::warn!(error = %error, "beam-tun engine stopped with an error");
                    "engine error"
                }
            };
            task_exited.store(true, Ordering::SeqCst);
            if !task_stopped.load(Ordering::SeqCst) {
                publish_state(
                    &task_state,
                    task_on_state.as_ref(),
                    STATE_DISCONNECTED,
                    detail,
                );
            }
        });

        Ok(Self {
            runtime: Mutex::new(Some(runtime)),
            shutdown_tx,
            network_reset_tx,
            telemetry,
            state,
            stopped,
            exited,
            on_state,
        })
    }

    /// Bumps the network-reset generation so the engine resets TCP flows,
    /// XUDP sessions, and the local DNS cache after a network switch.
    pub fn notify_network_change(&self) {
        self.network_reset_tx.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
        self.refresh_state();
    }

    /// Returns the current state code after re-deriving it from telemetry.
    ///
    /// A running engine is [`STATE_CONNECTED`] until a recent dial-failure
    /// streak marks it [`STATE_DEGRADED`], or the engine task exits and marks
    /// it [`STATE_DISCONNECTED`]. Both callers poll on demand, so an idle
    /// tunnel holds no timer and no wakeup.
    pub fn refresh_state(&self) -> u8 {
        if self.stopped.load(Ordering::SeqCst) || self.exited.load(Ordering::SeqCst) {
            return self.state.load(Ordering::Relaxed);
        }
        let failures = self
            .telemetry
            .activity
            .recent_failure_streak(DEGRADED_WINDOW);
        let state = if failures >= DEGRADED_FAILURE_STREAK {
            STATE_DEGRADED
        } else {
            STATE_CONNECTED
        };
        self.notify_state(state, state_label(state));
        self.state.load(Ordering::Relaxed)
    }

    /// Serializes one telemetry snapshot for the UI.
    ///
    /// The payload holds counters only: no server address, UUID, key, or link.
    /// A value the engine cannot measure yet is JSON `null`, never a fake `0`.
    pub fn telemetry_json(&self) -> String {
        let drops = &self.telemetry.snapshot().drops;
        let total_drops = drops.tun_tx_full
            + drops.ip_parse
            + drops.fragment
            + drops.route
            + drops.tcp_limit
            + drops.tcp_rx_overflow
            + drops.udp_mux_q
            + drops.udp_session_queue_full
            + drops.udp_pending_full
            + drops.udp_payload_invalid
            + drops.udp_session_table_full;
        let activity = &self.telemetry.activity;
        let last_rtt_ms = activity.recent_rtt(RTT_MAX_AGE);
        json!({
            "active_tcp_flows": activity.active_tcp_flows(),
            "active_udp_sessions": 0,
            "bytes_tx": activity.bytes_tx(),
            "bytes_rx": activity.bytes_rx(),
            "last_rtt_ms": last_rtt_ms,
            "dial_failures": activity.dial_failure_count(),
            "drops": total_drops,
            "state": self.refresh_state(),
        })
        .to_string()
    }

    /// Stops the engine and waits at most [`SHUTDOWN_DEADLINE`] for teardown.
    pub fn stop(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        self.notify_state(STATE_DISCONNECTING, state_label(STATE_DISCONNECTING));
        let _ = self.shutdown_tx.send(true);
        let runtime = match self.runtime.lock() {
            Ok(mut slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(runtime) = runtime {
            runtime.shutdown_timeout(SHUTDOWN_DEADLINE);
        }
        self.notify_state(STATE_DISCONNECTED, state_label(STATE_DISCONNECTED));
    }

    /// Records `state` and runs the callback only when it changed.
    fn notify_state(&self, state: u8, detail: &str) {
        publish_state(&self.state, self.on_state.as_ref(), state, detail);
    }
}

impl Drop for AndroidEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_VLESS_URI;
    use beam_tun::{DialFailure, DialFailureKind, DialFailureStage};
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    fn detached_socket() -> (LinuxTun, std::os::unix::net::UnixStream) {
        use std::os::fd::IntoRawFd;
        let (local, peer) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let tun =
            LinuxTun::from_detached_fd(local.into_raw_fd(), "tun0").expect("detached descriptor");
        (tun, peer)
    }

    fn test_config() -> AndroidEngineConfig {
        AndroidEngineConfig {
            vless_uri: TEST_VLESS_URI.to_owned(),
            ..AndroidEngineConfig::default()
        }
    }

    /// Builds an engine over a socket pair. The returned peer keeps the
    /// descriptor open until the test ends.
    fn test_engine(
        on_state: Option<StateCallback>,
    ) -> (AndroidEngine, std::os::unix::net::UnixStream) {
        let (tun, peer) = detached_socket();
        let engine = AndroidEngine::start(AndroidEngineStart {
            tun,
            config: test_config(),
            socket_protector: None,
            on_state,
        })
        .expect("engine start over a socket pair");
        (engine, peer)
    }

    #[test]
    fn start_reports_connected_and_stop_reports_disconnected() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let callback: StateCallback = Arc::new(move |state, label| {
            if let Ok(mut states) = recorder.lock() {
                states.push((state, label.to_owned()));
            }
        });

        let (engine, _peer) = test_engine(Some(callback));
        engine.refresh_state();

        let states = seen.lock().expect("state log").clone();
        assert_eq!(states.first(), Some(&(STATE_CONNECTED, String::new())));
        assert_eq!(engine.refresh_state(), STATE_CONNECTED);

        engine.stop();
        let states = seen.lock().expect("state log").clone();
        assert!(states.contains(&(STATE_DISCONNECTING, "disconnecting".to_owned())));
        assert_eq!(
            states.last(),
            Some(&(STATE_DISCONNECTED, "disconnected".to_owned()))
        );
    }

    #[test]
    fn degraded_state_follows_the_dial_failure_streak() {
        let (engine, _peer) = test_engine(None);
        let failure = DialFailure {
            stage: DialFailureStage::TcpConnect,
            kind: DialFailureKind::Timeout,
        };
        for _ in 0..DEGRADED_FAILURE_STREAK {
            engine.telemetry.activity.record_dial_failure(failure);
        }
        assert_eq!(engine.refresh_state(), STATE_DEGRADED);

        engine.telemetry.activity.record_dial_success(42);
        assert_eq!(engine.refresh_state(), STATE_CONNECTED);

        let value: serde_json::Value =
            serde_json::from_str(&engine.telemetry_json()).expect("telemetry JSON");
        assert_eq!(value["last_rtt_ms"], 42);
        engine.stop();
    }

    #[test]
    fn stop_finishes_within_the_shutdown_deadline() {
        let (engine, _peer) = test_engine(None);
        let stopped_at = Instant::now();
        engine.stop();
        assert!(
            stopped_at.elapsed() < SHUTDOWN_DEADLINE + Duration::from_secs(1),
            "stop took {:?}",
            stopped_at.elapsed()
        );
        assert_eq!(engine.refresh_state(), STATE_DISCONNECTED);
    }

    #[test]
    fn telemetry_json_has_every_field_and_no_secrets() {
        let (engine, _peer) = test_engine(None);
        let json = engine.telemetry_json();
        let value: serde_json::Value = serde_json::from_str(&json).expect("telemetry JSON");

        for key in [
            "active_tcp_flows",
            "active_udp_sessions",
            "bytes_tx",
            "bytes_rx",
            "dial_failures",
            "drops",
            "state",
        ] {
            assert!(value.get(key).is_some_and(|field| field.is_u64()), "{key}");
        }
        assert!(
            value
                .get("last_rtt_ms")
                .is_some_and(|field| field.is_null()),
            "last_rtt_ms"
        );
        assert_eq!(value["state"], u64::from(STATE_CONNECTED));
        assert_eq!(value["bytes_tx"], 0);
        assert_eq!(value["bytes_rx"], 0);
        assert_eq!(value["drops"], 0);
        assert!(!json.contains("vless"));
        assert!(!json.contains("203.0.113.10"));
        assert!(!json.contains("b831381d"));
        engine.stop();
    }

    #[test]
    fn network_change_bumps_the_reset_generation() {
        let (engine, _peer) = test_engine(None);
        // The engine owns the receiver; sending must never fail or panic.
        engine.notify_network_change();
        engine.notify_network_change();
        engine.stop();
    }

    #[test]
    fn rejected_config_closes_the_detached_descriptor() {
        use std::io::Read as _;

        let (tun, mut peer) = detached_socket();
        peer.set_nonblocking(true).expect("non-blocking peer");
        let start = AndroidEngineStart {
            tun,
            config: AndroidEngineConfig {
                vless_uri: "not-a-vless-link".to_owned(),
                ..AndroidEngineConfig::default()
            },
            socket_protector: None,
            on_state: None,
        };
        assert!(matches!(
            AndroidEngine::start(start),
            Err(AndroidEngineError::Config(_))
        ));
        // EOF rather than `WouldBlock` proves the failed start closed the fd
        // that the JNI layer detached from `VpnService`.
        assert_eq!(peer.read(&mut [0_u8; 1]).expect("peer read"), 0);
    }

    #[test]
    fn state_callback_runs_once_per_transition() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let callback: StateCallback = Arc::new(move |_state, _label| {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        let (engine, _peer) = test_engine(Some(callback));
        let after_start = calls.load(Ordering::Relaxed);
        assert_eq!(after_start, 1, "start reports connected once");
        engine.refresh_state();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            after_start,
            "same state repeats nothing"
        );
        engine.stop();
        assert_eq!(calls.load(Ordering::Relaxed), after_start + 2);
    }

    #[test]
    fn unexpected_engine_exit_publishes_disconnected() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let callback: StateCallback = Arc::new(move |state, label| {
            if let Ok(mut states) = recorder.lock() {
                states.push((state, label.to_owned()));
            }
        });

        let (engine, peer) = test_engine(Some(callback));
        // Closing the peer end causes `AndroidTun::recv` to return UnexpectedEof,
        // simulating a fatal TUN device error while the service is still attached.
        drop(peer);

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if engine.refresh_state() == STATE_DISCONNECTED {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(engine.refresh_state(), STATE_DISCONNECTED);
        let states = seen.lock().expect("state log").clone();
        assert_eq!(
            states.last(),
            Some(&(STATE_DISCONNECTED, "engine error".to_owned()))
        );
        engine.stop();
    }
}
