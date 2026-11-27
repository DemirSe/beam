#![cfg(windows)]

//! Windows service and console agent: tunnel lifecycle, IPC command handling,
//! and the `BeamClient` SCM plumbing around `beam_tun`.
//!
//! The agent owns one supervisor task that serializes tunnel lifecycle work, so
//! a `CONNECT` that arrives while a `RESTART` is tearing the tunnel down cannot
//! start two engines. The IPC thread only queues commands and answers `STATUS`
//! from the shared snapshot, which keeps the pipe responsive during a slow
//! route teardown.
//!
//! Cross-module contract (owned by `win_tun.rs` and `win_routes.rs`):
//!
//! ```text
//! AsyncWinTun::open(name: &str, mtu: usize) -> io::Result<Self>
//! AsyncWinTun::name(&self) -> &str
//! AsyncWinTun::luid(&self) -> u64
//!
//! ActivePhysicalInterface::new() -> Self                     // Clone
//! ActivePhysicalInterface::make_socket_protector(&self, family_v6: bool) -> SocketProtector
//!
//! WindowsRouteGuard::setup(tun_luid, tun_cidr, mtu, auto_route, strict_kill_switch,
//!                          server_ip, initial_local_dns, tun_dns_peer, bypass_cidrs,
//!                          active_if, state_path) -> io::Result<Self>
//! WindowsRouteGuard::install_dynamic_bypass_ip(&mut self, ip: IpAddr)
//! WindowsRouteGuard::update_bypass_gateway(&mut self, gw: &PhysicalGateways,
//!                                          local_dns: Option<IpAddr>) -> bool
//! WindowsRouteGuard::bypass_routes_installed(&self) -> bool
//! win_routes::cleanup_persisted_routes(path: &Path) -> io::Result<usize>
//! ```

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use beam_core::client::SocketProtector;
use beam_sys::windows::pipe::{CancelEvent, DEFAULT_PIPE_NAME};
use beam_sys::windows::service::{ServiceEvent, ServiceState, ServiceStatusHandle, run_service};
use beam_tun::{ProxyTcpStack, TunnelActivity, run_tun_engine_with_activity};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::config::{ClientFileConfig, ConfigError, ValidatedConfig};
use crate::win_health::{StatusPublisher, spawn_windows_network_monitor};
use crate::win_ipc::{
    IpcRequest, IpcStatus, format_err_reply, format_ok_reply, format_status_reply,
    import_vless_link_to_toml, read_allowed_user_sid, run_ipc_server_thread, write_config_atomic,
};
use crate::win_routes::{ActivePhysicalInterface, WindowsRouteGuard, cleanup_persisted_routes};
use crate::win_tun::AsyncWinTun;

/// Service name registered with the Service Control Manager.
pub const SERVICE_NAME: &str = "BeamClient";

/// Service state token for "no tunnel".
const STATE_DISCONNECTED: &str = "disconnected";
/// Service state token for "tunnel starting".
const STATE_CONNECTING: &str = "connecting";
/// Service state token for "tunnel tearing down".
const STATE_STOPPING: &str = "stopping";
/// Service state token for "the last attempt failed".
const STATE_ERROR: &str = "error";

/// SCM wait hint while the runtime and the pipe server start.
const START_WAIT_HINT_MS: u32 = 30_000;
/// SCM wait hint while the tunnel tears down.
const STOP_WAIT_HINT_MS: u32 = 45_000;
/// Bound on one engine or monitor shutdown.
const TUNNEL_STOP_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound on the whole supervisor shutdown: both tunnel tasks must fit inside.
const AGENT_STOP_TIMEOUT: Duration = Duration::from_secs(40);
/// Bound on the queued lifecycle commands, so the tray cannot flood the
/// supervisor faster than it can tear a tunnel down.
const COMMAND_QUEUE_DEPTH: usize = 16;

/// Error returned by the service and console entry points.
pub type AgentError = Box<dyn std::error::Error + Send + Sync>;

/// Lifecycle command queued by the IPC thread for the tunnel supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Connect,
    Disconnect,
    Restart,
}

/// State shared by the IPC thread and the supervisor.
struct Shared {
    config_path: PathBuf,
    routes_path: PathBuf,
    status: Arc<StatusPublisher>,
}

/// One running tunnel: the engine, the network monitor, and their stop signal.
struct Running {
    ifname: String,
    shutdown: watch::Sender<bool>,
    engine: tokio::task::JoinHandle<Result<(), String>>,
    monitor: tokio::task::JoinHandle<()>,
}

/// Where one supervisor wakeup came from.
enum Wake {
    Stop,
    Command(Option<Command>),
    Engine(Result<(), String>),
}

/// Running agent: IPC pipe server plus tunnel supervisor.
struct Agent {
    stop: watch::Sender<bool>,
    cancel: CancelEvent,
    status: Arc<StatusPublisher>,
    supervisor: tokio::task::JoinHandle<()>,
    ipc: std::thread::JoinHandle<()>,
}

impl Agent {
    /// Creates the data directory, cleans orphaned routes, and starts the pipe
    /// server and the supervisor.
    ///
    /// `auto_connect = true` in the config queues a `CONNECT` immediately. With
    /// no config file the agent stays in `disconnected` and waits for a tray
    /// `IMPORT_LINK`.
    fn start(
        runtime: &tokio::runtime::Runtime,
        config_path: &Path,
        data_dir: &Path,
        stop: &watch::Sender<bool>,
        power_resume_rx: watch::Receiver<u64>,
        cancel: CancelEvent,
    ) -> Result<Self, AgentError> {
        std::fs::create_dir_all(data_dir)?;
        // A crash can leave routes and the state file behind; remove them before
        // this run installs any route of its own.
        match cleanup_persisted_routes(&routes_state_path(data_dir)) {
            Ok(0) => {}
            Ok(count) => info!(count, "removed orphaned bypass routes from a previous run"),
            Err(err) => warn!(error = %err, "failed to remove orphaned bypass routes"),
        }

        let publisher = Arc::new(StatusPublisher::new(status_path(data_dir)));
        let mut initial = IpcStatus::disconnected(None);
        let mut auto_connect = false;
        match load_config_if_present(config_path) {
            Ok(Some(config)) => {
                initial.server = Some(config.engine.client.server_addr);
                auto_connect = config.auto_connect;
            }
            Ok(None) => info!(
                path = %config_path.display(),
                "no client config yet; waiting for a vless:// import"
            ),
            Err(message) => {
                warn!(%message, "client config is not usable");
                initial.state = STATE_ERROR.to_owned();
                initial.reason = "config_invalid".to_owned();
            }
        }
        publisher.publish(initial);

        let shared = Arc::new(Shared {
            config_path: config_path.to_path_buf(),
            routes_path: routes_state_path(data_dir),
            status: Arc::clone(&publisher),
        });

        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let handler = {
            let shared = Arc::clone(&shared);
            let command_tx = command_tx.clone();
            Arc::new(move |request: IpcRequest| handle_request(&shared, &command_tx, request))
        };
        let allowed_sid = read_allowed_user_sid(&allowed_user_sid_path(data_dir));
        let ipc = run_ipc_server_thread(
            DEFAULT_PIPE_NAME.to_owned(),
            allowed_sid,
            cancel.clone(),
            handler,
        )?;

        let supervisor = runtime.spawn(supervise(
            shared,
            command_rx,
            stop.subscribe(),
            power_resume_rx,
        ));
        if auto_connect {
            info!("tun.auto_connect is enabled; connecting");
            let _ = command_tx.try_send(Command::Connect);
        }

        Ok(Self {
            stop: stop.clone(),
            cancel,
            status: publisher,
            supervisor,
            ipc,
        })
    }

    /// Stops the IPC pipe server and the tunnel, bounded by
    /// [`AGENT_STOP_TIMEOUT`].
    fn stop(self, runtime: &tokio::runtime::Runtime) {
        let _ = self.cancel.set();
        let _ = self.stop.send(true);
        let mut supervisor = self.supervisor;
        let stopped = runtime.block_on(tokio::time::timeout(AGENT_STOP_TIMEOUT, &mut supervisor));
        if stopped.is_err() {
            warn!("tunnel supervisor did not stop in time; aborting it");
            supervisor.abort();
        }
        if self.ipc.join().is_err() {
            warn!("IPC thread panicked");
        }
        // A stopped agent must not leave a status file that still claims a
        // state the tray can read after the service is gone.
        self.status.remove();
    }
}

/// Runs the `BeamClient` service.
///
/// The service body reports `StartPending`, cleans stale routes, starts the pipe
/// server and the supervisor, reports `Running`, and blocks until the SCM asks
/// for `Stop` or `Shutdown`. A `SERVICE_CONTROL_POWEREVENT` resume bumps the
/// power counter that the network monitor and the engine read.
pub fn run_windows_service(config_path: &Path, data_dir: &Path) -> Result<(), AgentError> {
    let (stop_tx, _) = watch::channel(false);
    let (power_tx, power_rx) = watch::channel(0_u64);
    let power_seq = Arc::new(AtomicU64::new(0));
    let cancel = CancelEvent::new()?;

    let event_stop = stop_tx.clone();
    let event_cancel = cancel.clone();
    let on_event = Arc::new(move |event: ServiceEvent| match event {
        ServiceEvent::Stop | ServiceEvent::Shutdown => {
            info!(?event, "stop requested");
            // Signalling the event wakes a pending pipe accept, so the SCM stop
            // never waits for the 3 s request deadline. `send_replace` stores
            // the value even when no receiver exists yet, so the stop can never
            // be dropped.
            let _ = event_cancel.set();
            let _ = event_stop.send_replace(true);
        }
        ServiceEvent::PowerResume => {
            let resumes = power_seq.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
            info!(resumes, "system resumed from sleep");
            let _ = power_tx.send_replace(resumes);
        }
        ServiceEvent::PowerSuspend => info!("system is suspending"),
    });

    let config_path = config_path.to_path_buf();
    let data_dir = data_dir.to_path_buf();
    let body_stop = stop_tx;
    let body = move |status: ServiceStatusHandle| -> u32 {
        run_service_body(
            &status,
            &config_path,
            &data_dir,
            &body_stop,
            power_rx,
            cancel,
        )
    };
    run_service(SERVICE_NAME, on_event, body)?;
    Ok(())
}

/// Runs the client in the foreground: same agent as the service, `Ctrl-C` to
/// stop. Used by the CLI and by the elevated CI smoke test.
pub fn run_windows_console(config_path: &Path, data_dir: &Path) -> Result<(), AgentError> {
    let runtime = build_runtime()?;
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let (_power_tx, power_rx) = watch::channel(0_u64);
    let cancel = CancelEvent::new()?;
    let agent = {
        let _context = runtime.enter();
        Agent::start(&runtime, config_path, data_dir, &stop_tx, power_rx, cancel)
    }?;
    info!("beam-client console agent running; press Ctrl-C to stop");

    runtime.block_on(async {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("Ctrl-C received"),
            () = wait_for_stop(&mut stop_rx) => {}
        }
    });
    agent.stop(&runtime);
    Ok(())
}

/// Builds the multi-threaded runtime the engine, monitor, and probes share.
fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

/// Service entry point body; the returned value is the service exit code.
fn run_service_body(
    status: &ServiceStatusHandle,
    config_path: &Path,
    data_dir: &Path,
    stop: &watch::Sender<bool>,
    power_resume_rx: watch::Receiver<u64>,
    cancel: CancelEvent,
) -> u32 {
    let _ = status.set_state(ServiceState::StartPending, START_WAIT_HINT_MS);
    let runtime = match build_runtime() {
        Ok(runtime) => runtime,
        Err(err) => {
            error!(error = %err, "cannot start the Tokio runtime");
            return 1;
        }
    };
    let agent = {
        let _context = runtime.enter();
        Agent::start(
            &runtime,
            config_path,
            data_dir,
            stop,
            power_resume_rx,
            cancel,
        )
    };
    let agent = match agent {
        Ok(agent) => agent,
        Err(err) => {
            error!(error = %err, "cannot start the Windows client agent");
            return 2;
        }
    };
    let _ = status.set_state(ServiceState::Running, 0);

    let mut stop_rx = stop.subscribe();
    runtime.block_on(wait_for_stop(&mut stop_rx));

    let _ = status.set_state(ServiceState::StopPending, STOP_WAIT_HINT_MS);
    agent.stop(&runtime);
    0
}

/// Resolves when the stop flag becomes `true`, or when its sender is gone.
async fn wait_for_stop(stop: &mut watch::Receiver<bool>) {
    while !*stop.borrow() {
        if stop.changed().await.is_err() {
            return;
        }
    }
}

/// Runs tunnel lifecycle commands until stop.
async fn supervise(
    shared: Arc<Shared>,
    mut commands: mpsc::Receiver<Command>,
    mut stop: watch::Receiver<bool>,
    power_resume_rx: watch::Receiver<u64>,
) {
    let mut running: Option<Running> = None;
    loop {
        if *stop.borrow() {
            break;
        }
        let wake = match running.as_mut() {
            Some(tunnel) => tokio::select! {
                biased;
                _ = wait_for_stop(&mut stop) => Wake::Stop,
                command = commands.recv() => Wake::Command(command),
                result = &mut tunnel.engine => Wake::Engine(match result {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(message)) => Err(message),
                    Err(err) => Err(err.to_string()),
                }),
            },
            None => {
                tokio::select! {
                    biased;
                    _ = wait_for_stop(&mut stop) => Wake::Stop,
                    command = commands.recv() => Wake::Command(command),
                }
            }
        };

        match wake {
            Wake::Stop => break,
            Wake::Command(None) => break,
            Wake::Engine(Ok(())) => {
                if let Some(tunnel) = running.take() {
                    stop_tunnel(tunnel, true).await;
                }
                info!("tunnel engine exited");
                publish_idle(&shared, STATE_DISCONNECTED, "tunnel_closed");
            }
            Wake::Engine(Err(message)) => {
                if let Some(tunnel) = running.take() {
                    stop_tunnel(tunnel, true).await;
                }
                error!(%message, "tunnel engine stopped with an error");
                publish_idle(&shared, STATE_ERROR, "tunnel_error");
            }
            Wake::Command(Some(Command::Connect)) => {
                if running.is_some() {
                    debug!("CONNECT ignored; the tunnel is already running");
                    continue;
                }
                match start_tunnel(&shared, power_resume_rx.clone()).await {
                    Ok(tunnel) => {
                        info!(ifname = %tunnel.ifname, "tunnel started");
                        running = Some(tunnel);
                    }
                    Err(message) => {
                        warn!(%message, "connect failed");
                        publish_idle(&shared, STATE_ERROR, "connect_failed");
                    }
                }
            }
            Wake::Command(Some(Command::Disconnect)) => {
                if let Some(tunnel) = running.take() {
                    publish_idle(&shared, STATE_STOPPING, "disconnect_requested");
                    stop_tunnel(tunnel, false).await;
                }
                publish_idle(&shared, STATE_DISCONNECTED, "disconnected");
            }
            Wake::Command(Some(Command::Restart)) => {
                // Validate first: a broken edit must not tear down a tunnel that
                // still works.
                match load_config(&shared.config_path) {
                    Err(message) => {
                        warn!(%message, "RESTART rejected; keeping the current tunnel");
                        shared.status.update(|status| {
                            status.reason = "config_invalid".to_owned();
                        });
                    }
                    Ok(_) => {
                        if let Some(tunnel) = running.take() {
                            publish_idle(&shared, STATE_STOPPING, "restart_requested");
                            stop_tunnel(tunnel, false).await;
                        }
                        match start_tunnel(&shared, power_resume_rx.clone()).await {
                            Ok(tunnel) => {
                                info!(ifname = %tunnel.ifname, "tunnel restarted");
                                running = Some(tunnel);
                            }
                            Err(message) => {
                                warn!(%message, "restart failed");
                                publish_idle(&shared, STATE_ERROR, "restart_failed");
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(tunnel) = running.take() {
        publish_idle(&shared, STATE_STOPPING, "shutdown");
        stop_tunnel(tunnel, false).await;
    }
    publish_idle(&shared, STATE_DISCONNECTED, "stopped");
}

/// Opens WinTun, installs routes and leak protection, wires the socket
/// protectors and the DNS bypass callback, and starts the monitor and engine.
async fn start_tunnel(
    shared: &Shared,
    power_resume_rx: watch::Receiver<u64>,
) -> Result<Running, String> {
    let mut config = load_config(&shared.config_path)?;
    let server_addr = config.engine.client.server_addr;
    let tun_net = config.tun_net;
    let auto_route = config.auto_route;
    let fixed_local_dns = config.fixed_local_dns;
    let mtu = config.mtu;
    let strict_kill_switch = config.strict_kill_switch;
    let tun_dns_peer = config.tun_dns_peer;
    let initial_local_dns = config.initial_local_dns;
    let server_ip = config.server_ip;
    let tun_cidr = config.tun_cidr.clone();
    let bypass_cidrs = config.bypass_cidrs.clone();
    let routes_path = shared.routes_path.clone();

    let tun = AsyncWinTun::open(&config.tun_name, mtu)
        .map_err(|err| format!("cannot open the WinTun adapter: {err}"))?;
    let ifname = tun.name().to_owned();
    let tun_luid = tun.luid();
    info!(%ifname, mtu, %server_addr, "opened WinTun adapter");

    let active_if = ActivePhysicalInterface::new();
    let guard = {
        let active_if = active_if.clone();
        tokio::task::spawn_blocking(move || {
            WindowsRouteGuard::setup(
                tun_luid,
                &tun_cidr,
                mtu,
                auto_route,
                strict_kill_switch,
                server_ip,
                initial_local_dns,
                tun_dns_peer,
                &bypass_cidrs,
                active_if,
                routes_path,
            )
        })
        .await
        .map_err(|err| format!("route setup task failed: {err}"))?
        .map_err(|err| format!("route setup failed: {err}"))?
    };
    let routes = Arc::new(Mutex::new(guard));

    // Both upstream dials and local-DNS queries must leave through the physical
    // adapter, or they loop back into the tunnel they serve. With
    // `tun.auto_route = false` the host keeps its own default route, so nothing
    // needs protecting and a loopback or gateway-less setup still works.
    if auto_route {
        config.engine.client.socket_protector =
            Some(active_if.make_socket_protector(server_ip.is_ipv6()));
    }
    if let Some(dns) = config.engine.dns.as_mut() {
        let routes_callback = Arc::clone(&routes);
        dns.on_bypass_ips = Some(Arc::new(move |ips: Vec<IpAddr>| {
            let routes_background = Arc::clone(&routes_callback);
            tokio::task::spawn_blocking(move || {
                if let Ok(mut guard) = routes_background.lock() {
                    for ip in ips {
                        guard.install_dynamic_bypass_ip(ip);
                    }
                }
            })
        }));
        if auto_route {
            let local_upstream = dns.local_upstream;
            dns.local_socket_protector = Some(local_dns_protector(&active_if, local_upstream));
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (network_reset_tx, network_reset_rx) = watch::channel(0_u64);
    config.engine.network_reset = Some(network_reset_rx);
    let activity = Arc::new(TunnelActivity::new());

    shared.status.update(|status| {
        status.state = STATE_CONNECTING.to_owned();
        status.reason = "starting".to_owned();
        status.server = Some(server_addr);
        status.ifname = ifname.clone();
        status.rtt_ms = None;
        status.drops = None;
    });

    let monitor = spawn_windows_network_monitor(
        ifname.clone(),
        tun_luid,
        tun_net,
        server_addr,
        auto_route,
        fixed_local_dns,
        Arc::clone(&routes),
        active_if,
        Arc::clone(&activity),
        Arc::clone(&shared.status),
        network_reset_tx,
        power_resume_rx,
        shutdown_rx.clone(),
    );

    let stack = ProxyTcpStack::new(config.tcp_stack);
    let engine = tokio::spawn(async move {
        run_tun_engine_with_activity(tun, stack, config.engine, shutdown_rx, Some(activity))
            .await
            .map_err(|err| err.to_string())
    });

    Ok(Running {
        ifname,
        shutdown: shutdown_tx,
        engine,
        monitor,
    })
}

/// Signals one tunnel to stop and waits, bounded, for the engine and monitor.
///
/// The engine stops first so the adapter closes before the monitor drops the
/// route guard and removes the routes. When `engine_exited` is `true`, the
/// engine `JoinHandle` has already been polled to completion by the caller and
/// must not be polled again (Tokio panics on re-polling a completed handle).
async fn stop_tunnel(mut tunnel: Running, engine_exited: bool) {
    let ifname = tunnel.ifname;
    let _ = tunnel.shutdown.send(true);
    if !engine_exited {
        match tokio::time::timeout(TUNNEL_STOP_TIMEOUT, &mut tunnel.engine).await {
            Ok(Ok(Ok(()))) => info!(%ifname, "tunnel engine stopped"),
            Ok(Ok(Err(message))) => warn!(%message, %ifname, "tunnel engine failed"),
            Ok(Err(err)) => warn!(error = %err, %ifname, "tunnel engine task failed"),
            Err(_) => {
                warn!(%ifname, "tunnel engine did not stop in time; aborting it");
                tunnel.engine.abort();
            }
        }
    }
    match tokio::time::timeout(TUNNEL_STOP_TIMEOUT, &mut tunnel.monitor).await {
        Ok(Ok(())) => info!(%ifname, "network monitor stopped"),
        Ok(Err(err)) => warn!(error = %err, %ifname, "network monitor task failed"),
        Err(_) => {
            warn!(%ifname, "network monitor did not stop in time; aborting it");
            tunnel.monitor.abort();
        }
    }
}

/// Protector for the local resolver socket.
///
/// A configured local resolver names its own address family, so the socket is
/// bound right on the first attempt. Only a dynamically detected resolver has
/// no family at build time, and [`dual_family_protector`] covers that case.
fn local_dns_protector(
    active_if: &ActivePhysicalInterface,
    local_upstream: Option<SocketAddr>,
) -> SocketProtector {
    match local_upstream {
        Some(server) => active_if.make_socket_protector(server.is_ipv6()),
        None => dual_family_protector(active_if),
    }
}

/// Protector that tries both address families, for a resolver with no known
/// family at build time.
///
/// It tries the IPv4 binding first and the IPv6 binding second: the OS rejects
/// a family mismatch, which makes the second attempt the intended one. When
/// both fail, the first error is reported, because it names the socket's own
/// family.
fn dual_family_protector(active_if: &ActivePhysicalInterface) -> SocketProtector {
    let v4 = active_if.make_socket_protector(false);
    let v6 = active_if.make_socket_protector(true);
    Arc::new(move |socket| match v4(socket) {
        Ok(()) => Ok(()),
        Err(v4_err) => match v6(socket) {
            Ok(()) => Ok(()),
            Err(_) => Err(v4_err),
        },
    })
}

/// Handles one parsed request on the IPC thread.
fn handle_request(
    shared: &Shared,
    commands: &mpsc::Sender<Command>,
    request: IpcRequest,
) -> String {
    match request {
        IpcRequest::Status => format_status_reply(&shared.status.snapshot()),
        IpcRequest::Connect => queue(commands, Command::Connect, STATE_CONNECTING),
        IpcRequest::Disconnect => queue(commands, Command::Disconnect, STATE_STOPPING),
        IpcRequest::Restart => queue(commands, Command::Restart, "restarting"),
        IpcRequest::ImportLink(link) => import_link(shared, &link),
    }
}

/// Queues one lifecycle command and answers at once.
///
/// The reply reports the intent, not the outcome: the tray follows the
/// transition through `STATUS`, which keeps the pipe reply inside its deadline
/// even when a route teardown takes seconds. A full queue is refused instead of
/// buffered, so a restart storm cannot grow without bound.
fn queue(commands: &mpsc::Sender<Command>, command: Command, state: &str) -> String {
    match commands.try_send(command) {
        Ok(()) => format_ok_reply(&[("state", state)]),
        Err(mpsc::error::TrySendError::Full(_)) => format_err_reply("busy", "service is busy"),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            format_err_reply("unavailable", "the tunnel supervisor is not running")
        }
    }
}

/// Writes an imported `vless://` link into the config, atomically.
///
/// An active tunnel keeps running: a new server only takes effect on the next
/// `CONNECT` or `RESTART`, so a mistyped link cannot drop a working session.
fn import_link(shared: &Shared, link: &str) -> String {
    const MAX_CONFIG_BYTES: usize = 256 * 1024;
    let existing = match read_config_bounded(&shared.config_path, MAX_CONFIG_BYTES) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return format_err_reply("import_failed", &format!("cannot read config: {err}"));
        }
    };
    let text = match import_vless_link_to_toml(link, &existing) {
        Ok(text) => text,
        Err(message) => return format_err_reply("import_failed", &message),
    };
    // The imported text is already validated; re-parsing reads the address the
    // reply reports and keeps the two checks in one place.
    let server = match ClientFileConfig::parse_and_validate(&text) {
        Ok(config) => config.engine.client.server_addr,
        Err(_) => return format_err_reply("import_failed", "imported config does not validate"),
    };
    if let Err(err) = write_config_atomic(&shared.config_path, &text) {
        return format_err_reply("import_failed", &format!("cannot write config: {err}"));
    }
    shared.status.update(|status| status.server = Some(server));
    info!(%server, "imported a vless link into the client config");
    format_ok_reply(&[("server", &server.to_string())])
}

/// Reads a UTF-8 config file up to `max_bytes`, rejecting oversized files.
fn read_config_bounded(path: &Path, max_bytes: usize) -> std::io::Result<String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    let limit = (max_bytes as u64).saturating_add(1);
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("config exceeds {max_bytes} bytes"),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "config is not UTF-8"))
}

/// Publishes a state that has no live tunnel and keeps the configured server.
fn publish_idle(shared: &Shared, state: &str, reason: &str) {
    shared.status.update(|status| {
        status.state = state.to_owned();
        status.reason = reason.to_owned();
        status.ifname.clear();
        status.rtt_ms = None;
        status.bypass_ok = true;
        status.drops = None;
    });
}

/// Loads and validates the client config, keeping key material out of the text.
fn load_config(path: &Path) -> Result<ValidatedConfig, String> {
    ClientFileConfig::load(path).map_err(|err| match err {
        // A TOML parse error quotes the offending source line, which can carry
        // the UUID or the REALITY key, so it is replaced by a fixed message.
        ConfigError::Toml(_) => "config is not valid TOML".to_owned(),
        other => other.to_string(),
    })
}

/// Loads the config, reporting a missing file as `Ok(None)`.
fn load_config_if_present(path: &Path) -> Result<Option<ValidatedConfig>, String> {
    match std::fs::metadata(path) {
        Ok(_) => load_config(path).map(Some),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("cannot read config: {err}")),
    }
}

/// Persisted route state file, used to clean up after a crash.
fn routes_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("routes.state")
}

/// Status file consumed by the unelevated tray.
fn status_path(data_dir: &Path) -> PathBuf {
    data_dir.join("status")
}

/// SID file that grants the tray user access to the pipe.
fn allowed_user_sid_path(data_dir: &Path) -> PathBuf {
    data_dir.join("allowed-user.sid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_paths_live_beside_the_config() {
        let dir = Path::new(r"C:\ProgramData\beam");
        assert_eq!(routes_state_path(dir), dir.join("routes.state"));
        assert_eq!(status_path(dir), dir.join("status"));
        assert_eq!(allowed_user_sid_path(dir), dir.join("allowed-user.sid"));
    }

    #[test]
    fn state_tokens_match_the_documented_wire_values() {
        assert_eq!(STATE_DISCONNECTED, "disconnected");
        assert_eq!(STATE_CONNECTING, "connecting");
        assert_eq!(STATE_STOPPING, "stopping");
        assert_eq!(STATE_ERROR, "error");
    }

    #[test]
    fn connect_replies_without_waiting_for_the_supervisor() {
        let (commands, mut queued) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let shared = Shared {
            config_path: PathBuf::from("unused.toml"),
            routes_path: PathBuf::from("unused.state"),
            status: Arc::new(StatusPublisher::new(PathBuf::from("unused-status"))),
        };
        let reply = handle_request(&shared, &commands, IpcRequest::Connect);
        assert_eq!(reply, "OK state=connecting");
        assert_eq!(queued.try_recv(), Ok(Command::Connect));
    }

    #[test]
    fn a_dropped_supervisor_is_reported_as_unavailable() {
        let (commands, queued) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        drop(queued);
        let reply = queue(&commands, Command::Restart, "restarting");
        assert_eq!(
            reply,
            "ERR code=unavailable msg=the tunnel supervisor is not running"
        );
    }

    #[test]
    fn a_full_command_queue_is_reported_as_busy() {
        let (commands, _queued) = mpsc::channel(1);
        assert_eq!(
            queue(&commands, Command::Connect, STATE_CONNECTING),
            "OK state=connecting"
        );
        assert_eq!(
            queue(&commands, Command::Restart, "restarting"),
            "ERR code=busy msg=service is busy"
        );
    }
}
