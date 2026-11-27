#![forbid(unsafe_code)]

//! `beam-client`: lightweight, single-purpose VLESS + REALITY + Vision + XUDP
//! TUN client for `beam`.
//!
//! Linux opens the TUN device directly. Windows runs the same engine from the
//! `BeamClient` service (`--service`) or a foreground console, and imports a
//! `vless://` link from stdin so the link never appears in a process listing.

mod config;
#[cfg(target_os = "linux")]
mod health;
#[cfg(target_os = "linux")]
mod linux_tun;
// Cross-platform on purpose: the `vless://` import and the named-pipe message
// parsing are pure TOML/text logic, so their unit tests run on Linux CI too.
#[cfg(windows)]
mod win_health;
#[cfg_attr(not(windows), allow(dead_code))]
mod win_ipc;
mod win_routes;
#[cfg(windows)]
mod win_service;
#[cfg(windows)]
mod win_tun;

#[cfg(target_os = "linux")]
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use beam_tun::{ProxyTcpStack, TunnelActivity, run_tun_engine_with_activity};
#[cfg(target_os = "linux")]
use tokio::sync::watch;
#[cfg(target_os = "linux")]
use tracing::warn;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::{ClientFileConfig, ValidatedConfig};
#[cfg(target_os = "linux")]
use crate::health::{DEFAULT_STATUS_PATH, spawn_network_monitor};
#[cfg(target_os = "linux")]
use crate::linux_tun::{AsyncLinuxTun, LinuxRouteGuard, cleanup_persisted_routes};

#[cfg(target_os = "linux")]
const DEFAULT_CONFIG_PATH: &str = "/etc/beam/client.toml";

/// Longest config or `vless://` link `--import-link` accepts from disk/stdin.
#[cfg(windows)]
const MAX_IMPORT_BYTES: u64 = 256 * 1024;

/// Largest `beam-client.log` before the service moves it to `.1`.
#[cfg(windows)]
const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

struct CliArgs {
    config_path: PathBuf,
    check_only: bool,
    cleanup_routes: bool,
    show_version: bool,
    #[cfg(windows)]
    service: bool,
    #[cfg(windows)]
    import_link: bool,
}

/// `%ProgramData%\beam`, the Windows install and state directory.
#[cfg(windows)]
fn windows_data_dir() -> PathBuf {
    match std::env::var_os("ProgramData") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("beam"),
        _ => PathBuf::from(r"C:\ProgramData\beam"),
    }
}

#[cfg(windows)]
fn default_config_path() -> PathBuf {
    windows_data_dir().join("client.toml")
}

#[cfg(target_os = "linux")]
fn default_config_path() -> PathBuf {
    PathBuf::from(DEFAULT_CONFIG_PATH)
}

/// Bypass-route state file removed by `--cleanup-routes`.
#[cfg(target_os = "linux")]
fn routes_state_path() -> PathBuf {
    PathBuf::from(crate::linux_tun::DEFAULT_ROUTES_STATE_PATH)
}

#[cfg(windows)]
fn routes_state_path() -> PathBuf {
    windows_data_dir().join("routes.state")
}

#[cfg(target_os = "linux")]
fn cleanup_routes_file(path: &Path) -> std::io::Result<usize> {
    cleanup_persisted_routes(path)
}

#[cfg(windows)]
fn cleanup_routes_file(path: &Path) -> std::io::Result<usize> {
    win_routes::cleanup_persisted_routes(path)
}

fn parse_args() -> Result<CliArgs, String> {
    let mut args = std::env::args().skip(1);
    let mut config_path = default_config_path();
    let mut check_only = false;
    let mut cleanup_routes = false;
    let mut show_version = false;
    #[cfg(windows)]
    let mut service = false;
    #[cfg(windows)]
    let mut import_link = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("missing path argument after {arg}"))?;
                config_path = PathBuf::from(value);
            }
            "--check" => check_only = true,
            "--cleanup-routes" => cleanup_routes = true,
            "-V" | "--version" => show_version = true,
            #[cfg(windows)]
            "--service" => service = true,
            #[cfg(windows)]
            "--import-link" => import_link = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(CliArgs {
        config_path,
        check_only,
        cleanup_routes,
        show_version,
        #[cfg(windows)]
        service,
        #[cfg(windows)]
        import_link,
    })
}

#[cfg(target_os = "linux")]
fn print_help() {
    println!(
        "Usage: beam-client [-c|--config PATH] [--check] [--cleanup-routes] [--version]\n\n\
         Options:\n  \
           -c, --config PATH  Path to client TOML config (default: {DEFAULT_CONFIG_PATH})\n  \
           --check            Validate config and exit without opening TUN\n  \
           --cleanup-routes   Remove any orphaned bypass routes recorded in {}\n  \
           -V, --version      Print version and exit",
        routes_state_path().display()
    );
}

#[cfg(windows)]
fn print_help() {
    println!(
        "Usage: beam-client [-c|--config PATH] [--service] [--import-link] [--check] [--cleanup-routes] [--version]\n\n\
         Options:\n  \
           -c, --config PATH  Path to client TOML config (default: {})\n  \
           --service          Run as the BeamClient Windows service (logs to beam-client.log)\n  \
           --import-link      Read one vless:// link from stdin and update the config\n  \
           --check            Validate config and exit without opening the tunnel\n  \
           --cleanup-routes   Remove any orphaned bypass routes recorded in {}\n  \
           -V, --version      Print version and exit",
        default_config_path().display(),
        routes_state_path().display()
    );
}

fn main() -> ExitCode {
    let cli = match parse_args() {
        Ok(cli) => cli,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };

    if cli.show_version {
        println!("beam-client {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    #[cfg(windows)]
    if cli.import_link {
        return import_link_from_stdin(&cli.config_path);
    }

    #[cfg(windows)]
    if cli.service {
        return run_service(&cli.config_path);
    }

    if cli.cleanup_routes {
        let path = routes_state_path();
        return match cleanup_routes_file(&path) {
            Ok(_) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("route cleanup error ({}): {err}", path.display());
                ExitCode::from(1)
            }
        };
    }

    let validated = match ClientFileConfig::load(&cli.config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("config error ({}): {err}", cli.config_path.display());
            return ExitCode::from(1);
        }
    };

    if cli.check_only {
        println!(
            "OK: config valid (tun={}, mtu={}, server={}, reject_quic={})",
            validated.tun_name,
            validated.mtu,
            validated.engine.client.server_addr,
            validated.engine.route.reject_quic
        );
        println!("{}", describe_dns(&validated.engine.dns));
        return ExitCode::SUCCESS;
    }

    run_foreground(&cli, validated)
}

/// One-line DNS summary for `--check` (never prints query data or secrets).
fn describe_dns(dns: &Option<beam_tun::DnsConfig>) -> String {
    match dns {
        Some(cfg) => format!(
            "DNS: enabled (upstream={} kind={}, local_upstream={}, cache_size={}, ipv4_only={}, local_suffixes={}, bypass_domains={})",
            cfg.upstream,
            cfg.upstream.kind(),
            cfg.local_upstream
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "none".to_owned()),
            cfg.cache_size,
            cfg.ipv4_only,
            cfg.local_suffixes.len(),
            cfg.bypass_domains.len()
        ),
        None => "DNS: disabled".to_owned(),
    }
}

#[cfg(target_os = "linux")]
fn run_foreground(_cli: &CliArgs, validated: ValidatedConfig) -> ExitCode {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(validated.log_level.as_str()));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("failed to initialize Tokio runtime: {err}");
            return ExitCode::from(1);
        }
    };

    match runtime.block_on(run_client(validated)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!(error = %err, "beam-client exited with error");
            ExitCode::from(1)
        }
    }
}

#[cfg(windows)]
fn run_foreground(cli: &CliArgs, validated: ValidatedConfig) -> ExitCode {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(validated.log_level.as_str()));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    info!(tun = %validated.tun_name, "starting beam-client console");
    match win_service::run_windows_console(&cli.config_path, &windows_data_dir()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!(error = %err, "beam-client exited with error");
            ExitCode::from(1)
        }
    }
}

#[cfg(windows)]
fn run_service(config_path: &Path) -> ExitCode {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    init_file_logging();
    match win_service::run_windows_service(config_path, &windows_data_dir()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!(error = %err, "beam-client service exited with error");
            ExitCode::from(1)
        }
    }
}

/// Starts the service log at `%ProgramData%\beam\beam-client.log`.
///
/// A missing or unwritable log file only costs diagnostics, so the service
/// keeps running with the tracing subscriber default instead of failing.
#[cfg(windows)]
fn init_file_logging() {
    let data_dir = windows_data_dir();
    let log_path = data_dir.join("beam-client.log");
    let _ = std::fs::create_dir_all(&data_dir);
    rotate_log(&log_path);
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match opened {
        Ok(file) => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(file)
                .init();
            info!(log = %log_path.display(), "starting beam-client service");
        }
        Err(err) => {
            eprintln!("warning: cannot open {}: {err}", log_path.display());
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }
}

/// Moves a full `beam-client.log` to `beam-client.log.1`.
///
/// shortcut: rotation runs at service start, add a size-checking writer if a
/// single service run can exceed `MAX_LOG_BYTES`.
#[cfg(windows)]
fn rotate_log(path: &Path) {
    let full = std::fs::metadata(path).is_ok_and(|meta| meta.len() >= MAX_LOG_BYTES);
    if !full {
        return;
    }
    let rotated = path.with_extension("log.1");
    let _ = std::fs::remove_file(&rotated);
    let _ = std::fs::rename(path, &rotated);
}

/// Imports one `vless://` link from stdin into the config.
///
/// The link arrives on stdin, never argv, so it cannot leak through a process
/// listing. Nothing prints the link, the UUID, or the key: success prints only
/// the public `host:port` the link points at.
#[cfg(windows)]
fn import_link_from_stdin(config_path: &Path) -> ExitCode {
    let link = match read_bounded(&mut std::io::stdin().lock()) {
        Ok(link) => link,
        Err(err) => {
            eprintln!("import error: cannot read link from stdin: {err}");
            return ExitCode::from(1);
        }
    };
    // Stdin from `echo` or a pipe carries a trailing newline, and a CRLF line
    // ending must not reach the link parser.
    let link = link.trim();
    if link.is_empty() {
        eprintln!("import error: no vless:// link on stdin");
        return ExitCode::from(1);
    }
    // A fresh install may have no config yet; the importer starts from empty.
    let existing = match std::fs::File::open(config_path) {
        Ok(mut file) => match read_bounded(&mut file) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("import error: cannot read {}: {err}", config_path.display());
                return ExitCode::from(1);
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            eprintln!("import error: cannot read {}: {err}", config_path.display());
            return ExitCode::from(1);
        }
    };
    let updated = match win_ipc::import_vless_link_to_toml(link, &existing) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("import error: {err}");
            return ExitCode::from(1);
        }
    };
    let server = match ClientFileConfig::parse_and_validate(&updated) {
        Ok(cfg) => cfg.engine.client.server_addr,
        Err(err) => {
            eprintln!("import error: imported config does not validate: {err}");
            return ExitCode::from(1);
        }
    };
    if let Err(err) = win_ipc::write_config_atomic(config_path, &updated) {
        eprintln!(
            "import error: cannot write {}: {err}",
            config_path.display()
        );
        return ExitCode::from(1);
    }
    println!("OK server={server}");
    ExitCode::SUCCESS
}

/// Reads at most `MAX_IMPORT_BYTES + 1` bytes so a hostile config or link
/// cannot exhaust memory, and rejects an over-long or non-UTF-8 payload.
#[cfg(windows)]
fn read_bounded(reader: &mut impl std::io::Read) -> std::io::Result<String> {
    use std::io::Read as _;

    let mut text = String::new();
    reader
        .take(MAX_IMPORT_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_IMPORT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "payload is larger than the 256 KiB bound",
        ));
    }
    Ok(text)
}

/// Runs the Linux TUN engine in the foreground.
#[cfg(target_os = "linux")]
async fn run_client(mut cfg: ValidatedConfig) -> Result<(), Box<dyn std::error::Error>> {
    let tun = AsyncLinuxTun::open(&cfg.tun_name, cfg.mtu)?;
    let actual_name = tun.name().to_owned();
    info!(ifname = %actual_name, mtu = cfg.mtu, "opened Linux TUN device");

    let routes = Arc::new(Mutex::new(LinuxRouteGuard::setup(
        &actual_name,
        &cfg.tun_cidr,
        cfg.mtu,
        cfg.auto_route,
        cfg.server_ip,
        cfg.initial_local_dns,
        cfg.tun_dns_peer,
        &cfg.bypass_cidrs,
    )?));

    // Wire dynamic bypass route installation for resolved `bypass.domains` IPs.
    // The interceptor `.await`s the returned handle before sending the DNS
    // reply, so the blocking `ip` install runs on the blocking pool without
    // stalling the TUN loop or a Tokio worker thread (first-packet race).
    if let Some(dns_cfg) = cfg.engine.dns.as_mut() {
        let routes_cb = Arc::clone(&routes);
        dns_cfg.on_bypass_ips = Some(Arc::new(move |ips: Vec<IpAddr>| {
            let routes_bg = Arc::clone(&routes_cb);
            tokio::task::spawn_blocking(move || {
                if let Ok(mut guard) = routes_bg.lock() {
                    for ip in ips {
                        guard.install_dynamic_bypass_ip(ip);
                    }
                }
            })
        }));
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (network_reset_tx, network_reset_rx) = watch::channel(0u64);
    cfg.engine.network_reset = Some(network_reset_rx);

    let activity = Arc::new(TunnelActivity::new());

    let mut monitor_handle = spawn_network_monitor(
        actual_name.clone(),
        cfg.tun_net,
        cfg.engine.client.server_addr,
        cfg.auto_route,
        cfg.fixed_local_dns,
        Arc::clone(&routes),
        Arc::clone(&activity),
        network_reset_tx,
        shutdown_rx.clone(),
        PathBuf::from(DEFAULT_STATUS_PATH),
    );

    let signal_shutdown_tx = shutdown_tx.clone();
    let signal_handle = tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = ctrl_c => {}
            _ = async {
                if let Some(s) = sigterm.as_mut() {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
        info!("shutdown signal received");
        let _ = signal_shutdown_tx.send(true);
    });

    let stack = ProxyTcpStack::new(cfg.tcp_stack);
    let res =
        run_tun_engine_with_activity(tun, stack, cfg.engine, shutdown_rx, Some(activity)).await;
    let _ = shutdown_tx.send(true);
    signal_handle.abort();
    if tokio::time::timeout(Duration::from_secs(5), &mut monitor_handle)
        .await
        .is_err()
    {
        monitor_handle.abort();
        warn!("network monitor did not exit within 5s shutdown bound");
    }
    res?;
    Ok(())
}
