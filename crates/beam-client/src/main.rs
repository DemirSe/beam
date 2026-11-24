#![forbid(unsafe_code)]

//! `beam-client`: lightweight, single-purpose VLESS + REALITY + Vision + XUDP
//! TUN client for `beam`.

mod config;
mod health;
mod linux_tun;

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use beam_tun::{ProxyTcpStack, run_tun_engine};
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::ClientFileConfig;
use crate::health::{DEFAULT_STATUS_PATH, spawn_network_monitor};
use crate::linux_tun::{AsyncLinuxTun, LinuxRouteGuard};

const DEFAULT_CONFIG_PATH: &str = "/etc/beam/client.toml";

struct CliArgs {
    config_path: PathBuf,
    check_only: bool,
    show_version: bool,
}

fn parse_args() -> Result<CliArgs, String> {
    let mut args = std::env::args().skip(1);
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut check_only = false;
    let mut show_version = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("missing path argument after {arg}"))?;
                config_path = PathBuf::from(value);
            }
            "--check" => check_only = true,
            "-V" | "--version" => show_version = true,
            "-h" | "--help" => {
                println!(
                    "Usage: beam-client [-c|--config PATH] [--check] [--version]\n\n\
                     Options:\n  \
                       -c, --config PATH  Path to client TOML config (default: {DEFAULT_CONFIG_PATH})\n  \
                       --check            Validate config and exit without opening TUN\n  \
                       -V, --version      Print version and exit"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(CliArgs {
        config_path,
        check_only,
        show_version,
    })
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
        return ExitCode::SUCCESS;
    }

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

async fn run_client(mut cfg: config::ValidatedConfig) -> Result<(), Box<dyn std::error::Error>> {
    let tun = AsyncLinuxTun::open(&cfg.tun_name, cfg.mtu)?;
    let actual_name = tun.name().to_owned();
    info!(ifname = %actual_name, mtu = cfg.mtu, "opened Linux TUN device");

    let routes = Arc::new(Mutex::new(LinuxRouteGuard::setup(
        &actual_name,
        &cfg.tun_cidr,
        cfg.mtu,
        cfg.auto_route,
        cfg.server_ip,
        &cfg.bypass_cidrs,
    )?));

    // Wire dynamic bypass route installation for resolved `bypass.domains` IPs.
    if let Some(dns_cfg) = cfg.engine.dns.as_mut() {
        let routes_cb = Arc::clone(&routes);
        dns_cfg.on_bypass_ips = Some(Arc::new(move |ips: &[IpAddr]| {
            if let Ok(mut guard) = routes_cb.lock() {
                for &ip in ips {
                    if let IpAddr::V4(v4) = ip {
                        guard.install_dynamic_bypass_ip(v4);
                    }
                }
            }
        }));
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (network_reset_tx, network_reset_rx) = watch::channel(0u64);
    cfg.engine.network_reset = Some(network_reset_rx);

    let monitor_handle = spawn_network_monitor(
        actual_name.clone(),
        cfg.engine.client.server_addr,
        cfg.auto_route,
        Arc::clone(&routes),
        network_reset_tx,
        shutdown_rx.clone(),
        PathBuf::from(DEFAULT_STATUS_PATH),
    );

    tokio::spawn(async move {
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
        let _ = shutdown_tx.send(true);
    });

    let stack = ProxyTcpStack::new(cfg.tcp_stack);
    let res = run_tun_engine(tun, stack, cfg.engine, shutdown_rx).await;
    let _ = monitor_handle.await;
    res?;
    Ok(())
}
