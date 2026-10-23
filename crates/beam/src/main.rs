use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use beam_core::address::{Address, NetLocation};
use beam_core::config::{Config, LogLevel};
use beam_core::tls::{MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN, TlsServerConfig, handle_connection};
use beam_core::udp::LegacyUdpConfig;
use beam_core::xudp::XudpConfig;
use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::sleep;

/// High-performance VLESS + REALITY + Vision server.
#[derive(Debug, Parser)]
#[command(name = "beam", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/beam/config.toml")]
    config: PathBuf,

    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,
}

fn main() -> anyhow::Result<()> {
    // Each Vision Direct relay can occupy up to two blocking splice tasks.
    // 160 threads covers about 80 active relay pairs; max_connections is an
    // admission cap, not a promise of 1024 concurrent bulk relays.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(160)
        .enable_all()
        .build()
        .context("failed to build the Tokio runtime")?;
    runtime.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::from_path(&cli.config)
        .with_context(|| format!("failed to load `{}`", cli.config.display()))?;

    init_logging(config.log.level);

    if cli.check {
        println!("configuration is valid: {}", cli.config.display());
        return Ok(());
    }

    let tls_config = Arc::new(build_tls_config(&config)?);
    let listener = TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("failed to bind `{}`", config.server.listen))?;
    let semaphore = Arc::new(Semaphore::new(config.limits.max_connections as usize));

    tracing::info!(listen = %config.server.listen, "beam listening");

    // A transient fd shortage must not turn into a permanent outage. `accept`
    // can fail with EMFILE/ENFILE, ECONNABORTED, or an interrupted syscall;
    // keep the listener alive and retry with a bounded backoff instead of
    // dropping the runtime (and any in-flight blocking relays) on the first
    // error.
    let mut accept_backoff = Duration::from_millis(10);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => {
                accept_backoff = Duration::from_millis(10);
                accepted
            }
            Err(error) => {
                tracing::warn!(%error, "listener accept failed; retrying");
                sleep(accept_backoff).await;
                accept_backoff = (accept_backoff * 2).min(Duration::from_secs(1));
                continue;
            }
        };
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .context("connection limiter closed")?;
        let tls_config = Arc::clone(&tls_config);

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = stream.set_nodelay(true) {
                tracing::debug!(%peer, %error, "could not set TCP_NODELAY");
            }

            match handle_connection(stream, tls_config).await {
                Ok(outcome) => tracing::debug!(%peer, ?outcome, "connection finished"),
                Err(error) => tracing::debug!(%peer, %error, "connection failed"),
            }
        });
    }
}

fn build_tls_config(config: &Config) -> anyhow::Result<TlsServerConfig> {
    let destination = &config.reality.dest;
    let address = match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => Address::Ipv4(address),
        Ok(IpAddr::V6(address)) => Address::Ipv6(address),
        Err(_) => Address::Domain(destination.host.clone()),
    };
    let cover = NetLocation {
        address,
        port: destination.port,
    };
    let user_id = *config.user.id.as_bytes();

    let max_sessions = usize::try_from(config.limits.max_udp_destinations)
        .unwrap_or(usize::MAX)
        .clamp(1, usize::from(u16::MAX) + 1);
    let xudp = XudpConfig {
        max_sessions,
        session_idle_timeout: Duration::from_millis(config.limits.idle_timeout_ms),
        io_timeout: Duration::from_millis(config.limits.handshake_timeout_ms),
        // A single HTTP/3 body can arrive as hundreds of UDP datagrams while
        // the outer TCP stream drains. Keep a larger bounded reply queue so a
        // short client-side pause does not turn into QUIC packet loss.
        max_queued_replies: 512,
        ..XudpConfig::default()
    };
    xudp.validate().context("invalid XUDP limits")?;

    let max_packetaddr_destinations = usize::try_from(config.limits.max_udp_destinations)
        .unwrap_or(usize::MAX)
        .clamp(1, 65_536);
    let udp = LegacyUdpConfig {
        io_timeout: Duration::from_millis(config.limits.handshake_timeout_ms),
        idle_timeout: Duration::from_millis(config.limits.idle_timeout_ms),
        max_packetaddr_destinations,
        ..LegacyUdpConfig::default()
    };
    udp.validate().context("invalid legacy UDP limits")?;

    let tls = TlsServerConfig::new(
        *config.reality.private_key,
        config.reality.short_ids.clone(),
        config.reality.server_names.clone(),
        [0, 0, 0],
        [255, 255, 255],
        None,
        cover,
        Duration::from_millis(config.limits.handshake_timeout_ms),
        TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN,
        user_id,
    )
    .context("failed to build the TLS server configuration")?;

    Ok(tls
        .with_xudp(xudp)
        .with_udp(udp)
        .with_relay_idle_timeout(Duration::from_millis(config.limits.idle_timeout_ms)))
}

fn init_logging(level: LogLevel) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level.as_str()));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
