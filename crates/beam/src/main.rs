use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use beam_core::address::{Address, NetLocation};
use beam_core::config::{Config, LogLevel};
use beam_core::tls::{MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN, TlsServerConfig, handle_connection};
use beam_core::xudp::XudpConfig;
use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    loop {
        let (stream, peer) = listener.accept().await?;
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
        ..XudpConfig::default()
    };
    xudp.validate().context("invalid XUDP limits")?;

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

    Ok(tls.with_xudp(xudp))
}

fn init_logging(level: LogLevel) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level.as_str()));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
