use std::path::PathBuf;

use anyhow::Context;
use beam_core::config::{Config, LogLevel};
use clap::Parser;

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
    let cli = Cli::parse();
    let config = Config::from_path(&cli.config)
        .with_context(|| format!("failed to load `{}`", cli.config.display()))?;

    init_logging(config.log.level);

    if cli.check {
        println!("configuration is valid: {}", cli.config.display());
        return Ok(());
    }

    anyhow::bail!("server runtime is not implemented yet")
}

fn init_logging(level: LogLevel) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level.as_str()));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
