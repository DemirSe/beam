//! Strict TOML configuration for `beam-client`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use beam_core::client::BeamClientConfig;
use beam_core::reality::RealityClientConfig;
use beam_tun::{RoutePolicy, TcpStackConfig, TunEngineConfig, UdpBridgeConfig};
use serde::Deserialize;
use uuid::Uuid;

/// Top-level `beam-client` TOML configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientFileConfig {
    pub server: ServerSection,
    #[serde(default)]
    pub tun: TunSection,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub log: LogSection,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Server socket address (`ip:port`).
    pub address: SocketAddr,
    /// Cover SNI hostname (e.g. `whatsapp.net`).
    pub sni: String,
    /// Server X25519 public key in base64url (no padding).
    pub public_key: String,
    /// Configured REALITY short id in hex (2..=16 even hex chars).
    pub short_id: String,
    /// VLESS user UUID.
    pub user_id: Uuid,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunSection {
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_cidr")]
    pub address: String,
    #[serde(default = "default_mtu")]
    pub mtu: usize,
    #[serde(default = "default_true")]
    pub auto_route: bool,
    #[serde(default = "default_true")]
    pub reject_quic: bool,
    #[serde(default = "default_true")]
    pub drop_private_destinations: bool,
}

impl Default for TunSection {
    fn default() -> Self {
        Self {
            name: default_tun_name(),
            address: default_tun_cidr(),
            mtu: default_mtu(),
            auto_route: true,
            reject_quic: true,
            drop_private_destinations: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    #[serde(default = "default_max_tcp")]
    pub max_tcp_connections: usize,
    #[serde(default = "default_max_udp")]
    pub max_udp_sessions: usize,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_tcp_connections: default_max_tcp(),
            max_udp_sessions: default_max_udp(),
            handshake_timeout_ms: default_handshake_timeout_ms(),
            idle_timeout_ms: default_idle_timeout_ms(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_tun_name() -> String {
    "beamtun0".to_owned()
}
fn default_tun_cidr() -> String {
    "172.19.0.1/30".to_owned()
}
fn default_mtu() -> usize {
    1500
}
fn default_true() -> bool {
    true
}
fn default_max_tcp() -> usize {
    256
}
fn default_max_udp() -> usize {
    256
}
fn default_handshake_timeout_ms() -> u64 {
    10_000
}
fn default_idle_timeout_ms() -> u64 {
    300_000
}
fn default_log_level() -> String {
    "info".to_owned()
}

/// Errors returned while loading or validating `beam-client` configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse TOML config: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Validated runtime configuration ready for `beam-tun`.
#[derive(Clone, Debug)]
pub struct ValidatedConfig {
    pub tun_name: String,
    pub tun_cidr: String,
    pub mtu: usize,
    pub auto_route: bool,
    pub log_level: String,
    pub server_ip: Option<Ipv4Addr>,
    pub engine: TunEngineConfig,
    pub tcp_stack: TcpStackConfig,
}

impl ClientFileConfig {
    /// Loads and validates a TOML configuration file from disk.
    pub fn load(path: &Path) -> Result<ValidatedConfig, ConfigError> {
        let raw = std::fs::read_to_string(path)?;
        Self::parse_and_validate(&raw)
    }

    /// Parses and validates TOML configuration text.
    pub fn parse_and_validate(raw: &str) -> Result<ValidatedConfig, ConfigError> {
        let cfg: Self = toml::from_str(raw)?;
        cfg.validate()
    }

    fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        beam_sys::validate_ifname(&self.tun.name)
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;

        if !(576..=9000).contains(&self.tun.mtu) {
            return Err(ConfigError::Invalid(format!(
                "tun.mtu {} must be between 576 and 9000",
                self.tun.mtu
            )));
        }

        if self.limits.max_tcp_connections == 0 || self.limits.max_tcp_connections > 4096 {
            return Err(ConfigError::Invalid(
                "limits.max_tcp_connections must be in 1..=4096".into(),
            ));
        }
        if self.limits.max_udp_sessions == 0 || self.limits.max_udp_sessions > 4096 {
            return Err(ConfigError::Invalid(
                "limits.max_udp_sessions must be in 1..=4096".into(),
            ));
        }
        if !(100..=86_400_000).contains(&self.limits.handshake_timeout_ms) {
            return Err(ConfigError::Invalid(
                "limits.handshake_timeout_ms must be in 100..=86400000".into(),
            ));
        }
        if !(1000..=86_400_000).contains(&self.limits.idle_timeout_ms) {
            return Err(ConfigError::Invalid(
                "limits.idle_timeout_ms must be in 1000..=86400000".into(),
            ));
        }

        let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.server.public_key.trim())
            .map_err(|_| ConfigError::Invalid("server.public_key is not valid base64url".into()))?;
        let public_key: [u8; 32] = pk_bytes.try_into().map_err(|_| {
            ConfigError::Invalid("server.public_key must decode to 32 bytes".into())
        })?;

        let reality = RealityClientConfig::new(public_key, &self.server.short_id, &self.server.sni)
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;

        let mut client = BeamClientConfig::new(
            self.server.address,
            reality,
            *self.server.user_id.as_bytes(),
        );
        client.handshake_timeout = Duration::from_millis(self.limits.handshake_timeout_ms);
        client.idle_timeout = Duration::from_millis(self.limits.idle_timeout_ms);

        let server_ip = match self.server.address.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        };
        let mut exclude_ips = Vec::new();
        if let Some(ip) = server_ip {
            exclude_ips.push(ip);
        }

        let route = RoutePolicy {
            reject_quic: self.tun.reject_quic,
            drop_private_destinations: self.tun.drop_private_destinations,
            exclude_ips,
        };

        let engine = TunEngineConfig {
            client,
            route,
            max_tcp_connections: self.limits.max_tcp_connections,
            udp: UdpBridgeConfig {
                max_sessions: self.limits.max_udp_sessions,
                idle_timeout: Duration::from_millis(self.limits.idle_timeout_ms.min(60_000)),
            },
        };

        let tcp_stack = TcpStackConfig {
            mtu: self.tun.mtu,
            max_connections: self.limits.max_tcp_connections,
            ..TcpStackConfig::default()
        };

        Ok(ValidatedConfig {
            tun_name: self.tun.name,
            tun_cidr: self.tun.address,
            mtu: self.tun.mtu,
            auto_route: self.tun.auto_route,
            log_level: self.log.level,
            server_ip,
            engine,
            tcp_stack,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../config.client.example.toml");

    #[test]
    fn example_client_config_validates() {
        let cfg = ClientFileConfig::parse_and_validate(EXAMPLE).expect("example config valid");
        assert_eq!(cfg.tun_name, "beamtun0");
        assert_eq!(cfg.mtu, 1500);
        assert!(cfg.engine.route.reject_quic);
    }

    #[test]
    fn rejects_unknown_field() {
        let bad = format!("{EXAMPLE}\nunknown_key = 1\n");
        assert!(ClientFileConfig::parse_and_validate(&bad).is_err());
    }
}
