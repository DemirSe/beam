//! Strict TOML configuration for `beam-client`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use beam_core::client::BeamClientConfig;
use beam_core::reality::RealityClientConfig;
use beam_tun::{
    DnsConfig, DnsUpstream, IpNet, RoutePolicy, TcpStackConfig, TunEngineConfig, UdpBridgeConfig,
};
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
    pub dns: DnsSection,
    #[serde(default)]
    pub bypass: BypassSection,
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
pub struct DnsSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_dns_upstream")]
    pub upstream: String,
    #[serde(default)]
    pub local_upstream: Option<String>,
    #[serde(default = "default_local_suffixes")]
    pub local_suffixes: Vec<String>,
    #[serde(default = "default_dns_cache_size")]
    pub cache_size: usize,
    #[serde(default = "default_dns_timeout_ms")]
    pub query_timeout_ms: u64,
}

impl Default for DnsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream: default_dns_upstream(),
            local_upstream: None,
            local_suffixes: default_local_suffixes(),
            cache_size: default_dns_cache_size(),
            query_timeout_ms: default_dns_timeout_ms(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BypassSection {
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
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
fn default_dns_upstream() -> String {
    "https://1.1.1.1/dns-query".to_owned()
}
fn default_local_suffixes() -> Vec<String> {
    DnsConfig::default_local_suffixes()
}
fn default_dns_cache_size() -> usize {
    1024
}
fn default_dns_timeout_ms() -> u64 {
    4_000
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
    pub tun_dns_peer: Option<Ipv4Addr>,
    pub mtu: usize,
    pub auto_route: bool,
    pub log_level: String,
    pub server_ip: IpAddr,
    pub fixed_local_dns: Option<IpAddr>,
    pub initial_local_dns: Option<IpAddr>,
    pub bypass_cidrs: Vec<String>,
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

        validate_ipv4_cidr(&self.tun.address)?;

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
        if public_key == [0u8; 32] {
            return Err(ConfigError::Invalid(
                "server.public_key must not be all zeroes".into(),
            ));
        }

        let reality = RealityClientConfig::new(public_key, &self.server.short_id, &self.server.sni)
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;

        let mut client = BeamClientConfig::new(
            self.server.address,
            reality,
            *self.server.user_id.as_bytes(),
        );
        client.handshake_timeout = Duration::from_millis(self.limits.handshake_timeout_ms);
        client.idle_timeout = Duration::from_millis(self.limits.idle_timeout_ms);

        if self.bypass.cidrs.len() > 256 {
            return Err(ConfigError::Invalid(
                "bypass.cidrs must contain at most 256 entries".into(),
            ));
        }
        if self.bypass.domains.len() > 256 {
            return Err(ConfigError::Invalid(
                "bypass.domains must contain at most 256 entries".into(),
            ));
        }
        let mut parsed_bypass_cidrs = Vec::with_capacity(self.bypass.cidrs.len());
        let mut bypass_cidrs_raw = Vec::with_capacity(self.bypass.cidrs.len());
        for cidr in &self.bypass.cidrs {
            let trimmed = cidr.trim();
            let net = IpNet::parse_cidr(trimmed).ok_or_else(|| {
                ConfigError::Invalid(format!("bypass.cidrs has invalid CIDR: {trimmed}"))
            })?;
            parsed_bypass_cidrs.push(net);
            bypass_cidrs_raw.push(trimmed.to_owned());
        }

        let mut fixed_local_dns = None;
        let mut initial_local_dns = None;
        let dns_cfg = if self.dns.enabled {
            if self.dns.cache_size > 16_384 {
                return Err(ConfigError::Invalid(
                    "dns.cache_size must be <= 16384".into(),
                ));
            }
            if !(200..=30_000).contains(&self.dns.query_timeout_ms) {
                return Err(ConfigError::Invalid(
                    "dns.query_timeout_ms must be in 200..=30000".into(),
                ));
            }
            let upstream = DnsUpstream::parse(&self.dns.upstream)
                .map_err(|e| ConfigError::Invalid(format!("dns.upstream: {e}")))?;
            let (local_upstream, auto_detect) = match self.dns.local_upstream.as_deref() {
                Some(raw) if !raw.trim().is_empty() => {
                    let parsed = parse_dns_socket_addr(raw)?;
                    fixed_local_dns = Some(parsed.ip());
                    (Some(parsed), false)
                }
                _ => (detect_system_local_dns(), true),
            };
            initial_local_dns = local_upstream.map(|s| s.ip());
            let mut cfg = DnsConfig::new(upstream, local_upstream);
            if auto_detect {
                cfg.refresh_local_upstream = Some(std::sync::Arc::new(detect_system_local_dns));
            }
            cfg.local_suffixes = self.dns.local_suffixes;
            cfg.bypass_domains = self.bypass.domains;
            cfg.cache_size = self.dns.cache_size;
            cfg.query_timeout = Duration::from_millis(self.dns.query_timeout_ms);
            Some(cfg)
        } else {
            None
        };

        let tun_dns_peer = if dns_cfg.is_some() {
            derive_tun_peer_ipv4(&self.tun.address)
        } else {
            None
        };
        let server_ip = self.server.address.ip();
        let exclude_ips = vec![server_ip];

        let route = RoutePolicy {
            reject_quic: self.tun.reject_quic,
            drop_private_destinations: self.tun.drop_private_destinations,
            exclude_ips,
            bypass_cidrs: parsed_bypass_cidrs,
            intercept_dns: dns_cfg.is_some(),
        };

        let engine = TunEngineConfig {
            client,
            route,
            max_tcp_connections: self.limits.max_tcp_connections,
            udp: UdpBridgeConfig {
                max_sessions: self.limits.max_udp_sessions,
                idle_timeout: Duration::from_millis(self.limits.idle_timeout_ms.min(60_000)),
            },
            dns: dns_cfg,
            network_reset: None,
        };

        let tcp_stack = TcpStackConfig {
            mtu: self.tun.mtu,
            max_connections: self.limits.max_tcp_connections,
            ..TcpStackConfig::default()
        };

        Ok(ValidatedConfig {
            tun_name: self.tun.name,
            tun_cidr: self.tun.address,
            tun_dns_peer,
            mtu: self.tun.mtu,
            auto_route: self.tun.auto_route,
            log_level: self.log.level,
            server_ip,
            fixed_local_dns,
            initial_local_dns,
            bypass_cidrs: bypass_cidrs_raw,
            engine,
            tcp_stack,
        })
    }
}

fn parse_dns_socket_addr(raw: &str) -> Result<SocketAddr, ConfigError> {
    let trimmed = raw.trim();
    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return Ok(sock);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(ConfigError::Invalid(format!(
        "dns.local_upstream must be IP or IP:port, got: {trimmed}"
    )))
}

/// Auto-detects the host's pre-VPN local DNS server from systemd-resolved's
/// upstream resolv.conf or `/etc/resolv.conf`, skipping loopback stubs.
pub fn detect_system_local_dns() -> Option<SocketAddr> {
    for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        if let Ok(content) = std::fs::read_to_string(path)
            && let Some(addr) = parse_resolv_conf_nameserver(&content)
        {
            return Some(addr);
        }
    }
    None
}

fn parse_resolv_conf_nameserver(content: &str) -> Option<SocketAddr> {
    for line in content.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("nameserver") else {
            continue;
        };
        let Some(ip_str) = rest.split_whitespace().next() else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            continue;
        };
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        return Some(SocketAddr::new(ip, 53));
    }
    None
}

fn derive_tun_peer_ipv4(cidr: &str) -> Option<Ipv4Addr> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let ip: Ipv4Addr = addr_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix >= 31 {
        return None;
    }
    let raw = u32::from(ip);
    Some(Ipv4Addr::from(raw.wrapping_add(1)))
}

fn validate_ipv4_cidr(cidr: &str) -> Result<(), ConfigError> {
    let (addr_str, prefix_str) = cidr.split_once('/').ok_or_else(|| {
        ConfigError::Invalid("tun.address must be IPv4 CIDR (e.g. 172.19.0.1/30)".into())
    })?;
    let _ip: Ipv4Addr = addr_str
        .parse()
        .map_err(|_| ConfigError::Invalid("tun.address has invalid IPv4 address".into()))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| ConfigError::Invalid("tun.address has invalid prefix length".into()))?;
    if !(1..=32).contains(&prefix) {
        return Err(ConfigError::Invalid(
            "tun.address prefix length must be 1..=32".into(),
        ));
    }
    Ok(())
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

    #[test]
    fn rejects_invalid_tun_cidr_and_zero_public_key() {
        let bad_cidr = EXAMPLE.replace("172.19.0.1/30", "--flag");
        assert!(ClientFileConfig::parse_and_validate(&bad_cidr).is_err());

        let zero_pk = EXAMPLE.replace(
            "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert!(ClientFileConfig::parse_and_validate(&zero_pk).is_err());
    }

    #[test]
    fn parses_dns_and_bypass_sections() {
        let with_bypass = EXAMPLE
            .replace(
                "cidrs = []",
                "cidrs = [\"198.51.100.0/24\", \"2001:db8::/32\"]",
            )
            .replace("domains = []", "domains = [\"corp.example\"]");
        let cfg = ClientFileConfig::parse_and_validate(&with_bypass).expect("valid config");
        assert!(cfg.engine.dns.is_some());
        assert!(cfg.engine.route.intercept_dns);
        assert_eq!(cfg.bypass_cidrs.len(), 2);
        assert_eq!(cfg.engine.route.bypass_cidrs.len(), 2);
        assert_eq!(
            cfg.engine.dns.as_ref().expect("dns").bypass_domains,
            vec!["corp.example".to_owned()]
        );

        let bad_cidr = EXAMPLE.replace("cidrs = []", "cidrs = [\"not-a-cidr\"]");
        assert!(ClientFileConfig::parse_and_validate(&bad_cidr).is_err());

        let bad_dns = EXAMPLE.replace(
            "https://1.1.1.1/dns-query",
            "http://insecure.example/dns-query",
        );
        assert!(ClientFileConfig::parse_and_validate(&bad_dns).is_err());
    }

    #[test]
    fn resolv_conf_parser_skips_loopback_stub() {
        let text = "# comment\nnameserver 127.0.0.53\nnameserver 192.168.1.1\n";
        assert_eq!(
            parse_resolv_conf_nameserver(text),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                53
            ))
        );
        assert_eq!(parse_resolv_conf_nameserver("nameserver 127.0.0.1\n"), None);
    }
}
