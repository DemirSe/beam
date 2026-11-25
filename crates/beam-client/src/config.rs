//! Strict TOML configuration for `beam-client`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use beam_core::client::BeamClientConfig;
use beam_core::reality::RealityClientConfig;
use beam_tun::{
    DnsConfig, DnsUpstream, IpNet, RoutePolicy, TUN_V6_NET, TcpStackConfig, TunEngineConfig,
    UdpBridgeConfig,
};
use serde::Deserialize;
use uuid::Uuid;

const TCP_STACK_BUFFER_BUDGET_BYTES: usize = 256 * 1024 * 1024;
const MIN_TCP_SOCKET_BUFFER_BYTES: usize = 64 * 1024;
const MAX_TCP_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Derives per-direction TCP socket buffer size from `max_tcp_connections`
/// against a 256 MiB aggregate TCP stack budget, clamped to `64 KiB..=4 MiB`,
/// keeping memory safely under systemd's `MemoryHigh=384M` / `MemoryMax=512M`.
fn derive_tcp_socket_buffer_bytes(max_tcp_connections: usize) -> usize {
    let directions = max_tcp_connections.max(1).saturating_mul(2);
    (TCP_STACK_BUFFER_BUDGET_BYTES / directions)
        .clamp(MIN_TCP_SOCKET_BUFFER_BYTES, MAX_TCP_SOCKET_BUFFER_BYTES)
}

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

#[derive(Clone, Deserialize)]
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

impl fmt::Debug for ServerSection {
    /// Redacts every credential so a debug-printed config cannot leak
    /// `public_key`, `short_id`, or `user_id` into logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSection")
            .field("address", &self.address)
            .field("sni", &self.sni)
            .field("credentials", &"[REDACTED]")
            .finish()
    }
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
    #[serde(default)]
    pub reject_ipv6: bool,
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
            reject_ipv6: false,
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
    #[serde(default)]
    pub ipv4_only: bool,
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
            ipv4_only: false,
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
    pub tun_net: IpNet,
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
        if let Some(warning) = check_config_permissions(path) {
            eprintln!("{warning}");
        }
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
        if !self.bypass.domains.is_empty() && !self.dns.enabled {
            return Err(ConfigError::Invalid(
                "bypass.domains requires dns.enabled = true; the split is only applied by the \
                 built-in DNS interceptor"
                    .into(),
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

        let tun_net = IpNet::parse_cidr(&self.tun.address)
            .ok_or_else(|| ConfigError::Invalid("tun.address must be valid IPv4 CIDR".into()))?;
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
                _ => (detect_system_local_dns_excluding(Some(tun_net)), true),
            };
            initial_local_dns = local_upstream.map(|s| s.ip());
            let mut cfg = DnsConfig::new(upstream, local_upstream);
            if auto_detect {
                cfg.refresh_local_upstream = Some(std::sync::Arc::new(move || {
                    detect_system_local_dns_excluding(Some(tun_net))
                }));
            }
            cfg.local_suffixes = self.dns.local_suffixes;
            cfg.bypass_domains = self.bypass.domains;
            cfg.cache_size = self.dns.cache_size;
            cfg.query_timeout = Duration::from_millis(self.dns.query_timeout_ms);
            cfg.ipv4_only = self.dns.ipv4_only;
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
            reject_ipv6: self.tun.reject_ipv6,
            drop_private_destinations: self.tun.drop_private_destinations,
            exclude_ips: exclude_ips.into(),
            bypass_cidrs: parsed_bypass_cidrs.into(),
            intercept_dns: dns_cfg.is_some(),
        };

        let engine = TunEngineConfig {
            client,
            route,
            max_tcp_connections: self.limits.max_tcp_connections,
            tcp_relay_idle_timeout: None,
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
            socket_buffer_bytes: derive_tcp_socket_buffer_bytes(self.limits.max_tcp_connections),
            handshake_timeout_ms: self.limits.handshake_timeout_ms,
            idle_timeout_ms: self.limits.idle_timeout_ms,
        };

        Ok(ValidatedConfig {
            tun_name: self.tun.name,
            tun_cidr: self.tun.address,
            tun_net,
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
    let sock = if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        sock
    } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
        SocketAddr::new(ip, 53)
    } else {
        return Err(ConfigError::Invalid(format!(
            "dns.local_upstream must be IP or IP:port, got: {trimmed}"
        )));
    };
    if sock.ip().is_unspecified() {
        return Err(ConfigError::Invalid(
            "dns.local_upstream must not use an unspecified IP address".into(),
        ));
    }
    if sock.port() == 0 {
        return Err(ConfigError::Invalid(
            "dns.local_upstream must not use port 0".into(),
        ));
    }
    Ok(sock)
}

/// Auto-detects the host's pre-VPN local DNS server from systemd-resolved's
/// upstream resolv.conf or `/etc/resolv.conf`, skipping loopback stubs and any
/// address inside `exclude_tun_net` (or the IPv6 TUN subnet `fd00:be:a::/126`)
/// so `systemd-resolved`'s per-link TUN DNS never self-poisons `local_upstream`.
pub fn detect_system_local_dns_excluding(exclude_tun_net: Option<IpNet>) -> Option<SocketAddr> {
    for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        if let Ok(content) = std::fs::read_to_string(path)
            && let Some(addr) = parse_resolv_conf_nameserver(&content, exclude_tun_net)
        {
            return Some(addr);
        }
    }
    None
}

fn is_tun_ipv6(ip: IpAddr) -> bool {
    TUN_V6_NET.contains(ip)
}

fn parse_resolv_conf_nameserver(
    content: &str,
    exclude_tun_net: Option<IpNet>,
) -> Option<SocketAddr> {
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
        if ip.is_loopback()
            || ip.is_unspecified()
            || is_tun_ipv6(ip)
            || exclude_tun_net.is_some_and(|net| net.contains(ip))
        {
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
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    let raw = u32::from(ip);
    let network = raw & mask;
    let broadcast = network | !mask;
    let candidate = if raw.wrapping_add(1) < broadcast {
        raw.wrapping_add(1)
    } else if raw.saturating_sub(1) > network {
        raw.saturating_sub(1)
    } else {
        return None;
    };
    Some(Ipv4Addr::from(candidate))
}

/// Checks whether a secrets-bearing client config file has overly permissive
/// Unix mode bits (world-accessible `0o007` or group-writable `0o020`).
///
/// Mirrors `beam` server's mode check: group-readable (`0640`) is permitted
/// for service deployments while world access (`0644`) and group write (`0660`)
/// return an operator-facing warning string.
#[cfg(unix)]
pub fn check_config_permissions(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    let mode = metadata.permissions().mode();
    let reason = if mode & 0o007 != 0 {
        "is accessible to other users; use 0600, or 0640 with a trusted group"
    } else if mode & 0o020 != 0 {
        "is group-writable; use 0600, or 0640 with a trusted group"
    } else {
        return None;
    };
    Some(format!(
        "warning: config file {} has mode {:03o} and {reason}",
        path.display(),
        mode & 0o777
    ))
}

#[cfg(not(unix))]
pub fn check_config_permissions(_path: &Path) -> Option<String> {
    None
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
    fn tun_drop_private_destinations_propagates_to_route_policy() {
        // The example omits the key, so the default stays `true` (drop).
        let cfg = ClientFileConfig::parse_and_validate(EXAMPLE).expect("example config valid");
        assert!(cfg.engine.route.drop_private_destinations);

        // Explicit `false` routes private/LAN traffic through the tunnel.
        let raw = EXAMPLE.replace(
            "reject_ipv6 = false",
            "reject_ipv6 = false\ndrop_private_destinations = false",
        );
        let cfg = ClientFileConfig::parse_and_validate(&raw).expect("drop_private=false valid");
        assert!(!cfg.engine.route.drop_private_destinations);
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
    fn resolv_conf_parser_skips_loopback_and_tun_subnet() {
        let tun_net = IpNet::parse_cidr("172.19.0.1/30").expect("tun cidr");
        let text =
            "# comment\nnameserver 127.0.0.53\nnameserver 172.19.0.2\nnameserver 192.168.1.1\n";
        assert_eq!(
            parse_resolv_conf_nameserver(text, Some(tun_net)),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                53
            ))
        );
        assert_eq!(
            parse_resolv_conf_nameserver(
                "nameserver 127.0.0.1\nnameserver 172.19.0.2\n",
                Some(tun_net)
            ),
            None
        );

        // derive_tun_peer_ipv4 must never return the subnet broadcast address.
        assert_eq!(
            derive_tun_peer_ipv4("172.19.0.1/30"),
            Some(Ipv4Addr::new(172, 19, 0, 2))
        );
        assert_eq!(
            derive_tun_peer_ipv4("172.19.0.2/30"),
            Some(Ipv4Addr::new(172, 19, 0, 1))
        );
    }

    #[test]
    fn tcp_socket_buffer_budget_stays_bounded_across_connection_limits() {
        // Default 256 connections -> 512 KiB/dir -> 256 MiB aggregate.
        let default_cfg = ClientFileConfig::parse_and_validate(EXAMPLE).expect("example config");
        assert_eq!(default_cfg.tcp_stack.max_connections, 256);
        assert_eq!(default_cfg.tcp_stack.socket_buffer_bytes, 512 * 1024);
        assert_eq!(
            2 * default_cfg.tcp_stack.max_connections * default_cfg.tcp_stack.socket_buffer_bytes,
            256 * 1024 * 1024
        );

        // Small (16 connections) -> capped at 4 MiB/dir -> 128 MiB aggregate.
        let small = EXAMPLE.replace("max_tcp_connections = 256", "max_tcp_connections = 16");
        let small_cfg = ClientFileConfig::parse_and_validate(&small).expect("small config");
        assert_eq!(small_cfg.tcp_stack.socket_buffer_bytes, 4 * 1024 * 1024);
        assert_eq!(
            2 * small_cfg.tcp_stack.max_connections * small_cfg.tcp_stack.socket_buffer_bytes,
            128 * 1024 * 1024
        );

        // Max (4096 connections) -> clamped at 64 KiB/dir -> 512 MiB aggregate.
        let max = EXAMPLE.replace("max_tcp_connections = 256", "max_tcp_connections = 4096");
        let max_cfg = ClientFileConfig::parse_and_validate(&max).expect("max config");
        assert_eq!(max_cfg.tcp_stack.socket_buffer_bytes, 64 * 1024);
        assert!(
            2 * max_cfg.tcp_stack.max_connections * max_cfg.tcp_stack.socket_buffer_bytes
                <= 512 * 1024 * 1024
        );
    }

    #[test]
    fn custom_timeouts_propagate_into_tcp_stack_config() {
        let custom = EXAMPLE
            .replace(
                "handshake_timeout_ms = 10000",
                "handshake_timeout_ms = 4500",
            )
            .replace("idle_timeout_ms = 300000", "idle_timeout_ms = 90000");
        let cfg = ClientFileConfig::parse_and_validate(&custom).expect("custom timeouts valid");
        assert_eq!(cfg.tcp_stack.handshake_timeout_ms, 4500);
        assert_eq!(cfg.tcp_stack.idle_timeout_ms, 90_000);
        assert_eq!(
            cfg.engine.client.handshake_timeout,
            Duration::from_millis(4500)
        );
        assert_eq!(
            cfg.engine.client.idle_timeout,
            Duration::from_millis(90_000)
        );
    }

    #[cfg(unix)]
    #[test]
    fn config_permission_check_flags_world_accessible_and_group_writable() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir =
            std::env::temp_dir().join(format!("beam-client-perm-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("client.toml");
        std::fs::write(&path, EXAMPLE).expect("write temp config");

        for (mode, expect_warn) in [(0o600, false), (0o640, false), (0o644, true), (0o660, true)] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("set permissions");
            let warning = check_config_permissions(&path);
            assert_eq!(
                warning.is_some(),
                expect_warn,
                "unexpected warning state for mode {mode:03o}: {warning:?}"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_output_redacts_server_credentials() {
        let cfg: ClientFileConfig = toml::from_str(EXAMPLE).expect("example parses");
        let user_id = cfg.server.user_id.to_string();
        let secrets = [
            "user_id",
            "public_key",
            "short_id",
            user_id.as_str(),
            cfg.server.public_key.as_str(),
            cfg.server.short_id.as_str(),
        ];

        let rendered = format!("{cfg:?}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        assert!(rendered.contains("whatsapp.net"), "{rendered}");
        for secret in secrets {
            assert!(!rendered.contains(secret), "leaked {secret} in {rendered}");
        }

        let server_only = format!("{:?}", cfg.server);
        for secret in secrets {
            assert!(
                !server_only.contains(secret),
                "leaked {secret} in {server_only}"
            );
        }
    }

    #[test]
    fn validates_tun_cidr_prefix_and_address() {
        assert!(validate_ipv4_cidr("172.19.0.1/30").is_ok());
        assert!(validate_ipv4_cidr("10.0.0.0/8").is_ok());
        assert!(validate_ipv4_cidr("192.168.1.1/32").is_ok());
        assert!(validate_ipv4_cidr("172.19.0.1/0").is_err());
        assert!(validate_ipv4_cidr("172.19.0.1/33").is_err());
        assert!(validate_ipv4_cidr("not-an-ip/30").is_err());
        assert!(validate_ipv4_cidr("172.19.0.1").is_err());
    }

    #[test]
    fn rejects_zero_port_local_upstream() {
        assert!(parse_dns_socket_addr("192.168.1.1:53").is_ok());
        assert_eq!(
            parse_dns_socket_addr("192.168.1.1")
                .expect("default port")
                .port(),
            53
        );
        assert!(parse_dns_socket_addr("192.168.1.1:0").is_err());
        assert!(parse_dns_socket_addr("[fd00::1]:0").is_err());
        assert!(parse_dns_socket_addr("0.0.0.0:53").is_err());
        assert!(parse_dns_socket_addr("[::]:53").is_err());

        let zero_port = EXAMPLE.replace(
            "# local_upstream = \"192.168.1.1:53\"",
            "local_upstream = \"192.168.1.1:0\"",
        );
        assert!(ClientFileConfig::parse_and_validate(&zero_port).is_err());
    }

    #[test]
    fn rejects_bypass_domains_without_dns() {
        let with_domains = EXAMPLE.replace("domains = []", "domains = [\"corp.example\"]");
        assert!(ClientFileConfig::parse_and_validate(&with_domains).is_ok());

        let dns_disabled = with_domains.replace("enabled = true", "enabled = false");
        let err = ClientFileConfig::parse_and_validate(&dns_disabled)
            .expect_err("bypass.domains without dns must fail");
        assert!(
            err.to_string()
                .contains("bypass.domains requires dns.enabled"),
            "{err}"
        );

        let no_domains = EXAMPLE.replace("enabled = true", "enabled = false");
        assert!(ClientFileConfig::parse_and_validate(&no_domains).is_ok());
    }
}
