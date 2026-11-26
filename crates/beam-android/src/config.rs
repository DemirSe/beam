//! JSON configuration DTO and `vless://` link preview for the Android client.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use beam_core::client::{ClientLinkError, ParsedClientLink, SocketProtector, parse_client_link};
use beam_sys::validate_ifname;
use beam_tun::{
    BypassCidrs, DnsConfig, DnsUpstream, IpNet, RoutePolicy, TcpStackConfig, TunEngineConfig,
    UdpBridgeConfig,
};
use serde::Deserialize;
use tokio::sync::watch;

/// Default interface MTU for the `VpnService` TUN.
pub const DEFAULT_MTU: usize = 1500;
/// Highest accepted interface MTU.
pub const MAX_MTU: usize = 9000;
/// Lowest accepted interface MTU.
pub const MIN_MTU: usize = 576;
/// Upper bound on configured bypass prefixes.
pub const MAX_BYPASS_CIDRS: usize = 256;
/// Mobile idle timeout for TCP relay writes and idle XUDP mux connections.
/// Relay reads remain uncapped (`tcp_relay_idle_timeout: None`) for push sockets.
pub const MOBILE_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Mobile DNS LRU cache cap (4x smaller than desktop's 1024 to bound worst-case RSS).
pub const MOBILE_DNS_CACHE_SIZE: usize = 256;

/// Configuration that `BeamNativeBridge.nativeStart` receives as JSON.
///
/// Missing fields take the mobile defaults, so Kotlin only sends what the user
/// changed.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct AndroidEngineConfig {
    /// `vless://` REALITY share link of the server.
    pub vless_uri: String,
    /// Literal server IP used instead of resolving the link host.
    ///
    /// A `vless://` link with a hostname would resolve through the platform
    /// resolver after the TUN owns the default route, so that profile must
    /// pass this field.
    #[serde(default)]
    pub server_ip: Option<String>,
    /// TUN interface MTU.
    pub mtu: usize,
    /// Interface name requested from `VpnService.Builder`. Validation only:
    /// the detached descriptor is already attached, so the engine cannot rename
    /// it.
    pub tun_name: String,
    /// IPv4 address of the TUN interface, for display and route checks.
    pub tun_ipv4: String,
    /// IPv4 address the engine answers DNS queries on.
    pub tun_dns_ipv4: String,
    /// DNS-over-HTTPS endpoint, or empty to run without the DNS interceptor.
    pub doh_url: String,
    /// Answer tunneled `AAAA` queries empty and prefer IPv4 upstream addresses.
    pub ipv4_only: bool,
    /// Reject tunneled IPv6 immediately instead of leaking it in clear.
    pub reject_ipv6: bool,
    /// Reject UDP/443 with ICMP Port Unreachable so QUIC falls back to TCP.
    pub reject_quic: bool,
    /// CIDR prefixes that bypass the tunnel.
    pub bypass_cidrs: Vec<String>,
    /// Logcat level (`trace`, `debug`, `info`, `warn`, `error`, `off`).
    pub log_level: String,
}

impl Default for AndroidEngineConfig {
    fn default() -> Self {
        Self {
            vless_uri: String::new(),
            server_ip: None,
            mtu: DEFAULT_MTU,
            tun_name: "tun0".to_owned(),
            // Outside 172.16.0.0/12, which the route policy bypasses as LAN.
            tun_ipv4: "198.19.0.1".to_owned(),
            tun_dns_ipv4: "198.19.0.2".to_owned(),
            doh_url: String::new(),
            ipv4_only: true,
            reject_ipv6: true,
            reject_quic: true,
            bypass_cidrs: Vec::new(),
            log_level: "info".to_owned(),
        }
    }
}

/// Reasons a configuration or link is rejected before the engine starts.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The `vless://` link is malformed.
    #[error("vless link rejected: {0}")]
    Link(#[from] ClientLinkError),
    /// A field is outside its accepted range or format.
    #[error("invalid configuration: {0}")]
    Invalid(String),
    /// The DNS-over-HTTPS endpoint is not a usable upstream.
    #[error("invalid configuration: dns upstream rejected")]
    Dns,
    /// No usable address for the server host.
    #[error("invalid configuration: server host does not resolve")]
    Unresolved,
}

impl AndroidEngineConfig {
    /// Checks the field ranges that do not need the link.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(MIN_MTU..=MAX_MTU).contains(&self.mtu) {
            return Err(ConfigError::Invalid(format!(
                "mtu {} must be {MIN_MTU}..={MAX_MTU}",
                self.mtu
            )));
        }
        validate_ifname(&self.tun_name).map_err(|error| ConfigError::Invalid(error.to_string()))?;
        self.tun_ipv4
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|_| ConfigError::Invalid("tun_ipv4 must be an IPv4 address".to_owned()))?;
        self.tun_dns_ipv4
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|_| ConfigError::Invalid("tun_dns_ipv4 must be an IPv4 address".to_owned()))?;
        if self.bypass_cidrs.len() > MAX_BYPASS_CIDRS {
            return Err(ConfigError::Invalid(format!(
                "bypass_cidrs accepts at most {MAX_BYPASS_CIDRS} entries"
            )));
        }
        if self.log_level.is_empty()
            || self.log_level.len() > 16
            || !self
                .log_level
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic())
        {
            return Err(ConfigError::Invalid(
                "log_level must be 1..=16 ASCII letters".to_owned(),
            ));
        }
        Ok(())
    }

    /// Builds the TCP stack profile, keeping the configured MTU.
    pub fn tcp_stack_config(&self) -> TcpStackConfig {
        TcpStackConfig {
            mtu: self.mtu,
            ..TcpStackConfig::mobile()
        }
    }

    /// Builds the `beam-tun` engine configuration.
    ///
    /// The same protector reaches `BeamClientConfig::socket_protector` and
    /// `DnsConfig::local_socket_protector`. An unprotected upstream socket or
    /// local DNS socket would loop back into the TUN interface.
    pub fn build_engine_config(
        &self,
        socket_protector: Option<SocketProtector>,
        network_reset: Option<watch::Receiver<u64>>,
    ) -> Result<TunEngineConfig, ConfigError> {
        self.validate()?;
        let parsed = parse_client_link(&self.vless_uri)?;
        // A literal override skips `to_socket_addrs`, which would deadlock once
        // the TUN interface owns the default route.
        let server_addr = match self.server_ip.as_deref().map(str::trim) {
            Some(ip) if !ip.is_empty() => {
                let ip = ip.parse::<IpAddr>().map_err(|_| {
                    ConfigError::Invalid("server_ip must be an IPv4 or IPv6 address".to_owned())
                })?;
                SocketAddr::new(ip, parsed.port)
            }
            _ => resolve_server(&parsed.host, parsed.port, self.ipv4_only)?,
        };
        let mut client = parsed
            .into_beam_client_config(server_addr)
            .map_err(|_| ConfigError::Invalid("REALITY parameters rejected".to_owned()))?;
        client.socket_protector = socket_protector.clone();
        // Disable kernel TCP keepalive on mobile: periodic 30 s probes across
        // idle background sockets keep the cellular modem in high-power RRC
        // active state and wake the AP during Android Doze. `TCP_USER_TIMEOUT`
        // still bounds dead sockets on active writes, and `NetworkMonitor`
        // resets flows on network switches.
        client.keepalive_idle = None;
        client.keepalive_interval = None;
        client.keepalive_count = None;
        // Bound stalled TCP relay writes and idle XUDP muxes to 60 s instead of
        // the desktop 300 s default while keeping relay reads uncapped for push.
        client.idle_timeout = MOBILE_IDLE_TIMEOUT;

        let dns = self.dns_config(socket_protector)?;
        let mut bypass_nets = Vec::with_capacity(self.bypass_cidrs.len());
        for cidr in &self.bypass_cidrs {
            let net = IpNet::parse_cidr(cidr).ok_or_else(|| {
                ConfigError::Invalid(format!("invalid bypass CIDR: {}", cidr.trim()))
            })?;
            bypass_nets.push(net);
        }

        let tcp_stack = self.tcp_stack_config();
        Ok(TunEngineConfig {
            client,
            route: RoutePolicy {
                reject_quic: self.reject_quic,
                reject_ipv6: self.reject_ipv6,
                drop_private_destinations: true,
                exclude_ips: vec![server_addr.ip()].into(),
                bypass_cidrs: BypassCidrs::new(&bypass_nets),
                intercept_dns: dns.is_some(),
            },
            max_tcp_connections: tcp_stack.max_connections,
            tcp_relay_idle_timeout: None,
            udp: UdpBridgeConfig::mobile(),
            dns,
            network_reset,
        })
    }

    fn dns_config(
        &self,
        socket_protector: Option<SocketProtector>,
    ) -> Result<Option<DnsConfig>, ConfigError> {
        if self.doh_url.trim().is_empty() {
            return Ok(None);
        }
        let upstream = DnsUpstream::parse(&self.doh_url).map_err(|_| ConfigError::Dns)?;
        let mut dns = DnsConfig::new(upstream, None);
        dns.cache_size = MOBILE_DNS_CACHE_SIZE;
        dns.ipv4_only = self.ipv4_only;
        dns.local_socket_protector = socket_protector;
        Ok(Some(dns))
    }
}

/// Resolves the server host, preferring IPv4 when the profile is IPv4-only.
fn resolve_server(host: &str, port: u16, prefer_ipv4: bool) -> Result<SocketAddr, ConfigError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // shortcut: a hostname resolves through the platform resolver while the TUN
    // interface is already up; a vless:// link with a literal IP avoids it.
    let mut fallback = None;
    for addr in (host, port)
        .to_socket_addrs()
        .map_err(|_| ConfigError::Unresolved)?
    {
        if !prefer_ipv4 || addr.is_ipv4() {
            return Ok(addr);
        }
        fallback.get_or_insert(addr);
    }
    fallback.ok_or(ConfigError::Unresolved)
}

/// Serializes the non-secret fields of a `vless://` link for the profile UI.
///
/// The UUID, REALITY public key, short id, and the link itself never appear in
/// the output.
pub fn parse_vless_link_json(uri: &str) -> String {
    match parse_client_link(uri) {
        Ok(parsed) => {
            let ParsedClientLink {
                host,
                port,
                server_name,
                label,
                ..
            } = parsed;
            serde_json::json!({
                "ok": true,
                "name": label.unwrap_or_else(|| host.clone()),
                "server": host,
                "port": port,
                "sni": server_name,
            })
            .to_string()
        }
        Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}).to_string(),
    }
}

/// Asserts that a protector is wired to both engine hooks.
#[cfg(test)]
fn shared_protector(config: &TunEngineConfig, protector: &SocketProtector) -> bool {
    let client = config
        .client
        .socket_protector
        .as_ref()
        .is_some_and(|hook| std::sync::Arc::ptr_eq(hook, protector));
    let dns = config.dns.as_ref().and_then(|dns| {
        dns.local_socket_protector
            .as_ref()
            .map(|hook| std::sync::Arc::ptr_eq(hook, protector))
    });
    client && dns == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_VLESS_URI;
    use std::sync::Arc;

    fn mobile_config() -> AndroidEngineConfig {
        AndroidEngineConfig {
            vless_uri: TEST_VLESS_URI.to_owned(),
            doh_url: "https://dns.example/dns-query".to_owned(),
            ..AndroidEngineConfig::default()
        }
    }

    #[test]
    fn defaults_follow_the_mobile_plan() {
        let cfg = AndroidEngineConfig::default();
        assert_eq!(cfg.mtu, 1500);
        assert_eq!(cfg.tun_name, "tun0");
        assert_eq!(cfg.tun_ipv4, "198.19.0.1");
        assert_eq!(cfg.tun_dns_ipv4, "198.19.0.2");
        assert!(cfg.server_ip.is_none());
        assert_eq!(cfg.log_level, "info");
        assert!(cfg.ipv4_only && cfg.reject_ipv6 && cfg.reject_quic);
        assert!(cfg.doh_url.is_empty() && cfg.bypass_cidrs.is_empty());
        cfg.validate().expect("defaults must validate");
    }

    #[test]
    fn json_omitting_fields_takes_mobile_defaults() {
        let cfg: AndroidEngineConfig = serde_json::from_str(&format!(
            r#"{{"vless_uri":"{TEST_VLESS_URI}","tun_name":"beam0"}}"#
        ))
        .expect("minimal config JSON");
        assert_eq!(cfg.tun_name, "beam0");
        assert_eq!(cfg.mtu, DEFAULT_MTU);
        assert!(cfg.reject_quic);
    }

    #[test]
    fn builds_the_mobile_engine_config() {
        let cfg = mobile_config();
        let protector: SocketProtector = Arc::new(|_fd| Ok(()));
        let (_reset_tx, reset_rx) = watch::channel(0_u64);
        let engine = cfg
            .build_engine_config(Some(Arc::clone(&protector)), Some(reset_rx))
            .expect("engine config");

        assert!(shared_protector(&engine, &protector));
        assert!(engine.client.keepalive_idle.is_none());
        assert!(engine.client.keepalive_interval.is_none());
        assert!(engine.client.keepalive_count.is_none());
        assert_eq!(engine.client.idle_timeout, MOBILE_IDLE_TIMEOUT);
        assert_eq!(
            engine.client.server_addr,
            "203.0.113.10:443".parse().unwrap()
        );
        assert_eq!(engine.max_tcp_connections, 128);
        assert!(engine.tcp_relay_idle_timeout.is_none());
        assert_eq!(engine.udp.max_sessions, 128);
        assert!(engine.route.reject_quic && engine.route.reject_ipv6);
        assert!(engine.route.intercept_dns);
        assert!(
            engine
                .route
                .exclude_ips
                .contains("203.0.113.10".parse().unwrap())
        );
        assert!(engine.network_reset.is_some());

        let dns = engine.dns.as_ref().expect("dns interceptor");
        assert!(dns.ipv4_only);
        assert_eq!(dns.cache_size, MOBILE_DNS_CACHE_SIZE);
        assert!(matches!(dns.upstream, DnsUpstream::Doh { .. }));
    }

    #[test]
    fn empty_doh_url_disables_the_dns_interceptor() {
        let cfg = AndroidEngineConfig {
            vless_uri: TEST_VLESS_URI.to_owned(),
            ..AndroidEngineConfig::default()
        };
        let engine = cfg.build_engine_config(None, None).expect("engine config");
        assert!(engine.dns.is_none());
        assert!(!engine.route.intercept_dns);
        assert!(engine.client.socket_protector.is_none());
    }

    #[test]
    fn bypass_cidrs_become_route_policy_entries() {
        let cfg = AndroidEngineConfig {
            vless_uri: TEST_VLESS_URI.to_owned(),
            bypass_cidrs: vec!["192.168.0.0/16".to_owned(), "fd00:be:a::/126".to_owned()],
            ..AndroidEngineConfig::default()
        };
        let engine = cfg.build_engine_config(None, None).expect("engine config");
        assert!(
            engine
                .route
                .bypass_cidrs
                .contains("192.168.1.1".parse().unwrap())
        );
        assert!(
            engine
                .route
                .bypass_cidrs
                .contains("fd00:be:a::2".parse().unwrap())
        );
        assert!(
            !engine
                .route
                .bypass_cidrs
                .contains("203.0.113.10".parse().unwrap())
        );
    }

    #[test]
    fn server_ip_skips_hostname_resolution() {
        let cfg = AndroidEngineConfig {
            vless_uri: TEST_VLESS_URI.replace("203.0.113.10", "server.invalid"),
            server_ip: Some("203.0.113.10".to_owned()),
            ..AndroidEngineConfig::default()
        };
        // `server.invalid` cannot resolve, so this only passes without a lookup.
        let engine = cfg.build_engine_config(None, None).expect("engine config");
        assert_eq!(
            engine.client.server_addr,
            "203.0.113.10:443".parse().unwrap()
        );
        assert!(
            engine
                .route
                .exclude_ips
                .contains("203.0.113.10".parse().unwrap())
        );
    }

    #[test]
    fn rejects_invalid_server_ip_without_echoing_it() {
        let cfg = AndroidEngineConfig {
            vless_uri: TEST_VLESS_URI.to_owned(),
            server_ip: Some("203.0.113.999".to_owned()),
            ..AndroidEngineConfig::default()
        };
        match cfg.build_engine_config(None, None) {
            Err(error @ ConfigError::Invalid(_)) => {
                assert!(!error.to_string().contains("203.0.113.999"), "{error}");
            }
            other => panic!("invalid server_ip must be rejected: {other:?}"),
        }
    }

    #[test]
    fn tcp_stack_keeps_the_configured_mtu() {
        let cfg = AndroidEngineConfig {
            mtu: 1280,
            ..AndroidEngineConfig::default()
        };
        let stack = cfg.tcp_stack_config();
        assert_eq!(stack.mtu, 1280);
        assert_eq!(
            stack.max_connections,
            TcpStackConfig::mobile().max_connections
        );
    }

    #[test]
    fn rejects_invalid_configuration() {
        let cases = [
            AndroidEngineConfig {
                mtu: 500,
                ..AndroidEngineConfig::default()
            },
            AndroidEngineConfig {
                tun_name: "tun/0".to_owned(),
                ..AndroidEngineConfig::default()
            },
            AndroidEngineConfig {
                tun_ipv4: "not-an-ip".to_owned(),
                ..AndroidEngineConfig::default()
            },
            AndroidEngineConfig {
                tun_dns_ipv4: String::new(),
                ..AndroidEngineConfig::default()
            },
            AndroidEngineConfig {
                log_level: "verbose!".to_owned(),
                ..AndroidEngineConfig::default()
            },
            AndroidEngineConfig {
                vless_uri: "vless://".to_owned(),
                ..AndroidEngineConfig::default()
            },
            AndroidEngineConfig {
                vless_uri: TEST_VLESS_URI.to_owned(),
                bypass_cidrs: vec!["10.0.0.0/33".to_owned()],
                ..AndroidEngineConfig::default()
            },
            AndroidEngineConfig {
                vless_uri: TEST_VLESS_URI.to_owned(),
                doh_url: "ftp://dns.example".to_owned(),
                ..AndroidEngineConfig::default()
            },
        ];
        for cfg in cases {
            assert!(
                cfg.build_engine_config(None, None).is_err(),
                "{cfg:?} must be rejected"
            );
        }
    }

    #[test]
    fn link_preview_reports_only_non_secret_fields() {
        let json = parse_vless_link_json(TEST_VLESS_URI);
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert_eq!(value["ok"], true);
        assert_eq!(value["name"], "beam");
        assert_eq!(value["server"], "203.0.113.10");
        assert_eq!(value["port"], 443);
        assert_eq!(value["sni"], "whatsapp.net");
        assert!(!json.contains("b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert!(!json.contains("WlpaWlpa"));
        assert!(!json.contains("vless://"));
    }

    #[test]
    fn link_preview_reports_rejection_without_the_link() {
        let json = parse_vless_link_json("vless://b831381d-6324-4d53-ad4f-8cda48b30811@:443");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert_eq!(value["ok"], false);
        assert!(value["error"].as_str().is_some_and(|text| !text.is_empty()));
        assert!(!json.contains("b831381d-6324-4d53-ad4f-8cda48b30811"));
    }
}
