//! Configuration loading and validation.
//!
//! Parsing is split into two stages: TOML is deserialized into private raw
//! types, then every value is validated before the public [`Config`] is
//! constructed. Errors never include secret values.

use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::types::{
    Config, Flow, HostPort, LimitsConfig, LogConfig, LogLevel, RawConfig, RawLimits, RealityConfig,
    ServerConfig, UserConfig,
};

const MAX_DNS_NAME_LEN: usize = 253;
const MAX_DNS_LABEL_LEN: usize = 63;

/// Errors produced while loading a configuration file.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("failed to read configuration file `{path}`: {source}")]
    Read {
        /// Path that could not be read.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file was not valid TOML or did not match the schema.
    ///
    /// Only a location and a generic schema message are kept. The parser's
    /// rendered message is intentionally discarded because type errors can
    /// include the offending value, and source lines can contain secrets.
    #[error("invalid TOML configuration: {message}")]
    Toml {
        /// Sanitized parser location/message.
        message: String,
    },
    /// The file was valid TOML but failed semantic validation.
    #[error("invalid configuration: {0}")]
    Validation(#[from] ValidationError),
}

/// Semantic validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    /// `server.listen` is not a socket address.
    #[error("server.listen must be an IP socket address written as `IP:PORT`")]
    Listen,
    /// `user.id` is not a UUID.
    #[error("user.id must be a valid UUID")]
    UserId,
    /// `user.flow` is not supported.
    #[error("user.flow must be `xtls-rprx-vision`")]
    Flow,
    /// `reality.private_key` is not a 32-byte base64url key.
    #[error("reality.private_key must be 32 bytes encoded as unpadded base64url")]
    PrivateKey,
    /// No short IDs were configured.
    #[error("reality.short_ids must not be empty")]
    ShortIdsEmpty,
    /// A `reality.short_ids` entry is malformed.
    #[error("reality.short_ids[{index}] must be 2 to 16 hexadecimal characters")]
    ShortId {
        /// Zero-based position of the invalid entry.
        index: usize,
    },
    /// No server names were configured.
    #[error("reality.server_names must not be empty")]
    ServerNamesEmpty,
    /// A `reality.server_names` entry is not a plausible DNS name.
    #[error("reality.server_names[{index}] is not a plausible DNS name")]
    ServerName {
        /// Zero-based position of the invalid entry.
        index: usize,
    },
    /// `reality.dest` is not a usable `host:port` pair.
    #[error("reality.dest must be host:port with a non-empty host and port 1..=65535")]
    Dest,
    /// `log.level` is unknown.
    #[error("log.level must be one of: error, warn, info, debug, trace")]
    LogLevel,
    /// A limit or timeout is zero.
    #[error("limits.{name} must be greater than zero")]
    ZeroLimit {
        /// Name of the invalid field.
        name: &'static str,
    },
    /// A limit is outside its supported range.
    #[error("limits.{name} must be at most {max}")]
    LimitTooLarge {
        /// Name of the invalid field.
        name: &'static str,
        /// Largest supported value.
        max: u32,
    },
    /// A limit is below its supported minimum.
    #[error("limits.{name} must be between {min} and {max}")]
    LimitOutOfRange {
        /// Name of the invalid field.
        name: &'static str,
        /// Smallest supported value.
        min: u32,
        /// Largest supported value.
        max: u32,
    },
}

impl Config {
    /// Parse and validate a configuration from a TOML string.
    pub fn from_toml_str(input: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(input).map_err(|error| ConfigError::Toml {
            message: sanitized_toml_error(&error, input),
        })?;
        Self::try_from(raw).map_err(ConfigError::Validation)
    }

    /// Read, parse, and validate a configuration file synchronously.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let contents = Zeroizing::new(contents);
        Self::from_toml_str(contents.as_str())
    }
}

impl FromStr for Config {
    type Err = ConfigError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_toml_str(input)
    }
}

/// Returns a location-only TOML error message.
///
/// `toml::de::Error::message()` is not safe to print for type mismatches: it
/// renders the offending value (for example a secret pasted into a numeric
/// field). The span gives operators enough information to find the typo
/// without copying source text into logs.
fn sanitized_toml_error(error: &toml::de::Error, input: &str) -> String {
    let Some(span) = error.span() else {
        return "TOML syntax or schema error".to_owned();
    };
    let offset = span.start.min(input.len());
    let prefix = &input[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(offset, |(_, tail)| tail.len())
        + 1;
    format!("TOML syntax or schema error at line {line}, column {column}")
}

impl TryFrom<RawConfig> for Config {
    type Error = ValidationError;

    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        let RawConfig {
            server,
            user,
            reality,
            log,
            limits,
        } = raw;

        let listen: SocketAddr = server.listen.parse().map_err(|_| ValidationError::Listen)?;
        if listen.port() == 0 {
            return Err(ValidationError::Listen);
        }
        let id = Uuid::parse_str(&user.id).map_err(|_| ValidationError::UserId)?;
        let flow = parse_flow(&user.flow)?;
        let private_key = decode_private_key(reality.private_key.as_str())?;
        let short_ids = validate_short_ids(reality.short_ids)?;
        let server_names = validate_server_names(reality.server_names)?;
        let dest = parse_dest(&reality.dest)?;
        let level = parse_log_level(&log.level)?;
        let limits = validate_limits(limits)?;

        Ok(Self {
            server: ServerConfig { listen },
            user: UserConfig { id, flow },
            reality: RealityConfig {
                private_key,
                short_ids,
                server_names,
                dest,
            },
            log: LogConfig { level },
            limits,
        })
    }
}

fn parse_flow(value: &str) -> Result<Flow, ValidationError> {
    match value {
        "xtls-rprx-vision" => Ok(Flow::XtlsRprxVision),
        _ => Err(ValidationError::Flow),
    }
}

fn decode_private_key(encoded: &str) -> Result<Zeroizing<[u8; 32]>, ValidationError> {
    if encoded.contains('=') {
        return Err(ValidationError::PrivateKey);
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ValidationError::PrivateKey)?;
    let decoded = Zeroizing::new(decoded);
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| ValidationError::PrivateKey)?;

    Ok(Zeroizing::new(key))
}

fn validate_short_ids(short_ids: Vec<String>) -> Result<Vec<String>, ValidationError> {
    if short_ids.is_empty() {
        return Err(ValidationError::ShortIdsEmpty);
    }

    for (index, short_id) in short_ids.iter().enumerate() {
        let length_ok = (2..=16).contains(&short_id.len()) && short_id.len().is_multiple_of(2);
        let hex_ok = short_id.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !length_ok || !hex_ok {
            return Err(ValidationError::ShortId { index });
        }
    }

    Ok(short_ids)
}

fn validate_server_names(server_names: Vec<String>) -> Result<Vec<String>, ValidationError> {
    if server_names.is_empty() {
        return Err(ValidationError::ServerNamesEmpty);
    }

    for (index, name) in server_names.iter().enumerate() {
        if !is_plausible_dns_name(name) {
            return Err(ValidationError::ServerName { index });
        }
    }

    Ok(server_names)
}

fn is_plausible_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_DNS_NAME_LEN {
        return false;
    }

    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_DNS_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn parse_dest(value: &str) -> Result<HostPort, ValidationError> {
    let (host, port, bracketed) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or(ValidationError::Dest)?;
        let port = rest.strip_prefix(':').ok_or(ValidationError::Dest)?;
        (host, port, true)
    } else {
        let (host, port) = value.rsplit_once(':').ok_or(ValidationError::Dest)?;
        if host.contains(':') {
            return Err(ValidationError::Dest);
        }
        (host, port, false)
    };

    if host.is_empty()
        || host
            .chars()
            .any(|character| character.is_ascii_whitespace() || character.is_ascii_control())
    {
        return Err(ValidationError::Dest);
    }

    if bracketed && host.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(ValidationError::Dest);
    }

    let port: u16 = port.parse().map_err(|_| ValidationError::Dest)?;
    if port == 0 {
        return Err(ValidationError::Dest);
    }

    Ok(HostPort {
        host: host.to_owned(),
        port,
    })
}

fn parse_log_level(value: &str) -> Result<LogLevel, ValidationError> {
    match value {
        "error" => Ok(LogLevel::Error),
        "warn" => Ok(LogLevel::Warn),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        "trace" => Ok(LogLevel::Trace),
        _ => Err(ValidationError::LogLevel),
    }
}

fn validate_limits(raw: RawLimits) -> Result<LimitsConfig, ValidationError> {
    if raw.max_connections == 0 {
        return Err(ValidationError::ZeroLimit {
            name: "max_connections",
        });
    }
    if raw.max_connections > 65_536 {
        return Err(ValidationError::LimitTooLarge {
            name: "max_connections",
            max: 65_536,
        });
    }
    if raw.max_udp_destinations == 0 {
        return Err(ValidationError::ZeroLimit {
            name: "max_udp_destinations",
        });
    }
    if raw.max_udp_destinations > 65_536 {
        return Err(ValidationError::LimitTooLarge {
            name: "max_udp_destinations",
            max: 65_536,
        });
    }
    if raw.max_preauth_per_ip == 0 {
        return Err(ValidationError::ZeroLimit {
            name: "max_preauth_per_ip",
        });
    }
    if raw.max_preauth_per_ip > 65_536 {
        return Err(ValidationError::LimitTooLarge {
            name: "max_preauth_per_ip",
            max: 65_536,
        });
    }
    if raw.max_xudp_sessions == 0 {
        return Err(ValidationError::ZeroLimit {
            name: "max_xudp_sessions",
        });
    }
    if raw.max_xudp_sessions > 65_536 {
        return Err(ValidationError::LimitTooLarge {
            name: "max_xudp_sessions",
            max: 65_536,
        });
    }
    if !(16 * 1024..=4 * 1024 * 1024).contains(&raw.xudp_recv_buffer_bytes) {
        return Err(ValidationError::LimitOutOfRange {
            name: "xudp_recv_buffer_bytes",
            min: 16 * 1024,
            max: 4 * 1024 * 1024,
        });
    }
    if raw.listen_backlog == 0 {
        return Err(ValidationError::ZeroLimit {
            name: "listen_backlog",
        });
    }
    if raw.listen_backlog > u32::from(u16::MAX) {
        return Err(ValidationError::LimitTooLarge {
            name: "listen_backlog",
            max: u32::from(u16::MAX),
        });
    }
    if raw.shutdown_drain_ms == 0 {
        return Err(ValidationError::ZeroLimit {
            name: "shutdown_drain_ms",
        });
    }
    if raw.shutdown_drain_ms > 3_000 {
        return Err(ValidationError::LimitTooLarge {
            name: "shutdown_drain_ms",
            max: 3_000,
        });
    }
    if raw.handshake_timeout_ms == 0 {
        return Err(ValidationError::ZeroLimit {
            name: "handshake_timeout_ms",
        });
    }
    if raw.idle_timeout_ms == 0 {
        return Err(ValidationError::ZeroLimit {
            name: "idle_timeout_ms",
        });
    }

    Ok(LimitsConfig {
        max_connections: raw.max_connections,
        max_udp_destinations: raw.max_udp_destinations,
        max_preauth_per_ip: raw.max_preauth_per_ip,
        max_xudp_sessions: raw.max_xudp_sessions,
        xudp_recv_buffer_bytes: raw.xudp_recv_buffer_bytes,
        listen_backlog: raw.listen_backlog,
        shutdown_drain_ms: raw.shutdown_drain_ms,
        handshake_timeout_ms: raw.handshake_timeout_ms,
        idle_timeout_ms: raw.idle_timeout_ms,
    })
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    fn private_key() -> String {
        URL_SAFE_NO_PAD.encode([0x5a_u8; 32])
    }

    fn config_toml(private_key: &str) -> String {
        format!(
            r#"
[server]
listen = "127.0.0.1:443"

[user]
id = "00000000-0000-0000-0000-000000000000"
flow = "xtls-rprx-vision"

[reality]
private_key = "{private_key}"
short_ids = ["0123456789abcdef"]
server_names = ["whatsapp.net"]
dest = "whatsapp.net:443"

[log]
level = "warn"

[limits]
max_connections = 1024
max_udp_destinations = 2048
max_preauth_per_ip = 128
max_xudp_sessions = 256
listen_backlog = 1024
shutdown_drain_ms = 2000
handshake_timeout_ms = 60000
idle_timeout_ms = 300000
"#
        )
    }

    fn valid_config() -> Config {
        Config::from_toml_str(&config_toml(&private_key())).expect("test config must be valid")
    }

    #[test]
    fn parses_valid_config() {
        let config = valid_config();

        assert_eq!(config.server.listen, "127.0.0.1:443".parse().unwrap());
        assert_eq!(config.user.id, Uuid::nil());
        assert_eq!(config.user.flow, Flow::XtlsRprxVision);
        assert_eq!(&*config.reality.private_key, &[0x5a_u8; 32]);
        assert_eq!(config.reality.short_ids, vec!["0123456789abcdef"]);
        assert_eq!(config.reality.server_names, vec!["whatsapp.net"]);
        assert_eq!(config.reality.dest.host, "whatsapp.net");
        assert_eq!(config.reality.dest.port, 443);
        assert_eq!(config.log.level, LogLevel::Warn);
        assert_eq!(config.limits.max_connections, 1024);
        assert_eq!(config.limits.max_udp_destinations, 2048);
        assert_eq!(config.limits.max_preauth_per_ip, 128);
        assert_eq!(config.limits.max_xudp_sessions, 256);
        assert_eq!(config.limits.listen_backlog, 1024);
        assert_eq!(config.limits.shutdown_drain_ms, 2_000);
        assert_eq!(config.limits.handshake_timeout_ms, 60_000);
        assert_eq!(config.limits.idle_timeout_ms, 300_000);
    }

    #[test]
    fn supports_from_str_and_path_loading() {
        let parsed: Config = config_toml(&private_key()).parse().unwrap();
        assert_eq!(parsed, valid_config());

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("beam.toml");
        std::fs::write(&path, config_toml(&private_key())).unwrap();

        let loaded = Config::from_path(&path).unwrap();
        assert_eq!(loaded, valid_config());
    }

    #[test]
    fn rejects_unknown_fields() {
        let key = private_key();
        let nested = config_toml(&key).replace(
            "[server]\nlisten = \"127.0.0.1:443\"",
            "[server]\nlisten = \"127.0.0.1:443\"\nunexpected = true",
        );
        let error = Config::from_toml_str(&nested).unwrap_err();
        assert!(matches!(error, ConfigError::Toml { .. }), "{error}");

        let top_level = format!("{}\n[unexpected]\nvalue = true\n", config_toml(&key));
        let error = Config::from_toml_str(&top_level).unwrap_err();
        assert!(matches!(error, ConfigError::Toml { .. }), "{error}");
    }

    #[test]
    fn rejects_wrong_types_without_leaking_values() {
        const CANARY: &str = "SUPERSECRET-CANARY-0123456789";
        let key = private_key();
        let replacements = [
            (
                "max_connections = 1024",
                format!("max_connections = \"{CANARY}\""),
            ),
            (
                "max_udp_destinations = 2048",
                format!("max_udp_destinations = \"{CANARY}\""),
            ),
            (
                "max_preauth_per_ip = 128",
                format!("max_preauth_per_ip = \"{CANARY}\""),
            ),
            (
                "max_xudp_sessions = 256",
                format!("max_xudp_sessions = \"{CANARY}\""),
            ),
            (
                "listen_backlog = 1024",
                format!("listen_backlog = \"{CANARY}\""),
            ),
            (
                "shutdown_drain_ms = 2000",
                format!("shutdown_drain_ms = \"{CANARY}\""),
            ),
            (
                "handshake_timeout_ms = 60000",
                format!("handshake_timeout_ms = \"{CANARY}\""),
            ),
            (
                "idle_timeout_ms = 300000",
                format!("idle_timeout_ms = \"{CANARY}\""),
            ),
            (
                "listen = \"127.0.0.1:443\"",
                format!("listen = [\"{CANARY}\"]"),
            ),
            (
                "id = \"00000000-0000-0000-0000-000000000000\"",
                format!("id = [\"{CANARY}\"]"),
            ),
            (
                "short_ids = [\"0123456789abcdef\"]",
                format!("short_ids = \"{CANARY}\""),
            ),
            (
                "server_names = [\"whatsapp.net\"]",
                format!("server_names = \"{CANARY}\""),
            ),
            (
                "dest = \"whatsapp.net:443\"",
                format!("dest = [\"{CANARY}\"]"),
            ),
            ("level = \"warn\"", format!("level = [\"{CANARY}\"]")),
        ];
        for (old, new) in replacements {
            let input = config_toml(&key).replace(old, &new);
            assert_ne!(
                input,
                config_toml(&key),
                "replacement for {old:?} did not apply"
            );
            let error = Config::from_toml_str(&input).unwrap_err();
            assert!(matches!(error, ConfigError::Toml { .. }), "{error}");
            assert!(!error.to_string().contains(CANARY), "{error}");
        }
    }

    #[test]
    fn rejects_port_zero_listener() {
        let input = config_toml(&private_key())
            .replace("listen = \"127.0.0.1:443\"", "listen = \"127.0.0.1:0\"");
        let error = Config::from_toml_str(&input).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::Listen)
        ));
    }

    #[test]
    fn rejects_invalid_uuid() {
        let input = config_toml(&private_key()).replace(
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-0000-0000",
        );
        let error = Config::from_toml_str(&input).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::UserId)
        ));
    }

    #[test]
    fn rejects_wrong_key_length_without_leaking_it() {
        let key = URL_SAFE_NO_PAD.encode([0x11_u8; 31]);
        let error = Config::from_toml_str(&config_toml(&key)).unwrap_err();

        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::PrivateKey)
        ));
        assert!(!error.to_string().contains(&key), "{error}");
    }

    #[test]
    fn rejects_invalid_base64_without_leaking_it() {
        let key = "not_base64!";
        let error = Config::from_toml_str(&config_toml(key)).unwrap_err();

        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::PrivateKey)
        ));
        assert!(!error.to_string().contains(key), "{error}");
    }

    #[test]
    fn rejects_empty_short_ids() {
        let input = config_toml(&private_key())
            .replace("short_ids = [\"0123456789abcdef\"]", "short_ids = []");
        let error = Config::from_toml_str(&input).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::ShortIdsEmpty)
        ));
    }

    #[test]
    fn rejects_bad_short_ids() {
        let key = private_key();
        for short_id in ["0", "zz", "123", "0123456789abcdef00"] {
            let input =
                config_toml(&key).replace("\"0123456789abcdef\"", &format!("\"{short_id}\""));
            let error = Config::from_toml_str(&input).unwrap_err();
            assert!(
                matches!(
                    error,
                    ConfigError::Validation(ValidationError::ShortId { index: 0 })
                ),
                "short id {short_id:?} was accepted"
            );
        }
    }

    #[test]
    fn rejects_empty_server_names() {
        let input = config_toml(&private_key())
            .replace("server_names = [\"whatsapp.net\"]", "server_names = []");
        let error = Config::from_toml_str(&input).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::ServerNamesEmpty)
        ));
    }

    #[test]
    fn rejects_implausible_server_names() {
        let input = config_toml(&private_key()).replace(
            "server_names = [\"whatsapp.net\"]",
            "server_names = [\"bad..example\"]",
        );
        let error = Config::from_toml_str(&input).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::ServerName { index: 0 })
        ));
    }

    #[test]
    fn rejects_bad_destinations() {
        let key = private_key();
        for dest in [
            "whatsapp.net",
            "whatsapp.net:0",
            "whatsapp.net:65536",
            ":443",
            "[::1:443",
        ] {
            let input = config_toml(&key)
                .replace("dest = \"whatsapp.net:443\"", &format!("dest = \"{dest}\""));
            let error = Config::from_toml_str(&input).unwrap_err();
            assert!(
                matches!(error, ConfigError::Validation(ValidationError::Dest)),
                "destination {dest:?} was accepted"
            );
        }
    }

    #[test]
    fn accepts_bracketed_ipv6_destination() {
        let input = config_toml(&private_key()).replace(
            "dest = \"whatsapp.net:443\"",
            "dest = \"[2001:db8::1]:443\"",
        );
        let config = Config::from_toml_str(&input).unwrap();
        assert_eq!(config.reality.dest.host, "2001:db8::1");
        assert_eq!(config.reality.dest.port, 443);
        assert_eq!(config.reality.dest.to_string(), "[2001:db8::1]:443");
    }

    #[test]
    fn rejects_zero_limits() {
        let key = private_key();
        for (name, value) in [
            ("max_connections", "1024"),
            ("max_udp_destinations", "2048"),
            ("max_preauth_per_ip", "128"),
            ("max_xudp_sessions", "256"),
            ("listen_backlog", "1024"),
            ("shutdown_drain_ms", "2000"),
            ("handshake_timeout_ms", "60000"),
            ("idle_timeout_ms", "300000"),
        ] {
            let input =
                config_toml(&key).replace(&format!("{name} = {value}"), &format!("{name} = 0"));
            let error = Config::from_toml_str(&input).unwrap_err();
            match error {
                ConfigError::Validation(ValidationError::ZeroLimit { name: got }) => {
                    assert_eq!(got, name);
                }
                other => panic!("unexpected error for {name}: {other}"),
            }
        }
    }

    #[test]
    fn rejects_an_oversized_listen_backlog() {
        let input =
            config_toml(&private_key()).replace("listen_backlog = 1024", "listen_backlog = 65536");
        let error = Config::from_toml_str(&input).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::LimitTooLarge {
                name: "listen_backlog",
                max: 65535
            })
        ));
    }

    #[test]
    fn debug_redacts_secrets() {
        let key = private_key();
        let config = Config::from_toml_str(&config_toml(&key)).unwrap();
        let debug = format!("{config:?}");

        assert!(!debug.contains(&key), "{debug}");
        assert!(
            !debug.contains("00000000-0000-0000-0000-000000000000"),
            "{debug}"
        );
        assert!(!debug.contains("0123456789abcdef"), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");
    }
}
