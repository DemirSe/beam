//! Configuration value types.
//!
//! The raw types in this module mirror the TOML schema and are private to the
//! crate. Public types only exist after validation has succeeded.

use std::fmt;
use std::net::SocketAddr;

use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Validated beam configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Listener configuration.
    pub server: ServerConfig,
    /// The single VLESS user.
    pub user: UserConfig,
    /// REALITY authentication material and cover destination.
    pub reality: RealityConfig,
    /// Logging configuration.
    pub log: LogConfig,
    /// Resource limits and timeouts.
    pub limits: LimitsConfig,
}

/// Listener configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// Address the server binds and listens on.
    pub listen: SocketAddr,
}

/// The single configured VLESS user.
#[derive(Clone, PartialEq, Eq)]
pub struct UserConfig {
    /// User UUID. Redacted in `Debug` output.
    pub id: Uuid,
    /// VLESS flow.
    pub flow: Flow,
}

impl fmt::Debug for UserConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserConfig")
            .field("id", &Redacted)
            .field("flow", &self.flow)
            .finish()
    }
}

/// Supported VLESS flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// XTLS Vision.
    XtlsRprxVision,
}

impl Flow {
    /// The value used on the wire and in the configuration file.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XtlsRprxVision => "xtls-rprx-vision",
        }
    }
}

impl fmt::Display for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// REALITY configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct RealityConfig {
    /// X25519 private key. Redacted in `Debug` output and zeroized on drop.
    pub private_key: Zeroizing<[u8; 32]>,
    /// Accepted short IDs as lowercase or uppercase hexadecimal strings.
    pub short_ids: Vec<String>,
    /// Accepted SNI values.
    pub server_names: Vec<String>,
    /// Cover destination.
    pub dest: HostPort,
}

impl fmt::Debug for RealityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityConfig")
            .field("private_key", &Redacted)
            .field("short_ids", &RedactedList(self.short_ids.len()))
            .field("server_names", &self.server_names)
            .field("dest", &self.dest)
            .finish()
    }
}

/// A validated host and port pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    /// Host name or IP literal. IPv6 literals are stored without brackets.
    pub host: String,
    /// Port in the range `1..=65535`.
    pub port: u16,
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    /// Maximum log level.
    pub level: LogLevel,
}

/// Supported log levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Errors and warnings.
    Warn,
    /// Errors, warnings, and informational messages.
    Info,
    /// Debug diagnostics.
    Debug,
    /// Full trace diagnostics.
    Trace,
}

impl LogLevel {
    /// The value used in the configuration file.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resource limits and timeouts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitsConfig {
    /// Maximum concurrent connections.
    pub max_connections: u32,
    /// Maximum concurrent UDP destinations.
    pub max_udp_destinations: u32,
    /// Handshake timeout in milliseconds.
    pub handshake_timeout_ms: u64,
    /// Idle timeout in milliseconds.
    pub idle_timeout_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawConfig {
    pub(crate) server: RawServer,
    pub(crate) user: RawUser,
    pub(crate) reality: RawReality,
    pub(crate) log: RawLog,
    pub(crate) limits: RawLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawServer {
    pub(crate) listen: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawUser {
    pub(crate) id: String,
    pub(crate) flow: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawReality {
    #[serde(deserialize_with = "deserialize_secret")]
    pub(crate) private_key: Zeroizing<String>,
    pub(crate) short_ids: Vec<String>,
    pub(crate) server_names: Vec<String>,
    pub(crate) dest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLog {
    pub(crate) level: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLimits {
    pub(crate) max_connections: u32,
    pub(crate) max_udp_destinations: u32,
    pub(crate) handshake_timeout_ms: u64,
    pub(crate) idle_timeout_ms: u64,
}

fn deserialize_secret<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

struct RedactedList(usize);

impl fmt::Debug for RedactedList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted; {} entries>", self.0)
    }
}
