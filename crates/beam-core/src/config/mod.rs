//! TOML configuration schema and validation.
//!
//! Configuration is loaded once at startup. Unknown fields are rejected, and
//! every value is validated before a [`Config`] is returned.

mod types;
mod validate;

pub use types::{
    Config, Flow, HostPort, LimitsConfig, LogConfig, LogLevel, RealityConfig, ServerConfig,
    UserConfig,
};
pub use validate::{ConfigError, ValidationError};
