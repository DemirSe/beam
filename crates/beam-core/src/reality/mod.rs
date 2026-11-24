//! REALITY server-side authentication and client-side handshake builder.
//!
//! REALITY carries its authentication envelope in the 32-byte TLS 1.3
//! `legacy_session_id`. This module provides both server-side verification
//! ([`auth`]) and client-side envelope sealing + temporary certificate
//! verification ([`client`]).

pub mod auth;
pub mod client;

pub use auth::{Auth, AuthError, RealityAuthConfig, authenticate};
#[cfg(feature = "fuzz")]
pub use client::fuzz_extract_ed25519_cert_fields;
pub use client::{
    RealityClientConfig, RealityClientError, build_client_connection, build_client_connection_at,
};
