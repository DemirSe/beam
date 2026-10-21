//! REALITY server-side authentication.
//!
//! REALITY carries its authentication envelope in the 32-byte TLS 1.3
//! `legacy_session_id`. This module verifies that envelope and returns the
//! derived authentication key needed for the server flight.

pub mod auth;

pub use auth::{Auth, AuthError, RealityAuthConfig, authenticate};
