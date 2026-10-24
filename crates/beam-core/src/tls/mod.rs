//! TLS wire-format parsing used by the REALITY handshake.
//!
//! The parser here is deliberately strict about record and handshake framing
//! and bounded in every dimension, but it does not authenticate or emit
//! anything. REALITY decides what to do with a parsed ClientHello.

pub mod client_hello;
pub mod server;
pub mod stream;

pub use client_hello::{
    Alpn, AlpnIter, ClientHello, ClientHelloError, Extension, ExtensionIter, KeyShareEntry,
    KeyShareGroups, KeyShares, MAX_ALPN_PROTOCOLS, MAX_CIPHER_SUITES, MAX_CLIENT_HELLO_LEN,
    MAX_EXTENSIONS, MAX_KEY_SHARE_ENTRIES, MAX_RECORD_LEN, MAX_SESSION_ID_LEN,
    TLS_HANDSHAKE_HEADER_LEN, TLS_RECORD_HEADER_LEN, TLS13_VERSION, U16List, U16ListIter,
};
pub use server::{
    ConnectionOutcome, ReplayStream, TlsServerConfig, TlsServerError, handle_connection,
    handle_connection_admitted,
};
pub use stream::{RawTls, RawTlsHandoff, TlsStream, TlsStreamError};
