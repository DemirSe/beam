//! XUDP mux framing and UDP relay used for UDP over a VLESS stream.
//!
//! XUDP carries one frame per mux chunk. A frame is decoded with
//! [`parse_frame`] and replies are encoded with [`encode_frame`]. Parsing is
//! stateless: a relay keeps a byte buffer, consumes every complete frame, and
//! retains the remainder for the next read.
//!
//! [`handle_mux_stream`] is the session layer. It creates one unconnected
//! [`tokio::net::UdpSocket`] per session, relays datagrams with `send_to`, and
//! stamps every reply with the actual source address. One writer task
//! serializes frames from all reply tasks behind a bounded queue.
//!
//! Metadata is capped at [`MAX_METADATA_LEN`] bytes and payloads at
//! [`MAX_PAYLOAD_LEN`] bytes. Unknown option bits and trailing metadata padding
//! are preserved or ignored as appropriate; the encoder writes neither padding
//! nor unknown option bits of its own.
//!
//! # Scope and trade-offs
//!
//! - A UDP socket is unconnected and has no source allowlist. Any sender can
//!   deliver a datagram to the session socket and have its source forwarded,
//!   matching stock Xray. A future option could restrict replies to contacted
//!   destinations, but v1 deliberately does not.
//! - A GlobalID is accepted and stored, and a cleanly closed session keeps its
//!   socket for [`XudpConfig::close_expiry`] so a later `New` in the *same mux
//!   stream* can reattach. The table is not shared between mux streams, so
//!   cross-connection (full-cone) continuity is out of scope for v1.
//! - A `New` for a non-UDP network is rejected with `End + Error`; this module
//!   only implements the UDP relay that XUDP clients use.
//! - Domain destinations are resolved on every frame. Stock Xray caches the
//!   address for an outbound domain; the wire behavior is the same, but the
//!   cache is a future optimization.
//! - The handler is used by `crate::tls::server` for VLESS `Command::Mux`. It
//!   accepts any `AsyncRead + AsyncWrite + Unpin + Send + 'static`, which lets
//!   the TLS adapter pass a Vision-decoded or prefix-replayed VLESS body.

pub mod frame;
mod server;
mod session;

pub use frame::{
    Frame, FrameOption, FrameSpec, GLOBAL_ID_LEN, MAX_METADATA_LEN, MAX_PAYLOAD_LEN,
    METADATA_PREFIX_LEN, MIN_METADATA_LEN, SessionStatus, TargetNetwork, XudpError, encode_frame,
    parse_frame,
};
pub use server::{MuxError, handle_mux_stream};
pub use session::{DEFAULT_MAX_GLOBAL_SESSIONS, XudpConfig, XudpConfigError, XudpSessionLimiter};
