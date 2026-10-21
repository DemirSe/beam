//! XUDP mux framing used for UDP over a VLESS stream.
//!
//! XUDP carries one frame per mux chunk. A frame is decoded with
//! [`parse_frame`] and replies are encoded with [`encode_frame`]. Parsing is
//! stateless: a relay keeps a byte buffer, consumes every complete frame, and
//! retains the remainder for the next read.
//!
//! Metadata is capped at [`MAX_METADATA_LEN`] bytes and payloads at
//! [`MAX_PAYLOAD_LEN`] bytes. Unknown option bits and trailing metadata padding
//! are preserved or ignored as appropriate; the encoder writes neither padding
//! nor unknown option bits of its own.

pub mod frame;

pub use frame::{
    Frame, FrameOption, FrameSpec, GLOBAL_ID_LEN, MAX_METADATA_LEN, MAX_PAYLOAD_LEN,
    METADATA_PREFIX_LEN, MIN_METADATA_LEN, SessionStatus, TargetNetwork, XudpError, encode_frame,
    parse_frame,
};
