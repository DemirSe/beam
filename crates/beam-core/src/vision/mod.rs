//! XTLS Vision block framing and padding state.
//!
//! Vision wraps each VLESS body chunk in a block:
//!
//! ```text
//! [UUID(16) first block only] | command(1) | content_len(2 BE) |
//! padding_len(2 BE) | content | zero padding
//! ```
//!
//! The VLESS request/response header is outside this framing. Parsing is
//! stateless so a relay can keep a buffer, parse every complete block it holds,
//! and retain the remainder for the next read.
//!
//! Pass `first = true` only for the first block of a direction, and only after
//! the caller has verified the raw 16-byte UUID prefix described in
//! `docs/08-vision-xudp-spec.md` section 2.1. Later blocks never carry a UUID;
//! treating their leading bytes as one would consume content.
//!
//! [`frame`] is the stateless codec. [`state`] holds the per-connection TLS
//! detector, padding policy, writer plans, and reader transitions.

pub mod frame;
pub mod state;
pub mod stream;

pub use frame::{
    BLOCK_HEADER_LEN, Block, Command, MAX_BLOCK_LEN, MAX_CONTENT_LEN, MAX_PAYLOAD_LEN, UUID_LEN,
    VisionError, encode_block, parse_block,
};
pub use state::{
    DEFAULT_FILTER_BUDGET, PaddingPolicy, TlsDetector, TlsObservation, VisionBlockPlan,
    VisionReaderAction, VisionReaderMode, VisionReaderState, VisionStateError, VisionWritePlan,
    VisionWriterState,
};
pub use stream::VisionStream;
