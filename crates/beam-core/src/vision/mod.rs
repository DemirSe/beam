//! XTLS Vision block framing.
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

pub mod frame;

pub use frame::{
    BLOCK_HEADER_LEN, Block, Command, MAX_BLOCK_LEN, MAX_CONTENT_LEN, MAX_PAYLOAD_LEN, UUID_LEN,
    VisionError, encode_block, parse_block,
};
