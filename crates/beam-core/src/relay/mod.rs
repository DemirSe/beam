//! Zero-copy relay between two connected streams.
//!
//! [`copy_bidirectional`] moves bytes with `splice(2)` through one pipe per
//! direction. Both descriptors must be connected, nonblocking stream sockets
//! (TCP or Unix). The function does not take ownership of them and leaves them
//! open on return.
//!
//! The loop watches source readability, pipe writability when a pipe is full,
//! and sink writability when a pipe holds bytes. It does not poll pipe
//! readability: the relay tracks the bytes it has buffered, and polling a pipe
//! that already holds data would spin while the sink is blocked. Work is
//! bounded per round so one direction cannot starve the other. When a source
//! reaches EOF the destination's write half is shut down and the other
//! direction keeps running.
//!
//! Timeouts:
//!
//! - [`RelayConfig::idle_timeout`] bounds inactivity while both directions are
//!   still open.
//! - [`RelayConfig::shutdown_timeout`] bounds inactivity after the first
//!   half-close or after [`RelayConfig::max_bytes`] is reached. A direction
//!   that is still moving bytes is not interrupted.
//!
//! Errors are returned to the caller; the descriptors remain owned by the
//! caller.

mod splice_copy;

pub use splice_copy::{
    DEFAULT_PIPE_SIZE, MAX_PIPE_SIZE, MIN_PIPE_SIZE, RelayConfig, RelayStats, copy_bidirectional,
};
