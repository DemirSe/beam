//! Zero-copy relay between two connected streams.
//!
//! [`copy_one_way`] moves bytes with `splice(2)` through a single pipe. The
//! descriptors are borrowed, connected nonblocking stream sockets. A shared
//! [`RelayActivity`] clock coordinates the idle deadline with the other direction.
//!
//! The loop bounds work per round and polls the source, pipe and sink as needed.
//! After EOF it drains buffered bytes and shuts down the sink's write half.
//!
//! Timeouts:
//!
//! - [`RelayConfig::idle_timeout`] bounds inactivity while the source is open.
//! - [`RelayConfig::shutdown_timeout`] bounds inactivity after the source
//!   closes or after [`RelayConfig::max_bytes`] is reached. A direction
//!   that is still moving bytes is not interrupted.
//!
//! Errors are returned to the caller; the descriptors remain owned by the
//! caller.

mod splice_copy;

pub use splice_copy::{
    DEFAULT_PIPE_SIZE, MAX_PIPE_SIZE, MIN_PIPE_SIZE, RelayActivity, RelayConfig, RelayStats,
    copy_one_way, pipe_size_for_budget,
};
