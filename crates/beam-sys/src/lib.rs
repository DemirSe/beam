#![allow(unsafe_code)]

//! Isolated Linux syscall layer for beam.
//!
//! Every `unsafe` block in this crate must carry a safety comment that
//! explains the invariants the caller must uphold.

pub mod fd;
pub mod socket;
pub mod splice;

pub use fd::{set_cloexec, set_nonblocking};
pub use socket::{set_reuse_addr, set_tcp_keepalive, set_tcp_nodelay};
pub use splice::{SpliceFlags, pipe, splice};
