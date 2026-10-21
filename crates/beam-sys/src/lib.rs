#![allow(unsafe_code)]

//! Isolated Linux syscall layer for beam.
//!
//! Every `unsafe` block in this crate must carry a safety comment that
//! explains the invariants the caller must uphold.
