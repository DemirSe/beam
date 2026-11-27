#![forbid(unsafe_code)]

//! Core protocol and server logic for beam.

pub mod address;
pub mod admission;
pub mod client;
pub mod config;
pub mod dns;
pub mod identity;
pub mod metrics;
pub mod prepend_stream;
pub mod reality;
// `relay` is the server-side `splice(2)`/`io_uring` copy path (Linux/Android only).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod relay;
pub mod tls;
pub mod udp;
pub mod vision;
pub mod vless;
pub mod xudp;
