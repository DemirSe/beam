#![forbid(unsafe_code)]

//! Core protocol and server logic for beam.

pub mod address;
pub mod admission;
pub mod config;
pub mod metrics;
pub mod prepend_stream;
pub mod reality;
pub mod relay;
pub mod tls;
pub mod udp;
pub mod vision;
pub mod vless;
pub mod xudp;
