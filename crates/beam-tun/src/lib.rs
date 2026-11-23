#![forbid(unsafe_code)]

//! Platform-independent TUN packet engine for `beam-client`.
//!
//! Translates raw Layer 3 IPv4 packets from a [`device::TunDevice`] into:
//! - TCP streams through a pluggable [`stack::NetStack`] (Phase 1: `smoltcp`,
//!   Phase 2: optional custom lightweight proxy TCP/IP stack), relayed over
//!   `beam_core::client::dial_tcp` (REALITY + VLESS + Vision).
//! - UDP datagrams through [`udp::UdpNatBridge`], relayed directly over
//!   `beam_core::client::XudpClient` (full-cone).
//! - Immediate ICMP Port Unreachable replies for UDP/443 when `reject_quic`
//!   is enabled.

pub mod device;
pub mod engine;
pub mod packet;
pub mod proxy_tcp;
pub mod router;
pub mod stack;
pub mod udp;

pub use device::{MemoryTun, TunDevice};
pub use engine::{EngineError, TunEngineConfig, run_tun_engine};
pub use proxy_tcp::ProxyTcpStack;
pub use router::{RouteDecision, RoutePolicy};
pub use stack::{AcceptedTcpStream, NetStack, TcpStackConfig, TunTcpStream};
pub use udp::{UdpBridgeConfig, UdpNatBridge};
