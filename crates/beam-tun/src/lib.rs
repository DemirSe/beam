#![forbid(unsafe_code)]

//! Platform-independent TUN packet engine for `beam-client`.
//!
//! Translates raw Layer 3 IPv4/IPv6 packets from a [`device::TunDevice`] into:
//! - TCP streams through a pluggable [`stack::NetStack`] (default:
//!   [`proxy_tcp::ProxyTcpStack`], RFC 7323 Window Scaling, zero external TCP
//!   stack dependencies), relayed over `beam_core::client::dial_tcp`.
//! - UDP datagrams through [`udp::UdpNatBridge`], relayed directly over
//!   `beam_core::client::XudpClient` (full-cone, non-blocking reconnect).
//! - Immediate ICMP/ICMPv6 Port Unreachable replies for UDP/443 when
//!   `reject_quic` is enabled.

pub mod device;
pub mod dns;
pub mod engine;
pub mod packet;
pub mod proxy_tcp;
pub mod router;
pub mod stack;
pub mod udp;

pub use device::{MemoryTun, TunDevice};
pub use dns::{DnsConfig, DnsInterceptor, DnsUpstream};
pub use engine::{
    EngineError, TunEngineConfig, TunnelActivity, run_tun_engine, run_tun_engine_with_activity,
};
pub use proxy_tcp::ProxyTcpStack;
pub use router::{IpNet, RouteDecision, RoutePolicy};
pub use stack::{AcceptedTcpStream, NetStack, TcpStackConfig, TunTcpStream};
pub use udp::{UdpBridgeConfig, UdpNatBridge};
