//! Legacy VLESS UDP (`Command::Udp`) and packetaddr.
//!
//! A legacy UDP request fixes one destination in the VLESS request header and
//! frames the body as `length(2 BE) | payload` in both directions. When the
//! destination is the sing-box magic FQDN
//! [`PACKETADDR_MAGIC_DOMAIN`](legacy::PACKETADDR_MAGIC_DOMAIN), every body
//! datagram instead starts with an inner IPv4 or IPv6 address. The relay lives
//! in [`legacy`].

pub mod legacy;

pub use legacy::{
    DEFAULT_IDLE_TIMEOUT, DEFAULT_IO_TIMEOUT, DEFAULT_MAX_DATAGRAM_SIZE,
    DEFAULT_MAX_PACKETADDR_DESTINATIONS, LegacyUdpConfig, LegacyUdpConfigError, MAX_DATAGRAM_SIZE,
    PACKETADDR_MAGIC_DOMAIN, UdpError, handle_udp_stream, is_packetaddr_destination,
};
