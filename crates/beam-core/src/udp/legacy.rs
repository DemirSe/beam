//! Legacy VLESS UDP relay and packetaddr sessions.
//!
//! A VLESS `Command::Udp` request fixes one destination in the request header.
//! Its body is a sequence of `length(2 BE) | payload` datagrams in both
//! directions. [`handle_udp_stream`] binds one unconnected UDP socket in the
//! destination family, sends every request with `send_to`, and frames every
//! reply with its two-byte length.
//!
//! When the header destination is [`PACKETADDR_MAGIC_DOMAIN`], one connection
//! is a multi-destination packetaddr session. Each datagram starts with an
//! inner address:
//!
//! ```text
//! ATYP(1) | address | port(2 BE) | payload
//! ```
//!
//! `ATYP 1` is IPv4 and `ATYP 2` is IPv6. Domain names are not part of the
//! packetaddr format. Replies are stamped with the actual `recv_from` source
//! in the same format.
//!
//! # Limits and socket model
//!
//! - A decoded datagram payload is capped by
//!   [`LegacyUdpConfig::max_datagram_size`] and by the largest length that
//!   stock legacy framing can emit (`8190` bytes). A larger declared length is
//!   a protocol error and closes the connection.
//! - A packetaddr connection may contact many inner destinations. The distinct
//!   destinations are remembered in a bounded table so the session cannot be
//!   used to retain unbounded per-destination state. A datagram for a new
//!   destination is dropped after the table is full; destinations already in
//!   the table keep working.
//! - Both relay modes use unconnected sockets and forward the actual reply
//!   source, matching stock Xray. There is no source allowlist.
//! - Every stream, socket, and shutdown operation is bounded by a timeout. The
//!   idle timer covers both directions and is reset by requests and replies.
//! - A stream EOF exactly between datagrams is a clean close. EOF inside a
//!   length prefix or payload is reported as [`UdpError::Truncated`]. Legacy
//!   UDP has no half-close message, so the connection is not kept alive after
//!   the peer closes its write side.

use std::collections::HashSet;
use std::future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::ops::Range;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep, timeout};

use crate::address::{Address, NetLocation};

/// Magic VLESS destination that selects packetaddr framing.
///
/// sing-box matches this FQDN byte-for-byte. The port in the VLESS header is
/// zero and is not used.
pub const PACKETADDR_MAGIC_DOMAIN: &str = "sp.packet-addr.v2fly.arpa";

/// Hard upper bound for one UDP datagram payload.
pub const MAX_DATAGRAM_SIZE: usize = 8192;

/// Largest payload stock legacy framing can carry: `length + 2 <= 8192`.
const MAX_FRAMED_DATAGRAM_SIZE: usize = MAX_DATAGRAM_SIZE - 2;

/// Two-byte big-endian length prefix.
const LENGTH_PREFIX_LEN: usize = 2;

/// One stream read.
const READ_CHUNK_LEN: usize = 8192;

/// Largest packetaddr inner address: `ATYP | IPv6 | port`.
const MAX_PACKETADDR_HEADER_LEN: usize = 1 + 16 + 2;

const PACKETADDR_ATYP_IPV4: u8 = 1;
const PACKETADDR_ATYP_IPV6: u8 = 2;

/// Default per-datagram payload limit.
pub const DEFAULT_MAX_DATAGRAM_SIZE: usize = MAX_DATAGRAM_SIZE;

/// Default timeout for a socket bind/send/receive and a stream write.
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Default idle timeout for a legacy UDP connection.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Default bound on distinct packetaddr destinations per connection.
pub const DEFAULT_MAX_PACKETADDR_DESTINATIONS: usize = 1024;

/// Largest value accepted for either timeout.
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// Largest accepted packetaddr destination table.
const MAX_PACKETADDR_DESTINATIONS: usize = 65_536;

/// Limits for legacy VLESS UDP and packetaddr.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyUdpConfig {
    /// Maximum datagram payload in either direction, at most
    /// [`MAX_DATAGRAM_SIZE`]. Framing can only carry 8190 bytes.
    pub max_datagram_size: usize,
    /// Timeout for one bind, send, receive, or stream write.
    pub io_timeout: Duration,
    /// Close the connection after this long without a request or reply.
    pub idle_timeout: Duration,
    /// Maximum distinct packetaddr inner destinations tracked per connection.
    pub max_packetaddr_destinations: usize,
}

impl Default for LegacyUdpConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl LegacyUdpConfig {
    /// Creates the production defaults.
    pub const fn new() -> Self {
        Self {
            max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
            io_timeout: DEFAULT_IO_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_packetaddr_destinations: DEFAULT_MAX_PACKETADDR_DESTINATIONS,
        }
    }

    /// Validates every limit and timeout.
    pub fn validate(&self) -> Result<(), LegacyUdpConfigError> {
        if self.max_datagram_size == 0 || self.max_datagram_size > MAX_DATAGRAM_SIZE {
            return Err(LegacyUdpConfigError::MaxDatagramSize);
        }
        if self.io_timeout.is_zero() || self.io_timeout > MAX_TIMEOUT {
            return Err(LegacyUdpConfigError::IoTimeout);
        }
        if self.idle_timeout.is_zero() || self.idle_timeout > MAX_TIMEOUT {
            return Err(LegacyUdpConfigError::IdleTimeout);
        }
        if self.max_packetaddr_destinations == 0
            || self.max_packetaddr_destinations > MAX_PACKETADDR_DESTINATIONS
        {
            return Err(LegacyUdpConfigError::MaxPacketaddrDestinations);
        }
        Ok(())
    }
}

/// An invalid [`LegacyUdpConfig`] value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LegacyUdpConfigError {
    /// `max_datagram_size` was zero or above [`MAX_DATAGRAM_SIZE`].
    #[error("legacy UDP max_datagram_size must be between 1 and {MAX_DATAGRAM_SIZE}")]
    MaxDatagramSize,
    /// `io_timeout` was zero or unreasonably large.
    #[error("legacy UDP io_timeout must be between 1 ns and 24 hours")]
    IoTimeout,
    /// `idle_timeout` was zero or unreasonably large.
    #[error("legacy UDP idle_timeout must be between 1 ns and 24 hours")]
    IdleTimeout,
    /// `max_packetaddr_destinations` was zero or too large.
    #[error("legacy UDP max_packetaddr_destinations must be between 1 and 65536")]
    MaxPacketaddrDestinations,
}

/// Errors returned while relaying a legacy UDP connection.
#[derive(Debug, thiserror::Error)]
pub enum UdpError {
    /// The supplied configuration is invalid.
    #[error("invalid legacy UDP configuration: {0}")]
    Config(#[from] LegacyUdpConfigError),

    /// The destination cannot be used for a UDP relay.
    #[error("invalid legacy UDP destination: {reason}")]
    InvalidDestination {
        /// Why the destination was rejected.
        reason: &'static str,
    },

    /// A stream or socket operation failed.
    #[error("legacy UDP I/O error: {0}")]
    Io(#[from] io::Error),

    /// A bounded operation timed out.
    #[error("legacy UDP {stage} timed out")]
    Timeout {
        /// Operation that timed out.
        stage: &'static str,
    },

    /// The declared datagram length exceeds the accepted bound.
    #[error("legacy UDP datagram length {length} exceeds the {max}-byte limit")]
    DatagramTooLarge {
        /// Declared payload length.
        length: usize,
        /// Accepted payload limit.
        max: usize,
    },

    /// The stream ended inside a length prefix or payload.
    #[error("legacy UDP stream ended with {buffered} buffered bytes of an incomplete datagram")]
    Truncated {
        /// Bytes that were waiting for more input.
        buffered: usize,
    },

    /// The frame reassembly buffer exceeded its invariant bound.
    #[error("legacy UDP reassembly buffer exceeded its bound at {buffered} bytes")]
    BufferOverflow {
        /// Buffered byte count.
        buffered: usize,
    },

    /// A packetaddr datagram had no usable inner address.
    #[error("malformed packetaddr address: {reason}")]
    MalformedPacketAddr {
        /// Why the inner address was rejected.
        reason: &'static str,
    },

    /// Neither an IPv4 nor an IPv6 socket could be bound.
    #[error("could not bind an IPv4 or IPv6 UDP socket")]
    NoSocket,
}

/// Relays one VLESS UDP body until the peer closes or a protocol error occurs.
///
/// `destination` is the VLESS request destination. A magic packetaddr domain
/// selects the multi-destination packetaddr format; every other destination is
/// a fixed address, possibly a domain that is resolved once.
pub async fn handle_udp_stream<S>(
    stream: S,
    destination: NetLocation,
    config: &LegacyUdpConfig,
) -> Result<(), UdpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    config.validate()?;
    if is_packetaddr_destination(&destination) {
        handle_packetaddr(stream, config).await
    } else {
        handle_fixed(stream, &destination, config).await
    }
}

/// Returns `true` if `destination` selects packetaddr framing.
pub fn is_packetaddr_destination(destination: &NetLocation) -> bool {
    matches!(
        &destination.address,
        Address::Domain(domain) if domain == PACKETADDR_MAGIC_DOMAIN
    )
}

/// Relays a fixed-destination legacy UDP session.
async fn handle_fixed<S>(
    stream: S,
    destination: &NetLocation,
    config: &LegacyUdpConfig,
) -> Result<(), UdpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let resolved = resolve_fixed(destination, config.io_timeout).await?;
    let family = Family::of(resolved);
    let socket = timeout(config.io_timeout, UdpSocket::bind(family.bind_address()))
        .await
        .map_err(|_| UdpError::Timeout {
            stage: "socket bind",
        })??;

    let (mut reader, mut writer) = tokio::io::split(stream);
    let payload_limit = framed_payload_limit(config.max_datagram_size);
    let mut decoder = FrameDecoder::new(payload_limit);
    let mut chunk = vec![0u8; READ_CHUNK_LEN];
    let mut incoming = vec![0u8; config.max_datagram_size.saturating_add(1)];
    let mut reply = Vec::with_capacity(LENGTH_PREFIX_LEN + payload_limit);
    let idle = sleep(config.idle_timeout);
    tokio::pin!(idle);

    let outcome = 'session: loop {
        while let Some(frame) = decoder.next_frame()? {
            let payload = &decoder.buffer[frame.clone()];
            match timeout(config.io_timeout, socket.send_to(payload, resolved)).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => break 'session Err(UdpError::Io(error)),
                Err(_) => {
                    break 'session Err(UdpError::Timeout {
                        stage: "datagram send",
                    });
                }
            }
            decoder.consume(frame.end);
            idle.as_mut().reset(next_deadline(config.idle_timeout));
        }

        tokio::select! {
            _ = &mut idle => {
                break Err(UdpError::Timeout { stage: "stream idle" });
            }
            read = reader.read(&mut chunk) => {
                match read {
                    Ok(0) => {
                        if decoder.buffered() == 0 {
                            break Ok(());
                        }
                        break Err(UdpError::Truncated {
                            buffered: decoder.buffered(),
                        });
                    }
                    Ok(count) => {
                        if let Err(error) = decoder.push(&chunk[..count]) {
                            break Err(error);
                        }
                        idle.as_mut().reset(next_deadline(config.idle_timeout));
                    }
                    Err(error) => break Err(UdpError::Io(error)),
                }
            }
            received = socket.recv_from(&mut incoming) => {
                let (length, _source) = match received {
                    Ok(value) => value,
                    Err(error) => break Err(UdpError::Io(error)),
                };
                idle.as_mut().reset(next_deadline(config.idle_timeout));
                if length == 0 || length > payload_limit {
                    tracing::trace!(
                        length,
                        limit = payload_limit,
                        "legacy UDP reply dropped by the datagram limit"
                    );
                    continue;
                }
                if let Err(error) = write_fixed_reply(
                    &mut writer,
                    &incoming[..length],
                    &mut reply,
                    config.io_timeout,
                )
                .await
                {
                    break Err(error);
                }
            }
        }
    };

    if outcome.is_ok() {
        shutdown_writer(&mut writer, config.io_timeout).await?;
    }
    outcome
}

/// Relays a packetaddr session with one socket per address family.
async fn handle_packetaddr<S>(stream: S, config: &LegacyUdpConfig) -> Result<(), UdpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let v4 = bind_optional(Family::V4, config.io_timeout).await;
    let v6 = bind_optional(Family::V6, config.io_timeout).await;
    if v4.is_none() && v6.is_none() {
        return Err(UdpError::NoSocket);
    }

    let (mut reader, mut writer) = tokio::io::split(stream);
    let payload_limit = framed_payload_limit(config.max_datagram_size);
    let mut decoder = FrameDecoder::new(payload_limit);
    let mut table = DestinationTable::new(config.max_packetaddr_destinations);
    let mut chunk = vec![0u8; READ_CHUNK_LEN];
    let mut v4_incoming = vec![0u8; config.max_datagram_size.saturating_add(1)];
    let mut v6_incoming = vec![0u8; config.max_datagram_size.saturating_add(1)];
    let mut reply = Vec::with_capacity(LENGTH_PREFIX_LEN + payload_limit);
    let idle = sleep(config.idle_timeout);
    tokio::pin!(idle);

    let outcome = 'session: loop {
        while let Some(frame) = decoder.next_frame()? {
            let (destination, payload) = parse_packetaddr(&decoder.buffer[frame.clone()])?;
            let destination = normalize_address(destination);

            if !table.admit(destination) {
                tracing::trace!(
                    %destination,
                    max = config.max_packetaddr_destinations,
                    "packetaddr destination table is full; dropping the datagram"
                );
                decoder.consume(frame.end);
                idle.as_mut().reset(next_deadline(config.idle_timeout));
                continue;
            }

            let socket = match destination {
                SocketAddr::V4(_) => v4.as_ref(),
                SocketAddr::V6(_) => v6.as_ref(),
            };
            let Some(socket) = socket else {
                tracing::trace!(
                    %destination,
                    "packetaddr destination family has no socket; dropping the datagram"
                );
                decoder.consume(frame.end);
                idle.as_mut().reset(next_deadline(config.idle_timeout));
                continue;
            };

            match timeout(config.io_timeout, socket.send_to(payload, destination)).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => break 'session Err(UdpError::Io(error)),
                Err(_) => {
                    break 'session Err(UdpError::Timeout {
                        stage: "datagram send",
                    });
                }
            }
            decoder.consume(frame.end);
            idle.as_mut().reset(next_deadline(config.idle_timeout));
        }

        tokio::select! {
            _ = &mut idle => {
                break Err(UdpError::Timeout { stage: "stream idle" });
            }
            read = reader.read(&mut chunk) => {
                match read {
                    Ok(0) => {
                        if decoder.buffered() == 0 {
                            break Ok(());
                        }
                        break Err(UdpError::Truncated {
                            buffered: decoder.buffered(),
                        });
                    }
                    Ok(count) => {
                        if let Err(error) = decoder.push(&chunk[..count]) {
                            break Err(error);
                        }
                        idle.as_mut().reset(next_deadline(config.idle_timeout));
                    }
                    Err(error) => break Err(UdpError::Io(error)),
                }
            }
            received = recv_optional(v4.as_ref(), &mut v4_incoming) => {
                let (length, source) = match received {
                    Ok(value) => value,
                    Err(error) => break Err(UdpError::Io(error)),
                };
                idle.as_mut().reset(next_deadline(config.idle_timeout));
                if length == 0 || length > payload_limit {
                    tracing::trace!(
                        length,
                        limit = payload_limit,
                        "packetaddr reply dropped by the datagram limit"
                    );
                    continue;
                }
                if let Err(error) = write_packetaddr_reply(
                    &mut writer,
                    source,
                    &v4_incoming[..length],
                    &mut reply,
                    config.io_timeout,
                )
                .await
                {
                    break Err(error);
                }
            }
            received = recv_optional(v6.as_ref(), &mut v6_incoming) => {
                let (length, source) = match received {
                    Ok(value) => value,
                    Err(error) => break Err(UdpError::Io(error)),
                };
                idle.as_mut().reset(next_deadline(config.idle_timeout));
                if length == 0 || length > payload_limit {
                    tracing::trace!(
                        length,
                        limit = payload_limit,
                        "packetaddr reply dropped by the datagram limit"
                    );
                    continue;
                }
                if let Err(error) = write_packetaddr_reply(
                    &mut writer,
                    source,
                    &v6_incoming[..length],
                    &mut reply,
                    config.io_timeout,
                )
                .await
                {
                    break Err(error);
                }
            }
        }
    };

    if outcome.is_ok() {
        shutdown_writer(&mut writer, config.io_timeout).await?;
    }
    outcome
}

/// Address family of a UDP socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn of(address: SocketAddr) -> Self {
        if address.is_ipv4() {
            Self::V4
        } else {
            Self::V6
        }
    }

    fn bind_address(self) -> SocketAddr {
        match self {
            Self::V4 => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            Self::V6 => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        }
    }
}

/// Resolves the fixed destination and rejects unusable values.
async fn resolve_fixed(
    destination: &NetLocation,
    io_timeout: Duration,
) -> Result<SocketAddr, UdpError> {
    if destination.port == 0 {
        return Err(UdpError::InvalidDestination {
            reason: "port must be non-zero",
        });
    }

    match &destination.address {
        Address::Ipv4(address) => Ok(SocketAddr::from((*address, destination.port))),
        Address::Ipv6(address) => Ok(SocketAddr::from((*address, destination.port))),
        Address::Domain(domain) => {
            let addresses = timeout(
                io_timeout,
                tokio::net::lookup_host((domain.as_str(), destination.port)),
            )
            .await
            .map_err(|_| UdpError::Timeout {
                stage: "destination resolution",
            })??;

            let mut fallback = None;
            for address in addresses {
                if address.is_ipv4() {
                    return Ok(address);
                }
                fallback.get_or_insert(address);
            }
            fallback.ok_or(UdpError::InvalidDestination {
                reason: "domain has no address",
            })
        }
    }
}

/// Binds a family socket, returning `None` when that family is unavailable.
async fn bind_optional(family: Family, io_timeout: Duration) -> Option<UdpSocket> {
    match timeout(io_timeout, UdpSocket::bind(family.bind_address())).await {
        Ok(Ok(socket)) => Some(socket),
        Ok(Err(error)) => {
            tracing::debug!(
                family = ?family,
                %error,
                "packetaddr socket bind failed; that family is unavailable"
            );
            None
        }
        Err(_) => {
            tracing::debug!(
                family = ?family,
                "packetaddr socket bind timed out; that family is unavailable"
            );
            None
        }
    }
}

/// Waits for a datagram on an optional socket.
///
/// `future::pending` keeps the branch alive when the family has no socket.
async fn recv_optional(
    socket: Option<&UdpSocket>,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(buffer).await,
        None => future::pending::<io::Result<(usize, SocketAddr)>>().await,
    }
}

/// Writes one length-prefixed fixed-destination reply.
async fn write_fixed_reply<W>(
    writer: &mut W,
    payload: &[u8],
    reply: &mut Vec<u8>,
    io_timeout: Duration,
) -> Result<(), UdpError>
where
    W: AsyncWrite + Unpin,
{
    if !encode_fixed_reply(payload, reply) {
        return Ok(());
    }
    match timeout(io_timeout, writer.write_all(reply)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(UdpError::Io(error)),
        Err(_) => Err(UdpError::Timeout {
            stage: "stream write",
        }),
    }
}

/// Encodes `length | payload`, returning `false` when it cannot fit.
fn encode_fixed_reply(payload: &[u8], out: &mut Vec<u8>) -> bool {
    let Ok(length) = u16::try_from(payload.len()) else {
        return false;
    };
    if LENGTH_PREFIX_LEN + payload.len() > MAX_DATAGRAM_SIZE {
        return false;
    }
    out.clear();
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    true
}

/// Writes one packetaddr reply stamped with its actual source.
async fn write_packetaddr_reply<W>(
    writer: &mut W,
    source: SocketAddr,
    payload: &[u8],
    reply: &mut Vec<u8>,
    io_timeout: Duration,
) -> Result<(), UdpError>
where
    W: AsyncWrite + Unpin,
{
    if !encode_packetaddr_reply(source, payload, reply) {
        return Ok(());
    }
    match timeout(io_timeout, writer.write_all(reply)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(UdpError::Io(error)),
        Err(_) => Err(UdpError::Timeout {
            stage: "stream write",
        }),
    }
}

/// Encodes `length | inner address | payload`, returning `false` on overflow.
fn encode_packetaddr_reply(source: SocketAddr, payload: &[u8], out: &mut Vec<u8>) -> bool {
    let source = normalize_address(source);
    let total = LENGTH_PREFIX_LEN
        .saturating_add(packetaddr_header_len(source))
        .saturating_add(payload.len());
    if total > MAX_DATAGRAM_SIZE {
        return false;
    }
    let Ok(length) = u16::try_from(total - LENGTH_PREFIX_LEN) else {
        return false;
    };

    out.clear();
    out.resize(LENGTH_PREFIX_LEN, 0);
    encode_packetaddr_address(source, out);
    out.extend_from_slice(payload);
    out[..LENGTH_PREFIX_LEN].copy_from_slice(&length.to_be_bytes());
    true
}

/// Parses a packetaddr inner address and returns it with the payload.
fn parse_packetaddr(payload: &[u8]) -> Result<(SocketAddr, &[u8]), UdpError> {
    let (&address_type, rest) = payload
        .split_first()
        .ok_or(malformed_packetaddr("missing address type"))?;

    match address_type {
        PACKETADDR_ATYP_IPV4 => {
            let (address, rest) = rest
                .split_first_chunk::<4>()
                .ok_or(malformed_packetaddr("truncated IPv4 address"))?;
            let (port, rest) = rest
                .split_first_chunk::<2>()
                .ok_or(malformed_packetaddr("missing IPv4 port"))?;
            let port = u16::from_be_bytes(*port);
            if port == 0 {
                return Err(malformed_packetaddr("IPv4 port must be non-zero"));
            }
            Ok((SocketAddr::from((Ipv4Addr::from(*address), port)), rest))
        }
        PACKETADDR_ATYP_IPV6 => {
            let (address, rest) = rest
                .split_first_chunk::<16>()
                .ok_or(malformed_packetaddr("truncated IPv6 address"))?;
            let (port, rest) = rest
                .split_first_chunk::<2>()
                .ok_or(malformed_packetaddr("missing IPv6 port"))?;
            let port = u16::from_be_bytes(*port);
            if port == 0 {
                return Err(malformed_packetaddr("IPv6 port must be non-zero"));
            }
            Ok((SocketAddr::from((Ipv6Addr::from(*address), port)), rest))
        }
        _ => Err(malformed_packetaddr("unsupported address type")),
    }
}

fn malformed_packetaddr(reason: &'static str) -> UdpError {
    UdpError::MalformedPacketAddr { reason }
}

fn packetaddr_header_len(address: SocketAddr) -> usize {
    match address {
        SocketAddr::V4(_) => 1 + 4 + 2,
        SocketAddr::V6(_) => MAX_PACKETADDR_HEADER_LEN,
    }
}

fn encode_packetaddr_address(address: SocketAddr, out: &mut Vec<u8>) {
    match address {
        SocketAddr::V4(address) => {
            out.push(PACKETADDR_ATYP_IPV4);
            out.extend_from_slice(&address.ip().octets());
            out.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            out.push(PACKETADDR_ATYP_IPV6);
            out.extend_from_slice(&address.ip().octets());
            out.extend_from_slice(&address.port().to_be_bytes());
        }
    }
}

/// Converts a v4-mapped IPv6 source to IPv4.
fn normalize_address(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => match address.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::V4(SocketAddrV4::new(ip, address.port())),
            None => SocketAddr::V6(address),
        },
        address => address,
    }
}

/// Returns the largest payload the stream codec accepts for this config.
fn framed_payload_limit(configured: usize) -> usize {
    configured.min(MAX_FRAMED_DATAGRAM_SIZE)
}

fn next_deadline(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

async fn shutdown_writer<W>(writer: &mut W, io_timeout: Duration) -> Result<(), UdpError>
where
    W: AsyncWrite + Unpin,
{
    match timeout(io_timeout, writer.shutdown()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) if is_peer_closed(&error) => Ok(()),
        Ok(Err(error)) => Err(UdpError::Io(error)),
        Err(_) => Err(UdpError::Timeout {
            stage: "stream shutdown",
        }),
    }
}

fn is_peer_closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

/// Bounded packetaddr destination table.
struct DestinationTable {
    entries: HashSet<SocketAddr>,
    max: usize,
}

impl DestinationTable {
    fn new(max: usize) -> Self {
        Self {
            entries: HashSet::new(),
            max,
        }
    }

    /// Returns `true` if this destination may be used or is already known.
    fn admit(&mut self, destination: SocketAddr) -> bool {
        if self.entries.contains(&destination) {
            return true;
        }
        if self.entries.len() >= self.max {
            return false;
        }
        self.entries.insert(destination);
        true
    }
}

/// Bounded reassembly of `length(2 BE) | payload` frames.
struct FrameDecoder {
    buffer: Vec<u8>,
    max_payload: usize,
}

impl FrameDecoder {
    fn new(max_payload: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(LENGTH_PREFIX_LEN + max_payload),
            max_payload,
        }
    }

    fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Appends stream bytes while keeping the reassembly bound.
    fn push(&mut self, bytes: &[u8]) -> Result<(), UdpError> {
        let bound = READ_CHUNK_LEN
            .saturating_add(LENGTH_PREFIX_LEN)
            .saturating_add(self.max_payload);
        let buffered = self.buffer.len().saturating_add(bytes.len());
        if buffered > bound {
            return Err(UdpError::BufferOverflow { buffered });
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// Returns the range of the next complete payload.
    ///
    /// Zero-length datagrams are dropped like stock Xray writers do. A
    /// declared length above the configured limit is rejected instead of
    /// being buffered.
    fn next_frame(&mut self) -> Result<Option<Range<usize>>, UdpError> {
        loop {
            let Some(header) = self.buffer.get(..LENGTH_PREFIX_LEN) else {
                return Ok(None);
            };
            let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
            if length == 0 {
                self.consume(LENGTH_PREFIX_LEN);
                continue;
            }
            if length > self.max_payload {
                return Err(UdpError::DatagramTooLarge {
                    length,
                    max: self.max_payload,
                });
            }
            let Some(end) = LENGTH_PREFIX_LEN.checked_add(length) else {
                return Err(UdpError::DatagramTooLarge {
                    length,
                    max: self.max_payload,
                });
            };
            if self.buffer.len() < end {
                return Ok(None);
            }
            return Ok(Some(LENGTH_PREFIX_LEN..end));
        }
    }

    /// Drops the consumed frame bytes.
    fn consume(&mut self, end: usize) {
        if end >= self.buffer.len() {
            self.buffer.clear();
        } else {
            self.buffer.drain(..end);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FrameDecoder, LegacyUdpConfig, LegacyUdpConfigError, MAX_DATAGRAM_SIZE,
        PACKETADDR_MAGIC_DOMAIN, UdpError, handle_udp_stream, parse_packetaddr,
    };
    use crate::address::{Address, NetLocation};
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::UdpSocket;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn test_config(max_datagram_size: usize) -> LegacyUdpConfig {
        LegacyUdpConfig {
            max_datagram_size,
            io_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(5),
            max_packetaddr_destinations: 1024,
        }
    }

    fn start(
        destination: NetLocation,
        config: LegacyUdpConfig,
    ) -> (DuplexStream, JoinHandle<Result<(), UdpError>>) {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let task =
            tokio::spawn(async move { handle_udp_stream(server, destination, &config).await });
        (client, task)
    }

    fn net_location(address: SocketAddr) -> NetLocation {
        match address {
            SocketAddr::V4(address) => NetLocation {
                address: Address::Ipv4(*address.ip()),
                port: address.port(),
            },
            SocketAddr::V6(address) => NetLocation {
                address: Address::Ipv6(*address.ip()),
                port: address.port(),
            },
        }
    }

    fn packetaddr_destination() -> NetLocation {
        NetLocation {
            address: Address::Domain(PACKETADDR_MAGIC_DOMAIN.to_owned()),
            port: 0,
        }
    }

    struct Echo {
        address: SocketAddr,
        task: JoinHandle<()>,
    }

    impl Drop for Echo {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn try_spawn_echo(bind: SocketAddr) -> Option<Echo> {
        let socket = UdpSocket::bind(bind).await.ok()?;
        let address = socket.local_addr().ok()?;
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_DATAGRAM_SIZE];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                let _ = socket.send_to(&buffer[..length], peer).await;
            }
        });
        Some(Echo { address, task })
    }

    async fn spawn_ipv4_echo() -> Echo {
        try_spawn_echo(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("IPv4 echo socket must bind")
    }

    async fn write_frame(client: &mut DuplexStream, payload: &[u8]) {
        let length = u16::try_from(payload.len()).expect("test payload fits");
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(payload);
        timeout(TEST_TIMEOUT, client.write_all(&frame))
            .await
            .expect("timed out writing a frame")
            .expect("stream write failed");
    }

    async fn write_frame_slowly(client: &mut DuplexStream, payload: &[u8]) {
        let length = u16::try_from(payload.len()).expect("test payload fits");
        let mut frame = Vec::new();
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(payload);
        for byte in frame {
            timeout(TEST_TIMEOUT, client.write_all(std::slice::from_ref(&byte)))
                .await
                .expect("timed out writing a split frame")
                .expect("stream write failed");
            tokio::task::yield_now().await;
        }
    }

    async fn read_frame(client: &mut DuplexStream) -> Vec<u8> {
        let mut header = [0u8; 2];
        timeout(TEST_TIMEOUT, client.read_exact(&mut header))
            .await
            .expect("timed out reading a reply length")
            .expect("reply length read failed");
        let length = usize::from(u16::from_be_bytes(header));
        let mut payload = vec![0u8; length];
        timeout(TEST_TIMEOUT, client.read_exact(&mut payload))
            .await
            .expect("timed out reading a reply payload")
            .expect("reply payload read failed");
        payload
    }

    async fn finish_clean(client: DuplexStream, task: JoinHandle<Result<(), UdpError>>) {
        drop(client);
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("legacy UDP handler did not finish")
            .expect("legacy UDP handler panicked");
        assert!(result.is_ok(), "legacy UDP handler failed: {result:?}");
    }

    async fn finish_with_error(
        client: DuplexStream,
        task: JoinHandle<Result<(), UdpError>>,
    ) -> UdpError {
        drop(client);
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("legacy UDP handler did not finish")
            .expect("legacy UDP handler panicked");
        match result {
            Ok(()) => panic!("legacy UDP handler unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    fn packetaddr_datagram(destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        match destination {
            SocketAddr::V4(destination) => {
                out.push(1);
                out.extend_from_slice(&destination.ip().octets());
                out.extend_from_slice(&destination.port().to_be_bytes());
            }
            SocketAddr::V6(destination) => {
                out.push(2);
                out.extend_from_slice(&destination.ip().octets());
                out.extend_from_slice(&destination.port().to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        out
    }

    fn parse_packetaddr_reply(payload: &[u8]) -> (SocketAddr, Vec<u8>) {
        match parse_packetaddr(payload) {
            Ok((address, data)) => (address, data.to_vec()),
            Err(error) => panic!("malformed packetaddr reply: {error}"),
        }
    }

    #[test]
    fn defaults_and_validation() {
        let config = LegacyUdpConfig::default();
        assert_eq!(config.max_datagram_size, MAX_DATAGRAM_SIZE);
        assert!(config.io_timeout > Duration::ZERO);
        assert!(config.idle_timeout > Duration::ZERO);
        config.validate().expect("defaults must be valid");

        for (config, expected) in [
            (
                LegacyUdpConfig {
                    max_datagram_size: 0,
                    ..LegacyUdpConfig::default()
                },
                LegacyUdpConfigError::MaxDatagramSize,
            ),
            (
                LegacyUdpConfig {
                    max_datagram_size: MAX_DATAGRAM_SIZE + 1,
                    ..LegacyUdpConfig::default()
                },
                LegacyUdpConfigError::MaxDatagramSize,
            ),
            (
                LegacyUdpConfig {
                    io_timeout: Duration::ZERO,
                    ..LegacyUdpConfig::default()
                },
                LegacyUdpConfigError::IoTimeout,
            ),
            (
                LegacyUdpConfig {
                    idle_timeout: Duration::ZERO,
                    ..LegacyUdpConfig::default()
                },
                LegacyUdpConfigError::IdleTimeout,
            ),
            (
                LegacyUdpConfig {
                    max_packetaddr_destinations: 0,
                    ..LegacyUdpConfig::default()
                },
                LegacyUdpConfigError::MaxPacketaddrDestinations,
            ),
        ] {
            assert_eq!(config.validate(), Err(expected));
        }
    }

    #[test]
    fn detects_packetaddr_destination() {
        assert!(super::is_packetaddr_destination(&packetaddr_destination()));
        assert!(!super::is_packetaddr_destination(&NetLocation {
            address: Address::Domain("sp.packet-addr.v2fly.arpa.".to_owned()),
            port: 0,
        }));
        assert!(!super::is_packetaddr_destination(&NetLocation {
            address: Address::Domain(PACKETADDR_MAGIC_DOMAIN.to_uppercase()),
            port: 0,
        }));
    }

    #[tokio::test]
    async fn fixed_ipv4_echoes_coalesced_and_split_datagrams() {
        let echo = spawn_ipv4_echo().await;
        let (mut client, task) = start(net_location(echo.address), test_config(MAX_DATAGRAM_SIZE));
        let mut coalesced = Vec::new();
        coalesced.extend_from_slice(&3u16.to_be_bytes());
        coalesced.extend_from_slice(b"one");
        coalesced.extend_from_slice(&3u16.to_be_bytes());
        coalesced.extend_from_slice(b"two");
        timeout(TEST_TIMEOUT, client.write_all(&coalesced))
            .await
            .expect("write")
            .expect("write failed");

        assert_eq!(read_frame(&mut client).await, b"one");
        assert_eq!(read_frame(&mut client).await, b"two");

        write_frame_slowly(&mut client, b"split").await;
        assert_eq!(read_frame(&mut client).await, b"split");

        drop(client);
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .expect("legacy UDP handler did not finish")
            .expect("legacy UDP handler panicked");
        assert!(result.is_ok(), "handler failed: {result:?}");
    }

    #[tokio::test]
    async fn fixed_ipv6_echo() {
        let Some(echo) = try_spawn_echo(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).await else {
            // Hosts without IPv6 loopback skip this case; the codec and the
            // IPv4 path still cover the relay.
            return;
        };
        let (mut client, task) = start(net_location(echo.address), test_config(MAX_DATAGRAM_SIZE));
        write_frame(&mut client, b"v6").await;
        assert_eq!(read_frame(&mut client).await, b"v6");
        finish_clean(client, task).await;
    }

    #[tokio::test]
    async fn fixed_domain_destination_resolves() {
        let v4 = spawn_ipv4_echo().await;
        let port = v4.address.port();
        let _v6 = try_spawn_echo(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await;
        let destination = NetLocation {
            address: Address::Domain("localhost".to_owned()),
            port,
        };

        let (mut client, task) = start(destination, test_config(MAX_DATAGRAM_SIZE));
        write_frame(&mut client, b"domain").await;
        assert_eq!(read_frame(&mut client).await, b"domain");
        finish_clean(client, task).await;
    }

    #[tokio::test]
    async fn fixed_eof_between_datagrams_is_clean() {
        let echo = spawn_ipv4_echo().await;
        let (mut client, task) = start(net_location(echo.address), test_config(MAX_DATAGRAM_SIZE));
        write_frame(&mut client, b"before-eof").await;
        assert_eq!(read_frame(&mut client).await, b"before-eof");
        finish_clean(client, task).await;
    }

    #[tokio::test]
    async fn fixed_eof_inside_a_length_prefix_is_truncated() {
        let echo = spawn_ipv4_echo().await;
        let (mut client, task) = start(net_location(echo.address), test_config(MAX_DATAGRAM_SIZE));
        timeout(TEST_TIMEOUT, client.write_all(&[0x00]))
            .await
            .expect("write")
            .expect("write failed");
        let error = finish_with_error(client, task).await;
        assert!(matches!(error, UdpError::Truncated { buffered: 1 }));
    }

    #[tokio::test]
    async fn fixed_eof_inside_a_payload_is_truncated() {
        let echo = spawn_ipv4_echo().await;
        let (mut client, task) = start(net_location(echo.address), test_config(MAX_DATAGRAM_SIZE));
        timeout(TEST_TIMEOUT, client.write_all(&[0x00, 0x04, 0xaa, 0xbb]))
            .await
            .expect("write")
            .expect("write failed");
        let error = finish_with_error(client, task).await;
        assert!(matches!(error, UdpError::Truncated { buffered: 4 }));
    }

    #[tokio::test]
    async fn fixed_oversize_datagram_is_rejected() {
        let echo = spawn_ipv4_echo().await;
        let (mut client, task) = start(net_location(echo.address), test_config(32));
        timeout(TEST_TIMEOUT, client.write_all(&[0x00, 0x21]))
            .await
            .expect("write")
            .expect("write failed");
        let error = finish_with_error(client, task).await;
        assert!(matches!(
            error,
            UdpError::DatagramTooLarge {
                length: 33,
                max: 32
            }
        ));
    }

    #[tokio::test]
    async fn fixed_oversize_reply_is_dropped_without_closing() {
        let responder = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("responder socket");
        let address = responder.local_addr().expect("responder address");
        let responder_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (length, peer) = responder
                .recv_from(&mut buffer)
                .await
                .expect("first receive");
            assert_eq!(&buffer[..length], b"one");
            responder
                .send_to(&vec![0xaa; MAX_DATAGRAM_SIZE + 100], peer)
                .await
                .expect("oversize send");
            let (length, peer) = responder
                .recv_from(&mut buffer)
                .await
                .expect("second receive");
            assert_eq!(&buffer[..length], b"two");
            responder.send_to(b"ok", peer).await.expect("normal send");
        });

        let (mut client, task) = start(net_location(address), test_config(MAX_DATAGRAM_SIZE));
        write_frame(&mut client, b"one").await;
        write_frame(&mut client, b"two").await;
        assert_eq!(read_frame(&mut client).await, b"ok");
        responder_task.await.expect("responder task");
        finish_clean(client, task).await;
    }

    #[tokio::test]
    async fn fixed_zero_length_datagram_is_dropped() {
        let echo = spawn_ipv4_echo().await;
        let (mut client, task) = start(net_location(echo.address), test_config(MAX_DATAGRAM_SIZE));
        write_frame(&mut client, b"").await;
        write_frame(&mut client, b"after-zero").await;
        assert_eq!(read_frame(&mut client).await, b"after-zero");
        finish_clean(client, task).await;
    }

    #[tokio::test]
    async fn packetaddr_ipv4_echo_stamps_the_source() {
        let echo = spawn_ipv4_echo().await;
        let (mut client, task) = start(packetaddr_destination(), test_config(MAX_DATAGRAM_SIZE));

        let datagram = packetaddr_datagram(echo.address, b"packetaddr-v4");
        write_frame(&mut client, &datagram).await;

        let reply = read_frame(&mut client).await;
        let (source, payload) = parse_packetaddr_reply(&reply);
        assert_eq!(source, echo.address);
        assert_eq!(payload, b"packetaddr-v4");
        finish_clean(client, task).await;
    }

    #[tokio::test]
    async fn packetaddr_ipv6_echo_stamps_the_source() {
        let Some(echo) = try_spawn_echo(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).await else {
            return;
        };
        let (mut client, task) = start(packetaddr_destination(), test_config(MAX_DATAGRAM_SIZE));

        let datagram = packetaddr_datagram(echo.address, b"packetaddr-v6");
        write_frame(&mut client, &datagram).await;

        let reply = read_frame(&mut client).await;
        let (source, payload) = parse_packetaddr_reply(&reply);
        assert_eq!(source, echo.address);
        assert_eq!(payload, b"packetaddr-v6");
        finish_clean(client, task).await;
    }

    #[tokio::test]
    async fn packetaddr_mixed_families_share_one_session() {
        let v4 = spawn_ipv4_echo().await;
        let Some(v6) = try_spawn_echo(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).await else {
            return;
        };
        let (mut client, task) = start(packetaddr_destination(), test_config(MAX_DATAGRAM_SIZE));

        write_frame(&mut client, &packetaddr_datagram(v4.address, b"four")).await;
        let reply = read_frame(&mut client).await;
        let (source, payload) = parse_packetaddr_reply(&reply);
        assert_eq!(source, v4.address);
        assert_eq!(payload, b"four");

        write_frame(&mut client, &packetaddr_datagram(v6.address, b"six")).await;
        let reply = read_frame(&mut client).await;
        let (source, payload) = parse_packetaddr_reply(&reply);
        assert_eq!(source, v6.address);
        assert_eq!(payload, b"six");

        finish_clean(client, task).await;
    }

    #[tokio::test]
    async fn packetaddr_reply_carries_the_actual_responder() {
        // The destination never answers. A different socket sends the reply,
        // so the stamped source must be the responder.
        let destination = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("destination socket");
        let responder = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("responder socket");
        let destination_address = destination.local_addr().expect("destination address");
        let responder_address = responder.local_addr().expect("responder address");
        let responder_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (length, peer) = destination
                .recv_from(&mut buffer)
                .await
                .expect("destination receive");
            responder
                .send_to(&buffer[..length], peer)
                .await
                .expect("responder send");
        });

        let (mut client, task) = start(packetaddr_destination(), test_config(MAX_DATAGRAM_SIZE));
        write_frame(
            &mut client,
            &packetaddr_datagram(destination_address, b"source"),
        )
        .await;
        let reply = read_frame(&mut client).await;
        let (source, payload) = parse_packetaddr_reply(&reply);
        assert_eq!(source, responder_address);
        assert_eq!(payload, b"source");

        responder_task.await.expect("responder task");
        finish_clean(client, task).await;
    }

    #[tokio::test]
    async fn packetaddr_rejects_malformed_inner_addresses() {
        // A zero-length outer datagram is dropped before packetaddr parsing,
        // so every malformed inner address needs at least one byte.
        let cases: &[&[u8]] = &[
            &[0],
            &[3, 0, 0, 0, 0, 0, 0],
            &[1, 127, 0, 0],
            &[1, 127, 0, 0, 1, 0],
            &[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[1, 127, 0, 0, 1, 0, 0],
        ];

        for case in cases {
            let (mut client, task) =
                start(packetaddr_destination(), test_config(MAX_DATAGRAM_SIZE));
            write_frame(&mut client, case).await;
            let error = finish_with_error(client, task).await;
            assert!(
                matches!(error, UdpError::MalformedPacketAddr { .. }),
                "unexpected error for {case:?}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn packetaddr_oversize_datagram_is_rejected() {
        let echo = spawn_ipv4_echo().await;
        let (mut client, task) = start(packetaddr_destination(), test_config(32));
        let datagram = packetaddr_datagram(echo.address, &[0x5a; 26]);
        assert_eq!(datagram.len(), 33);
        write_frame(&mut client, &datagram).await;
        let error = finish_with_error(client, task).await;
        assert!(matches!(
            error,
            UdpError::DatagramTooLarge {
                length: 33,
                max: 32
            }
        ));
    }

    #[tokio::test]
    async fn packetaddr_destination_table_is_bounded() {
        let first = spawn_ipv4_echo().await;
        let second = spawn_ipv4_echo().await;
        let config = LegacyUdpConfig {
            max_packetaddr_destinations: 1,
            ..test_config(MAX_DATAGRAM_SIZE)
        };
        let (mut client, task) = start(packetaddr_destination(), config);

        write_frame(&mut client, &packetaddr_datagram(first.address, b"one")).await;
        let reply = read_frame(&mut client).await;
        let (_, payload) = parse_packetaddr_reply(&reply);
        assert_eq!(payload, b"one");

        // A second destination is not admitted. No reply may arrive.
        write_frame(&mut client, &packetaddr_datagram(second.address, b"two")).await;
        let mut header = [0u8; 2];
        let absent = timeout(Duration::from_millis(250), client.read_exact(&mut header)).await;
        assert!(
            absent.is_err(),
            "the bounded table admitted a new destination"
        );

        // The known destination still works, and the connection stays open.
        write_frame(&mut client, &packetaddr_datagram(first.address, b"three")).await;
        let reply = read_frame(&mut client).await;
        let (source, payload) = parse_packetaddr_reply(&reply);
        assert_eq!(source, first.address);
        assert_eq!(payload, b"three");

        finish_clean(client, task).await;
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn arbitrary_frame_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..=20_000)) {
            let mut decoder = FrameDecoder::new(64);
            let _ = decoder.push(&data);
            while let Ok(Some(frame)) = decoder.next_frame() {
                let _ = &decoder.buffer[frame.clone()];
                decoder.consume(frame.end);
            }
        }

        #[test]
        fn arbitrary_packetaddr_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..=128)) {
            let _ = parse_packetaddr(&data);
        }
    }
}
