//! Bounded, zero-copy codec for VLESS request and response headers.
//!
//! A request is:
//!
//! ```text
//! version(1)=0 | user_id(16) | addons_len(1) | addons | command(1)
//!     | [port(2 BE) | atyp(1) | address]
//! ```
//!
//! The destination is present for the TCP and UDP commands and absent for Mux
//! and Rvs. Addons are a small protobuf message with a length-delimited Flow
//! field (1) and a length-delimited Seed field (2). Unknown fields are skipped,
//! while malformed lengths, invalid wire types, invalid UTF-8 Flow values, and
//! duplicate known fields are rejected.
//!
//! The parser never allocates for addons or addresses other than a domain name.
//! Addon values and the trailing body borrow the input. The only owned field is
//! the destination domain, whose one-byte wire length bounds it to 255 bytes.
//!
//! The response is always `version(1)=0 | addons_len(1)=0`; the flow is not
//! echoed.

use crate::address::{AddressError, NetLocation};

/// VLESS version used by the request and response headers.
pub const VLESS_VERSION: u8 = 0;

/// Maximum number of bytes a request header may consume.
///
/// A maximally sized addons field (255 bytes) combined with a maximally sized
/// domain destination (259 bytes) would exceed this limit and is rejected. In
/// practice stock clients use empty or 18-byte addons and short domain names.
pub const MAX_REQUEST_HEADER_LEN: usize = 512;

/// Maximum addons length allowed by the one-byte wire field.
pub const MAX_ADDONS_LEN: usize = u8::MAX as usize;

/// Flow value used by XTLS Vision.
pub const VISION_FLOW: &str = "xtls-rprx-vision";

/// Wire length of the stock Vision addons protobuf message.
pub const VISION_ADDONS_LEN: u8 = 0x12;

/// Protobuf bytes stock Xray sends for the Vision flow.
///
/// This is field 1 (`0x0a`), length 16 (`0x10`), followed by
/// [`VISION_FLOW`].
pub const VISION_ADDONS: &[u8] = b"\x0a\x10xtls-rprx-vision";

const FLOW_FIELD: u64 = 1;
const SEED_FIELD: u64 = 2;
const MAX_PROTOBUF_FIELD_NUMBER: u64 = (1 << 29) - 1;

const WIRE_TYPE_VARINT: u8 = 0;
const WIRE_TYPE_FIXED64: u8 = 1;
const WIRE_TYPE_LENGTH_DELIMITED: u8 = 2;
const WIRE_TYPE_START_GROUP: u8 = 3;
const WIRE_TYPE_END_GROUP: u8 = 4;
const WIRE_TYPE_FIXED32: u8 = 5;

/// Errors returned while parsing a VLESS header or addons message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VlessError {
    /// The input ended before a field could be read completely.
    #[error("truncated VLESS input at offset {offset}: need {needed} bytes, {remaining} remain")]
    Truncated {
        /// Offset at which the read started.
        offset: usize,
        /// Number of bytes the field needs.
        needed: usize,
        /// Number of bytes left in the input.
        remaining: usize,
    },

    /// The request header consumes more than the accepted maximum.
    #[error("VLESS header length {length} exceeds the {max}-byte limit")]
    HeaderTooLarge {
        /// Number of bytes the header consumes.
        length: usize,
        /// Maximum accepted header length.
        max: usize,
    },

    /// The version byte is not zero.
    #[error("unsupported VLESS version {0}")]
    UnsupportedVersion(u8),

    /// The command byte is not one of the four defined commands.
    #[error("unknown VLESS command {0}")]
    UnknownCommand(u8),

    /// The addons protobuf message is malformed.
    #[error("malformed VLESS addons: {reason}")]
    MalformedAddons {
        /// Reason the addons were rejected.
        reason: &'static str,
    },

    /// The client selected a flow this server does not implement.
    #[error("unsupported VLESS flow")]
    UnsupportedFlow,

    /// The destination address is malformed or truncated.
    #[error("invalid VLESS destination: {0}")]
    Address(#[from] AddressError),
}

impl VlessError {
    /// Returns `true` if the input ended before the header was complete.
    ///
    /// A streaming caller can use this to decide whether to read more bytes
    /// instead of rejecting the connection. Truncation inside a destination
    /// address is reported through [`AddressError::Truncated`] and counts as
    /// truncated here.
    pub fn is_truncated(&self) -> bool {
        matches!(
            self,
            Self::Truncated { .. } | Self::Address(AddressError::Truncated)
        )
    }
}

/// A VLESS command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// TCP stream to the destination.
    Tcp = 1,
    /// Legacy VLESS UDP to the destination.
    Udp = 2,
    /// Mux stream, which carries its destinations inside XUDP frames.
    Mux = 3,
    /// Reverse stream.
    Rvs = 4,
}

impl Command {
    /// Returns the one-byte wire value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns the command for a wire value, or `None` if it is unknown.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Tcp),
            2 => Some(Self::Udp),
            3 => Some(Self::Mux),
            4 => Some(Self::Rvs),
            _ => None,
        }
    }

    /// Returns `true` if requests with this command carry a destination.
    pub const fn has_destination(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }
}

impl TryFrom<u8> for Command {
    type Error = VlessError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or(VlessError::UnknownCommand(value))
    }
}

/// Parsed VLESS addons.
///
/// The fields borrow the addons bytes from the request. An empty addons field
/// yields a value with no flow and no seed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Addons<'a> {
    /// The Flow field, if present and valid UTF-8.
    pub flow: Option<&'a str>,
    /// The Seed field, if present.
    pub seed: Option<&'a [u8]>,
    /// The complete, unmodified addons protobuf bytes.
    pub raw: &'a [u8],
}

impl<'a> Addons<'a> {
    /// Addons with no Flow and no Seed.
    pub const EMPTY: Self = Self {
        flow: None,
        seed: None,
        raw: &[],
    };

    /// Returns an empty addons value.
    pub const fn empty() -> Self {
        Self::EMPTY
    }

    /// Returns the stock XTLS Vision addons.
    pub const fn vision() -> Self {
        Self {
            flow: Some(VISION_FLOW),
            seed: None,
            raw: VISION_ADDONS,
        }
    }

    /// Parses a protobuf addons message.
    ///
    /// Unknown fields of every valid wire type are skipped. Lengths are checked
    /// against the input before they are used, so this performs no allocation.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, VlessError> {
        if bytes.len() > MAX_ADDONS_LEN {
            return Err(malformed_addons("addons exceed the one-byte length limit"));
        }

        let mut reader = Reader::new(bytes);
        let mut flow = None;
        let mut seed = None;

        while reader.remaining_len() > 0 {
            let key = reader.varint()?;
            let field = key >> 3;
            let wire_type = (key & 0x07) as u8;

            if field == 0 || field > MAX_PROTOBUF_FIELD_NUMBER {
                return Err(malformed_addons("invalid protobuf field number"));
            }

            match field {
                FLOW_FIELD => {
                    if wire_type != WIRE_TYPE_LENGTH_DELIMITED {
                        return Err(malformed_addons("flow field is not length-delimited"));
                    }
                    if flow.is_some() {
                        return Err(malformed_addons("duplicate flow field"));
                    }
                    let length = reader.length()?;
                    let value = reader.take(length)?;
                    let value = core::str::from_utf8(value)
                        .map_err(|_| malformed_addons("flow is not valid UTF-8"))?;
                    flow = Some(value);
                }
                SEED_FIELD => {
                    if wire_type != WIRE_TYPE_LENGTH_DELIMITED {
                        return Err(malformed_addons("seed field is not length-delimited"));
                    }
                    if seed.is_some() {
                        return Err(malformed_addons("duplicate seed field"));
                    }
                    let length = reader.length()?;
                    seed = Some(reader.take(length)?);
                }
                _ => reader.skip(wire_type)?,
            }
        }

        Ok(Self {
            flow,
            seed,
            raw: bytes,
        })
    }

    /// Returns `true` if the addons message has no bytes.
    pub const fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Returns `true` if the Flow value is `xtls-rprx-vision`.
    pub fn is_vision(&self) -> bool {
        self.flow == Some(VISION_FLOW)
    }
}

/// A parsed VLESS request header and the trailing body bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHeader<'a> {
    /// Protocol version. Always zero for a successfully parsed header.
    pub version: u8,
    /// The raw 16-byte user id sent by the client.
    ///
    /// Xray authenticates after zeroing bytes 6 and 7 but retains these raw
    /// bytes for the Vision prefix, so the parser preserves them unchanged.
    pub user_id: [u8; 16],
    /// The parsed addons.
    pub addons: Addons<'a>,
    /// The requested command.
    pub command: Command,
    /// The destination for TCP and UDP; `None` for Mux and Rvs.
    pub destination: Option<NetLocation>,
}

impl<'a> RequestHeader<'a> {
    /// Parses a request header and returns it with the trailing body bytes.
    ///
    /// The body is the remaining input after the header, which lets a caller
    /// decode a header that was coalesced with the first payload. Mux and Rvs
    /// have no destination, so every byte after the command is body.
    pub fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), VlessError> {
        let mut reader = Reader::new(input);

        let version = reader.u8()?;
        if version != VLESS_VERSION {
            return Err(VlessError::UnsupportedVersion(version));
        }

        let user_id = reader.take_array::<16>()?;

        let addons_len = usize::from(reader.u8()?);
        let addons = Addons::parse(reader.take(addons_len)?)?;

        let command = Command::try_from(reader.u8()?)?;

        let (destination, body) = if command.has_destination() {
            let (destination, body) = NetLocation::parse_port_address(reader.remaining())?;
            (Some(destination), body)
        } else {
            (None, reader.remaining())
        };

        let header_len = input.len().saturating_sub(body.len());
        if header_len > MAX_REQUEST_HEADER_LEN {
            return Err(VlessError::HeaderTooLarge {
                length: header_len,
                max: MAX_REQUEST_HEADER_LEN,
            });
        }

        Ok((
            Self {
                version,
                user_id,
                addons,
                command,
                destination,
            },
            body,
        ))
    }

    /// Returns `true` if the request selected the XTLS Vision flow.
    pub fn is_vision(&self) -> bool {
        self.addons.is_vision()
    }
}

/// The VLESS response header.
///
/// Xray always sends `00 00`, does not echo the requested flow, and carries no
/// other fields. This type therefore has no state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResponseHeader;

impl ResponseHeader {
    /// Encoded length of a response header.
    pub const ENCODED_LEN: usize = 2;

    /// Creates a response header.
    pub const fn new() -> Self {
        Self
    }

    /// Appends the response header to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_bytes());
    }

    /// Returns the encoded response header.
    pub const fn to_bytes(self) -> [u8; Self::ENCODED_LEN] {
        [VLESS_VERSION, 0]
    }
}

/// Appends the stock VLESS response header to `out`.
pub fn encode_response(out: &mut Vec<u8>) {
    ResponseHeader::new().encode(out);
}

fn malformed_addons(reason: &'static str) -> VlessError {
    VlessError::MalformedAddons { reason }
}

fn truncated(offset: usize, needed: usize, remaining: usize) -> VlessError {
    VlessError::Truncated {
        offset,
        needed,
        remaining,
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn remaining_len(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }

    fn remaining(&self) -> &'a [u8] {
        self.input.get(self.offset..).unwrap_or(&[])
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], VlessError> {
        let offset = self.offset;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| truncated(offset, len, self.remaining_len()))?;
        let bytes = self
            .input
            .get(offset..end)
            .ok_or_else(|| truncated(offset, len, self.remaining_len()))?;
        self.offset = end;
        Ok(bytes)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], VlessError> {
        let offset = self.offset;
        let bytes = self.take(N)?;
        let remaining = bytes.len();
        bytes
            .try_into()
            .map_err(|_| truncated(offset, N, remaining))
    }

    fn u8(&mut self) -> Result<u8, VlessError> {
        let [value] = self.take_array::<1>()?;
        Ok(value)
    }

    fn varint(&mut self) -> Result<u64, VlessError> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.u8()?;
            if index == 9 && byte > 1 {
                return Err(malformed_addons("varint overflows u64"));
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(malformed_addons("varint is longer than 10 bytes"))
    }

    fn length(&mut self) -> Result<usize, VlessError> {
        let value = self.varint()?;
        usize::try_from(value).map_err(|_| malformed_addons("length does not fit in usize"))
    }

    fn skip(&mut self, wire_type: u8) -> Result<(), VlessError> {
        match wire_type {
            WIRE_TYPE_VARINT => {
                self.varint()?;
            }
            WIRE_TYPE_FIXED64 => {
                self.take(8)?;
            }
            WIRE_TYPE_LENGTH_DELIMITED => {
                let length = self.length()?;
                self.take(length)?;
            }
            WIRE_TYPE_FIXED32 => {
                self.take(4)?;
            }
            WIRE_TYPE_START_GROUP | WIRE_TYPE_END_GROUP => {
                return Err(malformed_addons("group wire types are not supported"));
            }
            _ => return Err(malformed_addons("invalid protobuf wire type")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const USER_ID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    fn request(
        addons: &[u8],
        command: Command,
        destination: Option<&[u8]>,
        body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(VLESS_VERSION);
        out.extend_from_slice(&USER_ID);
        out.push(addons.len() as u8);
        out.extend_from_slice(addons);
        out.push(command.as_u8());
        if let Some(destination) = destination {
            out.extend_from_slice(destination);
        }
        out.extend_from_slice(body);
        out
    }

    fn ipv4_destination(port: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&port.to_be_bytes());
        out.push(1);
        out.extend_from_slice(&[192, 0, 2, 1]);
        out
    }

    fn domain_destination(port: u16, domain: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&port.to_be_bytes());
        out.push(2);
        out.push(domain.len() as u8);
        out.extend_from_slice(domain.as_bytes());
        out
    }

    fn ipv6_destination(port: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&port.to_be_bytes());
        out.push(3);
        out.extend_from_slice(&Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).octets());
        out
    }

    fn proto_varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn proto_bytes_field(field: u64, data: &[u8]) -> Vec<u8> {
        let mut out = proto_varint((field << 3) | u64::from(WIRE_TYPE_LENGTH_DELIMITED));
        out.extend_from_slice(&proto_varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    fn vision_addons() -> Vec<u8> {
        proto_bytes_field(FLOW_FIELD, VISION_FLOW.as_bytes())
    }

    #[test]
    fn parses_tcp_ipv4_request() {
        let destination = ipv4_destination(443);
        let input = request(&[], Command::Tcp, Some(&destination), b"payload");

        let (header, body) = RequestHeader::parse(&input).expect("valid TCP IPv4 request");
        assert_eq!(header.version, VLESS_VERSION);
        assert_eq!(header.user_id, USER_ID);
        assert_eq!(header.addons, Addons::empty());
        assert!(header.addons.is_empty());
        assert_eq!(header.command, Command::Tcp);
        assert_eq!(
            header.destination,
            Some(NetLocation {
                address: Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                port: 443,
            })
        );
        assert_eq!(body, b"payload");
    }

    #[test]
    fn parses_tcp_domain_request() {
        let destination = domain_destination(8443, "example.com");
        let input = request(&[], Command::Tcp, Some(&destination), b"body");

        let (header, body) = RequestHeader::parse(&input).expect("valid TCP domain request");
        assert_eq!(header.version, VLESS_VERSION);
        assert_eq!(header.command, Command::Tcp);
        assert_eq!(
            header.destination,
            Some(NetLocation {
                address: Address::Domain("example.com".to_owned()),
                port: 8443,
            })
        );
        assert_eq!(body, b"body");
    }

    #[test]
    fn parses_tcp_ipv6_request() {
        let destination = ipv6_destination(443);
        let input = request(&[], Command::Tcp, Some(&destination), b"tail");

        let (header, body) = RequestHeader::parse(&input).expect("valid TCP IPv6 request");
        assert_eq!(header.command, Command::Tcp);
        assert_eq!(
            header.destination,
            Some(NetLocation {
                address: Address::Ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
                port: 443,
            })
        );
        assert_eq!(body, b"tail");
    }

    #[test]
    fn parses_udp_request() {
        let destination = ipv4_destination(53);
        let input = request(&[], Command::Udp, Some(&destination), b"datagram");

        let (header, body) = RequestHeader::parse(&input).expect("valid UDP request");
        assert_eq!(header.command, Command::Udp);
        assert_eq!(
            header.destination,
            Some(NetLocation {
                address: Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                port: 53,
            })
        );
        assert_eq!(body, b"datagram");
    }

    #[test]
    fn parses_mux_and_rvs_without_destination() {
        // These bytes look like a destination but are body for Mux and Rvs.
        let body = [0x01, 0xbb, 0x01, 192, 0, 2, 1];

        for command in [Command::Mux, Command::Rvs] {
            let input = request(&[], command, None, &body);
            let (header, rest) =
                RequestHeader::parse(&input).expect("valid request without destination");
            assert_eq!(header.command, command);
            assert_eq!(header.destination, None);
            assert_eq!(rest, body);
        }
    }

    #[test]
    fn parses_vision_addons() {
        let addons = vision_addons();
        assert_eq!(addons, VISION_ADDONS);
        assert_eq!(addons.len(), usize::from(VISION_ADDONS_LEN));
        assert_eq!(VISION_FLOW.len(), 16);

        let destination = ipv4_destination(443);
        let input = request(&addons, Command::Tcp, Some(&destination), b"");

        let (header, body) = RequestHeader::parse(&input).expect("valid Vision request");
        assert_eq!(header.addons.raw, addons.as_slice());
        assert_eq!(header.addons.flow, Some(VISION_FLOW));
        assert_eq!(header.addons.seed, None);
        assert!(header.addons.is_vision());
        assert!(header.is_vision());
        assert!(body.is_empty());

        let parsed = Addons::parse(&addons).expect("valid Vision addons");
        assert_eq!(parsed, Addons::vision());
        assert_eq!(parsed.raw, VISION_ADDONS);
    }

    #[test]
    fn parses_empty_addons() {
        let destination = ipv4_destination(443);
        let input = request(&[], Command::Tcp, Some(&destination), b"data");

        let (header, body) = RequestHeader::parse(&input).expect("empty addons are valid");
        assert_eq!(header.addons.flow, None);
        assert_eq!(header.addons.seed, None);
        assert_eq!(header.addons.raw, &[]);
        assert!(header.addons.is_empty());
        assert!(!header.addons.is_vision());
        assert_eq!(body, b"data");
    }

    #[test]
    fn skips_unknown_addon_fields() {
        let mut addons = Vec::new();
        addons.extend_from_slice(&proto_varint((3 << 3) | u64::from(WIRE_TYPE_VARINT)));
        addons.extend_from_slice(&proto_varint(150));
        addons.extend_from_slice(&proto_bytes_field(SEED_FIELD, &[0x01, 0x02, 0x03]));
        addons.extend_from_slice(&proto_bytes_field(4, b"ignored"));
        addons.extend_from_slice(&proto_varint((5 << 3) | u64::from(WIRE_TYPE_FIXED32)));
        addons.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        addons.extend_from_slice(&proto_varint((6 << 3) | u64::from(WIRE_TYPE_FIXED64)));
        addons.extend_from_slice(&[0xaa; 8]);
        addons.extend_from_slice(&proto_bytes_field(FLOW_FIELD, VISION_FLOW.as_bytes()));

        let parsed = Addons::parse(&addons).expect("unknown fields are skipped");
        assert_eq!(parsed.flow, Some(VISION_FLOW));
        assert_eq!(parsed.seed, Some(&[0x01, 0x02, 0x03][..]));
        assert_eq!(parsed.raw, addons.as_slice());
    }

    #[test]
    fn parses_empty_flow_value() {
        let addons = proto_bytes_field(FLOW_FIELD, b"");
        let parsed = Addons::parse(&addons).expect("empty flow is structurally valid");
        assert_eq!(parsed.flow, Some(""));
        assert!(!parsed.is_vision());
    }

    #[test]
    fn preserves_trailing_body() {
        let destination = ipv4_destination(443);
        let payload = [0x00, 0xff, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00];
        let input = request(&[], Command::Tcp, Some(&destination), &payload);

        let (header, body) = RequestHeader::parse(&input).expect("valid request");
        assert_eq!(header.command, Command::Tcp);
        assert_eq!(body, payload);
        assert_eq!(body.as_ptr(), input[input.len() - payload.len()..].as_ptr());
    }

    #[test]
    fn rejects_truncated_header_at_every_prefix() {
        let destination = domain_destination(443, "example.com");
        let input = request(&vision_addons(), Command::Tcp, Some(&destination), b"");

        for cut in 0..input.len() {
            let error =
                RequestHeader::parse(&input[..cut]).expect_err("a truncated header must not parse");
            assert!(
                error.is_truncated(),
                "a {cut}-byte prefix returned a non-truncation error: {error:?}"
            );
        }
        assert!(RequestHeader::parse(&input).is_ok());
    }

    #[test]
    fn rejects_truncated_mux_header_at_every_prefix() {
        let input = request(&[], Command::Mux, None, b"body");

        // The command is the last header byte; only shorter prefixes are cut.
        for cut in 0..18 {
            assert!(
                RequestHeader::parse(&input[..cut]).is_err(),
                "accepted a {cut}-byte prefix"
            );
        }
        assert!(RequestHeader::parse(&input).is_ok());
    }

    #[test]
    fn rejects_invalid_version() {
        let destination = ipv4_destination(443);
        let mut input = request(&[], Command::Tcp, Some(&destination), b"");
        input[0] = 1;

        assert_eq!(
            RequestHeader::parse(&input),
            Err(VlessError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn rejects_unknown_command() {
        let input = request(&[], Command::Mux, None, b"");

        for command in [0, 5, 0xff] {
            let mut malformed = input.clone();
            malformed[18] = command;
            assert_eq!(
                RequestHeader::parse(&malformed),
                Err(VlessError::UnknownCommand(command))
            );
        }
    }

    #[test]
    fn rejects_malformed_addons() {
        fn assert_malformed(addons: &[u8]) {
            let destination = ipv4_destination(443);
            let input = request(addons, Command::Tcp, Some(&destination), b"");
            assert!(
                matches!(
                    RequestHeader::parse(&input),
                    Err(VlessError::MalformedAddons { .. })
                ),
                "accepted malformed addons {addons:?}"
            );
        }

        // Field 1 with a varint wire type.
        assert_malformed(&[0x08, 0x01]);
        // Field 2 with a varint wire type.
        assert_malformed(&[0x10, 0x01]);
        // Duplicate Flow.
        assert_malformed(&[0x0a, 0x01, b'a', 0x0a, 0x01, b'b']);
        // Duplicate Seed.
        assert_malformed(&[0x12, 0x01, b'a', 0x12, 0x01, b'b']);
        // Invalid UTF-8 Flow.
        assert_malformed(&[0x0a, 0x01, 0xff]);
        // Field number zero.
        assert_malformed(&[0x00, 0x00]);
        // Protobuf start-group wire type.
        assert_malformed(&[0x1b, 0x00]);
        // Invalid wire type seven.
        assert_malformed(&[0x1f, 0x00]);
        // Varint with more than ten bytes.
        assert_malformed(&[
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
        ]);
        // Varint that overflows u64.
        assert_malformed(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02]);
    }

    #[test]
    fn rejects_addon_lengths_past_the_end() {
        // Flow declares five bytes but only one is present.
        let addons = [0x0a, 0x05, b'a'];
        let destination = ipv4_destination(443);
        let input = request(&addons, Command::Tcp, Some(&destination), b"");
        assert!(matches!(
            RequestHeader::parse(&input),
            Err(VlessError::Truncated { .. })
        ));

        // Unknown length-delimited field declares more bytes than remain.
        let addons = [0x1a, 0x7f, 0x00];
        let input = request(&addons, Command::Tcp, Some(&destination), b"");
        assert!(matches!(
            RequestHeader::parse(&input),
            Err(VlessError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_addons_longer_than_the_wire_limit() {
        let addons = vec![0u8; MAX_ADDONS_LEN + 1];
        assert!(matches!(
            Addons::parse(&addons),
            Err(VlessError::MalformedAddons { .. })
        ));
    }

    #[test]
    fn rejects_header_longer_than_the_limit() {
        // A 255-byte addons field made of one unknown length-delimited field.
        let mut addons = vec![0x1a];
        addons.extend_from_slice(&proto_varint(252));
        addons.extend_from_slice(&[0x00; 252]);
        assert_eq!(addons.len(), MAX_ADDONS_LEN);

        let destination = domain_destination(443, &"a".repeat(255));
        let input = request(&addons, Command::Tcp, Some(&destination), b"");
        assert!(matches!(
            RequestHeader::parse(&input),
            Err(VlessError::HeaderTooLarge {
                max: MAX_REQUEST_HEADER_LEN,
                ..
            })
        ));
    }

    #[test]
    fn encodes_response_header() {
        let mut out = vec![0xaa];
        ResponseHeader::new().encode(&mut out);
        assert_eq!(out, [0xaa, VLESS_VERSION, 0]);
        assert_eq!(ResponseHeader::new().to_bytes(), [VLESS_VERSION, 0]);
        assert_eq!(ResponseHeader::ENCODED_LEN, 2);

        let mut out = Vec::new();
        encode_response(&mut out);
        assert_eq!(out, [VLESS_VERSION, 0]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..=1024)) {
            let _ = RequestHeader::parse(&data);
            let _ = Addons::parse(&data);
        }

        #[test]
        fn mutated_valid_request_never_panics(index in 0usize..128, value in any::<u8>()) {
            let destination = ipv4_destination(443);
            let mut input = request(&vision_addons(), Command::Tcp, Some(&destination), b"body");
            if let Some(byte) = input.get_mut(index) {
                *byte = value;
            }
            let _ = RequestHeader::parse(&input);
        }
    }
}
