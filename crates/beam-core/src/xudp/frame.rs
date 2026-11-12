//! XUDP mux frame codec.
//!
//! XUDP is the mux frame format used by Xray and sing-box for UDP over a VLESS
//! stream (`v1.mux.cool`). The wire layout is:
//!
//! ```text
//! meta_len(2 BE) | session_id(2 BE) | status(1) | option(1)
//!     [network(1) | port(2 BE) | atyp(1) | address]
//!     [GlobalID(8)]
//!     [padding]
//! [payload_len(2 BE) | payload]
//! ```
//!
//! The address is present on every `New` frame. A `Keep` frame may carry an
//! address, but stock implementations only do so for a UDP source, so a
//! network byte other than UDP in a `Keep` frame is treated as padding.
//!
//! The payload length and payload are present only when the data option is
//! set. Frames with only the error option (normally an `End` frame) and
//! `KeepAlive` frames end after their metadata. This matches Xray's mux reader
//! and writer.
//!
//! Metadata is limited to [`MAX_METADATA_LEN`] bytes and a payload to
//! [`MAX_PAYLOAD_LEN`] bytes. Every length is checked before use. Trailing
//! metadata bytes after the last known field are padding and are ignored;
//! the encoder writes no padding.
//!
//! Parsing borrows the payload from the input. Addresses are materialized as
//! [`NetLocation`] because a domain name owns its string.

use std::fmt;

use crate::address::{AddressError, NetLocation};

/// Length of the metadata length prefix.
pub const METADATA_PREFIX_LEN: usize = 2;

/// Smallest metadata length: session id, status, and option.
pub const MIN_METADATA_LEN: usize = 4;

/// Largest accepted metadata length.
pub const MAX_METADATA_LEN: usize = 512;

/// Largest accepted payload length.
pub const MAX_PAYLOAD_LEN: usize = 8192;

/// Length of the optional XUDP global session id.
pub const GLOBAL_ID_LEN: usize = 8;

/// XUDP session status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionStatus {
    /// Create a session or reattach an existing global session.
    New = 0x01,
    /// Append data to an existing session.
    Keep = 0x02,
    /// Close a session.
    End = 0x03,
    /// Keep a session alive; any data is discarded by the caller.
    KeepAlive = 0x04,
}

impl SessionStatus {
    /// Decodes a status byte, rejecting values that are not defined by XUDP.
    pub const fn from_byte(byte: u8) -> Result<Self, XudpError> {
        match byte {
            0x01 => Ok(Self::New),
            0x02 => Ok(Self::Keep),
            0x03 => Ok(Self::End),
            0x04 => Ok(Self::KeepAlive),
            other => Err(XudpError::UnknownStatus(other)),
        }
    }

    /// Returns the wire byte for this status.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for SessionStatus {
    type Error = XudpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_byte(value)
    }
}

/// XUDP frame option bits.
///
/// Unknown bits are preserved so that a relay can pass a frame through
/// unchanged even if it does not understand every option.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FrameOption(pub u8);

impl FrameOption {
    /// A two-byte payload length and payload follow the metadata.
    pub const DATA: Self = Self(0x01);
    /// The session ended abnormally.
    pub const ERROR: Self = Self(0x02);

    /// Wraps a raw option byte, preserving every bit.
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the raw option byte.
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Returns `true` when the data option is set.
    pub const fn has_data(self) -> bool {
        self.0 & Self::DATA.0 != 0
    }

    /// Returns `true` when the error option is set.
    pub const fn has_error(self) -> bool {
        self.0 & Self::ERROR.0 != 0
    }
}

impl From<u8> for FrameOption {
    fn from(raw: u8) -> Self {
        Self(raw)
    }
}

/// Network of an XUDP destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TargetNetwork {
    /// Stream target.
    Tcp = 0x01,
    /// Datagram target.
    Udp = 0x02,
}

impl TargetNetwork {
    /// Decodes a network byte, rejecting values that are not defined by XUDP.
    pub const fn from_byte(byte: u8) -> Result<Self, XudpError> {
        match byte {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            other => Err(XudpError::UnknownNetwork(other)),
        }
    }

    /// Returns the wire byte for this network.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for TargetNetwork {
    type Error = XudpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_byte(value)
    }
}

/// A parsed XUDP frame borrowing its payload from the input buffer.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Client-assigned mux session id for a UDP flow.
    pub session_id: u16,
    /// Session status.
    pub status: SessionStatus,
    /// Option bits, including unknown bits.
    pub option: FrameOption,
    /// Target network, present when [`Frame::destination`] is present.
    pub network: Option<TargetNetwork>,
    /// Target or reply source address, when the frame carries one.
    pub destination: Option<NetLocation>,
    /// Global session id. An all-zero id on the wire is reported as `None`.
    pub global_id: Option<[u8; GLOBAL_ID_LEN]>,
    /// Payload bytes. Empty when the data option is not set.
    pub payload: &'a [u8],
}

// Payloads and global ids are user data and opaque session identifiers. Do not
// render them; this type is easy to log while debugging a relay.
impl fmt::Debug for Frame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("session_id", &self.session_id)
            .field("status", &self.status)
            .field("option", &self.option)
            .field("network", &self.network)
            .field("destination", &self.destination)
            .field("global_id", &self.global_id.map(|_| "<redacted>"))
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Values needed to encode one XUDP frame.
///
/// `destination` borrows the address so a server can encode each reply without
/// cloning the source. A destination requires a network; for `Keep` frames the
/// network must be UDP, because that is the only address form stock peers send.
#[derive(Clone, Copy)]
pub struct FrameSpec<'a> {
    /// Mux session id.
    pub session_id: u16,
    /// Session status.
    pub status: SessionStatus,
    /// Option bits, including unknown bits.
    pub option: FrameOption,
    /// Target network, required when a destination is present.
    pub network: Option<TargetNetwork>,
    /// Destination or reply source address.
    pub destination: Option<&'a NetLocation>,
    /// Optional global session id.
    pub global_id: Option<[u8; GLOBAL_ID_LEN]>,
    /// Payload bytes.
    pub payload: &'a [u8],
}

impl<'a> FrameSpec<'a> {
    /// Creates a metadata-only specification for `session_id` and `status`.
    pub const fn new(session_id: u16, status: SessionStatus) -> Self {
        Self {
            session_id,
            status,
            option: FrameOption(0),
            network: None,
            destination: None,
            global_id: None,
            payload: &[],
        }
    }

    /// Replaces the option bits.
    pub const fn with_option(mut self, option: FrameOption) -> Self {
        self.option = option;
        self
    }
}

/// Errors returned while parsing or encoding an XUDP frame.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum XudpError {
    /// The metadata length is outside [`MIN_METADATA_LEN`]..=[`MAX_METADATA_LEN`].
    #[error("XUDP metadata length {0} is outside {MIN_METADATA_LEN}..={MAX_METADATA_LEN}")]
    InvalidMetadataLength(usize),
    /// The status byte is not New, Keep, End, or KeepAlive.
    #[error("unknown XUDP session status 0x{0:02x}")]
    UnknownStatus(u8),
    /// The network byte is not TCP or UDP.
    #[error("unknown XUDP target network 0x{0:02x}")]
    UnknownNetwork(u8),
    /// Metadata ended inside a required field.
    #[error("truncated XUDP {field}")]
    Truncated {
        /// Name of the field that ended early.
        field: &'static str,
    },
    /// The destination address is malformed.
    #[error(transparent)]
    Address(#[from] AddressError),
    /// The declared payload exceeds [`MAX_PAYLOAD_LEN`].
    #[error("XUDP payload length {0} exceeds the {MAX_PAYLOAD_LEN}-byte limit")]
    PayloadTooLarge(usize),
    /// A New frame was encoded without a destination.
    #[error("a New XUDP frame requires a destination")]
    MissingDestination,
    /// A destination was encoded without a network.
    #[error("an XUDP destination requires a target network")]
    MissingNetwork,
    /// Only Keep frames with a UDP destination may carry an address.
    #[error("an XUDP Keep destination must use the UDP network")]
    InvalidNetworkForStatus,
    /// The status cannot carry a destination.
    #[error("a {0:?} XUDP frame cannot carry a destination")]
    UnexpectedDestination(SessionStatus),
    /// A network was supplied without a destination, or the status forbids one.
    #[error("unexpected XUDP target network for this session status")]
    UnexpectedNetwork,
    /// A global id was supplied on a frame other than New+Data+UDP.
    #[error("a GlobalID is only valid on a New+Data+UDP XUDP frame")]
    UnexpectedGlobalId,
    /// Payload bytes were supplied without the data option.
    #[error("an XUDP frame without the Data option cannot carry a payload")]
    PayloadWithoutData,
}

/// Parses one XUDP frame from `input`.
///
/// Returns `Ok(None)` when more bytes are required, `Ok(Some((frame, used)))`
/// for a complete frame, where `used` is the number of bytes consumed, or an
/// error for a value that can never become valid.
///
/// A frame without the data option ends after its metadata; there is no
/// two-byte payload length in that case. Trailing metadata bytes after the
/// last known field are ignored as padding.
pub fn parse_frame(input: &[u8]) -> Result<Option<(Frame<'_>, usize)>, XudpError> {
    let Some((length_bytes, _)) = input.split_first_chunk::<METADATA_PREFIX_LEN>() else {
        return Ok(None);
    };
    let metadata_len = usize::from(u16::from_be_bytes(*length_bytes));
    if !(MIN_METADATA_LEN..=MAX_METADATA_LEN).contains(&metadata_len) {
        return Err(XudpError::InvalidMetadataLength(metadata_len));
    }

    let metadata_end = METADATA_PREFIX_LEN + metadata_len;
    let Some(metadata) = input.get(METADATA_PREFIX_LEN..metadata_end) else {
        return Ok(None);
    };

    let (session_bytes, rest) = metadata
        .split_first_chunk::<2>()
        .ok_or(XudpError::Truncated {
            field: "session id",
        })?;
    let session_id = u16::from_be_bytes(*session_bytes);

    let (&status_byte, rest) = rest
        .split_first()
        .ok_or(XudpError::Truncated { field: "status" })?;
    let status = SessionStatus::from_byte(status_byte)?;

    let (&option_byte, mut rest) = rest
        .split_first()
        .ok_or(XudpError::Truncated { field: "option" })?;
    let option = FrameOption(option_byte);

    let mut network = None;
    let mut destination = None;
    match status {
        SessionStatus::New => {
            let (target_network, target, remaining) = parse_target(rest)?;
            network = Some(target_network);
            destination = Some(target);
            rest = remaining;
        }
        SessionStatus::Keep => {
            // Stock peers only attach an address to a Keep when its network
            // byte is UDP. Anything else is padding.
            if let Some((&first, _)) = rest.split_first()
                && first == TargetNetwork::Udp.as_byte()
            {
                let (target_network, target, remaining) = parse_target(rest)?;
                network = Some(target_network);
                destination = Some(target);
                rest = remaining;
            }
        }
        SessionStatus::End | SessionStatus::KeepAlive => {}
    }

    let global_id =
        if status == SessionStatus::New && option.has_data() && network == Some(TargetNetwork::Udp)
        {
            match rest.split_first_chunk::<GLOBAL_ID_LEN>() {
                Some((bytes, _)) if bytes.iter().any(|&byte| byte != 0) => Some(*bytes),
                _ => None,
            }
        } else {
            None
        };

    let mut offset = metadata_end;
    let payload = if option.has_data() {
        let Some((payload_length_bytes, _)) = input
            .get(offset..)
            .and_then(|remaining| remaining.split_first_chunk::<2>())
        else {
            return Ok(None);
        };
        let payload_len = usize::from(u16::from_be_bytes(*payload_length_bytes));
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(XudpError::PayloadTooLarge(payload_len));
        }
        offset += 2;
        let Some(payload) = input.get(offset..offset + payload_len) else {
            return Ok(None);
        };
        offset += payload_len;
        payload
    } else {
        &[]
    };

    Ok(Some((
        Frame {
            session_id,
            status,
            option,
            network,
            destination,
            global_id,
            payload,
        },
        offset,
    )))
}

fn parse_target(input: &[u8]) -> Result<(TargetNetwork, NetLocation, &[u8]), XudpError> {
    let (&network_byte, rest) = input.split_first().ok_or(XudpError::Truncated {
        field: "target network",
    })?;
    let network = TargetNetwork::from_byte(network_byte)?;
    let (destination, rest) = NetLocation::parse_port_address(rest)?;
    Ok((network, destination, rest))
}

/// Encodes one XUDP frame and appends it to `out`.
///
/// Nothing is appended when the frame is rejected. No padding is written.
/// The payload length field is written only when [`FrameSpec::option`] has the
/// data bit set.
///
/// A `New` frame requires a destination and network. A `Keep` frame may carry
/// a destination, but only with the UDP network. `End` and `KeepAlive` frames
/// carry neither. A nonzero global id is accepted only on a `New+Data+UDP`
/// frame, matching Xray.
pub fn encode_frame(out: &mut Vec<u8>, spec: FrameSpec<'_>) -> Result<(), XudpError> {
    let start = out.len();
    let result = encode_frame_inner(out, spec);
    if result.is_err() {
        out.truncate(start);
    }
    result
}

fn encode_frame_inner(out: &mut Vec<u8>, spec: FrameSpec<'_>) -> Result<(), XudpError> {
    let global_id = spec.global_id.filter(|id| id.iter().any(|&byte| byte != 0));

    match spec.status {
        SessionStatus::New => {
            if spec.destination.is_none() {
                return Err(XudpError::MissingDestination);
            }
            if spec.network.is_none() {
                return Err(XudpError::MissingNetwork);
            }
        }
        SessionStatus::Keep => match (spec.destination, spec.network) {
            (Some(_), None) => return Err(XudpError::MissingNetwork),
            (Some(_), Some(TargetNetwork::Udp)) => {}
            (Some(_), Some(TargetNetwork::Tcp)) => {
                return Err(XudpError::InvalidNetworkForStatus);
            }
            (None, Some(_)) => return Err(XudpError::UnexpectedNetwork),
            (None, None) => {}
        },
        SessionStatus::End | SessionStatus::KeepAlive => {
            if spec.destination.is_some() {
                return Err(XudpError::UnexpectedDestination(spec.status));
            }
            if spec.network.is_some() {
                return Err(XudpError::UnexpectedNetwork);
            }
        }
    }

    if global_id.is_some()
        && !(spec.status == SessionStatus::New
            && spec.option.has_data()
            && spec.network == Some(TargetNetwork::Udp))
    {
        return Err(XudpError::UnexpectedGlobalId);
    }

    if !spec.option.has_data() && !spec.payload.is_empty() {
        return Err(XudpError::PayloadWithoutData);
    }
    if spec.payload.len() > MAX_PAYLOAD_LEN {
        return Err(XudpError::PayloadTooLarge(spec.payload.len()));
    }

    out.extend_from_slice(&[0, 0]);
    let metadata_start = out.len();
    out.extend_from_slice(&spec.session_id.to_be_bytes());
    out.push(spec.status.as_byte());
    out.push(spec.option.raw());

    if let (Some(network), Some(destination)) = (spec.network, spec.destination) {
        out.push(network.as_byte());
        destination.encode(out)?;
    }
    if let Some(global_id) = global_id {
        out.extend_from_slice(&global_id);
    }

    let metadata_len = out.len() - metadata_start;
    if !(MIN_METADATA_LEN..=MAX_METADATA_LEN).contains(&metadata_len) {
        return Err(XudpError::InvalidMetadataLength(metadata_len));
    }
    let metadata_len =
        u16::try_from(metadata_len).map_err(|_| XudpError::InvalidMetadataLength(metadata_len))?;
    let prefix_start = metadata_start - METADATA_PREFIX_LEN;
    out[prefix_start..metadata_start].copy_from_slice(&metadata_len.to_be_bytes());

    if spec.option.has_data() {
        let payload_len = u16::try_from(spec.payload.len())
            .map_err(|_| XudpError::PayloadTooLarge(spec.payload.len()))?;
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(spec.payload);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Frame, FrameOption, FrameSpec, GLOBAL_ID_LEN, MAX_METADATA_LEN, MAX_PAYLOAD_LEN,
        MIN_METADATA_LEN, SessionStatus, TargetNetwork, XudpError, encode_frame, parse_frame,
    };
    use crate::address::{Address, AddressError, NetLocation};
    use std::net::{Ipv4Addr, Ipv6Addr};

    const TEST_SESSION_ID: u16 = 0x0102;
    const TEST_GLOBAL_ID: [u8; GLOBAL_ID_LEN] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];

    fn ipv4(port: u16) -> NetLocation {
        NetLocation {
            address: Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            port,
        }
    }

    fn ipv6(port: u16) -> NetLocation {
        NetLocation {
            address: Address::Ipv6(Ipv6Addr::LOCALHOST),
            port,
        }
    }

    fn domain(port: u16) -> NetLocation {
        NetLocation {
            address: Address::Domain("example.com".to_owned()),
            port,
        }
    }

    fn encoded(spec: FrameSpec<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        encode_frame(&mut out, spec).expect("frame must encode");
        out
    }

    fn parsed(input: &[u8]) -> (Frame<'_>, usize) {
        parse_frame(input)
            .expect("frame must not be rejected")
            .expect("frame must be complete")
    }

    fn patch_metadata_len(bytes: &mut [u8]) {
        let metadata_len = u16::try_from(bytes.len() - 2).expect("metadata length fits in u16");
        bytes[..2].copy_from_slice(&metadata_len.to_be_bytes());
    }

    #[test]
    fn constants_match_the_wire() {
        assert_eq!(SessionStatus::New.as_byte(), 0x01);
        assert_eq!(SessionStatus::Keep.as_byte(), 0x02);
        assert_eq!(SessionStatus::End.as_byte(), 0x03);
        assert_eq!(SessionStatus::KeepAlive.as_byte(), 0x04);
        assert_eq!(SessionStatus::from_byte(0x01), Ok(SessionStatus::New));
        assert_eq!(SessionStatus::from_byte(0x02), Ok(SessionStatus::Keep));
        assert_eq!(SessionStatus::from_byte(0x03), Ok(SessionStatus::End));
        assert_eq!(SessionStatus::from_byte(0x04), Ok(SessionStatus::KeepAlive));
        assert_eq!(
            SessionStatus::from_byte(0x00),
            Err(XudpError::UnknownStatus(0x00))
        );
        assert_eq!(
            SessionStatus::from_byte(0x05),
            Err(XudpError::UnknownStatus(0x05))
        );
        assert_eq!(SessionStatus::try_from(0x02), Ok(SessionStatus::Keep));

        assert_eq!(TargetNetwork::Tcp.as_byte(), 0x01);
        assert_eq!(TargetNetwork::Udp.as_byte(), 0x02);
        assert_eq!(TargetNetwork::from_byte(0x01), Ok(TargetNetwork::Tcp));
        assert_eq!(TargetNetwork::from_byte(0x02), Ok(TargetNetwork::Udp));
        assert_eq!(
            TargetNetwork::from_byte(0x03),
            Err(XudpError::UnknownNetwork(0x03))
        );

        assert_eq!(FrameOption::DATA.raw(), 0x01);
        assert_eq!(FrameOption::ERROR.raw(), 0x02);
        assert!(FrameOption::DATA.has_data());
        assert!(!FrameOption::DATA.has_error());
        assert!(FrameOption::ERROR.has_error());
        assert!(!FrameOption::ERROR.has_data());

        let unknown = FrameOption(0x80);
        assert_eq!(unknown.raw(), 0x80);
        assert!(!unknown.has_data());
        assert!(!unknown.has_error());

        let combined = FrameOption(0x83);
        assert!(combined.has_data());
        assert!(combined.has_error());
        assert_eq!(combined.raw(), 0x83);
        assert_eq!(FrameOption::from(0x81), FrameOption(0x81));
    }

    #[test]
    fn parses_new_ipv4() {
        let destination = ipv4(443);
        let bytes = encoded(FrameSpec {
            session_id: TEST_SESSION_ID,
            status: SessionStatus::New,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(&destination),
            global_id: None,
            payload: b"hello",
        });

        let (frame, used) = parsed(&bytes);

        assert_eq!(used, bytes.len());
        assert_eq!(frame.session_id, TEST_SESSION_ID);
        assert_eq!(frame.status, SessionStatus::New);
        assert_eq!(frame.option, FrameOption::DATA);
        assert_eq!(frame.network, Some(TargetNetwork::Udp));
        assert_eq!(frame.destination.as_ref(), Some(&destination));
        assert_eq!(frame.global_id, None);
        assert_eq!(frame.payload, b"hello");
    }

    #[test]
    fn parses_new_domain() {
        let destination = domain(53);
        let bytes = encoded(FrameSpec {
            session_id: 7,
            status: SessionStatus::New,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Tcp),
            destination: Some(&destination),
            global_id: None,
            payload: b"dns",
        });

        let (frame, used) = parsed(&bytes);

        assert_eq!(used, bytes.len());
        assert_eq!(frame.status, SessionStatus::New);
        assert_eq!(frame.network, Some(TargetNetwork::Tcp));
        assert_eq!(frame.destination.as_ref(), Some(&destination));
        assert_eq!(frame.global_id, None);
        assert_eq!(frame.payload, b"dns");
    }

    #[test]
    fn parses_new_ipv6() {
        let destination = ipv6(8443);
        let bytes = encoded(FrameSpec {
            session_id: 9,
            status: SessionStatus::New,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(&destination),
            global_id: Some(TEST_GLOBAL_ID),
            payload: b"v6",
        });

        let (frame, used) = parsed(&bytes);

        assert_eq!(used, bytes.len());
        assert_eq!(frame.network, Some(TargetNetwork::Udp));
        assert_eq!(frame.destination.as_ref(), Some(&destination));
        assert_eq!(frame.global_id, Some(TEST_GLOBAL_ID));
        assert_eq!(frame.payload, b"v6");
    }

    #[test]
    fn parses_keep_with_and_without_destination() {
        let destination = ipv6(5353);
        let with_destination = encoded(FrameSpec {
            session_id: 11,
            status: SessionStatus::Keep,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(&destination),
            global_id: None,
            payload: b"reply",
        });
        let (frame, used) = parsed(&with_destination);
        assert_eq!(used, with_destination.len());
        assert_eq!(frame.status, SessionStatus::Keep);
        assert_eq!(frame.network, Some(TargetNetwork::Udp));
        assert_eq!(frame.destination.as_ref(), Some(&destination));
        assert_eq!(frame.payload, b"reply");

        let without_destination = encoded(FrameSpec {
            session_id: 11,
            status: SessionStatus::Keep,
            option: FrameOption::DATA,
            network: None,
            destination: None,
            global_id: None,
            payload: b"more",
        });
        let (frame, used) = parsed(&without_destination);
        assert_eq!(used, without_destination.len());
        assert_eq!(frame.status, SessionStatus::Keep);
        assert_eq!(frame.network, None);
        assert_eq!(frame.destination, None);
        assert_eq!(frame.payload, b"more");

        let metadata_only = encoded(FrameSpec::new(11, SessionStatus::Keep));
        let (frame, used) = parsed(&metadata_only);
        assert_eq!(used, metadata_only.len());
        assert_eq!(frame.network, None);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn parses_end_keepalive_and_error_option() {
        let end = encoded(FrameSpec::new(7, SessionStatus::End));
        assert_eq!(end, [0x00, 0x04, 0x00, 0x07, 0x03, 0x00]);
        let (frame, used) = parsed(&end);
        assert_eq!(used, end.len());
        assert_eq!(frame.status, SessionStatus::End);
        assert_eq!(frame.option, FrameOption(0));
        assert!(frame.payload.is_empty());

        let error = encoded(FrameSpec {
            option: FrameOption::ERROR,
            ..FrameSpec::new(7, SessionStatus::End)
        });
        assert_eq!(error, [0x00, 0x04, 0x00, 0x07, 0x03, 0x02]);
        let (frame, used) = parsed(&error);
        assert_eq!(used, error.len());
        assert_eq!(frame.status, SessionStatus::End);
        assert!(frame.option.has_error());
        assert!(!frame.option.has_data());
        assert!(frame.payload.is_empty());

        let keep_alive = encoded(FrameSpec::new(7, SessionStatus::KeepAlive));
        assert_eq!(keep_alive, [0x00, 0x04, 0x00, 0x07, 0x04, 0x00]);
        let (frame, used) = parsed(&keep_alive);
        assert_eq!(used, keep_alive.len());
        assert_eq!(frame.status, SessionStatus::KeepAlive);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn exact_new_frame_layout() {
        let destination = ipv4(443);
        let bytes = encoded(FrameSpec {
            session_id: TEST_SESSION_ID,
            status: SessionStatus::New,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(&destination),
            global_id: Some(TEST_GLOBAL_ID),
            payload: b"abc",
        });

        let expected = [
            0x00, 0x14, // metadata length: 20
            0x01, 0x02, // session id
            0x01, // New
            0x01, // Data
            0x02, // UDP
            0x01, 0xbb, // port 443
            0x01, // address type IPv4
            0xc0, 0x00, 0x02, 0x01, // 192.0.2.1
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // global id
            0x00, 0x03, // payload length
            0x61, 0x62, 0x63, // payload
        ];
        assert_eq!(bytes, expected);

        let (frame, used) = parsed(&bytes);
        assert_eq!(used, expected.len());
        assert_eq!(frame.destination.as_ref(), Some(&destination));
        assert_eq!(frame.global_id, Some(TEST_GLOBAL_ID));
        assert_eq!(frame.payload, b"abc");
    }

    #[test]
    fn exact_keep_frame_layout() {
        let bytes = encoded(FrameSpec {
            session_id: 7,
            status: SessionStatus::Keep,
            option: FrameOption::DATA,
            network: None,
            destination: None,
            global_id: None,
            payload: b"abc",
        });

        let expected = [
            0x00, 0x04, // metadata length
            0x00, 0x07, // session id
            0x02, // Keep
            0x01, // Data
            0x00, 0x03, // payload length
            0x61, 0x62, 0x63, // payload
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn parses_global_id_only_on_new_data_udp() {
        let destination = ipv4(53);

        let with_id = encoded(FrameSpec {
            session_id: 1,
            status: SessionStatus::New,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(&destination),
            global_id: Some(TEST_GLOBAL_ID),
            payload: b"q",
        });
        let (frame, _) = parsed(&with_id);
        assert_eq!(frame.global_id, Some(TEST_GLOBAL_ID));

        // A zero id means no global session. Build it by hand because the
        // encoder omits all-zero ids.
        let mut zero_id = vec![0, 0];
        zero_id.extend_from_slice(&[0x00, 0x01]); // session id
        zero_id.extend_from_slice(&[0x01, 0x01]); // New + Data
        zero_id.push(TargetNetwork::Udp.as_byte());
        zero_id.extend_from_slice(&53_u16.to_be_bytes());
        zero_id.push(0x01);
        zero_id.extend_from_slice(&[192, 0, 2, 1]);
        zero_id.extend_from_slice(&[0; GLOBAL_ID_LEN]);
        patch_metadata_len(&mut zero_id);
        zero_id.extend_from_slice(&0_u16.to_be_bytes());
        let (frame, used) = parsed(&zero_id);
        assert_eq!(used, zero_id.len());
        assert_eq!(frame.global_id, None);
        assert_eq!(frame.destination.as_ref(), Some(&destination));

        // Without the Data option, trailing bytes are padding, not a GlobalID.
        let mut no_data = vec![0, 0];
        no_data.extend_from_slice(&[0x00, 0x01]); // session id
        no_data.extend_from_slice(&[0x01, 0x00]); // New, no option
        no_data.push(TargetNetwork::Udp.as_byte());
        no_data.extend_from_slice(&53_u16.to_be_bytes());
        no_data.push(0x01);
        no_data.extend_from_slice(&[127, 0, 0, 1]);
        no_data.extend_from_slice(&TEST_GLOBAL_ID);
        patch_metadata_len(&mut no_data);
        let (frame, used) = parsed(&no_data);
        assert_eq!(used, no_data.len());
        assert_eq!(frame.global_id, None);
        assert_eq!(frame.payload, b"");

        // A TCP New frame never carries a GlobalID; the same bytes are padding.
        let mut tcp = vec![0, 0];
        tcp.extend_from_slice(&[0x00, 0x01]); // session id
        tcp.extend_from_slice(&[0x01, 0x01]); // New + Data
        tcp.push(TargetNetwork::Tcp.as_byte());
        tcp.extend_from_slice(&80_u16.to_be_bytes());
        tcp.push(0x01);
        tcp.extend_from_slice(&[127, 0, 0, 1]);
        tcp.extend_from_slice(&TEST_GLOBAL_ID);
        patch_metadata_len(&mut tcp);
        tcp.extend_from_slice(&0_u16.to_be_bytes());
        let (frame, used) = parsed(&tcp);
        assert_eq!(used, tcp.len());
        assert_eq!(frame.network, Some(TargetNetwork::Tcp));
        assert_eq!(frame.global_id, None);
    }

    #[test]
    fn accepts_trailing_metadata_padding() {
        // End metadata with three padding bytes.
        let end = [
            0x00, 0x07, // metadata length
            0x00, 0x01, // session id
            0x03, // End
            0x00, // no option
            0xaa, 0xbb, 0xcc, // padding
        ];
        let (frame, used) = parsed(&end);
        assert_eq!(used, end.len());
        assert_eq!(frame.status, SessionStatus::End);
        assert!(frame.payload.is_empty());

        // New frame with padding after the address.
        let mut new = vec![0, 0];
        new.extend_from_slice(&[0x00, 0x01]); // session id
        new.extend_from_slice(&[0x01, 0x00]); // New, no option
        new.push(TargetNetwork::Tcp.as_byte());
        new.extend_from_slice(&80_u16.to_be_bytes());
        new.push(0x01);
        new.extend_from_slice(&[127, 0, 0, 1]);
        new.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        patch_metadata_len(&mut new);
        let (frame, used) = parsed(&new);
        assert_eq!(used, new.len());
        assert_eq!(
            frame.destination,
            Some(NetLocation {
                address: Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 80,
            })
        );

        // A Keep whose first trailing byte is not UDP is also padding.
        let keep = [
            0x00, 0x06, // metadata length
            0x00, 0x01, // session id
            0x02, // Keep
            0x01, // Data
            0x11, 0x22, // padding
            0x00, 0x00, // payload length
        ];
        let (frame, used) = parsed(&keep);
        assert_eq!(used, keep.len());
        assert_eq!(frame.network, None);
        assert_eq!(frame.destination, None);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn rejects_invalid_metadata_lengths() {
        assert_eq!(parse_frame(&[]), Ok(None));
        assert_eq!(parse_frame(&[0x00]), Ok(None));
        assert_eq!(
            parse_frame(&[0x00, 0x00]),
            Err(XudpError::InvalidMetadataLength(0))
        );
        assert_eq!(
            parse_frame(&[0x00, 0x03]),
            Err(XudpError::InvalidMetadataLength(MIN_METADATA_LEN - 1))
        );
        assert_eq!(
            parse_frame(&[0x02, 0x01]),
            Err(XudpError::InvalidMetadataLength(MAX_METADATA_LEN + 1))
        );

        // A complete frame with the maximum metadata length is accepted; the
        // unused bytes are padding.
        let mut maximum = vec![0, 0];
        maximum.extend_from_slice(&[0x00, 0x01]); // session id
        maximum.extend_from_slice(&[0x03, 0x01]); // End + Data
        maximum.resize(2 + MAX_METADATA_LEN, 0xaa);
        patch_metadata_len(&mut maximum);
        maximum.extend_from_slice(&0_u16.to_be_bytes());
        let (frame, used) = parsed(&maximum);
        assert_eq!(used, maximum.len());
        assert_eq!(frame.status, SessionStatus::End);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn rejects_payload_overflow() {
        let mut frame = vec![
            0x00, 0x04, // metadata length
            0x00, 0x01, // session id
            0x02, 0x01, // Keep + Data
        ];
        frame.extend_from_slice(&[0x20, 0x01]); // 8193
        assert_eq!(
            parse_frame(&frame),
            Err(XudpError::PayloadTooLarge(MAX_PAYLOAD_LEN + 1))
        );

        let payload = vec![0x5a; MAX_PAYLOAD_LEN + 1];
        let mut out = b"prefix".to_vec();
        assert_eq!(
            encode_frame(
                &mut out,
                FrameSpec {
                    payload: &payload,
                    ..FrameSpec::new(1, SessionStatus::Keep).with_option(FrameOption::DATA)
                }
            ),
            Err(XudpError::PayloadTooLarge(MAX_PAYLOAD_LEN + 1))
        );
        assert_eq!(out, b"prefix");
    }

    #[test]
    fn accepts_maximum_payload() {
        let payload = vec![0x5a; MAX_PAYLOAD_LEN];
        let bytes = encoded(FrameSpec {
            payload: &payload,
            ..FrameSpec::new(1, SessionStatus::Keep).with_option(FrameOption::DATA)
        });
        assert_eq!(bytes.len(), 2 + MIN_METADATA_LEN + 2 + MAX_PAYLOAD_LEN);

        let (frame, used) = parsed(&bytes);
        assert_eq!(used, bytes.len());
        assert_eq!(frame.payload, payload.as_slice());
    }

    #[test]
    fn every_prefix_needs_more_data() {
        let destination = ipv4(443);
        let new = encoded(FrameSpec {
            session_id: TEST_SESSION_ID,
            status: SessionStatus::New,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(&destination),
            global_id: Some(TEST_GLOBAL_ID),
            payload: b"truncate me",
        });
        for end in 0..new.len() {
            assert!(
                matches!(parse_frame(&new[..end]), Ok(None)),
                "a {end}-byte prefix of a data frame must ask for more data"
            );
        }
        assert!(matches!(parse_frame(&new), Ok(Some(_))));

        let error = encoded(FrameSpec {
            option: FrameOption::ERROR,
            ..FrameSpec::new(7, SessionStatus::End)
        });
        for end in 0..error.len() {
            assert!(
                matches!(parse_frame(&error[..end]), Ok(None)),
                "a {end}-byte prefix of an error frame must ask for more data"
            );
        }
        assert!(matches!(parse_frame(&error), Ok(Some(_))));
    }

    #[test]
    fn parses_back_to_back_frames() {
        let first = encoded(FrameSpec {
            session_id: 1,
            status: SessionStatus::Keep,
            option: FrameOption::DATA,
            network: None,
            destination: None,
            global_id: None,
            payload: b"one",
        });
        let second = encoded(FrameSpec::new(1, SessionStatus::End));
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let (frame, used) = parsed(&stream);
        assert_eq!(frame.payload, b"one");
        assert_eq!(used, first.len());

        let (frame, used_second) = parsed(&stream[used..]);
        assert_eq!(frame.status, SessionStatus::End);
        assert_eq!(used + used_second, stream.len());
    }

    #[test]
    fn round_trips_server_reply_shapes() {
        let ipv4_destination = ipv4(53);
        let ipv6_destination = ipv6(443);
        let domain_destination = domain(8080);

        let specs = [
            FrameSpec {
                session_id: 1,
                status: SessionStatus::New,
                option: FrameOption::DATA,
                network: Some(TargetNetwork::Udp),
                destination: Some(&ipv4_destination),
                global_id: Some(TEST_GLOBAL_ID),
                payload: b"new",
            },
            FrameSpec {
                session_id: 2,
                status: SessionStatus::New,
                option: FrameOption::DATA,
                network: Some(TargetNetwork::Tcp),
                destination: Some(&domain_destination),
                global_id: None,
                payload: b"tcp",
            },
            FrameSpec {
                session_id: 3,
                status: SessionStatus::Keep,
                option: FrameOption::DATA,
                network: Some(TargetNetwork::Udp),
                destination: Some(&ipv6_destination),
                global_id: None,
                payload: b"reply",
            },
            FrameSpec {
                session_id: 4,
                status: SessionStatus::Keep,
                option: FrameOption::DATA,
                network: None,
                destination: None,
                global_id: None,
                payload: b"more",
            },
            FrameSpec::new(5, SessionStatus::Keep),
            FrameSpec {
                option: FrameOption::ERROR,
                ..FrameSpec::new(6, SessionStatus::End)
            },
            FrameSpec::new(7, SessionStatus::End),
            FrameSpec::new(8, SessionStatus::KeepAlive),
        ];

        for spec in specs {
            let bytes = encoded(spec);
            let (frame, used) = parsed(&bytes);
            assert_eq!(used, bytes.len());
            assert_eq!(frame.session_id, spec.session_id);
            assert_eq!(frame.status, spec.status);
            assert_eq!(frame.option, spec.option);
            assert_eq!(frame.network, spec.network);
            assert_eq!(frame.destination.as_ref(), spec.destination);
            assert_eq!(
                frame.global_id,
                spec.global_id.filter(|id| id.iter().any(|&byte| byte != 0))
            );
            assert_eq!(frame.payload, spec.payload);
        }
    }

    #[test]
    fn preserves_unknown_option_bits() {
        let bytes = encoded(FrameSpec {
            option: FrameOption(0x81),
            ..FrameSpec::new(3, SessionStatus::Keep)
        });
        let (frame, used) = parsed(&bytes);
        assert_eq!(used, bytes.len());
        assert_eq!(frame.option.raw(), 0x81);
        assert!(frame.option.has_data());
        assert!(!frame.option.has_error());
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn rejects_invalid_encoder_combinations() {
        let destination = ipv4(53);
        let cases = [
            (
                FrameSpec::new(1, SessionStatus::New),
                XudpError::MissingDestination,
            ),
            (
                FrameSpec {
                    network: Some(TargetNetwork::Udp),
                    ..FrameSpec::new(1, SessionStatus::New)
                },
                XudpError::MissingDestination,
            ),
            (
                FrameSpec {
                    destination: Some(&destination),
                    ..FrameSpec::new(1, SessionStatus::New)
                },
                XudpError::MissingNetwork,
            ),
            (
                FrameSpec {
                    status: SessionStatus::Keep,
                    network: Some(TargetNetwork::Tcp),
                    destination: Some(&destination),
                    ..FrameSpec::new(1, SessionStatus::Keep)
                },
                XudpError::InvalidNetworkForStatus,
            ),
            (
                FrameSpec {
                    network: Some(TargetNetwork::Udp),
                    ..FrameSpec::new(1, SessionStatus::Keep)
                },
                XudpError::UnexpectedNetwork,
            ),
            (
                FrameSpec {
                    destination: Some(&destination),
                    network: Some(TargetNetwork::Udp),
                    ..FrameSpec::new(1, SessionStatus::End)
                },
                XudpError::UnexpectedDestination(SessionStatus::End),
            ),
            (
                FrameSpec {
                    network: Some(TargetNetwork::Udp),
                    ..FrameSpec::new(1, SessionStatus::KeepAlive)
                },
                XudpError::UnexpectedNetwork,
            ),
            (
                FrameSpec {
                    global_id: Some(TEST_GLOBAL_ID),
                    ..FrameSpec::new(1, SessionStatus::Keep)
                },
                XudpError::UnexpectedGlobalId,
            ),
            (
                FrameSpec {
                    payload: b"x",
                    ..FrameSpec::new(1, SessionStatus::End)
                },
                XudpError::PayloadWithoutData,
            ),
        ];

        for (spec, expected) in cases {
            let mut out = b"prefix".to_vec();
            assert_eq!(encode_frame(&mut out, spec), Err(expected));
            assert_eq!(out, b"prefix");
        }
    }

    #[test]
    fn rejects_oversized_address_on_encode() {
        let destination = NetLocation {
            address: Address::Domain("a".repeat(256)),
            port: 53,
        };
        let mut out = b"prefix".to_vec();
        assert_eq!(
            encode_frame(
                &mut out,
                FrameSpec {
                    session_id: 1,
                    status: SessionStatus::New,
                    option: FrameOption::DATA,
                    network: Some(TargetNetwork::Udp),
                    destination: Some(&destination),
                    global_id: None,
                    payload: b"x",
                }
            ),
            Err(XudpError::Address(AddressError::InvalidDomainLength(256)))
        );
        assert_eq!(out, b"prefix");
    }

    #[test]
    fn rejects_truncated_and_unknown_target_fields() {
        // New with metadata that ends before the target network.
        assert_eq!(
            parse_frame(&[0x00, 0x04, 0x00, 0x01, 0x01, 0x00]),
            Err(XudpError::Truncated {
                field: "target network"
            })
        );

        // New with a valid network but no port.
        assert_eq!(
            parse_frame(&[0x00, 0x05, 0x00, 0x01, 0x01, 0x00, 0x01]),
            Err(XudpError::Address(AddressError::Truncated))
        );

        // Unknown network byte.
        assert_eq!(
            parse_frame(&[0x00, 0x05, 0x00, 0x01, 0x01, 0x00, 0x03]),
            Err(XudpError::UnknownNetwork(0x03))
        );

        // A Keep with a UDP network byte is a destination and must parse.
        assert_eq!(
            parse_frame(&[0x00, 0x05, 0x00, 0x01, 0x02, 0x00, 0x02]),
            Err(XudpError::Address(AddressError::Truncated))
        );
    }
}
