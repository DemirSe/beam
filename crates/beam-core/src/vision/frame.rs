//! XTLS Vision block framing.
//!
//! A block is laid out as:
//!
//! ```text
//! [UUID(16) first block only] | command(1) | content_len(2 BE) |
//! padding_len(2 BE) | content | zero padding
//! ```
//!
//! Padding is not part of the content and its value is ignored on receive.
//! The stock writer clamps `content_len + padding_len` to `8192 - 21`, so a
//! complete block, UUID prefix included, never exceeds [`MAX_BLOCK_LEN`].

use std::fmt;

/// Length of the raw UUID prefix carried by the first block of a direction.
pub const UUID_LEN: usize = 16;

/// Length of `command(1) | content_len(2) | padding_len(2)`.
pub const BLOCK_HEADER_LEN: usize = 5;

/// Largest complete Vision block, including the UUID prefix and padding.
pub const MAX_BLOCK_LEN: usize = 8192;

/// Maximum combined content and padding.
///
/// The stock writer reserves the 21-byte first-block header even for blocks
/// without a UUID, so this limit applies to every block. A first block can
/// therefore fill [`MAX_BLOCK_LEN`] exactly.
pub const MAX_PAYLOAD_LEN: usize = MAX_BLOCK_LEN - UUID_LEN - BLOCK_HEADER_LEN;

/// Largest content field that can appear in a valid block.
pub const MAX_CONTENT_LEN: usize = MAX_PAYLOAD_LEN;

/// Vision block command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Another block follows; padding continues.
    Continue = 0x00,
    /// Stop padding; the remaining bytes stay inside the outer transport.
    End = 0x01,
    /// Stop padding; the outer TLS/REALITY layer is bypassed.
    Direct = 0x02,
}

impl Command {
    /// Decodes a command byte, rejecting values that are not defined by Vision.
    pub const fn from_byte(byte: u8) -> Result<Self, VisionError> {
        match byte {
            0x00 => Ok(Self::Continue),
            0x01 => Ok(Self::End),
            0x02 => Ok(Self::Direct),
            other => Err(VisionError::UnknownCommand(other)),
        }
    }

    /// Returns the wire byte for this command.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// A parsed Vision block borrowing its content from the input buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Block<'a> {
    /// Raw UUID prefix, present only on the first block of a direction.
    pub uuid: Option<[u8; UUID_LEN]>,
    /// Block command.
    pub command: Command,
    /// Content bytes, with padding stripped.
    pub content: &'a [u8],
    /// Number of padding bytes that followed the content.
    pub padding_len: u16,
}

// Never render the UUID or payload: both are sensitive and this type is easy to
// log by accident while debugging a relay.
impl fmt::Debug for Block<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Block")
            .field("uuid", &self.uuid.map(|_| "<redacted>"))
            .field("command", &self.command)
            .field("content_len", &self.content.len())
            .field("padding_len", &self.padding_len)
            .finish()
    }
}

/// Errors returned while parsing or encoding a Vision block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VisionError {
    /// The command byte is not Continue, End, or Direct.
    #[error("unknown Vision command 0x{0:02x}")]
    UnknownCommand(u8),
    /// Content is longer than the 16-bit `content_len` field can represent.
    #[error("Vision content length {0} does not fit the 16-bit length field")]
    ContentTooLong(usize),
    /// Content plus padding is larger than the stock writer's clamp.
    #[error("Vision content and padding length {0} exceeds the {MAX_PAYLOAD_LEN}-byte limit")]
    PayloadTooLarge(usize),
}

/// Parses one Vision block from `input`.
///
/// `first` must be `true` only for the first block of a direction. In that
/// case the leading [`UUID_LEN`] bytes are returned as [`Block::uuid`]; later
/// blocks never carry a UUID and their first bytes are always the command.
/// Callers must establish that the stream is framed (the raw UUID prefix was
/// matched) before passing `first = true`; this function does not guess.
///
/// Returns `Ok(None)` when more bytes are required, `Ok(Some((block, used)))`
/// for a complete block, where `used` is the number of bytes consumed, or an
/// error for values that can never become valid.
pub fn parse_block(input: &[u8], first: bool) -> Result<Option<(Block<'_>, usize)>, VisionError> {
    let (uuid, rest) = if first {
        match input.split_first_chunk::<UUID_LEN>() {
            Some((uuid, rest)) => (Some(*uuid), rest),
            None => return Ok(None),
        }
    } else {
        (None, input)
    };

    let Some((&command_byte, rest)) = rest.split_first() else {
        return Ok(None);
    };
    let command = Command::from_byte(command_byte)?;

    let Some((lengths, body)) = rest.split_first_chunk::<4>() else {
        return Ok(None);
    };
    let content_len = u16::from_be_bytes([lengths[0], lengths[1]]);
    let padding_len = u16::from_be_bytes([lengths[2], lengths[3]]);

    let payload_len = usize::from(content_len) + usize::from(padding_len);
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(VisionError::PayloadTooLarge(payload_len));
    }

    let header_len = input.len() - body.len();
    let total_len = header_len + payload_len;
    let Some((content, padding)) = body.split_at_checked(usize::from(content_len)) else {
        return Ok(None);
    };
    if padding.len() < usize::from(padding_len) {
        return Ok(None);
    }

    Ok(Some((
        Block {
            uuid,
            command,
            content,
            padding_len,
        },
        total_len,
    )))
}

/// Encodes one Vision block and appends it to `out`.
///
/// `uuid` is `Some` only for the first block of a direction. Padding is
/// written as zero bytes. Nothing is appended when the block is rejected.
pub fn encode_block(
    out: &mut Vec<u8>,
    uuid: Option<[u8; UUID_LEN]>,
    command: Command,
    content: &[u8],
    padding_len: u16,
) -> Result<(), VisionError> {
    let content_len =
        u16::try_from(content.len()).map_err(|_| VisionError::ContentTooLong(content.len()))?;
    let payload_len = content.len() + usize::from(padding_len);
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(VisionError::PayloadTooLarge(payload_len));
    }

    if let Some(uuid) = uuid {
        out.extend_from_slice(&uuid);
    }
    out.push(command.as_byte());
    out.extend_from_slice(&content_len.to_be_bytes());
    out.extend_from_slice(&padding_len.to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + usize::from(padding_len), 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BLOCK_HEADER_LEN, Block, Command, MAX_BLOCK_LEN, MAX_CONTENT_LEN, MAX_PAYLOAD_LEN,
        UUID_LEN, VisionError, encode_block, parse_block,
    };

    /// Synthetic UUID. It is not derived from any real configuration.
    const TEST_UUID: [u8; UUID_LEN] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn encoded(
        uuid: Option<[u8; UUID_LEN]>,
        command: Command,
        content: &[u8],
        padding_len: u16,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        encode_block(&mut out, uuid, command, content, padding_len).expect("block must encode");
        out
    }

    fn parsed(input: &[u8], first: bool) -> (Block<'_>, usize) {
        parse_block(input, first)
            .expect("block must not be rejected")
            .expect("block must be complete")
    }

    #[test]
    fn command_values_match_the_wire() {
        assert_eq!(Command::Continue.as_byte(), 0x00);
        assert_eq!(Command::End.as_byte(), 0x01);
        assert_eq!(Command::Direct.as_byte(), 0x02);

        assert_eq!(Command::from_byte(0x00), Ok(Command::Continue));
        assert_eq!(Command::from_byte(0x01), Ok(Command::End));
        assert_eq!(Command::from_byte(0x02), Ok(Command::Direct));
        assert_eq!(
            Command::from_byte(0x03),
            Err(VisionError::UnknownCommand(0x03))
        );
    }

    #[test]
    fn encodes_exact_first_block_layout() {
        let bytes = encoded(Some(TEST_UUID), Command::Direct, b"abc", 2);

        let mut expected = Vec::new();
        expected.extend_from_slice(&TEST_UUID);
        expected.push(0x02);
        expected.extend_from_slice(&[0x00, 0x03, 0x00, 0x02]);
        expected.extend_from_slice(b"abc");
        expected.extend_from_slice(&[0x00, 0x00]);

        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), UUID_LEN + BLOCK_HEADER_LEN + 3 + 2);
    }

    #[test]
    fn encodes_exact_later_block_layout() {
        let bytes = encoded(None, Command::End, b"", 1);
        assert_eq!(bytes.as_slice(), &[0x01, 0x00, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn parses_first_block_with_uuid() {
        let mut bytes = encoded(Some(TEST_UUID), Command::Continue, b"hello", 3);
        let block_len = bytes.len();
        bytes.extend_from_slice(b"trailing");

        let (block, used) = parsed(&bytes, true);

        assert_eq!(block.uuid, Some(TEST_UUID));
        assert_eq!(block.command, Command::Continue);
        assert_eq!(block.content, b"hello");
        assert_eq!(block.padding_len, 3);
        assert_eq!(used, block_len);
    }

    #[test]
    fn parses_later_block_without_consuming_a_uuid() {
        // The content deliberately looks like a UUID prefix. A later block
        // must treat it as content, not as a prefix.
        let bytes = encoded(None, Command::End, &TEST_UUID, 0);

        let (block, used) = parsed(&bytes, false);

        assert_eq!(block.uuid, None);
        assert_eq!(block.command, Command::End);
        assert_eq!(block.content, &TEST_UUID);
        assert_eq!(block.padding_len, 0);
        assert_eq!(used, BLOCK_HEADER_LEN + UUID_LEN);
    }

    #[test]
    fn round_trips_every_command() {
        for command in [Command::Continue, Command::End, Command::Direct] {
            let bytes = encoded(Some(TEST_UUID), command, b"body", 2);
            let (block, used) = parsed(&bytes, true);
            assert_eq!(block.uuid, Some(TEST_UUID));
            assert_eq!(block.command, command);
            assert_eq!(block.content, b"body");
            assert_eq!(used, bytes.len());
        }
    }

    #[test]
    fn parses_multiple_blocks_in_one_buffer() {
        let mut stream = Vec::new();
        encode_block(&mut stream, Some(TEST_UUID), Command::Continue, b"one", 0)
            .expect("first block must encode");
        encode_block(&mut stream, None, Command::Continue, b"two", 3)
            .expect("second block must encode");
        encode_block(&mut stream, None, Command::Direct, b"three", 1)
            .expect("third block must encode");
        let stream_len = stream.len();

        let mut offset = 0;

        let (first, used) = parsed(&stream[offset..], true);
        assert_eq!(first.uuid, Some(TEST_UUID));
        assert_eq!(first.command, Command::Continue);
        assert_eq!(first.content, b"one");
        assert_eq!(first.padding_len, 0);
        offset += used;

        let (second, used) = parsed(&stream[offset..], false);
        assert_eq!(second.uuid, None);
        assert_eq!(second.command, Command::Continue);
        assert_eq!(second.content, b"two");
        assert_eq!(second.padding_len, 3);
        offset += used;

        let (third, used) = parsed(&stream[offset..], false);
        assert_eq!(third.uuid, None);
        assert_eq!(third.command, Command::Direct);
        assert_eq!(third.content, b"three");
        assert_eq!(third.padding_len, 1);
        offset += used;

        assert_eq!(offset, stream_len);
    }

    #[test]
    fn incomplete_blocks_need_more_data() {
        let first = encoded(Some(TEST_UUID), Command::Continue, b"hello", 4);
        for end in 0..first.len() {
            assert!(
                matches!(parse_block(&first[..end], true), Ok(None)),
                "a {end}-byte prefix of a first block must ask for more data"
            );
        }

        let later = encoded(None, Command::Direct, b"hello", 4);
        for end in 0..later.len() {
            assert!(
                matches!(parse_block(&later[..end], false), Ok(None)),
                "a {end}-byte prefix of a later block must ask for more data"
            );
        }
    }

    #[test]
    fn parses_zero_length_content() {
        let bytes = encoded(Some(TEST_UUID), Command::Continue, b"", 0);
        let (block, used) = parsed(&bytes, true);
        assert!(block.content.is_empty());
        assert_eq!(block.padding_len, 0);
        assert_eq!(used, UUID_LEN + BLOCK_HEADER_LEN);

        // A zero-length block can still carry padding.
        let bytes = encoded(None, Command::Continue, b"", 5);
        let (block, used) = parsed(&bytes, false);
        assert!(block.content.is_empty());
        assert_eq!(block.padding_len, 5);
        assert_eq!(used, BLOCK_HEADER_LEN + 5);
    }

    #[test]
    fn maximum_padding_matches_the_stock_clamp() {
        let padding = u16::try_from(MAX_PAYLOAD_LEN).expect("padding fits in u16");

        // The first block reserves 21 header bytes, so this fills 8192 bytes.
        let bytes = encoded(Some(TEST_UUID), Command::Continue, b"", padding);
        assert_eq!(bytes.len(), MAX_BLOCK_LEN);
        assert!(
            bytes[UUID_LEN + BLOCK_HEADER_LEN..]
                .iter()
                .all(|&byte| byte == 0)
        );
        let (block, used) = parsed(&bytes, true);
        assert_eq!(block.padding_len, padding);
        assert_eq!(used, MAX_BLOCK_LEN);

        // Later blocks share the same content+padding clamp even though their
        // header is 16 bytes shorter.
        let bytes = encoded(None, Command::Continue, b"", padding);
        assert_eq!(bytes.len(), BLOCK_HEADER_LEN + MAX_PAYLOAD_LEN);
        let (block, used) = parsed(&bytes, false);
        assert_eq!(block.padding_len, padding);
        assert_eq!(used, BLOCK_HEADER_LEN + MAX_PAYLOAD_LEN);
    }

    #[test]
    fn maximum_content_without_padding() {
        let content = vec![0x5a; MAX_CONTENT_LEN];

        let bytes = encoded(None, Command::Continue, &content, 0);
        assert_eq!(bytes.len(), BLOCK_HEADER_LEN + MAX_CONTENT_LEN);
        let (block, used) = parsed(&bytes, false);
        assert_eq!(block.content, content.as_slice());
        assert_eq!(used, bytes.len());

        let bytes = encoded(Some(TEST_UUID), Command::Continue, &content, 0);
        assert_eq!(bytes.len(), MAX_BLOCK_LEN);
        let (block, used) = parsed(&bytes, true);
        assert_eq!(block.content, content.as_slice());
        assert_eq!(used, MAX_BLOCK_LEN);
    }

    #[test]
    fn rejects_content_and_padding_over_the_stock_clamp() {
        // Later block: content 8187 gives a total of 8192, but the stock
        // writer would never emit more than 8171 content+padding bytes.
        let header = [Command::Continue.as_byte(), 0x1f, 0xfb, 0x00, 0x00];
        assert_eq!(
            parse_block(&header, false),
            Err(VisionError::PayloadTooLarge(8187))
        );

        // Later block: 5 + 8188 = 8193.
        let header = [Command::Continue.as_byte(), 0x1f, 0xfc, 0x00, 0x00];
        assert_eq!(
            parse_block(&header, false),
            Err(VisionError::PayloadTooLarge(8188))
        );

        // First block: 8000 content + 172 padding = 8172.
        let mut header = Vec::new();
        header.extend_from_slice(&TEST_UUID);
        header.push(Command::Continue.as_byte());
        header.extend_from_slice(&8000_u16.to_be_bytes());
        header.extend_from_slice(&172_u16.to_be_bytes());
        assert_eq!(
            parse_block(&header, true),
            Err(VisionError::PayloadTooLarge(MAX_PAYLOAD_LEN + 1))
        );

        // The encoder rejects the same size and must not write a partial block.
        let mut out = Vec::new();
        assert_eq!(
            encode_block(&mut out, None, Command::Continue, &[0; 8188], 0),
            Err(VisionError::PayloadTooLarge(8188))
        );
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_content_that_does_not_fit_the_length_field() {
        let content = vec![0; usize::from(u16::MAX) + 1];
        let mut out = Vec::new();
        assert_eq!(
            encode_block(&mut out, None, Command::Continue, &content, 0),
            Err(VisionError::ContentTooLong(content.len()))
        );
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_unknown_commands() {
        assert_eq!(
            parse_block(&[0x03, 0x00, 0x00, 0x00, 0x00], false),
            Err(VisionError::UnknownCommand(0x03))
        );

        let mut first = Vec::new();
        first.extend_from_slice(&TEST_UUID);
        first.extend_from_slice(&[0xff, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            parse_block(&first, true),
            Err(VisionError::UnknownCommand(0xff))
        );
    }

    #[test]
    fn ignores_padding_contents() {
        let mut bytes = encoded(None, Command::Continue, b"payload", 4);
        let len = bytes.len();
        bytes[len - 4..].fill(0xaa);

        let (block, used) = parsed(&bytes, false);
        assert_eq!(block.content, b"payload");
        assert_eq!(block.padding_len, 4);
        assert_eq!(used, len);
    }

    #[test]
    fn encoder_round_trips_first_and_later_blocks() {
        let first = encoded(Some(TEST_UUID), Command::Continue, b"first payload", 900);
        let (block, used) = parsed(&first, true);
        assert_eq!(block.uuid, Some(TEST_UUID));
        assert_eq!(block.command, Command::Continue);
        assert_eq!(block.content, b"first payload");
        assert_eq!(block.padding_len, 900);
        assert_eq!(used, first.len());

        let later = encoded(None, Command::End, b"second payload", 0);
        let (block, used) = parsed(&later, false);
        assert_eq!(block.uuid, None);
        assert_eq!(block.command, Command::End);
        assert_eq!(block.content, b"second payload");
        assert_eq!(block.padding_len, 0);
        assert_eq!(used, later.len());
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_valid_blocks_round_trip(
            uuid in prop::option::of(any::<[u8; UUID_LEN]>()),
            command_byte in 0_u8..3,
            content in prop::collection::vec(any::<u8>(), 0..=512),
            padding_len in 0_u16..=1024,
        ) {
            let command = Command::from_byte(command_byte).expect("command is in range");
            let mut bytes = Vec::new();
            encode_block(&mut bytes, uuid, command, &content, padding_len)
                .expect("block fits the limit");

            let (block, used) = parse_block(&bytes, uuid.is_some())
                .expect("encoded block must parse")
                .expect("encoded block is complete");

            prop_assert_eq!(block.uuid, uuid);
            prop_assert_eq!(block.command, command);
            prop_assert_eq!(block.content, content.as_slice());
            prop_assert_eq!(block.padding_len, padding_len);
            prop_assert_eq!(used, bytes.len());
        }

        #[test]
        fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..=MAX_BLOCK_LEN)) {
            for first in [true, false] {
                let _ = parse_block(&data, first);
            }
        }
    }
}
