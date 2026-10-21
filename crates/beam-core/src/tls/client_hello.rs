//! Bounded, zero-copy parser for a single TLS record carrying a ClientHello.
//!
//! The parser accepts exactly one TLS handshake record whose payload is one
//! complete ClientHello handshake message. Trailing bytes after that record are
//! ignored so a caller can hand over a read buffer that contains more data.
//!
//! Every length is checked before it is used. The parser performs no heap
//! allocation: the record, handshake message, session id, lists, and extension
//! payloads are borrowed slices of the input. The only copies are the 32-byte
//! random value and the small, fixed-capacity key share group table.
//!
//! Unknown and GREASE values are preserved rather than rejected. Duplicate
//! extension types are rejected, as are duplicate `server_name` entries and
//! duplicate key share groups.

use bytes::Bytes;

/// Length of a TLS record header.
pub const TLS_RECORD_HEADER_LEN: usize = 5;

/// Length of a TLS handshake message header.
pub const TLS_HANDSHAKE_HEADER_LEN: usize = 4;

/// Maximum TLS record payload accepted by this parser (RFC 8446, 2^14).
pub const MAX_RECORD_LEN: usize = 16_384;

/// Maximum ClientHello handshake body that fits in a maximum-size record.
pub const MAX_CLIENT_HELLO_LEN: usize = MAX_RECORD_LEN - TLS_HANDSHAKE_HEADER_LEN;

/// Maximum length of a TLS 1.3 legacy session id.
pub const MAX_SESSION_ID_LEN: usize = 32;

/// Maximum number of cipher suites kept by the parser.
pub const MAX_CIPHER_SUITES: usize = 1_024;

/// Maximum number of extensions accepted in one ClientHello.
pub const MAX_EXTENSIONS: usize = 64;

/// Maximum number of key share entries accepted in one ClientHello.
pub const MAX_KEY_SHARE_ENTRIES: usize = 16;

/// Maximum number of ALPN protocols accepted in one ClientHello.
pub const MAX_ALPN_PROTOCOLS: usize = 64;

/// TLS 1.3 protocol version, as carried in `supported_versions`.
pub const TLS13_VERSION: u16 = 0x0304;

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

const RECORD_VERSION_TLS10: u16 = 0x0301;
const RECORD_VERSION_TLS12: u16 = 0x0303;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;

/// Errors returned while parsing a ClientHello record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientHelloError {
    /// The input ended before a field could be read completely.
    #[error("truncated input at offset {offset}: need {needed} bytes, {remaining} remain")]
    Truncated {
        /// Offset at which the read started.
        offset: usize,
        /// Number of bytes the field needs.
        needed: usize,
        /// Number of bytes left in the input.
        remaining: usize,
    },

    /// The record does not carry a handshake message.
    #[error("record content type {0:#04x} is not handshake (0x16)")]
    NotHandshakeRecord(u8),

    /// The record version is not one accepted for an initial ClientHello.
    #[error("unsupported TLS record version {0:#06x}")]
    UnsupportedRecordVersion(u16),

    /// The record length exceeds the TLS plaintext record limit.
    #[error("record length {length} exceeds the {max}-byte limit")]
    RecordTooLarge {
        /// Declared record payload length.
        length: usize,
        /// Maximum accepted length.
        max: usize,
    },

    /// The handshake message is not a ClientHello.
    #[error("handshake type {0:#04x} is not ClientHello (0x01)")]
    NotClientHello(u8),

    /// The declared handshake length exceeds the parser limit.
    #[error("ClientHello length {length} exceeds the {max}-byte limit")]
    ClientHelloTooLarge {
        /// Declared ClientHello body length.
        length: usize,
        /// Maximum accepted length.
        max: usize,
    },

    /// The handshake length does not consume the whole record payload.
    #[error("ClientHello length {declared} does not match the {available} bytes in the record")]
    ClientHelloLengthMismatch {
        /// Declared ClientHello body length.
        declared: usize,
        /// Bytes actually available after the handshake header.
        available: usize,
    },

    /// The legacy session id is longer than 32 bytes.
    #[error("session id length {length} exceeds {max} bytes")]
    SessionIdTooLong {
        /// Declared session id length.
        length: usize,
        /// Maximum accepted length.
        max: usize,
    },

    /// The cipher suite vector is empty or has an odd byte length.
    #[error("cipher suite list length {0} is not a positive even number")]
    InvalidCipherSuitesLength(usize),

    /// The cipher suite vector exceeds the parser limit.
    #[error("cipher suite count {count} exceeds the {max}-entry limit")]
    TooManyCipherSuites {
        /// Number of declared cipher suites.
        count: usize,
        /// Maximum accepted number.
        max: usize,
    },

    /// The compression method vector is empty.
    #[error("compression method list is empty")]
    EmptyCompressionMethods,

    /// The extension block length does not consume the rest of the ClientHello.
    #[error("extension block length {declared} does not match the {available} bytes remaining")]
    ExtensionsLengthMismatch {
        /// Declared extension block length.
        declared: usize,
        /// Bytes actually remaining.
        available: usize,
    },

    /// The ClientHello contains too many extensions.
    #[error("extension count exceeds the {max}-entry limit")]
    TooManyExtensions {
        /// Maximum accepted extension count.
        max: usize,
    },

    /// The same extension type appears more than once.
    #[error("duplicate extension type {0:#06x}")]
    DuplicateExtension(u16),

    /// An extension payload is structurally malformed.
    #[error("malformed {extension} extension: {reason}")]
    MalformedExtension {
        /// Extension name, for diagnostics.
        extension: &'static str,
        /// Reason the extension was rejected.
        reason: &'static str,
    },

    /// The key share extension contains too many entries.
    #[error("key_share extension has more than {max} entries")]
    TooManyKeyShares {
        /// Maximum accepted entry count.
        max: usize,
    },
}

/// A list of big-endian `u16` values stored in wire format.
///
/// The underlying bytes are borrowed from the input and are never copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U16List<'a> {
    bytes: &'a [u8],
}

impl<'a> U16List<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the wire-format bytes of the list.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the number of `u16` values in the list.
    pub fn len(&self) -> usize {
        self.bytes.len() / 2
    }

    /// Returns `true` if the list contains no values.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the value at `index`, or `None` if it is out of bounds.
    pub fn get(&self, index: usize) -> Option<u16> {
        let start = index.checked_mul(2)?;
        let end = start.checked_add(2)?;
        let bytes: [u8; 2] = self.bytes.get(start..end)?.try_into().ok()?;
        Some(u16::from_be_bytes(bytes))
    }

    /// Returns the first value, if any.
    pub fn first(&self) -> Option<u16> {
        self.get(0)
    }

    /// Returns `true` if `value` appears in the list.
    pub fn contains(&self, value: u16) -> bool {
        self.iter().any(|candidate| candidate == value)
    }

    /// Iterates over the values in wire order.
    pub fn iter(&self) -> U16ListIter<'a> {
        U16ListIter { bytes: self.bytes }
    }
}

/// Iterator over a [`U16List`].
#[derive(Clone, Debug)]
pub struct U16ListIter<'a> {
    bytes: &'a [u8],
}

impl Iterator for U16ListIter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() < 2 {
            return None;
        }
        let (head, tail) = self.bytes.split_at(2);
        self.bytes = tail;
        let head: [u8; 2] = head.try_into().ok()?;
        Some(u16::from_be_bytes(head))
    }
}

/// ALPN protocol names from a ClientHello.
///
/// The stored bytes are the 1-byte-length-prefixed protocol list, without the
/// outer `u16` list length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alpn<'a> {
    bytes: &'a [u8],
}

impl<'a> Alpn<'a> {
    /// Returns the raw length-prefixed protocol list.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the number of protocols in the list.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Returns `true` if the list contains no protocols.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns `true` if `protocol` is offered by the client.
    pub fn contains(&self, protocol: &[u8]) -> bool {
        self.iter().any(|candidate| candidate == protocol)
    }

    /// Iterates over the offered protocol names.
    pub fn iter(&self) -> AlpnIter<'a> {
        AlpnIter {
            remaining: self.bytes,
        }
    }
}

/// Iterator over ALPN protocol names.
#[derive(Clone, Debug)]
pub struct AlpnIter<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for AlpnIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.remaining;
        let (&length, rest) = rest.split_first()?;
        let length = usize::from(length);
        let Some(protocol) = rest.get(..length) else {
            self.remaining = &[];
            return None;
        };
        self.remaining = rest.get(length..).unwrap_or(&[]);
        Some(protocol)
    }
}

/// Key share groups advertised by a ClientHello.
///
/// Entry order is preserved. The group identifiers live in a fixed-capacity
/// inline array, so parsing never allocates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyShareGroups {
    groups: [u16; MAX_KEY_SHARE_ENTRIES],
    len: usize,
}

impl KeyShareGroups {
    /// Returns the groups in wire order.
    pub fn as_slice(&self) -> &[u16] {
        self.groups.get(..self.len).unwrap_or(&[])
    }

    /// Returns the number of key share entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the client sent no key shares.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if the client sent a share for `group`.
    pub fn contains(&self, group: u16) -> bool {
        self.as_slice().contains(&group)
    }

    /// Iterates over the groups in wire order.
    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.as_slice().iter().copied()
    }
}

/// One parsed TLS extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extension<'a> {
    /// The extension type.
    pub extension_type: u16,
    /// The extension payload.
    pub data: &'a [u8],
}

/// Iterator over the extensions of a ClientHello.
#[derive(Clone, Debug)]
pub struct ExtensionIter<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for ExtensionIter<'a> {
    type Item = Extension<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.remaining;
        if rest.len() < 4 {
            self.remaining = &[];
            return None;
        }
        let (header, rest) = rest.split_at(4);
        let header: [u8; 4] = header.try_into().ok()?;
        let extension_type = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let Some(data) = rest.get(..length) else {
            self.remaining = &[];
            return None;
        };
        self.remaining = rest.get(length..).unwrap_or(&[]);
        Some(Extension {
            extension_type,
            data,
        })
    }
}

/// A parsed TLS ClientHello record.
///
/// All borrowed fields point into the input passed to [`ClientHello::parse`] or
/// [`ClientHello::parse_bytes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientHello<'a> {
    /// The TLS record version from the record header.
    pub record_version: u16,
    /// The ClientHello `legacy_version` field.
    pub legacy_version: u16,
    /// The 32-byte ClientHello random.
    pub random: [u8; 32],
    /// The legacy session id, including REALITY's 32-byte session id.
    pub session_id: &'a [u8],
    /// The advertised cipher suites.
    pub cipher_suites: U16List<'a>,
    /// The advertised compression methods.
    pub compression_methods: &'a [u8],
    /// The `host_name` SNI value, if one was sent.
    pub server_name: Option<&'a str>,
    /// The `supported_versions` list, if the extension was sent.
    pub supported_versions: Option<U16List<'a>>,
    /// The key share groups, if the extension was sent.
    pub key_share_groups: Option<KeyShareGroups>,
    /// The `signature_algorithms` list, if the extension was sent.
    pub signature_algorithms: Option<U16List<'a>>,
    /// The advertised ALPN protocols, if the extension was sent.
    pub alpn: Option<Alpn<'a>>,
    /// The complete TLS record, including the five-byte record header.
    pub raw_record: &'a [u8],
    /// The complete ClientHello handshake message, including its four-byte
    /// handshake header.
    pub raw_client_hello: &'a [u8],
    extensions: &'a [u8],
    extension_count: usize,
}

impl<'a> ClientHello<'a> {
    /// Parses the first TLS record in `input`.
    ///
    /// Trailing bytes after the record are ignored. Use [`Self::raw_record`] to
    /// determine how much of the input was consumed.
    pub fn parse(input: &'a [u8]) -> Result<Self, ClientHelloError> {
        let mut record = Reader::new(input);

        let content_type = record.u8()?;
        if content_type != CONTENT_TYPE_HANDSHAKE {
            return Err(ClientHelloError::NotHandshakeRecord(content_type));
        }

        let record_version = record.u16()?;
        if !matches!(record_version, RECORD_VERSION_TLS10 | RECORD_VERSION_TLS12) {
            return Err(ClientHelloError::UnsupportedRecordVersion(record_version));
        }

        let record_len = usize::from(record.u16()?);
        if record_len > MAX_RECORD_LEN {
            return Err(ClientHelloError::RecordTooLarge {
                length: record_len,
                max: MAX_RECORD_LEN,
            });
        }

        let record_body = record.take(record_len)?;
        let record_end = record.position();
        let raw_record = input.get(..record_end).ok_or(ClientHelloError::Truncated {
            offset: 0,
            needed: record_end,
            remaining: input.len(),
        })?;

        let mut handshake = Reader::new(record_body);
        let handshake_type = handshake.u8()?;
        if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(ClientHelloError::NotClientHello(handshake_type));
        }

        let client_hello_len = handshake.u24()?;
        if client_hello_len > MAX_CLIENT_HELLO_LEN {
            return Err(ClientHelloError::ClientHelloTooLarge {
                length: client_hello_len,
                max: MAX_CLIENT_HELLO_LEN,
            });
        }

        let available = handshake.remaining_len();
        if client_hello_len > available {
            return Err(ClientHelloError::Truncated {
                offset: handshake.position(),
                needed: client_hello_len,
                remaining: available,
            });
        }
        if client_hello_len < available {
            return Err(ClientHelloError::ClientHelloLengthMismatch {
                declared: client_hello_len,
                available,
            });
        }

        let client_hello_body = handshake.take(client_hello_len)?;
        let handshake_end = TLS_HANDSHAKE_HEADER_LEN
            .checked_add(client_hello_len)
            .ok_or(ClientHelloError::Truncated {
                offset: 0,
                needed: client_hello_len,
                remaining: record_body.len(),
            })?;
        let raw_client_hello =
            record_body
                .get(..handshake_end)
                .ok_or(ClientHelloError::Truncated {
                    offset: TLS_HANDSHAKE_HEADER_LEN,
                    needed: client_hello_len,
                    remaining: record_body.len(),
                })?;

        parse_client_hello_body(
            client_hello_body,
            record_version,
            raw_record,
            raw_client_hello,
        )
    }

    /// Parses the first TLS record in a [`Bytes`] buffer without copying it.
    pub fn parse_bytes(input: &'a Bytes) -> Result<Self, ClientHelloError> {
        Self::parse(input.as_ref())
    }

    /// Returns the ClientHello body without its four-byte handshake header.
    pub fn client_hello_body(&self) -> &'a [u8] {
        self.raw_client_hello
            .get(TLS_HANDSHAKE_HEADER_LEN..)
            .unwrap_or(&[])
    }

    /// Returns the `host_name` SNI value as raw bytes.
    pub fn server_name_bytes(&self) -> Option<&'a [u8]> {
        self.server_name.map(str::as_bytes)
    }

    /// Returns `true` if the client advertised TLS 1.3.
    pub fn supports_tls13(&self) -> bool {
        self.supported_versions
            .as_ref()
            .is_some_and(|versions| versions.contains(TLS13_VERSION))
    }

    /// Returns `true` if the client sent a key share for `group`.
    pub fn has_key_share_group(&self, group: u16) -> bool {
        self.key_share_groups
            .as_ref()
            .is_some_and(|groups| groups.contains(group))
    }

    /// Returns the number of extensions in the ClientHello.
    pub fn extension_count(&self) -> usize {
        self.extension_count
    }

    /// Iterates over all extensions, including unknown ones.
    pub fn extensions(&self) -> ExtensionIter<'a> {
        ExtensionIter {
            remaining: self.extensions,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ClientHello<'a> {
    type Error = ClientHelloError;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        Self::parse(input)
    }
}

impl<'a> TryFrom<&'a Bytes> for ClientHello<'a> {
    type Error = ClientHelloError;

    fn try_from(input: &'a Bytes) -> Result<Self, Self::Error> {
        Self::parse_bytes(input)
    }
}

struct ParsedExtensions<'a> {
    server_name: Option<&'a str>,
    supported_versions: Option<U16List<'a>>,
    key_share_groups: Option<KeyShareGroups>,
    signature_algorithms: Option<U16List<'a>>,
    alpn: Option<Alpn<'a>>,
    count: usize,
}

fn parse_client_hello_body<'a>(
    body: &'a [u8],
    record_version: u16,
    raw_record: &'a [u8],
    raw_client_hello: &'a [u8],
) -> Result<ClientHello<'a>, ClientHelloError> {
    let mut reader = Reader::new(body);

    let legacy_version = reader.u16()?;
    let random = reader.take_array::<32>()?;

    let session_id_len = usize::from(reader.u8()?);
    if session_id_len > MAX_SESSION_ID_LEN {
        return Err(ClientHelloError::SessionIdTooLong {
            length: session_id_len,
            max: MAX_SESSION_ID_LEN,
        });
    }
    let session_id = reader.take(session_id_len)?;

    let cipher_suites_len = usize::from(reader.u16()?);
    if cipher_suites_len == 0 || cipher_suites_len % 2 != 0 {
        return Err(ClientHelloError::InvalidCipherSuitesLength(
            cipher_suites_len,
        ));
    }
    let cipher_suite_count = cipher_suites_len / 2;
    if cipher_suite_count > MAX_CIPHER_SUITES {
        return Err(ClientHelloError::TooManyCipherSuites {
            count: cipher_suite_count,
            max: MAX_CIPHER_SUITES,
        });
    }
    let cipher_suites = U16List::new(reader.take(cipher_suites_len)?);

    let compression_methods_len = usize::from(reader.u8()?);
    if compression_methods_len == 0 {
        return Err(ClientHelloError::EmptyCompressionMethods);
    }
    let compression_methods = reader.take(compression_methods_len)?;

    let extension_block = if reader.remaining_len() == 0 {
        &[][..]
    } else {
        let declared = usize::from(reader.u16()?);
        let available = reader.remaining_len();
        if declared > available {
            return Err(ClientHelloError::Truncated {
                offset: reader.position(),
                needed: declared,
                remaining: available,
            });
        }
        if declared < available {
            return Err(ClientHelloError::ExtensionsLengthMismatch {
                declared,
                available,
            });
        }
        reader.take(declared)?
    };

    let parsed = parse_extensions(extension_block)?;

    Ok(ClientHello {
        record_version,
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        server_name: parsed.server_name,
        supported_versions: parsed.supported_versions,
        key_share_groups: parsed.key_share_groups,
        signature_algorithms: parsed.signature_algorithms,
        alpn: parsed.alpn,
        raw_record,
        raw_client_hello,
        extensions: extension_block,
        extension_count: parsed.count,
    })
}

fn parse_extensions<'a>(block: &'a [u8]) -> Result<ParsedExtensions<'a>, ClientHelloError> {
    let mut reader = Reader::new(block);
    let mut seen = [0u16; MAX_EXTENSIONS];
    let mut seen_len = 0usize;
    let mut parsed = ParsedExtensions {
        server_name: None,
        supported_versions: None,
        key_share_groups: None,
        signature_algorithms: None,
        alpn: None,
        count: 0,
    };

    while reader.remaining_len() > 0 {
        if seen_len >= MAX_EXTENSIONS {
            return Err(ClientHelloError::TooManyExtensions {
                max: MAX_EXTENSIONS,
            });
        }

        let extension_type = reader.u16()?;
        let extension_len = usize::from(reader.u16()?);
        let data = reader.take(extension_len)?;

        if seen
            .get(..seen_len)
            .is_some_and(|types| types.contains(&extension_type))
        {
            return Err(ClientHelloError::DuplicateExtension(extension_type));
        }
        let Some(slot) = seen.get_mut(seen_len) else {
            return Err(ClientHelloError::TooManyExtensions {
                max: MAX_EXTENSIONS,
            });
        };
        *slot = extension_type;
        seen_len += 1;

        match extension_type {
            EXT_SERVER_NAME => parsed.server_name = parse_server_name(data)?,
            EXT_SUPPORTED_VERSIONS => {
                parsed.supported_versions = Some(parse_supported_versions(data)?);
            }
            EXT_KEY_SHARE => parsed.key_share_groups = Some(parse_key_share(data)?),
            EXT_SIGNATURE_ALGORITHMS => {
                parsed.signature_algorithms = Some(parse_u16_list(data, "signature_algorithms")?);
            }
            EXT_ALPN => parsed.alpn = Some(parse_alpn(data)?),
            _ => {}
        }
    }

    parsed.count = seen_len;
    Ok(parsed)
}

fn parse_server_name(data: &[u8]) -> Result<Option<&str>, ClientHelloError> {
    let mut reader = Reader::new(data);
    let list_len = usize::from(reader.u16()?);
    let available = reader.remaining_len();
    if list_len != available {
        return Err(malformed_extension(
            "server_name",
            "server name list length mismatch",
        ));
    }
    if list_len == 0 {
        return Err(malformed_extension("server_name", "empty server name list"));
    }

    let list = reader.take(list_len)?;
    let mut names = Reader::new(list);
    let mut host_name = None;

    while names.remaining_len() > 0 {
        let name_type = names.u8()?;
        let name_len = usize::from(names.u16()?);
        let name = names.take(name_len)?;

        if name_type != 0 {
            continue;
        }
        if name_len == 0 {
            return Err(malformed_extension("server_name", "empty host_name"));
        }
        if host_name.is_some() {
            return Err(malformed_extension(
                "server_name",
                "duplicate host_name entry",
            ));
        }
        let name = core::str::from_utf8(name)
            .map_err(|_| malformed_extension("server_name", "host_name is not valid UTF-8"))?;
        host_name = Some(name);
    }

    Ok(host_name)
}

fn parse_supported_versions<'a>(data: &'a [u8]) -> Result<U16List<'a>, ClientHelloError> {
    let mut reader = Reader::new(data);
    let list_len = usize::from(reader.u8()?);
    let available = reader.remaining_len();
    if list_len != available {
        return Err(malformed_extension(
            "supported_versions",
            "version list length mismatch",
        ));
    }
    if list_len == 0 || list_len % 2 != 0 {
        return Err(malformed_extension(
            "supported_versions",
            "version list must be non-empty and even",
        ));
    }
    Ok(U16List::new(reader.take(list_len)?))
}

fn parse_key_share(data: &[u8]) -> Result<KeyShareGroups, ClientHelloError> {
    let mut reader = Reader::new(data);
    let shares_len = usize::from(reader.u16()?);
    let available = reader.remaining_len();
    if shares_len != available {
        return Err(malformed_extension(
            "key_share",
            "client share list length mismatch",
        ));
    }

    let shares = reader.take(shares_len)?;
    let mut shares = Reader::new(shares);
    let mut groups = [0u16; MAX_KEY_SHARE_ENTRIES];
    let mut count = 0usize;

    while shares.remaining_len() > 0 {
        if count >= MAX_KEY_SHARE_ENTRIES {
            return Err(ClientHelloError::TooManyKeyShares {
                max: MAX_KEY_SHARE_ENTRIES,
            });
        }

        let group = shares.u16()?;
        let key_len = usize::from(shares.u16()?);
        let _key_exchange = shares.take(key_len)?;

        if groups
            .get(..count)
            .is_some_and(|seen| seen.contains(&group))
        {
            return Err(malformed_extension(
                "key_share",
                "duplicate key share group",
            ));
        }
        let Some(slot) = groups.get_mut(count) else {
            return Err(ClientHelloError::TooManyKeyShares {
                max: MAX_KEY_SHARE_ENTRIES,
            });
        };
        *slot = group;
        count += 1;
    }

    Ok(KeyShareGroups { groups, len: count })
}

fn parse_u16_list<'a>(
    data: &'a [u8],
    extension: &'static str,
) -> Result<U16List<'a>, ClientHelloError> {
    let mut reader = Reader::new(data);
    let list_len = usize::from(reader.u16()?);
    let available = reader.remaining_len();
    if list_len != available {
        return Err(malformed_extension(extension, "list length mismatch"));
    }
    if list_len == 0 || list_len % 2 != 0 {
        return Err(malformed_extension(
            extension,
            "list must be non-empty and even",
        ));
    }
    Ok(U16List::new(reader.take(list_len)?))
}

fn parse_alpn(data: &[u8]) -> Result<Alpn<'_>, ClientHelloError> {
    let mut reader = Reader::new(data);
    let list_len = usize::from(reader.u16()?);
    let available = reader.remaining_len();
    if list_len != available {
        return Err(malformed_extension("alpn", "protocol list length mismatch"));
    }
    if list_len == 0 {
        return Err(malformed_extension("alpn", "empty protocol list"));
    }

    let list = reader.take(list_len)?;
    let mut protocols = Reader::new(list);
    let mut count = 0usize;

    while protocols.remaining_len() > 0 {
        let protocol_len = usize::from(protocols.u8()?);
        if protocol_len == 0 {
            return Err(malformed_extension("alpn", "empty protocol name"));
        }
        protocols.take(protocol_len)?;
        count += 1;
        if count > MAX_ALPN_PROTOCOLS {
            return Err(malformed_extension("alpn", "too many protocols"));
        }
    }

    Ok(Alpn { bytes: list })
}

fn malformed_extension(extension: &'static str, reason: &'static str) -> ClientHelloError {
    ClientHelloError::MalformedExtension { extension, reason }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn remaining_len(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ClientHelloError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ClientHelloError::Truncated {
                offset: self.offset,
                needed: len,
                remaining: self.remaining_len(),
            })?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(ClientHelloError::Truncated {
                offset: self.offset,
                needed: len,
                remaining: self.remaining_len(),
            })?;
        self.offset = end;
        Ok(bytes)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ClientHelloError> {
        let offset = self.offset;
        let bytes = self.take(N)?;
        let available = bytes.len();
        bytes.try_into().map_err(|_| ClientHelloError::Truncated {
            offset,
            needed: N,
            remaining: available,
        })
    }

    fn u8(&mut self) -> Result<u8, ClientHelloError> {
        Ok(self.take_array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ClientHelloError> {
        Ok(u16::from_be_bytes(self.take_array::<2>()?))
    }

    fn u24(&mut self) -> Result<usize, ClientHelloError> {
        let bytes = self.take_array::<3>()?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize)
    }
}

#[cfg(test)]
mod tests {
    // Test specs are built field by field to keep each case readable.
    #![allow(clippy::field_reassign_with_default)]

    use super::*;
    use bytes::Bytes;
    use proptest::prelude::*;

    const TEST_SESSION_ID: [u8; 32] = [0xa5; 32];

    #[derive(Clone)]
    struct HelloSpec {
        content_type: u8,
        record_version: u16,
        handshake_type: u8,
        legacy_version: u16,
        random: [u8; 32],
        session_id: Vec<u8>,
        cipher_suites: Vec<u8>,
        compression_methods: Vec<u8>,
        extensions: Vec<Vec<u8>>,
    }

    impl Default for HelloSpec {
        fn default() -> Self {
            Self {
                content_type: 0x16,
                record_version: 0x0301,
                handshake_type: 0x01,
                legacy_version: 0x0303,
                random: [0x42; 32],
                session_id: TEST_SESSION_ID.to_vec(),
                cipher_suites: cipher_suite_bytes(&[0x1301, 0x1302, 0x1303]),
                compression_methods: vec![0x00],
                extensions: vec![
                    sni("whatsapp.net"),
                    supported_versions(&[0x0304, 0x0303]),
                    key_share(&[(0x001d, &[0x99; 32])]),
                    signature_algorithms(&[0x0804, 0x0403, 0x0201]),
                    alpn(&[b"h2", b"http/1.1"]),
                ],
            }
        }
    }

    impl HelloSpec {
        fn build(&self) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&self.legacy_version.to_be_bytes());
            body.extend_from_slice(&self.random);
            body.push(self.session_id.len() as u8);
            body.extend_from_slice(&self.session_id);
            body.extend_from_slice(&(self.cipher_suites.len() as u16).to_be_bytes());
            body.extend_from_slice(&self.cipher_suites);
            body.push(self.compression_methods.len() as u8);
            body.extend_from_slice(&self.compression_methods);
            let extensions: Vec<u8> = self.extensions.iter().flatten().copied().collect();
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);

            let mut handshake = Vec::new();
            handshake.push(self.handshake_type);
            handshake.extend_from_slice(&u24(body.len() as u32));
            handshake.extend_from_slice(&body);

            let mut record = Vec::new();
            record.push(self.content_type);
            record.extend_from_slice(&self.record_version.to_be_bytes());
            record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
            record.extend_from_slice(&handshake);
            record
        }
    }

    fn u24(value: u32) -> [u8; 3] {
        let bytes = value.to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }

    fn cipher_suite_bytes(suites: &[u16]) -> Vec<u8> {
        suites
            .iter()
            .flat_map(|suite| suite.to_be_bytes())
            .collect()
    }

    fn extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&extension_type.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn sni_list(names: &[&str]) -> Vec<u8> {
        let list_len: usize = names.iter().map(|name| 3 + name.len()).sum();
        let mut data = Vec::new();
        data.extend_from_slice(&(list_len as u16).to_be_bytes());
        for name in names {
            data.push(0);
            data.extend_from_slice(&(name.len() as u16).to_be_bytes());
            data.extend_from_slice(name.as_bytes());
        }
        extension(EXT_SERVER_NAME, &data)
    }

    fn sni(name: &str) -> Vec<u8> {
        sni_list(&[name])
    }

    fn supported_versions(versions: &[u16]) -> Vec<u8> {
        let mut data = Vec::new();
        data.push((versions.len() * 2) as u8);
        for &version in versions {
            data.extend_from_slice(&version.to_be_bytes());
        }
        extension(EXT_SUPPORTED_VERSIONS, &data)
    }

    fn key_share(entries: &[(u16, &[u8])]) -> Vec<u8> {
        let entries_len: usize = entries.iter().map(|(_, key)| 4 + key.len()).sum();
        let mut data = Vec::new();
        data.extend_from_slice(&(entries_len as u16).to_be_bytes());
        for (group, key) in entries {
            data.extend_from_slice(&group.to_be_bytes());
            data.extend_from_slice(&(key.len() as u16).to_be_bytes());
            data.extend_from_slice(key);
        }
        extension(EXT_KEY_SHARE, &data)
    }

    fn signature_algorithms(algorithms: &[u16]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&((algorithms.len() * 2) as u16).to_be_bytes());
        for &algorithm in algorithms {
            data.extend_from_slice(&algorithm.to_be_bytes());
        }
        extension(EXT_SIGNATURE_ALGORITHMS, &data)
    }

    fn alpn(protocols: &[&[u8]]) -> Vec<u8> {
        let list_len: usize = protocols.iter().map(|protocol| 1 + protocol.len()).sum();
        let mut data = Vec::new();
        data.extend_from_slice(&(list_len as u16).to_be_bytes());
        for protocol in protocols {
            data.push(protocol.len() as u8);
            data.extend_from_slice(protocol);
        }
        extension(EXT_ALPN, &data)
    }

    #[test]
    fn parses_crafted_tls13_client_hello() {
        let record = HelloSpec::default().build();
        let hello = ClientHello::parse(&record).expect("crafted hello must parse");

        assert_eq!(hello.record_version, 0x0301);
        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(hello.random, [0x42; 32]);
        assert_eq!(hello.session_id, TEST_SESSION_ID.as_slice());
        assert_eq!(
            hello.cipher_suites.iter().collect::<Vec<_>>(),
            vec![0x1301, 0x1302, 0x1303]
        );
        assert_eq!(hello.cipher_suites.len(), 3);
        assert_eq!(hello.cipher_suites.first(), Some(0x1301));
        assert!(hello.cipher_suites.contains(0x1302));
        assert_eq!(hello.compression_methods, &[0x00]);
        assert_eq!(hello.server_name, Some("whatsapp.net"));
        assert_eq!(hello.server_name_bytes(), Some(b"whatsapp.net".as_slice()));
        assert!(hello.supports_tls13());
        assert!(
            hello
                .supported_versions
                .as_ref()
                .is_some_and(|versions| versions.contains(0x0303))
        );
        assert_eq!(
            hello
                .key_share_groups
                .as_ref()
                .map(KeyShareGroups::as_slice),
            Some(&[0x001d][..])
        );
        assert!(hello.has_key_share_group(0x001d));
        assert!(
            hello
                .signature_algorithms
                .as_ref()
                .is_some_and(|algorithms| algorithms.contains(0x0804))
        );
        let alpn = hello.alpn.as_ref().expect("ALPN extension");
        assert_eq!(
            alpn.iter().collect::<Vec<_>>(),
            vec![b"h2".as_slice(), b"http/1.1".as_slice()]
        );
        assert!(alpn.contains(b"h2"));
        assert!(!alpn.contains(b"h3"));

        assert_eq!(hello.raw_record, record.as_slice());
        assert_eq!(hello.raw_client_hello, &record[5..]);
        assert_eq!(hello.client_hello_body(), &record[9..]);
        assert_eq!(hello.extension_count(), 5);
        assert_eq!(hello.extensions().count(), 5);
    }

    #[test]
    fn parses_from_bytes_and_try_from() {
        let record = HelloSpec::default().build();
        let bytes = Bytes::from(record);

        let hello = ClientHello::parse_bytes(&bytes).expect("valid bytes hello");
        assert_eq!(hello.server_name, Some("whatsapp.net"));
        assert_eq!(hello.raw_record.as_ptr(), bytes.as_ptr());
        assert_eq!(hello.raw_record.len(), bytes.len());

        let hello = ClientHello::try_from(&bytes).expect("TryFrom<&Bytes>");
        assert_eq!(hello.server_name, Some("whatsapp.net"));

        let hello = ClientHello::try_from(bytes.as_ref()).expect("TryFrom<&[u8]>");
        assert_eq!(hello.server_name, Some("whatsapp.net"));
    }

    #[test]
    fn rejects_truncation_at_every_byte_boundary() {
        let record = HelloSpec::default().build();
        for cut in 0..record.len() {
            assert!(
                ClientHello::parse(&record[..cut]).is_err(),
                "accepted a {cut}-byte prefix"
            );
        }
        assert!(ClientHello::parse(&record).is_ok());
    }

    #[test]
    fn rejects_wrong_content_type_version_and_handshake_type() {
        let mut spec = HelloSpec::default();
        spec.content_type = 0x17;
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::NotHandshakeRecord(0x17))
        ));

        let mut spec = HelloSpec::default();
        spec.record_version = 0x0302;
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::UnsupportedRecordVersion(0x0302))
        ));

        let mut spec = HelloSpec::default();
        spec.handshake_type = 0x02;
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::NotClientHello(0x02))
        ));
    }

    #[test]
    fn rejects_oversized_record_length() {
        let mut record = HelloSpec::default().build();
        record[3..5].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            ClientHello::parse(&record),
            Err(ClientHelloError::RecordTooLarge {
                length: 65_535,
                max: MAX_RECORD_LEN
            })
        ));
    }

    #[test]
    fn rejects_oversized_client_hello_length() {
        let mut record = HelloSpec::default().build();
        record[6..9].copy_from_slice(&[0xff, 0xff, 0xff]);
        assert!(matches!(
            ClientHello::parse(&record),
            Err(ClientHelloError::ClientHelloTooLarge {
                length: 0x00ff_ffff,
                max: MAX_CLIENT_HELLO_LEN
            })
        ));
    }

    #[test]
    fn rejects_duplicate_sni_extension() {
        let mut spec = HelloSpec::default();
        spec.extensions.push(sni("example.com"));
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::DuplicateExtension(EXT_SERVER_NAME))
        ));
    }

    #[test]
    fn rejects_duplicate_host_name_entries() {
        let mut spec = HelloSpec::default();
        spec.extensions[0] = sni_list(&["whatsapp.net", "example.com"]);
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::MalformedExtension {
                extension: "server_name",
                ..
            })
        ));
    }

    #[test]
    fn keeps_unknown_extensions_and_parses_known_ones() {
        let mut spec = HelloSpec::default();
        spec.extensions
            .push(extension(0x1234, &[0xde, 0xad, 0xbe, 0xef]));
        let record = spec.build();
        let hello = ClientHello::parse(&record).expect("unknown extension must be accepted");

        assert_eq!(hello.server_name, Some("whatsapp.net"));
        assert_eq!(hello.extension_count(), 6);
        let unknown = hello
            .extensions()
            .find(|extension| extension.extension_type == 0x1234)
            .expect("unknown extension is exposed");
        assert_eq!(unknown.data, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn accepts_grease_values() {
        let mut spec = HelloSpec::default();
        spec.cipher_suites = cipher_suite_bytes(&[0x0a0a, 0x1301, 0x1302, 0x1303]);
        spec.extensions[1] = supported_versions(&[0x0a0a, 0x0304, 0x0303]);
        spec.extensions[2] = key_share(&[(0x0a0a, &[]), (0x001d, &[0x11; 32])]);
        spec.extensions[3] = signature_algorithms(&[0x0a0a, 0x0804, 0x0403]);
        spec.extensions.push(extension(0x1a1a, &[0x00]));

        let record = spec.build();
        let hello = ClientHello::parse(&record).expect("GREASE values must be accepted");

        assert!(hello.cipher_suites.contains(0x0a0a));
        assert!(
            hello
                .supported_versions
                .as_ref()
                .is_some_and(|versions| versions.contains(0x0a0a))
        );
        assert_eq!(
            hello
                .key_share_groups
                .as_ref()
                .map(KeyShareGroups::as_slice),
            Some(&[0x0a0a, 0x001d][..])
        );
        assert!(
            hello
                .signature_algorithms
                .as_ref()
                .is_some_and(|algorithms| algorithms.contains(0x0a0a))
        );
        assert!(
            hello
                .extensions()
                .any(|extension| extension.extension_type == 0x1a1a)
        );
    }

    #[test]
    fn accepts_empty_and_reality_session_ids() {
        let mut spec = HelloSpec::default();
        spec.session_id.clear();
        let record = spec.build();
        let hello = ClientHello::parse(&record).expect("empty session id must parse");
        assert!(hello.session_id.is_empty());

        let record = HelloSpec::default().build();
        let hello = ClientHello::parse(&record).expect("32-byte session id");
        assert_eq!(hello.session_id, TEST_SESSION_ID.as_slice());
    }

    #[test]
    fn rejects_oversized_session_id() {
        let mut spec = HelloSpec::default();
        spec.session_id = vec![0x5a; MAX_SESSION_ID_LEN + 1];
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::SessionIdTooLong {
                length: 33,
                max: 32
            })
        ));
    }

    #[test]
    fn rejects_invalid_cipher_suite_lists() {
        let mut spec = HelloSpec::default();
        spec.cipher_suites.clear();
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::InvalidCipherSuitesLength(0))
        ));

        let mut spec = HelloSpec::default();
        spec.cipher_suites = vec![0x13, 0x01, 0x13];
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::InvalidCipherSuitesLength(3))
        ));

        let mut spec = HelloSpec::default();
        spec.cipher_suites = cipher_suite_bytes(&vec![0x1301; MAX_CIPHER_SUITES + 1]);
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::TooManyCipherSuites {
                count: 1_025,
                max: MAX_CIPHER_SUITES
            })
        ));
    }

    #[test]
    fn rejects_empty_compression_methods() {
        let mut spec = HelloSpec::default();
        spec.compression_methods.clear();
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::EmptyCompressionMethods)
        ));
    }

    #[test]
    fn rejects_more_than_max_extensions() {
        let mut spec = HelloSpec::default();
        spec.extensions.clear();
        for index in 0..=MAX_EXTENSIONS {
            spec.extensions.push(extension(0x1000 + index as u16, &[]));
        }
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::TooManyExtensions {
                max: MAX_EXTENSIONS
            })
        ));
    }

    #[test]
    fn rejects_extension_length_past_end() {
        let mut spec = HelloSpec::default();
        let mut malformed = extension(0x1234, &[0xde, 0xad]);
        malformed[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
        spec.extensions.push(malformed);
        assert!(matches!(
            ClientHello::parse(&spec.build()),
            Err(ClientHelloError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_trailing_data_in_client_hello() {
        let mut record = HelloSpec::default().build();

        // Extend the handshake and record lengths by one byte and append that
        // byte, which makes the extension block shorter than the body.
        let handshake_len = u32::from_be_bytes([0, record[6], record[7], record[8]]) as usize;
        let new_len = handshake_len + 1;
        let length = u24(new_len as u32);
        record[6..9].copy_from_slice(&length);
        record.push(0);
        let record_len = (new_len + TLS_HANDSHAKE_HEADER_LEN) as u16;
        record[3..5].copy_from_slice(&record_len.to_be_bytes());

        assert!(matches!(
            ClientHello::parse(&record),
            Err(ClientHelloError::ExtensionsLengthMismatch { .. })
        ));
    }

    #[test]
    fn ignores_bytes_after_the_first_record() {
        let mut record = HelloSpec::default().build();
        let first_record_len = record.len();
        record.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let hello = ClientHello::parse(&record).expect("first record must parse");
        assert_eq!(hello.raw_record.len(), first_record_len);
        assert_eq!(hello.server_name, Some("whatsapp.net"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..=2048)) {
            let _ = ClientHello::parse(&data);

            let bytes = Bytes::from(data);
            let _ = ClientHello::parse_bytes(&bytes);
        }

        #[test]
        fn mutated_valid_hello_never_panics(index in 0usize..256, value in any::<u8>()) {
            let mut record = HelloSpec::default().build();
            if let Some(byte) = record.get_mut(index) {
                *byte = value;
            }
            let _ = ClientHello::parse(&record);
        }
    }
}
