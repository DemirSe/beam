//! Strict `vless://` REALITY client-link parser.
//!
//! The parser is the inverse of [`crate::identity::client_link`]. It accepts
//! exactly the shape beam emits, so a link either yields the values the server
//! was configured with or a typed error. Unknown query parameters are
//! rejected instead of ignored: a silently ignored `security` or `pbk` value
//! would otherwise produce a connection attempt the user did not configure.
//!
//! `fp` is accepted as standard VLESS URI metadata and preserved on
//! [`ParsedClientLink::fingerprint`]. `beam-core` uses its own TLS
//! ClientHello profile when dialing and does not change behavior based on
//! `fp`.
//!
//! Every input byte is hostile. The parser allocates only relative to the
//! bounded input length and never panics.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use thiserror::Error;
use uuid::Uuid;

use crate::client::BeamClientConfig;
use crate::reality::{RealityClientConfig, RealityClientError};
use crate::vless::VISION_FLOW;

/// Maximum accepted URI length in bytes.
pub const MAX_CLIENT_LINK_LEN: usize = 2048;

/// Maximum length of a DNS name in bytes.
const MAX_HOSTNAME_LEN: usize = 253;

/// Maximum length of one DNS label in bytes.
const MAX_LABEL_LEN: usize = 63;

/// Length of an X25519 public key in bytes.
const PUBLIC_KEY_LEN: usize = 32;

/// Maximum length of a REALITY short id in bytes.
const SHORT_ID_MAX_LEN: usize = 8;

const SCHEME: &str = "vless://";

const PARAM_SECURITY: u16 = 1 << 0;
const PARAM_ENCRYPTION: u16 = 1 << 1;
const PARAM_FLOW: u16 = 1 << 2;
const PARAM_TYPE: u16 = 1 << 3;
const PARAM_SERVER_NAME: u16 = 1 << 4;
const PARAM_PUBLIC_KEY: u16 = 1 << 5;
const PARAM_SHORT_ID: u16 = 1 << 6;
const PARAM_FINGERPRINT: u16 = 1 << 7;

/// Reasons a `vless://` link is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClientLinkError {
    /// The link is longer than [`MAX_CLIENT_LINK_LEN`].
    #[error("client link exceeds {MAX_CLIENT_LINK_LEN} bytes")]
    TooLong,

    /// The link does not start with `vless://`.
    #[error("client link does not start with vless://")]
    Scheme,

    /// The link contains a byte that must be percent-encoded, such as a space,
    /// a control character, or a non-ASCII byte.
    #[error("client link contains a character that must be percent-encoded")]
    IllegalCharacter,

    /// The `user@host:port` part is missing or has extra separators.
    #[error("client link has a malformed authority")]
    Authority,

    /// The user part is not a valid UUID.
    #[error("client link has an invalid user id")]
    UserId,

    /// The host is not a bracketed IPv6 address, an IPv4 address, or a hostname.
    #[error("client link has an invalid host")]
    Host,

    /// The port is missing, zero, out of range, or not digits.
    #[error("client link has an invalid port")]
    Port,

    /// A query parameter is empty or has no `=`.
    #[error("client link has a malformed query")]
    Query,

    /// A percent escape is truncated or not hexadecimal.
    #[error("client link has an invalid percent escape")]
    PercentEncoding,

    /// `security` is missing or not `reality`.
    #[error("client link requires security=reality")]
    Security,

    /// `encryption` is present but not `none`.
    #[error("client link supports only encryption=none")]
    Encryption,

    /// `flow` is missing or not `xtls-rprx-vision`.
    #[error("client link requires flow=xtls-rprx-vision")]
    Flow,

    /// `type` is present but not `tcp`.
    #[error("client link supports only type=tcp")]
    Transport,

    /// `pbk` is missing or is not a non-zero 32-byte base64url key.
    #[error("client link has an invalid REALITY public key")]
    PublicKey,

    /// `sid` is missing or is not 2..=16 hexadecimal characters.
    #[error("client link has an invalid REALITY short id")]
    ShortId,

    /// `sni` is missing or is not an IP-free hostname.
    #[error("client link has an invalid REALITY server name")]
    ServerName,

    /// `fp` is present but is not a short ASCII fingerprint name.
    #[error("client link has an invalid fingerprint")]
    Fingerprint,

    /// The query contains a parameter beam does not support.
    #[error("client link has an unknown query parameter")]
    UnknownParameter,

    /// The query repeats a parameter that must appear once.
    #[error("client link repeats a query parameter")]
    DuplicateParameter,
}

/// The values of a parsed `vless://` REALITY link.
pub struct ParsedClientLink {
    /// Raw 16-byte VLESS user UUID.
    pub user_id: [u8; 16],
    /// Host or IP address the client connects to, without IPv6 brackets.
    pub host: String,
    /// TCP port the client connects to.
    pub port: u16,
    /// REALITY server name used as SNI.
    pub server_name: String,
    /// REALITY X25519 public key.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// REALITY short id, 1 to 8 bytes.
    pub short_id: Vec<u8>,
    /// Client fingerprint name from `fp`, preserved as standard VLESS URI
    /// metadata. `beam-core` uses its own TLS ClientHello profile when
    /// dialing and ignores this value.
    pub fingerprint: Option<String>,
    /// Percent-decoded link fragment used as a display name.
    pub label: Option<String>,
}

impl ParsedClientLink {
    /// Builds a [`BeamClientConfig`] for the parsed link.
    ///
    /// `server_addr` is the resolved address of [`Self::host`] and
    /// [`Self::port`], because a share link carries no resolved address.
    pub fn into_beam_client_config(
        self,
        server_addr: SocketAddr,
    ) -> Result<BeamClientConfig, RealityClientError> {
        let short_id_hex = hex::encode(&self.short_id);
        let reality = RealityClientConfig::new(self.public_key, &short_id_hex, self.server_name)?;
        Ok(BeamClientConfig::new(server_addr, reality, self.user_id))
    }
}

impl fmt::Debug for ParsedClientLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedClientLink")
            .field("user_id", &"<redacted>")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("server_name", &self.server_name)
            .field("public_key", &"<redacted>")
            .field("short_id", &"<redacted>")
            .field("fingerprint", &self.fingerprint)
            .field("label", &self.label)
            .finish()
    }
}

/// Parses a `vless://` REALITY link into its connection values.
pub fn parse_client_link(uri: &str) -> Result<ParsedClientLink, ClientLinkError> {
    if uri.len() > MAX_CLIENT_LINK_LEN {
        return Err(ClientLinkError::TooLong);
    }
    if uri.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(ClientLinkError::IllegalCharacter);
    }

    let rest = uri.strip_prefix(SCHEME).ok_or(ClientLinkError::Scheme)?;
    let (rest, label) = match rest.split_once('#') {
        Some((rest, fragment)) => {
            if fragment.contains('#') {
                return Err(ClientLinkError::IllegalCharacter);
            }
            let label = if fragment.is_empty() {
                None
            } else {
                Some(decode_text(fragment)?)
            };
            (rest, label)
        }
        None => (rest, None),
    };

    let (authority, query) = match rest.split_once('?') {
        Some((authority, query)) => {
            if query.contains('?') {
                return Err(ClientLinkError::Query);
            }
            (authority, query)
        }
        None => (rest, ""),
    };

    let (user, host_port) = authority
        .split_once('@')
        .ok_or(ClientLinkError::Authority)?;
    if host_port.contains('@') {
        return Err(ClientLinkError::Authority);
    }
    let user_id = parse_canonical_user_id(user)?;
    let (host, port) = parse_host_port(host_port)?;

    if query.is_empty() {
        return Err(ClientLinkError::Security);
    }

    let mut seen = 0u16;
    let mut server_name = None;
    let mut public_key = None;
    let mut short_id = None;
    let mut fingerprint = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').ok_or(ClientLinkError::Query)?;
        let decoded = percent_decode(value)?;
        match key {
            "security" => {
                mark(&mut seen, PARAM_SECURITY)?;
                if decoded.as_slice() != b"reality" {
                    return Err(ClientLinkError::Security);
                }
            }
            "encryption" => {
                mark(&mut seen, PARAM_ENCRYPTION)?;
                if decoded.as_slice() != b"none" {
                    return Err(ClientLinkError::Encryption);
                }
            }
            "flow" => {
                mark(&mut seen, PARAM_FLOW)?;
                if decoded.as_slice() != VISION_FLOW.as_bytes() {
                    return Err(ClientLinkError::Flow);
                }
            }
            "type" => {
                mark(&mut seen, PARAM_TYPE)?;
                if decoded.as_slice() != b"tcp" {
                    return Err(ClientLinkError::Transport);
                }
            }
            "sni" => {
                mark(&mut seen, PARAM_SERVER_NAME)?;
                server_name = Some(parse_server_name(&decoded)?);
            }
            "pbk" => {
                mark(&mut seen, PARAM_PUBLIC_KEY)?;
                public_key = Some(parse_public_key(&decoded)?);
            }
            "sid" => {
                mark(&mut seen, PARAM_SHORT_ID)?;
                short_id = Some(parse_short_id(&decoded)?);
            }
            "fp" => {
                mark(&mut seen, PARAM_FINGERPRINT)?;
                fingerprint = Some(parse_fingerprint(&decoded)?);
            }
            _ => return Err(ClientLinkError::UnknownParameter),
        }
    }

    if seen & PARAM_SECURITY == 0 {
        return Err(ClientLinkError::Security);
    }
    if seen & PARAM_FLOW == 0 {
        return Err(ClientLinkError::Flow);
    }

    Ok(ParsedClientLink {
        user_id,
        host,
        port,
        server_name: server_name.ok_or(ClientLinkError::ServerName)?,
        public_key: public_key.ok_or(ClientLinkError::PublicKey)?,
        short_id: short_id.ok_or(ClientLinkError::ShortId)?,
        fingerprint,
        label,
    })
}

/// Parses a canonical 36-char hyphenated UUID (`8-4-4-4-12`) into raw bytes.
///
/// The hyphen-position check runs before [`Uuid::parse_str`] so 32-char
/// unhyphenated, braced, or otherwise non-canonical forms fail as
/// [`ClientLinkError::UserId`] instead of parsing as an equivalent UUID.
fn parse_canonical_user_id(user: &str) -> Result<[u8; 16], ClientLinkError> {
    let bytes = user.as_bytes();
    if user.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
    {
        return Err(ClientLinkError::UserId);
    }
    Ok(Uuid::parse_str(user)
        .map_err(|_| ClientLinkError::UserId)?
        .into_bytes())
}

/// Splits and validates `host:port`, accepting bracketed IPv6 hosts.
fn parse_host_port(input: &str) -> Result<(String, u16), ClientLinkError> {
    if let Some(bracketed) = input.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']').ok_or(ClientLinkError::Host)?;
        Ipv6Addr::from_str(host).map_err(|_| ClientLinkError::Host)?;
        let port = after.strip_prefix(':').ok_or(ClientLinkError::Port)?;
        return Ok((host.to_owned(), parse_port(port)?));
    }
    if input.contains(['[', ']']) {
        return Err(ClientLinkError::Host);
    }
    // An unbracketed IPv6 literal cannot be split unambiguously and is
    // rejected by the hostname rules below.
    let (host, port) = input.rsplit_once(':').ok_or(ClientLinkError::Port)?;
    validate_host(host)?;
    Ok((host.to_owned(), parse_port(port)?))
}

/// Returns the port for a digit-only string in `1..=65535`.
fn parse_port(text: &str) -> Result<u16, ClientLinkError> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ClientLinkError::Port);
    }
    let port: u16 = text.parse().map_err(|_| ClientLinkError::Port)?;
    if port == 0 {
        return Err(ClientLinkError::Port);
    }
    Ok(port)
}

/// Accepts an IPv4 address or a hostname.
///
/// A dotted string made only of digits must parse as an [`Ipv4Addr`].
/// Decimal dotted-numeric forms that are not IPv4 addresses (e.g.
/// `999.999.999.999` or `1.2.3`) are therefore rejected, so a mistyped numeric
/// address cannot route as a DNS name.
fn validate_host(host: &str) -> Result<(), ClientLinkError> {
    if host.is_empty() {
        return Err(ClientLinkError::Host);
    }
    if host.contains('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Ipv4Addr::from_str(host)
            .map(|_| ())
            .map_err(|_| ClientLinkError::Host);
    }
    if is_hostname(host) || Ipv4Addr::from_str(host).is_ok() {
        Ok(())
    } else {
        Err(ClientLinkError::Host)
    }
}

/// Returns `true` for a DNS name made of dot-separated LDH labels.
fn is_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOSTNAME_LEN
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// Rejects an SNI that is an IP address or not a DNS name.
fn parse_server_name(value: &[u8]) -> Result<String, ClientLinkError> {
    let name = std::str::from_utf8(value).map_err(|_| ClientLinkError::ServerName)?;
    if name.contains(':') || Ipv4Addr::from_str(name).is_ok() || !is_hostname(name) {
        return Err(ClientLinkError::ServerName);
    }
    Ok(name.to_owned())
}

/// Decodes a base64url X25519 public key.
fn parse_public_key(value: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], ClientLinkError> {
    let key = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ClientLinkError::PublicKey)?;
    let key: [u8; PUBLIC_KEY_LEN] = key.try_into().map_err(|_| ClientLinkError::PublicKey)?;
    if key.iter().all(|&byte| byte == 0) {
        return Err(ClientLinkError::PublicKey);
    }
    Ok(key)
}

/// Decodes a REALITY short id of 1 to 8 bytes.
fn parse_short_id(value: &[u8]) -> Result<Vec<u8>, ClientLinkError> {
    if value.len() < 2 || value.len() > SHORT_ID_MAX_LEN * 2 || !value.len().is_multiple_of(2) {
        return Err(ClientLinkError::ShortId);
    }
    hex::decode(value).map_err(|_| ClientLinkError::ShortId)
}

/// Accepts a short ASCII fingerprint name such as `chrome`.
///
/// The value is preserved as standard VLESS URI metadata only; `beam-core`
/// dials with its own TLS ClientHello profile.
fn parse_fingerprint(value: &[u8]) -> Result<String, ClientLinkError> {
    let name = std::str::from_utf8(value).map_err(|_| ClientLinkError::Fingerprint)?;
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ClientLinkError::Fingerprint);
    }
    Ok(name.to_owned())
}

/// Records one query parameter and rejects a repetition.
fn mark(seen: &mut u16, bit: u16) -> Result<(), ClientLinkError> {
    if *seen & bit != 0 {
        return Err(ClientLinkError::DuplicateParameter);
    }
    *seen |= bit;
    Ok(())
}

/// Percent-decodes a query value or fragment into UTF-8 text.
fn decode_text(input: &str) -> Result<String, ClientLinkError> {
    let bytes = percent_decode(input)?;
    if bytes.iter().any(|&byte| byte < 0x20 || byte == 0x7f) {
        return Err(ClientLinkError::IllegalCharacter);
    }
    String::from_utf8(bytes).map_err(|_| ClientLinkError::PercentEncoding)
}

/// Percent-decodes `input` into raw bytes.
fn percent_decode(input: &str) -> Result<Vec<u8>, ClientLinkError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes
                .get(index + 1)
                .copied()
                .and_then(hex_value)
                .ok_or(ClientLinkError::PercentEncoding)?;
            let low = bytes
                .get(index + 2)
                .copied()
                .and_then(hex_value)
                .ok_or(ClientLinkError::PercentEncoding)?;
            out.push(high << 4 | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Ok(out)
}

/// Returns the value of one ASCII hexadecimal digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{ClientLink, client_link};
    use proptest::prelude::*;

    const USER_ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const SERVER_NAME: &str = "whatsapp.net";
    const SHORT_ID_HEX: &str = "0123456789abcdef";
    const KEY: [u8; PUBLIC_KEY_LEN] = [0x5a; PUBLIC_KEY_LEN];

    fn public_key() -> String {
        URL_SAFE_NO_PAD.encode(KEY)
    }

    fn user_id() -> Uuid {
        Uuid::parse_str(USER_ID).expect("test uuid")
    }

    fn generated_link(host: &str, port: u16, remark: &str) -> String {
        client_link(&ClientLink {
            user_id: user_id(),
            host,
            port,
            server_name: SERVER_NAME,
            public_key: &public_key(),
            short_id: SHORT_ID_HEX,
            remark,
        })
    }

    fn good_query() -> String {
        format!(
            "encryption=none&security=reality&sni={SERVER_NAME}&fp=chrome\
             &pbk={}&sid={SHORT_ID_HEX}&type=tcp&flow=xtls-rprx-vision",
            public_key()
        )
    }

    fn link_with(query: &str) -> String {
        format!("vless://{USER_ID}@203.0.113.10:443?{query}")
    }

    #[test]
    fn generated_links_round_trip() {
        for (host, port, remark) in [
            ("203.0.113.10", 443u16, "beam"),
            ("2001:db8::1", 8443, "beam"),
            ("beam.example.com", 443, "my server #1 & more"),
            ("beam.example.com", 443, "sérv"),
        ] {
            let uri = generated_link(host, port, remark);
            let parsed = parse_client_link(&uri).unwrap_or_else(|error| {
                panic!("generated link {uri} must parse: {error}");
            });
            assert_eq!(parsed.user_id, *user_id().as_bytes(), "{uri}");
            assert_eq!(parsed.host, host, "{uri}");
            assert_eq!(parsed.port, port, "{uri}");
            assert_eq!(parsed.server_name, SERVER_NAME, "{uri}");
            assert_eq!(parsed.public_key, KEY, "{uri}");
            assert_eq!(parsed.short_id, hex::decode(SHORT_ID_HEX).unwrap(), "{uri}");
            assert_eq!(parsed.fingerprint.as_deref(), Some("chrome"), "{uri}");
            assert_eq!(parsed.label.as_deref(), Some(remark), "{uri}");
        }
    }

    #[test]
    fn optional_parameters_may_be_absent() {
        let query = format!(
            "security=reality&sni={SERVER_NAME}&pbk={}&sid=01&flow=xtls-rprx-vision",
            public_key()
        );
        let parsed = parse_client_link(&link_with(&query)).expect("minimal link");
        assert_eq!(parsed.fingerprint, None);
        assert_eq!(parsed.short_id, vec![1]);
        assert_eq!(parsed.label, None);
    }

    #[test]
    fn parsed_link_builds_a_beam_client_config() {
        let parsed =
            parse_client_link(&generated_link("2001:db8::1", 443, "beam")).expect("generated link");
        let server_addr: SocketAddr = "[2001:db8::1]:443".parse().expect("address");
        let config = parsed
            .into_beam_client_config(server_addr)
            .expect("config from parsed link");

        assert_eq!(config.server_addr, server_addr);
        assert_eq!(config.user_id, *user_id().as_bytes());
        assert_eq!(config.reality.server_name, SERVER_NAME);
        assert_eq!(config.reality.server_public_key, KEY);
        assert_eq!(
            &config.reality.short_id[..],
            &hex::decode(SHORT_ID_HEX).unwrap()[..]
        );
        assert!(!format!("{config:?}").contains(USER_ID));
    }

    #[test]
    fn rejects_malformed_links() {
        let good = good_query();
        let cases = vec![
            (String::new(), ClientLinkError::Scheme),
            (
                format!("vlesss://{USER_ID}@203.0.113.10:443?{good}"),
                ClientLinkError::Scheme,
            ),
            (
                format!("VLESS://{USER_ID}@203.0.113.10:443?{good}"),
                ClientLinkError::Scheme,
            ),
            (
                link_with(&good).replace('@', ""),
                ClientLinkError::Authority,
            ),
            (
                link_with(&good).replace("203.0.113.10", "a@203.0.113.10"),
                ClientLinkError::Authority,
            ),
            (
                link_with(&good).replace(USER_ID, "not-a-uuid"),
                ClientLinkError::UserId,
            ),
            (
                link_with(&good).replace(":443?", ":0?"),
                ClientLinkError::Port,
            ),
            (
                link_with(&good).replace(":443?", ":65536?"),
                ClientLinkError::Port,
            ),
            (
                link_with(&good).replace(":443?", ":+443?"),
                ClientLinkError::Port,
            ),
            (
                link_with(&good).replace(":443?", ":44a?"),
                ClientLinkError::Port,
            ),
            (
                link_with(&good).replace(":443?", "?"),
                ClientLinkError::Port,
            ),
            (
                link_with(&good).replace("203.0.113.10", "2001:db8::1"),
                ClientLinkError::Host,
            ),
            (
                link_with(&good).replace("203.0.113.10", "[not:ipv6]"),
                ClientLinkError::Host,
            ),
            (
                link_with(&good).replace("203.0.113.10", "bad_host"),
                ClientLinkError::Host,
            ),
            (
                link_with(&good).replace("203.0.113.10", "-bad.example.com"),
                ClientLinkError::Host,
            ),
            (
                link_with(&good).replace("203.0.113.10", "bad..example.com"),
                ClientLinkError::Host,
            ),
            (
                link_with(&good).replace("203.0.113.10", &"a".repeat(64)),
                ClientLinkError::Host,
            ),
            (
                link_with(&good.replace("security=reality&", "")),
                ClientLinkError::Security,
            ),
            (
                link_with(&good.replace("security=reality", "security=tls")),
                ClientLinkError::Security,
            ),
            (
                link_with(&good.replace("security=reality", "security=reality&security=reality")),
                ClientLinkError::DuplicateParameter,
            ),
            (
                link_with(&good.replace("encryption=none", "encryption=reality")),
                ClientLinkError::Encryption,
            ),
            (
                link_with(&good.replace("flow=xtls-rprx-vision", "flow=vless-rprx-vision")),
                ClientLinkError::Flow,
            ),
            (
                link_with(&good.replace("&flow=xtls-rprx-vision", "")),
                ClientLinkError::Flow,
            ),
            (
                link_with(&good.replace("type=tcp", "type=udp")),
                ClientLinkError::Transport,
            ),
            (
                link_with(&good.replace(&format!("pbk={}", public_key()), "pbk=short")),
                ClientLinkError::PublicKey,
            ),
            (
                link_with(&good.replace(
                    &format!("pbk={}", public_key()),
                    &format!("pbk={}={}", &public_key()[..42], "="),
                )),
                ClientLinkError::PublicKey,
            ),
            (
                link_with(&good.replace(
                    &format!("pbk={}", public_key()),
                    &format!("pbk={}", URL_SAFE_NO_PAD.encode([0u8; PUBLIC_KEY_LEN])),
                )),
                ClientLinkError::PublicKey,
            ),
            (
                link_with(&good.replace(SHORT_ID_HEX, "012")),
                ClientLinkError::ShortId,
            ),
            (
                link_with(&good.replace(SHORT_ID_HEX, "0")),
                ClientLinkError::ShortId,
            ),
            (
                link_with(&good.replace(SHORT_ID_HEX, "0123456789abcdef00")),
                ClientLinkError::ShortId,
            ),
            (
                link_with(&good.replace(SHORT_ID_HEX, "zz")),
                ClientLinkError::ShortId,
            ),
            (
                link_with(&good.replace(&format!("sni={SERVER_NAME}"), "sni=203.0.113.10")),
                ClientLinkError::ServerName,
            ),
            (
                link_with(&good.replace(&format!("sni={SERVER_NAME}"), "sni=2001:db8::1")),
                ClientLinkError::ServerName,
            ),
            (
                link_with(&good.replace(&format!("sni={SERVER_NAME}"), "sni=")),
                ClientLinkError::ServerName,
            ),
            (
                link_with(&good.replace("fp=chrome", "fp=chr%20ome")),
                ClientLinkError::Fingerprint,
            ),
            (
                link_with(&good.replace("fp=chrome", "fp=")),
                ClientLinkError::Fingerprint,
            ),
            (
                link_with(&good.replace(SHORT_ID_HEX, "0123456789abcdef&sid=0123")),
                ClientLinkError::DuplicateParameter,
            ),
            (
                link_with(&good.replace("&flow", "&alpn=h2&flow")),
                ClientLinkError::UnknownParameter,
            ),
            (
                link_with(&good.replace("flow=xtls", "=flow=xtls")),
                ClientLinkError::UnknownParameter,
            ),
            (
                link_with(&good.replace("sni=", "sni=%zz")),
                ClientLinkError::PercentEncoding,
            ),
            (
                link_with(&good.replace("sni=", "sni=%1")),
                ClientLinkError::PercentEncoding,
            ),
            (
                link_with(&good.replace("sni=", "sni=%2")),
                ClientLinkError::PercentEncoding,
            ),
            (format!("{}&", link_with(&good)), ClientLinkError::Query),
            (
                format!("{}#one#two", link_with(&good)),
                ClientLinkError::IllegalCharacter,
            ),
            (
                format!("{}?second", link_with(&good)),
                ClientLinkError::Query,
            ),
            (
                format!("{} ", link_with(&good)),
                ClientLinkError::IllegalCharacter,
            ),
            (
                format!("{}\n", link_with(&good)),
                ClientLinkError::IllegalCharacter,
            ),
            (
                format!("{}\u{00e9}", link_with(&good)),
                ClientLinkError::IllegalCharacter,
            ),
            (
                link_with(&good.replace("reality", "reality%00")),
                ClientLinkError::Security,
            ),
            (
                format!(
                    "vless://{USER_ID}@203.0.113.10:443?{}",
                    good.replace('&', "&&")
                ),
                ClientLinkError::Query,
            ),
        ];

        for (uri, expected) in cases {
            assert_eq!(
                parse_client_link(&uri).err(),
                Some(expected),
                "rejected link: {uri}"
            );
        }
    }

    #[test]
    fn rejects_non_canonical_uuid_forms() {
        let good = good_query();
        let unhyphenated = USER_ID.replace('-', "");
        assert_eq!(unhyphenated.len(), 32);
        for (user, expected) in [
            (unhyphenated.as_str(), ClientLinkError::UserId),
            (
                "b831381d-6324-4d53-ad4f-8cda48b3081",
                ClientLinkError::UserId,
            ),
            (
                "b831381d6324-4d53-ad4f-8cda48b30811",
                ClientLinkError::UserId,
            ),
            (
                "{b831381d-6324-4d53-ad4f-8cda48b30811}",
                ClientLinkError::UserId,
            ),
            (
                "not-a-uuid-at-all-see-reject-me-now",
                ClientLinkError::UserId,
            ),
        ] {
            let uri = format!("vless://{user}@203.0.113.10:443?{good}");
            assert_eq!(
                parse_client_link(&uri).err(),
                Some(expected),
                "user: {user}"
            );
        }
    }

    #[test]
    fn rejects_all_numeric_dotted_hosts_that_are_not_ipv4() {
        let good = good_query();
        for host in ["999.999.999.999", "1.2.3", "1.2.3.4.5", "256.1.1.1"] {
            let uri = format!("vless://{USER_ID}@{host}:443?{good}");
            assert_eq!(
                parse_client_link(&uri).err(),
                Some(ClientLinkError::Host),
                "host: {host}"
            );
        }
    }

    #[test]
    fn rejects_empty_host_and_missing_or_empty_query() {
        let good = good_query();
        assert_eq!(
            parse_client_link(&format!("vless://{USER_ID}@:443?{good}")).err(),
            Some(ClientLinkError::Host)
        );
        assert_eq!(
            parse_client_link(&format!("vless://{USER_ID}@203.0.113.10:443")).err(),
            Some(ClientLinkError::Security)
        );
        assert_eq!(
            parse_client_link(&format!("vless://{USER_ID}@203.0.113.10:443?")).err(),
            Some(ClientLinkError::Security)
        );
    }

    #[test]
    fn rejects_oversized_links_before_parsing() {
        let mut uri = generated_link("203.0.113.10", 443, "beam");
        assert!(parse_client_link(&uri).is_ok());
        uri.push_str(&"a".repeat(MAX_CLIENT_LINK_LEN));
        assert_eq!(
            parse_client_link(&uri).err(),
            Some(ClientLinkError::TooLong)
        );
    }

    #[test]
    fn hostile_query_names_and_values_stay_bounded() {
        for query in [
            "==",
            "&&&",
            "security",
            "=reality",
            "security=",
            "security=reality&security",
            "pbk=&sid=&sni=&flow=",
        ] {
            assert!(
                parse_client_link(&link_with(query)).is_err(),
                "query must be rejected: {query}"
            );
        }
    }

    #[test]
    fn debug_redacts_the_secret_material() {
        let parsed = parse_client_link(&generated_link("203.0.113.10", 443, "beam"))
            .expect("generated link");
        let rendered = format!("{parsed:?}");

        assert_eq!(rendered.matches("<redacted>").count(), 3, "{rendered}");
        assert!(!rendered.contains(USER_ID), "{rendered}");
        assert!(
            !rendered.contains(&hex::encode(&parsed.short_id)),
            "{rendered}"
        );
        assert!(!rendered.contains(&public_key()), "{rendered}");
        assert!(
            !rendered.contains(&URL_SAFE_NO_PAD.encode(KEY)),
            "{rendered}"
        );
    }

    proptest! {
        #[test]
        fn parsing_arbitrary_text_never_panics(input in ".{0,600}") {
            let _ = parse_client_link(&input);
        }

        #[test]
        fn parsing_links_with_arbitrary_queries_never_panics(query in ".{0,256}") {
            let _ = parse_client_link(&format!("vless://{USER_ID}@203.0.113.10:443?{query}"));
        }
    }
}
