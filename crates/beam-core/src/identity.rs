//! Generation of REALITY and VLESS identity material.
//!
//! The module produces the values a new deployment needs: a VLESS user id, a
//! REALITY X25519 keypair, a short id, and an Xray-compatible client link.
//! Random bytes come from the aws-lc-rs source that rustls already uses, so
//! generation adds no dependency and no second RNG.
//!
//! The private key is held in [`Zeroizing`] memory, never appears in `Debug`
//! output, and is the only generated value that must stay on the server.

use std::fmt;
use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Length of an X25519 private or public key.
pub const X25519_KEY_LEN: usize = 32;

/// Length of a REALITY short id in bytes.
pub const SHORT_ID_LEN: usize = 8;

/// Errors returned while generating identity material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The system random source failed.
    #[error("system random source failed")]
    Entropy,
}

/// A generated REALITY X25519 keypair.
pub struct RealityKeyPair {
    private: Zeroizing<[u8; X25519_KEY_LEN]>,
    public: [u8; X25519_KEY_LEN],
}

impl RealityKeyPair {
    /// Generates a keypair from the system random source.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut private = Zeroizing::new([0u8; X25519_KEY_LEN]);
        fill_random(&mut private[..])?;
        let public = PublicKey::from(&StaticSecret::from(*private)).to_bytes();
        Ok(Self { private, public })
    }

    /// Returns the private key as unpadded base64url.
    ///
    /// This is the `reality.private_key` value. Keep it secret; it is zeroized
    /// when the returned buffer is dropped.
    pub fn private_key(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.private.as_slice()))
    }

    /// Returns the public key as unpadded base64url.
    ///
    /// This is the `pbk` value of a REALITY client. It is not a secret.
    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public)
    }
}

impl fmt::Debug for RealityKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityKeyPair")
            .field("private", &"<redacted>")
            .field("public", &self.public_key())
            .finish()
    }
}

/// Generates an RFC 4122 version 4 (random) UUID for `user.id`.
pub fn generate_uuid() -> Result<Uuid, IdentityError> {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes)?;
    // Random version 4 and RFC 4122 variant bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

/// Generates a REALITY short id: 8 random bytes as 16 hex characters.
///
/// Xray and beam accept 2 to 16 hex characters. Eight bytes is the largest
/// value, and it is the length the README documents.
pub fn generate_short_id() -> Result<String, IdentityError> {
    let mut bytes = Zeroizing::new([0u8; SHORT_ID_LEN]);
    fill_random(&mut bytes[..])?;
    Ok(hex::encode(bytes.as_slice()))
}

/// The values of a stock VLESS share link.
pub struct ClientLink<'a> {
    /// VLESS user id.
    pub user_id: Uuid,
    /// Host or IP address the client connects to.
    pub host: &'a str,
    /// TCP port the client connects to.
    pub port: u16,
    /// REALITY server name used as SNI.
    pub server_name: &'a str,
    /// REALITY public key in unpadded base64url.
    pub public_key: &'a str,
    /// REALITY short id in hex.
    pub short_id: &'a str,
    /// Display name shown by the client.
    pub remark: &'a str,
}

/// Renders a `vless://` link that stock Xray and sing-box accept.
///
/// The parameters match a REALITY + Vision TCP outbound. `spx` is absent
/// because both clients default it to `/`.
pub fn client_link(link: &ClientLink<'_>) -> String {
    let host = match link.host {
        host if host.contains(':') && !host.starts_with('[') => format!("[{host}]"),
        host => host.to_owned(),
    };
    format!(
        "vless://{user}@{host}:{port}?encryption=none&security=reality\
         &sni={sni}&fp=chrome&pbk={pbk}&sid={sid}&type=tcp\
         &flow=xtls-rprx-vision#{remark}",
        user = link.user_id,
        port = link.port,
        sni = encode_component(link.server_name),
        pbk = encode_component(link.public_key),
        sid = encode_component(link.short_id),
        remark = encode_component(link.remark),
    )
}

/// Fills `bytes` from the aws-lc-rs secure random source.
fn fill_random(bytes: &mut [u8]) -> Result<(), IdentityError> {
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(bytes)
        .map_err(|_| IdentityError::Entropy)
}

/// Percent-encodes one URI query or fragment value.
///
/// Bytes outside the RFC 3986 unreserved set are escaped, so a server name or
/// remark that contains `#`, `&`, or a space cannot break the link.
fn encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::reality::auth::decode_short_id;

    const SERVER_NAME: &str = "whatsapp.net";

    #[test]
    fn generated_identity_validates_as_a_server_configuration() {
        let keys = RealityKeyPair::generate().expect("keypair generation");
        let user_id = generate_uuid().expect("uuid generation");
        let short_id = generate_short_id().expect("short id generation");
        let private_key = keys.private_key();
        let toml = format!(
            r#"
[server]
listen = "0.0.0.0:443"

[user]
id = "{user_id}"
flow = "xtls-rprx-vision"

[reality]
private_key = "{private}"
short_ids = ["{short_id}"]
server_names = ["{SERVER_NAME}"]
dest = "{SERVER_NAME}:443"

[log]
level = "warn"

[limits]
max_connections = 1024
max_udp_destinations = 2048
handshake_timeout_ms = 10000
idle_timeout_ms = 300000
"#,
            private = private_key.as_str(),
        );

        let config = Config::from_toml_str(&toml).expect("generated identity must validate");
        assert_eq!(config.user.id, user_id);
        assert_eq!(config.reality.short_ids, vec![short_id]);
        assert_eq!(config.reality.server_names, vec![SERVER_NAME.to_owned()]);
    }

    #[test]
    fn generated_public_key_is_derived_from_the_private_key() {
        let keys = RealityKeyPair::generate().expect("keypair generation");
        let private_key = keys.private_key();

        let decoded = URL_SAFE_NO_PAD
            .decode(private_key.as_str())
            .expect("private key is base64url");
        assert_eq!(decoded.len(), X25519_KEY_LEN);
        let raw: [u8; X25519_KEY_LEN] = decoded.as_slice().try_into().expect("32-byte key");
        let derived = PublicKey::from(&StaticSecret::from(raw)).to_bytes();

        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(keys.public_key())
                .expect("public key is base64url"),
            derived
        );
    }

    #[test]
    fn generated_uuid_is_version_4() {
        let user_id = generate_uuid().expect("uuid generation");
        assert_eq!(user_id.get_version_num(), 4);
        assert_eq!(user_id.get_variant(), uuid::Variant::RFC4122);
        assert!(!user_id.is_nil());
    }

    #[test]
    fn generated_short_id_is_eight_bytes_of_lowercase_hex() {
        let short_id = generate_short_id().expect("short id generation");
        assert_eq!(short_id.len(), SHORT_ID_LEN * 2);
        assert!(
            short_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{short_id} must be lowercase hex"
        );
        // The REALITY authenticator must accept what the generator emits.
        let decoded = decode_short_id(&short_id).expect("generated short id must decode");
        assert_eq!(decoded.len(), SHORT_ID_LEN);
    }

    #[test]
    fn generated_values_differ_between_calls() {
        let first = generate_uuid().expect("uuid generation");
        let second = generate_uuid().expect("uuid generation");
        assert_ne!(first, second);

        let first = generate_short_id().expect("short id generation");
        let second = generate_short_id().expect("short id generation");
        assert_ne!(first, second);

        let first = RealityKeyPair::generate().expect("keypair generation");
        let second = RealityKeyPair::generate().expect("keypair generation");
        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn debug_redacts_the_private_key() {
        let keys = RealityKeyPair::generate().expect("keypair generation");
        let rendered = format!("{keys:?}");
        assert!(rendered.contains("private: \"<redacted>\""));
        assert!(!rendered.contains(keys.private_key().as_str()));
    }

    #[test]
    fn client_link_matches_the_stock_xray_format() {
        let user_id = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").expect("test uuid");
        let link = client_link(&ClientLink {
            user_id,
            host: "203.0.113.10",
            port: 443,
            server_name: SERVER_NAME,
            public_key: "aGVsbG8_d29ybGQ",
            short_id: "0123456789abcdef",
            remark: "beam",
        });

        assert_eq!(
            link,
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443\
             ?encryption=none&security=reality&sni=whatsapp.net&fp=chrome\
             &pbk=aGVsbG8_d29ybGQ&sid=0123456789abcdef&type=tcp\
             &flow=xtls-rprx-vision#beam"
        );
    }

    #[test]
    fn client_link_brackets_ipv6_hosts() {
        let link = client_link(&ClientLink {
            user_id: Uuid::nil(),
            host: "2001:db8::1",
            port: 8443,
            server_name: SERVER_NAME,
            public_key: "key",
            short_id: "01",
            remark: "beam",
        });

        assert!(link.contains("@[2001:db8::1]:8443?"), "{link}");
    }

    #[test]
    fn client_link_escapes_values_that_would_break_it() {
        let link = client_link(&ClientLink {
            user_id: Uuid::nil(),
            host: "example.com",
            port: 443,
            server_name: "example.com",
            public_key: "key",
            short_id: "01",
            remark: "my server #1",
        });

        assert!(link.ends_with("#my%20server%20%231"), "{link}");
        assert_eq!(link.matches('#').count(), 1);
    }

    #[test]
    fn encode_component_keeps_unreserved_characters() {
        assert_eq!(encode_component("A-z.0_9~"), "A-z.0_9~");
        assert_eq!(encode_component("a b"), "a%20b");
        assert_eq!(encode_component("/?&="), "%2F%3F%26%3D");
    }
}
