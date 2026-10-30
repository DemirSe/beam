//! REALITY ClientHello envelope authentication.
//!
//! The envelope is carried in the TLS 1.3 `legacy_session_id` and is opened
//! with AES-256-GCM after deriving a key from the X25519 shared secret. See
//! `docs/07-reality-spec.md` for the wire format.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::tls::{ClientHello, MAX_RECORD_LEN};

const X25519_GROUP: u16 = 0x001d;
const X25519_MLKEM768_GROUP: u16 = 0x11ec;
const X25519_SHARE_LEN: usize = 32;
const X25519_MLKEM768_SHARE_LEN: usize = 1_216;
const SESSION_ID_LEN: usize = 32;
const AUTH_PLAINTEXT_LEN: usize = 16;
const SESSION_ID_START: usize = 39;
const SESSION_ID_END: usize = SESSION_ID_START + SESSION_ID_LEN;
const HKDF_INFO: &[u8] = b"REALITY";

/// Configuration needed to authenticate a REALITY ClientHello.
pub struct RealityAuthConfig<'a> {
    /// The server's static X25519 private key.
    pub private_key: &'a [u8; 32],
    /// Configured short ids as hex strings, decoded and zero-padded to 8 bytes.
    pub short_ids: &'a [String],
    /// Accepted TLS server names.
    pub server_names: &'a [String],
    /// Minimum accepted client version.
    pub min_client_version: [u8; 3],
    /// Maximum accepted client version.
    pub max_client_version: [u8; 3],
    /// Optional maximum clock difference for the client timestamp.
    ///
    /// `None` disables the timestamp check.
    pub max_time_diff: Option<Duration>,
}

impl fmt::Debug for RealityAuthConfig<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityAuthConfig")
            .field("private_key", &"<redacted>")
            .field("short_ids", &"<redacted>")
            .field("server_names", &self.server_names)
            .field("min_client_version", &self.min_client_version)
            .field("max_client_version", &self.max_client_version)
            .field("max_time_diff", &self.max_time_diff)
            .finish()
    }
}

/// The authenticated REALITY envelope fields and derived authentication key.
pub struct Auth {
    /// The REALITY authentication key used by the server flight.
    pub auth_key: Zeroizing<[u8; 32]>,
    /// Client version from the envelope.
    pub client_version: [u8; 3],
    /// Client Unix timestamp from the envelope.
    pub timestamp: u32,
    /// Client short id from the envelope, zero-padded to 8 bytes.
    pub short_id: [u8; 8],
    /// Encrypted 32-byte REALITY session id from the ClientHello.
    pub session_id: [u8; 32],
}

impl fmt::Debug for Auth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Auth")
            .field("auth_key", &"<redacted>")
            .field("client_version", &self.client_version)
            .field("timestamp", &self.timestamp)
            .field("short_id", &"<redacted>")
            .field("session_id", &"<redacted>")
            .finish()
    }
}

/// Errors returned by REALITY envelope authentication.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The ClientHello did not advertise TLS 1.3.
    #[error("REALITY requires TLS 1.3")]
    Tls13Required,

    /// The SNI was absent or not configured.
    #[error("REALITY server name is missing or not configured")]
    ServerNameMismatch,

    /// No supported key share was present.
    #[error("REALITY requires an X25519 or X25519MLKEM768 key share")]
    MissingKeyShare,

    /// A key share had the wrong length.
    #[error("key share for group {group:#06x} has invalid length {length}")]
    InvalidKeyShareLength {
        /// The named group.
        group: u16,
        /// The observed key-exchange length.
        length: usize,
    },

    /// X25519 produced a non-contributory shared secret.
    #[error("X25519 key agreement failed")]
    KeyAgreement,

    /// HKDF expansion failed.
    #[error("REALITY key derivation failed")]
    KeyDerivation,

    /// AES-256-GCM initialization failed.
    #[error("REALITY cipher initialization failed")]
    CipherInit,

    /// The session id was not the required 32-byte envelope.
    #[error("REALITY session id must be exactly 32 bytes")]
    InvalidSessionId,

    /// The raw ClientHello could not hold the authentication envelope.
    #[error("ClientHello is not structurally usable for REALITY authentication")]
    InvalidClientHello,

    /// The temporary AAD buffer could not be allocated.
    #[error("REALITY authentication buffer allocation failed")]
    Allocation,

    /// AES-GCM authentication failed.
    #[error("REALITY envelope authentication failed")]
    DecryptFailed,

    /// The decrypted envelope had the wrong length.
    #[error("REALITY envelope plaintext has invalid length")]
    InvalidPlaintext,

    /// The client version was outside the configured range.
    #[error("client version is outside the configured REALITY range")]
    UnsupportedClientVersion,

    /// The system clock was before the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    Clock,

    /// The client timestamp was outside the configured window.
    #[error("client timestamp is outside the configured REALITY window")]
    TimestampOutOfRange,

    /// The decrypted short id did not match any configured short id.
    #[error("client short id is not configured")]
    UnknownShortId,

    /// A configured short id was not a valid 2..=16 character hex string.
    #[error("REALITY short id configuration is invalid")]
    InvalidConfig,
}

/// Authenticates the REALITY envelope in `hello`.
pub fn authenticate(
    hello: &ClientHello<'_>,
    config: &RealityAuthConfig<'_>,
) -> Result<Auth, AuthError> {
    if !hello.supports_tls13() {
        return Err(AuthError::Tls13Required);
    }

    let server_name = hello.server_name.ok_or(AuthError::ServerNameMismatch)?;
    if !config
        .server_names
        .iter()
        .any(|configured| configured == server_name)
    {
        return Err(AuthError::ServerNameMismatch);
    }

    if hello.session_id.len() != SESSION_ID_LEN {
        return Err(AuthError::InvalidSessionId);
    }

    let client_share = select_client_share(hello)?;

    let server_secret = StaticSecret::from(*config.private_key);
    let client_public = PublicKey::from(client_share);
    let shared_secret = server_secret.diffie_hellman(&client_public);
    if !shared_secret.was_contributory() {
        return Err(AuthError::KeyAgreement);
    }

    let mut auth_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&hello.random[..20]), shared_secret.as_bytes())
        .expand(HKDF_INFO, &mut auth_key[..])
        .map_err(|_| AuthError::KeyDerivation)?;

    let aad = build_aad(hello.raw_client_hello)?;
    let cipher = Aes256Gcm::new_from_slice(&auth_key[..]).map_err(|_| AuthError::CipherInit)?;
    let nonce = Nonce::from_slice(&hello.random[20..32]);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: hello.session_id,
                aad: &aad,
            },
        )
        .map_err(|_| AuthError::DecryptFailed)?;
    let plaintext = Zeroizing::new(plaintext);

    if plaintext.len() != AUTH_PLAINTEXT_LEN {
        return Err(AuthError::InvalidPlaintext);
    }

    let client_version = copy_array::<3>(&plaintext, 0)?;
    let timestamp = u32::from_be_bytes(copy_array::<4>(&plaintext, 4)?);
    let short_id = copy_array::<8>(&plaintext, 8)?;

    if version_value(client_version) < version_value(config.min_client_version)
        || version_value(client_version) > version_value(config.max_client_version)
    {
        return Err(AuthError::UnsupportedClientVersion);
    }

    check_timestamp(timestamp, config.max_time_diff)?;

    let mut matched = Choice::from(0u8);
    for configured in config.short_ids {
        let expected = decode_short_id(configured)?;
        matched |= expected.ct_eq(&short_id);
    }
    if !bool::from(matched) {
        return Err(AuthError::UnknownShortId);
    }

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(hello.session_id);

    Ok(Auth {
        auth_key,
        client_version,
        timestamp,
        short_id,
        session_id,
    })
}

fn select_client_share(hello: &ClientHello<'_>) -> Result<[u8; 32], AuthError> {
    let shares = hello
        .key_shares
        .as_ref()
        .ok_or(AuthError::MissingKeyShare)?;

    if let Some(share) = shares.get(X25519_GROUP) {
        return copy_x25519_share(share, X25519_GROUP);
    }

    if let Some(share) = shares.get(X25519_MLKEM768_GROUP) {
        if share.len() != X25519_MLKEM768_SHARE_LEN {
            return Err(AuthError::InvalidKeyShareLength {
                group: X25519_MLKEM768_GROUP,
                length: share.len(),
            });
        }
        let Some(offset) = share.len().checked_sub(X25519_SHARE_LEN) else {
            return Err(AuthError::InvalidKeyShareLength {
                group: X25519_MLKEM768_GROUP,
                length: share.len(),
            });
        };
        let Some(x25519) = share.get(offset..) else {
            return Err(AuthError::InvalidKeyShareLength {
                group: X25519_MLKEM768_GROUP,
                length: share.len(),
            });
        };
        return copy_x25519_share(x25519, X25519_MLKEM768_GROUP);
    }

    Err(AuthError::MissingKeyShare)
}

fn copy_x25519_share(share: &[u8], group: u16) -> Result<[u8; 32], AuthError> {
    if share.len() != X25519_SHARE_LEN {
        return Err(AuthError::InvalidKeyShareLength {
            group,
            length: share.len(),
        });
    }
    share
        .try_into()
        .map_err(|_| AuthError::InvalidKeyShareLength {
            group,
            length: share.len(),
        })
}

fn build_aad(raw_client_hello: &[u8]) -> Result<Vec<u8>, AuthError> {
    if raw_client_hello.len() < SESSION_ID_END || raw_client_hello.len() > MAX_RECORD_LEN {
        return Err(AuthError::InvalidClientHello);
    }

    let mut aad = Vec::new();
    aad.try_reserve_exact(raw_client_hello.len())
        .map_err(|_| AuthError::Allocation)?;
    aad.extend_from_slice(raw_client_hello);

    let session_id = aad
        .get_mut(SESSION_ID_START..SESSION_ID_END)
        .ok_or(AuthError::InvalidClientHello)?;
    session_id.fill(0);
    Ok(aad)
}

fn copy_array<const N: usize>(source: &[u8], offset: usize) -> Result<[u8; N], AuthError> {
    let end = offset.checked_add(N).ok_or(AuthError::InvalidPlaintext)?;
    source
        .get(offset..end)
        .ok_or(AuthError::InvalidPlaintext)?
        .try_into()
        .map_err(|_| AuthError::InvalidPlaintext)
}

fn version_value(version: [u8; 3]) -> u32 {
    u32::from_be_bytes([0, version[0], version[1], version[2]])
}

fn check_timestamp(timestamp: u32, max_time_diff: Option<Duration>) -> Result<(), AuthError> {
    let Some(max_time_diff) = max_time_diff else {
        return Ok(());
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Clock)?
        .as_secs();
    let difference = now.abs_diff(u64::from(timestamp));
    if Duration::from_secs(difference) > max_time_diff {
        return Err(AuthError::TimestampOutOfRange);
    }
    Ok(())
}

fn decode_short_id(value: &str) -> Result<[u8; 8], AuthError> {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes.len() > 16 || !bytes.len().is_multiple_of(2) {
        return Err(AuthError::InvalidConfig);
    }

    let mut short_id = [0u8; 8];
    let decoded_len = bytes.len() / 2;
    let Some(target) = short_id.get_mut(..decoded_len) else {
        return Err(AuthError::InvalidConfig);
    };
    hex::decode_to_slice(bytes, target).map_err(|_| AuthError::InvalidConfig)?;
    Ok(short_id)
}

#[cfg(test)]
mod tests {
    // Test configurations are assembled field by field for readability.
    #![allow(clippy::field_reassign_with_default)]

    use super::*;
    use base64::Engine as _;
    use std::time::Duration;

    use crate::tls::ClientHello;

    const STOCK_CLIENT_HELLO: &[u8] = include_bytes!("../../tests/fixtures/stock-client-hello.bin");

    // Test-only credentials from the local stock Xray baseline. Never use
    // these keys outside tests.
    const TEST_PRIVATE_KEY_B64: &str = "YLxrYleugiQ4iDDvCtbKHw3SNGAlEHJO6PR-BN6ypH4";
    const TEST_SHORT_ID_HEX: &str = "0123456789abcdef";
    const TEST_SHORT_ID: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    const TEST_SERVER_NAME: &str = "whatsapp.net";
    const TEST_CLIENT_VERSION: [u8; 3] = [26, 3, 27];

    struct TestConfig {
        private_key: [u8; 32],
        short_ids: Vec<String>,
        server_names: Vec<String>,
        min_client_version: [u8; 3],
        max_client_version: [u8; 3],
        max_time_diff: Option<Duration>,
    }

    impl TestConfig {
        fn new() -> Self {
            Self {
                private_key: test_private_key(),
                short_ids: vec![TEST_SHORT_ID_HEX.to_string()],
                server_names: vec![TEST_SERVER_NAME.to_string()],
                min_client_version: [0, 0, 0],
                max_client_version: [255, 255, 255],
                max_time_diff: None,
            }
        }

        fn auth_config(&self) -> RealityAuthConfig<'_> {
            RealityAuthConfig {
                private_key: &self.private_key,
                short_ids: &self.short_ids,
                server_names: &self.server_names,
                min_client_version: self.min_client_version,
                max_client_version: self.max_client_version,
                max_time_diff: self.max_time_diff,
            }
        }
    }

    fn test_private_key() -> [u8; 32] {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(TEST_PRIVATE_KEY_B64)
            .expect("test private key is valid base64url");
        bytes.try_into().expect("test private key is 32 bytes")
    }

    fn test_random() -> [u8; 32] {
        let mut random = [0u8; 32];
        for (index, byte) in random.iter_mut().enumerate() {
            *byte = index as u8;
        }
        random
    }

    fn client_public(client_private: [u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(client_private)).to_bytes()
    }

    #[test]
    fn authenticates_stock_xray_client_hello() {
        let hello = ClientHello::parse(STOCK_CLIENT_HELLO).expect("fixture must parse");
        let mut config = TestConfig::new();
        config.min_client_version = TEST_CLIENT_VERSION;
        config.max_client_version = TEST_CLIENT_VERSION;

        let auth = authenticate(&hello, &config.auth_config())
            .expect("stock Xray envelope must authenticate");

        assert_eq!(auth.client_version, TEST_CLIENT_VERSION);
        assert_eq!(auth.short_id, TEST_SHORT_ID);
        assert!(
            auth.timestamp > 1_700_000_000,
            "captured timestamp should be in the modern era"
        );
        assert_ne!(&auth.auth_key[..], &[0u8; 32][..]);
    }

    #[test]
    fn rejects_wrong_private_key() {
        let hello = ClientHello::parse(STOCK_CLIENT_HELLO).expect("fixture must parse");
        let mut config = TestConfig::new();
        config.private_key = [0x42; 32];

        assert!(matches!(
            authenticate(&hello, &config.auth_config()),
            Err(AuthError::DecryptFailed)
        ));
    }

    #[test]
    fn rejects_wrong_server_name() {
        let hello = ClientHello::parse(STOCK_CLIENT_HELLO).expect("fixture must parse");
        let mut config = TestConfig::new();
        config.server_names = vec!["example.com".to_string()];

        assert!(matches!(
            authenticate(&hello, &config.auth_config()),
            Err(AuthError::ServerNameMismatch)
        ));
    }

    #[test]
    fn rejects_out_of_range_client_version() {
        let hello = ClientHello::parse(STOCK_CLIENT_HELLO).expect("fixture must parse");
        let mut config = TestConfig::new();
        config.min_client_version = [99, 0, 0];
        config.max_client_version = [99, 0, 0];

        assert!(matches!(
            authenticate(&hello, &config.auth_config()),
            Err(AuthError::UnsupportedClientVersion)
        ));
    }

    #[test]
    fn debug_redacts_authentication_secrets() {
        let config = TestConfig::new();
        let config_debug = format!("{:?}", config.auth_config());
        assert!(config_debug.contains("private_key: \"<redacted>\""));
        assert!(config_debug.contains("short_ids: \"<redacted>\""));

        let hello = ClientHello::parse(STOCK_CLIENT_HELLO).expect("fixture must parse");
        let auth =
            authenticate(&hello, &config.auth_config()).expect("test envelope must authenticate");
        let auth_debug = format!("{auth:?}");
        assert!(auth_debug.contains("auth_key: \"<redacted>\""));
        assert!(auth_debug.contains("short_id: \"<redacted>\""));
    }

    #[test]
    fn rejects_unknown_short_id_after_aead() {
        let hello = ClientHello::parse(STOCK_CLIENT_HELLO).expect("fixture must parse");
        let mut config = TestConfig::new();
        config.short_ids = vec!["deadbeef".to_string()];

        assert!(matches!(
            authenticate(&hello, &config.auth_config()),
            Err(AuthError::UnknownShortId)
        ));
    }

    #[test]
    fn rejects_session_ids_that_are_not_32_bytes() {
        let config = TestConfig::new();
        let empty: &[u8] = &[];
        let short = [0xaa; 31];
        let x25519_share = [0x09; 32];

        for session_id in [empty, &short] {
            let record = build_client_hello(
                &test_random(),
                session_id,
                &[(X25519_GROUP, &x25519_share)],
                true,
            );
            let hello = ClientHello::parse(&record).expect("synthetic hello must parse");
            assert!(matches!(
                authenticate(&hello, &config.auth_config()),
                Err(AuthError::InvalidSessionId)
            ));
        }
    }

    #[test]
    fn rejects_tls12_client_hello() {
        let record = build_client_hello(
            &test_random(),
            &[0u8; SESSION_ID_LEN],
            &[(X25519_GROUP, &[0x09; 32])],
            false,
        );
        let hello = ClientHello::parse(&record).expect("synthetic hello must parse");
        let config = TestConfig::new();

        assert!(matches!(
            authenticate(&hello, &config.auth_config()),
            Err(AuthError::Tls13Required)
        ));
    }

    #[test]
    fn authenticates_hybrid_x25519_mlkem768_share() {
        let server_private = test_private_key();
        let client_private = [0x22; 32];
        let client_public = client_public(client_private);
        let mut hybrid_share = vec![0xaa; X25519_MLKEM768_SHARE_LEN];
        hybrid_share[X25519_MLKEM768_SHARE_LEN - X25519_SHARE_LEN..]
            .copy_from_slice(&client_public);

        let random = test_random();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs() as u32;
        let mut record = build_client_hello(
            &random,
            &[0u8; SESSION_ID_LEN],
            &[(X25519_MLKEM768_GROUP, hybrid_share.as_slice())],
            true,
        );
        let expected_key = seal_envelope(
            &mut record,
            &random,
            client_private,
            &server_private,
            TEST_CLIENT_VERSION,
            timestamp,
            TEST_SHORT_ID,
        );

        let hello = ClientHello::parse(&record).expect("hybrid hello must parse");
        let mut config = TestConfig::new();
        config.private_key = server_private;
        config.min_client_version = TEST_CLIENT_VERSION;
        config.max_client_version = TEST_CLIENT_VERSION;
        config.max_time_diff = Some(Duration::from_secs(60));

        let auth = authenticate(&hello, &config.auth_config())
            .expect("hybrid REALITY envelope must authenticate");

        assert_eq!(auth.client_version, TEST_CLIENT_VERSION);
        assert_eq!(auth.timestamp, timestamp);
        assert_eq!(auth.short_id, TEST_SHORT_ID);
        assert_eq!(&auth.auth_key[..], &expected_key[..]);
    }

    #[test]
    fn rejects_stale_timestamp() {
        let server_private = test_private_key();
        let client_private = [0x33; 32];
        let client_public = client_public(client_private);
        let random = test_random();
        let timestamp = 1_600_000_000;
        let mut record = build_client_hello(
            &random,
            &[0u8; SESSION_ID_LEN],
            &[(X25519_GROUP, &client_public)],
            true,
        );
        seal_envelope(
            &mut record,
            &random,
            client_private,
            &server_private,
            TEST_CLIENT_VERSION,
            timestamp,
            TEST_SHORT_ID,
        );

        let hello = ClientHello::parse(&record).expect("signed hello must parse");
        let mut config = TestConfig::new();
        config.private_key = server_private;
        config.max_time_diff = Some(Duration::from_secs(60));

        assert!(matches!(
            authenticate(&hello, &config.auth_config()),
            Err(AuthError::TimestampOutOfRange)
        ));
    }

    #[test]
    fn rejects_low_order_key_share() {
        let record = build_client_hello(
            &test_random(),
            &[0u8; SESSION_ID_LEN],
            &[(X25519_GROUP, &[0u8; 32])],
            true,
        );
        let hello = ClientHello::parse(&record).expect("synthetic hello must parse");
        let config = TestConfig::new();

        assert!(matches!(
            authenticate(&hello, &config.auth_config()),
            Err(AuthError::KeyAgreement)
        ));
    }

    #[test]
    fn mutated_stock_fixture_never_panics() {
        let config = TestConfig::new();
        let auth_config = config.auth_config();

        for index in 0..STOCK_CLIENT_HELLO.len() {
            let mut mutated = STOCK_CLIENT_HELLO.to_vec();
            mutated[index] ^= 0xff;
            if let Ok(hello) = ClientHello::parse(&mutated) {
                let _ = authenticate(&hello, &auth_config);
            }
        }
    }

    fn build_client_hello(
        random: &[u8; 32],
        session_id: &[u8],
        key_shares: &[(u16, &[u8])],
        include_supported_versions: bool,
    ) -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&server_name_extension());
        if include_supported_versions {
            extensions.extend_from_slice(&supported_versions_extension());
        }
        extensions.extend_from_slice(&key_share_extension(key_shares));

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(random);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);

        let cipher_suites = [0x1301u16, 0x1302, 0x1303];
        body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
        for suite in cipher_suites {
            body.extend_from_slice(&suite.to_be_bytes());
        }
        body.push(1);
        body.push(0);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.extend_from_slice(&u24(body.len() as u32));
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn seal_envelope(
        record: &mut [u8],
        random: &[u8; 32],
        client_private: [u8; 32],
        server_private: &[u8; 32],
        client_version: [u8; 3],
        timestamp: u32,
        short_id: [u8; 8],
    ) -> [u8; 32] {
        let client_secret = StaticSecret::from(client_private);
        let server_public = PublicKey::from(&StaticSecret::from(*server_private));
        let shared_secret = client_secret.diffie_hellman(&server_public);
        assert!(
            shared_secret.was_contributory(),
            "test key exchange must be contributory"
        );

        let mut auth_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&random[..20]), shared_secret.as_bytes())
            .expand(HKDF_INFO, &mut auth_key)
            .expect("test HKDF expansion");

        let mut plaintext = [0u8; AUTH_PLAINTEXT_LEN];
        plaintext[..3].copy_from_slice(&client_version);
        plaintext[3] = 0;
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plaintext[8..].copy_from_slice(&short_id);

        let cipher = Aes256Gcm::new_from_slice(&auth_key).expect("test AES key");
        let nonce = Nonce::from_slice(&random[20..32]);
        let sealed = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: &record[5..],
                },
            )
            .expect("test AES-GCM seal");
        assert_eq!(sealed.len(), SESSION_ID_LEN);
        record[5 + SESSION_ID_START..5 + SESSION_ID_END].copy_from_slice(&sealed);
        auth_key
    }

    fn server_name_extension() -> Vec<u8> {
        let name = TEST_SERVER_NAME.as_bytes();
        let mut data = Vec::new();
        data.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        data.push(0);
        data.extend_from_slice(&(name.len() as u16).to_be_bytes());
        data.extend_from_slice(name);
        extension(0x0000, &data)
    }

    fn supported_versions_extension() -> Vec<u8> {
        extension(0x002b, &[2, 0x03, 0x04])
    }

    fn key_share_extension(key_shares: &[(u16, &[u8])]) -> Vec<u8> {
        let entries_len: usize = key_shares.iter().map(|(_, key)| 4 + key.len()).sum();
        let mut data = Vec::new();
        data.extend_from_slice(&(entries_len as u16).to_be_bytes());
        for (group, key_exchange) in key_shares {
            data.extend_from_slice(&group.to_be_bytes());
            data.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
            data.extend_from_slice(key_exchange);
        }
        extension(0x0033, &data)
    }

    fn extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&extension_type.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn u24(value: u32) -> [u8; 3] {
        let bytes = value.to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }
}
