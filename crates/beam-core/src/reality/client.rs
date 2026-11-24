//! REALITY client-side handshake builder and certificate verifier.
//!
//! Produces a TLS 1.3 [`rustls::ClientConnection`] whose `legacy_session_id`
//! carries the encrypted 32-byte REALITY authentication envelope and verifies
//! the server's temporary Ed25519 certificate via constant-time HMAC-SHA512.

use std::cell::RefCell;
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup, WebPkiSupportedAlgorithms, verify_tls13_signature,
};
use rustls::pki_types::{CertificateDer, DnsName, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, NamedGroup,
    SignatureScheme,
};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::reality::auth::decode_short_id;
use crate::tls::{ClientHello, MAX_RECORD_LEN, TLS_RECORD_HEADER_LEN};

const SESSION_ID_START: usize = 39;
const SESSION_ID_LEN: usize = 32;
const SESSION_ID_END: usize = SESSION_ID_START + SESSION_ID_LEN;
const HKDF_INFO: &[u8] = b"REALITY";
const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70]; // 1.3.101.112
const DEFAULT_CLIENT_VERSION: [u8; 3] = [26, 3, 27];

/// Configuration for a REALITY client handshake.
#[derive(Clone)]
pub struct RealityClientConfig {
    /// Server's static X25519 public key (32 bytes).
    pub server_public_key: [u8; 32],
    /// Decoded 8-byte short id (zero-padded).
    pub short_id: [u8; 8],
    /// Cover SNI DNS hostname sent in the TLS ClientHello.
    pub server_name: String,
    /// Client version bytes placed in the REALITY envelope.
    pub client_version: [u8; 3],
}

impl RealityClientConfig {
    /// Creates a new REALITY client configuration from a raw public key,
    /// hex-encoded short id, and DNS server name.
    pub fn new(
        server_public_key: [u8; 32],
        short_id_hex: &str,
        server_name: impl Into<String>,
    ) -> Result<Self, RealityClientError> {
        let short_id =
            decode_short_id(short_id_hex).map_err(|_| RealityClientError::InvalidShortId)?;
        let server_name = server_name.into();
        DnsName::try_from(server_name.clone())
            .map_err(|_| RealityClientError::InvalidServerName)?;
        Ok(Self {
            server_public_key,
            short_id,
            server_name,
            client_version: DEFAULT_CLIENT_VERSION,
        })
    }
}

impl fmt::Debug for RealityClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityClientConfig")
            .field("server_public_key", &"<redacted>")
            .field("short_id", &"<redacted>")
            .field("server_name", &self.server_name)
            .field("client_version", &self.client_version)
            .finish()
    }
}

/// Errors returned while constructing a REALITY client TLS connection.
#[derive(Debug, thiserror::Error)]
pub enum RealityClientError {
    /// The configured short id is not valid 2..=16 hex characters.
    #[error("invalid REALITY short id")]
    InvalidShortId,

    /// The configured SNI is not a valid DNS server name.
    #[error("invalid REALITY server name")]
    InvalidServerName,

    /// OS randomness failed.
    #[error("secure random generation failed")]
    Random,

    /// System clock is before Unix epoch or exceeds u32 seconds.
    #[error("system clock out of range for REALITY timestamp")]
    Clock,

    /// X25519 produced a non-contributory shared secret.
    #[error("X25519 key agreement failed")]
    KeyAgreement,

    /// HKDF or AES-GCM failed.
    #[error("REALITY envelope encryption failed")]
    Crypto,

    /// The dry-run ClientHello did not match expected offsets.
    #[error("ClientHello capture did not match REALITY envelope layout")]
    ClientHelloLayout,

    /// rustls rejected the configuration or connection construction.
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

struct PendingMaterial {
    session_id: [u8; 32],
    hello_random: [u8; 32],
    ext_seed: [u8; 2],
    secret: Zeroizing<[u8; 32]>,
    fills_32: usize,
}

thread_local! {
    static PENDING: RefCell<Option<PendingMaterial>> = const { RefCell::new(None) };
}

struct PendingGuard;

impl PendingGuard {
    fn install(material: PendingMaterial) -> Self {
        PENDING.with(|slot| {
            *slot.borrow_mut() = Some(material);
        });
        Self
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        PENDING.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}

#[derive(Debug)]
struct ThreadLocalRandom;

impl SecureRandom for ThreadLocalRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let handled = PENDING.with(|slot| {
            let mut guard = slot.borrow_mut();
            let Some(mat) = guard.as_mut() else {
                return false;
            };
            match buf.len() {
                32 => {
                    let idx = mat.fills_32;
                    mat.fills_32 = mat.fills_32.saturating_add(1);
                    match idx {
                        0 => {
                            buf.copy_from_slice(&mat.session_id);
                            true
                        }
                        1 => {
                            buf.copy_from_slice(&mat.hello_random);
                            true
                        }
                        _ => false,
                    }
                }
                2 => {
                    buf.copy_from_slice(&mat.ext_seed);
                    true
                }
                _ => false,
            }
        });
        if handled {
            return Ok(());
        }
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(buf)
    }
}

#[derive(Debug)]
struct ThreadLocalX25519;

impl SupportedKxGroup for ThreadLocalX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret_bytes = PENDING.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|mat| Zeroizing::new(*mat.secret))
        });
        let secret_bytes = match secret_bytes {
            Some(bytes) => bytes,
            None => {
                let mut fresh = Zeroizing::new([0u8; 32]);
                rustls::crypto::aws_lc_rs::default_provider()
                    .secure_random
                    .fill(&mut fresh[..])
                    .map_err(|_| rustls::Error::General("random failed".into()))?;
                fresh
            }
        };
        let secret = StaticSecret::from(*secret_bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Box::new(EphemeralX25519 { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct EphemeralX25519 {
    secret: StaticSecret,
    public: [u8; 32],
}

impl ActiveKeyExchange for EphemeralX25519 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::General("invalid X25519 peer share".into()))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(rustls::Error::General(
                "non-contributory X25519 peer share".into(),
            ));
        }
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

fn reality_crypto_provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![&ThreadLocalX25519];
        provider.secure_random = &ThreadLocalRandom;
        Arc::new(provider)
    }))
}

#[derive(Debug)]
struct DryRunVerifier;

impl ServerCertVerifier for DryRunVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Err(rustls::Error::General(
            "dry-run verifier must never be used on a live connection".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 unsupported".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("dry-run verifier".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

fn dry_run_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let config = ClientConfig::builder_with_provider(reality_crypto_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 supported by aws-lc-rs")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DryRunVerifier))
            .with_no_client_auth();
        Arc::new(config)
    }))
}

struct RealityCertVerifier {
    auth_key: Zeroizing<[u8; 32]>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for RealityCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityCertVerifier")
            .field("auth_key", &"<redacted>")
            .finish()
    }
}

impl ServerCertVerifier for RealityCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::BadEncoding,
            ));
        }
        let (pubkey, sig) = extract_ed25519_cert_fields(end_entity.as_ref()).ok_or(
            rustls::Error::InvalidCertificate(CertificateError::BadEncoding),
        )?;

        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&self.auth_key[..])
            .map_err(|_| rustls::Error::General("HMAC init failed".into()))?;
        mac.update(&pubkey);
        let expected: [u8; 64] = mac.finalize().into_bytes().into();

        if bool::from(expected.ct_eq(&sig)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::BadSignature,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("REALITY requires TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Builds a TLS 1.3 [`ClientConnection`] carrying a fresh REALITY authentication
/// envelope in `legacy_session_id` and verifying the server's temporary Ed25519
/// certificate against the derived `auth_key`.
pub fn build_client_connection(
    config: &RealityClientConfig,
) -> Result<ClientConnection, RealityClientError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RealityClientError::Clock)?
        .as_secs();
    let timestamp = u32::try_from(timestamp).map_err(|_| RealityClientError::Clock)?;
    build_client_connection_at(config, timestamp)
}

/// Same as [`build_client_connection`] with an explicit Unix timestamp (for tests).
pub fn build_client_connection_at(
    config: &RealityClientConfig,
    timestamp: u32,
) -> Result<ClientConnection, RealityClientError> {
    let rng = rustls::crypto::aws_lc_rs::default_provider().secure_random;
    let mut hello_random = [0u8; 32];
    let mut secret = Zeroizing::new([0u8; 32]);
    let mut ext_seed = [0u8; 2];
    rng.fill(&mut hello_random)
        .map_err(|_| RealityClientError::Random)?;
    rng.fill(&mut secret[..])
        .map_err(|_| RealityClientError::Random)?;
    rng.fill(&mut ext_seed)
        .map_err(|_| RealityClientError::Random)?;

    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| RealityClientError::InvalidServerName)?;

    // Pass 1: in-memory dry run with a zeroed 32-byte session_id to capture the
    // exact ClientHello bytes rustls will emit.
    let mut record = Vec::with_capacity(512);
    {
        let _guard = PendingGuard::install(PendingMaterial {
            session_id: [0u8; 32],
            hello_random,
            ext_seed,
            secret: Zeroizing::new(*secret),
            fills_32: 0,
        });
        let mut dry = ClientConnection::new(dry_run_client_config(), server_name.clone())?;
        while dry.wants_write() {
            dry.write_tls(&mut record)
                .map_err(|_| RealityClientError::ClientHelloLayout)?;
        }
    }

    if record.len() < TLS_RECORD_HEADER_LEN + SESSION_ID_END
        || record.len() > TLS_RECORD_HEADER_LEN + MAX_RECORD_LEN
    {
        return Err(RealityClientError::ClientHelloLayout);
    }

    let hello = ClientHello::parse(&record).map_err(|_| RealityClientError::ClientHelloLayout)?;
    if hello.random != hello_random || hello.session_id != [0u8; 32] {
        return Err(RealityClientError::ClientHelloLayout);
    }

    let body = &record[TLS_RECORD_HEADER_LEN..];
    if body.get(SESSION_ID_START..SESSION_ID_END) != Some(&[0u8; SESSION_ID_LEN][..]) {
        return Err(RealityClientError::ClientHelloLayout);
    }

    // Derive REALITY auth_key and seal the 16-byte envelope into 32 bytes.
    let server_pub = PublicKey::from(config.server_public_key);
    let shared = StaticSecret::from(*secret).diffie_hellman(&server_pub);
    if !shared.was_contributory() {
        return Err(RealityClientError::KeyAgreement);
    }

    let mut auth_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&hello_random[..20]), shared.as_bytes())
        .expand(HKDF_INFO, &mut auth_key[..])
        .map_err(|_| RealityClientError::Crypto)?;

    let cipher =
        Aes256Gcm::new_from_slice(&auth_key[..]).map_err(|_| RealityClientError::Crypto)?;
    let mut plaintext = [0u8; 16];
    plaintext[..3].copy_from_slice(&config.client_version);
    plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..16].copy_from_slice(&config.short_id);

    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&hello_random[20..32]),
            Payload {
                msg: &plaintext,
                aad: body,
            },
        )
        .map_err(|_| RealityClientError::Crypto)?;
    let envelope: [u8; 32] = sealed.try_into().map_err(|_| RealityClientError::Crypto)?;

    // Pass 2: construct the live ClientConnection with the sealed envelope and
    // per-connection HMAC-SHA512 certificate verifier.
    let verifier = Arc::new(RealityCertVerifier {
        auth_key,
        supported_algs: rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms,
    });
    let client_config = Arc::new(
        ClientConfig::builder_with_provider(reality_crypto_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    );

    let _guard = PendingGuard::install(PendingMaterial {
        session_id: envelope,
        hello_random,
        ext_seed,
        secret,
        fills_32: 0,
    });
    let conn = ClientConnection::new(client_config, server_name)?;
    Ok(conn)
}

/// Fuzzing entry point for the DER X.509 Ed25519 certificate parser.
#[cfg(feature = "fuzz")]
pub fn fuzz_extract_ed25519_cert_fields(der: &[u8]) -> Option<([u8; 32], [u8; 64])> {
    extract_ed25519_cert_fields(der)
}

/// Extracts the 32-byte Ed25519 public key and 64-byte signature from a
/// DER-encoded X.509 Certificate.
///
/// Certificate ::= SEQUENCE {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
fn extract_ed25519_cert_fields(der: &[u8]) -> Option<([u8; 32], [u8; 64])> {
    let (cert_body, rest) = read_der_tlv(der, 0x30)?;
    if !rest.is_empty() {
        return None;
    }

    // 1. tbsCertificate
    let (tbs_body, after_tbs) = read_der_tlv(cert_body, 0x30)?;
    // 2. signatureAlgorithm
    let (_sig_alg, after_sig_alg) = read_der_tlv(after_tbs, 0x30)?;
    // 3. signatureValue (BIT STRING: 0x00 unused bits + 64-byte signature)
    let (sig_bits, trailing) = read_der_tlv(after_sig_alg, 0x03)?;
    if !trailing.is_empty() || sig_bits.len() != 65 || sig_bits[0] != 0 {
        return None;
    }
    let signature: [u8; 64] = sig_bits[1..].try_into().ok()?;

    // Walk TBSCertificate fields to SubjectPublicKeyInfo:
    //   [0] EXPLICIT version OPTIONAL (tag 0xA0)
    //   serialNumber         INTEGER (0x02)
    //   signature            SEQUENCE (0x30)
    //   issuer               SEQUENCE (0x30)
    //   validity             SEQUENCE (0x30)
    //   subject              SEQUENCE (0x30)
    //   subjectPublicKeyInfo SEQUENCE (0x30)
    let mut cursor = tbs_body;
    if cursor.first().copied() == Some(0xa0) {
        let (_, next) = read_der_tlv(cursor, 0xa0)?;
        cursor = next;
    }
    let (_, cursor) = read_der_tlv(cursor, 0x02)?; // serialNumber
    let (_, cursor) = read_der_tlv(cursor, 0x30)?; // signature
    let (_, cursor) = read_der_tlv(cursor, 0x30)?; // issuer
    let (_, cursor) = read_der_tlv(cursor, 0x30)?; // validity
    let (_, cursor) = read_der_tlv(cursor, 0x30)?; // subject
    let (spki_body, _) = read_der_tlv(cursor, 0x30)?; // subjectPublicKeyInfo

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE { OID }, subjectPublicKey BIT STRING }
    let (alg_body, after_alg) = read_der_tlv(spki_body, 0x30)?;
    let (oid, alg_trailing) = read_der_tlv(alg_body, 0x06)?;
    if oid != ED25519_OID || !alg_trailing.is_empty() {
        return None;
    }
    let (pub_bits, spki_trailing) = read_der_tlv(after_alg, 0x03)?;
    if !spki_trailing.is_empty() || pub_bits.len() != 33 || pub_bits[0] != 0 {
        return None;
    }
    let pubkey: [u8; 32] = pub_bits[1..].try_into().ok()?;

    Some((pubkey, signature))
}

fn read_der_tlv(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag != expected_tag {
        return None;
    }
    let (&first_len, rest) = rest.split_first()?;
    let (len, rest) = if first_len < 0x80 {
        (usize::from(first_len), rest)
    } else {
        let num_bytes = usize::from(first_len & 0x7f);
        if num_bytes == 0 || num_bytes > 2 {
            return None;
        }
        let (len_bytes, rest) = rest.split_at_checked(num_bytes)?;
        // Enforce minimal DER length encoding (no leading zero byte, and
        // multi-byte form only for lengths >= 128).
        if len_bytes[0] == 0 {
            return None;
        }
        let mut value = 0usize;
        for &b in len_bytes {
            value = (value << 8) | usize::from(b);
        }
        if value < 0x80 {
            return None;
        }
        (value, rest)
    };
    let (value, trailing) = rest.split_at_checked(len)?;
    Some((value, trailing))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::auth::{RealityAuthConfig, authenticate};

    #[test]
    fn client_hello_authenticates_against_server_auth() {
        let server_secret = [0x42u8; 32];
        let server_public = PublicKey::from(&StaticSecret::from(server_secret)).to_bytes();
        let short_id_hex = "0123456789abcdef";
        let short_id = decode_short_id(short_id_hex).expect("short id");

        let client_cfg =
            RealityClientConfig::new(server_public, short_id_hex, "whatsapp.net").expect("cfg");
        let mut conn = build_client_connection_at(&client_cfg, 1_700_000_000).expect("client conn");

        let mut wire = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut wire).expect("write ClientHello");
        }

        let hello = ClientHello::parse(&wire).expect("parse ClientHello");
        let server_names = vec!["whatsapp.net".to_string()];
        let short_ids = vec![short_id];
        let server_cfg = RealityAuthConfig {
            private_key: &server_secret,
            short_ids: &short_ids,
            server_names: &server_names,
            min_client_version: [0, 0, 0],
            max_client_version: [255, 255, 255],
            max_time_diff: None,
        };

        let auth = authenticate(&hello, &server_cfg).expect("server must authenticate client");
        assert_eq!(auth.timestamp, 1_700_000_000);
        assert_eq!(auth.short_id, short_id);
        assert_eq!(auth.client_version, DEFAULT_CLIENT_VERSION);
    }

    #[test]
    fn cert_verifier_accepts_hmac_signed_ed25519_and_rejects_tampered() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
        let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        let cert = params.self_signed(&key_pair).expect("self signed");
        let mut der = cert.der().to_vec();
        let pubkey: [u8; 32] = key_pair
            .public_key_raw()
            .try_into()
            .expect("32-byte pubkey");

        let auth_key = Zeroizing::new([0x77u8; 32]);
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&auth_key[..]).expect("hmac");
        mac.update(&pubkey);
        let sig: [u8; 64] = mac.finalize().into_bytes().into();
        let sig_offset = der.len() - 64;
        der[sig_offset..].copy_from_slice(&sig);

        let verifier = RealityCertVerifier {
            auth_key: Zeroizing::new(*auth_key),
            supported_algs: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        };
        let sni = ServerName::try_from("whatsapp.net").expect("sni");
        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from(der.clone()),
                    &[],
                    &sni,
                    &[],
                    UnixTime::now()
                )
                .is_ok()
        );

        // Flipping one signature byte must fail verification.
        der[sig_offset] ^= 0x01;
        assert!(
            verifier
                .verify_server_cert(&CertificateDer::from(der), &[], &sni, &[], UnixTime::now())
                .is_err()
        );
    }
}
