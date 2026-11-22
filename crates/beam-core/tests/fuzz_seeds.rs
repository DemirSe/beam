//! Synthetic fuzz seed corpus checks.
//!
//! The seed files under `fuzz/seeds/` give each fuzz target a structurally
//! valid starting input. Every seed is generated here from synthetic values:
//! a fixed placeholder UUID and documentation address ranges, never real
//! credentials or captured traffic.
//!
//! Set `BEAM_WRITE_FUZZ_SEEDS=1` to rewrite the files after an intended format
//! change; the test otherwise compares the checked-in bytes.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use beam_core::address::{Address, NetLocation};
use beam_core::config::Config;
use beam_core::reality::{AuthError, RealityAuthConfig, authenticate};
use beam_core::tls::ClientHello;
use beam_core::udp::is_packetaddr_destination;
use beam_core::udp::legacy::PACKETADDR_MAGIC_DOMAIN;
use beam_core::vless::{Command, RequestHeader, VISION_ADDONS};
use beam_core::xudp::{
    FrameOption, FrameSpec, GLOBAL_ID_LEN, SessionStatus, TargetNetwork, encode_frame, parse_frame,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Synthetic server private key matching `fuzz/fuzz_targets/reality_auth.rs`.
/// Pattern data only — never a real credential.
const FUZZ_REALITY_PRIVATE_KEY: [u8; 32] = [0x11_u8; 32];
const FUZZ_REALITY_SHORT_ID: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const FUZZ_REALITY_SNI: &str = "whatsapp.net";

/// Placeholder account UUID. Not an account: every byte is pattern data.
const SYNTHETIC_UUID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn seeds_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds")
}

fn ipv4(address: [u8; 4], port: u16) -> NetLocation {
    NetLocation {
        address: Address::Ipv4(Ipv4Addr::from(address)),
        port,
    }
}

fn domain(name: &str, port: u16) -> NetLocation {
    NetLocation {
        address: Address::Domain(name.to_owned()),
        port,
    }
}

/// Encodes `version | uuid | addons | command | destination | body`.
fn request(
    command: Command,
    addons: &[u8],
    destination: Option<&NetLocation>,
    body: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&SYNTHETIC_UUID);
    bytes.push(u8::try_from(addons.len()).expect("addons fit the wire field"));
    bytes.extend_from_slice(addons);
    bytes.push(command.as_u8());
    if let Some(destination) = destination {
        destination
            .encode(&mut bytes)
            .expect("test address encodes");
    }
    bytes.extend_from_slice(body);
    bytes
}

fn vless_seeds() -> Vec<(&'static str, Vec<u8>)> {
    // A plain TCP request with a first payload, as a client sends it.
    let tcp = request(
        Command::Tcp,
        &[],
        Some(&ipv4([192, 0, 2, 1], 443)),
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    // A mux request carrying the stock Vision addons and a body prefix.
    let mux = request(Command::Mux, VISION_ADDONS, None, b"\x00\x01hello");
    // A legacy UDP request for the packetaddr sentinel: port zero is part of
    // the sentinel, and the body carries the inner address.
    let mut packetaddr_body = vec![1];
    packetaddr_body.extend_from_slice(&[192, 0, 2, 53]);
    packetaddr_body.extend_from_slice(&53_u16.to_be_bytes());
    packetaddr_body.extend_from_slice(b"query");
    let packetaddr = request(
        Command::Udp,
        &[],
        Some(&domain(PACKETADDR_MAGIC_DOMAIN, 0)),
        &packetaddr_body,
    );
    vec![
        ("tcp_ipv4_request", tcp),
        ("mux_vision_request", mux),
        ("udp_packetaddr_request", packetaddr),
    ]
}

fn xudp_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let first = ipv4([192, 0, 2, 1], 53);
    let second = ipv4([198, 51, 100, 7], 443);
    let global_id = [0x3c; GLOBAL_ID_LEN];
    let mut bytes = Vec::new();
    let frames = [
        FrameSpec {
            session_id: 1,
            status: SessionStatus::New,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(&first),
            global_id: None,
            payload: b"\x00\x01query",
        },
        FrameSpec {
            session_id: 1,
            status: SessionStatus::Keep,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(&second),
            global_id: None,
            payload: b"\x00\x02answer",
        },
        FrameSpec {
            session_id: 1,
            status: SessionStatus::Keep,
            option: FrameOption::DATA,
            // An address-less Keep reuses the session destination, so it
            // carries no network either.
            network: None,
            destination: None,
            global_id: None,
            payload: b"\x00\x03after",
        },
        FrameSpec {
            session_id: 2,
            status: SessionStatus::New,
            option: FrameOption::DATA,
            network: Some(TargetNetwork::Udp),
            destination: Some(&domain("example.com", 53)),
            global_id: Some(global_id),
            payload: b"",
        },
        FrameSpec::new(2, SessionStatus::KeepAlive),
        FrameSpec::new(1, SessionStatus::End),
        FrameSpec::new(2, SessionStatus::End),
    ];
    for frame in frames {
        encode_frame(&mut bytes, frame).expect("test frame encodes");
    }
    vec![("new_keep_end_sequence", bytes)]
}

fn check_seed(path: &Path, bytes: &[u8]) {
    if std::env::var_os("BEAM_WRITE_FUZZ_SEEDS").is_some() {
        std::fs::create_dir_all(path.parent().expect("seed path has a parent"))
            .expect("seed directory");
        std::fs::write(path, bytes).expect("seed file");
        return;
    }
    let actual = std::fs::read(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    assert_eq!(
        actual,
        bytes,
        "{} is stale; regenerate it with BEAM_WRITE_FUZZ_SEEDS=1",
        path.display()
    );
}

#[test]
fn vless_seeds_are_valid_synthetic_requests() {
    for (name, bytes) in vless_seeds() {
        check_seed(&seeds_dir().join("vless").join(name), &bytes);
        let (header, body) = RequestHeader::parse(&bytes).expect("seed must parse");
        match name {
            "tcp_ipv4_request" => {
                assert_eq!(header.command, Command::Tcp);
                assert_eq!(header.destination, Some(ipv4([192, 0, 2, 1], 443)));
                assert!(header.addons.is_empty());
                assert_eq!(body, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
            }
            "mux_vision_request" => {
                assert_eq!(header.command, Command::Mux);
                assert!(header.addons.is_vision());
                assert_eq!(header.destination, None);
                assert_eq!(body, b"\x00\x01hello");
            }
            "udp_packetaddr_request" => {
                assert_eq!(header.command, Command::Udp);
                let destination = header.destination.expect("UDP carries a destination");
                assert_eq!(destination.port, 0, "the sentinel keeps port zero");
                assert!(
                    is_packetaddr_destination(&destination),
                    "the sentinel must select packetaddr framing"
                );
                assert_eq!(body.first(), Some(&1), "inner IPv4 address type");
            }
            other => panic!("unexpected vless seed {other}"),
        }
    }
}

#[test]
fn xudp_seeds_are_a_valid_frame_sequence() {
    for (name, bytes) in xudp_seeds() {
        check_seed(&seeds_dir().join("xudp").join(name), &bytes);
        let mut offset = 0;
        let mut seen = Vec::new();
        while offset < bytes.len() {
            let (frame, used) = parse_frame(&bytes[offset..])
                .expect("seed frame must parse")
                .expect("seed holds complete frames");
            offset += used;
            seen.push((frame.session_id, frame.status));
        }
        assert_eq!(offset, bytes.len(), "the sequence consumes the seed");
        assert_eq!(
            seen,
            vec![
                (1, SessionStatus::New),
                (1, SessionStatus::Keep),
                (1, SessionStatus::Keep),
                (2, SessionStatus::New),
                (2, SessionStatus::KeepAlive),
                (1, SessionStatus::End),
                (2, SessionStatus::End),
            ]
        );
    }
}

fn config_seeds() -> Vec<(&'static str, Vec<u8>)> {
    // Minimal synthetically valid TOML config (placeholder identity + RFC 5737
    // documentation address) so fuzzing starts inside semantic/derived checks.
    let minimal = concat!(
        "[server]\n",
        "listen = \"127.0.0.1:443\"\n\n",
        "[user]\n",
        "id = \"00112233-4455-6677-8899-aabbccddeeff\"\n",
        "flow = \"xtls-rprx-vision\"\n\n",
        "[reality]\n",
        "private_key = \"ERERERERERERERERERERERERERERERERERERERERERE\"\n",
        "short_ids = [\"0123456789abcdef\"]\n",
        "server_names = [\"example.com\"]\n",
        "dest = \"example.com:443\"\n\n",
        "[log]\n",
        "level = \"warn\"\n\n",
        "[limits]\n",
        "max_connections = 64\n",
        "max_udp_destinations = 64\n",
        "max_preauth_per_ip = 16\n",
        "max_xudp_sessions = 64\n",
        "xudp_recv_buffer_bytes = 65536\n",
        "listen_backlog = 128\n",
        "shutdown_drain_ms = 1000\n",
        "handshake_timeout_ms = 5000\n",
        "idle_timeout_ms = 10000\n",
    );
    vec![("minimal_valid.toml", minimal.as_bytes().to_vec())]
}

#[test]
fn config_seeds_parse_and_pass_derived_checks() {
    for (name, bytes) in config_seeds() {
        check_seed(&seeds_dir().join("config").join(name), &bytes);
        let text = std::str::from_utf8(&bytes).expect("config seed must be UTF-8");
        let config = Config::from_toml_str(text).expect("config seed must validate");
        config
            .validate_fd_budget(65_536)
            .expect("config seed must fit deployment FD floor");
    }
}

fn build_synthetic_reality_client_hello(
    client_private: [u8; 32],
    random: [u8; 32],
    client_version: [u8; 3],
    timestamp: u32,
) -> Vec<u8> {
    let client_secret = StaticSecret::from(client_private);
    let client_public = PublicKey::from(&client_secret).to_bytes();

    let mut extensions = Vec::new();
    // SNI extension (0x0000)
    let name = FUZZ_REALITY_SNI.as_bytes();
    let mut sni_data = Vec::new();
    sni_data.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni_data.push(0);
    sni_data.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(name);
    extensions.extend_from_slice(&0x0000_u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_data);

    // supported_versions extension (0x002b) advertising TLS 1.3
    extensions.extend_from_slice(&0x002b_u16.to_be_bytes());
    extensions.extend_from_slice(&3_u16.to_be_bytes());
    extensions.extend_from_slice(&[2, 0x03, 0x04]);

    // key_share extension (0x0033) with X25519 share (0x001d)
    let mut ks_data = Vec::new();
    ks_data.extend_from_slice(&((4 + client_public.len()) as u16).to_be_bytes());
    ks_data.extend_from_slice(&0x001d_u16.to_be_bytes());
    ks_data.extend_from_slice(&(client_public.len() as u16).to_be_bytes());
    ks_data.extend_from_slice(&client_public);
    extensions.extend_from_slice(&0x0033_u16.to_be_bytes());
    extensions.extend_from_slice(&(ks_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&ks_data);

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&[0u8; 32]);
    let cipher_suites = [0x1301_u16, 0x1302, 0x1303];
    body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
    for suite in cipher_suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let body_len = (body.len() as u32).to_be_bytes();
    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.extend_from_slice(&body_len[1..4]);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&0x0301_u16.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    let server_public = PublicKey::from(&StaticSecret::from(FUZZ_REALITY_PRIVATE_KEY));
    let shared_secret = client_secret.diffie_hellman(&server_public);
    assert!(shared_secret.was_contributory());

    let mut auth_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&random[..20]), shared_secret.as_bytes())
        .expand(b"REALITY", &mut auth_key)
        .expect("HKDF expansion");

    let mut plaintext = [0u8; 16];
    plaintext[..3].copy_from_slice(&client_version);
    plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..].copy_from_slice(&FUZZ_REALITY_SHORT_ID);

    let cipher = Aes256Gcm::new_from_slice(&auth_key).expect("AES key");
    let nonce = Nonce::from_slice(&random[20..32]);
    let sealed = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &record[5..],
            },
        )
        .expect("AES-GCM seal");
    assert_eq!(sealed.len(), 32);
    // TLS record header (5) + handshake header (4) + legacy_version (2) +
    // random (32) + session_id_len (1) = offset 44.
    record[44..76].copy_from_slice(&sealed);
    record
}

fn reality_auth_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut random_valid = [0u8; 32];
    for (index, byte) in random_valid.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut random_old_version = [0u8; 32];
    for (index, byte) in random_old_version.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(0x40);
    }
    // Fixed synthetic timestamp (2023-11-14) keeps seeds deterministic while
    // exercising the timestamp-window rejection path under TIME_CHECKED_CONFIG.
    let valid =
        build_synthetic_reality_client_hello([0x22; 32], random_valid, [26, 3, 27], 1_700_000_000);
    let old_version = build_synthetic_reality_client_hello(
        [0x33; 32],
        random_old_version,
        [0, 1, 0],
        1_700_000_000,
    );
    vec![
        ("valid_x25519", valid),
        ("out_of_range_version", old_version),
    ]
}

#[test]
fn reality_auth_seeds_reach_post_authentication_and_bounds_checks() {
    let server_names = [FUZZ_REALITY_SNI.to_owned()];
    let short_ids = [FUZZ_REALITY_SHORT_ID];
    let wide = RealityAuthConfig {
        private_key: &FUZZ_REALITY_PRIVATE_KEY,
        short_ids: &short_ids,
        server_names: &server_names,
        min_client_version: [0, 0, 0],
        max_client_version: [255, 255, 255],
        max_time_diff: None,
    };
    let time_checked = RealityAuthConfig {
        max_time_diff: Some(Duration::from_secs(300)),
        ..wide
    };
    let version_bounded = RealityAuthConfig {
        min_client_version: [1, 8, 0],
        max_client_version: [26, 3, 27],
        ..wide
    };

    for (name, bytes) in reality_auth_seeds() {
        check_seed(&seeds_dir().join("reality_auth").join(name), &bytes);
        let hello = ClientHello::parse(&bytes).expect("seed ClientHello must parse");
        let auth = authenticate(&hello, &wide).expect("seed must pass AEAD + short_id");
        assert_eq!(auth.short_id, FUZZ_REALITY_SHORT_ID);
        assert_eq!(
            authenticate(&hello, &time_checked).unwrap_err(),
            AuthError::TimestampOutOfRange
        );
        match name {
            "valid_x25519" => {
                authenticate(&hello, &version_bounded)
                    .expect("in-range version must pass bounded config");
            }
            "out_of_range_version" => {
                assert_eq!(
                    authenticate(&hello, &version_bounded).unwrap_err(),
                    AuthError::UnsupportedClientVersion
                );
            }
            other => panic!("unexpected reality_auth seed {other}"),
        }
    }
}
