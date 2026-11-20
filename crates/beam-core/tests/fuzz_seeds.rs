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

use beam_core::address::{Address, NetLocation};
use beam_core::udp::is_packetaddr_destination;
use beam_core::udp::legacy::PACKETADDR_MAGIC_DOMAIN;
use beam_core::vless::{Command, RequestHeader, VISION_ADDONS};
use beam_core::xudp::{
    FrameOption, FrameSpec, GLOBAL_ID_LEN, SessionStatus, TargetNetwork, encode_frame, parse_frame,
};

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
