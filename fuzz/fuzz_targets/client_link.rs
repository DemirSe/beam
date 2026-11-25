#![no_main]

use std::net::{Ipv4Addr, SocketAddr};

use beam_core::client::parse_client_link;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(link) = parse_client_link(input) {
        // Exercise the redacting Debug renderer and the config conversion so a
        // parsed value cannot panic downstream.
        let _ = format!("{link:?}");
        let _ = link.into_beam_client_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
    }
});
