#![no_main]

use beam_core::reality::{RealityAuthConfig, authenticate};
use beam_core::tls::ClientHello;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(hello) = ClientHello::parse(data) else {
        return;
    };

    let private_key = [0x11_u8; 32];
    let short_ids = ["0123456789abcdef".to_string()];
    let server_names = ["whatsapp.net".to_string()];
    let config = RealityAuthConfig {
        private_key: &private_key,
        short_ids: &short_ids,
        server_names: &server_names,
        min_client_version: [0, 0, 0],
        max_client_version: [255, 255, 255],
        max_time_diff: None,
    };
    let _ = authenticate(&hello, &config);
});
