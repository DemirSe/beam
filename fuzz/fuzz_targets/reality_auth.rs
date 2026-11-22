#![no_main]

use std::sync::LazyLock;
use std::time::Duration;

use beam_core::reality::{RealityAuthConfig, authenticate};
use beam_core::tls::ClientHello;
use libfuzzer_sys::fuzz_target;

/// Synthetic test-only REALITY configuration reused across fuzz iterations
/// (never real credentials). Matches the synthetic seeds in
/// `fuzz/seeds/reality_auth/`.
const PRIVATE_KEY: [u8; 32] = [0x11_u8; 32];
const SHORT_IDS: [[u8; 8]; 1] = [[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]];
const TIME_WINDOW: Duration = Duration::from_secs(300);

static SERVER_NAMES: LazyLock<Vec<String>> = LazyLock::new(|| vec!["whatsapp.net".to_string()]);

static WIDE_CONFIG: LazyLock<RealityAuthConfig<'static>> = LazyLock::new(|| RealityAuthConfig {
    private_key: &PRIVATE_KEY,
    short_ids: &SHORT_IDS,
    server_names: SERVER_NAMES.as_slice(),
    min_client_version: [0, 0, 0],
    max_client_version: [255, 255, 255],
    max_time_diff: None,
});

static TIME_CHECKED_CONFIG: LazyLock<RealityAuthConfig<'static>> =
    LazyLock::new(|| RealityAuthConfig {
        private_key: &PRIVATE_KEY,
        short_ids: &SHORT_IDS,
        server_names: SERVER_NAMES.as_slice(),
        min_client_version: [0, 0, 0],
        max_client_version: [255, 255, 255],
        max_time_diff: Some(TIME_WINDOW),
    });

static VERSION_BOUNDED_CONFIG: LazyLock<RealityAuthConfig<'static>> =
    LazyLock::new(|| RealityAuthConfig {
        private_key: &PRIVATE_KEY,
        short_ids: &SHORT_IDS,
        server_names: SERVER_NAMES.as_slice(),
        min_client_version: [1, 8, 0],
        max_client_version: [26, 3, 27],
        max_time_diff: None,
    });

fuzz_target!(|data: &[u8]| {
    let Ok(hello) = ClientHello::parse(data) else {
        return;
    };

    // Exercise wide acceptance, timestamp-window validation, and client
    // version-bound rejection against the same reused configuration.
    let _ = authenticate(&hello, &WIDE_CONFIG);
    let _ = authenticate(&hello, &TIME_CHECKED_CONFIG);
    let _ = authenticate(&hello, &VERSION_BOUNDED_CONFIG);
});
