#![no_main]

use beam_core::reality::fuzz_extract_ed25519_cert_fields;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_extract_ed25519_cert_fields(data);
});
