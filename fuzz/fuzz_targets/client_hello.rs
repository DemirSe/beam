#![no_main]

use beam_core::tls::ClientHello;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ClientHello::parse(data);
});
