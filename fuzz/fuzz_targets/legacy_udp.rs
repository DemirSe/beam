#![no_main]

use beam_core::udp::legacy::fuzz_legacy_parser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_legacy_parser(data);
});
