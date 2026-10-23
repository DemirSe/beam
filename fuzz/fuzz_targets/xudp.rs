#![no_main]

use beam_core::xudp::parse_frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_frame(data);
});
