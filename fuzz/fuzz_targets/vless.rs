#![no_main]

use beam_core::vless::{Addons, RequestHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = RequestHeader::parse(data);
    let _ = Addons::parse(data);
});
