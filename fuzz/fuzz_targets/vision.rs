#![no_main]

use beam_core::vision::{TlsDetector, parse_block};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_block(data, true);
    let _ = parse_block(data, false);

    let mut detector = TlsDetector::new();
    let _ = detector.inspect(data);
});
