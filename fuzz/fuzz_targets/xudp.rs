#![no_main]

use beam_core::xudp::{fuzz_frame_sequence, parse_frame};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_frame(data);
    // Apply a bounded frame sequence to a session model, so New/Keep/End
    // transitions and their bounds are covered as well as one frame.
    fuzz_frame_sequence(data);
});
