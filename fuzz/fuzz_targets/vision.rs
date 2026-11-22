#![no_main]

use beam_core::vision::{TlsDetector, parse_block};
use libfuzzer_sys::fuzz_target;

/// Upper bound on chunks fed to a single detector per fuzz input so mutation
/// exercises multi-chunk ServerHello continuation and filter-budget exhaustion
/// without unbounded work.
const MAX_CHUNKS: usize = 16;

fuzz_target!(|data: &[u8]| {
    let _ = parse_block(data, true);
    let _ = parse_block(data, false);

    // Single-buffer pass preserves direct coverage of one-shot records.
    let mut single = TlsDetector::new();
    let _ = single.inspect(data);

    // Multi-chunk pass splits the input into a bounded sequence of slices and
    // feeds them into one detector so fragmented ServerHello assembly, rejected
    // candidate recovery, and filter-budget exhaustion are all exercised.
    if data.len() < 2 {
        return;
    }
    let mut detector = TlsDetector::new();
    let mut rest = data;
    for _ in 0..MAX_CHUNKS {
        let Some((&len_hint, tail)) = rest.split_first() else {
            break;
        };
        let take = usize::from(len_hint).min(tail.len());
        let (chunk, next) = tail.split_at(take);
        let _ = detector.inspect(chunk);
        rest = next;
    }
    if !rest.is_empty() {
        let _ = detector.inspect(rest);
    }
});
