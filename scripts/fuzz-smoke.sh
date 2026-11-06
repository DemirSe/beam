#!/usr/bin/env bash
# Run short fuzz campaigns with the corpus cache outside the repository.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="${BEAM_FUZZ_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/beam/fuzz-corpus}"
SECONDS_PER_TARGET="${BEAM_FUZZ_SECONDS:-60}"
TARGETS="${BEAM_FUZZ_TARGETS:-client_hello reality_auth vless vision xudp legacy_udp config}"

case "$SECONDS_PER_TARGET" in
    ''|*[!0-9]*) echo "fuzz-smoke: BEAM_FUZZ_SECONDS must be a positive integer" >&2; exit 2 ;;
esac
[ "$SECONDS_PER_TARGET" -gt 0 ] || { echo "fuzz-smoke: BEAM_FUZZ_SECONDS must be positive" >&2; exit 2; }
command -v cargo-fuzz >/dev/null 2>&1 || {
    echo "fuzz-smoke: cargo-fuzz is not installed (cargo install cargo-fuzz --locked)" >&2
    exit 2
}
mkdir -p "$CACHE"
cd "$ROOT"
for target in $TARGETS; do
    corpus="$CACHE/$target"
    mkdir -p "$corpus"
    echo "fuzz-smoke: $target for ${SECONDS_PER_TARGET}s (corpus=$corpus)"
    cargo +nightly fuzz run "$target" "$corpus" -- \
        -max_total_time="$SECONDS_PER_TARGET" -timeout=10 -rss_limit_mb=1536
done
echo "fuzz-smoke: PASS; corpus cache is $CACHE"
