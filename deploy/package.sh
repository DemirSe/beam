#!/bin/bash
# Build a root-readable deployment bundle from the local secrets file.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SECRETS="${BEAM_SECRETS:-$HOME/.config/beam/beam.toml}"
OUT="${BEAM_BUNDLE_OUT:-/tmp/opencode/beam-deploy-$(date -u +%Y%m%dT%H%M%SZ)}"

[ -f "$SECRETS" ] || { echo "package: missing secrets file $SECRETS" >&2; exit 1; }
source "$ROOT/scripts/dev-env.sh"
cargo build --manifest-path "$ROOT/Cargo.toml" --release -p beam

rm -rf "$OUT"
install -d -m 0700 "$OUT"
install -m 0755 "$ROOT/target/release/beam" "$OUT/beam"
install -m 0600 "$SECRETS" "$OUT/beam.toml"
install -m 0644 "$HERE/beam.service" "$OUT/beam.service"
install -m 0644 "$HERE/99-beam.conf" "$OUT/99-beam.conf"
install -m 0755 "$HERE/bootstrap.sh" "$OUT/bootstrap.sh"
tar -C "$OUT" -czf "$OUT/beam-deploy.tar.gz" beam beam.toml beam.service 99-beam.conf bootstrap.sh
chmod 0600 "$OUT/beam-deploy.tar.gz"
sha256sum "$OUT/beam-deploy.tar.gz" > "$OUT/beam-deploy.tar.gz.sha256"
echo "bundle=$OUT/beam-deploy.tar.gz"
echo "sha256=$(cat "$OUT/beam-deploy.tar.gz.sha256")"
