# Fuzz targets

The fuzz workspace is separate from the production workspace so fuzz-only
dependencies and instrumentation never enter the release build.

Run from the repository root:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz build
cargo +nightly fuzz run client_hello -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run reality_auth -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run vless -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run vision -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run xudp -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run legacy_udp -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run config -- -max_total_time=60 -timeout=10
```

The targets have no network side effects. `legacy_udp` uses a test-only
feature-gated helper to exercise the pure reassembly and packetaddr parsers.
The GitHub fuzz workflow is **manual-only**: there is no schedule and no
automatic trigger. GitHub only exposes `workflow_dispatch` from the default
branch, so while these changes are on the hardening branch, run the targets
locally. The manual button becomes available after this branch is merged or
made the default.
