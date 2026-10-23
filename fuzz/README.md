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
The scheduled GitHub workflow runs a short **weekly** budget to stay inside a
private repository's free Actions minutes. GitHub only exposes scheduled and
manual workflows from the default branch, so while these changes are on the
hardening branch, run the targets locally. The weekly schedule and the manual
button become available after this branch is merged or made the default.
