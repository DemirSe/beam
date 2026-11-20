# Fuzz targets

The `fuzz/` crate has seven targets. Each target is a binary in
`fuzz/fuzz_targets/`:

- `client_hello`
- `reality_auth`
- `vless`
- `vision`
- `xudp`
- `legacy_udp`
- `config`

`fuzz/Cargo.toml` names the same seven binaries. `scripts/fuzz-smoke.sh` uses
this list by default.

## Run one target

Install `cargo-fuzz` with `cargo install cargo-fuzz --locked`. Then run a target
from the repository root:

```bash
cargo +nightly fuzz run <target>
```

`scripts/fuzz-smoke.sh` passes the corpus cache and, when present, the checked-in
seed directory `fuzz/seeds/<target>/` to `cargo +nightly fuzz run`, and sets
`-max_total_time=60`, `-timeout=10`, and `-rss_limit_mb=1536` by default.
`BEAM_FUZZ_SECONDS` changes the time limit.

## Seeds

`fuzz/seeds/<target>/` holds synthetic seed inputs. They are pattern data only:
a placeholder UUID and documentation address ranges, never real credentials or
captured traffic. `vless` seeds cover a plain TCP request, a Vision mux request,
and the legacy UDP packetaddr sentinel; `xudp` holds a multi-frame
New/Keep/End/KeepAlive sequence. `crates/beam-core/tests/fuzz_seeds.rs`
validates the checked-in bytes and rebuilds them:

```bash
BEAM_WRITE_FUZZ_SEEDS=1 cargo test -p beam-core --test fuzz_seeds
```

The `xudp` target also runs a bounded stateful sequence model
(`xudp::fuzz_frame_sequence`), so session transitions are exercised instead of
one frame in isolation. The `client_hello` target runs the assembler with the
budget derived from the record header and again at the production cap.

## Short campaign

```bash
make fuzz-smoke
```

The Makefile sets `BEAM_FUZZ_CACHE` to `~/.cache/beam/fuzz-corpus`. That keeps
the corpus cache outside the repository. `fuzz/.gitignore` excludes `/corpus`.
