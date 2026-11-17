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

`scripts/fuzz-smoke.sh` passes a corpus directory to `cargo +nightly fuzz run`
and sets `-max_total_time=60`, `-timeout=10`, and `-rss_limit_mb=1536` by
default. `BEAM_FUZZ_SECONDS` changes the time limit.

## Short campaign

```bash
make fuzz-smoke
```

The Makefile sets `BEAM_FUZZ_CACHE` to `~/.cache/beam/fuzz-corpus`. That keeps
the corpus cache outside the repository. `fuzz/.gitignore` excludes `/corpus`.
There is no seed corpus in the tree yet.
