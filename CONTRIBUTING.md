# Contributing

## Before you change code

Read `AGENTS.md` first. It defines the architecture boundaries, the security
rules, and the commit rules. Keep each commit focused on one concern.

## Build and test

The Makefile defines the local commands:

- `make build` runs `cargo build --locked --release`.
- `make verify` aliases `make check`. It runs `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`, and
  `cargo test --workspace`.
- `make test` also runs `make test-scripts`: report, deploy, release, install,
  and Linux tray DNS checks.
- `make smoke` builds the release binary, checks `config.example.toml`, and
  runs `bash -n` on tracked shell scripts.
- `make fuzz-smoke` runs short fuzz campaigns. See `fuzz/README.md`.

Run `make verify` before every commit.

## Change rules

- Use short conventional commits, for example `fix(xudp): reject zero-length
  frames`. `AGENTS.md` lists more examples.
- Do not use `unsafe` outside `crates/beam-sys`. Add a `// SAFETY:` comment to
  each unsafe block.
- If you change wire behavior, update the Compatibility section of `README.md`
  and add a test.

## Further reading

- `docs/STATE-MACHINES.md` inventories the implicit state in the server and
  both client launchers. Read it before changing a lifecycle or timeout path.
- `docs/AUDIT.md` is the historical 2026-11-11 hardening pass.
- `docs/STRESS-FINDINGS.md` is the historical lab record.
- `docs/ISSUES.md` and `docs/TODO.md` hold the open gaps.
- `docs/DEPLOY.md` is the operator runbook.

## Security reports

See `SECURITY.md` for the private reporting route and the scope.
