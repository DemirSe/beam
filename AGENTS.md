# AI agent rules

This repository is written and maintained by AI agents. These rules exist to
keep the codebase correct, reviewable, and safe to change without human
supervision.

## Read order

1. `docs/00-scope.md`
2. `docs/01-compatibility.md`
3. `docs/02-architecture.md`
4. `docs/03-test-plan.md`
5. `docs/04-benchmark.md`
6. `docs/05-roadmap.md`
7. The code you are about to change

## Golden rules

- Correctness first, then performance, then elegance.
- Never change wire behavior without updating the compatibility matrix and
  adding a test.
- Never commit credentials, private keys, UUIDs from real configs, or captures
  of real traffic.
- No `unsafe` outside `crates/beam-sys`. Every unsafe block needs a `// SAFETY:`
  comment that states the invariant.
- No panics, `unwrap`, `expect`, `todo`, or `unimplemented` on paths reachable
  from network input.
- Bound every allocation, queue, frame, handshake, and retry loop.
- Every network read and write must have a timeout or an explicit shutdown
  deadline.
- Use `tracing`, not `println!`, for diagnostics. Development profiles may be
  verbose; deployment profiles must be minimal.
- Keep dependencies small. A new crate needs a reason in the commit message or
  PR description.
- Update the relevant document when a decision or behavior changes.

## Verification before every commit

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Hot-path changes also require a benchmark comparison. Parser changes also
require the relevant fuzz target to run locally.

## Architecture boundaries

- `beam`: process lifecycle, CLI, config loading, logging, signal handling.
- `beam-core`: REALITY, TLS record handling, VLESS, Vision, XUDP, relay logic.
- `beam-sys`: `splice`, `io_uring`, socket options, and other Linux-specific
  primitives. This is the only crate allowed to use `unsafe`.

`beam-core` must stay testable without root, without a real network, and without
a VPS. Tests use loopback, temporary directories, and generated certificates.

## Commits

Use short conventional commits:

```text
feat(reality): authenticate client hello
fix(xudp): reject zero-length frames
perf(relay): batch splice wakeups
docs(scope): record the single-user constraint
test(vision): cover padding flush
```

Keep each commit focused on one concern. `main` must always build and pass the
verification commands above.

## Security

- Treat every byte from the network as hostile.
- Keep secrets out of logs, error messages, test fixtures, and benchmark output.
- Use constant-time comparison for authentication material.
- Prefer `subtle` or an equivalent constant-time primitive over `==`.
- Do not add a feature that weakens the REALITY cover behavior without an
  explicit decision in `docs/01-compatibility.md`.
