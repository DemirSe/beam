# AI agent rules

This repository is written and maintained by AI agents. These rules exist to
keep the codebase correct, reviewable, and safe to change without human
supervision.

## Read order

1. `README.md`
2. `STRESS-FINDINGS.md` while it exists
3. The code you are about to change

## Golden rules

- Correctness first, then performance, then elegance.
- Never change wire behavior without updating the compatibility section of
  `README.md` and adding a test.
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

## Agent workflow and evidence

- Before substantive work, state the intended change, verification and success
  criteria briefly. Report each relevant check as passed, failed, pending or
  not tested, with the tested commit and Actions run where applicable. Scale
  the detail to the task; a small edit does not need a formal table.
- Separate observations from assumptions and conclusions. Do not claim that
  untested behavior is proven; state what remains unverified. Report failed
  gates as failed even when an interpretation suggests another explanation.
- Independent review is only started at the owner's request, using the model
  and reasoning level specified by the owner. For risky changes, the owner may
  request it before an implementation decision. Ask the reviewer to challenge
  assumptions, user-visible effects and whether the tests prove the claims.
- When work is delegated in parallel, assign non-overlapping file ownership
  or make a task read-only. If changes overlap, designate one agent to combine
  them and verify the result.
- Present consequential decisions early and briefly: options, user impact,
  tradeoffs and missing evidence. Continue already authorized routine work,
  including Actions dispatches, without asking again; preserve the owner's
  approval requirement for merging into `main`.

## Verification before every commit

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Hot-path changes also require a benchmark comparison. Parser changes also
require the relevant fuzz target to run locally.

## Branch and release workflow

- Do all development on `dev`. `main` holds production code.
- Only the repository owner merges into `main`. Do not merge `dev` into `main`
  without explicit owner approval and the required green tests.
- Run lab, TUN, stress, bench, and protocol campaigns on GitHub Actions, not
  locally. Dispatch them with `gh workflow run lab-hosted.yml ...`.
- Record the commit, purpose and success criteria for each Actions run. If a
  push cancels or supersedes a run, verify that its replacement covers the
  same requirements. Reuse applicable evidence when later changes do not
  affect it; do not claim that an earlier run tested a later commit.
- Locally, run only the short isolated checks: the three commands in
  "Verification before every commit" and the report contract tests in
  `make test`.
- A check that needs root, a TUN device, netem, pinned tool binaries, or a long
  wall-clock window belongs to Actions. Do not add it to the local loop.
- If a local check cannot pass because of the host itself (for example, no IPv6
  for a loopback test), record the exact failing test names in the report and
  require the matching Actions job to pass before the merge. Do not skip a check
  silently and do not merge a red check without that evidence.

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

Keep each commit focused on one concern. `dev` and `main` must always build and
pass the verification commands above.

## Security

- Treat every byte from the network as hostile.
- Keep secrets out of logs, error messages, test fixtures, and benchmark output.
- Use constant-time comparison for authentication material.
- Prefer `subtle` or an equivalent constant-time primitive over `==`.
- Do not add a feature that weakens the REALITY cover behavior without an
  explicit decision in the compatibility section of `README.md`.
