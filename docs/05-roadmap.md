# Roadmap

Timeline is an estimate for an AI-driven implementation. Each phase ends with
evidence, not with a date.

## Phase 0 - Preparation

Deliverables:

- Repository skeleton and pinned toolchain.
- Scope, compatibility, architecture, test, and benchmark documents.
- Rust toolchain installed locally.
- Stock Xray v26.3.27 source available as reference.
- Initial benchmark and fuzz harness plan.

Exit criteria:

- `cargo fmt`, `clippy`, and `test` pass on the skeleton.
- The documents agree on scope and non-goals.

## Phase 1 - REALITY/TLS spike

Deliverables:

- Minimal TLS 1.3 server with ClientHello parsing.
- REALITY authentication and cover forwarding.
- Test against a stock Xray client.
- Measured comparison of rustls, BoringSSL, and a custom record layer.
- ADR for the chosen TLS stack.

Exit criteria:

- A stock Xray client completes a REALITY handshake and a VLESS request.
- Unauthenticated probes reach the cover and receive a plausible response.
- The chosen stack meets the first latency and CPU measurements.

## Phase 2 - TCP + VLESS + Vision MVP

Deliverables:

- VLESS request/response parsing.
- Vision padding and direct-mode transition.
- Freedom outbound.
- `splice(2)` relay with buffered fallback.
- TOML config and logging.
- Interoperability tests with Xray and sing-box.

Exit criteria:

- TCP download/upload works through unchanged client configs.
- Half-close, reset, idle, and reconnect cases pass.
- No panic on malformed input.

## Phase 3 - UDP and XUDP

Deliverables:

- XUDP frame codec and session table.
- UDP relay with source filtering.
- Legacy VLESS UDP compatibility.
- Limits, expiry, and resource accounting.
- DNS and QUIC tests.

Exit criteria:

- DNS and QUIC work through the full-TUN client.
- Many-destination and reconnect cases pass.
- No socket or memory leak after churn.

## Phase 4 - Hardening

Deliverables:

- Fuzz targets and corpus.
- Timeout and limit audit.
- Probe-resistance tests.
- 24-hour soak and 10,000-connection churn.
- Crash and resource-leak fixes.

Exit criteria:

- Fuzzers run clean for the agreed budget.
- Soak and churn pass with stable RSS and fd counts.

## Phase 5 - Performance

Deliverables:

- Full benchmark matrix against stock Xray.
- Buffer, batching, and syscall optimization.
- `io_uring` evaluation if `splice` leaves headroom.
- Regression benchmark in CI or a scheduled job.

Exit criteria:

- `beam` is better than stock in the aggregate benchmark.
- No tested condition regresses under loss, added RTT, or single-core pinning.
- Numeric targets in `docs/04-benchmark.md` are met, or the gap is documented
  and accepted.

## Phase 6 - Deployment package

Deliverables:

- Static musl release binary.
- Systemd unit and config template.
- Install, rollback, and health-check scripts.
- Deployment runbook.

Exit criteria:

- Clean Debian 13 install works.
- Rollback is tested.
- The user approves the final VPS cutover.

## Risks

| Risk | Mitigation |
|---|---|
| REALITY/TLS behavior differs from stock | Spike first; compare record-level traces; keep a compatibility test |
| Rust async complexity slows the data path | Keep the hot path in a dedicated splice loop; isolate async at the edges |
| UDP session semantics diverge | Reuse the compatibility matrix and fuzz XUDP |
| Performance gates fail on 1 vCPU | Measure early; optimize buffers and syscalls; evaluate io_uring |
| AI-generated code drifts | Strict lints, tests, fuzz, ADRs, and small commits |

## First two weeks

1. Finish Phase 0 documents and repository hygiene.
2. Build the ClientHello parser and test fixtures.
3. Run the TLS stack spike.
4. Produce the first compatibility report against stock Xray.
