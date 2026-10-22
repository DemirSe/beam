# Status

Updated: 2026-10-22.

## Decisions

- Language: Rust 2024, pinned to 1.99.1.
- Configuration: TOML, strict unknown-field rejection.
- TLS: rustls 0.23 + aws-lc-rs with `prefer-post-quantum` (ADR 0003).
- REALITY: authenticated path does not dial the cover; unauthenticated probes
  are forwarded byte-for-byte.
- Full TUN (TCP, UDP, DNS, QUIC, IPv4/IPv6) is a release blocker.
- Performance acceptance is relative: aggregate better than stock, no
  regression in any tested condition.
- Known v1 cover gaps: extension order and encrypted-flight size; documented in
  `docs/10-cover-parity.md`.

## Implemented and merged

| Area | State |
|---|---|
| Repository skeleton, CI, ADRs | Done |
| TOML config + validation | Done |
| CLI config check + accept loop | Done |
| VLESS/XUDP address codec | Done |
| TLS ClientHello parser | Done |
| REALITY envelope authentication | Done |
| VLESS request/response header codec | Done |
| Vision block framing codec | Done |
| Vision padding/direct state machine | Done |
| XUDP frame codec | Done |
| XUDP session table and UDP relay | Done |
| Linux fd/socket/splice primitives | Done |
| Zero-copy splice relay loop | Done |
| REALITY TLS server adapter (rustls) | Done |
| Cover fallback (byte-exact ClientHello) | Done |
| VLESS user validation | Done |
| Vision-framed relay | Done |
| Stock Xray no-flow TCP interop | **HTTP 200** |
| Stock Xray Vision TCP interop | **HTTP 200** |
| Cover-parity harness | Done; gaps documented |
| Stock Xray baseline + test fixture | Done |
| Benchmark harness design | Done |

## In progress

- Vision Direct implementation (raw TLS handoff).
- Mux command integration with the XUDP session layer.
- Full TUN harness.

## Known gaps / not started

- Vision Direct transition to raw sockets, including TLS read-ahead.
- TLS extension-order and encrypted-flight-size parity.
- Full TUN interoperability tests (DNS, QUIC, IPv6).
- Performance matrix and regression harness.
- Deployment package and VPS cutover.

## Evidence

- `docs/07-reality-spec.md`: REALITY envelope and stock cover behavior.
- `docs/08-vision-xudp-spec.md`: VLESS, Vision, XUDP, legacy UDP, packetaddr.
- `docs/09-tls-stack-spike.md`: rustls/BoringSSL measurements.
- `docs/10-cover-parity.md`: whatsapp.net cover measurements and gaps.
- `docs/06-benchmark-harness.md`: local benchmark topology and gates.
- `docs/12-custom-tls-design.md`: reference-only exact-mirroring design.
- `docs/13-vision-direct-design.md`: Direct raw-handoff design.

## Current verification

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/cover-parity.sh
```

The workspace currently has 202 `beam-core` unit tests, two integration tests,
and 22 `beam-sys` tests. Both the no-flow and Vision stock Xray clients complete
a REALITY handshake and an HTTP request through the `beam` binary.
