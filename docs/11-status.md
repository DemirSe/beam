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

## Implemented

| Area | State |
|---|---|
| Repository skeleton, CI, ADRs | Done |
| TOML config + validation | Done |
| CLI config check | Done |
| VLESS/XUDP address codec | Done |
| TLS ClientHello parser | Done |
| REALITY envelope authentication | Done |
| VLESS request/response header codec | Done |
| Vision block framing codec | Done |
| XUDP frame codec | Done |
| Linux fd/socket/splice primitives | Done |
| Stock Xray baseline + test fixture | Done |
| Benchmark harness design | Done |
| TLS server adapter (rustls + cover fallback) | In progress |

## Not started

- Vision state machine: TLS detection, long/short padding, Direct transition,
  read-ahead preservation.
- XUDP session table and UDP relay.
- TCP relay with `splice`.
- Config-to-runtime wiring.
- Full TUN interoperability tests (DNS, QUIC, IPv6).
- Cover-parity harness for the authenticated flight.
- Performance matrix.
- Deployment package and VPS cutover.

## Evidence

- `docs/07-reality-spec.md`: REALITY envelope and stock cover behavior.
- `docs/08-vision-xudp-spec.md`: VLESS, Vision, XUDP, legacy UDP, packetaddr.
- `docs/09-tls-stack-spike.md`: rustls/BoringSSL measurements.
- `docs/10-cover-parity.md`: whatsapp.net cover measurements.
- `docs/06-benchmark-harness.md`: local benchmark topology and gates.

## Current verification

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The workspace currently has 115 `beam-core` unit tests, one stock-ClientHello
integration test, and 10 `beam-sys` tests. The TLS server adapter adds its own
tests when merged.
