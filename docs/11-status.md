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
| Vision Direct raw TLS handoff | Done |
| Prefix replay stream | Done |
| Stock Xray no-flow TCP interop | **HTTP 200** |
| Stock Xray Vision TCP interop | **HTTP 200** |
| Cover-parity harness | Done; gaps documented |
| XUDP over VLESS Mux | Done |
| Full-TUN harness | TCP v4/v6, UDP, DNS, HTTPS Direct PASS; QUIC blocked on local H3 origin |
| Stock Xray baseline + test fixture | Done |
| Benchmark harness design | Done |

## In progress

- TUN harness v2: IPv6 UDP/DNS and a local HTTP/3 origin.

## Known gaps / not started

- TLS extension-order and encrypted-flight-size parity.
- QUIC/HTTP3 local origin (the UDP/XUDP path itself is validated by DNS/UDP echo).
- Legacy VLESS UDP and packetaddr.
- Splice integration for the Vision Direct raw leg.
- Performance matrix against stock Xray.
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

The workspace currently has 211 `beam-core` unit tests, two integration tests,
and 22 `beam-sys` tests. The full-TUN harness passes TCP v4/v6, UDP echo, DNS,
and HTTPS Direct through the real sing-box client; QUIC is blocked only by the
lack of a local HTTP/3 origin in the harness.
