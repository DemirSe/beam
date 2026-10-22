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
| XUDP over VLESS Mux | Done |
| Legacy VLESS UDP and packetaddr | Done |
| Linux fd/socket/splice primitives | Done |
| Zero-copy splice relay loop | Done |
| REALITY TLS server adapter (rustls) | Done |
| Cover fallback (byte-exact ClientHello) | Done |
| VLESS user validation | Done |
| Vision-framed relay | Done |
| Vision Direct raw TLS handoff | Done |
| Early one-way raw download splice | Done |
| Prefix replay stream | Done |
| Stock Xray no-flow TCP interop | **HTTP 200** |
| Stock Xray Vision TCP/HTTPS interop | **HTTP 200** |
| Cover-parity harness | Done; gaps documented |
| Full-TUN harness v2 | **8/8 PASS** |
| Full-TUN benchmark harness | Done |
| No-TUN server-capacity smoke | Done |

## Full-TUN matrix

The same eight probes pass through the real sing-box TUN client with all three
UDP modes:

| Probe | XUDP | packetaddr | legacy UDP |
|---|---|---|---|
| TCP HTTP IPv4 | PASS | PASS | PASS |
| TCP HTTP IPv6 | PASS | PASS | PASS |
| UDP echo IPv4 | PASS | PASS | PASS |
| UDP echo IPv6 | PASS | PASS | PASS |
| DNS IPv4 | PASS | PASS | PASS |
| DNS IPv6 | PASS | PASS | PASS |
| QUIC / HTTP3 | PASS | PASS | PASS |
| HTTPS through Vision Direct | PASS | PASS | PASS |

## Performance snapshot

- Full-TUN bulk throughput is **client-capped** by the sing-box TUN client on
  this host; stock and beam are at roughly 0.98-1.00x, so the fixed-multiplier
  throughput gates are not evaluable in that harness.
- **No-TUN server-capacity smoke** (stock Xray SOCKS client, 256 MiB plain
  HTTP, separate CPUs): beam **872 MB/s** vs stock **589 MB/s** in the final
  run (**1.48x**; earlier runs 1.56x). This removes the TUN client cap and
  exposes the server path.
- Server CPU per GiB, TCP download: **0.79x** stock (21% lower).
- Server CPU per GiB, TCP upload: ~1.00x / 1.03x (slightly worse).
- HTTPS Vision Direct: early one-way splice reduced server CPU from ~0.32 to
  **0.107 s/GiB**, matching stock; quick throughput ratio **1.033x**.
- UDP echo throughput: **1.22x** stock.
- Server RSS after warm-up: **0.24x** stock (76% lower).
- DNS p50/p95 favor beam; p99 and H3 p99 are slightly worse on a noisy host.
- Syscall/wakeup/splice gates need a privileged, quiet acceptance run.

## In progress

- Final soak/churn and RTT-condition validation.
- Deployment package (not deployed).

## Known gaps / not started

- TLS extension-order and encrypted-flight-size parity.
- HTTPS upload still uses tokio copy; only the download direction gets the
  early one-way splice.
- VPS cutover is intentionally not performed.

## Evidence

- `docs/07-reality-spec.md`: REALITY envelope and stock cover behavior.
- `docs/08-vision-xudp-spec.md`: VLESS, Vision, XUDP, legacy UDP, packetaddr.
- `docs/09-tls-stack-spike.md`: rustls/BoringSSL measurements.
- `docs/10-cover-parity.md`: whatsapp.net cover measurements and gaps.
- `docs/06-benchmark-harness.md`: local benchmark topology and gates.
- `docs/12-custom-tls-design.md`: reference-only exact-mirroring design.
- `docs/13-vision-direct-design.md`: Direct raw-handoff design.
- `docs/14-tun-harness.md`: full-TUN topology, probes, and control results.
- `bench/README.md`: benchmark and no-TUN smoke usage.

## Current verification

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/cover-parity.sh
bash tests/tun/run.sh
bash tests/tun/run.sh --udp-mode packetaddr
bash tests/tun/run.sh --udp-mode legacy
bash bench/no-tun.sh
```

The workspace currently has 234 `beam-core` unit tests, two integration tests,
and 22 `beam-sys` tests. The full-TUN harness passes all eight probes for XUDP,
packetaddr, and legacy VLESS UDP; the no-TUN server-capacity smoke is ~1.5x
stock.
