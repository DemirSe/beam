# beam

A minimal, high-performance VLESS + REALITY + Vision server written in Rust.

## Status

Implemented, tested, and deployed for the single-user VLESS + REALITY + Vision
profile. See [`docs/11-status.md`](docs/11-status.md) for the current state and
[`docs/15-production-runbook.md`](docs/15-production-runbook.md) for live
operations. The local stock-Xray comparison is in
[`docs/16-local-comparison-2026-10-22.md`](docs/16-local-comparison-2026-10-22.md).

## Goal

Replace the stock Xray server for a single-user, full-TUN VPN profile:

- VLESS inbound over TCP
- REALITY with a `whatsapp.net` cover
- XTLS Vision (`xtls-rprx-vision`)
- XUDP for UDP
- Direct (`freedom`) outbound
- One user, one inbound, Linux x86_64

`beam` must be wire-compatible with stock Xray clients and with sing-box/Hiddify,
and faster than stock Xray on the same 1 vCPU VPS.

## Non-goals

Client/TUN, multi-user, VMess/Trojan/Shadowsocks, WebSocket/gRPC/QUIC
transports, H2MUX, routing/DNS server, stats API, and hot reload are out of
scope for the first release.

## Build

```bash
source scripts/dev-env.sh
cargo build --release
```

The toolchain is pinned in `rust-toolchain.toml`. The script adds the local
portable CMake/Ninja used to build `aws-lc-rs`; on a normal build host it falls
back to the system tools.

## Configuration check

```bash
cargo run -- --check -c config.example.toml
```

`config.example.toml` contains a sample key and a nil user id. Replace every
value before deployment.

## Documents

- [`docs/00-scope.md`](docs/00-scope.md)
- [`docs/01-compatibility.md`](docs/01-compatibility.md)
- [`docs/02-architecture.md`](docs/02-architecture.md)
- [`docs/03-test-plan.md`](docs/03-test-plan.md)
- [`docs/04-benchmark.md`](docs/04-benchmark.md)
- [`docs/05-roadmap.md`](docs/05-roadmap.md)
- [`docs/06-benchmark-harness.md`](docs/06-benchmark-harness.md)
- [`docs/07-reality-spec.md`](docs/07-reality-spec.md)
- [`docs/08-vision-xudp-spec.md`](docs/08-vision-xudp-spec.md)
- [`docs/09-tls-stack-spike.md`](docs/09-tls-stack-spike.md)
- [`docs/10-cover-parity.md`](docs/10-cover-parity.md)
- [`docs/11-status.md`](docs/11-status.md)
- [`docs/12-custom-tls-design.md`](docs/12-custom-tls-design.md)
- [`docs/13-vision-direct-design.md`](docs/13-vision-direct-design.md)
- [`docs/14-tun-harness.md`](docs/14-tun-harness.md)
- [`docs/15-production-runbook.md`](docs/15-production-runbook.md)
- [`docs/16-local-comparison-2026-10-22.md`](docs/16-local-comparison-2026-10-22.md)
- [`docs/17-resource-hardening.md`](docs/17-resource-hardening.md)

## Repository layout

- `crates/beam` - binary, CLI, configuration, runtime wiring
- `crates/beam-core` - protocol and server logic, no `unsafe`
- `crates/beam-sys` - isolated Linux syscall layer (`splice`, socket options)
