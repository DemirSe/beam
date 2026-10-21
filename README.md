# beam

A minimal, high-performance VLESS + REALITY + Vision server written in Rust.

## Status

Preparation. This repository contains the project skeleton and design documents.
There is no working server yet.

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
cargo build --release
```

The toolchain is pinned in `rust-toolchain.toml`.

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

## Repository layout

- `crates/beam` - binary, CLI, configuration, runtime wiring
- `crates/beam-core` - protocol and server logic, no `unsafe`
- `crates/beam-sys` - isolated Linux syscall layer (`splice`, socket options)
