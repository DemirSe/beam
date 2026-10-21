# Scope

## Purpose

`beam` is a server-only replacement for the current stock Xray deployment. It
serves one user and one VPN profile. The goal is to be wire-compatible with
stock clients, faster than stock Xray on the same hardware, and small enough to
audit and maintain with AI agents.

## Production profile

| Item | Value |
|---|---|
| Inbound | VLESS over TCP |
| Security | REALITY |
| Cover | `whatsapp.net:443` |
| SNI | `whatsapp.net` |
| Flow | `xtls-rprx-vision` |
| UDP | XUDP, plus legacy VLESS UDP where needed for client compatibility |
| Outbound | `freedom` (direct) |
| Users | One |
| Listener | One IPv4 address, TCP/443 |
| Platform | Debian 13, x86_64, 1 vCPU, 1 GB RAM |
| Logging | Detailed in development, minimal in deployment |

The client side is a full-TUN VPN client (Hiddify, sing-box, or stock Xray).
The server does not implement TUN, DNS, routing, or a GUI.

## Full TUN

The client provides the TUN interface and routes traffic into it. The server
must carry every TCP and UDP flow the client sends, including DNS and QUIC.
UDP requires XUDP (and legacy VLESS UDP for clients that select it). IPv4 and
IPv6 destinations are both in scope. ICMP is not carried by VLESS; stock Xray
has the same limitation, so this is not a regression.

## In scope

- VLESS request and response parsing.
- REALITY server handshake and unauthenticated forwarding to the cover.
- XTLS Vision padding and the transition to direct relay.
- XUDP framing, session lifecycle, and UDP relay.
- TCP relay with `splice(2)` and a buffered fallback.
- TOML configuration, validation, and clear startup errors.
- Structured logging and minimal runtime counters.
- Systemd unit, static binary, and rollback procedure.
- Unit, integration, interoperability, fuzz, soak, and benchmark coverage.

## Out of scope for the first release

- Client, TUN device, GUI, or mobile application.
- Multi-user, panels, subscription links, or accounting.
- VMess, Trojan, Shadowsocks, SOCKS, HTTP proxy, Hysteria2, TUIC, AnyTLS.
- WebSocket, gRPC, HTTP/2, QUIC, or H2MUX transports.
- Routing engine, DNS server, freedom chaining, or multiple outbounds.
- Statistics API, Prometheus endpoint, or hot configuration reload.
- Windows, macOS, ARM64, or 32-bit platforms.

## Success criteria

1. An unchanged stock Xray client, sing-box client, and Hiddify client can use
   the server with full TUN: TCP, UDP, DNS, QUIC, and IPv4/IPv6 destinations.
2. The server survives 24 hours of mixed traffic and 10,000 connection churn
   without leaks, crashes, or unbounded memory growth.
3. On the same 1 vCPU machine, `beam` is better than stock Xray in the aggregate
   benchmark and does not regress in any tested condition. Numeric targets live
   in `docs/04-benchmark.md`; they are goals, not release blockers.
4. Unauthenticated probes see plausible cover behavior and cannot distinguish
   `beam` from the cover at the TLS-record level within the tested cases.
5. A new AI agent can understand the repository from the documents and run all
   checks without hidden context.
