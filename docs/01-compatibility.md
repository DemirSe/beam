# Compatibility

## Reference versions

| Component | Version | Role |
|---|---|---|
| Xray-core | `v26.3.27` | Latest stable; wire reference |
| sing-box | `v1.14.3` | Client interoperability |
| Hiddify | `v4.1.1` | User-facing client; core varies |

The server must accept the same client configuration that works with stock
Xray today. The UUID, REALITY public key, short ID, SNI, and flow stay
unchanged.

## Profile under test

```text
VLESS + TCP + REALITY + Vision
cover: whatsapp.net:443
SNI: whatsapp.net
flow: xtls-rprx-vision
UDP: xudp, and legacy VLESS UDP when the client selects it
outbound: freedom
```

## Client matrix

| Client | Transport | UDP mode | Required result |
|---|---|---|---|
| Xray-core v26.3.27 | TCP + REALITY + Vision | `xudp` | Pass |
| Xray-core v26.3.27 | TCP + REALITY + Vision | no packet encoding | Pass |
| sing-box v1.14.3 | TCP + REALITY + Vision | default | Pass |
| sing-box v1.14.3 | TCP + REALITY + Vision | `packetaddr` | Pass |
| Hiddify v4.1.1 | Bundled core | Default | Pass |

## Scenario matrix

| Scenario | Pass condition |
|---|---|
| TCP bulk download | Payload integrity, no stalls, expected throughput |
| TCP bulk upload | Payload integrity, no stalls, expected throughput |
| Small interactive TCP | Low latency, no coalescing bugs |
| UDP DNS | Correct replies, correct source address |
| QUIC / HTTP3 | Stable session, no truncation |
| Many UDP destinations | Correct demultiplexing and expiry |
| Reconnect | New session works; old state is released |
| Half-close | Peer receives the complete response |
| Idle connection | Bounded resource use; no leak |
| Unauthenticated TLS probe | Forwarded to the cover, plausible behavior |
| Wrong short ID / SNI | Treated as unauthenticated; no crash |
| Replay / malformed frame | Rejected; no panic or unbounded allocation |
| Concurrent clients | No cross-session data leakage |
| Full TUN route-all | All client traffic uses the tunnel; DNS, QUIC, and IPv6 work |
| IPv6 destination | VLESS/XUDP address parsing and freedom dialing work |

## Wire behaviors to preserve

- TLS 1.3 ClientHello parsing and REALITY authentication.
- Cover SNI, certificate, TLS 1.3/PQ group, and cipher behavior for
  unauthenticated peers. Byte-identical extension order and encrypted-flight
  size are **not** required.
- Vision padding rules in both directions.
- VLESS response header and addons.
- XUDP frame layout, session IDs, status codes, and expiry.
- Error handling that does not reveal whether authentication succeeded.

## Deliberate differences

- Configuration is TOML, not Xray JSON. Existing Xray configs are not imported.
- Only the production profile above is implemented. Unsupported options fail
  at startup with a clear message.
- An absent or explicitly empty VLESS flow is accepted; unknown non-empty flow
  values are rejected instead of being silently treated as unframed TCP.
- Unauthenticated connections are capped separately (256 pre-auth slots on the
  production config, 5 s ClientHello deadline) and authenticated connections
  use the configured `max_connections` budget. Legacy VLESS UDP/packetaddr has
  a separate 64-stream cap; XUDP has a process-wide 256-session cap and a 60 s
  idle expiry.
- A bare TCP FIN without `close_notify` is treated as a half-close by the
  relay; the opposite direction may still finish.
- No statistics API or hot reload in the first release.

## Evidence

Every compatibility claim must name the test or the source reference that
supports it. Behavior that is not covered by a test is not considered
compatible.

- XUDP: `crates/beam-core/src/xudp` unit tests and the full-TUN
  `packet_encoding: xudp` arm.
- Legacy VLESS UDP: `crates/beam-core/src/udp/legacy.rs` unit tests and
  `tests/tun/run.sh --udp-mode legacy`.
- packetaddr: the same unit tests plus
  `tests/tun/run.sh --udp-mode packetaddr`; the magic FQDN and per-datagram
  address layout match sing-vmess v0.2.8 (`packetaddr/packetaddr.go`,
  `packetaddr/conn.go`) and sing-box v1.14.3 (`protocol/vless/outbound.go`,
  `protocol/vless/inbound.go`).
