# Test plan

## Levels

### Unit tests

Pure functions and state machines:

- ClientHello parser and bounds checks.
- REALITY authentication result handling.
- VLESS header encode/decode.
- Vision padding and mode transitions.
- XUDP frame encode/decode.
- Config parsing and validation.
- Error mapping and timeout policy.

### Property and fuzz tests

Every parser that consumes untrusted bytes gets a fuzz target:

- TLS ClientHello.
- TLS record framing.
- VLESS request and addons.
- Vision padding stream.
- XUDP frames.
- TOML configuration.

The invariant is: no panic, no unbounded allocation, no out-of-bounds read, and
either a valid value or a typed error.

Implemented targets live in the separate `fuzz/` workspace:
`client_hello`, `reality_auth`, `vless`, `vision`, `xudp`, `legacy_udp`, and
`config`. The `legacy_udp` target uses a feature-gated pure parser helper and
opens no sockets. The scheduled `fuzz` workflow runs a short budget nightly;
local parser changes should use a longer budget.

### Integration tests

Loopback-only fixtures:

- Local TLS 1.3 cover server.
- Synthetic REALITY client hello.
- Real VLESS request and response.
- TCP echo and bulk transfer.
- UDP echo, DNS-shaped payloads, and many destinations.
- Half-close, reset, idle, and reconnect cases.

### Local stock baseline

A working stock Xray v26.3.27 baseline has been validated locally:

- Server: VLESS + REALITY + Vision on `127.0.0.1:18443`, cover
  `whatsapp.net:443`.
- Client: SOCKS5 on `127.0.0.1:11080`, REALITY outbound with
  `xtls-rprx-vision`.
- Target: Python `http.server` on `127.0.0.1:18080`.
- Probe:
  `curl --socks5-hostname 127.0.0.1:11080 http://127.0.0.1:18080/index.txt`.

Generate a fresh X25519 keypair with `xray x25519` for every run. Never commit
the generated server config or keys; keep them under `/tmp`.

### Interoperability tests

Run the real clients from `docs/01-compatibility.md`:

- Stock Xray v26.3.27.
- sing-box v1.14.3.
- Hiddify v4.1.1.

Each client uses the unchanged production profile. Tests cover TCP, UDP, QUIC,
DNS, small packets, and reconnect.

### Full TUN

Run Hiddify or sing-box in TUN mode in a network namespace and route all
client traffic through the server:

- TCP bulk and interactive traffic.
- UDP DNS and QUIC/HTTP3.
- IPv4 and IPv6 destinations.
- Reconnect while a transfer is active.
- TUN MTU 1400 (production value); verify no fragmentation or truncation.
  Also run a 1500-byte control to separate client-stack behavior from the
  production MTU.

The client configuration is unchanged from the stock deployment. This test is
a release blocker for replacing the production server.

### Probe resistance tests

- Unauthenticated TLS client is forwarded to the cover.
- Wrong short ID, wrong SNI, empty session ID, and replayed hello are handled as
  unauthenticated traffic.
- Silent cover does not produce a fabricated response.
- Error messages and timing do not reveal authentication success.

### Soak and churn

- 24 hours of mixed TCP/UDP traffic.
- 10,000 connection open/close cycles.
- Memory, file descriptors, threads, and pipe descriptors sampled over time.
- No monotonic growth after warm-up.

### Deployment tests

- Static binary starts on Debian 13.
- Invalid config fails before binding.
- Systemd restart and rollback.
- File permissions and secret handling.

## CI gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --release
```

Fuzz and soak runs are scheduled separately; they are not required on every
commit, but a release candidate cannot ship without them.

## Test data rules

- Generate certificates and keys in temporary directories.
- Never use production UUIDs, private keys, or cover credentials.
- Keep captures and logs out of the repository.
- Tests must pass without root, except the explicitly marked syscall tests.
