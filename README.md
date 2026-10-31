# beam

A single-user VLESS + REALITY + Vision + XUDP server in Rust, intended to
replace stock Xray on one small Linux VPS. This is the canonical repository
note; the separate open stress findings live in
[`STRESS-FINDINGS.md`](STRESS-FINDINGS.md) until they are fixed and re-tested.

## Status

Implemented, tested, and deployed. The current production build was verified
on 2026-10-30 21:51 UTC:

| Item | Value |
|---|---|
| Binary | `/usr/local/bin/beam` |
| SHA-256 | `a41facef1a3cfad79dfbddfaca1a2cbe1a2a6121216d3aed852fde71d39a6b49` |
| Version | `0.1.0 (b4d93821950e)` |
| Service | `beam.service`, active, `NRestarts=0` |
| Listener | `0.0.0.0:443` |
| Live limits | 1024 authenticated connections, 1024 UDP destinations, 1024 XUDP sessions, 128 KiB UDP receive buffer, 10 s handshake |
| Verification | HTTPS IPv4/IPv6 200, cover certificate valid, local TUN path 200 |

The deployed binary is code-identical to build `1007354…`; `b4d9382` only
refreshes the embedded commit identity. The full-TUN matrix last passed 8/8 in
`xudp`, `packetaddr`, and `legacy` modes. `STRESS-FINDINGS.md` records one
lab-reproduced XUDP lifecycle defect and several code-confirmed backpressure
and timeout risks that are **not yet fixed**. Do not describe the release as
fully accepted until those findings and the open acceptance gates are resolved.

## Scope

The target profile is:

- one user, one inbound, Linux x86_64;
- VLESS over TCP/443;
- REALITY with a `whatsapp.net` cover;
- `xtls-rprx-vision`;
- XUDP plus legacy VLESS UDP and packetaddr;
- Direct (`freedom`) outbound;
- a full-TUN client such as sing-box, Hiddify, or stock Xray.

TCP, UDP, DNS, QUIC/HTTP/3, IPv4, and IPv6 must work through the tunnel.
ICMP is not carried, matching stock Xray. The server must remain compatible
with stock clients using the same UUID, public key, short ID, SNI, and flow.

Out of scope for v1: client/TUN implementation, multi-user/panels/accounting,
VMess/Trojan/Shadowsocks/SOCKS/HTTP, WebSocket/gRPC/H2/QUIC transports, H2MUX,
routing/DNS/chaining, stats APIs/Prometheus, hot reload, non-Linux-x86_64,
and byte-for-byte TLS cover parity.

## Build

The toolchain is pinned by `rust-toolchain.toml`. On this development host,
`scripts/dev-env.sh` adds portable CMake/Ninja/compiler helpers when present;
on a normal Linux build host it falls back to system tools.

```bash
source scripts/dev-env.sh
cargo build --release
cargo run -- --check -c config.example.toml
```

`config.example.toml` contains a sample key and nil UUID. Replace every value
before deployment. The real config must be mode `0600` locally and
root:beam `0640` on the server.

### Verification before commit

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Parser changes also require the relevant fuzz target. Hot-path changes require
a benchmark comparison. The current workspace has 336 tests: 306 `beam-core`,
2 TLS adapter, 2 stock-ClientHello fixture, and 26 `beam-sys`.

## Repository layout

```text
crates/beam       CLI, config loading, logging, signals, listener lifecycle
crates/beam-core  protocol/server logic; forbid(unsafe)
crates/beam-sys   splice/socket/eventfd primitives; sole unsafe crate
tests/tun         full-TUN interoperability harness and target services
bench             stock-Xray vs beam benchmark harness and no-TUN smoke
fuzz              separate cargo-fuzz workspace
deploy            package/bootstrap, systemd, nftables, client rotation
scripts           cover-parity and local build helpers
```

All production code, tests, deploy assets, and notes are in this repository.
There are no separate build worktrees. The optional QEMU stress lab used during
development is external test infrastructure and is not part of the release
tree.

## Architecture

```text
client --TCP/443--> listener --> REALITY handler
                                  | authenticated: VLESS -> Vision/XUDP -> freedom
                                  | unauthenticated: byte-exact cover forward
```

- `beam` owns process lifecycle, CLI, config, logging, signals, and the
  listener. It contains no protocol implementation.
- `beam-core` contains TLS/ClientHello handling, REALITY, VLESS, Vision, XUDP,
  legacy UDP, packetaddr, relay logic, config validation, and metrics.
- `beam-sys` contains the only `unsafe` code: `splice`, fd helpers, socket
  options, and eventfd. Every unsafe block needs a `// SAFETY:` invariant.

The TLS path pre-reads and authenticates ClientHello, then uses rustls through
a record-bounded `TlsStream` that owns the TLS record boundary. This preserves
unread bytes when Vision switches one direction to raw Direct. TCP uses a
blocking `splice(2)` fast path with a bounded async-copy fallback. XUDP uses
one outbound UDP socket per session, a per-mux session table, and a
process-wide session limiter. Config is strict TOML: unknown fields are errors,
and `--check` validates both scalar limits and derived XUDP/TLS settings before
bind.

## Protocol invariants

### REALITY

- REALITY uses the TLS 1.3 ClientHello `legacy_session_id` as a 32-byte
  envelope: client ciphertext then server tag.
- The plaintext carries client version, timestamp, and 8-byte short ID. The
  key is X25519 + HKDF-SHA256 with info `REALITY`; the payload is AES-256-GCM
  with the ClientHello as associated data. No HMAC is in the envelope; the
  temporary certificate is authenticated separately with HMAC-SHA512.
- Prefer a standalone X25519 key share; otherwise use the final 32 bytes of
  an exact 1216-byte `X25519MLKEM768` share. Reject low-order/non-contributory
  X25519 shares.
- Check SNI exactly, then the share, AEAD, client version range, optional
  timestamp skew, and constant-time short-ID membership. Never expose an
  authentication oracle: unauthenticated or failed probes go to the cover.
- Short IDs are validated and decoded at startup into fixed 8-byte values;
  comparisons are constant-time.
- Stock has no replay cache. beam checks a bounded replay cache at
  classification but inserts only after TLS Finished. The cache is
  approximately 60 seconds / 4096 entries; outside that window, Finished
  verification still blocks a replay, but a replayed ClientHello can occupy an
  authenticated slot until handshake timeout. Timestamp checking is currently
  disabled by policy.
- Unauthenticated traffic is relayed to the configured cover. Never send a
  TLS alert or a synthetic response on authentication failure.

### VLESS and Vision

- VLESS request: version, 16-byte UUID, addons, command, optional port and
  target address. Commands: TCP, UDP, Mux, Rvs. The response is always
  `00 00`; unknown or malformed commands are rejected.
- Vision first block per direction carries the raw 16-byte UUID. Blocks carry
  command, content length, padding length, content, and zero padding. Padding
  follows the stock long/short rules, is clamped to the frame bound, and is
  symmetric in both directions.
- Direct is enabled only for a complete inner TLS application-data record
  after the expected TLS 1.3 ServerHello: TLS detected and the stock enable
  condition satisfied. The last padded block is Direct; subsequent raw reads
  and writes bypass Vision framing for that direction only.
- Direct handoff preserves bytes already read ahead and same-record leftovers;
  write pending outer TLS ciphertext before raw data. Each direction can be
  raw independently. There is no outer `close_notify` after Direct; FIN ends
  one direction.
- Unknown Vision commands, overlong lengths, and malformed state transitions
  are rejected rather than passed through and desynchronized.

### XUDP, legacy UDP, and packetaddr

- XUDP is carried in VLESS Mux frames: metadata length, stream ID, status,
  option, optional destination, optional GlobalID, payload length, payload.
  Statuses are New, Keep, End, KeepAlive; options are Data and Error.
- Clients generally send New/Keep and close the flow with TCP FIN; do not
  require an End. Keep frames may carry a new destination. Replies are Keep
  with Data, plus End on closure (Error only when relay failed). An unknown
  stream ID gets a clean End and is discarded.
- Accept zero GlobalID and per-frame destinations from sing-box. A nonzero
  GlobalID may reattach a retained socket only within the same mux and user;
  never use GlobalID as identity or policy.
- XUDP datagrams are capped at 7526 bytes inside an 8192-byte frame; empty or
  oversize datagrams are dropped. Legacy UDP is capped at 8190 bytes.
  packetaddr uses the magic `sp.packet-addr.v2fly.arpa` destination and
  carries an inner address per datagram.
- Session sockets are currently unconnected and accept any reply source.
  This is intentional stock compatibility, but it is also the root of the
  reproduced idle-pinning finding in `STRESS-FINDINGS.md`: only touch a
  session after accepting a valid reply, or validate/connect the source.
- Live XUDP limits are 1024 process-wide sessions and 128 KiB per socket
  receive buffer; a mux holds at most half the global active slots. XUDP idle
  expiry is at most 60 seconds even when the TCP relay idle timeout is 300
  seconds.

### TLS stack, cover, and MTU

- TLS is rustls 0.23 + aws-lc-rs with the `prefer-post-quantum` feature.
  Initialize `aws_lc_rs::default_provider()` at startup. Do not replace it
  with BoringSSL or a custom TLS implementation for v1.
- Cover parity is **SNI-level**, decided 2026-10-29: matching SNI, certificate,
  TLS 1.3/PQ group, cipher behavior, and normal unauthenticated forwarding is
  enough. Plaintext extension order and encrypted-flight size may differ; do
  not gate a deploy on them.
- The cover is `whatsapp.net:443`, PQ-capable (`X25519MLKEM768`), TLS 1.3,
  AES-128-GCM, ALPN `h2`. Authenticated connections do not dial the cover.
- Set `TCP_MAXSEG=1400` before connecting every target and cover socket. This
  creates an effective advertised MSS around 1388 and avoids 1460-byte PMTU
  black holes on some Meta/Vercel paths. Host TCP traffic is not clamped.
- Keep `net.ipv4.tcp_mtu_probing=0` unless a measured PMTU failure justifies a
  change. The production client uses TUN MTU 1500 and `stack: system`; 1400
  loses Google/YouTube H3, and gVisor stalls large H3 bodies.

## Configuration and limits

Strict TOML sections: `[server]`, `[user]`, `[reality]`, `[log]`, `[limits]`.
Secrets stay outside git. The live profile uses:

| Setting | Default | Production |
|---|---:|---:|
| `max_connections` | 1024 | 1024 |
| `max_preauth_per_ip` | 128 | 128 |
| `max_udp_destinations` | 2048 | **1024** |
| `max_xudp_sessions` | 256 | **1024** |
| `xudp_recv_buffer_bytes` | 128 KiB | 128 KiB |
| `listen_backlog` | 1024 | 1024 |
| `shutdown_drain_ms` | 2000 | 2000 |
| `handshake_timeout_ms` | example 60000 | **10000** |
| `idle_timeout_ms` | 300000 | 300000 |

Other fixed admission behavior: 256 pre-auth handshake slots process-wide, a
5-second ClientHello intake deadline, 32 cover relays process-wide with 8 per
source, and a 30-second cover idle timeout. `max_connections=1024` is admission
headroom, not bulk capacity: the blocking pool has 120 splice permits (about
60 fully spliced Vision pairs) and falls back to async copy above that.

`--version` embeds the git commit. `--check` validates derived runtime
configuration. Startup logs include version and configured limits. `SIGHUP`
is logged and ignored; restart the service to reload. `SIGTERM` stops accepting,
drains for at most `shutdown_drain_ms`, then bounds runtime shutdown.

## Operations

Set `SSH_KEY` and `SERVER` in the shell before using the examples below. For a
first-time host, install Debian 13 with key-only `demir` access and
passwordless sudo; test the `deploy/` nftables/SSH/resolver files before
enabling them, keeping the provider console available. The local client
rotation helper is `deploy/update-client.py` (TUN `system`, MTU 1500); the
tray polkit/autostart files are in `deploy/`. Never commit or paste secrets.

### Daily checks

```bash
ssh -i "$SSH_KEY" "$SERVER" \
  'systemctl status --no-pager -l beam; systemctl is-failed beam; systemctl show beam -p NRestarts --value'
ssh -i "$SSH_KEY" "$SERVER" \
  'sudo -n ss -ltnp; sudo -n journalctl -u beam --since "24 hours ago" -p warning --no-pager'
ssh -i "$SSH_KEY" "$SERVER" \
  'pid=$(systemctl show beam -p MainPID --value); ps -o pid,rss,vsz,nlwp,etime,comm -p "$pid"; printf "fds="; sudo -n ls "/proc/$pid/fd" | wc -l'
ssh -i "$SSH_KEY" "$SERVER" \
  'cat /sys/fs/cgroup/system.slice/beam.service/memory.current; cat /sys/fs/cgroup/system.slice/beam.service/memory.peak'
```

Expect active/running, enabled, `NRestarts=0`, no unexpected listeners, and a
quiet warn-level journal. `runtime pressure counters increased` is actionable;
inspect its deltas. A healthy idle process is roughly 2 threads and 10 fds;
RSS is normally under 20 MiB but can retain an allocator plateau after a large
burst. Warn at RSS >128 MiB or monotonic growth, fds >256, threads >128, or
sustained swap.

### Deploy

```bash
source scripts/dev-env.sh
BUNDLE=$(bash deploy/package.sh | sed -n 's/^bundle=//p')
scp -i "$SSH_KEY" "$BUNDLE" "$SERVER:/tmp/beam-deploy.tar.gz"
ssh -i "$SSH_KEY" "$SERVER" 'chmod 600 /tmp/beam-deploy.tar.gz'
ssh -i "$SSH_KEY" "$SERVER" \
  'rm -rf /tmp/beam-deploy && mkdir -p /tmp/beam-deploy && tar -xzf /tmp/beam-deploy.tar.gz -C /tmp/beam-deploy && sudo -n bash /tmp/beam-deploy/bootstrap.sh'
ssh -i "$SSH_KEY" "$SERVER" 'rm -rf /tmp/beam-deploy /tmp/beam-deploy.tar.gz'
```

Use `BEAM_KEEP_CONFIG=1` to preserve the live `/etc/beam/config.toml` while
installing the new binary/unit. The package script validates local secrets;
bootstrap validates the installed config, backs up replaced files, prunes each
backup set to five, and polls beam's own 443 listener. Compare SHA-256 of the
local binary with `/usr/local/bin/beam`. Then verify:

```bash
curl -4 -sS -o /dev/null -w '%{http_code}\n' https://example.com/
curl -6 -sS -o /dev/null -w '%{http_code}\n' https://example.com/
curl --http3-only -sS -o /dev/null -w '%{http_code}\n' https://cloudflare-quic.com/
dig +short example.com
```

For cover verification, request `https://whatsapp.net` through the server and
confirm the public `*.whatsapp.net` certificate. Run the local TUN matrix in
all three UDP modes after client or server changes.

### Rollback and emergency

Backups are timestamped beside each installed file:

```text
/usr/local/bin/beam.bak-<stamp>
/etc/beam/config.toml.bak-<stamp>
/etc/systemd/system/beam.service.bak-<stamp>
/etc/sysctl.d/99-beam.conf.bak-<stamp>
/etc/sysctl.d/99-beam-conntrack.conf.bak-<stamp>
```

Stop beam, install all required backups, validate config, run `sysctl
--system`, daemon-reload/reset-failed, and start. Rollback is not atomic and
there is no automatic stock-Xray fallback. Keep provider console access before
changing SSH or firewall state. For a crash loop, read the unit and journal
and run `beam --check` as the `beam` user. For a full disk, inspect and vacuum
the journal.

### Identity rotation

The identity is the X25519 keypair, short ID, UUID, and SNI/cover. It exists
only in local/server secret files; there is no escrow. Generate a new keypair
with a trusted X25519 tool, a new short ID with `secrets.token_hex(8)`, and a
new UUID; rotate all three together. Update client and server, deploy, verify,
then destroy the old copies. Never commit or paste secrets.

### Host hardening

The live host uses Debian 13 with nftables default-deny (22/443, established,
ICMP/ICMPv6, loopback), SSH key-only `demir`, root/debian disabled, BBR + fq,
conntrack 65536, resolver DoT/DNSSEC, and systemd sandboxing with
`MemoryHigh=512M`, `MemoryMax=768M`, `MemorySwapMax=512M`, `LimitNOFILE=65536`,
and only `CAP_NET_BIND_SERVICE`. Test nftables before enabling. SSH, firewall,
and resolver changes are deliberately not applied by `bootstrap.sh`.

## Testing and benchmarking

### Full TUN

```bash
source scripts/dev-env.sh
bash -n tests/tun/run.sh
bash tests/tun/run.sh
bash tests/tun/run.sh --udp-mode packetaddr
bash tests/tun/run.sh --udp-mode legacy
```

Each mode must report 8/8 PASS: TCP HTTP v4/v6, UDP echo v4/v6, DNS v4/v6,
QUIC/H3, and HTTPS through Vision Direct. `BLOCKED` is not pass. If
`/dev/net/tun` is unavailable, all rows are BLOCKED and the script exits 0.
This harness is local and does not touch production.

### Fuzz

The fuzz workspace is separate so fuzz dependencies never enter release builds:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz build
cargo +nightly fuzz run client_hello -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run reality_auth -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run vless -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run vision -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run xudp -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run legacy_udp -- -max_total_time=60 -timeout=10
cargo +nightly fuzz run config -- -max_total_time=60 -timeout=10
```

The GitHub fuzz workflow is manual-only. Parser changes require a local run.
The multi-record ClientHello assembler still needs final fuzz coverage.

### Performance

```bash
source scripts/dev-env.sh
bash bench/run.sh --reps 3            # full stock-vs-beam run
bash bench/run.sh --quick --reps 1    # smoke
bash bench/run.sh --arms beam         # one arm
bash bench/no-tun.sh                  # server-capacity smoke
bash bench/churn.sh                   # connection-churn smoke
```

Results are written under `bench/results/<timestamp>/`; raw logs/configs and
large artifacts are gitignored. Full-TUN bulk is client-capped on this host
(about 0.98-1.00x), so it is not a headline result. The balanced no-TUN
capacity result is about 1.46x stock; the final smoke was about 1.40x. Treat
older n=3 claims as provisional and require n>=10 with matched CPU accounting
for any new headline.

The local TUN matrix and cover diagnostic are:

```bash
scripts/cover-parity.sh
```

Cover flight differences are diagnostic only by the SNI-level decision.

## Decisions

- **Rust 2024**, pinned toolchain, safe Rust plus an isolated `beam-sys` unsafe
  layer. Go would share Xray's runtime limits; C++ is not maintainable by
  agents.
- **Strict TOML**, no Xray JSON import. Unknown fields fail before bind.
- **rustls + aws-lc-rs PQ**, no custom TLS or BoringSSL server for v1.
- **Relative performance acceptance**: aggregate better than stock, no
  condition regressions beyond noise, stable soak/churn, and no corruption.
  Numeric multipliers are goals, not release blockers.
- **SNI-level cover parity** is accepted; byte-for-byte flight parity is not
  required.
- **One user, one inbound, no hot reload/stats** keeps the attack surface and
  resource model bounded.

## Known gaps

- `STRESS-FINDINGS.md` contains the unfixed XUDP idle-pinning defect, mux
  head-of-line blocking, close/reserve races, timeout-validation gap, and
  lower-risk items. Do not fold it into this note until each item is fixed and
  re-verified.
- A clean 24-hour mixed soak, privileged syscall/wakeup/splice gates, cgroup
  socket-memory/OOM sampling, and a final fuzz run of the multi-record
  ClientHello assembler remain open release-acceptance items.
- Fully framed HTTPS uploads stay on the async path; early Direct acceleration
  requires the client to send Direct before the body (for example
  `Expect: 100-continue`). This is a performance gap, not a correctness defect.
- Large H3 bodies can show rare completion outliers through some client/TUN
  combinations. At MTU 1500 those are consistent with QUIC PTO/TCP
  head-of-line behavior, not server packet drops.
- No per-IP authenticated connection cap, no stats API, no hot reload, and no
  automatic stock fallback. Recover with the timestamped backups.
