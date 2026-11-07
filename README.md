# beam

A single-user VLESS + REALITY + Vision + XUDP server in Rust, intended to
replace stock Xray on one small Linux VPS. This is the canonical repository
note; the separate open stress findings live in
[`STRESS-FINDINGS.md`](STRESS-FINDINGS.md) until they are fixed and re-tested.

## Status

Implemented, tested, and deployed. The current production build was verified
on 2026-11-07 22:41 UTC:

| Item | Value |
|---|---|
| Binary | `/usr/local/bin/beam` |
| SHA-256 | `6c0b13df7e9b310e33c920a82ea5d715cb6def879200cf401834a3d2441325af` |
| Version | `0.1.0 (d273200d578a)` |
| Service | `beam.service`, active, `NRestarts=0` |
| Listener | `0.0.0.0:443` |
| Live limits | 1024 authenticated connections, 1024 UDP destinations, 1024 XUDP sessions, 128 KiB UDP receive buffer, 10 s handshake, `TasksMax=4096` |
| Host network | BBR + fq, conntrack 65536, 600 s UDP retention |
| Verification | Hash-pinned verifier PASS with tunnel-egress proof; 10-minute soak 60/60 HTTP 200 with threads plateaued at 111, RSS 17 MB and `NRestarts=0`; client DNS/HTTP 200; lab 11/11 clean and loss |

The deployed binary includes the XUDP junk-reply idle-pinning fix (`2163c0a`),
the mux-wide resolution/send-stall fix (`e0ca0bc`), the 2026-11-03
handshake/legacy-UDP/End-enqueue hardening, the bounded in-flight replay
reservation (`647623b`), and the 2026-11-06 hardening batch: XUDP socket-budget
validation, control-frame idle pinning, Vision empty-block rejection, replay
first-wins with a 300-second timestamp/cache window, cancellable cover relays,
bounded legacy UDP, parallel resolver lookups, and the descriptor budget check.
The process-wide resolver changes were reverted after intermittent client DNS
failures (`64d9856`); production runs `d273200`, which includes that revert.
Remaining
code-confirmed backpressure and lower-risk resource items in
`STRESS-FINDINGS.md` are still tracked; the full release gates remain the
24 h soak, privileged syscall/wakeup/splice measurements, cgroup OOM sampling,
and final fuzzing.

## Where to look

| Need | Read |
|---|---|
| Current production state | [Status](#status), [Operations](#operations) |
| Protocol behavior and invariants | [Protocol invariants](#protocol-invariants), [Decisions](#decisions) |
| Configuration | [Configuration and limits](#configuration-and-limits), [`config.example.toml`](config.example.toml) |
| Client setup | [Windows tray launcher](#windows-tray-launcher), [Linux tray and DNS switch](#linux-tray-and-dns-switch), [Mobile profile](#mobile-profile) |
| Tests and performance | [Testing and benchmarking](#testing-and-benchmarking), [One-command checks](#one-command-checks), `tests/tun`, `fuzz`, `bench` |
| Open risks | [Known gaps](#known-gaps), [`STRESS-FINDINGS.md`](STRESS-FINDINGS.md) |
| Agent rules | [`AGENTS.md`](AGENTS.md) |

## Scope

The target profile is:

- one user, one inbound, Linux x86_64;
- VLESS over TCP/443;
- REALITY with a `whatsapp.net` cover;
- `xtls-rprx-vision`;
- XUDP plus legacy VLESS UDP and packetaddr;
- Direct (`freedom`) outbound;
- a full-TUN client such as sing-box, Hiddify, or stock Xray.

The server carries TCP, UDP, DNS, QUIC/HTTP3, IPv4, and IPv6 through the
tunnel. The recommended stock-client profiles intentionally reject public
UDP/443 before sniffing so H3/QUIC falls back immediately to HTTP/2; the
server-side XUDP/legacy paths remain available for profiles that explicitly
allow H3. ICMP is not carried, matching stock Xray. The server must remain
compatible with stock clients using the same UUID, public key, short ID, SNI,
and flow.

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
a benchmark comparison. The current workspace has 359 tests: 329 `beam-core`,
2 TLS adapter, 2 stock-ClientHello fixture, and 26 `beam-sys`.

### One-command checks

```bash
make doctor          # required build tools, optional benchmark tools, local paths
make verify          # fmt + clippy + test
make smoke           # release build, example config check, shell syntax
make lab-check       # external three-VM lab, 11/11, then teardown
LAB_PROFILE=loss make lab-check   # same, with 30 ms +/- 8 ms and 0.5% loss
make acceptance      # verify + smoke + lab-check
```

`lab-check` builds the current source, installs the binary on the lab server,
restarts it, and reruns the matrix before the optional impaired run; the initial
boot check uses whatever binary the lab already has. Lab output is written under
`~/.cache/beam/lab-results/<timestamp>/`. Set `KEEP_LAB=1` to leave the VMs
running or `LAB_SKIP_BUILD=1` to reuse the installed lab binary. The lab path
defaults to `/home/demir/pi/beam-lab` and must match the lab scripts.

### Default stock-client QUIC policy

All recommended profiles use this pre-match rule and ordering:

```json
[
  {"ip_is_private": true, "outbound": "direct"},
  {"action": "reject", "network": "udp", "port": [443],
   "method": "default", "no_drop": true},
  {"action": "sniff", "sniffer": ["http", "tls", "quic", "dns"],
   "timeout": "300ms"},
  {"protocol": "dns", "action": "hijack-dns"}
]
```

The private rule comes first so LAN destinations remain direct. The public
UDP/443 reject is before sniff so sing-box synthesizes ICMP port unreachable
instead of silently dropping; `no_drop` prevents burst protection from
degrading later requests to timeouts. Public HTTP/3 therefore fails fast and
the application uses HTTP/2 over the TCP/REALITY path. This is the default for
Linux, Android, and the embedded Windows profile. A profile that needs H3 must
explicitly opt in and accepts the XUDP/TCP head-of-line risk.

## Windows tray launcher

`clients/windows-tray` is an optional native Win32 tray launcher for the
official `sing-box.exe`. It has no settings UI and does not rewrite the
configuration. TUN, DNS, routing, and QUIC/H3 behavior come only from
`config.json`; the tray offers Start, Stop, Restart, Open config, Open log, and
Exit.

Build with a MinGW-w64 toolchain:

```bash
cd clients/windows-tray
CC=x86_64-w64-mingw32-clang WINDRES=x86_64-w64-mingw32-windres ./build.sh
```

The supported Windows install is the one-file installer below. Build the tray
only for development; do not assemble an elevated install by hand in a
user-writable directory. The tray has a `requireAdministrator` manifest because
the TUN inbound needs elevation and starts sing-box automatically on launch, so
TUN comes up from the config without a GUI toggle.

### One-file installer

`clients/windows-tray/beam-install.ps1` is a locally generated one-file
installer containing the tray executable and the real profile. Run it from an
elevated Windows PowerShell. It downloads the official sing-box 1.14.4 Windows
archive, verifies the archive and individual core files, installs to
`%ProgramFiles%\beam`, stages and checks `config.json`, sets Windows
`strict_route` to `true`, protects the directory/config/log ACLs, and creates a
desktop shortcut. The embedded profile uses the same route shape as the Linux
client: private destinations direct, public UDP/443 rejected, port-53 DNS
hijacked to DoH, and no HTTP/TLS/QUIC sniffing. The installer normalizes the decoded route rules again before
staging, so an older embedded blob cannot reintroduce full sniffing or drop the
UDP/443 rule. Windows therefore falls back to HTTP/2 without waiting for
XUDP/TCP retransmission. The config is restricted to Administrators and SYSTEM.
It is ignored by Git because it embeds real credentials.

Reinstall is deliberately destructive: it stops the old tray/core, unregisters
the old logon task, removes the old Program Files and LocalAppData installs,
config/log/backups, desktop/startup shortcuts, stale staging directories, and
the downloaded core cache. The replacement install contains only the new
binary, core files, config, and log; no old credentials or leftovers remain.

```powershell
# Start Windows PowerShell with "Run as administrator", then:
powershell -NoProfile -ExecutionPolicy Bypass -File .\beam-install.ps1
# -Startup registers an unlimited highest-privilege logon task
# -NoLaunch installs only
# -ZipPath uses an already-downloaded official archive
```

The one-file installer has been run successfully on Windows. The hardened
revision, tray menu, Stop/Restart/Exit, Explorer restart, reinstall, and
scheduled-task paths still need a Windows smoke test.

## Linux tray and DNS switch

`clients/linux-tray` is a minimal GTK/AppIndicator tray plus a small setuid
root helper. It has one action: Connect/Disconnect. There is no settings window
and no autostart entry.

- Disconnected: systemd-resolved uses the existing local ctrld resolver at
  `127.0.0.1:5300`, which forwards to Control D.
- Connected: `beam-client.service` starts and its `ExecStartPost` calls the
  helper's `dns-on`. The helper waits for `sbtun0`, moves the ctrld resolved
  drop-in aside, writes `99-beam.conf` with `DNS=1.1.1.1`, and reloads
  systemd-resolved. That DNS traffic enters the TUN and the profile's Control D
  DoH configuration handles it.
- The Linux profile sets `auto_redirect: true` on the TUN. With only
  `auto_route`, TCP through the TUN timed out; the nftables redirect path fixes
  TCP and is required on this host. Requires nftables and a root client service.
- The Linux profile also rejects UDP/443 before sniffing with
  `action: reject`, `method: default`, and `no_drop: true`. sing-box emits ICMP
  port unreachable immediately, so browsers and curl fall back to HTTP/2
  without waiting for the XUDP/TCP retransmission timeout. H3 is intentionally
  unavailable on this stock-client profile; the TCP/REALITY cover is unchanged.
- `ExecStopPost` calls `dns-off` and restores ctrld. `Restart=no` avoids a
  restart cycle where the TUN comes back without the matching DNS state.
- `beam-dns-reset.service` is enabled at boot and only runs when the beam DNS
  drop-in is present, restoring ctrld after an unclean shutdown.

Build and install:

```bash
cd clients/linux-tray
./build.sh
sudo ./install.sh
/usr/local/bin/beam-tray
```

On kernels that expose `tcp_bbr`, the installer enables BBR and the `fq`
default qdisc through `/etc/sysctl.d/99-beam-client-bbr.conf`. This is
sender-side tuning: it improves TCP uploads on lossy/high-RTT paths, while
downloads still follow the remote server's congestion control. The setting is
applied immediately; `default_qdisc` affects interfaces created afterwards,
and BBR falls back to internal per-socket pacing on an existing non-fq qdisc.
The installer warns and continues if the kernel has no BBR. No buffer or
`tcp_notsent_lowat` changes are installed. Remove
`/etc/sysctl.d/99-beam-client-bbr.conf` and `/etc/modules-load.d/beam-bbr.conf`
to revert.

The installer no longer assumes a profile in `/tmp`. If `CONFIG_SRC` is unset
and `/etc/beam/config.json` exists, a reinstall reuses it as input. A fresh
install must set `CONFIG_SRC=/path/to/config.json`; the sanitized structure is
in `clients/linux-tray/config.example.json`. The installer requires `python3`,
normalizes the canonical QUIC reject policy, and validates the normalized
profile before stopping the running service. An older reused profile therefore
cannot silently keep a missing reject rule.

The installer verifies the official Linux core files by SHA-256 before
installing them. The service is installed but not enabled or started. DNS
changes use `systemctl reload systemd-resolved`, so rapid tray toggles do not
restart the resolver or hit its start limit. The tray also applies a three
second cooldown after each helper action. The helper only accepts fixed
commands, checks that its real user matches `/etc/beam/allowed-user`, clears its
environment, redirects stdio, closes inherited descriptors, and executes
absolute `systemctl` paths. The TUN profile excludes the VLESS server and the
Control D IPv4 anycast addresses from the TUN route, and uses
`auto_redirect: true` for TCP.

The helper is local, unsigned, and setuid root; treat the repository and
installer as trusted input. SELinux relabeling is attempted on Fedora, but the
service/helper still need a real TUN/DNS smoke test.

## Mobile profile

The single canonical Android profile is the gitignored, mode-0600
`mobile-singbox.json` in the repository root. Do not commit it; it contains the
live UUID, REALITY keys, and Control D DoH path. `~/.config/beam/android-singbox.json`
is only a symlink to that file.

The profile keeps Android's TUN on `stack: system`, MTU 1500, `auto_route` on,
and no generic mux. Like the Linux profile, it rejects UDP/443 before sniffing
with `method: default` and `no_drop: true`, so H3/QUIC fails fast and the client
falls back to HTTP/2 instead of waiting for the XUDP/TCP retransmission timeout.
H3 is therefore intentionally unavailable in this recommended profile; the
TCP/REALITY/WhatsApp SNI path is unchanged.

## Repository layout

```text
crates/beam       CLI, config loading, logging, signals, listener lifecycle
crates/beam-core  protocol/server logic; forbid(unsafe)
crates/beam-sys   splice/socket/eventfd primitives; sole unsafe crate
tests/tun         full-TUN interoperability harness and target services
bench             stock-Xray vs beam benchmark harness and no-TUN smoke
fuzz              separate cargo-fuzz workspace
deploy            package/bootstrap, systemd, nftables, client rotation
clients/windows-tray  optional native Windows tray launcher for official sing-box
clients/linux-tray    minimal Linux tray plus root helper and DNS switch
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
- Stock has no replay cache. beam reserves in-flight handshakes before TLS and
  inserts the first Finished handshake into a bounded 300-second replay cache.
  Capacity scales with `max_connections` (64x, clamped to 4096..65536), and
  REALITY timestamps older than five minutes are rejected. Concurrent
  duplicates are first-wins: a second Finished handshake is closed rather than
  served. This bounds both the in-flight permit race and the post-cache window.
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
- Session sockets remain unconnected and accept replies from arbitrary UDP
  sources. This preserves stock XUDP/full-cone behavior (STUN, WebRTC, P2P).
  Only a valid, non-empty reply that passes size/frame/queue/byte-budget checks
  and is handed to the writer refreshes the idle clock. Zero-length, oversize,
  encoding-drop, queue-drop, and budget-drop datagrams do **not** refresh it;
  this closes the lab-reproduced junk-reply idle-pinning defect. "Valid" here
  means size/frame/admission-valid, not application-validated: a sender that
  can reach the ephemeral port with an admissible datagram can still keep the
  session active while the mux remains open. The queue and byte budgets bound
  outstanding memory, not session lifetime; this is inherent to keeping
  arbitrary-source/full-cone replies.
- Domain `New`/`Keep` frames are queued per session id while a bounded
  per-mux resolver performs DNS; the lookup owner and suffix are tracked
  separately, results carry a generation, and a newer GlobalID cancels older
  pending New frames. IP frames, queued suffixes, and rejected replies retain
  their ordering. Resolved domains are cached for 300 seconds. The resolver is
  serial per mux, pending payload has a process-wide 4 MiB budget plus bounded
  metadata, and UDP send/close waits are capped at 100 ms. This is not
  universally nonblocking: a sequence of slow domains, a congested send, or
  many close operations can still delay a mux briefly.
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

`handshake_timeout_ms` must be at least 100 and `idle_timeout_ms` at least
1000; both cap at 24 h. The authenticated TLS, VLESS, dial, response, and
non-Vision first-body stages share one absolute handshake deadline; Vision
passes its initial body into the Vision relay under `idle_timeout_ms`.

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
ssh -i "$SSH_KEY" "$SERVER" \
  'cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max'
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

For an existing host, use
`sudo env BEAM_KEEP_CONFIG=1 bash /tmp/beam-deploy/bootstrap.sh` to preserve
the live `/etc/beam/config.toml` explicitly. If `BEAM_KEEP_CONFIG` is unset,
bootstrap automatically preserves any existing `/etc/beam/config.toml`;
replacing it requires the explicit fresh-install/update override
`sudo env BEAM_KEEP_CONFIG=0 bash /tmp/beam-deploy/bootstrap.sh`. A plain
`sudo bash ...` cannot inherit an exported `BEAM_KEEP_CONFIG`, so use `env`
for both modes. The package script validates local secrets; bootstrap applies
and validates sysctls, validates the new binary as the unprivileged service
user, backs up replaced files, rolls back on a failed restart/readiness probe,
prunes each backup set to five, and polls beam's own 443 listener. Verify the
deployed state without printing config contents:

```bash
SSH_KEY="$SSH_KEY" SERVER="$SERVER" deploy/verify-production.sh
SSH_KEY="$SSH_KEY" SERVER="$SERVER" CHECK_H2=1 \
  TUN_IFACE=sbtun0 deploy/verify-production.sh
```

`CHECK_H2=1` requires the named local tunnel and fails if it is missing. It
verifies the path real traffic takes: three sequential HTTPS requests, then a
held client connection that must produce a new established socket owned by beam
on the server for the same destination (`CHECK_H2_DST`, default `1.1.1.1:443`).
The second half is what distinguishes the tunnel from the host's direct
uplink, because a direct path also answers the HTTPS requests. Override the hold
length with `CHECK_H2_HOLD` (default 8 seconds); it must be at least 4 seconds,
and IPv6 destinations work bare or bracketed. The Linux profile sets
`auto_redirect`, so never pin probes to the tunnel device: traffic bound to it
is not proxied. Set `EXPECTED_BINARY_SHA` and `EXPECTED_CONFIG_SHA` to make the
script fail on a hash mismatch. Then verify end to end:

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
/etc/modules-load.d/99-beam-conntrack.conf.bak-<stamp>
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
conntrack 65536 with 600 s UDP retention, resolver DoT/DNSSEC, and systemd
sandboxing with `MemoryHigh=512M`, `MemoryMax=768M`, `MemorySwapMax=512M`,
`LimitNOFILE=65536`, `TasksMax=4096`, and only `CAP_NET_BIND_SERVICE`. Test
nftables before enabling. SSH, firewall, and resolver changes are deliberately
not applied by `bootstrap.sh`; the systemd sysctl files are.

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

`make fuzz-smoke` runs the same short campaigns and keeps the corpus under
`~/.cache/beam/fuzz-corpus/` so the repository stays free of generated fuzz
data. Override the location with `BEAM_FUZZ_CACHE` and the duration with
`BEAM_FUZZ_SECONDS`.

The GitHub fuzz workflow is manual-only. Parser changes require a local run.
The multi-record ClientHello assembler still needs final fuzz coverage.

### XUDP idle-pinning fix verification

Commit `2163c0a` moves the idle touch after reply admission. The regression
test is
`xudp::session::tests::dropped_replies_do_not_refresh_idle_clock`. In the lab,
the unpatched binary kept a zero-length-fed session alive (`xudp_active=1`,
**8 socket descriptors** at t27) while the patched binary returned to the
socket-descriptor baseline by t17. A
5-rep unpatched→patched A/B measured clean up/down 0.997x/0.994x, HTTP RPS
1.015x, DNS QPS 0.951x (focused 10-pair 0.9995x), loss1 1.021x, and RTT50
1.016x. Download CPU was **1.079x** (all five pairs higher); upload CPU was
1.002x. The CPU signal is not attributed to this one-line ordering change and
is not claimed as parity. DNS p95 was 1.071x in the focused 10-pair run
(6/10 pairs), so latency equivalence is not established. No consistent
throughput regression was established in these short lab comparisons.
Bidirectional runs had zero samples in both arms and were excluded.

### XUDP mux HOL fix verification

Commit `e0ca0bc` moves domain resolution off the shared read loop, bounds send
and close waits, and adds lookup-owner/generation handling plus a process-wide
4 MiB pending-payload budget. Regression tests cover slow-domain isolation,
failed-lookup suffix draining, stale completions, queued/newer GlobalID
ordering, TCP-network preservation, and accepted/dropped reply activity.

Lab candidate: 11/11 checks; DNS 1000@32 **1000/0** at 1063 qps, p95 46 ms;
UDP 3000×1200 **3000/3000**; HTTP 2000@32 **2000/0** after drain, p95 47 ms.
A 5-rep A/B before the final owner/generation amendment measured clean up/down
0.996x/0.986x, HTTP RPS 1.017x/p95 1.047x, DNS QPS 1.011x/p95 1.161x, loss1
0.975x, RTT50 0.987x, and CPU up/down 0.991x/1.026x. A focused 10-pair DNS
A/B on the final source measured QPS **0.996x** and p95 **1.023x** with zero
errors. These are short lab comparisons, not equivalence proof; the full-A/B
DNS p95 and HTTP p95 adverse signals remain. Bidirectional A/B had four valid
pairs after excluding a zero-receive fifth new-arm run.
Final Sol review: **APPROVE WITH NONBLOCKING CAVEATS**. Remaining caveats:
the 4 MiB budget is payload-only, timing tests are scheduling-dependent, and
there is no controlled multithreaded close/enqueue test.

### Performance

```bash
source scripts/dev-env.sh
bash bench/run.sh --reps 3            # full stock-vs-beam run
bash bench/run.sh --quick --reps 1    # smoke
bash bench/run.sh --arms beam         # one arm
bash bench/no-tun.sh                  # server-capacity smoke
bash bench/churn.sh                   # connection-churn smoke
make bench-cache                      # results under ~/.cache/beam/bench-results
```

Results from `make bench-cache` are written outside the repository; raw logs
and large artifacts stay out of Git. Tool binaries come from `PATH` by default
(`sing-box`, `xray`, `iperf3`, `tc`); override them with `SING_BOX`, `XRAY_BIN`,
`IPERF3`, and `TC`. `TEST_CONFIG` defaults to the local
`config.example.toml`; replace it with a private fixture when measuring a real
identity. Full-TUN bulk is client-capped on this host
(about 0.98-1.00x), so it is not a headline result. The balanced no-TUN
capacity result is about 1.46x stock; the final smoke was about 1.40x. Treat
older n=3 claims as provisional and require n>=10 with matched CPU accounting
for any new headline.

### Baseline ledger

These are decision baselines, not universal performance claims. Re-run the
specific scenario before using a number in a new release note.

| Date | Build/commit | Environment | Scenario | Result |
|---|---|---|---|---|
| 2026-10-31 | lab `1007354…` | lab, 1024 limits | mixed soak, 10 m 37 s | 0 application errors; RSS plateau 93,920 KiB; fds 12–478; `NRestarts=0` |
| 2026-11 | `fa0c0ca` | lab, 6.12.115, 30 ms ± 8 ms, 0.5% loss | iperf3 reverse, 10 s, 4 streams | CUBIC median 62.4 Mbps; BBR median 909.2 Mbps; ~14.6× |
| 2026-11-06 | `647623b` | lab | captured ClientHello replay burst | 905/1024 established before fix; 12/1024 after |
| 2026-11-06 | `2469971` | lab, clean | three-VM functional matrix | 11/11 PASS |
| 2026-11-06 | `2469971` | production, local TUN | HTTPS through H2 | HTTP 200; 0.096–0.104 s |

The BBR value is from a virtual 1 Gbps lab link, not a 5G guarantee. The soak
is short; the 24 h soak and privileged syscall/wakeup/splice gates remain open.

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
- **Production is pinned at `d273200d578a`.** Deploys are an explicit operator
  action, not a consequence of a green tree; source HEAD may be ahead of the
  host. Move it only with `deploy/package.sh` plus
  `BEAM_KEEP_CONFIG=1 bootstrap.sh`, then re-run the hash-pinned verifier and
  update the pin here.

## Known gaps

- The XUDP junk-reply idle-pinning defect and the mux-wide resolution/send
  stalls are fixed, deployed, and lab-verified; their invariants are documented
  above. The control-frame idle pinning, Vision empty-block spin, and cover
  splice-permit bypass are fixed in `2469971`, and concurrent exact replays are
  bounded in `647623b`. `STRESS-FINDINGS.md` retains the remaining
  close/reserve, reply-budget, short-flow lifecycle, and lower-risk items.
  Do not fold the remaining items into this note until they are fixed and
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
