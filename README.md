# beam

A single-user VLESS + REALITY + Vision + XUDP server in Rust, intended to
replace stock Xray on one small Linux VPS. This is the canonical repository
note; the separate open stress findings live in
[`STRESS-FINDINGS.md`](STRESS-FINDINGS.md) until they are fixed and re-tested.

## Status

Implemented, tested, and deployed. The current production build was verified
on 2026-11-11 16:39 UTC:

| Item | Value |
|---|---|
| Binary | `/usr/local/bin/beam` |
| SHA-256 | `176349b54c5de007c34d87d789a9b3bbba142f2b5e232dca2b5bd57ee9195671` |
| Version | `0.1.0 (66494a09a092)` |
| Source release | `66494a0` (deployed); later `main` commits are docs/test cleanup only |
| Service | `beam.service`, active, `NRestarts=0`, `RestrictAddressFamilies=AF_INET AF_UNIX` |
| Listener | `0.0.0.0:443` (no IPv6 listener) |
| Live limits | 1024 authenticated connections, 1024 UDP destinations, 1024 XUDP sessions, 128 KiB UDP receive buffer, 10 s handshake, `TasksMax=4096` |
| Host network | IPv6 disabled (`all/default/lo`), BBR + fq, conntrack 65536, 600 s UDP retention |
| SSH | `AddressFamily inet`, `0.0.0.0:22`; no IPv6 listener |
| Verification | Hash-pinned verifier PASS for plain and IPv4 HTTP/2 tunnel with `EXPECT_HOST_IPV6_DISABLED=1`; 20/20 HTTP 200 burst at 20-way concurrency; `NRestarts=0`; 42 threads, 26 MiB RSS, 137–158 fds while relays drain (fds vary with active relays); 900 s soak with fd 10→10 and byte-exact TCP/UDP; TUN matrix 8/8; config matrix 57/57; fuzz 7/7; A/B valid/complete/unsaturated; 405 workspace tests |

Production is IPv4-only end to end: the beam drop-in
`/etc/systemd/system/beam.service.d/99-ipv4-only.conf` resets the base family
list before setting `RestrictAddressFamilies=AF_INET AF_UNIX`; host IPv6 is
disabled by `/etc/sysctl.d/99-beam-ipv6-disable.conf`
(`all/default/lo.disable_ipv6=1`); and
`/etc/ssh/sshd_config.d/61-ipv4-only.conf` sets `AddressFamily inet`. The host
has no IPv6 addresses, routes, or listeners, and `sshd` listens on
`0.0.0.0:22` only. The kernel IPv6 module is not unloaded and no
`ipv6.disable=1` kernel-cmdline change is made. IPv6 HTTP/2 is intentionally
not used in production verification.

The annotated tag `v0.1.0-rc.1` remains the previous release candidate.
Production now runs the `66494a0` build `0.1.0 (66494a09a092)` (binary
`176349b5…`, config `d20d16…`, drop-in `f852fce5…`), which adds the
2026-11-11 Vision Direct lazy-descriptor fix (STRESS-FINDINGS #10) to the RC
fix set. The RC contains the current server fixes plus the IPv4-only client
and deployment artifacts. It includes the XUDP junk-reply
idle-pinning fix (`2163c0a`), the mux-wide resolution/send-stall fix
(`e0ca0bc`), the 2026-11-03 handshake/legacy-UDP/End-enqueue hardening, the
bounded in-flight replay reservation (`647623b`), and the 2026-11-06 hardening
batch: XUDP socket-budget validation, control-frame idle pinning, Vision
empty-block rejection, replay first-wins with a 300-second timestamp window
and timestamp-based retention, cancellable cover relays, bounded legacy UDP,
bounded resolver lookups, and the descriptor budget check, plus the packetaddr
unbound-family admission fix (`5a1cc82`), the counted XUDP End control reserve
(`fb45eda`), and the deploy preflight fd-limit fix (`8c64e5c`).
The 2026-11-08 follow-up adds the coalesced `New+End` empty-mux timer restart,
KeepAlive/retained-GlobalID idle isolation, the 2 MiB per-mux reply budget
inside the 32 MiB process-wide budget, transient legacy UDP send-error
handling, deterministic timestamp-boundary tests, installer rollback
hardening, and secure deploy staging/HTTP/2 verification.
The later IPv4-only client-profile and production-drop-in changes are
client/deployment artifacts; they are not part of the deployed server binary.
The process-wide resolver changes remain reverted after intermittent client DNS
failures (`64d9856`); resolution is bounded to four concurrent lookups per mux.
The RC is cut with these known gaps; the five-hour soak is now the default
release gate and completed cleanly on 2026-11-10, while privileged
syscall/wakeup/splice measurements and cgroup OOM sampling remain required for
stable.

## Where to look

| Need | Read |
|---|---|
| Current production state | [Status](#status), [Operations](#operations) |
| Protocol behavior and invariants | [Protocol invariants](#protocol-invariants), [Decisions](#decisions) |
| Implicit state machines and lifecycle risks | [`STATE-MACHINES.md`](STATE-MACHINES.md) |
| Configuration | [Configuration and limits](#configuration-and-limits), [`config.example.toml`](config.example.toml) |
| Client setup | [Windows tray launcher](#windows-tray-launcher), [Linux tray and DNS switch](#linux-tray-and-dns-switch), [Mobile profile](#mobile-profile) |
| Tests and performance | [Testing and benchmarking](#testing-and-benchmarking), [One-command checks](#one-command-checks), `tests/tun`, `fuzz`, `bench` |
| Open risks | [Known gaps](#known-gaps), [`STRESS-FINDINGS.md`](STRESS-FINDINGS.md) |
| Client backlog | [`clients/TODO.md`](clients/TODO.md) |
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

The server code carries TCP, UDP, DNS, QUIC/HTTP3, IPv4, and IPv6 through the
tunnel. Production is IPv4-only end to end: the systemd drop-in narrows the
service, host IPv6 is disabled, and `sshd` is IPv4-only. The lab and TUN
harnesses still exercise IPv6 server paths; the local Linux client
intentionally rejects IPv6 while connected. The recommended stock-client
profiles are IPv4-only: they reject IPv6 first, use
`dns.strategy: ipv4_only`, and carry no IPv6 TUN address. The recommended
profiles intentionally reject public UDP/443 before sniffing so H3/QUIC falls
back immediately to HTTP/2; the server-side XUDP/legacy paths remain available
for profiles that explicitly allow H3. ICMP is not carried, matching stock
Xray. The server must remain compatible with stock clients using the same
UUID, public key, short ID, SNI, and flow.

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
a benchmark comparison. The current workspace has 405 tests: 371 `beam-core`,
4 `beam` CLI, 2 TLS adapter, 2 stock-ClientHello fixture, and 26 `beam-sys`.
When the IPv4-only Linux client is active, run the workspace checks with
`sudo systemctl stop beam-client` and restart it afterward: sing-box's
`auto_redirect` rules reject local IPv6 loopback, so the Rust IPv6 loopback
tests otherwise fail. The server code and lab/TUN IPv6 coverage are unchanged.
The client normalizers have a focused regression test:
`python3 tests/test_ipv4_only.py`.

### One-command checks

```bash
make doctor          # required build tools, optional benchmark tools, local paths
make verify          # fmt + clippy + test
make smoke           # release build, example config check, shell syntax
make acceptance      # verify + smoke
python3 tests/stress/config_matrix.py target/release/beam   # 57 boundary configs, no panic
python3 tests/stress/vless_interop.py --beam target/release/beam \
    --sing-box /usr/local/bin/sing-box --encoding xudp       # authenticated end-to-end
```

The external three-VM lab was retired in favor of the dispatch-only
[hosted pre-release lab](#hosted-pre-release-lab): `make acceptance` is now
`verify + smoke`, and `gh workflow run lab-hosted.yml -f profile=standard`
covers the functional TUN matrix and the stock-vs-beam A/B.

### Default stock-client IPv4-only and QUIC policy

All recommended profiles use this pre-match rule and ordering:

```json
[
  {"ip_version": 6, "action": "reject"},
  {"ip_is_private": true, "outbound": "direct"},
  {"action": "reject", "network": "udp", "port": [443],
   "method": "default", "no_drop": true},
  {"action": "sniff", "sniffer": ["http", "tls", "quic", "dns"],
   "timeout": "300ms"},
  {"protocol": "dns", "action": "hijack-dns"}
]
```

The IPv6 reject is first so no IPv6 literal or AAAA-derived destination can
escape the IPv4-only tunnel. The private rule comes next so IPv4 LAN
destinations remain direct. The public UDP/443 reject is before sniff so
sing-box synthesizes ICMP port unreachable instead of silently dropping;
`no_drop` prevents burst protection from degrading later requests to
timeouts. Public HTTP/3 therefore fails fast and the application uses HTTP/2
over the TCP/REALITY path. This is the default for Linux, Android, and the
embedded Windows profile. A profile that needs H3 must explicitly opt in and
accepts the XUDP/TCP head-of-line risk. Normalization strips IPv6 addresses
from DNS predefined lists and TUN address arrays, sets `dns.strategy` to
`ipv4_only`, and re-adds a single first `ip_version: 6` reject. The Python
normalizers only replace a UDP/443 rule whose port set is exactly `443`; a rule
that also lists another port (for example `[443, 8443]`) is preserved. The
Windows installer's pre-existing normalization uses a broader
`-contains 443` predicate and is unchanged by this IPv4-only work.

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
desktop shortcut. The embedded profile is IPv4-only (`dns.strategy:
ipv4_only`, no IPv6 TUN address or IPv6 DoH bootstrap) and uses the same route
shape as the Linux client: IPv6 rejected first, then private destinations
direct, public UDP/443 rejected, port-53 DNS hijacked to DoH, and no
HTTP/TLS/QUIC sniffing. The installer normalizes the decoded route rules again
before staging, so an older embedded blob cannot reintroduce full sniffing,
drop the UDP/443 rule, or move IPv6 ahead of the reject. Windows therefore
falls back to HTTP/2 without waiting for XUDP/TCP retransmission. The config is
restricted to Administrators and SYSTEM. It is ignored by Git because it embeds
real credentials.

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
  The profile has no IPv6 TUN address and uses `dns.strategy: ipv4_only`; with
  `auto_redirect`, sing-box rejects IPv6 at the host, so IPv6 (including local
  loopback) is intentionally unavailable while connected.
- The Linux profile also rejects UDP/443 before sniffing with
  `action: reject`, `method: default`, and `no_drop: true`. sing-box emits ICMP
  port unreachable immediately, so browsers and curl fall back to HTTP/2
  without waiting for the XUDP/TCP retransmission timeout. H3 is intentionally
  unavailable on this stock-client profile; the TCP/REALITY cover is unchanged.
- `ExecStopPost` calls `dns-off` and restores ctrld. `Restart=no` avoids a
  restart cycle where the TUN comes back without the matching DNS state.
- `beam-dns-reset.service` is enabled at boot and only runs when the saved
  ctrld drop-in exists, restoring ctrld after an unclean shutdown (including a
  crash between the rename and the beam drop-in write).

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

The installer copies the core into a private staging directory under
`/usr/local/lib`, verifies the staged copies by SHA-256, normalizes the config,
and runs `sing-box check` with the staged binary before it stops the service or
touches the live core/config. If replacement of the live files fails, the
managed config, core, helper, tray, and unit files are restored from the
pre-install snapshot; an active service is started again with the restored
configuration. If restoration itself fails, the installer exits nonzero and
keeps the snapshot under `/usr/local/lib/.beam-backup.*` for recovery. The
service is installed but not enabled or
started. DNS
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

The profile is IPv4-only: `dns.strategy` is `ipv4_only`, the TUN has no IPv6
address, IPv6 DoH bootstrap entries are absent, and the first route rule is
`{"ip_version": 6, "action": "reject"}`. It keeps Android's TUN on
`stack: system`, MTU 1500, `auto_route` on, and no generic mux. Like the Linux
profile, it rejects UDP/443 before sniffing with `method: default` and
`no_drop: true`, so H3/QUIC fails fast and the client falls back to HTTP/2
instead of waiting for the XUDP/TCP retransmission timeout. H3 is therefore
intentionally unavailable in this recommended profile; the TCP/REALITY/WhatsApp
SNI path is unchanged.

## Repository layout

```text
crates/beam       CLI, config loading, logging, signals, listener lifecycle
crates/beam-core  protocol/server logic; forbid(unsafe)
crates/beam-sys   splice/socket/eventfd primitives; sole unsafe crate
tests/tun         full-TUN interoperability harness, protocol lab and
                  target services (protocol.py, protocol_report.py)
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
  inserts the first Finished handshake into a bounded exact-replay cache.
  Capacity scales with `max_connections` (128x, clamped to 4096..131072) and is
  wired to `limits.max_connections`. Each entry is retained until its
  authenticated envelope timestamp plus the REALITY timestamp window plus one
  second: a timestamp at the current time is retained for 301 s, and the worst
  case for a timestamp five minutes in the future is 601 s. A settled entry
  with admitted concurrent copies is held until those copies drain even past
  that deadline, so first-wins is preserved. The deadline is monotonic; keep
  the server clock disciplined, because a backward wall-clock step can keep an
  envelope timestamp acceptable past the cache deadline. A full cache rejects
  the new handshake instead of evicting a live id; `replay_cache_full` counts
  that case separately from a duplicate ClientHello. Concurrent duplicates are
  first-wins: a second Finished handshake is closed rather than served. This
  bounds the in-flight permit race, the post-cache window, and cache pressure.
- Unauthenticated traffic is relayed to the configured cover. Never send a
  TLS alert or a synthetic response on authentication failure.
- A cover relay ends on the first half-close: once the probe's write side
  finishes (FIN or reset), beam releases the relay and its cover permit as
  soon as that direction's shutdown completes, instead of holding them until
  the 30 s cover idle timeout. This is a deliberate parity tradeoff: a
  response the cover would send after the probe's FIN is not forwarded, and a
  cover-first close cancels the remaining upload. The authenticated relay keeps
  its TCP half-close semantics, so an idle direction cannot cut a
  download-only Vision stream. Bounding unauthenticated retention keeps the
  cover cap from being pinned by disconnected probes.

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
  require an End. Keep frames may carry a per-datagram destination; empty or
  non-Data Keeps do not update the session destination, and address-less Keeps
  reuse the last destination accepted from `New` or a non-empty Data Keep.
  Replies are Keep
  with Data, plus End on closure (Error only when relay failed). An unknown
  stream ID gets a clean End and is discarded.
- Accept zero GlobalID and per-frame destinations from sing-box. A nonzero
  GlobalID may reattach a retained socket only within the same mux and user;
  never use GlobalID as identity or policy.
- XUDP datagram payloads are capped at 8192 bytes; empty or oversize
  datagrams are dropped. Legacy UDP is capped at 8190 bytes. packetaddr uses
  the magic `sp.packet-addr.v2fly.arpa` destination and carries an inner
  address per datagram. A 100 ms send timeout or a transient send error
  (`WouldBlock`, `TimedOut`, `Interrupted`) on the fixed-destination legacy
  path drops only that datagram; other send errors close the association.
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
  their ordering. Resolved domains are cached for 300 seconds. A mux runs at
  most four concurrent lookups; the resolver permit is held until the result
  is queued, so a full result channel backpressures the request queue instead
  of spawning unbounded tasks. Pending payload has a process-wide 4 MiB budget
  plus bounded metadata, and UDP send/close waits are capped at 100 ms. This is
  not universally nonblocking: a sequence of slow domains, a congested send,
  or many close operations can still delay a mux briefly.
- Reply bytes are bounded by a 2 MiB per-mux budget inside the 32 MiB
  process-wide budget; one slow reader cannot hold the whole global allowance.
- An empty mux closes after `session_idle_timeout` even while KeepAlive frames
  arrive or a retained GlobalID socket is waiting for `close_expiry`. Retained
  sockets do not extend the empty-mux timer.
- Live XUDP limits are 1024 process-wide sessions and 128 KiB per socket
  receive buffer; a mux holds at most half the global active slots. XUDP idle
  expiry is at most 60 seconds even when the TCP relay idle timeout is 300
  seconds.
- Legacy/packetaddr UDP holds one stream permit per VLESS `Command::Udp`
  connection, and the pool equals `max_xudp_sessions` (1024 in the production
  profile, 256 with the example config); one stream owns one relay socket, or
  two for packetaddr. The
  legacy idle clock is capped at 60 seconds like the XUDP one, so an idle flow
  releases its permit five times sooner than the TCP idle timeout would. The
  effective clock is `min(idle_timeout_ms, 60 s)`, so a smaller configured
  value shortens UDP flows too. Legacy relay sockets keep the kernel's default
  receive buffer; only XUDP requests `xudp_recv_buffer_bytes`. A stub
  resolver opens one UDP socket per query, so a DNS burst is a burst of streams:
  it is admitted from this pool and, at the cap, refused as
  `TlsServerError::LegacyUdpLimited` and counted in `legacy_udp_limited`.
  `max_xudp_sessions` also sizes the XUDP kernel buffer budget, so lowering it
  to save memory lowers this pool as well: keep it at 200 or more when a
  legacy/packetaddr client bursts short UDP flows.

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
STAGE=$(ssh -4 -i "$SSH_KEY" "$SERVER" 'mktemp -d /tmp/beam-deploy.XXXXXXXX')
test -n "$STAGE"
test "$(ssh -4 -i "$SSH_KEY" "$SERVER" "stat -c %a '$STAGE'")" = 700
trap 'ssh -4 -i "$SSH_KEY" "$SERVER" "rm -rf -- \"$STAGE\""' EXIT
scp -4 -i "$SSH_KEY" "$BUNDLE" "$SERVER:$STAGE/beam-deploy.tar.gz"
ssh -4 -i "$SSH_KEY" "$SERVER" "chmod 600 '$STAGE/beam-deploy.tar.gz'"
ssh -4 -i "$SSH_KEY" "$SERVER" "tar -xzf '$STAGE/beam-deploy.tar.gz' -C '$STAGE'"
ssh -4 -i "$SSH_KEY" "$SERVER" \
  "sudo -n env BEAM_KEEP_CONFIG=1 bash '$STAGE/bootstrap.sh'"
ssh -4 -i "$SSH_KEY" "$SERVER" "rm -rf -- '$STAGE'"
```

`mktemp -d` creates an atomically named, mode-0700 staging directory; do not
use a predictable `/tmp/beam-deploy` directory. Remove the secret-bearing
stage in every outcome, including a failed rollout, after preserving local
logs and the timestamped recovery backups.

For an existing host, use
`sudo env BEAM_KEEP_CONFIG=1 bash "$STAGE/bootstrap.sh"` to preserve
the live `/etc/beam/config.toml` explicitly. If `BEAM_KEEP_CONFIG` is unset,
bootstrap automatically preserves any existing `/etc/beam/config.toml`;
replacing it requires the explicit fresh-install/update override
`sudo env BEAM_KEEP_CONFIG=0 bash "$STAGE/bootstrap.sh"`. A plain
`sudo bash ...` cannot inherit an exported `BEAM_KEEP_CONFIG`, so use `env`
for both modes. The package script validates local secrets and bundles the
beam IPv4-only drop-in, host IPv6 sysctl, and SSH IPv4-only drop-in. Bootstrap
applies and validates sysctls, validates the new binary as the unprivileged
service user, installs the beam drop-in, backs up replaced files, rolls back on
a failed restart/readiness probe, prunes each backup set to five, and polls
beam's own 443 listener. After beam is ready it installs the SSH
`AddressFamily inet` drop-in and applies the host IPv6 sysctl; a failure in
either step restores the previous SSH/sysctl state before exit. Verify the
deployed state without printing config contents:

```bash
SSH_KEY="$SSH_KEY" SERVER="$SERVER" EXPECT_IPV4_ONLY=1 \
  EXPECT_HOST_IPV6_DISABLED=1 deploy/verify-production.sh
SSH_KEY="$SSH_KEY" SERVER="$SERVER" EXPECT_IPV4_ONLY=1 \
  EXPECT_HOST_IPV6_DISABLED=1 CHECK_H2=1 \
  TUN_IFACE=sbtun0 CHECK_H2_DST=1.1.1.1:443 CHECK_H2_FAMILY=4 \
  deploy/verify-production.sh
```

`EXPECT_IPV4_ONLY=1` checks that systemd reports
`RestrictAddressFamilies=AF_INET AF_UNIX` and fails if `AF_INET6` remains.
`EXPECT_HOST_IPV6_DISABLED=1` requires `all/default/lo.disable_ipv6=1`, zero
IPv6 addresses, routes, and listeners, and `sshd` reporting
`addressfamily inet`.
`CHECK_H2=1` requires the named local tunnel and fails if it is missing. It
verifies the path real traffic takes: three sequential HTTPS requests to
`https://<CHECK_H2_DST>/cdn-cgi/trace`, each requiring HTTP 200 and negotiated
HTTP/2, then a held client connection that must produce a new established
socket owned by beam on the server for the same destination. The production
profile uses `CHECK_H2_DST=1.1.1.1:443` and `CHECK_H2_FAMILY=4`; IPv6 probes
remain available for lab use only via `CHECK_H2_FAMILY=6`. The correlated
beam-owned socket observation during the held connection is the discriminator;
HTTPS alone can also succeed through the host's direct uplink. Override the
hold length with `CHECK_H2_HOLD` (default 8 seconds); it must be at least 4
seconds. The Linux profile sets `auto_redirect`, so never pin probes to the
tunnel device: traffic bound to it is not proxied. Set `EXPECTED_BINARY_SHA`
and `EXPECTED_CONFIG_SHA` to make the script fail on a hash mismatch.

Production uses the production-only drop-in
`deploy/beam-ipv4-only.conf`; copy it to the host and install it as
`/etc/systemd/system/beam.service.d/99-ipv4-only.conf`:

```bash
sudo install -d -m 0755 /etc/systemd/system/beam.service.d
sudo install -m 0644 deploy/beam-ipv4-only.conf \
  /etc/systemd/system/beam.service.d/99-ipv4-only.conf
sudo systemctl daemon-reload
sudo systemctl restart beam
```

The empty `RestrictAddressFamilies=` assignment is required: systemd appends
repeated family assignments, so without the reset the base unit's `AF_INET6`
remains. To roll back, remove the drop-in, reload, reset the failed state, and
restart:

```bash
sudo rm -f /etc/systemd/system/beam.service.d/99-ipv4-only.conf
sudo systemctl daemon-reload
sudo systemctl reset-failed beam
sudo systemctl restart beam
```

This narrows only the beam service's socket families. Host IPv6 and SSH are
controlled by separate files: `deploy/99-beam-ipv6-disable.conf` (installed as
`/etc/sysctl.d/99-beam-ipv6-disable.conf`) and
`deploy/sshd-61-ipv4-only.conf` (installed as
`/etc/ssh/sshd_config.d/61-ipv4-only.conf`). The fresh-host bootstrap installs
the beam drop-in before restart, then the SSH and IPv6 files after beam is
ready. To roll back host-wide policy, remove the SSH
and IPv6 files, re-enable IPv6, reconfigure the IPv4-default interface, and
reload ssh while retaining provider console access:

```bash
sudo rm -f /etc/ssh/sshd_config.d/61-ipv4-only.conf
sudo rm -f /etc/sysctl.d/99-beam-ipv6-disable.conf
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 \
  net.ipv6.conf.default.disable_ipv6=0 net.ipv6.conf.lo.disable_ipv6=0
iface=$(ip -o -4 route show default | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -n "$iface" ]; then
  sudo networkctl reconfigure "$iface" || sudo systemctl restart systemd-networkd
fi
sudo sshd -t && sudo systemctl reload ssh
```

Then verify end to end on IPv4:

```bash
curl -4 -sS -o /dev/null -w '%{http_code}\n' https://example.com/
# Expected failure: the default profile rejects public UDP/443.
if curl --http3-only -sS -o /dev/null --max-time 5 https://cloudflare-quic.com/; then
  echo 'unexpected H3 success' >&2
  exit 1
fi
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
/etc/systemd/system/beam.service.d/99-ipv4-only.conf.bak-<stamp>
/etc/sysctl.d/99-beam.conf.bak-<stamp>
/etc/sysctl.d/99-beam-conntrack.conf.bak-<stamp>
/etc/sysctl.d/99-beam-ipv6-disable.conf.bak-<stamp>
/etc/modules-load.d/99-beam-conntrack.conf.bak-<stamp>
/etc/ssh/sshd_config.d/61-ipv4-only.conf.bak-<stamp>
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
nftables before enabling. The 61 address-family drop-in and the host IPv6
sysctl are applied by `bootstrap.sh` after beam readiness; the existing 60
authentication hardening, firewall, and resolver remain manual.

## Testing and benchmarking

### Full TUN

```bash
source scripts/dev-env.sh
bash -n tests/tun/run.sh
bash tests/tun/run.sh
bash tests/tun/run.sh --udp-mode packetaddr
bash tests/tun/run.sh --udp-mode legacy
TUN_RTT_MS=250 TUN_LOSS_PCT=1 bash tests/tun/run.sh --suite protocols
```

Each mode must report 8/8 PASS: TCP HTTP v4/v6, UDP echo v4/v6, DNS v4/v6,
QUIC/H3, and HTTPS through Vision Direct. `--suite protocols` replaces the
eight probes with the protocol campaign: it applies netem (`TUN_RTT_MS`,
`TUN_LOSS_PCT`), records the qdisc and baseline-RTT evidence, and merges the
per-case JSON into `protocol-report-<arm>.json`; `tests/tun/protocol.py` is the
per-case driver and `tests/tun/protocol_report.py validate` is the gate. `BLOCKED` is not pass: any blocked
row makes the harness exit 2. If `/dev/net/tun` is unavailable, all rows are
BLOCKED and the script also exits 2; set `ALLOW_TUN_BLOCKED=1` only when
skipping the matrix is intended.
This harness is local and does not touch production.

The coalesced `New+End` test uses real 500 ms scheduling margins and may be
scheduler-sensitive; it is retained as a timing test, not deterministic-clock
proof.

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
the 4 MiB resolver budget charges payload plus domain, metadata, and structural
overhead, but it is still an estimate rather than a byte-exact allocation cap;
timing tests are scheduling-dependent, and there is no controlled
multithreaded close/enqueue test.

### Performance

```bash
source scripts/dev-env.sh
bash bench/run.sh --reps 3            # full stock-vs-beam run
bash bench/run.sh --quick --reps 1    # smoke
bash bench/run.sh --arms beam         # one arm
bash bench/no-tun.sh                  # server-capacity smoke
bash bench/churn.sh                   # connection-churn smoke
make soak                             # five-hour local data-path soak
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

The 2026-11-10 hardening pass sizes each Vision splice pipe from
`fs.pipe-user-pages-soft` and the splice permit count, so raising
`BEAM_MAX_BLOCKING_THREADS` cannot silently fall back to the kernel's 8 KiB
allocation default. XUDP request sends try the socket first and queue only a
`WouldBlock` datagram in a bounded mux queue; a failed send closes that session
with `End + Error` through a failure channel. The TLS record path reuses one
initialized header+body buffer per stream, and XUDP replies are encoded in the
writer batch while the idle clock is an atomic epoch counter. Hosted paired
cells showed no regression (UDP pps/loss and p99 within noise; HTTPS
beam-vs-beam 0.9988 over five repetitions), and a local no-TUN UDP A/B moved
from about 78k to 83k pps after the send fast-path fix. The hosted runner has
perf tracepoints disabled, so per-record CPU deltas are not claimed; the
upload-side chunk copy remains.

A scenario is condemned only when a harness role is saturated *typically*, not
when one repetition spikes: `report.py` compares the median client, target and
driver core utilisation across repetitions against 85% (peaks stay visible in
the resource rows). Give the client proxy enough threads that its per-core
median stays below that line, for example
`BENCH_CLIENT_CPUS=0,1,4,5 BENCH_DRIVER_CPU=7` on a four-core/eight-thread
host; one client core caps the whole comparison. Host-noise coverage excludes a
role core's hyperthread siblings, so an allocation that claims every thread
leaves no core to observe — the CPU noise metric is then empty and the
settled host load average is the only interference signal, which cannot see
load that exists solely inside the measurement windows. Latency pooling uses
only the repetitions that succeeded in both arms and lists the repetitions it
dropped. `BENCH_PERF=1` (root) and `BENCH_HTTPS_PARALLEL>1` produce probe
measurements, not gate measurements; the concurrent HTTPS mode exists only to
force the Vision async fallback.

### Hosted pre-release lab

`.github/workflows/lab-hosted.yml` runs the functional 8-row TUN matrix, the
stock-vs-beam A/B, and the loopback stress probes in one GitHub-hosted
`ubuntu-24.04` job, on demand:

```bash
gh workflow run lab-hosted.yml -f profile=standard
gh workflow run lab-hosted.yml -f profile=smoke -f suite=tun
gh workflow run lab-hosted.yml -f profile=claim -f suite=bench
gh workflow run lab-hosted.yml -f suite=stress
gh workflow run lab-hosted.yml -f suite=protocols -f udp_mode=xudp
```

| Profile | RTT | Server ceiling | Reps | Window | Duration | Use |
|---|---|---|---|---|---|---|
| `smoke` | 250 ms | 50% CPU, 1 GiB | 2 | quick | ~15 min | wiring, pre-push |
| `standard` | 250 ms | 50% CPU, 1 GiB | 3 | full | ~40 min | routine pre-release |
| `claim` | 250 ms | 50% CPU, 1 GiB | 10 | full | ~90 min | claim-grade cell |

`suite=stress` takes seconds and ignores the profile budget. It starts its own
server on loopback (no root, no net namespace, no TUN) with reduced limits and
checks the admission and cover bounds: per-source and global pre-auth
exhaustion, the ClientHello handoff deadline for idle/partial/trickled probes,
fd stability under RST churn, the 32-slot cover cap and its response, prompt
cover-slot release when a probe disconnects, a refused cover dial, and
graceful shutdown under a full pre-auth pool. `tests/stress/loopback.py` is the
same suite locally:

```bash
make stress   # release build + python3 tests/stress/loopback.py
```

Targeted experiments keep the profile budget but override its knobs:

```bash
gh workflow run lab-hosted.yml -f suite=bench -f scenarios=https-bulk \
  -f https_mib=16 -f rtt_ms=0 -f reps=3 -f publish=false
gh workflow run lab-hosted.yml -f suite=bench -f scenarios=tcp-ul-4 \
  -f reps=8 -f publish=false
```

`scenarios`, `https_mib`, `https_parallel`, `rtt_ms`, `loss_pct`, `reps`, and
`duration` are optional; empty keeps the profile value. A filtered scenario
list disables `--require-complete`, and `publish=false` keeps a partial cell
from overwriting `bench-results`.

The job is dispatch-only: no push, tag, or PR event runs it, so a shared
runner's noise never blocks a release by itself. A green job means every
selected suite passed: TUN 8/8 PASS, the bench cell complete
(`--require-complete`) and unsaturated, every stress check PASS, and for
`suite=protocols` a validated 20-case beam report with no FAIL or BLOCKED row.
A ratio outside 0.95-1.05 only emits a warning. Results land in the
`bench-results` branch (latest bench run), a run artifact, and the step
summary. Stress-only runs leave `bench-results` untouched; their summary is in
the artifact and the step summary. `BLOCKED` TUN rows fail the job;
`ALLOW_TUN_BLOCKED` is never used there.

`suite=protocols` runs the real-protocol campaign (HTTP/1.1, HTTP/2, HTTP/3,
UDP/XUDP, DNS over UDP and TCP, TCP echo, mixed load, idle and restart) through
the same sing-box -> beam full-TUN path under netem. It writes
`protocol-report-beam.json` and a stock-Xray control report; the beam report is
the gate and the control report is diagnostic. Each report records the qdisc
evidence, both baseline RTTs and the per-case metrics, and the acceptance step
re-runs `tests/tun/test_protocol_report.py` so a truncated, incomplete,
duplicated or FAIL-carrying report cannot pass. The same campaign runs locally
with `bash tests/tun/run.sh --suite protocols` plus `TUN_RTT_MS` and
`TUN_LOSS_PCT`; it needs root (or `TUN_ALLOW_ROOT=1`) and a prebuilt h3-origin
and h2-client helper.

The runner is shared and the four vCPUs are all assigned to roles, so these are
noisy, high-RTT probe measurements, not headline numbers, and the `non_role`
noise metric is empty by construction. `quic-udp` depends on the pinned static
curl having HTTP/3; if it ever loses it, the job fails closed instead of
reporting a permanent BLOCKED row. Because the workflow is dispatch-only,
harness changes no longer trigger a benchmark automatically; dispatch a
`smoke` run before merging a harness change.

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
| 2026-11-10 | `9d67ebc` | local no-TUN | five-hour data-path soak | 181,677 downloads, 0 errors, 19 stress rounds PASS, fds 10, threads 9, RSS 8.5→23.3 MiB |

The BBR value is from a virtual 1 Gbps lab link, not a 5G guarantee. The soak
default is five hours (completed 2026-11-10); privileged syscall/wakeup/splice
gates remain open.
The low-rate UDP A/B is provisional: the current arm ran at 3700.1 MHz versus
the baseline's 3600 MHz with two repetitions. Its +1.99% throughput /
-1.10% CPU delta is frequency-confounded and is not regression-freedom
evidence. TCP 860.6 vs 840.1 MB/s remains inside the existing 5% gate; the
saturated UDP run was driver-bound.

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
- **Production runs the `66494a0` build `0.1.0 (66494a09a092)` (binary
  `176349b5…`); later `main` commits are docs/test cleanup only. The annotated
  `v0.1.0-rc.1` tag is the previous release candidate.** Move it only with
  `deploy/package.sh` plus
  `BEAM_KEEP_CONFIG=1 bootstrap.sh`, then re-run the hash-pinned verifier and
  update the pin here when deployed.
- **Production is IPv4-only at the host boundary** — the beam
  `99-ipv4-only.conf` drop-in resets the base family list and sets
  `RestrictAddressFamilies=AF_INET AF_UNIX`; host IPv6 is disabled
  (`all/default/lo.disable_ipv6=1`) and `sshd` is `AddressFamily inet`. The lab
  and TUN harness still exercise IPv6 server code; the local Linux client
  intentionally rejects IPv6 while connected.

## Known gaps

- The XUDP junk-reply idle-pinning defect, mux-wide resolution/send stalls,
  control-frame idle pinning, Vision empty-block spin, cover splice-permit
  bypass, concurrent exact replays, and the 2026-11-08 reply-budget,
  short-flow lifecycle, replay-cache, resolver-task, legacy-send, and installer
  issues are fixed in the repository. The server deploy carries the
  `beam-core`/`beam`/server-deploy fixes; the IPv4-only client profiles, beam
  drop-in, SSH drop-in, and host IPv6 sysctl are deployment artifacts, and
  client installer/tray changes are not installed by that deploy.
  `STRESS-FINDINGS.md` retains only the Vision raw-handoff fd-clone cost (#10).
  Stable-promotion validation is tracked in `ISSUES.md` test gaps; the rootless
  Android BBR limitation is tracked in `clients/TODO.md` (no client work
  planned). Do not fold those remaining items into this note until they are
  fixed and re-verified.
- The 11 local client `/etc/beam/config.json.bak-*` backups were removed after
  live-profile validation; the production host retains five
  `/etc/beam/config.toml.bak-*` recovery backups. Existing Android/Windows
  profiles and any stock-Xray configuration are operator-managed outside this
  repository rollout.
- A clean five-hour mixed soak is the release default (the 2026-11-10 run had
  181,677 downloads with zero errors, stable fds/threads, and 19 stress
  rounds). Privileged syscall/wakeup/splice gates, cgroup socket-memory/OOM
  sampling, and a final fuzz run of the multi-record ClientHello assembler
  remain required for stable promotion; they were not completed for
  `v0.1.0-rc.1`.
- Fully framed HTTPS uploads stay on the async path; early Direct acceleration
  requires the client to send Direct before the body (for example
  `Expect: 100-continue`). This is a performance gap, not a correctness defect.
- Large H3 bodies can show rare completion outliers through some client/TUN
  combinations. At MTU 1500 those are consistent with QUIC PTO/TCP
  head-of-line behavior, not server packet drops.
- No per-IP authenticated connection cap, no stats API, no hot reload, and no
  automatic stock fallback. Recover with the timestamped backups.
