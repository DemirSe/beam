# beam

beam is a single-user VLESS + REALITY + Vision + XUDP server in Rust for Linux.
It replaces stock Xray on one small server and keeps compatibility with stock
VLESS clients. It is for one operator who runs one tunnel and wants a small,
auditable server with explicit resource bounds. It is not a multi-user proxy.

## What it does

- **REALITY:** authenticates a TLS 1.3 ClientHello with an X25519/AEAD envelope
  and forwards unauthenticated traffic to a cover destination without an
  authentication oracle.
- **VLESS:** parses the version, user UUID, addons, command, and target address
  inside the authenticated TCP connection.
- **Vision:** pads TLS blocks and switches one direction to raw Direct after a
  valid inner TLS 1.3 ServerHello, preserving bytes already read.
- **XUDP:** carries bounded UDP sessions inside VLESS Mux frames, with legacy
  VLESS UDP and packetaddr modes for stock clients.

## Should you run this?

beam is for one operator who runs one Linux server and one tunnel, can read
systemd journals, and can edit a TOML file. It is not for:

- Teams, shared access, or resold access. beam is not a shared proxy; see
  [Security notes](#security-notes).
- Panels, billing, or per-user limits. There is no account system.
- Windows or macOS as the server.
- Anyone without root, or anyone who wants a one-click client.

It does not protect against:

- Traffic analysis by an adversary who observes both ends.
- The server provider's own logging.
- A misconfigured host.
- A cover site that does not look plausible from the client's network.

Running a proxy may break the host provider's terms of service, and local law
also applies. That decision is the operator's.

## Requirements

- Linux x86_64 and a Rust toolchain. [`rust-toolchain.toml`](rust-toolchain.toml)
  pins the version together with the `clippy` and `rustfmt` components.
- Root to install the service, manage systemd, and bind a low port. Running
  `beam generate` and `beam --check` needs no root.
- **Single user, one inbound.** beam supports one configured user ID. See
  [Security notes](#security-notes) for what that rules out.

## Build

The Makefile's `build` target runs the locked release build. Build and validate
the example configuration with:

```bash
make build
target/release/beam --check -c config.example.toml
```

`make smoke` adds the same config check and a `bash -n` pass over tracked shell
scripts. The example config contains placeholder values only.

## Configure

Start from [`config.example.toml`](config.example.toml). Unknown fields are
errors, and `--check` validates scalar and derived limits before the server
binds a socket. The important keys are:

| Section | Keys |
|---|---|
| `[server]` | `listen` — listener address and port. |
| `[user]` | `id` — client UUID; `flow` — must be `xtls-rprx-vision` for configuration compatibility. |
| `[reality]` | `private_key`, `short_ids`, `server_names`, `dest` — server identity, accepted short IDs and SNI values, and cover destination. |
| `[log]` | `level` — log level. |
| `[limits]` | `max_connections`, `max_udp_destinations`, `max_preauth_per_ip`, `max_xudp_sessions`, `xudp_recv_buffer_bytes`, `listen_backlog`, `shutdown_drain_ms`, `handshake_timeout_ms`, `idle_timeout_ms`. |

`handshake_timeout_ms` must be at least 100 and `idle_timeout_ms` at least
1000; both are capped at 24 hours. `max_xudp_sessions` also sizes the legacy
UDP stream pool and the XUDP kernel buffer budget. The derived packetaddr
budget also limits `max_udp_destinations * max_xudp_sessions` to 4,194,304
entries (512 MiB at an estimated 128 bytes per table entry). Keep it at 200 or
more when a legacy or packetaddr client bursts short UDP flows.

Generate a new identity under a restrictive umask, then put the server fragment
into a copy of the example config:

```bash
cp config.example.toml config.toml
(umask 077; target/release/beam generate --host example.com --sni example.com > identity.txt)
chmod 600 config.toml identity.txt
target/release/beam --check -c config.toml
```

The umask applies only to the subshell, so later build and test commands keep
their normal modes. Both files hold secrets and are git-ignored.
`beam generate` refuses to emit when standard output is a regular file that
group or other users can read, so a forgotten umask fails instead of writing a
0644 identity file.

Replace every placeholder. `beam generate` does not choose a cover
destination: set `reality.dest` to a `host:port` whose TLS certificate is valid
for your `--sni` value, usually `<sni>:443`, and replace the sample
`whatsapp.net:443` unless that name is your SNI. The cover must serve the chosen
name and meet the cover parity rules in
[TLS stack, cover, and MTU](#tls-stack-cover-and-mtu); `--check` does not test
it. Keep secrets out of git. Use mode `0600` locally and root:beam `0640` on
the service host. See [Security notes](#security-notes) for the full rule.

The startup and `--check` permission warning reads mode bits only: it reports
when other users can access the config or the file's group can write it. It
does not verify the owner or group, so verify those separately against the
ownership your service unit uses. A custom owner or group is valid.

Beam warns at startup and during `--check` when `user.id`,
`reality.private_key`, or a `reality.short_ids` entry still holds the published
sample value (including X25519-equivalent encodings of the sample private
key). It prints the field names only, never the values, on stderr and
independently of `RUST_LOG`. The warning does not fail either path, because
builds and tests load the example file. A passing check or a running server
with this warning is not deployment ready.

## Run

Start the built binary with the config path:

```bash
target/release/beam -c /etc/beam/config.toml
```

The default config path is `/etc/beam/config.toml`. For systemd, use
[`deploy/beam.service`](deploy/beam.service) as the unit. It runs
`/usr/local/bin/beam -c /etc/beam/config.toml` as the unprivileged `beam` user,
runs `--check` first, and sets resource and sandbox limits. It expects the
config to be readable by the service user. Beam installs its service signal
handlers before loading the configuration. Once installed, `SIGHUP` is
ignored. Restart the service to reload configuration. `SIGTERM` or `SIGINT`
stops accepting and drains for at most `shutdown_drain_ms`. A further
`SIGTERM` or `SIGINT` delivered during drain ends it early. Runtime shutdown
has a separate three-second bound.

Before you install the service, read [Deploy](#deploy) below. Step-by-step
install, update, rollback, and recommended host tuning are in
[`docs/DEPLOY.md`](docs/DEPLOY.md).

## Deploy

Read this section before you deploy beam on a server. The repository ships a
distribution-agnostic systemd installer and unit; host policy (SSH, firewall,
sysctls, NTP, IPv6) stays with the operator.

### Choose the host

- Use the smallest dedicated Linux server that fits one tunnel.
- Choose a provider that allows the traffic you intend to send and receive.
- Choose a region that makes your cover name plausible.
- Choose a provider console or rescue mode that you tested.
- Do not use a shared host with other services. Other services on the host
  increase the blast radius.

### Prepare the host

1. Use Linux x86_64 with systemd, your own account with key-only SSH, and root
   or sudo access.
2. Keep the provider console reachable while you work.
3. Take a snapshot or backup before changing host firewall or SSH settings.
4. `deploy/beam-install.sh` checks systemd, not a distribution. It requires
   `systemctl`, `sha256sum`, `getent`, `groupadd`, `useradd`, `runuser`, and
   `install` (plus `tar` when using `BEAM_ARTIFACT`, and `python3` if you run
   the optional `beam-liveness.timer`).

### Recommended minimum posture

- Pin the release artifact by SHA-256 with `BEAM_SHA256` or its `.sha256`
  sidecar file.
- Keep `/etc/beam/config.toml` at `root:beam 0640` (and local copies at `0600`)
  and out of git.
- Keep the host clock synchronized with NTP (REALITY rejects timestamps more
  than 300 seconds off).
- Restrict inbound firewall traffic to SSH and beam's listening port (default
  TCP 443).
- Watch `journalctl -u beam` after each install or update.

[`docs/DEPLOY.md`](docs/DEPLOY.md) covers `beam-install.sh` install/update/uninstall,
optional recommended sysctl/firewall/clock settings, and troubleshooting.

## Verify

The Makefile is the single source for the local gate. Run it before you
commit:

```bash
make verify
```

It runs `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo test --workspace`. The `test` target runs these rootless script suites
before the cargo tests:

```bash
python3 tests/bench/test_report.py
python3 tests/bench/test_workflow_budget.py
python3 tests/tun/test_protocol_report.py
python3 tests/preprod/test_preprod_gate.py
python3 tests/test_ipv4_only.py
python3 tests/deploy/test_deploy_contracts.py
python3 tests/deploy/test_restart_policy.py
python3 tests/deploy/test_liveness_check.py
python3 tests/release/test_release_artifact.py
bash tests/deploy/test_beam_install.sh
bash tests/linux-tray/test_dns_state.sh
```

Parser changes also require the relevant fuzz target; hot-path changes require
a benchmark comparison. Root, TUN, netem, stress, soak, and long benchmark
runs belong in hosted CI, not in this local loop. See
[AGENTS.md](AGENTS.md#verification-before-every-commit) for the full rule.

### Before promoting to production

Dispatch [lab-hosted](.github/workflows/lab-hosted.yml) on the exact candidate
commit with `suite=preprod`, `profile=standard`, `publish=false`, and the
current full `prod` SHA as `baseline_ref`. Review the final gate before
promotion.

Preprod runs four independent jobs: `tun`, `protocols`, `bench` and `stress`.
Each job uses the same candidate commit and the current `prod` SHA. Each job
uploads evidence under its own artifact name. The `preprod-gate` job checks all
four reports, their commits and the matrix result. It fails on a missing,
cancelled, failed or duplicated phase. A green final gate is the only
production evidence for that dispatch. Standalone suites still run as one job.

For independent parallel campaigns, select distinct `concurrency_slot` values
(`parallel-1`, `parallel-2`, `parallel-3`). The default `shared` slot serializes
runs. `job_timeout_minutes=180` bounds each job. A `10`-minute cap leaves the
production gate incomplete.

The standard profile sets the inner benchmark timeout to 2400 s. With a
`reps` override, the timeout becomes the smaller of 6000 s and 800 s
multiplied by the repetition count. Five repetitions receive 4000 s.
The smoke and claim profiles keep their fixed 900 s and 6000 s timeouts.
`reps` must be an integer from 1 to 6000.

The hosted runner requires real TUN, private network namespaces and netem. It
runs the IPv4/IPv6 client matrix in XUDP, legacy and packetaddr modes, alongside
the XUDP protocol suite with mixed traffic, payload verification and restart
recovery. Small-request p95 under mixed load must stay at or below 2 s. The lab
server runs with 50% of one vCPU and 768 MiB of memory.
The paired benchmark uses the same limits for both builds, three repetitions,
250 ms RTT and zero configured loss. TCP and HTTPS throughput must be at least
98% of the baseline. Every planned DNS query must be sent, and every query must
answer without an error. Every UDP echo request must receive a reply. UDP echo,
DNS and HTTP/3 p50/p95/p99 latency must stay within 102% of baseline. The UDP
packet rate is informational only because the client driver core bounds it.
Incomplete evidence, a noisy or producer-bound run, missing replies, HTTP/3
retries or server OOM fail the gate. The workflow keeps the evidence as an
Actions artifact.

## Architecture

- `beam` owns process lifecycle, CLI, config loading, logging, signals, and the
  listener. It contains no protocol implementation.
- `beam-core` owns TLS and ClientHello handling, REALITY, VLESS, Vision, XUDP,
  legacy UDP, packetaddr, relay logic, config validation, and metrics. It stays
  testable without root or a network.
- `beam-sys` owns the only `unsafe` code: `splice`, fd helpers, socket options,
  and eventfd. See [AGENTS.md](AGENTS.md#golden-rules) for the `unsafe` rule.

The TLS path pre-reads and authenticates ClientHello, then uses rustls through
a record-bounded `TlsStream` that owns the TLS record boundary. TCP uses a
blocking `splice(2)` fast path with a bounded async-copy fallback. Startup
clamps splice concurrency to the pipe-page soft budget at the 4 KiB minimum
pipe size and logs soft pages, requested tasks, and used tasks; a soft limit of
zero means unlimited, and a soft limit that leaves no capacity above the
1024-page reserve sets a zero-task limiter so every direction uses the async
copy fallback. XUDP uses
one outbound UDP socket per session, a per-mux session table, and a
process-wide session limiter.

## Repository layout

| Path | Holds |
|---|---|
| `crates/` | The Rust workspace: `beam`, `beam-core`, `beam-sys`. |
| `deploy/` | Distribution-agnostic systemd service install: `beam.service`, `beam-install.sh`, and the optional liveness probe/timer. |
| `scripts/` | Developer tooling that runs on your machine and is never installed. |
| `bench/` | The TUN A/B benchmark and soak harness. Its own test is `tests/bench/`. |
| `tests/` | Rootless suites, plus the TUN harness and its Rust origin in `tests/tun/`. |
| `fuzz/` | cargo-fuzz targets, kept in a separate workspace. |
| `clients/` | Optional tray clients for Linux and Windows. Not needed to run the server. |
| `docs/` | Server runbook, client setup, and the historical audits. |

## Compatibility

This section is the single source of truth for wire behavior. Update it and
add a test when wire behavior changes. The server must stay compatible with
stock clients that use the same UUID, public key, short ID, SNI, and flow.
That compatibility is the supported path, and the TUN interop workflow proves
it end to end against pinned sing-box 1.14.4 and Xray 26.3.27.

The tray clients in `clients/` are optional convenience. Nothing in this
section depends on them, and any standard Xray or sing-box client that speaks
VLESS with `xtls-rprx-vision` is expected to work.

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
- A cover relay is also cut at a fixed 120 s maximum lifetime
  (`COVER_MAX_LIFETIME`), because the idle timeout never fires while a probe
  keeps both directions busy. Cutting an active relay bounds unauthenticated
  admission retention; no config key controls it.

### VLESS and Vision

- VLESS request: version, 16-byte UUID, addons, command, optional port and
  target address. Commands: TCP, UDP, Mux, Rvs. The response is always
  `00 00`; unknown or malformed commands are rejected. Rvs is recognised but
  not served: the server writes `00 00` and closes, because reverse streams
  are server-side in stock Xray and stay out of scope here.
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
- A TCP destination with port 0 is rejected before any lookup or dial. Port 0
  stays valid only for the legacy UDP packetaddr sentinel
  (`sp.packet-addr.v2fly.arpa`), which selects packetaddr framing; a fixed UDP
  destination with port 0 is rejected before a socket is bound.

### XUDP, legacy UDP, and packetaddr

- XUDP is carried in VLESS Mux frames: metadata length, stream ID, status,
  option, optional destination, optional GlobalID, payload length, payload.
  Statuses are New, Keep, End, KeepAlive; options are Data and Error.
- Clients generally send New/Keep and close the flow with TCP FIN; do not
  require an End. Keep frames may carry a per-datagram destination; empty or
  non-Data Keeps do not update the session destination, and address-less Keeps
  reuse the last destination accepted from `New` or a non-empty Data Keep.
  Replies are Keep with Data, plus End on closure (Error only when relay
  failed). The empty-mux timer pauses while an accepted DNS lookup is pending.
  Only requests accepted by the UDP socket or send queue refresh session idle
  time. A transient send error (`WouldBlock`, `TimedOut`, `Interrupted`) or the
  100 ms send deadline drops only that datagram and never closes the session; a
  datagram that fails the immediate send is retried once through the bounded
  send queue, and other send errors close the session with an error End.
  Removing a live session owns its terminal report, including a reply
  failure already observed when it closes. An unknown stream ID gets a clean
  End and is discarded.
- Accept zero GlobalID and per-frame destinations from sing-box. A nonzero
  GlobalID may reattach a retained socket only within the same mux and user;
  never use GlobalID as identity or policy.
- XUDP datagram payloads are capped at 8192 bytes; empty or oversize
  datagrams are dropped. Legacy UDP is capped at 8190 bytes. packetaddr uses
  the magic `sp.packet-addr.v2fly.arpa` destination and carries an inner
  address per datagram. A new packetaddr destination occupies a table slot
  after its first successful send. A 100 ms send timeout or a transient send error
  (`WouldBlock`, `TimedOut`, `Interrupted`) on the fixed-destination legacy
  path drops only that datagram; other send errors close the association.
  A transient receive error (`WouldBlock`, `TimedOut`, `Interrupted`) retries
  after a 1 ms backoff while the idle deadline still bounds the session; other
  receive errors close the association. An idle expiry is a normal close, not
  a failure: like a peer EOF it runs one bounded shutdown that flushes the
  buffered reply and sends `close_notify` before FIN, and a shutdown that fails
  keeps the close normal. An association that ends at a failed stage is
  dropped without writing, because its stream state is unknown. The failing
  stage (`stream read`, `stream write`, `UDP send`, `UDP receive`, `socket
  bind`, `destination resolution`, `stream shutdown`) is named in the error. A packetaddr reply is admitted only when
  `2 + source header (7 bytes for IPv4, 19 for IPv6) + payload` fits the
  datagram cap; a v4-mapped source uses the 7-byte header, and a larger reply is
  dropped without refreshing idle time.
- Session sockets remain unconnected and accept replies from arbitrary UDP
  sources. This preserves stock XUDP/full-cone behavior (STUN, WebRTC, P2P).
  Only a valid, non-empty reply that passes size/frame/queue/byte-budget checks
  and is handed to the writer refreshes the idle clock. Zero-length, oversize,
  encoding-drop, queue-drop, and budget-drop datagrams do **not** refresh it.
  "Valid" here means size/frame/admission-valid, not application-validated: a
  sender that can reach the ephemeral port with an admissible datagram can
  still keep the session active while the mux remains open. The queue and byte
  budgets bound outstanding memory, not session lifetime; this is inherent to
  keeping arbitrary-source/full-cone replies.
- Domain `New`/`Keep` frames are queued per session id while a bounded
  per-mux resolver performs DNS; the lookup owner and suffix are tracked
  separately, results carry a generation, and a newer GlobalID cancels older
  pending New frames. In-flight lookups are coalesced by domain, port, and
  family, so concurrent sessions for one uncached destination share a single
  lookup, its waiters are served in arrival order, and its result is cached
  even when every waiter was superseded. IP frames, queued suffixes, and rejected replies retain
  their ordering. Resolved domains are cached for 300 seconds. A mux runs at
  most four concurrent lookups; the resolver permit is held until the result
  is queued, so a full result channel backpressures the request queue instead
  of spawning unbounded tasks. Pending payload has a process-wide 4 MiB budget
  plus bounded metadata, and UDP send/close waits are capped at 100 ms. The
  cache key is the domain, port, and requested address family, so a
  family-constrained lookup never answers an unconstrained one. Only a later
  `New` that would itself be accepted (UDP target, usable destination, payload
  within the datagram cap) supersedes the pending `New` of the previous
  attachment: a rejected `New` cannot cancel an accepted lookup. The
  superseded result is dropped without creating or ending a session, and so
  are the frames the old attachment queued before that `New` while no session
  owns the id: they would otherwise answer with an `End` that the peer applies
  to the replacement created next. A live session keeps those frames and its
  own terminal `End`. If several acceptable replacements are already queued,
  only the last is opened; intermediate attachments and their queued frames
  are dropped without an `End`. Frames after the final replacement run in
  arrival order, and a frame rejected by a full resolver queue gets an `End`
  only when no session owns its stream id. A non-UDP or destination-less `New` likewise
  cannot end an existing session: it is dropped while that session is live.
  A `New` for an id whose live session carries a different GlobalID is also
  dropped without an `End`, so that session keeps the id until its own close
  path ends it. This is not universally nonblocking: a sequence of slow
  domains, a congested send, or many close operations can still delay a mux
  briefly.
- Reply bytes are bounded by a 2 MiB per-mux budget inside the 32 MiB
  process-wide budget; one slow reader cannot hold the whole global allowance.
- An empty mux closes after `session_idle_timeout` even while KeepAlive frames
  arrive or a retained GlobalID socket is waiting for `close_expiry`. Retained
  sockets do not extend the empty-mux timer.
- XUDP limits come from `limits.max_xudp_sessions` and
  `limits.xudp_recv_buffer_bytes` (example defaults: 256 sessions and 128 KiB
  per socket). A mux holds at most half the global active slots. XUDP idle
  expiry is at most 60 seconds even when `idle_timeout_ms` is 300 seconds.
- A GlobalID socket keeps one global session slot through retention and
  reattachment. The slot is shared with any queued work that still owns the
  session, so evicting or expiring the retained entry cannot release a permit
  while an old datagram still owns the socket, and a reattach cannot count the
  same socket twice.
- Legacy/packetaddr UDP holds one stream permit per VLESS `Command::Udp`
  connection, and the pool equals `max_xudp_sessions` (256 with the example
  config); a stream owns one relay socket, or up to two in packetaddr mode when
  both address families bind. The legacy idle clock is capped at 60 seconds
  like the XUDP one, so with the documented 300 s `idle_timeout_ms` an idle
  flow releases its permit five times sooner than the TCP relay would; a send
  or an admitted reply resets the clock. The effective clock is
  `min(idle_timeout_ms, 60 s)`, so a smaller configured value shortens UDP
  flows too. Legacy relay sockets keep the kernel's default receive buffer;
  only XUDP requests `xudp_recv_buffer_bytes`. A stub resolver opens one UDP
  socket per query, so a DNS burst is a burst of streams: it is admitted from
  this pool and, at the cap, refused as `TlsServerError::LegacyUdpLimited` and
  counted in `legacy_udp_limited`. `max_xudp_sessions` also sizes the XUDP
  kernel buffer budget, so lowering it to save memory lowers this pool as well.
- UDP bind, resolve, stream-write, and shutdown waits use their own deadline,
  `min(idle_timeout_ms, 30 s)` with a 1 s floor, instead of the TLS
  `handshake_timeout_ms`. Retuning the handshake deadline therefore does not
  change how long UDP work can retain capacity.

### TLS stack, cover, and MTU

- TLS is rustls 0.23 + aws-lc-rs with the `prefer-post-quantum` feature.
  Initialize `aws_lc_rs::default_provider()` at startup. Do not replace it
  with BoringSSL or a custom TLS implementation for v1.
- Cover parity is **SNI-level**: matching SNI, certificate, TLS 1.3/PQ group,
  cipher behavior, and normal unauthenticated forwarding are enough. Plaintext
  extension order and encrypted-flight size may differ; do not gate a deploy
  on them.
- The default cover is `whatsapp.net:443`, PQ-capable (`X25519MLKEM768`), TLS
  1.3, AES-128-GCM, ALPN `h2`. Authenticated connections do not dial the cover.
- Set `TCP_MAXSEG=1400` before connecting every target and cover socket. This
  creates an effective advertised MSS around 1388 and avoids 1460-byte PMTU
  black holes on some paths. Host TCP traffic is not clamped.
- Destination and cover dials share a process-wide 32-job DNS admission
  limit. Address literals are dialed without a lookup, so an exhausted
  resolver budget never delays an IP target. A blocking `getaddrinfo` job
  keeps its permit after the caller's dial deadline, so a resolver outage
  cannot grow the blocking pool past that bound.
- Relay idleness is a property of the whole connection, in both the
  authenticated and the cover relay: a direction with nothing to read, or a
  sink that stops accepting bytes, is retried while the opposite direction
  keeps the shared activity clock recent, and the relay ends once the whole
  connection has been idle for `idle_timeout`. A blocked write retries the same
  offset, so a slow sink cannot lose bytes, and it cannot spin: every write is
  bounded and a zero-length write ends the direction. The one-way splice relay
  shares that clock, so a stalled splice sink is kept alive and cut by the same
  rule. Once the source has finished, a sink that no longer accepts the bytes
  still buffered in the pipe ends at the 30 s shutdown deadline and reports a
  timeout, so a half-open sink is not recorded as a completed copy. That error
  also drops the opposite Vision direction: an upload that stalls at the
  shutdown deadline truncates a download that was still working.
- Keep `net.ipv4.tcp_mtu_probing=0` unless a measured PMTU failure justifies a
  change. Client TUN profiles use MTU 1500; lowering that MTU loses some
  HTTP/3 paths and stalls large H3 bodies in gVisor.

## Security notes

- **Single-user only.** One user ID, one inbound, and no account system. beam
  makes no multi-tenant claim and has no per-user isolation, panels, billing,
  or per-user limits. Do not expose it as a shared proxy.
- Treat every byte from the network as hostile. Authentication failures go to
  the cover; malformed authenticated input is rejected.
- Keep the config and private key out of git. Use mode `0600` locally and
  root:beam `0640` on the service host. Never log secrets or raw key material.
- Authentication material uses constant-time comparison. `unsafe` stays in
  `beam-sys`, and each block needs a `// SAFETY:` invariant. See
  [AGENTS.md](AGENTS.md#golden-rules).
- Known gaps and test gaps are tracked in [`ISSUES.md`](docs/ISSUES.md) and
  [`TODO.md`](docs/TODO.md). Report vulnerabilities privately per
  [`SECURITY.md`](SECURITY.md); contributions follow
  [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the build and test commands, the
change rules, and the paths to the architecture and audit notes.

## License

Released under the [MIT License](LICENSE).
