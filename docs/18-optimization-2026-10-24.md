# Optimization and robustness pass — 2026-10-24

This pass started from `2936cab` and focused on behavior that a long-lived
single-user mobile client actually exercises: pre-auth scanners, browser
connection counts, idle HTTPS keepalives, XUDP session churn, DNS/QUIC bursts,
large downloads, and restarts. The live VPS remained on the old binary while
the local full-TUN and capacity harnesses ran.

## Changes

### Admission is no longer blocked by pre-auth connections

`main` used to acquire the global `max_connections` permit *before* spawning a
connection task. Once the pool was full, the accept loop stopped calling
`accept`, the listener backlog filled, and a cheap scanner could take the
service down without authenticating.

The accept loop now:

- accepts continuously;
- takes a small, separate pre-auth permit (16–256 depending on
  `max_connections`) only for the ClientHello/REALITY phase;
- drops excess pre-auth connections instead of blocking the loop;
- acquires the authenticated connection permit only after REALITY succeeds;
- releases the pre-auth permit before cover forwarding.

A local regression with `max_connections = 8` and eight idle one-byte sockets
reproduced the old failure and verifies the fix:

| Binary | Legitimate request after 8 idle sockets |
|---|---|
| old `bd17ac26…` | timed out after 6.00 s with `000` |
| new | HTTP 200 in 0.005 s |

A second check holds 128 one-byte sockets against the production-shaped
`max_connections=1024` config and then makes one legitimate request. With the
128-slot build the request was reset while the slots were full; with the final
256-slot budget it returned HTTP 200 in 5 ms. An attacker can always fill any
fixed budget, but the accept loop and authenticated data path no longer stop.

The pre-auth ClientHello deadline is capped at 5 s even when the configured
handshake timeout is 10 s.

### Cover fallback for non-TLS and over-limit first records

`read_client_hello_record` used to read the declared record body before any
cover decision. A plain `GET / HTTP/1.1` decoded a bogus 12064-byte length and
was never sent to the cover; the connection simply closed after the handshake
timeout. That is a cheap active-probe distinguisher.

The reader now validates the five-byte header first:

- non-TLS content/version, or a record larger than the configured bound, is
  forwarded to the cover immediately together with any already-read bytes;
- a peer that stalls or closes mid-record forwards the partial prefix;
- only a plausible, complete TLS record is parsed for REALITY.

`crates/beam-core/tests/tls_server.rs` now has a mock-cover regression that
sends an HTTP request and asserts that the cover receives the prefix and
answers. The exact-ClientHello fallback test still passes. Oversized and
stalled-partial first records use the same forward path but do not yet have a
dedicated timing/cover-capture regression.

### The blocking relay pool has a hard cap and an async fallback

Two `spawn_blocking` splice tasks per Vision Direct connection meant the
160-thread pool supported only about 80 pairs. Beyond that, `spawn_blocking`
queued a handoff with no deadline: the connection stopped forwarding while
still holding its admission permit. A process-wide splice semaphore now
reserves 40 threads for cover relays/dials and falls back to the bounded async
copy path when the splice budget is exhausted. The fallback is slower but
never hangs. The reserve assumes the production 160-thread pool; setting
`BEAM_MAX_BLOCKING_THREADS` below about 40 is a test-only configuration.

Accepted and destination sockets now also set TCP keepalive (60 s idle, 15 s
interval). A Vision direction that has itself reached EOF uses a 30 s
shutdown timeout instead of the 300 s relay idle timeout. The sibling
direction keeps the normal idle deadline until it finishes; a shared sibling
deadline is not implemented. Dead mobile mappings release their thread and
pipe sooner.

### Graceful shutdown without a long outage

`SIGTERM`/`SIGINT` now stop the listener, wait up to 2 s for established tasks,
and then use `Runtime::shutdown_timeout(3 s)` as the final bound for blocking
splices. A controlled test with one held socket exits in about 2.05 s. A
`SIGHUP` is logged and ignored instead of killing the process.

### TLS `close_notify` is a real EOF

`TlsStream` used to treat rustls `Ok(0)` as "no data" and a bare TCP FIN as a
clean EOF. A client could send `close_notify`, keep TCP open, and leave the
target half-open until the 300 s idle timeout; conversely, a truncated stream
was reported as clean.

`TlsStream` now records a clean `close_notify`, returns EOF once buffered
plaintext is drained, and lets rustls classify socket EOF (`UnexpectedEof`
when the peer never sent `close_notify`). The relay treats that error as a
half-close, so a bare FIN does not abort the opposite direction. Regressions
cover `close_notify` with TCP kept open and the bare-FIN relay case; the
`close_notify` assertion uses a 200 ms deadline so an unrelated socket wakeup
cannot mask a missing EOF check.

### Vision reader: linear parsing and coalesced writes

The reader consumed each block with `Vec::drain`, memmoving the tail for every
tiny block, and returned after one block. A post-auth client sending 5-byte
blocks could amplify memory movement by hundreds of times and force one small
destination write per block.

The reader now:

- consumes blocks with a cursor and compacts only when more input is needed;
- coalesces complete block content into a bounded 64 KiB read batch;
- keeps the empty-block yield and Direct/End ordering intact.

A 2,000-block regression passes. The reader's Direct transition and raw-tail
ordering are unchanged.

### Vision writer: partial inner TLS records no longer defeat Direct

The Direct trigger only fired when the buffer handed to `poll_write` ended on a
complete inner TLS record. Because `read()` boundaries do not align with TLS
records, a busy server could keep a connection framed for its entire lifetime.

The writer now carries at most one partial TLS record (handshake or
application data) across `poll_write` calls, processes the complete prefix,
and still switches to Direct when the application-data record completes. If
Direct is planned, the carried raw tail is written after the queued Direct
block; if End is planned, it is flushed through outer TLS before any later
write. Regressions cover split headers, split bodies, Direct tails in the same
write, End/partial tails, and one-byte write boundaries.

### TLS record reads use one buffer

`RecordRead` used to allocate a body `Vec` and then copy it into a second
record `Vec` for every TLS record. It now stores the header and body in one
buffer. This removes one allocation and one full ciphertext copy per record.

### XUDP lifecycle fixes

- `Session::stop` used `watch::Sender::send`, which does not store the stop
  value when a newly spawned reply task has not subscribed yet. A mux that
  closed in that window leaked the reply task, its UDP socket, and its global
  permit forever. `send_replace` plus `mark_closed` makes teardown
  deterministic; timed-out joins are aborted.
- XUDP sessions now expire after at most 60 s of idleness instead of inheriting
  the 300 s TCP relay timeout. Xray/sing-box clients normally close UDP flows
  with the TCP stream, not an `End` frame, so the 256-slot global cap could
  otherwise fill with stale sessions.
- A closed GlobalID socket is drained (bounded) before retention; if it still
  has queued data, it is dropped instead of being retained with stale replies.
- Reply writes batch already-queued frames (up to 32 frames / 64 KiB) and flush
  once per batch. A full `End` queue no longer tears down unrelated flows;
  reply-budget permits are released before waiting for the next frame.
- Domain resolution in the mux read loop is bounded to 2 s instead of the
  generic 10 s I/O timeout.
- The reply batch buffers are allocated lazily.

### Smaller hardening

- Unknown non-empty VLESS flows are rejected instead of silently relayed as
  unframed bytes; a typo cannot corrupt the destination stream.
- Legacy VLESS UDP and packetaddr streams are capped at 64 process-wide, so
  compatibility mode cannot bind sockets outside the XUDP budget.
- Destination dials are capped at 5 s.
- Pipe-size warnings are emitted once, then debug-level.
- Splice batching only enables between 2 MiB/s and 500 MiB/s, so paced video,
  voice, and game traffic does not pay the 500 µs coalescing sleep.
- Logs disable ANSI; `RUST_LOG` overrides and diagnostic log levels emit a
  startup warning.
- `deploy/beam.service` adds `ExecStartPre=--check`, `TimeoutStopSec=20s`,
  `RestartSec=3s`, start limits, `TasksMax=512`, and `RestrictRealtime=yes`.
- `deploy/bootstrap.sh` validates the new binary against the live config before
  replacing the installed binary, and installs through a same-directory rename.

## Verification

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`: **286 tests** pass (260 core unit tests, 2 TLS
  adapter integration tests, 1 stock ClientHello fixture, 23 beam-sys unit
  tests).
- Full-TUN harness: **8/8 PASS** (`xudp`, MTU 1500) and a 1,333,889-byte H3
  body passes.
- New regressions: non-TLS cover fallback, `close_notify`, bare-FIN
  half-close, split-record Direct/End tails, 2,000 tiny Vision blocks, XUDP
  stop-before-first-poll permit release, and empty/unknown VLESS flows.
- A local TLS 1.2-only origin (which takes the End path, not Direct) completed
  eight concurrent 4 MiB downloads through the stock SOCKS client without a
  TLS error; body lengths were verified (1.05 s). This exercises the End carry flush.
- No-TUN capacity on the final binary: beam **873.1 MB/s** vs stock
  **624.7 MB/s** = **1.398x**; an earlier run measured 913.7 vs 651.8
  (**1.402x**). Same harness, noisy host.
- Churn: 3,000 requests at concurrency 32 in **15 s**, 5,000 at 64 in **26 s**,
  **10,000 at 64 in 55 s**, **50,000 at 128 in 274 s**, and **100,000 at 128
  in 566 s**; every request returned HTTP 200, RSS moved 8.2 → 10.3 MiB,
  threads stayed at 2, and fds stayed at 10.
- Concurrent HTTPS: 120 simultaneous 16 MiB Vision Direct downloads all
  completed with body lengths verified, 3.00 s wall time, server RSS 16.9 MiB
  and 96 threads at peak. This lands near the splice budget without a stalled
  handoff.
- Forced fallback: with `BEAM_MAX_BLOCKING_THREADS=8` (one splice permit) and
  four concurrent 8 MiB HTTPS downloads, all four completed (1.05 s) with
  verified body lengths through the async path, proving that budget
  exhaustion no longer hangs a handoff.
- Quick full-TUN (host load was high, so headline-ineligible): across two
  runs TCP download was 1.01–1.05x, upload 1.01–1.43x, HTTPS 1.03–1.31x,
  and UDP echo **1.23–1.96x** (beam held 50–52 kpps while the stock arm
  varied 25–42 kpps). RSS was 0.24–0.25x stock and server CPU/GiB was
  0.73–0.88x stock. Treat the ratios as directional; the client core was
  saturated in every run. Those quick runs used the intermediate
  `7671abdb`/`50df25e7` binaries; the final `f33f07fe` binary was separately
  checked with full-TUN, large H3, no-TUN, and the verified bulk runs above.

## Remaining work

- 24-hour soak and privileged syscall/wakeup acceptance are still pending.
- TLS cover parity remains the largest traffic-shape gap (extension order and
  encrypted-flight size); the authenticated path still does not dial the cover.
- XUDP reply scheduling is FIFO; a very large QUIC burst can still delay DNS.
  Per-session fairness and counters are the next step.
- Legacy UDP/packetaddr now have a separate 64-stream cap but are still not
  part of the XUDP 256-session budget.
- Domain destinations are resolved per `New`/address `Keep`; a bounded TTL
  cache would remove repeated resolver round trips.
- Host conntrack was raised to 65536 (1 h established / 30 s TIME_WAIT) and
  shipped in `deploy/`; a 10k churn against the live host has not been run.
  Pipe page limits remain live-only tuning.
- SIGHUP is logged and ignored; hot reload is not implemented.
- `flush()` intentionally does not emit an incomplete inner TLS record; the
  next write or `shutdown()` completes it. A caller that flushes mid-record
  must send the remainder before expecting downstream bytes.

## Deployment

Deployed on 2026-10-24 10:05 UTC with `BEAM_KEEP_CONFIG=1`:

- Binary SHA-256:
  `f33f07fe7d7ef24d4d9fd8ae52b591c79e1028c79e77f65e8584029df0e1eb2c`
- Live config SHA-256 is unchanged:
  `c0abace24e0f839a3ae3c1300d3f79b94ccfee437df5e7a4d8ec67b1b2722a02`
  (`log.level = "warn"`, 1024 connections, 10 s handshake, 300 s TCP idle).
- Backups were created by `bootstrap.sh` with stamp `20261024T100534Z`.
- Service active, `NRestarts=0`, listener `0.0.0.0:443`, cgroup peak 2.9 MiB
  immediately after start.
- IPv4/IPv6 egress, HTTPS, HTTP, DNS, and the local TUN MTU 1500 client pass.
- The cover path returns the real WhatsApp certificate (`302`, verify 0), and
  a plain HTTP GET to the live listener receives the cover's TLS alert instead
  of a silent timeout.
- Host conntrack was raised to 65536 with 1 h established / 30 s TIME_WAIT
  timeouts and persisted in `/etc/sysctl.d/99-beam-conntrack.conf`; the repo now
  carries `deploy/99-beam-conntrack.conf`.
- A low-rate live observation (HTTPS + DNS + IPv6 every minute, 1 MiB HTTPS
  every ten minutes) ran for about four hours across several deployments;
  about 2.5 hours were on the final binary. It is not a final-binary 24-hour
  soak, and its fd/restart columns were malformed because the sampler ran
  without permission to read the service fd table.
