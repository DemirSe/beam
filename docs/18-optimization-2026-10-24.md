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
- takes a small, separate pre-auth permit (16–128 depending on
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
answers. The exact-ClientHello fallback test still passes.

### The blocking relay pool has a hard cap and an async fallback

Two `spawn_blocking` splice tasks per Vision Direct connection meant the
160-thread pool supported only about 80 pairs. Beyond that, `spawn_blocking`
queued a handoff with no deadline: the connection stopped forwarding while
still holding its admission permit. A process-wide splice semaphore now
reserves 40 threads for cover relays/dials and falls back to the bounded async
copy path when the splice budget is exhausted. The fallback is slower but
never hangs.

Accepted and destination sockets now also set TCP keepalive (60 s idle, 15 s
interval), and a half-closed Vision direction uses a 30 s shutdown timeout
instead of the 300 s relay idle timeout. Dead mobile mappings release their
thread and pipe sooner.

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
when the peer never sent `close_notify`). A regression sends `close_notify`
while keeping the TCP socket open and asserts that the server sees EOF within
one second.

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

The writer now carries at most one partial application-data record across
`poll_write` calls, processes the complete prefix, and still switches to Direct
when the record completes. If Direct is planned, the carried raw tail is
appended after the queued Direct block. A regression splits a record inside
the header and again inside the body and asserts the Direct block and raw tail.

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
  once per batch. A full `End` queue no longer tears down unrelated flows.
- Domain resolution in the mux read loop is bounded to 2 s instead of the
  generic 10 s I/O timeout.
- The reply batch buffers are allocated lazily.

### Smaller hardening

- Unknown non-empty VLESS flows are rejected instead of silently relayed as
  unframed bytes; a typo cannot corrupt the destination stream.
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
- `cargo test --workspace`: **279 tests** pass (253 core unit tests, 2 TLS
  adapter integration tests, 1 stock ClientHello fixture, 23 other integration
  tests).
- Full-TUN harness: **8/8 PASS** (`xudp`, MTU 1500) and a 1,333,889-byte H3
  body passes.
- New regressions: non-TLS cover fallback, `close_notify`, split-record
  Direct, 2,000 tiny Vision blocks, XUDP stop-before-first-poll permit
  release.
- No-TUN capacity: beam **913.7 MB/s** vs stock **651.8 MB/s** = **1.402x**
  (previous beam run 890.5 MB/s; same harness, noisy host).
- Churn: 3,000 requests at concurrency 32 in **15 s**, 5,000 at 64 in **26 s**,
  all HTTP 200, RSS +0.9 MiB, threads 2, fds 10.
- Quick full-TUN (host load was high, so headline-ineligible):
  TCP download 1.051x/1.012x, upload 1.024x/1.006x, HTTPS 1.029x, UDP echo
  **1.232x** (52.10 vs 42.28 kpps), RSS 0.252x stock, server CPU/GiB
  0.755–0.876x stock.

## Remaining work

- 24-hour soak and privileged syscall/wakeup acceptance are still pending.
- TLS cover parity remains the largest traffic-shape gap (extension order and
  encrypted-flight size); the authenticated path still does not dial the cover.
- XUDP reply scheduling is FIFO; a very large QUIC burst can still delay DNS.
  Per-session fairness and counters are the next step.
- Legacy VLESS UDP/packetaddr are not covered by the 256-session XUDP limiter.
- Domain destinations are resolved per `New`/address `Keep`; a bounded TTL
  cache would remove repeated resolver round trips.
- Host conntrack (`nf_conntrack_max=8192`, 5-day established timeout) and pipe
  page limits are live-only tuning and should be raised/shipped before a 10k
  churn test.
- Production deployment of this pass must use `BEAM_KEEP_CONFIG=1` and verify
  the live config hash, listener, cover certificate, DNS, and IPv6 afterward.
