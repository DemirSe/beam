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
- `cargo test --workspace`: **287 tests** pass (261 core unit tests, 2 TLS
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
  **10,000 at 64 in 55 s**, **50,000 at 128 in 274 s**, and a final-binary
  **100,000 at 128 in 582 s**; every request returned HTTP 200, RSS moved
  7.9 → 10.5 MiB, threads stayed at 2, and fds stayed at 10.
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

## Upload CPU follow-up (audited, benchmarked, deployed)

A local-only follow-up reduces upload/read-path copying:

- `TlsStream` now reads rustls plaintext directly into the caller's `ReadBuf`
  instead of stack -> `Vec` -> caller. Handshake buffering remains for the
  pre-data phase.
- `VisionStream` copies large block content (>= 4 KiB) straight into the
  caller's buffer; only an excess tail goes through `read_out`.
- A stack chunk table for `VisionStream::plan_and_queue` was tried and then
  reverted: the A/B showed no reliable gain and a possible download-CPU noise
  signal, so the original `Vec` path stays.

An adversarial review (GPT-6.1 Sol, high reasoning) initially returned
**DO NOT DEPLOY** and found three ordering/loss bugs before this benchmark:

- Raw handoff dropped plaintext still buffered inside rustls. `take_plaintext`
  and `into_raw` now drain rustls first, and real-TLS regressions cover both
  paths.
- Empty `End`/`Direct` blocks could leave coalescing enabled, so passthrough
  or raw bytes were returned before buffered block content, and the read
  handoff could be published too early. Framing transitions now stop
  coalescing and drain `read_out` first.
- The empty-block limit and `MAX_READ_OUT` paths returned an empty success
  with data buffered, which callers read as EOF. Both now drain buffered
  output before returning.

Method: no-TUN stock Xray SOCKS client, HTTP POST, server CPU summed from
`/proc/<pid>/task/*/schedstat` (nanosecond resolution), 1 GiB (or 4 × 128 MiB)
per sample, 10 samples per arm, per-sample alternating old/new order, pinned
server/client/target/driver cores. The download control used the same harness
with HTTP GET. The baseline is `f33f07fe…`; the candidate is `d017c131…`.
Earlier coarse-tick A/B numbers are superseded by this run.

| Scenario | `f33f07fe` | follow-up `d017c131` |
|---|---:|---:|
| Upload 1 flow, 1 GiB, CPU/GiB | 0.9287 s | **0.8617 s** (-7.2%) |
| Upload 1 flow, wall time | 1.1894 s | **1.0824 s** (-9.0%) |
| Upload 4 flows × 128 MiB, CPU/GiB | 0.9208 s | **0.8734 s** (-5.1%) |
| Upload 4 flows, wall time | 0.5785 s | **0.5508 s** (-4.8%) |
| Download 1 flow, 1 GiB, CPU/GiB | 0.4946 s | 0.4907 s (-0.8%, noise) |
| Download 1 flow, wall time | 1.4007 s | 1.4198 s (+1.4%, noise) |
| 120×16 MiB HTTPS | 120/120 | **120/120**, 2.99 s |
| TLS 1.2-only 8×4 MiB | 8/8 | **8/8** |
| Full-TUN 8/8 + 1.33 MiB H3 | pass | **pass** |

Raw samples, binary hashes, logs, and configs are retained at:

- `/tmp/opencode/upload-ab-20261024T120443Z` (1 GiB, 1 flow)
- `/tmp/opencode/upload-ab-20261024T120631Z` (4 × 128 MiB)
- `/tmp/opencode/download-ab-20261024T120810Z` (1 GiB download control)

The upload gain is consistent (5–7%), the download control is flat within
noise, and RSS stayed around 8 MiB. `cargo fmt`, clippy, and the full test
suite pass (**296 tests**), including a real-TLS Vision Direct integration
test with a small caller buffer, rustls-held plaintext, and subsequent raw
socket bytes.

Deployed on 2026-10-24 12:31 UTC with `BEAM_KEEP_CONFIG=1`; the live binary
is now `d017c131…` and the config hash is unchanged. The post-deploy mobile
hotspot run passed download/upload, DNS, IPv6, and payload-integrity checks;
see the deployment section for details.

## Mobile hotspot validation

After deployment the client ran on a phone hotspot (`Demir`, signal 100%,
1170 Mbit/s link, TUN MTU 1500). Direct-vs-VPN samples alternated:

| Test | Direct | VPN TUN |
|---|---:|---:|
| Download median, 3×32 MiB | 13.66 MB/s* | 14.56 MB/s* |
| Upload median, 3×8 MiB | 135 KB/s | 102 KB/s |
| `example.com` TTFB | 354–453 ms | 475–618 ms |
| DNS | — | 10/10 |
| IPv6 HTTPS | unavailable | **200** |
| H3/QUIC | — | refused (client block) |

\*One direct download sample fell to 4.31 MB/s; mobile throughput varied
widely, so the VPN/direct comparison is directional only. All six 8 MiB
uploads returned 200 with exact byte counts. The mobile uplink (~0.1–0.3 MB/s)
was the bottleneck, not beam.

Receiver-side integrity through the live tunnel:

- Random 4 MiB upload: client and receiver SHA-256 both
  `cf83b7711e8ae6855e7dfce0d49971c41806620c9e9de8e53deb2ccaa638f78a`
  (12 s).
- Random 32 MiB download: both sides
  `aca592fa47aae9017a9777c9d084b8dda205618305e0ca10432b7826e9675d57`
  (9.89 MB/s).

The server stayed active with `NRestarts=0`, no UDP errors, and no journal
warnings during the run.

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

Deployed on 2026-10-24 12:31 UTC with `BEAM_KEEP_CONFIG=1` (upload follow-up):

- Binary SHA-256:
  `d017c1311f2075fe546fe80d97af938208514f35fac9044acda50c2a7f777842`
- Live config SHA-256 unchanged:
  `c0abace24e0f839a3ae3c1300d3f79b94ccfee437df5e7a4d8ec67b1b2722a02`.
- Backups were created by `bootstrap.sh` with stamp `20261024T123121Z`.
- Service active, `NRestarts=0`, listener `0.0.0.0:443`, config check passed.
- Post-deploy mobile hotspot TUN: 4 MiB upload and 32 MiB download SHA-256
  matched end to end, DNS 10/10, IPv6 200, H3 still refused client-side.

Earlier deployment, 2026-10-24 10:05 UTC with `BEAM_KEEP_CONFIG=1`:

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
