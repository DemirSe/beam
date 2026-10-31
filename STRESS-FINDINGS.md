# Open stress findings — 2026-10-31

This file is intentionally separate from `README.md` for the findings that are
still open. Findings 1 and 2 have been fixed, re-verified, and deployed; their
durable invariants are now in `README.md`, while the remaining items below stay
here until resolved. The initial audit made no code changes; the fixes are
commits `2163c0a` and `e0ca0bc`. Production was updated after each fix. The lab
is stopped and its config was restored after the temporary idle-timeout
experiment. Initial binary under test: final `1007354…` code (embedded identity
`b4d9382`, deployed build `a41facef…`).

This note records the results of three read-only code audits plus the QEMU lab
run. It distinguishes **lab-reproduced** findings from code-confirmed risks.
Do not treat the latter as fixed or as measured production incidents.

## Lab results

Three VMs, fixed 2 GHz benchmark profile, final lab binary, `max_connections =
1024`, `max_xudp_sessions = 1024`, `xudp_recv_buffer_bytes = 128 KiB`.

### Mixed soak

- Duration: **10 min 37 s**.
- Client workload: HTTP (24,300 requests), DNS (8,100), churn (6,100), HTTPS
  (130), UDP (31,000 datagrams), H3 (6 probes), sequential/moderate
  concurrency.
- Application errors: **0**.
- Server: RSS stayed at **93,920 KiB** (allocator plateau after earlier burst;
  no growth during the soak), fds 12–478, threads 2–5,
  `NRestarts=0`, no OOM.
- XUDP: no `xudp_rejected_per_stream`, no `xudp_rejected_global`, no
  `xudp_replies_dropped`, no `xudp_end_dropped`; idle sweep closed 62
  sessions. `xudp_high_water=1024` remained from the earlier high-load trial,
  not from this soak.
- After the soak: 22 fds, 2 threads; no stuck sessions. A fresh restart later
  returned RSS to about 7.9 MiB.

### Impairment

Client `lab0` with `netem loss 3% delay 50ms 20ms distribution normal`:

| Probe | Result |
|---|---:|
| HTTP 2,000 @ 16 | **2,000 ok / 0 errors**, p95 520 ms, max 1.56 s |
| DNS 1,000 @ 8 | **1,000 ok / 0 errors**, p95 474 ms |
| UDP 3,000 × 1,200 B | **3,000 / 3,000**, 0% loss, p95 260 ms |
| H3 (one probe) | **1 / 1** |

No restart or leak signal. The high latency is consistent with 50 ms RTT and
loss/retransmission, not a server failure.

### Adversarial checks

- Target 8080/4443 blackholed for 12 s: 0/40 HTTP during the outage; after
  unblocking, **40/40** succeeded. No fd/RSS growth, no restart.
- Pre-auth flood: 256 one-byte connections from a separate source IP; HTTP
  from the normal client remained **20/20** during and after the flood
  (TTFB p95 about 126 ms).
- Abrupt RST churn: **200/200**.
- Slow reader (SIGSTOPed iperf3 download): HTTP 100/0 and DNS 100/0 while the
  reader was stopped; RSS/fds stayed bounded.
- Mixed high-load trial (above the intended rate): authenticated
  `connection_limited` increased by 14k and clients saw resets. This is the
  expected 1024-connection admission cap, not a leak; after load stopped the
  server returned to 11/11 checks and fds 10–24.
- DNS 1,000 @ 32 followed immediately by HTTP 2,000 @ 32 produced 576 HTTP
  resets; an immediate rerun produced **2,000/0**, the server counter did not
  increase, and client `TIME_WAIT` was 2,550. This was a lab-client/TUN limit,
  not a beam rejection.

## Findings

### 1. [RESOLVED] XUDP idle sessions can be pinned by junk replies — HIGH, lab reproduced and fixed

`crates/beam-core/src/xudp/session.rs` (fixed in `2163c0a`)

The original reply loop called `session.touch()` before checking zero length,
oversize, encoding, queue reserve, and byte budget. Those dropped datagrams
therefore refreshed the idle clock. The session socket is unconnected and
accepts any source.

Lab reproduction with a temporary `idle_timeout_ms=10000`:

- Control session (one legit echo): +2 fds at t3, back to baseline by t17.
- Junkiest session (target sent a zero-length datagram every second): +2 fds
  remained at t2, t15, t25, and t35.
- `xudp_active=1`; `xudp_replies_dropped=26`.
- The client had sent one legitimate datagram and then no application traffic.

Impact: a destination or any host that learns the ephemeral source port can
keep sockets and global permits alive, eventually rejecting legitimate XUDP
traffic. The idle-timeout invariant is broken.

**Resolution:** `session.touch()` now runs only after a valid reply passes all
size/frame/queue/byte-budget checks and is handed to the writer. Zero-length,
oversize, encoding-drop, queue-drop, and budget-drop datagrams do not refresh
the idle clock. The regression test
`xudp::session::tests::dropped_replies_do_not_refresh_idle_clock` verifies both
dropped paths and a valid reply. The socket remains unconnected to preserve
stock full-cone UDP behavior; source validation was rejected because it would
break STUN/WebRTC/P2P.

Lab verification (temporary `idle_timeout_ms=10000`):

| Arm | Control (echo) | Junk (zero-length every 1 s) |
|---|---|---|
| Unpatched | 6→8 socket fds at t3, 6 at t17 | 8 socket fds at t3/t17/t27; `xudp_active=1` |
| Patched | 6→8 socket fds at t3, 6 at t17 | 8 socket fds at t3, **6 at t17/t27** |

These counts are `/proc/<pid>/fd` entries matching `socket`, not total process
descriptors.

The unpatched run reproduced the bug; the patched run closed the junk-fed
session at the idle deadline while legitimate echo/control behavior was
unchanged.

Performance regression check, 5-rep unpatched→patched A/B (paired medians):
clean up **0.997x**, clean down **0.994x**, HTTP RPS **1.015x**, HTTP p95
**0.939x**, DNS QPS **0.951x**, DNS p95 **1.059x**, loss1 **1.021x**, RTT50
**1.016x**. Download CPU was **1.079x** (higher in all five pairs); upload CPU
was **1.002x**. The CPU difference is not attributed to this one-line
ordering change, but CPU parity is not claimed. A focused 10-pair DNS A/B
measured QPS **0.9995x** and p95 **1.071x**, with **0 errors** in both arms;
latency equivalence is not established. The bidir harness had zero samples in
both arms; its valid pairs were excluded. A 337-test workspace pass,
lib/clippy/fmt, lab 11/11, and the quick suite completed.

Final Sol review: **APPROVE WITH NONBLOCKING CAVEATS**. The code fix and
full-cone compatibility were approved; the only requested changes were to stop
claiming CPU parity/equivalence, distinguish repository-fixed from deployed,
and label fd counts as socket descriptors. All were applied.

### 2. [RESOLVED] XUDP mux read loop had head-of-line blocking — HIGH

`crates/beam-core/src/xudp/server.rs` (fixed in `e0ca0bc`)

The original read loop sequentially awaited domain DNS (2 s), UDP `send_to`
(full `io_timeout`), and reply-task join (full `io_timeout`), stalling every
session on that mux. The fix:

- domain `New`/`Keep` frames are queued per session id and resolved by a
  bounded per-mux resolver task; IP frames continue immediately;
- lookup owner and suffix are separate, results carry an immutable generation,
  and stale completions are ignored;
- newer GlobalID attachments cancel older pending/queued New frames;
- resolved domains are cached for 300 s; pending payload has a process-wide
  4 MiB budget plus bounded metadata;
- sends use `try_send_to`, with only a 100 ms `WouldBlock` fallback, and close
  uses an enqueue gate plus a 100 ms bounded reply-task join. A socket is not
  retained if the old reader did not stop.

Tests: slow-domain isolation, failed-lookup suffix draining, replacement New
after failure, stale same-id completion, queued/newer GlobalID ordering,
canceled-owner suffix, TCP network preservation, and pending budget. The HOL
test uses a 500 ms resolver fixture and checks an unrelated IP Keep within
300 ms. Workspace: **347 tests**, fmt/clippy pass.

Lab candidate: 11/11 checks; DNS 1000@32 **1000/0** at 1063 qps, p95 46 ms;
UDP 3000×1200 **3000/3000**; HTTP 2000@32 **2000/0** after drain, p95 47 ms.
A 5-rep A/B before the final owner/generation amendment: clean up/down
0.996x/0.986x, HTTP RPS 1.017x/p95 1.047x, DNS QPS 1.011x/p95 1.161x, loss1
0.975x, RTT50 0.987x, CPU up/down 0.991x/1.026x. Focused 10-pair DNS on final
source: QPS **0.996x**, p95 **1.023x**, zero errors. Bidirectional: four valid
pairs after excluding a zero-receive fifth new-arm run. Sol: **APPROVE WITH
NONBLOCKING CAVEATS** (payload-only budget, scheduling-sensitive tests, no
controlled multithreaded close test; no universal nonblocking claim).

Residual: resolver lookups are serial per mux; a sequence of slow domains,
congested sends, or close bursts can still delay a mux briefly. The 4 MiB
budget does not count frame metadata.

### 3. Burst `End` closes still serialize on 250 ms — MEDIUM-HIGH, code-confirmed

`crates/beam-core/src/xudp/server.rs:842`, `887-888`;
`crates/beam-core/src/xudp/session.rs:904-911`

Only idle sweep uses nonblocking `try_send_end`. `ClientEnd`, `RelayError`, and
`New` rejection use `send_end().await`, capped at 250 ms per close. A burst of
50 closes can stall the mux for about 12.5 s when the peer is slow. The earlier
single-End cap is correct but the burst fix is incomplete.

Fix direction: use a nonblocking/control-reserved path for all closes and a
shared close deadline.

### 4. Control reserve check is racy — MEDIUM, code-confirmed

`crates/beam-core/src/xudp/session.rs:978-990`

`outbound.capacity()` is sampled, then `try_reserve()` is called separately.
Concurrent reply tasks can all pass the check and consume the reserved slots.
This makes the 8-slot control reserve advisory and feeds the blocking `End`
path.

Fix direction: reserve control capacity atomically, or use a separate bounded
control queue.

### 5. Process-wide 32 MiB reply budget couples slow and fast mux streams — MEDIUM, code-confirmed

`crates/beam-core/src/xudp/session.rs:94`, `404-409`;
`crates/beam-core/src/xudp/server.rs:258-285`

A slow reader can hold the process-wide reply budget while frames sit in its
queue. Other mux streams then drop replies until the slow writer times out or
drains. The single slow-reader probe did not exhaust the budget, but the
coupling is global and affects unrelated sessions.

Fix direction: per-mux byte fairness or a per-stream cap within the global
budget.

### 6. 1 ms timeouts pass `--check` — HIGH operational risk, lab reproduced

`crates/beam-core/src/config/validate.rs:400-422`

Only zero and values above 24 h are rejected. A copied config with
`handshake_timeout_ms=1` and `idle_timeout_ms=1` printed:

```text
configuration is valid: /tmp/beam-1ms.toml
```

At runtime these values drive TLS/VLESS/XUDP/legacy timeouts, so ordinary RTT
causes total handshake/relay failure while the service still appears active.
Add a realistic minimum (for example 100 ms–1 s, decided explicitly) and a
regression test.

### 7. Authenticated handshake stages do not share one absolute deadline — MEDIUM, code-confirmed

`crates/beam-core/src/tls/server.rs:1021-1141`; `crates/beam/src/main.rs:440`

TLS handshake, VLESS request, response writes, first body write, and dial each
consume a separate `handshake_timeout` (plus the dial cap). A slow/lossy client
or a replay can hold a connection permit for roughly three to four times the
configured timeout. `max_connections=1024` masks this in normal single-user
use, but it weakens the timeout bound.

### 8. Replay cache is post-Finished and timestamp checking is disabled — MEDIUM security/DoS

`crates/beam-core/src/tls/server.rs:704-728`, `1036`;
`crates/beam/src/main.rs:440`

`replay_contains` happens at classification, but insertion happens only after
TLS Finished. Concurrent copies of a captured ClientHello can acquire
authenticated permits and stall until the handshake timeout. With timestamp
checking disabled (`None`), the same capture can be reused. Stock Xray has no
cache, so this is a tradeoff rather than an interop regression, but the
authenticated-permit pressure is real and needs either a bounded in-flight
reservation or a documented threat model.

### 9. Short GlobalID flows can pin a mux/connection for about 120 s — MEDIUM, code-confirmed

`crates/beam-core/src/xudp/server.rs:804-861`, `939-944`

A clean GlobalID close can retain the socket for `close_expiry` (60 s). Once
retained state is gone, the empty-stream timer can add another 60 s before the
mux teardown releases its connection permit. Frequent short UDP flows can
therefore contribute to authenticated/XUDP pressure after the application is
finished. This was not reproduced as a leak this round; it is a lifecycle
accounting risk.

### 10. Lower-risk resource/CPU items

- Vision eagerly creates about five extra fds per connection
  (`crates/beam-core/src/tls/server.rs:1439-1442`). At 1024 connections this is
  about 6k fds; `LimitNOFILE=65536` kept the lab safe, but churn cost is real.
- Cover relay uses `copy_bidirectional` without a stop/eventfd
  (`crates/beam-core/src/tls/server.rs:1817-1818`); only cancellation,
  shutdown, or panic leaves detached blocking work and fds for the 30 s cover
  idle limit.
- `handle_mux_stream` cleanup is skipped if the handler future is aborted or
  panics (`crates/beam-core/src/xudp/server.rs:192-221`); no in-process abort
  path was found, so this is a shutdown/panic concern.
- Vision padding-only input still uses `wake_by_ref` after the empty-block
  budget (`crates/beam-core/src/vision/stream.rs:562-572`), so an authenticated
  hostile client can burn CPU while staying connected.
- `take_idle` holds the session-table lock while taking up to 2048 session
  locks (`crates/beam-core/src/xudp/session.rs:865-876`); bounded, no lock
  cycle found.

## Non-findings

- No fd, task, permit, or XUDP session leak appeared in normal load, the 10k
  churn history, the 10.5 min soak, or post-outage recovery.
- No server restart or OOM occurred. `NRestarts` remained 0.
- Packet loss stayed 0% at the application level under 3% network loss and
  50 ms ±20 ms jitter.
- The 1024 authenticated-connection cap and client-side `TIME_WAIT` limits are
  capacity behavior, not beam defects. They explain the high-load resets.
- Half-close remains the previously documented shared client/TUN limitation;
  this round did not establish a beam-only regression.
- The patched junk test closed the idle session and restored the socket-fd
  baseline; the unpatched binary kept it open. Legitimate echo control expired
  normally on both.
- Domain resolution isolation is bounded, not a claim that every mux operation
  is nonblocking; serial resolver, 100 ms send/close bounds, and End enqueue
  remain.

## Next actions

1. ~~Fix finding 1: junk replies must not refresh idle state.~~ Done in
   `2163c0a`; deployed.
2. ~~Remove the XUDP read-loop stalls (finding 2).~~ Done in `e0ca0bc`;
   deployed with documented residual bounds.
3. Make all close paths nonblocking and the control reserve atomic (3–4).
4. Add a minimum timeout bound and an absolute authenticated-handshake
   deadline (6–7).
5. Resume the 24 h/privileged/fuzz release gates after the remaining findings.

## Reproduction notes

- Low soak: `/tmp/opencode/soak-low/{client,server.csv,journal.txt}`
- High mixed trial: `/tmp/opencode/soak-high/{client,server.csv,journal.txt}`
- Slow reader: `/tmp/opencode/slow-{http,dns}.json`
- Impairment: `/tmp/opencode/impaired-{http,dns,udp,h3}.json`
- Junk-idle probe outputs: `/tmp/beam-soak-*` on the lab VMs (temporary; VMs
  were stopped after the run).
- These paths are scratch evidence, not committed test fixtures.
