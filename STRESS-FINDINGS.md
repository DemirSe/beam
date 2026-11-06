# Open stress findings — updated 2026-11-06

This file is intentionally separate from `README.md` for the findings that are
still open. Findings 1 and 2 were fixed in `2163c0a`/`e0ca0bc`; findings 3, 6,
7, and 11 are fixed in `fa0c0ca`; the concurrent-replay bound is in `647623b`;
the four 2026-11-06 fixes are in `2469971`. All of those are deployed. The
remaining items below stay open. Production runs `2469971` (SHA
`61d8b045…`) with `NRestarts=0`; the lab is stopped after the 11/11 checks.
Initial binary under test was final `1007354…` code (embedded identity
`b4d9382`, deployed build `a41facef…`).

This note records the results of three read-only code audits plus the QEMU lab
run. It distinguishes **lab-reproduced** findings from code-confirmed risks.
Do not treat the latter as fixed or as measured production incidents.

## Current open findings

| # | Status | Area | Summary |
|---:|---|---|---|
| 4 | open | XUDP close | The reserved control slots are advisory; a racing End is dropped and counted rather than blocking. |
| 5 | open | XUDP reply budget | The process-wide 32 MiB budget lets a slow reader delay unrelated mux streams. |
| 8 | partial | TLS replay | Concurrent in-flight copies are bounded; the disabled timestamp window remains a decision. |
| 9 | open | XUDP lifecycle | Short GlobalID flows can retain a socket and mux permit for about two close timers. |
| 10 | open | Lower-risk resources | Remaining cover stop-signal, mux-abort cleanup, and session-table lock items; Vision CPU spin is fixed. |
| 12 | open | Client platform | Rootless Android cannot enable BBR while preserving the REALITY outer TCP cover. |

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
300 ms. Workspace tests, fmt/clippy pass; the 2026-11-03 follow-up added
timeout, legacy-idle, and FrameDecoder regression tests.

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
budget now charges payload, domain bytes, and a `size_of` floor; allocator
capacity slack above that estimate is not charged.

### 3. [RESOLVED] Burst `End` closes still serialize on 250 ms — MEDIUM-HIGH, code-confirmed

`crates/beam-core/src/xudp/server.rs:1350-1389`

All `End` enqueue paths now use nonblocking `try_send`. A full queue drops that
flow's End and increments `xudp_end_dropped`; it cannot stall the mux read
loop. The obsolete 250 ms `END_ENQUEUE_TIMEOUT` was removed.

### 4. Control reserve check remains advisory — LOW, nonblocking residual

`crates/beam-core/src/xudp/session.rs:946-953`, `1018`

`outbound.capacity()` is still sampled before `try_reserve()`, so concurrent
reply tasks can consume the eight nominally reserved slots. With finding 3
fixed this no longer creates a blocking close path: an End that loses the race
is dropped and counted. A future separate control queue would make the reserve
strict; it is not required to prevent the read-loop stall.

Fix direction: separate bounded control queue or an atomic reservation.

### 5. Process-wide 32 MiB reply budget couples slow and fast mux streams — MEDIUM, code-confirmed

`crates/beam-core/src/xudp/session.rs:94`, `404-409`;
`crates/beam-core/src/xudp/server.rs:258-285`

A slow reader can hold the process-wide reply budget while frames sit in its
queue. Other mux streams then drop replies until the slow writer times out or
drains. The single slow-reader probe did not exhaust the budget, but the
coupling is global and affects unrelated sessions.

Fix direction: per-mux byte fairness or a per-stream cap within the global
budget.

### 6. [RESOLVED] 1 ms timeouts pass `--check` — HIGH operational risk

`crates/beam-core/src/config/validate.rs:400-441`

`handshake_timeout_ms` now requires at least 100 ms and `idle_timeout_ms` at
least 1 s; both still cap at 24 h. `rejects_sub_minimum_timeouts` is the
behavioral regression test.

### 7. [RESOLVED] Authenticated handshake stages do not share one absolute deadline — MEDIUM

`crates/beam-core/src/tls/server.rs:1018-1149`

TLS handshake, VLESS request, dial, response, and initial body write now share
one absolute `tokio::time::Instant` deadline. A slow client can hold a permit
for at most the configured handshake budget, not a multiple of it.

### 8. [PARTIAL] Replay cache is post-Finished and timestamp checking is disabled — MEDIUM security/DoS

`crates/beam-core/src/tls/server.rs:704-728`, `1036`;
`crates/beam/src/main.rs:440`

The concurrent-copy permit pressure is bounded: `647623b` adds a maximum of
four in-flight reservations per exact replay id and releases them on handshake
failure (lab: 905/1024 pre-fix, 12 post-fix). The cache still inserts only
after TLS Finished, and timestamp checking remains disabled (`None`); a
captured ClientHello can therefore authenticate once after the 60 s replay
window. Stock Xray has no cache, so this is a tradeoff rather than an interop
regression. The timestamp-window decision remains open and needs either strict
timestamp checking or a documented threat model.

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
  idle limit. `2469971` now bounds concurrent cover relays with the splice
  permit pool and falls back to the async relay, but does not add a stop
  signal.
- `handle_mux_stream` cleanup is skipped if the handler future is aborted or
  panics (`crates/beam-core/src/xudp/server.rs:192-221`); no in-process abort
  path was found, so this is a shutdown/panic concern.
- ~~Vision padding-only input still uses `wake_by_ref` after the empty-block
  budget (`crates/beam-core/src/vision/stream.rs:562-572`), so an authenticated
  hostile client can burn CPU while staying connected.~~ Fixed in `abdc033`:
  after 64 consecutive empty blocks with no coalesced content the stream
  returns `InvalidData`; regression tested.
- `take_idle` holds the session-table lock while taking up to 2048 session
  locks (`crates/beam-core/src/xudp/session.rs:865-876`); bounded, no lock
  cycle found.

### 11. [RESOLVED] Legacy UDP dropped replies and quadratic decoder — MEDIUM

`crates/beam-core/src/udp/legacy.rs:318-341`, `379-399`, `442-492`, `835-922`

Dropped/oversized legacy and packetaddr replies no longer refresh the idle
clock, matching the XUDP fix. `FrameDecoder` now keeps a consumed cursor and
compacts once per read batch instead of `Vec::drain` per frame. Regression
tests cover dropped-legacy-reply idle expiry and coalesced zero-length frames.

### 12. [OPEN] Rootless Android cannot change the REALITY outer TCP congestion control — CLIENT PLATFORM

A rootless Android client can keep the REALITY/TCP cover (`TCP/443` with the
`whatsapp.net` TLS ClientHello) or change congestion control, but not both on
this device class.

Device/lab evidence (2026-11-06):

- Samsung SM-S721B, Android 17 / SDK 37, kernel `6.1.162-android14-11`.
- `tcp_available_congestion_control` and `tcp_allowed_congestion_control` are
  both `reno cubic`; `tcp_congestion_control=cubic`; no `tcp_bbr` module.
- Root is absent (`ro.debuggable=0`, locked bootloader); `shell` cannot modify
  the sysctls or qdisc.
- Buffer tuning is already generous: `tcp_rmem` max 16 MiB, `tcp_wmem` max
  8 MiB, `rmem_max` 32 MiB, `wmem_max` 16 MiB.
- Stock SFA/sing-box is active; its VPN TUN is MTU 1500. sing-box exposes no
  TCP congestion-control field for standard VLESS/TCP outbounds.
- Lab, 20 Mbps UDP upload, client CUBIC, `30 ms ±8 ms`, 0.5% loss:
  `xudp` **61.5%**, `packetaddr` **51.2%**, `legacy` **73.1%** loss.
  The same client with BBR produced **0–0.74%** loss.
- Hysteria2/TUIC or other QUIC/UDP transports use userspace congestion control,
  but the WAN packet is UDP, not the visible `whatsapp.net` TCP/REALITY
  stream. They therefore violate the current cover requirement.
- A custom client on the same kernel TCP can add queueing/pacing or per-socket
  options, but cannot replace missing kernel BBR; it is mitigation only.
- Cover-preserving paths are: root/custom-kernel BBR, or an external BBR Linux
  gateway/router that terminates REALITY/TCP while the phone stays rootless.

Next probe: evaluate an external BBR Linux gateway as the rootless
cover-preserving path (TUN/MTU, 20 Mbps UDP upload, loss matrix, latency,
throughput, and whether the WAN side still shows `whatsapp.net` TCP/443). If
that fails, quantify custom-client pacing/queue only; a QUIC transport is a
separate product decision because it changes the visible transport.

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
3. Separate control queue for a strict End reserve (4).
4. Per-mux reply-budget fairness (5).
5. ~~Bound concurrent in-flight replays (8).~~ In-flight bound shipped in
   `647623b`; decide the timestamp-checking window.
6. Short-GlobalID lifecycle accounting (9).
7. Resume the 24 h/privileged/fuzz release gates after the remaining findings.
8. Test the external BBR Linux gateway path for finding 12 under the same loss
   matrix while keeping TCP/443 + `whatsapp.net` on the WAN side.
9. If 8 does not hold, quantify custom-client pacing/queue only; treat
   Hysteria2/TUIC or another QUIC transport as a separate cover-changing
   product decision.

## Reproduction notes

- Raw soak, impairment, slow-reader, and junk-idle outputs were scratch
  evidence on the lab hosts, not committed test fixtures. Reproduce them with
  the lab harness instead of relying on stale paths.
