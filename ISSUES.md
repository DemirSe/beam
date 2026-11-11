# Open issues

Last updated 2026-11-11. Short register; the historical hardening audit is
[`AUDIT-2026-11-11.md`](AUDIT-2026-11-11.md), and the lifecycle inventory is
[`STATE-MACHINES.md`](STATE-MACHINES.md).

Nothing here is a known-broken data path: byte integrity, admission bounds, and
descriptor/memory stability are covered by CI gates. Both I-entries are fixed
and merged to `main`; they remain listed with the proof and deployment evidence.
The one open entry (P1) is a compatibility-mode admission bound found by the
protocol lab, not a data-path or integrity defect.

## Summary

|ID|Issue|Status|Severity|
|---|---|---|---|
|I1|Replay cache saturates under sustained heavy churn|Fixed on `main`, deployed|resolved|
|I2|A client restart appeared to be refused as a replay|Fixed on `main`, deployed; same root cause as I1|resolved|
|P1|Legacy/packetaddr UDP refuses flows above 64 concurrent streams|Open; found by the protocol lab, not fixed here|medium|

## I1 — replay cache saturates under sustained heavy churn (fixed)

- **Status:** fixed and merged to `main`; proof run 43016632684 passed and the
  binary is deployed to the production host. The baseline job reproduced the
  stall at 7,288 rounds / 65,536 handshakes; both fixed 900 s reps passed with
  zero unexplained failures and `replay_rejected=0` / `replay_cache_full=0`.
  This was not a data-path defect: descriptors, threads, and RSS stayed flat;
  the cache reached its configured bound and failed closed.
- **What a user would notice:** after unusually heavy sustained use, apps that use
  the tunnel stop getting replies while web browsing may still work; only a server
  restart (or waiting for entries to age out) would bring the tunnel back.
- **Cause:** capacity was `clamp(64 × max_connections, 4096, 65536)` = 65,536,
  and every entry was retained for `2 × 300 s + 1 s` = 601 s, a sustainable rate
  of about 109 authenticated handshakes/s. The soak shape creates 9 handshakes
  per round at 16-28 rounds/s (146-255/s). The first rejection occurs at exactly
  65,536 completed handshakes. Instrumented runs showed 65,536 unique session
  ids, zero reserve-level rejections, and zero rejected ids that had completed
  earlier, so this was cache saturation, not a client reusing a ClientHello.
- **Evidence:** current-dev failing runs 43004235340, 43004266767,
  43004276244; older run 42937823294; instrumented runs 43005043280,
  43005052880, 43005143151; fixed proof run 43016632684.
- **Fix:** `ReplayPhase::{Unseen,InFlight,Settled,Expired}` with a deadline
  min-heap; entries expire at `envelope timestamp + window + 1 s` (301 s typical,
  601 s worst case), and a settled entry with admitted copies remains until those
  copies drain; capacity is `clamp(128 × max_connections, 4096, 131072)`;
  `replay_cache_full` and occupancy/in-flight counters are exported. Pinned by
  the replay tests in `tls/server.rs`.

## I2 — a client restart appeared to be refused as a replay (fixed)

- **Status:** fixed and merged to `main`; same root cause as I1.
- **What a user would notice:** the client says connected but nothing loads for a
  few minutes, then it recovers by itself or after another restart.
- **Evidence:** the `authenticated ClientHello replay` lines appeared after the
  replay cache was full, including the no-restart soak 42937823294. The dedicated
  restart probes 42937037698 and 42937485208 never reached 65,536 handshakes.
  Instrumented fingerprints showed every rejected id was a new id, not a
  previously completed one; there is no evidence that the client reused
  ClientHello material.
- **Fix:** the capacity/retention fix removes the saturation window, and the new
  `replay_cache_full` counter separates cache pressure from duplicate rejection.

## Test and observability gaps

Not defects; these are the places where the current evidence stops.

- `xudp_send_dropped` was observed in the log only with the value `0`. The field is
  wired end to end; a non-zero increment is covered by a unit test only.
- A client-initiated FIN cannot be exercised through sing-box, which resets the
  stream instead of propagating it. Server-side half-close is covered with a
  target-initiated FIN.
- The teardown guard's panic path relies on the same `Drop` mechanism as the tested
  abort path; it is not separately tested.
- Stable-promotion validation remains open: privileged syscall/wakeup/splice
  measurements and cgroup OOM sampling. The five-hour soak passed on 2026-11-10
  and the short fuzz campaign is clean; exhaustive fuzzing is not claimed.
- No throughput or latency benchmark was run for the last delta (the teardown guard
  and the replay counter). No performance claim is made.

## Documented behaviour that can look like a bug

- An XUDP frame whose payload exceeds 8 192 bytes closes the whole multiplexed
  stream. That is the client contract; a misbehaving client hurts only itself.
- Probes beyond the per-source pre-auth or cover caps are closed without dialing the
  cover. That is the anti-scan design, and it is why a burst of probes from one
  address sees fewer cover responses.
- An empty or non-Data `Keep` does not retarget a session (see `README.md`, "XUDP,
  legacy UDP, and packetaddr"). It was briefly reported as a defect and withdrawn
  after review against upstream Xray and sing-vmess.

## Fixed in the 2026-11-11 pass

- **Replay cache saturation under sustained churn.** The cache was bounded at
  65,536 entries with 601 s retention and failed closed above ~109 authenticated
  handshakes/s. The phase is now explicit, retention is per envelope timestamp
  (301 s typical), capacity is 131,072, settled entries keep first-wins until
  admitted copies drain, and `replay_cache_full`/occupancy are observable.
- **Mux teardown skipped on cancellation.** Sessions, sockets, and global permits
  survived an aborted or panicking handler. Fixed with a lifetime guard; pinned by
  `aborting_the_mux_handler_releases_sessions_and_permits`.
- **Replay rejections were unobservable.** `replay_rejected` now counts both
  reservation-level and post-handshake rejections, and appears in the pressure
  warning and the periodic counter line.

## Protocol lab findings (2026-11-11)

The `suite=protocols` campaign ran three times on the hosted lab
(`ubuntu-24.04`, `standard` profile, 250 ms netem RTT, 20 cases per arm) through
the full-TUN sing-box -> beam path. Each run also ran the stock Xray control
arm; the beam report is the gate and the control report is diagnostic. Reports,
TSVs, server and target logs, qdisc JSON and per-case probes are in each run's
`lab-hosted-*` artifact.

|Run|UDP mode|Loss|Beam arm|Control arm|
|---|---|---|---|---|
|[A](https://github.com/DemirSe/beam/actions/runs/43099892457)|xudp|0%|20/20 accepted (19 PASS, 1 WARN)|15 PASS, 2 WARN, 3 FAIL|
|[B](https://github.com/DemirSe/beam/actions/runs/43101196768)|xudp|1%|20/20 accepted (18 PASS, 2 WARN)|15 PASS, 2 WARN, 3 FAIL|
|[C](https://github.com/DemirSe/beam/actions/runs/43103918524)|packetaddr|0%|19/20 accepted (18 PASS, 1 WARN, 1 FAIL)|9 PASS, 2 WARN, 9 FAIL|

### P1 — legacy/packetaddr UDP exhausts a 64-stream permit pool (open)

- **Check:** `dns-udp-200` with `udp_mode=packetaddr`; 10 sequential plus 190
  queries across 16 workers.
- **Observed:** 142/200 queries answered, p95 4,028 ms; the 58 queries that
  failed still failed after dig's retry, and the beam log recorded 120
  `legacy VLESS UDP stream limit reached` rejections (`legacy_udp_limited=120`)
  in that window. `xudp_new_frames=0` confirms the traffic took the legacy
  path, not XUDP. The same case answers 200/200 in both `xudp` runs.
- **Expected:** 200/200 NOERROR, as with XUDP.
- **Cause:** `legacy_udp_permits = Semaphore::new(64)` is a process-wide cap
  (`crates/beam/src/main.rs`); each legacy/packetaddr VLESS UDP flow holds one
  permit for its whole lifetime, and `LegacyUdpConfig::idle_timeout` defaults to
  300 s. glibc's stub resolver opens a new UDP socket per query, so a modest
  query rate (a few new flows per second) exhausts the 64 permits within
  seconds, and refusals continue until the older flows idle out. Neither the cap
  nor its retention is documented in `README.md`.
- **User impact:** a client using `packet_encoding=packetaddr` (or a legacy
  client) sees DNS and QUIC failures after a burst of short UDP flows even
  though each individual flow is correct; it recovers as old flows expire. The
  XUDP path, the production default, is unaffected.
- **Attribution:** beam. Not fixed in this task (harness-only scope).
- **Severity:** medium, compatibility mode only.

### P2 — HTTP/2 origin peak is runner-bound (WARN, no beam signal)

`h2-multiplex-16` always proves the hard contract: one TLS connection, 16/16
exact bodies, client-side peak of 16 in flight. The origin's own `active=`
counter peaks at 4 on the hosted runner (7-8 locally), below the case's WARN
threshold of 8, so the row is WARN on every run. That is a function of the
runner's vCPU count and batching, not of beam; the WARN is recorded and does
not gate.

### P3 — the stock Xray control is a diagnostic, not a like-for-like baseline

The control arm fails DNS while beam passes: `dns-udp-200` 15-18/200,
`dns-tcp-fallback` 17/20, `mixed-hol-60s` DNS 143-146/300, and its restart
recovery is ~7.5 s against 3.0-3.8 s for beam. With `udp_mode=packetaddr` it
also loses UDP entirely (0/1200 echoes, 0/200 DNS) and fails both H3 cases.
These rows are why the beam report is the gate and the control report is
attached as evidence instead.

### Lab notes (behaviour, not defects)

- XUDP and legacy UDP travel inside the VLESS TCP stream, so 1% link loss is
  retransmitted rather than dropped: `udp-realtime-1200` still reports 0% loss
  at 1% netem loss, while its p95 rises from ~0.65 s to ~1.06 s and DNS retries
  raise p95 from ~0.77 s to ~1.50 s. Loss on this path shows up as latency, and
  as slower bulk transfers (the 8 MiB HTTP/2 transfer went from ~3.5 s to
  ~82 s at 1% loss).
- A multi-destination UDP burst is retarget-sensitive in sing-box: with 75
  packets to three echo ports plus 25 to an alternate-source port in one burst,
  both arms lose the tail of the last destination (64/75 echoes). The case now
  gives each destination its own reply window on the same socket and
  association; with that pacing both arms deliver 75/75 echoes plus 25/25
  alternate-source replies.
- `udp-alt-source` passes on both arms: a reply from 10.10.2.2:9995 to a client
  that sent to 10.10.2.2:9998 is delivered, i.e. full-cone behaviour holds.
- The target DNS answer now carries the required CLASS field. Before the fix
  `dig` reported a malformed packet for both A and AAAA, and the old 8-row TUN
  suite passed only because its grep matched the `SERVER:` line.
