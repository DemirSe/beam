# Open issues

Last updated 2026-11-12. Short register; the historical hardening audit is
[`AUDIT-2026-11-11.md`](AUDIT-2026-11-11.md), and the lifecycle inventory is
[`STATE-MACHINES.md`](STATE-MACHINES.md).

Nothing here is a known-broken data path: byte integrity, admission bounds, and
descriptor/memory stability are covered by CI gates. Every entry is fixed in
code and proven on the lab; each one stays listed with its proof.

## Summary

|ID|Issue|Status|
|---|---|---|
|I1|Replay cache saturates under sustained heavy churn|Fixed on `main`, deployed|
|I2|A client restart appeared to be refused as a replay|Fixed on `main`, deployed; same root cause as I1|
|P1|Legacy/packetaddr UDP refuses flows above a fixed 64-stream pool|Fixed on `main`, proven on the lab (run 43247381742); deployment reported at `c4aef3a`|

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

### P1 — legacy/packetaddr UDP exhausts a fixed 64-stream permit pool (fixed)

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
  nor its retention was documented in `README.md` before this fix.
- **User impact:** a client using `packet_encoding=packetaddr` (or a legacy
  client) sees DNS and QUIC failures after a burst of short UDP flows even
  though each individual flow is correct; it recovers as old flows expire. The
  XUDP path, the production default, is unaffected.
- **Attribution:** beam. Fixed after the harness was merged; see the fix
  below.
- **Severity:** medium, compatibility mode only.
- **Fix (2026-11-12, `dev`):**
  1. The pool is no longer the literal `64`; `legacy_udp_stream_limit` derives
     it from `limits.max_xudp_sessions`, the configured UDP socket budget
     (1024 in the production profile, 256 with the example config). The pool
     now holds the same number of streams as the XUDP session budget.
  2. The legacy idle clock is capped at 60 s by `udp_idle_clock`, the same
     value the XUDP session clock already used. With the documented 300 s
     `idle_timeout_ms`, a permit is therefore released five times sooner than
     the TCP relay would release it; a send or an admitted reply resets the
     clock, so only a genuinely quiet flow is reclaimed. The TCP relay idle
     timeout stays at `idle_timeout_ms`.
  3. `README.md` now documents the cap, the two sockets per packetaddr stream,
     the 60 s idle clock, and `legacy_udp_limited`.
  4. `Config::validate_fd_budget` counts the legacy relay sockets; before, it
     counted only XUDP session sockets.
  - Unit coverage: `legacy_udp_streams_follow_the_udp_socket_budget` and
    `udp_idle_clock_is_capped_below_the_tcp_timeout` in
    `crates/beam/src/main.rs`, plus
    `the_example_config_caps_only_the_udp_idle_clock`, which pins the wiring
    into `TlsServerConfig`.
  - **Lab result (run
    [43233573450](https://github.com/DemirSe/beam/actions/runs/43233573450),
    commit `484e7e2`, `udp_mode=packetaddr`):** `dns-udp-200` PASS at 200/200,
    `legacy_udp_limited=0` in every metric line, no
    `legacy VLESS UDP stream limit reached` line in `beam.log`, and the startup
    log shows `max_legacy_udp_streams=256`. The whole suite was 19 PASS,
    1 WARN (`h2-multiplex-16`, runner-bound), 0 FAIL.
  - **Idle-clock result:** run
    [43247381742](https://github.com/DemirSe/beam/actions/runs/43247381742)
    (`5fa5869`, `udp_mode=packetaddr`) added the idle row: `dns-udp-200` PASS at
    200/200, `udp-idle-resume-70s` PASS after one post-idle datagram echoed in
    753 ms, `legacy_udp_limited=0`, `max_legacy_udp_streams=256`, and the suite
    was 20 PASS, 1 WARN (`h2-multiplex-16`, runner-bound), 0 FAIL, 21 cases.
    For this traffic class the clock cost no datagram: the client reopened the
    flow by itself and its first post-idle datagram was answered.
  - **Source-port measurement (run
    [43270220607](https://github.com/DemirSe/beam/actions/runs/43270220607),
    `2867f4a`):** both idle cases recovered on their first post-idle datagram
    (753 ms, one attempt) and `source_port_changed=true` — `56889 → 47745`
    after 70 s and `48778 → 42297` after 600 s. The target sees a new flow
    after the teardown; that is the accepted risk below.
  - **Accepted risk, and why it is not fixed:** the legacy/packetaddr framing
    carries no flow identifier, so a reconnecting stream cannot prove it owned a
    retained socket. Keeping the client source port would need heuristic keying
    on (user, client IP, destination, address family), which collides for two
    clients behind one NAT and for one client opening the same destination
    twice. XUDP solves this with a GlobalID and keeps retained sockets inside
    one mux stream, so its design does not transfer. Decision (2026-11-12,
    reviewed by Sol and the code owner): do not implement heuristic
    reattachment. A flow that pins the client source port and stays silent past
    the idle clock therefore sees a new session. WireGuard and quiet QUIC
    sessions are expected to survive, because the reopen rides the client's
    next datagram and needs no server-side state, but no lab case has tested a
    real WireGuard endpoint: treat that as unproven, not as tested.

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
  in run B, while its p95 moves from 654 ms (run A) to 713 ms and DNS retries
  push p95 from 791 ms to 1,506 ms. Loss on this path shows up as latency and
  as slower bulk transfers: the 8 MiB HTTP/2 transfer took 3.3 s in run A and
  45.6 s in run B, the 8 MiB HTTP/3 transfer 3.9 s and 58.9 s, and the 8 MiB
  TCP echo 3.3 s and 73.8 s.
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
