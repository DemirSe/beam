# Open issues

Last updated 2026-11-11. Short register; the evidence behind each entry lives in
[`AUDIT-2026-11-11.md`](AUDIT-2026-11-11.md), and the lifecycle defect history in
[`STATE-MACHINES.md`](STATE-MACHINES.md).

Nothing here is a known-broken data path: byte integrity, admission bounds, and
descriptor/memory stability are covered by CI gates. These are the items that are
not clean.

## Summary

|ID|Issue|Status|Severity|
|---|---|---|---|
|I1|Transfers stop after sustained heavy churn in one test rig|Inconclusive|medium if real, not seen in real traffic|
|I2|A client restart was once refused as a replay|Open, trigger unidentified|low, self-healing|

## I1 — transfers stop after sustained heavy churn (inconclusive)

- **Status:** not reproducible on demand, and no server-side fault is visible.
- **What a user would notice:** after unusually heavy sustained use, apps that use
  the tunnel stop getting replies while web browsing may still work; only a server
  restart would bring the tunnel back.
- **Evidence:** five soak-shaped runs stalled after roughly 7 300 rounds. A 420 s run
  of the same shape passed with 6 953 sessions created, and a faster traffic shape
  ran 7 800 rounds with no slowdown at all. In every run, including the failing
  ones, descriptors stayed at 10-12, threads at 5, RSS plateaued near 18 MB, and
  every rejection counter was zero.
- **Runs:** 42930317510, 42933254782, 42935430888, 42937823294, 42939376474 (stalls);
  42940524407 (pass), 42942423567 (fast shape), 42943941476 (probe never reached a
  working baseline).
- **Next step:** re-run with a probe that first proves a working baseline (N
  successful rounds), then prints the server's `runtime counters` on both sides of
  the transition. That single measurement decides whether this is beam or the test
  client.

## I2 — a client restart was once refused as a replay (open)

- **Status:** trigger unidentified; two targeted attempts to reproduce it were
  negative.
- **What a user would notice:** the client says connected but nothing loads for a few
  minutes, then it recovers by itself or after another restart.
- **Evidence:** `authenticated ClientHello replay` log lines after client restarts
  during soak runs. Deliberate restarts — idle, and in the middle of eight
  concurrent transfers — reconnected in 0.06 s with zero refusals.
- **Runs:** 42937037698 (idle restart), 42937485208 (restart under load).
- **Next step:** capture the client's handshake at the moment of refusal and compare
  the REALITY session ids; check whether the client reuses ClientHello material
  under load.

## Test and observability gaps

Not defects; these are the places where the current evidence stops.

- `xudp_send_dropped` was observed in the log only with the value `0`. The field is
  wired end to end; a non-zero increment is covered by a unit test only.
- A client-initiated FIN cannot be exercised through sing-box, which resets the
  stream instead of propagating it. Server-side half-close is covered with a
  target-initiated FIN.
- The teardown guard's panic path relies on the same `Drop` mechanism as the tested
  abort path; it is not separately tested.
- Replay cache occupancy and the in-flight peak are still not exported.
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

- **Mux teardown skipped on cancellation.** Sessions, sockets, and global permits
  survived an aborted or panicking handler. Fixed with a lifetime guard; pinned by
  `aborting_the_mux_handler_releases_sessions_and_permits`.
- **Replay rejections were unobservable.** `replay_rejected` now counts both
  reservation-level and post-handshake rejections, and appears in the pressure
  warning and the periodic counter line.
