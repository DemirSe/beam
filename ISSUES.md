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
|I1|Replay cache saturates under sustained heavy churn|Fixed on `fix/replay-cache` (pending merge)|resolved|
|I2|A client restart appeared to be refused as a replay|Fixed on `fix/replay-cache` (pending merge)|resolved|

## I1 — replay cache saturates under sustained heavy churn (fixed on branch)

- **Status:** fixed on `fix/replay-cache`, pending merge; proof run 43016632684
  pairs the pinned pre-fix SHA with the fixed branch. This was not a data-path
  defect: descriptors, threads, and RSS stayed flat; the cache reached its
  configured bound and failed closed.
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

## I2 — a client restart appeared to be refused as a replay (fixed on branch)

- **Status:** fixed on `fix/replay-cache`; same root cause as I1.
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
