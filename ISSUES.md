# Open issues

Last updated 2026-11-11. This is the short register; the evidence behind each entry
lives in [`AUDIT-2026-11-11.md`](AUDIT-2026-11-11.md), and the lifecycle defect
history in [`STATE-MACHINES.md`](STATE-MACHINES.md).

Nothing here is a known-broken data path: byte integrity, admission bounds,
descriptor and memory stability are all covered by CI gates. These are the items
that are *not* clean.

## Open

|ID|Issue|Status|What a user would notice|Evidence|Next step|
|---|---|---|---|---|---|
|I1|Transfers stop after sustained heavy churn in one test rig|**Inconclusive** - not reproducible on demand, no server-side fault visible|After unusually heavy sustained use, apps using the tunnel stop getting replies while the web may still work; only a server restart would bring it back|Four soak runs stalled after ~7 300 rounds; one 420 s run passed cleanly at 6 953 rounds; a faster traffic shape ran 7 800 rounds with no slowdown. In every run: descriptors 10-12, five threads, RSS plateaued near 18 MB, every rejection counter at zero. Runs 42930317510, 42937823294, 42940524407, 42942423567, 42943941476|Re-run with a probe that first proves a working baseline (N successful rounds), then prints the server's `runtime counters` on both sides of the transition|
|I2|A client restart was once refused as a replay|**Open** - trigger unidentified, two targeted repros negative|The client says connected but nothing loads for a few minutes, then recovers by itself or after another restart|`authenticated ClientHello replay` lines in the log after client restarts during soak runs; deliberate restarts (idle, and mid-transfer with eight concurrent flows) reconnected in 0.06 s with zero refusals. Runs 42937037698, 42937485208|Capture the client's handshake at the refusal and compare the REALITY session ids; check whether the client reuses ClientHello material under load|

Severity, for triage: I1 matters only if it is real and repeatable under real
traffic (not seen); I2 is low and self-healing.

## Test and observability gaps

Not defects; they are the places where the current evidence stops.

- `xudp_send_dropped` was observed in the log, but only with the value `0`: the field
  is wired end to end, its non-zero increment is covered by a unit test only.
- A client-initiated FIN cannot be exercised through sing-box, which resets the
  stream instead of propagating it. Server-side half-close is covered with a
  target-initiated FIN instead.
- The teardown guard's panic path relies on the same `Drop` mechanism as the tested
  abort path; it is not separately tested.
- Replay cache occupancy and the in-flight peak are still not exported.
- No throughput or latency benchmark was run for the last delta (teardown guard and
  the replay counter). No performance claim is made.

## Documented behaviour that can look like a bug

- An XUDP frame whose payload exceeds 8 192 bytes closes the whole multiplexed
  stream. The limit is the client contract, so this is a misbehaving client hurting
  itself, not a server fault.
- Probes beyond the per-source pre-auth or cover caps are closed without dialing the
  cover. That is the anti-scan design; it is why a burst of probes from one address
  sees fewer cover responses.
- An empty or non-Data `Keep` does not retarget a session (see `README.md`, "XUDP,
  legacy UDP, and packetaddr"). It was briefly reported as a defect and withdrawn
  after review against upstream Xray and sing-vmess.

## Fixed in the 2026-11-11 pass

- **Mux teardown skipped on cancellation** - sessions, sockets, and global permits
  survived an aborted or panicking handler. Fixed with a lifetime guard; pinned by
  `aborting_the_mux_handler_releases_sessions_and_permits`.
- **Replay rejections were unobservable** - `replay_rejected` now counts both
  reservation-level and post-handshake rejections and appears in the pressure
  warning and the periodic counter line.
