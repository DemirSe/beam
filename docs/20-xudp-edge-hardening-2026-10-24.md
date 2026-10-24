# XUDP edge hardening, 2026-10-24

Status: merged into `main` and deployed. No wire-format change.

## Changes

### Sweep close-error cleanup

`MuxState::sweep` removes every expired session from the table with
`take_idle`, then closes them one by one. If one close failed (for example
`WriterClosed` after the mux writer died), the `?` dropped the remaining
`ActiveSession` values and their `JoinHandle`s. Tokio detaches a dropped join
handle, so those reply tasks could keep their UDP sockets and global limiter
permits forever. The table no longer owned them, so the normal
`handle_mux_stream` shutdown path could not recover them.

The fix stops and aborts every remaining task before returning the first close
error. The cleanup lives in a `#[cold]` helper so the normal expiry path stays
small. `sweep` itself is marked `#[cold]`: it runs once per sweep interval, not
on the per-packet path.

Tests:

- `sweep_stops_remaining_sessions_when_writer_is_closed` fails on the previous
  code with a leaked global session permit and passes with the fix.
- `sweep_queues_one_end_for_every_idle_session` proves a healthy sweep still
  emits exactly one clean `End` per expired session.

### Single frame-buffer compaction

`read_loop` used `buffer.drain(..used)` after every parsed frame. Coalesced
small frames therefore moved the remaining batch repeatedly, which is
quadratic in the number of frames in one read. A `consumed` cursor now parses
from `&buffer[consumed..]` and compacts once per read, before the buffer-bound
check and the read arm.

Tests:

- `dense_frames_are_parsed_across_reads`
- `dense_frames_keep_an_incomplete_tail` (1,360 six-byte frames plus a
  four-byte partial frame in one batch; `TruncatedFrame { buffered: 4 }` is
  preserved)

The frame parser itself was not changed, so no parser fuzz target was required.

## Local verification

| Check | Result |
|---|---|
| `cargo fmt --all --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace` | 276 PASS |
| `cargo test --workspace --release` | 276 PASS |
| XUDP server tests, 20 repetitions | 20/20 PASS |
| Full TUN, eight probes | 8/8 PASS |
| Churn | 5,000/5,000 HTTP 200, 27 s |
| Server fds | 10 -> 10 |
| Server threads | 2 -> 2 |
| RSS | 7,696 -> 8,648 KiB |

The first combined build, without the `#[cold]` sweep layout, measured a
repeatable +2.4% CPU on a 100k-packet 1,200-byte echo run (0/6 wins). Marking
the 1 Hz sweep path cold removed that layout effect: the final build measured
+0.27% median (3/6), and the swapped arm measured +0.6% (3/6). This is within
the roughly 0.6% A/A noise floor.

## Measurements

Compaction microbenchmark, median of seven rounds:

| Frames | Batch | Drain per frame | One compaction | Speedup |
|---:|---:|---:|---:|---:|
| 1 | 6 B | 24.6 ns | 24.6 ns | 1.0x |
| 16 | 96 B | 160.9 ns | 143.0 ns | 1.1x |
| 128 | 768 B | 1.693 us | 1.095 us | 1.5x |
| 1,365 | 8,190 B | 58.8 us | 11.5 us | 5.1x |

End-to-end XUDP A/B against the previous deployed binary:

| Workload | Result |
|---|---|
| 1,200 B echo, 100k packets | +0.27% median CPU, 3/6, neutral |
| 1,200 B echo, 100k, swapped order | +0.6% median, 3/6, neutral |
| IPv6 echo | neutral, 4/6 |
| 300k UDP burst | neutral, 4/6 |
| 4 B payload, 40k packets | +0.7% median, 4/10, noise |

The compaction win is in the dense-batch edge case; normal traffic is neutral
because frame handling and UDP relay dominate.

## Deployment

Deployed on 2026-10-24 20:27 UTC with `BEAM_KEEP_CONFIG=1`.

- Live binary:
  `ce87e0b30cd353903db75914bb7182d015f7f37c53a5e46382a6904efefb59c7`
- Previous binary:
  `9d417394a46a27a83168fa146ca358ae1cba01d154d73fb153cfd0adfd0c3b9b`
- Rollback binary: `/usr/local/bin/beam.bak-20261024T202729Z`
- Config SHA-256 unchanged:
  `c0abace24e0f839a3ae3c1300d3f79b94ccfee437df5e7a4d8ec67b1b2722a02`
- Service active, `NRestarts=0`, listener on `0.0.0.0:443`, config check
  passes, no journal warnings.
- Post-deploy: DNS 10/10, IPv6 200, TTFB 0.153 s, 32 MiB download
  4.36 MB/s, 8 MiB upload 1.51 MB/s, 4 MiB upload SHA-256 matched, 16 MiB
  download SHA-256 matched.
- The client-side HTTP/3 block remains intentional.

Temporary VPS hash/HTTP servers, the temporary loopback alias, and remote
temporary files were removed after the checks.

## Open items

The 24-hour soak and the privileged syscall/wakeup acceptance gates remain
separate follow-ups. Rollback is binary-only because the config did not change:

```bash
sudo install -m 0755 /usr/local/bin/beam.bak-20261024T202729Z /usr/local/bin/beam
sudo systemctl restart beam
```
