# Local improvements — 2026-10-24

This pass asked an independent read-only audit (GPT-6.1 Sol, high) for three
locally testable improvements, then implemented each one on its own branch and
measured it against the unmodified `6616db2` binary. Nothing was deployed or
run against the live VPS; the production host stayed on `d017c131…` with the
unchanged config throughout.

"Stock" in this document means the unmodified beam baseline, not stock Xray.
The existing Xray comparison remains in `docs/16-local-comparison-2026-10-22.md`
and is out of scope here.

## Baseline and method

| Item | Value |
|---|---|
| Baseline commit | `6616db2` |
| Baseline binary | `d017c1311f2075fe546fe80d97af938208514f35fac9044acda50c2a7f777842` |
| Host | i5-1135G7, 8 logical threads, Linux 7.2.10 |
| Client | Xray 26.3.27 (SOCKS UDP/TCP) or sing-box 1.14.2 full TUN |
| Build | `cargo build --locked --release -p beam` |
| Server CPU | one pinned logical CPU for the bulk/UDP arms |
| Ordering | every sample alternates baseline and fix; per-sample CPU and wall time are kept |

Each branch changes one subsystem only. All three pass `cargo fmt --all
--check`, `cargo clippy --workspace --all-targets -- -D warnings`, the
workspace test suite, and the local full-TUN matrix.

| Branch | Commit | Binary SHA-256 |
|---|---|---|
| `improve/xudp-reply-admission` | `34c83b6` | `ab7ae1f6eb92b53282956f19b4493b5fba47d754aeb876843cdd99e419ff504e` |
| `improve/relay-stop-eventfd` | `0988f3a` (perf `034189c`, plus comment and EINTR fixes) | `e9286dc9a699c556d6e4ec83de03797b549991888fbd65ccc0b00bdaffe0efc4` |
| `improve/tls-record-recycle` | `2467291` | `3da1fb2e436695e32bcff32a1e2d460ef84dddf6d14b9a69220307a5773074c0` |

## Result summary

| # | Change | Measured effect | Confidence | Recommendation |
|---|---|---|---|---|
| 1 | XUDP: exact IPv6 frame sizing + admit before allocating | IPv6 echo CPU **-1.6%** paired median, **8/8** wins; IPv4 neutral; slow-client burst **-0.4%** median (4/6) | High for IPv6 sizing; low for drop-path CPU | Merge; the IPv6 sizing win is real, the admission reorder is defensive |
| 2 | Splice relay: eventfd stop wakeup | Idle 120 directions: CPU **-87%**, polls **586 → 24/s**, cancellation **248 → 3.5 ms**, 10/10 | Very high, deterministic | Merge; latency/wakeup win, not a throughput claim |
| 3 | TLS: recycle the record buffer | 1 GiB upload **-1.9%** CPU/GiB (27/34); 4×128 MiB upload **-1.2%** (24/30) | Medium-high | Merge; small but consistent upload gain |

## 1. XUDP reply admission and IPv6 sizing

### Finding

`reply_loop` allocated and encoded every reply before checking the aggregate
byte budget or the bounded queue (`crates/beam-core/src/xudp/session.rs:751`).
Under backpressure, replies that were certain to be dropped still paid for a
`Vec` allocation, framing, and payload copy.

The same code reserved `len + 24` bytes. An IPv4 reply needs 16 overhead bytes,
but an IPv6 reply needs 28 (2 metadata prefix + 4 session/status/option +
1 network + 2 port + 1 atyp + 16 address + 2 payload length). Every IPv6 reply
therefore grew the vector during `encode_frame`, even on the normal path.
Evidence: `crates/beam-core/src/xudp/frame.rs:475` and
`crates/beam-core/src/address.rs:70`.

### Change

- Added `reply_frame_len(SocketAddr, usize)` with the exact IPv4/IPv6 overhead.
- The reply task now reserves a queue slot (`try_reserve`) and the reply-byte
  budget before allocating or encoding. A rejected reply drops with no frame
  allocation.
- The frame is allocated fallibly with the exact capacity and sent through the
  reserved slot. Source addresses, FIFO order, and drop-on-congestion policy
  are unchanged.
- Added a test that compares the helper with `encode_frame` for both families
  and payload sizes 0..8192, and asserts the reserved capacity does not grow.

### Measurements

Local SOCKS5 UDP echo through Xray → beam → loopback UDP target, window 1,
20,000 requests per sample, 1,200-byte payload, 8 paired samples.

| Workload | Stock CPU | Fix CPU | Paired delta | Wins |
|---|---:|---:|---:|---:|
| IPv4 echo | 0.3463 s | 0.3487 s | **+0.54%** | 3/8 |
| IPv6 echo | 0.3726 s | 0.3644 s | **-1.57%** | **8/8** |
| IPv6 median-of-medians | 0.3726 s | 0.3644 s | **-2.20%** | — |

The IPv4 path is a negative control: it already had enough capacity, so the
only difference is the extra reservation step. The result is within noise and
slightly positive, which is acceptable but not a claimed gain.

Slow-client burst: target sends 300,000 × 256-byte replies while the client
does not read, 6 paired samples.

| Metric | Stock | Fix | Paired delta | Wins |
|---|---:|---:|---:|---:|
| Server CPU | 0.6159 s | 0.6100 s | **-0.37%** median, -1.11% mean | 4/6 |

The burst confirms the new drop path is safe but does not prove a CPU win:
the Xray client keeps draining the mux stream well enough that queue rejection
is not the dominant cost. The allocation removal is still true by construction.

Full-TUN matrix: **8/8 PASS**, including IPv4/IPv6 UDP echo, DNS, H3, and
HTTPS Direct.

**Verdict:** the IPv6 exact-size change is a clear, deterministic win and
should ship. The admission-before-allocation change is low-risk and aligns
with the bounded-allocation rule; keep it, but do not sell it as a measured
CPU improvement.

## 2. Splice relay: explicit stop wakeup

### Finding

Every one-way relay sharing a `RelayActivity` capped its `poll` timeout at
250 ms (`crates/beam-core/src/relay/splice_copy.rs:64` and `:484`) only to
observe the `AtomicBool` stop flag. `RelayActivity::stop` set the flag but
could not wake a blocked `poll` (`:334`). Two idle Vision Direct directions
therefore woke four times per second per connection, and cancellation could
take up to 250 ms.

### Change

- Added `beam_sys::EventFd`, a safe owned `eventfd(2)` wrapper with
  `EFD_CLOEXEC | EFD_NONBLOCK`, `notify()`, and `AsRawFd`. All `unsafe` stays
  in `beam-sys` with SAFETY comments.
- `RelayActivity` creates one eventfd best-effort. `stop()` sets the flag and
  signals the fd. If creation fails, the old 250 ms bounded-poll fallback is
  retained.
- `run_one_way` includes the fd in its `poll` set and uses the full inactivity
  timeout. Because the fd stays readable, both directions wake and observe the
  stop flag at the top of the loop.
- `notify` retries `EINTR`, so an interrupted 8-byte write cannot silently fall
  back to the full idle timeout. Counter saturation (`EAGAIN`) means the fd is
  already readable and is treated as success.
- Added tests for eventfd readability/wakeup, a stopped relay polling at most
  twice, and the existing shared-activity/cancellation coverage.

### Measurements

Direct harness using the production `copy_one_way` with 120 idle directions,
one `RelayActivity` per direction, pinned to one CPU, ten 5-second paired
windows.

| Metric | Stock | Fix | Delta |
|---|---:|---:|---:|
| Process CPU per 5 s | 5.474 ms | 0.691 ms | **-87.4%** |
| Polls per second | 586.2 | 24.0 | **-95.9%** |
| Stop-to-join latency | 247.99 ms | 3.50 ms | **-98.6%** |
| Paired CPU wins | — | — | **10/10** |

The fixed build performs one initial poll per direction; the baseline performs
about 4.9 polls per direction per second. This is the intended effect and is
deterministic, unlike a throughput measurement.

Bulk download control (1 GiB, 8 paired samples, Vision Direct/splice path):
CPU/GiB 0.4823 → 0.4753 (-1.5% median-of-medians), paired median +0.2%,
4/8 wins. This is within noise; the change is not a bulk-throughput
optimization.

Full-TUN matrix: **8/8 PASS**. Churn: 2,000/2,000 HTTP 200, server fds
10 → 10, threads 2 → 2, RSS 7,796 → 8,600 KiB. The extra eventfd is one per
active `RelayActivity`, released with the connection; the churn run shows no
fd growth. The EINTR retry is a hardening follow-up found during the regression
review; the idle, churn, and TUN runs above use the final binary.

**Verdict:** merge. The absolute CPU saving on an idle 1-vCPU VPS is small
(roughly 0.1% of a core per 120 idle directions), but the 250 ms → 3 ms
cancellation improvement is real, and 480+ needless wakeups per second for 60
two-direction connections disappear. This is a latency/wakeup fix, not a
throughput headline.

## 3. TLS record buffer recycling

### Finding

The previous single-buffer change removed one copy per TLS record, but
`RecordRead::poll` still created a fresh `Vec` (`crates/beam-core/src/tls/stream.rs:711`)
and returned it with `mem::take` (`:744`). `poll_read_inner` cleared the
consumed `pending` buffer (`:367`) and then replaced it on the next record
(`:411`). A 16 KiB record stream therefore still did one allocation/free cycle
per record, about 65,536 per GiB.

### Change

- `RecordRead::poll` accepts the fully consumed `pending` vector and reuses its
  capacity. A partially consumed record is never recycled.
- The header/body layout, socket read boundaries, record-size validation, and
  Direct handoff rules are unchanged.
- The test that reads two records now passes the first record's allocation into
  the second read and asserts the capacity is unchanged.

### Measurements

Vision upload, 1 GiB, 1 flow, alternating samples:

| Run | n | Stock CPU/GiB | Fix CPU/GiB | Paired median | Wins |
|---|---:|---:|---:|---:|---:|
| A | 10 | 0.8159 | 0.8060 | -1.85% | 7/10 |
| B (arms swapped) | 8 | 0.8113 | 0.8139 | -0.67%* | 5/8 |
| C | 16 | 0.8237 | 0.8032 | -2.16% | 15/16 |
| Combined pairs | 34 | — | — | **-1.9%** | **27/34** |

\*Run B passed the fix as the `old` arm and stock as the `new` arm (the
harness still alternated order within the run). The medians are normalized back
to stock vs fix, while the paired median is the primary statistic. Its medians
and paired median disagree in sign, which is why that run is treated as noise
rather than as evidence for a larger gain.

Vision upload, 4 × 128 MiB:

| Run | n | Stock CPU/GiB | Fix CPU/GiB | Paired median | Wins |
|---|---:|---:|---:|---:|---:|
| A | 10 | 0.8354 | 0.8223 | -0.79% | 7/10 |
| B | 20 | 0.8342 | 0.8225 | -1.32% | 17/20 |
| Combined pairs | 30 | — | — | **-1.2%** | **24/30** |

The expected saving is consistent with the record count: 65,536 fewer
allocation/free pairs per GiB, a few milliseconds of CPU against roughly 0.8 s
of server CPU per GiB. The 1 GiB runs vary from -0.7% to -2.2% across sessions;
the combined paired median is the number to use.

Download negative control (Direct path bypasses record reads): the first run
showed -0.7% paired CPU (3/6) with a +3.5% wall-time drift; a swapped run showed
+0.9% (2/6) and flat wall time. The control is noise, as expected, and shows no
consistent regression.

Full-TUN matrix: **8/8 PASS**.

**Verdict:** merge. The gain is small but consistent on uploads with many
records, and the change preserves the record-boundary/authentication rules.

## Verification matrix

| Check | XUDP | Relay | TLS |
|---|---|---|---|
| `cargo fmt --all --check` | PASS | PASS | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS | PASS | PASS |
| `cargo test --workspace` | PASS (297) | PASS (299) | PASS (296) |
| Full TUN, 8 probes | PASS | PASS | PASS |
| Churn 2,000 / fds stable | not run | PASS | not run |
| Targeted A/B | IPv4/IPv6 echo + burst | idle + 1 GiB download | 1 GiB + 4×128 MiB upload + download control |
| Live server touched | no | no | no |

## Artifacts

Raw samples, manifests, and logs are under `/tmp/opencode`:

- `upgrade-xudp-echo4-ab-20261024T131219Z` — IPv4 echo
- `upgrade-xudp-echo6-ab-20261024T131341Z` — IPv6 echo
- `upgrade-xudp-burst-ab-20261024T131501Z` — slow-client burst
- `upgrade-xudp-tun-20261024T132544Z` — full TUN
- `upgrade-relay-idle-ab2-20261024T135047Z` — 120 idle directions
- `upgrade-relay-download-ab2-20261024T135256Z` — bulk control
- `upgrade-relay-churn2-20261024T135354Z` — churn
- `upgrade-relay-tun2-20261024T135413Z` — full TUN
- `upgrade-tls-upload-ab-20261024T130456Z`,
  `upgrade-tls-upload-swap-ab-20261024T132556Z`,
  `upgrade-tls-upload-ab2-20261024T132904Z` — 1 GiB upload
- `upgrade-tls-upload4-ab-20261024T130618Z`,
  `upgrade-tls-upload4-ab2-20261024T132704Z` — 4 × 128 MiB upload
- `upgrade-tls-download-ab-20261024T130722Z`,
  `upgrade-tls-download-swap-ab-20261024T132424Z` — download control
- `upgrade-tls-tun-20261024T132532Z` — full TUN
- `combined-tun-20261024T135729Z` — combined full TUN
- `combined-churn-20261024T140323Z` — combined churn
- `combined-upload-ab-20261024T140400Z` — combined 1 GiB upload
- `combined-download-ab2-20261024T140540Z` — combined 1 GiB download
- `combined-xudp-v6-ab-20261024T140650Z`,
  `combined-xudp-v6-ab2-20261024T140817Z`,
  `combined-xudp-v6-swap-20261024T141333Z` — combined IPv6 echo, 20k
- `combined-xudp-v6-long-20261024T142137Z` — combined IPv6 echo, 100k
- `xudp-only-v6-long-20261024T142502Z`,
  `relay-xudp-v6-long-20261024T142328Z`,
  `tls-xudp-v6-long-20261024T142637Z` — isolation, 100k
- `combined-relay-idle-ab-20261024T141657Z` — combined idle relay
- `combined-xudp-burst-ab-20261024T141907Z` — combined UDP burst
- `upgrade-report-data.json` — consolidated numbers used above

Harness sources: `/tmp/opencode/run-xudp-ab.sh`,
`/tmp/opencode/xudp_driver.py`, `/tmp/opencode/udp_target.py`,
`/tmp/opencode/relay-idle-bench/`, and the existing
`/tmp/opencode/run-upload-ab.sh` / `run-download-ab.sh`.

## Combined local test

All three branches were cherry-picked onto
`improve/combined-local-2026-10-24` (tip `c3728a0`) and tested as one binary:

- Combined binary:
  `aa51e6d9bf9196cc681cea8a312b1f67438b244574d180dff335ec275079f6b2`
- `cargo fmt --all --check`: PASS
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS
- `cargo test --workspace`: PASS (299)
- Full TUN, 8 probes: **8/8 PASS**
- Churn: 5,000/5,000 HTTP 200, 26 s, fds 10 → 10, threads 2 → 2,
  RSS 7,884 → 8,808 KiB

Performance controls against the same stock binary:

| Test | Stock | Combined | Paired result |
|---|---:|---:|---:|
| 1 GiB upload CPU/GiB | 0.8032 s | 0.8000 s | -1.5% median, 4/6 |
| 1 GiB download CPU/GiB (10 reps) | 0.4823 s | 0.4849 s | -0.5% paired median, 6/10 |
| Idle relay CPU / 5 s, 120 directions | 5.406 ms | 0.712 ms | **-86.8%**, 10/10 |
| Idle relay polls/s | 586.2 | 24.0 | **-95.9%** |
| Idle relay stop latency | 247.1 ms | 3.5 ms | **-98.6%** |
| XUDP 300k burst CPU | 0.6195 s | 0.6154 s | -0.3% median, 3/6 |
| XUDP IPv6 echo CPU, 20k | 0.3684 s | 0.3735 s | **+1.2%**, 2/8 |
| XUDP IPv6 echo CPU, 100k | 1.8445 s | 1.8737 s | **+1.6%**, 0/4 |

The combined binary preserves the relay win and the small TLS upload gain.
Download is neutral within noise. The XUDP IPv6 echo result is the one
inconsistency. Longer 100k-packet samples confirm a repeatable +1.6% on the
combined binary, so this is not merely short-sample jitter. Isolation runs on
the same harness (4 samples each) gave:

| Build | IPv6 echo CPU delta vs stock | Wins |
|---|---:|---:|
| XUDP only | -0.8% | 2/4 |
| Relay only | +0.2% | 1/4 |
| TLS only | +1.1% | 1/4 |
| All three | +1.6% | 0/4 |

The combined build does not reproduce the XUDP-only gain. The most likely
explanation is code layout plus a small-record TLS interaction; the exact
IPv6 sizing test still proves the reserve no longer grows, but a combined-build
IPv6 CPU gain is **not** claimed. Re-measure the final deployment binary before
attributing a production CPU win to it. No correctness or stability regression
was observed: full TUN and 5,000-request churn pass, and the XUDP burst path is
neutral.

## Merge order and open items

All three branches are independent and based on `6616db2`; none is merged or
pushed. `improve/combined-local-2026-10-24` contains all three and passed the
combined test above. If merging separately, the suggested order is:

1. TLS record recycling (lowest risk, measured upload win).
2. Relay eventfd (small structural change, clear idle/cancel win).
3. XUDP reply admission (IPv6 sizing is proven; the combined CPU gain is not).

A live deploy remains a separate step. The live server remains on
`d017c131…`; no config, service, or deployment artifact was changed by this
pass. The 24-hour soak and privileged syscall/wakeup gates from
`docs/18-optimization-2026-10-24.md` remain pending.
