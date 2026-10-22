# Local performance benchmark: stock Xray v26.3.27 vs `beam`

This directory contains the local throughput, latency, CPU and memory
comparison for the full-TUN profile. It reuses the verified three-namespace
topology and the same sing-box v1.14.3 client as `tests/tun/run.sh`.

The measured path never leaves the host: no VPS, no external network, no
production credentials. The only dependency fetch is the one-time build of
the test-only HTTP/3 origin before the private network namespace is entered.

## Topology and fairness

```text
client ns                         server ns                     target ns
10.10.1.2/24 -- vc | sc -- 10.10.1.1/24
                                 10.10.2.1/24 -- vs | ts -- 10.10.2.2/24
sing-box TUN 198.18.0.1/15       VLESS+REALITY+Vision :443   HTTP :8080
routes 10.10.2.0/24 to tun0                                   HTTPS :4443
                                                              UDP echo :9999
                                                              DNS :53
                                                              HTTP/3 UDP :4443
                                                              iperf3 :5201
```

- One sing-box config, byte-identical for both arms. The client uses
  `flow: xtls-rprx-vision`, `packet_encoding: xudp`, `utls: chrome`,
  `stack: system`, MTU 1500.
- Both server configs are rendered from the same REALITY fixture (UUID,
  private key, short id, SNI). Nothing secret is printed or committed.
- The target services and the HTTPS payload are started once per session and
  are identical for both arms.
- Only the server binary (`target/release/beam` or stock Xray) and its
  semantically equivalent config change between arms.
- The default CPU model is the documented `vps-1c` shape: server on one
  logical CPU, client + driver on another, target on a third. The exit trap
  records the actual affinity masks in `masks.tsv` and in `summary.md`.
- Ordering is balanced: odd repetitions run stock then beam, even repetitions
  run beam then stock.
- A warm-up (TCP, HTTPS, UDP, DNS, HTTP/3) runs before every arm/repetition
  and is excluded from the measured scenarios.

## Usage

```bash
cd <worktree>
source scripts/dev-env.sh
bash -n bench/run.sh
bash bench/run.sh --reps 3                 # full run, ~6-8 minutes
bash bench/run.sh --quick --reps 1         # smoke run
bash bench/run.sh --arms beam              # one arm only
bash bench/run.sh --out /tmp/my-run        # explicit result directory
```

Defaults: 3 repetitions, 10 s per TCP scenario, 64 MiB HTTPS payload,
50 HTTP/3 requests, 200 DNS queries, 5000 UDP echo packets. Results are
written to `bench/results/<UTC timestamp>/`.

Options:

| Option | Meaning |
|---|---|
| `--reps N` | repetitions per arm (default 3) |
| `--duration S` | seconds per iperf3 scenario (default 10) |
| `--arms stock,beam` | arms to run |
| `--out DIR` | result directory |
| `--quick` | 1 repetition, 3 s scenarios, smaller payloads |
| `--no-build` | reuse `target/release/beam` and the H3 origin |
| `--server-cpu N` | server affinity (default 2) |
| `--client-cpus 1[,5]` | client proxy affinity (default 1) |
| `--driver-cpu N` | driver affinity; defaults to the first client CPU |
| `--target-cpu N` | target affinity (default 3) |
| `--rtt-ms N` | add `N/2` ms netem delay on each client/server veth (default 0) |
| `--max-load L` | host load warning threshold (default 0.3) |

Environment variables: `SING_BOX`, `XRAY_BIN`, `IPERF3`, `IPERF3_LIB`,
`TC`, `TEST_CONFIG`, `H3_ORIGIN_BIN`, `SKIP_BUILD`, and the `BENCH_*`
equivalents for the options above.

Tools used from `/tmp/opencode` (recreated by the harness when missing):

| Tool | Default path |
|---|---|
| stock Xray v26.3.27 | `/tmp/opencode/xray-server-compare/xray` |
| sing-box v1.14.3 | `/tmp/opencode/bench/bin/sing-box` |
| iperf3 3.22 | `/tmp/opencode/tools/root/usr/bin/iperf3` |
| iperf3 library | `LD_LIBRARY_PATH=/tmp/opencode/tools/root/usr/lib64` |
| `tc` | `/tmp/opencode/tools/root/usr/bin/tc` |

## Scenarios and metrics

| Scenario | Driver | Metric |
|---|---|---|
| `tcp-dl-1`, `tcp-dl-4` | `iperf3 -R -P 1/4 -l 128K` | Mbit/s, bytes, retransmits, CPU/GiB |
| `tcp-ul-1`, `tcp-ul-4` | `iperf3 -P 1/4 -l 128K` | Mbit/s, bytes, retransmits, CPU/GiB |
| `https-bulk` | `curl --http1.1` for a local 64 MiB file | MiB/s through Vision Direct |
| `udp-echo` | UDP echo, 1200 B, window 32 | kpps, Mbit/s, loss, p50/p95/p99 |
| `dns-a` | 200 UDP A queries for `target.test` | p50/p95/p99, loss |
| `h3-latency` | 50 `curl --http3-only` requests | p50/p95/p99 (includes QUIC handshake) |

Per-scenario JSON records the application metrics, server CPU seconds and
CPU seconds per GiB, client/target/driver core utilisation, RSS after warm-up,
peak RSS, file descriptors, threads, host load, and CPU frequency before/after.

Latency percentiles pool every raw sample from every repetition. Throughput,
CPU/GiB and HTTPS rates report median with min/max across repetitions.

## Result semantics

- `PASS` / `FAIL`: a valid measurement against the relative gate.
- `INVALID`: the scenario ran, but the client or target core was at or above
  85%, so the number describes the harness limit, not the server. The ratio is
  still printed; it cannot be used for the headline.
- `BLOCKED`: the metric could not be measured (for example no local HTTP/3
  origin or no HTTP/3-capable curl). The exact reason is in `summary.json`.
- `INFO`: diagnostic row without a gate.

The report also records host noise (load above the threshold, non-role CPU
busy). A clean run requires both `valid` and `headline_eligible` to be true.

Known limitation on this development host: the single-core sing-box full-TUN
client is the throughput bottleneck at roughly 2.5-3.5 Gbit/s. The server uses
well under a full core at that rate. The throughput scenarios are therefore
reported as `INVALID` for the headline on this host; CPU per GiB and RSS are
still server-side measurements and remain comparable. A wider client (for
example `--client-cpus 1,5 --driver-cpu 0`) was also tested; it raises absolute
throughput but the client remains the bottleneck.

## Artifacts

```text
bench/results/<timestamp>/
  summary.json              aggregated metrics, gates, validity
  summary.md                compact human report
  meta.json                 commit, host, binaries, hashes, masks, load
  environment.txt           run id, paths, payload hash, RTT, roles
  masks.tsv                 per-arm/per-repetition actual affinity masks
  network.txt               addresses and routes from all namespaces
  logs/                     server/client/target/tool logs (gitignored)
  raw/                      one JSON per arm/scenario/repetition (gitignored)
  config/                   test-only configs and payload (gitignored)
```

`summary.json` and `summary.md` are kept with the run; `raw/`, `logs/`, and
`config/` are ignored because they are large and contain test-only material.
No REALITY private key, UUID, or generated TLS key is written to the report.

## Verification of the harness itself

```bash
bash -n bench/run.sh
python3 -m py_compile bench/measure.py bench/report.py bench/meta.py
bash bench/run.sh --quick --reps 1 --arms stock
bash bench/run.sh --quick --reps 1
```

The full-TUN correctness matrix remains `tests/tun/run.sh`; this harness does
not replace it. The benchmark reuses the same client config renderer and
target services, with two additive options (`config.py --log-level` and
`services.py --large-file/--quiet`).

## Server-capacity smoke without TUN

```bash
bash bench/no-tun.sh
```

This uses a stock Xray SOCKS client (VLESS + REALITY + Vision) against either
stock Xray or beam, with the 256 MiB target on separate physical CPUs. It
removes the sing-box TUN client cap and exposes the server data path.

Latest local result (2026-10-22, loopback, test fixture from
`config.example.toml`, **balanced 8-repetition order passes**):

| Arm | Median | Min | Max |
|---|---:|---:|---:|
| beam | **897.1 MB/s** | 868.0 | 921.3 |
| stock Xray | **613.4 MB/s** | 197.4* | 649.3 |

Beam/stock ratio: **1.462x** on the warm samples. *One stock outlier; the
median is unaffected. An earlier single-order run measured 889.3 vs 569.5
MB/s (1.562x). The balanced result is the current figure. This is a
server-capacity smoke test, not a WAN or full-TUN headline; the full-TUN
client remains the bottleneck in the main harness. See
`docs/16-local-comparison-2026-10-22.md` for the full comparison.

## Connection churn smoke

```bash
bash bench/churn.sh
```

The last local run sent **1,000** requests at concurrency **32** through the
stock Xray SOCKS client. All 1,000 returned HTTP 200 in ~5 seconds. Beam's
server RSS moved from 7,676 KiB to 8,328 KiB after warm-up; threads stayed at 2
and file descriptors at 10. A failure count or an fd growth above baseline + 16
fails the script.

This is a short smoke, not a 24-hour soak. The 24-hour soak and privileged
syscall/wakeup gates still need a dedicated acceptance run.
