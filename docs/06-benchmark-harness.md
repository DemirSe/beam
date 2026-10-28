# Local benchmark harness: stock Xray v26.3.27 vs `beam`

Status: historical design note. The current harness is documented in
`bench/README.md` (`bench/run.sh`, `bench/no-tun.sh`, and the Python reporters);
the planned `bench/driver` and `bench/bin/fetch.sh` paths below were never
committed.

Read-only design aligned with `docs/04-benchmark.md` (goal, gates, local methodology, conditions, scenarios, tools, reporting). It targets the profile in `docs/00-scope.md` and the reference versions in `docs/01-compatibility.md`. No VPS, no repository change, no external network in any measured path. All traffic stays in three local namespaces.

## Targets and gates (from `docs/04-benchmark.md`; numeric rows are goals, aggregate/no-regression/soak/churn are hard requirements)

| Metric | Target / gate |
|---|---|
| Single-flow throughput | `beam` >= 1.15x stock |
| Multi-flow throughput (4/16) | `beam` >= 1.10x stock |
| p99 latency | `beam` <= stock |
| Responsiveness under bulk | `beam` <= stock |
| RSS after warm-up | `beam` <= 50% of stock |
| CPU per GiB | `beam` < stock |
| Aggregate / regressions / stability | aggregate (geometric mean throughput ratio) better; no condition regressed beyond noise (max 2%, 2x pooled CV); no crash/leak/leakage; 24 h soak + 10k churn pass |

## Privilege model (local facts verified)

This host: 4 physical cores (0-3), SMT siblings `(0,4) (1,5) (2,6) (3,7)`, 8 threads; kernel 7.2.10. `NoNewPrivs: 1`, so `sudo` fails. `unshare --user --map-root-user --net --mount` works, and veth, `ip netns`, and `netem` all work inside it. `tc`, `iperf3`, `h2load`, `perf`, and `bpftrace` are not on `PATH`; `dnf download --arch=x86_64` + `rpm2cpio` extraction works (verified with `tc` netem and iperf3). `perf_event_paranoid=2`; perf software events work for a launched child, tracepoints do not. `curl` has HTTP/3; `dig`, `ss`, `nstat`, `jq`, `taskset`, `unshare` exist.

| Step | Root / `--privileged` | `--user` fallback |
|---|---|---|
| netns, veth, addresses, routes, netem | normal | userns + private mount ns; mount tmpfs on `/run`, create `/run/netns`; verified |
| CPU pinning | `taskset` or cpuset | `taskset` only |
| IRQ affinity, governor, sysctls | yes | unavailable; record MHz/load instead |
| syscalls, wakeups, splice bytes | perf tracepoints / bpftrace | perf `task-clock,context-switches,page-faults`; `/proc/<pid>/io` `syscr+syscw`; beam dev counters |
| RPM tools (`tc`, iperf3, h2load, perf) | package install | `dnf download` + `rpm2cpio`, per-RPM prefix, `LD_LIBRARY_PATH` for iperf3 |

The unprivileged run cannot prove the syscall/wakeup gates. It records them as `unavailable` and must be followed by one privileged acceptance run on a root-capable host. Never weaken a gate to make `--user` pass.

## Topology

```text
client ns                         server ns                         target ns
10.10.1.2/24 --vc|sc-- 10.10.1.1  10.10.2.1 --vs|ts-- 10.10.2.2/24
  sing-box TUN 198.18.0.1/15        VLESS :443                  origin :8080/:4443
  driver, iperf3, curl, dig         cover TCP :443              DNS UDP :53, H3 UDP :443
```

Set `lo` up in every namespace; client default route via `10.10.1.1`; target uses its connected route. No default route leaves the server/target namespaces, so an accidental external dependency fails immediately. Target also runs a local TLS cover on TCP 443 (generated cert, SNI `whatsapp.net`); REALITY `dest` points at it. The cover is used only by unauthenticated probes and is not in the measured authenticated path.

`tc` on veth egress, e.g. `tc -n server qdisc add dev sc root netem delay 5ms loss 1% limit 20000`: total RTT `R` means `delay R/2` on both client `vc` and server `sc`; loss/reorder apply to the direction under test (download: `sc`; upload: `vc`; bidirectional: both), target link clean. Use `limit 20000` to avoid BDP drops at 100 ms; capture `tc -s` and invalidate a run if qdisc drops occur. For loss/reorder, disable GSO/TSO/GRO on the veths so drops are per packet; record and use the same setting both arms. MTU 9000 sets all veths, TUN, and target to 9000 in both arms.

## CPU modes

| Mode | server | client + driver | target | Purpose |
|---|---|---|---|---|
| `vps-1c` (headline) | CPU 2 | CPU 1 | CPU 3 | 1-vCPU VPS server; distinct physical cores, siblings idle |
| `vps-2c` | CPUs 2,3 | CPU 1 | CPU 0 | docs' 2-core condition |
| `shared-1c` | CPU 2 | CPU 2 | CPU 2 | optional all-roles contention stress |

Use one logical thread per physical core (no SMT), `taskset -c` for every process, and leave core 0 free in `vps-1c`. Record topology and actual masks. Abort if host load exceeds 0.3 or non-role CPU busy exceeds 5%; record `scaling MHz` before/after.

## Traffic and scenarios

| ID | `docs/04-benchmark.md` scenario | Driver |
|---|---|---|
| `bulk-dl` / `bulk-ul` | 1, 2, 3 | `iperf3 -c 10.10.2.2 -t 35 -O 5 -l 128K` (`-R` for upload), `-P 1,4,16`, JSON |
| `bidi` | direction=bidirectional | `iperf3 --bidir`, report both directions |
| `interactive` | 4 | bulk iperf3 + driver request every 50 ms; payloads 1 B, 1 KiB, 64 KiB; curl H1/H2, h2load H2; TTFB |
| `dns` | 5 | driver UDP/53 at fixed qps; `dig +tries=1 +time=1 @10.10.2.2` spot-checks |
| `h3` | 6 | `curl --http3-only` to UDP/443; driver H3 origin; 1, 4 and 16 flows |
| `churn` | 7 | driver: 10,000 TCP connections, `Connection: close`, concurrency 64 |
| `soak` | 8 | 24 h mixed low-rate profile, resource sampling every second |

Core matrix: RTT 0/10/50/100 ms, loss 0/1/5%, reorder 0/25% (subset), flows 1/4/16, upload/download/bidirectional, payload 1 B/1 KiB/64 KiB/bulk, MTU 1500/9000, CPU 1/2. Run a ~32-condition core subset by default; `--full` expands the Cartesian product. HTTP/DNS/churn payloads are generated once, hashed, and reused; iperf3 uses the same pinned version, block size, and duration both arms.

## Metrics and tools

| Metric | Collection |
|---|---|
| Throughput, retransmits, errors | iperf3 JSON intervals; target byte counters; `nstat -az`, `ss -s` per ns |
| p50/p95/p99, TTFB, connect | driver JSONL monotonic timestamps; `curl -w`; timeouts counted separately from latency |
| Responsiveness | same driver during bulk; compare with idle baseline |
| CPU per GiB | `/proc/<pid>/stat` utime+stime delta / application GiB, per direction/flow; perf `task-clock` as cross-check |
| RSS / peak | `/proc/<pid>/status` `VmRSS`, `VmHWM`, sampled 1 s; 24 h growth slope |
| fds, threads | `/proc/<pid>/fd` count, `Threads`, sampled 1 s; max and end |
| Context switches / wakeups | root: `perf stat -e sched:sched_wakeup`; user: `voluntary_ctxt_switches` + `nonvoluntary_ctxt_switches` as proxy |
| Syscalls per GiB | root: `perf stat -e raw_syscalls:sys_enter` or bpftrace count; user: `/proc/<pid>/io` `syscr+syscw`, marked partial |
| Splice bytes | beam development counters or root bpftrace; informational only (stock Xray does not splice) |
| Frequency, load, qdisc | `/proc/cpuinfo`, `/proc/loadavg`, `tc -s`, `ethtool -k` |

Tools: `iperf3` bulk, `curl`/`h2load` HTTP and TTFB, `dig` DNS correctness, `perf`/`bpftrace` kernel counters, `ss`/`nstat`/`/proc` lifecycle and system counters. `bench/driver` supplies precise request timing, DNS load, churn, and the H1/H2/H3 origin; it is benchmark-only and workspace-excluded.

## Fairness protocol

- Generate an ephemeral UUID, REALITY keypair, and short ID per session; both server configs use the same values. Store config SHA-256 only; config files are 0600 in a 0700 run dir; never print secrets.
- One sing-box v1.14.3 TUN client (pinned; local 1.14.2 only for dry-run) with a byte-identical config for both arms. Same server address, target IPs/ports, TUN MTU, `stack: system`, `utls: chrome`, `flow: xtls-rprx-vision`, `packet_encoding: xudp`. Origin leaf has IP SAN `10.10.2.2`; tools trust the local CA via `--cacert`/`SSL_CERT_FILE`.
- Server configs are semantically identical: same listener, flow, limits, cover, `warn` logging, no stats/debug counters. Set `GOMAXPROCS` and Tokio worker count to the server vCPU count for both arms; scrub proxy env. Fail preflight if either config is rejected or differs in effective limits.
- Target services start once per session and stay up; only the server binary/config changes between arms; server and client restart per repetition; qdiscs are deleted and re-added; same warm-up and measurement windows.
- Each timed scenario runs >= 5 times (soak once); report median and min/max, excluding warm-up. Order is balanced ABBA, not all-stock-then-all-beam. Record host load, client CPU, target CPU; flag a run as client/target-bound above 85% of its pinned core and do not use it for the headline.

## Result format

One self-contained `run.json` per arm/scenario/repetition (shape below, arrays abbreviated); `manifest.json` indexes the session; `summary.json` aggregates ratios and gates. Raw arrays are retained; the 24 h soak uses `samples.jsonl` plus a summary.

```json
{"schema":"beam-bench/1","run_id":"...","arm":"beam","scenario":"bulk-dl-rtt10",
 "git":{"commit":"...","dirty":false},
 "binaries":{"server":{"path":"...","sha256":"..."},"client":{"sha256":"..."},"tools":{...}},
 "host":{"kernel":"...","cpu":"...","cores":4,"threads":8,"loadavg":[...],"toolchain":{"rustc":"...","go":"..."}},
 "env":{"rtt_ms":10,"loss_pct":0,"reorder_pct":0,"mtu":1500,"flows":4,"direction":"download","cpu_mode":"vps-1c","warmup_s":5,"measure_s":30},
 "commands":[["ip","netns","exec","client","taskset","-c","1","iperf3", "..."],["taskset","-c","2","..."]],
 "configs":{"server_sha256":"...","client_sha256":"..."},
 "raw":{"throughput_bps":[...],"latency_us":[...],"ttfb_us":[...],"cpu_s":[...],"rss_kib":[...],"fds":[...],"threads":[...],"syscalls":[...],"wakeups":[...]},
 "summary":{"throughput_bps":{"median":0,"min":0,"max":0},"latency_us":{"p50":0,"p95":0,"p99":0},"cpu_s_per_gib":0,"rss_kib_max":0,"fds_max":0,"threads_max":0,"syscalls_per_gib":null,"wakeups_per_s":null},
 "gates":{"single_flow_ratio":1.0,"p99_ratio":1.0,"pass":false},"warnings":[]}
```

## Script layout

```text
bench/
  run.sh                    # preflight|up|smoke|run|report|down
  lib/{netns,netem,pin,measure}.sh  # setup/teardown, qdiscs, masks, sampling
  bin/fetch.sh              # pinned tools/binaries, SHA-256 manifest
  scenarios/core.json       # axes, payload hashes, timing schedule
  configs/                  # xray.json, beam.toml, singbox.json, generated certs
  driver/                   # Rust: origin H1/H2/H3, DNS, churn, timer
  report.py                 # raw JSON -> summary, gates, markdown
  results/                  # gitignored; or $BENCH_OUT
```

`run.sh --user` re-execs itself under `unshare --user --map-root-user --mount --net` after checking `NoNewPrivs`, userns availability, `sch_netem`, and tools. It sets `mount -t tmpfs tmpfs /run`, `mkdir -p /run/netns`, and tears everything down in a trap. Every network command has `timeout`; every process has a log under `results/.../logs`.

## First commands

```bash
cd /home/demir/pi/beam
git rev-parse HEAD; sha256sum /tmp/opencode/xray-server-compare/xray /usr/local/bin/sing-box
unshare --user --map-root-user --mount --net sh -c \
  'mount -t tmpfs tmpfs /run; mkdir -p /run/netns; ip netns add probe; \
   ip link add v0 type veth peer name v1; ip netns list'
bench/bin/fetch.sh              # dnf download --arch=x86_64 + rpm2cpio; hashes
bench/run.sh --user preflight
bench/run.sh --user up
bench/run.sh --user smoke --arm stock --duration 5
bench/run.sh --user run --arms stock,beam --scenario core/bulk-dl-rtt10 --reps 5
bench/run.sh --user report --out bench/results/latest
```

The first three probes work today. Beam's CLI is not implemented yet; `run.sh` takes `BEAM_BIN`/`BEAM_ARGS` and records argv, so stock-only smoke works now. On a root-capable host later: `bench/run.sh --privileged --full --with-kernel` for syscall/wakeup gates and the 24 h soak.

## Limits

- H3 needs a local HTTP/3 origin; if `bench/driver` cannot serve it, mark `h3` BLOCKED, never substitute TCP.
- Unprivileged runs cannot validate syscall/wakeup/splice gates; state this in the report and require one privileged acceptance run.
- Local cover/cert is for handshake realism and probe checks only; do not infer REALITY probe resistance from throughput runs.
- netem queue drops, client CPU saturation, and target saturation are invalidating conditions, not results to average.

## Prep environment on this host

The design was validated on the current development host. These paths are
temporary and must be recreated by `bench/bin/fetch.sh`; they are recorded here
so a later agent can reproduce the setup.

| Tool | Path / setting |
|---|---|
| Stock Xray v26.3.27 | `/tmp/opencode/xray-server-compare/xray` |
| sing-box v1.14.3 | `/tmp/opencode/bench/bin/sing-box` |
| `tc` | `/tmp/opencode/tools/root/usr/bin/tc` |
| `iperf3` | `/tmp/opencode/tools/root/usr/bin/iperf3` |
| `iperf3` library | `LD_LIBRARY_PATH=/tmp/opencode/tools/root/usr/lib64` |

User namespaces, veth, and netem work without root. `perf` tracepoints,
IRQ affinity, and sysctl changes still need a privileged acceptance run.
