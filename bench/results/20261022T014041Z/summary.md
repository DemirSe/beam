# Local benchmark: stock Xray v26.3.27 vs beam

Run: `20261022T014041Z-1969179`  
Generated: 2026-10-22T01:45:40Z  
Worktree: `/home/demir/.local/share/opencode/worktree/3dd5f2/bench-harness`  
Commit: `c23bfc7ab6801cff5421932f4ea1d07e9faf2620` (dirty=False)  
Kernel: `Linux 7.2.10-200.fc44.x86_64 x86_64 GNU/Linux`  CPU: 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (8 logical threads)

## Conditions

- CPU roles: server `CPU 2`, client + driver `CPU 1`, target `CPU 3`; free: 0, 4, 5, 6, 7
- Actual affinity masks: server `2`, client `1`, target `3`
- Repetitions: 3 per arm, 10 s per bulk scenario, warm-up excluded.
- netem RTT: 0 ms total (0 ms on each veth); target link clean.
- Client: sing-box v1.14.3 full TUN, utls chrome, VLESS + REALITY + Vision, XUDP; byte-identical config for both arms.
- beam: `/home/demir/.local/share/opencode/worktree/3dd5f2/bench-harness/target/release/beam` sha256 `787f97e06468b927…`
- stock: `/tmp/opencode/xray-server-compare/xray` sha256 `8255dd939c34cf96…`
- singbox: `/tmp/opencode/bench/bin/sing-box` sha256 `768d31fa7f68debc…`
- iperf3: `/tmp/opencode/tools/root/usr/bin/iperf3` sha256 `1e9652955954e762…`
- h3_origin: `/home/demir/.local/share/opencode/worktree/3dd5f2/bench-harness/bench/../tests/tun/h3-origin/target/debug/h3-origin` sha256 `de30144ad177b81d…`
- Host load: before 3.1, after 2.05.
- HTTPS payload: 64 MiB, sha256 `cd62408d27f7c2d3…`.
- HTTP/3 origin: ready

## Gates

| Gate | Requirement | Result |
|---|---|---|
| single_flow_throughput | beam >= 1.15x stock for 1-flow download and upload | INVALID |
| multi_flow_throughput | beam >= 1.10x stock for 4-flow download and upload | INVALID |
| p99_latency | beam p99 <= stock p99 (DNS, HTTP/3) | FAIL |
| rss_after_warmup | beam <= 50% of stock RSS after warm-up | PASS |
| cpu_per_gib | beam server CPU per GiB < stock in every TCP scenario | PASS |
| aggregate_throughput | geometric mean of TCP throughput ratios > 1.0 | INVALID |
| no_regression | no throughput < 0.98x and no latency > 1.02x | INVALID |

## Throughput (median, min–max over repetitions)

| Metric | stock Xray | beam | ratio (beam/stock) | Gate | Result |
|---|---|---|---|---|---|
| TCP download, 1 flow | 1,597.0 Mbit/s (1,555.53–1,760.62) | 1,586.6 Mbit/s (1,568.45–1,742.82) | 0.993x | >= 1.15x | INVALID |
| TCP download, 4 flows | 1,504.2 Mbit/s (1,496.17–1,514.32) | 1,520.8 Mbit/s (1,512.96–1,525.31) | 1.011x | >= 1.10x | INVALID |
| TCP upload, 1 flow | 3,081.7 Mbit/s (3,054.71–3,086.67) | 3,107.3 Mbit/s (3,099.72–3,143.78) | 1.008x | >= 1.15x | INVALID |
| TCP upload, 4 flows | 2,945.1 Mbit/s (2,915.98–2,949.53) | 2,928.8 Mbit/s (2,907.13–2,936.82) | 0.994x | >= 1.10x | INVALID |
| HTTPS Vision Direct, 64 MiB | 199.4 MiB/s (196.25–208.64) | 201.1 MiB/s (198.50–205.80) | 1.008x | >= 0.98x (no regression) | INVALID |

## UDP

| Metric | stock Xray | beam | ratio (beam/stock) | Requirement | Result |
|---|---|---|---|---|---|
| UDP echo packet rate | 47.41 kpps (46.20–49.21) | 50.78 kpps (50.01–51.00) | 1.071x | >= 0.98x (no regression) | PASS |
| UDP echo throughput | 455.2 Mbit/s (443.54–472.40) | 487.5 Mbit/s (480.13–489.56) | 1.071x | >= 0.98x (no regression) | PASS |
| UDP echo loss | 0.00% (0.00–0.00) | 0.00% (0.00–0.00) | n/a | informational | INFO |

## Latency (pooled samples, p50/p95/p99)

| Metric | stock Xray | beam | ratio (beam/stock) | Requirement | Result |
|---|---|---|---|---|---|
| DNS A over UDP p50 | 0.055 ms | 0.047 ms | 0.843x | informational | INFO |
| DNS A over UDP p95 | 0.097 ms | 0.062 ms | 0.633x | informational | INFO |
| DNS A over UDP p99 | 0.161 ms | 0.212 ms | 1.314x | <= 1.00x | FAIL |
| QUIC/HTTP3 requests p50 | 7.283 ms | 7.543 ms | 1.036x | informational | INFO |
| QUIC/HTTP3 requests p95 | 8.092 ms | 8.445 ms | 1.044x | informational | INFO |
| QUIC/HTTP3 requests p99 | 8.477 ms | 8.600 ms | 1.015x | <= 1.00x | FAIL |
| UDP echo p50 | 0.047 ms | 0.042 ms | 0.876x | informational | INFO |
| UDP echo p95 | 0.072 ms | 0.054 ms | 0.757x | informational | INFO |
| UDP echo p99 | 0.117 ms | 0.089 ms | 0.763x | informational | INFO |

## Resources

| Metric | stock Xray | beam | ratio | Requirement | Result |
|---|---|---|---|---|---|
| Server CPU per GiB, TCP download, 1 flow | 0.597 s/GiB (0.60–0.60) | 0.476 s/GiB (0.47–0.48) | 0.798x | < 1.00x | PASS |
| Server CPU per GiB, TCP download, 4 flows | 0.614 s/GiB (0.61–0.62) | 0.483 s/GiB (0.48–0.48) | 0.786x | < 1.00x | PASS |
| Server CPU per GiB, TCP upload, 1 flow | 0.713 s/GiB (0.71–0.72) | 0.630 s/GiB (0.62–0.63) | 0.883x | < 1.00x | PASS |
| Server CPU per GiB, TCP upload, 4 flows | 0.720 s/GiB (0.72–0.72) | 0.634 s/GiB (0.63–0.64) | 0.880x | < 1.00x | PASS |
| Server CPU per GiB, HTTPS Vision Direct | 0.160 s/GiB (0.16–0.21) | 0.373 s/GiB (0.37–0.37) | 2.333x | informational | INFO |
| Client proxy CPU per GiB (TCP median) | 3.389 s/GiB | 3.405 s/GiB | 1.005x | informational | INFO |
| Server RSS after warm-up (peak) | 36.0 MiB | 8.6 MiB | 0.239x | <= 0.50x | PASS |
| Server file descriptors (max) | 60 | 66 | n/a | no leak | INFO |
| Server threads (max) | 7 | 3 | n/a | no leak | INFO |
| Client + driver core busy (TCP scenarios) | 100.00% (99.90–100.00) | 100.00% (99.90–100.00) | n/a | < 85% | FAIL |
| Target core busy (TCP scenarios) | 11.84% (7.52–16.13) | 9.32% (7.13–11.76) | n/a | < 85% | PASS |
| Server core busy (TCP scenarios) | 24.84% (15.03–35.49) | 22.25% (13.36–30.99) | n/a | 1-vCPU model | INFO |

## Validity

- Measurement valid (no client/target saturation, required data present): **no**
- Headline eligible (also free of host noise): **no**
- All numeric gates: **INVALID**
- Hard requirements (aggregate + no regression + valid + clean host): **INVALID**
- Invalidating conditions:
  - tcp-dl-1/stock: client core saturated (99.9-100.0%)
  - tcp-dl-1/beam: client core saturated (99.9-100.0%)
  - tcp-dl-4/stock: client core saturated (99.9-100.0%)
  - tcp-dl-4/beam: client core saturated (100.0-100.0%)
  - tcp-ul-1/stock: client core saturated (99.9-100.0%)
  - tcp-ul-1/beam: client core saturated (100.0-100.0%)
  - tcp-ul-4/stock: client core saturated (99.9-100.0%)
  - tcp-ul-4/beam: client core saturated (100.0-100.0%)
  - https-bulk/stock: client core saturated (98.9-99.0%)
  - https-bulk/beam: client core saturated (99.0-100.0%)
- Host noise:
  - host load after=2.05 (warning threshold 0.3)
  - host load before=3.1 (warning threshold 0.3)
  - dns-a/stock: non-role CPU busy (max 50.0%)
  - h3-latency/beam: non-role CPU busy (max 10.0%)
  - h3-latency/stock: non-role CPU busy (max 8.5%)
  - https-bulk/beam: non-role CPU busy (max 9.0%)
  - https-bulk/stock: non-role CPU busy (max 11.9%)
  - tcp-dl-1/beam: non-role CPU busy (max 8.6%)
  - tcp-dl-1/stock: non-role CPU busy (max 8.7%)
  - tcp-dl-4/beam: non-role CPU busy (max 7.9%)
  - tcp-dl-4/stock: non-role CPU busy (max 8.8%)
  - tcp-ul-1/beam: non-role CPU busy (max 8.9%)
  - tcp-ul-1/stock: non-role CPU busy (max 10.0%)
  - tcp-ul-4/beam: non-role CPU busy (max 9.5%)
  - tcp-ul-4/stock: non-role CPU busy (max 9.7%)
  - udp-echo/beam: non-role CPU busy (max 16.7%)
  - udp-echo/stock: non-role CPU busy (max 16.7%)

## Limitations

- Unprivileged user namespace: perf tracepoints, IRQ affinity and sysctls are unavailable, so syscall/wakeup/splice gates are not measured. Use the privileged acceptance run for those.
- A throughput scenario where the client or target core is at or above 85% is reported as INVALID, not as a pass or fail.
- HTTP/3 uses the test-only local origin; it is not a general QUIC capacity test.
