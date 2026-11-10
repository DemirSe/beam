# Local benchmark: stock Xray v26.3.27 vs beam

Run: `20261109T233215Z-3345`  
Generated: 2026-11-10T00:59:56Z  
Worktree: `/home/runner/work/beam/beam`  
Commit: `9d67ebc51073d8a490e1960d893699cbdb159e28` (dirty=False)  
Kernel: `Linux 7.0.0-1017-azure x86_64 GNU/Linux`  CPU: AMD EPYC 9V45 96-Core Processor (4 logical threads)

## Conditions

- CPU roles: server `CPU 2`, client + driver `CPU 0,1`, target `CPU 3`; free: 
- Actual affinity masks: server `2`, client `0,1`, target `3`
- Repetitions: 10 per arm, 10 s per bulk scenario, warm-up excluded.
- netem RTT: 250 ms total (125 ms on each veth); injected loss: 0.0%; target link clean.
- Host load threshold: 4.0 (1-minute average).
- Client: sing-box v1.14.3 full TUN, utls chrome, VLESS + REALITY + Vision, XUDP; byte-identical config for both arms.
- beam: `/home/runner/work/beam/beam/target/release/beam` sha256 `df644543bd261420…`
- stock: `/home/runner/work/_temp/tools/xray-bin` sha256 `8255dd939c34cf96…`
- singbox: `/home/runner/work/_temp/tools/sing-box` sha256 `768d31fa7f68debc…`
- iperf3: `/usr/bin/iperf3` sha256 `39ac8bc6433ea045…`
- h3_origin: `/home/runner/work/beam/beam/tests/tun/h3-origin/target/debug/h3-origin` sha256 `cb78d86feb620e88…`
- Host load: before 1.51, after 1.33.
- HTTPS payload: 64 MiB, sha256 `5d59a5b5f610028c…`.
- HTTP/3 origin: ready

## Gates

| Gate | Requirement | Result |
|---|---|---|
| single_flow_throughput | beam >= 1.15x stock for 1-flow download and upload | INFO |
| multi_flow_throughput | beam >= 1.10x stock for 4-flow download and upload | INFO |
| p99_latency | beam p99 <= stock p99 (DNS, HTTP/3) | INFO |
| rss_after_warmup | beam <= 50% of stock RSS after warm-up | INFO |
| cpu_per_gib | beam server CPU per GiB < stock in every TCP scenario | INFO |
| aggregate_throughput | geometric mean of TCP throughput ratios > 1.0 | INFO |
| no_regression | no throughput < 0.98x and no latency > 1.02x | INFO |

## Throughput (median, min–max over repetitions)

| Metric | stock Xray | beam | ratio (beam/stock) | Gate | Result |
|---|---|---|---|---|---|
| TCP download, 1 flow | 94.2 Mbit/s (85.45–96.67) | 101.6 Mbit/s (99.08–103.49) | 1.079x | >= 1.15x | FAIL |
| TCP download, 4 flows | 366.4 Mbit/s (353.75–375.04) | 399.1 Mbit/s (374.51–403.34) | 1.089x | >= 1.10x | FAIL |
| TCP upload, 1 flow | 97.1 Mbit/s (95.12–99.93) | 97.2 Mbit/s (94.51–98.97) | 1.001x | >= 1.15x | FAIL |
| TCP upload, 4 flows | 367.2 Mbit/s (350.24–384.70) | 385.6 Mbit/s (381.48–390.42) | 1.050x | >= 1.10x | FAIL |
| HTTPS Vision Direct, 64 MiB | 9.3 MiB/s (8.73–9.43) | 9.0 MiB/s (8.80–9.21) | 0.965x | >= 0.98x (no regression) | FAIL |

## UDP

| Metric | stock Xray | beam | ratio (beam/stock) | Requirement | Result |
|---|---|---|---|---|---|
| UDP echo packet rate | 0.12 kpps (0.12–0.12) | 0.12 kpps (0.12–0.12) | 1.000x | >= 0.98x (no regression) | PASS |
| UDP echo throughput | 1.2 Mbit/s (1.19–1.20) | 1.2 Mbit/s (1.19–1.20) | 1.000x | >= 0.98x (no regression) | PASS |
| UDP echo loss | 0.00% (0.00–0.00) | 0.00% (0.00–0.00) | n/a | informational | INFO |

## Latency (pooled samples, p50/p95/p99)

| Metric | stock Xray | beam | ratio (beam/stock) | Requirement | Result |
|---|---|---|---|---|---|
| DNS A over UDP p50 | 250.859 ms | 250.565 ms | 0.999x | informational | INFO |
| DNS A over UDP p95 | 254.869 ms | 253.935 ms | 0.996x | informational | INFO |
| DNS A over UDP p99 | 256.992 ms | 255.035 ms | 0.992x | <= 1.00x | PASS |
| QUIC/HTTP3 requests p50 | 1,010.264 ms | 1,009.313 ms | 0.999x | informational | INFO |
| QUIC/HTTP3 requests p95 | 1,014.510 ms | 1,011.269 ms | 0.997x | informational | INFO |
| QUIC/HTTP3 requests p99 | 1,017.308 ms | 1,012.037 ms | 0.995x | <= 1.00x | PASS |
| UDP echo p50 | 250.546 ms | 250.502 ms | 1.000x | informational | INFO |
| UDP echo p95 | 253.998 ms | 253.052 ms | 0.996x | informational | INFO |
| UDP echo p99 | 256.808 ms | 254.409 ms | 0.991x | informational | INFO |

## Resources

| Metric | stock Xray | beam | ratio | Requirement | Result |
|---|---|---|---|---|---|
| Server CPU per GiB, TCP download, 1 flow | 1.261 s/GiB (1.16–1.39) | 0.766 s/GiB (0.69–0.86) | 0.607x | < 1.00x | PASS |
| Server CPU per GiB, TCP download, 4 flows | 1.325 s/GiB (1.27–1.44) | 0.736 s/GiB (0.68–0.77) | 0.555x | < 1.00x | PASS |
| Server CPU per GiB, TCP upload, 1 flow | 1.956 s/GiB (1.79–2.17) | 1.292 s/GiB (1.13–1.54) | 0.660x | < 1.00x | PASS |
| Server CPU per GiB, TCP upload, 4 flows | 1.769 s/GiB (1.71–1.92) | 1.159 s/GiB (1.12–1.45) | 0.655x | < 1.00x | PASS |
| Server CPU per GiB, HTTPS Vision Direct | 0.213 s/GiB (0.21–1.55) | 0.267 s/GiB (0.21–0.32) | 1.250x | informational | INFO |
| Client proxy CPU per GiB (TCP median) | 7.466 s/GiB | 7.181 s/GiB | 0.962x | informational | INFO |
| Server RSS after warm-up (peak) | 37.2 MiB | 9.6 MiB | 0.257x | <= 0.50x | PASS |
| Server file descriptors (max) | 54 | 50 | n/a | no leak | INFO |
| Server threads (max) | 8 | 4 | n/a | no leak | INFO |
| Client + driver core busy (TCP scenarios) | 48.94% (12.22–92.99) | 44.06% (20.59–80.93) | n/a | < 85% (median) | PASS |
| Target core busy (TCP scenarios) | 20.08% (0.82–55.34) | 24.50% (5.40–63.76) | n/a | < 85% (median) | PASS |
| Server cgroup CPU ceiling (cpu.max) | 50000 100000 | 50000 100000 | n/a | informational | INFO |
| Server cgroup memory ceiling (memory.max) | 1073741824 | 1073741824 | n/a | informational | INFO |
| Server memory peak (memory.peak) | 27.8 MiB | 21.8 MiB | n/a | informational | INFO |
| Server OOM kills (memory.events) | 0 | 0 | n/a | informational | INFO |
| Server core busy (TCP scenarios) | 27.84% (2.05–51.85) | 24.18% (10.88–46.79) | n/a | 1-vCPU model | INFO |

## Validity

- Ratio-only mode: gate results are informational; summary.json keeps the strict verdicts.

## Limitations

- Unprivileged user namespace: perf tracepoints, IRQ affinity and sysctls are unavailable, so syscall/wakeup/splice gates are not measured. Use the privileged acceptance run for those.
- A throughput scenario whose client, target or driver core median is at or above 85% is reported as INVALID, not as a pass or fail. Single-repetition peaks are shown in the resource rows but do not condemn a scenario.
- Host-noise coverage: role cores and their hyperthread siblings claimed every logical CPU, so no core was left to observe and the CPU noise metric is empty. Only the settled host load average reports interference here, and it cannot see load that exists solely inside the measurement windows.
- HTTP/3 uses the test-only local origin; it is not a general QUIC capacity test.
