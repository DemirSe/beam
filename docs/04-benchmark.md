# Benchmark plan

## Goal

Prove that `beam` is faster than stock Xray for the production profile on the
same hardware and under the same client behavior. "Faster" means the gates
below, not a single best-case number.

## Metrics

- Throughput: single flow and 4/16 flows, upload and download.
- Latency: TCP connect, TTFB, p50/p95/p99 request latency.
- Responsiveness: small request latency while a bulk transfer runs.
- CPU: seconds per GiB, normalized by direction and flow count.
- Memory: RSS after warm-up, peak RSS, and growth over 24 hours.
- Kernel: syscalls per GiB, context switches, wakeups, splice bytes.
- Stability: errors, resets, timeouts, and file descriptor count.

## Acceptance gates

| Gate | Target |
|---|---|
| Single-flow throughput | >= 1.15x stock |
| Multi-flow throughput | >= 1.10x stock |
| p99 latency | <= stock |
| Responsiveness under load | <= stock |
| RSS after warm-up | <= 50% of stock |
| CPU per GiB | < stock |
| 24h soak | No leak, no crash, bounded memory |
| 10k churn | No fd/thread/pipe leak |

If a gate fails, the result is recorded and the cause is investigated before
any optimization is accepted.

## Local methodology

- One Linux host, one network namespace per role: client, server, target.
- `veth` links with `tc netem` for delay, loss, and reordering.
- CPU pinning: server on one physical core, client and target on separate
  cores. A single-core run is included to model the VPS.
- Stock Xray v26.3.27 and `beam` use the same client, target, and payloads.
- Each scenario runs at least 5 times; report median and min/max.
- Warm-up traffic is excluded from the measurement window.

## Conditions

| Variable | Values |
|---|---|
| RTT | 0, 10, 50, 100 ms |
| Loss | 0, 1, 5% |
| Flows | 1, 4, 16 |
| Direction | upload, download, bidirectional |
| Payload | 1 B, 1 KiB, 64 KiB, bulk |
| MTU | 1500, 9000 |
| CPU | 1 core, 2 cores |

## Scenarios

1. Bulk TCP download through one flow.
2. Bulk TCP upload through one flow.
3. Four parallel bulk flows.
4. Small interactive requests during a bulk transfer.
5. UDP DNS queries.
6. QUIC/HTTP3 transfer.
7. Connection churn: 10,000 short connections.
8. 24-hour mixed soak.

## Tools

- `iperf3` for bulk TCP and UDP.
- `curl`/`h2load` for HTTP and TTFB.
- `dig` for DNS.
- A small Rust or Python driver for precise request timing.
- `perf`, `bpftrace`, `ss`, `/proc/<pid>` for kernel and process counters.

## Reporting

Each run records:

- commit and binary SHA-256
- kernel, CPU, and compiler versions
- exact commands and configuration
- raw samples and summary statistics
- pass/fail against the gates

Results live outside the repository or in a dedicated `bench/results/`
directory with large artifacts ignored.

## VPS

VPS benchmarking is out of scope for the preparation phase. The final
deployment check will repeat the acceptance gates on the real Debian 13 VPS
when the user schedules it.
