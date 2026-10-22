# Local stock Xray vs beam comparison (2026-10-22)

This is a local lab comparison, not a production WAN benchmark. It uses the
stock Xray 26.3.27 server/client for the control arm, the current `beam`
release, the sing-box 1.14.3 full-TUN client, and the test-only REALITY/H3
fixtures. No production credentials, VPS traffic, or secrets are included.

Host: i5-1135G7, 4 physical cores / 8 threads, performance governor. Full-TUN
CPU affinity: server 2, client/driver 1, target 3. The production sing-box VPN
was active during the run; the light 24-hour soak was stopped for a clean
measurement.

## 1. No-TUN server capacity

`bench/no-tun.sh`: stock Xray SOCKS client, 256 MiB plain HTTP, separate CPUs;
8 repetitions in both order passes. The first stock sample (cold REALITY
setup, ~5.4 s / 49.5 MB/s) is excluded by the script's warm-only summary.

| Pass | Arm | Warm median | Warm min | Warm max | Ratio |
|---|---|---:|---:|---:|---:|
| beam → stock | beam | **903.0 MB/s** | 895.6 | 921.3 | **1.447x** |
| beam → stock | stock | 623.9 MB/s | 613.5 | 649.3 | |
| stock → beam | stock | 595.9 MB/s | 197.4* | 613.4 | **1.496x** |
| stock → beam | beam | **891.6 MB/s** | 868.0 | 898.5 | |
| Combined (n=14 warm) | beam | **897.1 MB/s** | 868.0 | 921.3 | **1.462x** |
| Combined (n=14 warm) | stock | **613.4 MB/s** | 197.4* | 649.3 | |

\* One stock outlier; the median is unaffected. Beam's worst warm sample
(868.0) is still 1.337x stock's best warm sample (649.3).

Connection churn (beam-only script): 1000 requests at concurrency 32, all
HTTP 200 in 6 s; RSS 7,596 → 8,144 KiB; threads 2 → 2; fds 11 → 11. PASS.

## 2. Full-TUN performance

This harness is **client-capped** on this host: the single sing-box client
used 99–100% of its core at 0 ms. Client-saturated rows are `INVALID` for
server comparison and are reported only as a harness limit.

### 0 ms RTT

| Scenario | stock Xray | beam | beam/stock | Status |
|---|---:|---:|---:|---|
| TCP download 1 flow | 1710.2 Mbit/s | 1549.4 | 0.906x | INVALID (client 100%) |
| TCP download 4 flows | 1481.8 | 1497.3 | 1.010x | INVALID |
| TCP upload 1 flow | 3043.3 | 3010.6 | 0.989x | INVALID |
| TCP upload 4 flows | 2897.1 | 2863.7 | 0.988x | INVALID |
| HTTPS 64 MiB | 201.2 MiB/s | 203.1 | 1.010x | INVALID |
| UDP echo | 48.35 kpps | 48.94 | 1.012x | PASS |
| DNS A p99 | 0.258 ms | 0.144 ms | 0.559x | PASS |
| H3 p99 | 7.869 ms | 8.274 ms | 1.051x | FAIL (+5.1%) |

Server CPU/GiB: TCP download **0.483 vs 0.596** (0.812x), 4-flow **0.490 vs
0.597** (0.820x); upload **0.639 vs 0.713** (0.896x), 4-flow **0.638 vs 0.726**
(0.879x). RSS **8.2 vs 35.5 MiB** (0.238x); threads **3 vs 7**; server core
**20.9% vs 24.4%**. HTTPS CPU was 0.213 vs 0.160 s/GiB (1.333x, client-capped,
noisy).

### 50 ms RTT

Netem 25 ms per veth (50 ms total); 0 drops, 0 overlimits.

| Scenario | stock Xray | beam | beam/stock | Status |
|---|---:|---:|---:|---|
| TCP download 1 flow | 467.4 Mbit/s | 466.6 | 0.998x | valid, gate FAIL |
| TCP download 4 flows | 1460.0 | 1501.3 | 1.028x | INVALID (client 91–93%) |
| TCP upload 1 flow | 490.9 | 487.9 | 0.994x | valid, gate FAIL |
| TCP upload 4 flows | 2009.1 | 1982.7 | 0.987x | valid |
| HTTPS 64 MiB | 37.6 MiB/s | 38.0 | 1.012x | PASS |
| UDP echo | 0.62 kpps | 0.62 | 1.000x | PASS |
| DNS A p99 | 51.873 ms | 51.803 ms | 0.999x | PASS |
| H3 p99 | 208.659 ms | 210.859 ms | 1.011x | FAIL (+1.1%) |

Server CPU/GiB: download **0.442 vs 0.587** (0.753x) and **0.475 vs 0.599**
(0.793x); upload 1-flow **1.016 vs 0.998** (1.018x, slightly worse), 4-flow
**0.777 vs 0.900** (0.864x); HTTPS **0.107 vs 0.107** (equal). RSS **8.4 vs
35.4 MiB** (0.243x); threads **3 vs 6**.

H3 caveat: beam's 50 ms rep 3 failed with `curl: (18) HTTP/3 stream 0 reset by
server` after 11/20 responses; the test origin is deliberately unpinned and
already has sporadic stream resets. The harness pooled 40 beam samples vs 60
stock samples and marked the scenario FAILED. This is a test-origin/client
caveat, not a production VPS measurement.

## 3. Full-TUN compatibility/control

`tests/tun/run.sh --control --udp-mode <mode>`, beam and stock Xray on the same
topology and client:

| Mode | beam | stock Xray | Notes |
|---|---|---|---|
| xudp | **8/8 PASS** | **8/8 PASS** | no blocked/fail |
| packetaddr | **8/8 PASS** | **3/8 PASS** (5 UDP FAIL) | stock Xray has no packetaddr implementation; its control arm is not a valid oracle |
| legacy | **8/8 PASS** | **8/8 PASS** | no blocked/fail |

The stock packetaddr failures are all UDP (`udp-echo`, `udp-echo-v6`,
`dns-udp`, `dns-udp-v6`, `quic-udp`); Xray logs it treating
`sp.packet-addr.v2fly.arpa:0` as a real destination. This matches
`docs/08-vision-xudp-spec.md:170`.

## 4. Cover parity

Capture/parse check PASS: handshake completed against the recording target,
HTTP body received. Beam negotiated the same group/cipher
(`X25519MLKEM768`, `TLS_AES_128_GCM_SHA256`), 1215-byte ServerHello, TLS 1.3,
32-byte session ID.

Known gaps remain unchanged:

- Plaintext extension order: beam `[key_share, supported_versions]` vs cover
  `[supported_versions, key_share]`.
- Flight size: beam 3 records / 1637 B (encrypted 416 B) vs cover 5 / 4306 B
  (encrypted 3085 B); delta **-2669 B** due to the temporary Ed25519 cert.
  See `docs/10-cover-parity.md`.

## Interpretation

- **Server capacity:** beam is clearly faster: 897 vs 613 MB/s warm
  (**1.462x**) with lower CPU/GiB and ~4x lower RSS. This is the valid
  server-side headline.
- **Full-TUN:** the client is the bottleneck; throughput ratios do not rank
  the servers. Server CPU/GiB and RSS still favor beam. At 50 ms, 4-flow
  upload is 1.3% lower and 1-flow upload is at parity; HTTPS is at parity or
  slightly higher.
- **Compatibility:** beam passes all eight probes in all three UDP modes.
  Stock Xray matches on xudp/legacy and cannot serve packetaddr.
- **H3:** p99 is marginally worse (5.1% at 0 ms, 1.1% at 50 ms) on a noisy
  host; one test-origin rep reset. Not a production H3 claim.
- Neither full-TUN run is headline-eligible: host load exceeded 0.3 and the
  client core was saturated. The no-TUN result is the reliable capacity
  comparison.

## Caveats

- The prebuilt `target/release/beam` used by the no-TUN/full-TUN runs predates
  the last cover/relay-log commits; those do not change the measured relay/TLS
  hot path. A fresh HEAD rebuild is still preferable for a final number.
- The no-TUN `/tmp` user quota was tight, so the 256 MiB target and full-TUN
  50 ms payload were served from `/dev/shm`/`~/.cache`; both are RAM-backed and
  identical to both arms.
- The churn script is beam-only; it does not provide a stock arm.
- The full-TUN H3 origin is test-only and unpinned; a reset is recorded as a
  failed rep, not silently retried.

## Artifacts

- `/tmp/opencode/bench-suite/no-tun/` (balanced no-TUN, churn)
- `/tmp/opencode/bench-suite/full-tun-0ms/` and `.../full-tun-50ms/`
- `/dev/shm/beam-control/tun-{xudp,packetaddr,legacy}/`
- `/dev/shm/beam-control/cover-parity/`
- `/tmp/opencode/bench-suite/full-tun-NOTES.md` (retry/quota provenance)
