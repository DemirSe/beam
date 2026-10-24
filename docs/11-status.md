# Status

Updated: 2026-10-23.

## Decisions

- Language: Rust 2024, pinned to 1.99.1.
- Configuration: TOML, strict unknown-field rejection.
- TLS: rustls 0.23 + aws-lc-rs with `prefer-post-quantum` (ADR 0003).
- REALITY: authenticated path does not dial the cover; unauthenticated probes
  are forwarded byte-for-byte.
- Full TUN (TCP, UDP, DNS, QUIC, IPv4/IPv6) is a release blocker.
- Performance acceptance is relative: aggregate better than stock, no
  regression in any tested condition.
- Known v1 cover gaps: extension order and encrypted-flight size; documented in
  `docs/10-cover-parity.md`.

## Implemented and merged

| Area | State |
|---|---|
| Repository skeleton, CI, ADRs | Done |
| TOML config + validation | Done |
| CLI config check + accept loop | Done |
| VLESS/XUDP address codec | Done |
| TLS ClientHello parser | Done |
| REALITY envelope authentication | Done |
| VLESS request/response header codec | Done |
| Vision block framing codec | Done |
| Vision padding/direct state machine | Done |
| XUDP frame codec | Done |
| XUDP session table and UDP relay | Done |
| Process-wide XUDP session limiter | Done (256 sessions) |
| XUDP over VLESS Mux | Done |
| Legacy VLESS UDP and packetaddr | Done |
| Linux fd/socket/splice primitives | Done |
| Zero-copy splice relay loop | Done |
| REALITY TLS server adapter (rustls) | Done |
| Cover fallback (byte-exact ClientHello) | Done |
| Cover concurrency cap | Done (32 relays) |
| VLESS user validation | Done |
| Vision-framed relay | Done |
| Vision Direct raw TLS handoff | Done |
| Early one-way raw download splice | Done |
| Early one-way raw upload splice | Done |
| Prefix replay stream | Done |
| Stock Xray no-flow TCP interop | **HTTP 200** |
| Stock Xray Vision TCP/HTTPS interop | **HTTP 200** |
| Cover-parity harness | Done; gaps documented |
| Fuzz workspace and manual fuzz CI | Done; 60 s target runs locally |
| Full-TUN harness v2 | **8/8 PASS** |
| Full-TUN benchmark harness | Done |
| No-TUN server-capacity smoke | Done |

## Full-TUN matrix

The same eight probes pass through the real sing-box TUN client with all three
UDP modes:

| Probe | XUDP | packetaddr | legacy UDP |
|---|---|---|---|
| TCP HTTP IPv4 | PASS | PASS | PASS |
| TCP HTTP IPv6 | PASS | PASS | PASS |
| UDP echo IPv4 | PASS | PASS | PASS |
| UDP echo IPv6 | PASS | PASS | PASS |
| DNS IPv4 | PASS | PASS | PASS |
| DNS IPv6 | PASS | PASS | PASS |
| QUIC / HTTP3 | PASS | PASS | PASS |
| HTTPS through Vision Direct | PASS | PASS | PASS |

## Performance snapshot

- **Latest local comparison (2026-10-22, detailed):** in the balanced no-TUN
  server-capacity run (8 warm repetitions per order), beam **897.1 MB/s** vs
  stock **613.4 MB/s** = **1.462x**; every warm beam sample beat every warm
  stock sample. Churn: 1000/1000 HTTP 200 at concurrency 32; RSS +0.5 MiB,
  threads 2, fds 11. See `docs/16-local-comparison-2026-10-22.md`.
- Full-TUN bulk throughput is **client-capped** by the sing-box TUN client on
  this host; stock and beam are at roughly 0.98-1.00x, so the fixed-multiplier
  throughput gates are not evaluable in that harness. In the latest 0/50 ms
  runs, server CPU/GiB was 0.75-0.90x stock on TCP, RSS was 0.24x, and the
  4-flow upload at 50 ms was 0.987x (1.3% lower); H3 p99 was 1.05x/1.01x on a
  noisy host. Neither full-TUN run is headline-eligible.
- **Compatibility:** beam passes all 8 full-TUN probes in `xudp`,
  `packetaddr`, and `legacy`; stock Xray matches on `xudp`/`legacy` and is
  3/8 on `packetaddr` because Xray has no packetaddr implementation. Cover
  parity capture passes; the known extension-order and flight-size gaps are
  unchanged.
- **No-TUN server-capacity smoke** (stock Xray SOCKS client, 256 MiB plain
  HTTP, separate CPUs): beam **872 MB/s** vs stock **589 MB/s** in the final
  older run (**1.48x**; earlier 1.56x; latest balanced 1.462x). This removes
  the TUN client cap and exposes the server path.
- Server CPU per GiB, TCP download: **0.79x** stock (21% lower).
- Server CPU per GiB, TCP upload: ~1.00x / 1.03x (slightly worse).
- HTTPS Vision Direct: early one-way splice reduced server CPU from ~0.32 to
  **0.107 s/GiB**, matching stock; quick throughput ratio **1.033x**.
- HTTPS upload with `Expect: 100-continue`: server CPU fell from ~0.288 to
  **0.113 s/GiB** (~2.5x lower) at throughput parity. Clients that keep the
  entire body framed do not trigger the early handoff; that is a client
  behavior limitation, not a server regression.
- UDP echo throughput: **1.22x** stock.
- Server RSS after warm-up: **0.24x** stock (76% lower).
- DNS p50/p95 favor beam; p99 and H3 p99 are slightly worse on a noisy host.
- At **50 ms RTT** (valid quick run, no client saturation): TCP throughput
  0.98–1.01x stock; server CPU/GiB 0.77–0.95x; RSS 0.24x; DNS p99 +0.3%,
  HTTP/3 p99 0.0%. Beam is at throughput parity with lower CPU/RSS under
  added RTT.
- Connection churn smoke: 1,000 requests at concurrency 32, all HTTP 200;
  RSS 7.7→8.3 MiB, threads 2, fds 10, no leaks.
- Syscall/wakeup/splice gates and a 24-hour soak need a privileged, quiet
  acceptance run.

## Deployment

- 2026-10-22: fresh Debian 13.6 on the VPS, 1 vCPU/1 GB, 1 GB swap.
- `beam.service` is **active and enabled**, listening on `0.0.0.0:443`;
  idle process memory ~17 MiB.
- A new REALITY identity was generated because the old private key was lost
  with the server wipe. The old client credentials no longer work; the client
  must be rotated once.
- Verified from the laptop with stock Xray 26.3.27: HTTPS `example.com` 200,
  HTTP 200, and a SOCKS5 UDP echo round trip.
- Local client rotation completed. Full-TUN egress is the VPS: IPv4
  `158.94.216.102`, IPv6 `2a01:f900:11:168::1`. HTTPS/HTTP, DNS, HTTP/3 and
  IPv6 all pass through the live TUN.
- Unauthenticated probe test: a TLS client with SNI `whatsapp.net` sent to the
  VPS is forwarded to the real cover; the observed certificate is Meta's valid
  `*.whatsapp.net` certificate.
- `sing-box` is active; the updated `update-client.py` enables it at boot, and
  the tray autostart is installed. Until the local sudo step runs, the service
  remains `disabled` and a reboot needs a manual/tray start.
- `sudo python3 deploy/update-client.py` or the link import is the only local
  privileged action; the agent's sandbox sets `no_new_privs`.
- Production hardening applied on 2026-10-22:
  - 13 pending security updates installed; `needrestart` added. Kernel
    `6.12.113+deb13-cloud-amd64` is active after a controlled reboot on
    2026-10-22.
  - Live limits lowered to `max_connections=1024` and
    `handshake_timeout_ms=10000`; unauthenticated cover relays are capped at
    30 s.
  - Tokio blocking pool capped at 160 threads; XUDP reply queue raised to 512;
    session sockets request a 1 MiB receive buffer; host
    `net.core.rmem_max=4 MiB`.
  - systemd sandbox extended with a syscall filter, kernel/control-group/clock
    protection, no devices, no namespaces, no new privileges, and core dumps
    disabled. `systemd-analyze security beam` reports **1.7 OK** (was 5.6
    MEDIUM).
  - Host nftables is enabled with default-deny input; 22/443, established,
    ICMP/ICMPv6 and loopback are allowed; LLMNR is dropped.
  - BBR + `fq` enabled on 2026-10-23 for the live hotspot path. Five 5 MB
    downloads per mode: cubic median **2.76 MB/s** (2.37–4.63), BBR median
    **5.75 MB/s** (5.39–6.65); the qdisc reported zero drops. Persisted with
    `/etc/sysctl.d/99-beam-net.conf`, `/etc/modules-load.d/beam-net.conf`, and
    `beam-qdisc.service`.
  - `tcp_mtu_probing` remains **0** intentionally. The live outer MSS is
    1348–1448, but false black-hole detection would cap the MSS to
    `tcp_base_mss=1024` after three RTOs and can halve it further; no MTU
    black hole has been observed (`TcpExtTCPMTUPFail/Success=0`,
    `IpExtInNoRoutes=0`). Revisit only with a measured PMTU failure.
  - SSH is `AllowUsers demir`, `PermitRootLogin no`, key-only, X11 off,
    `MaxAuthTries 3`, `LoginGraceTime 30`. Root and `debian` keys were removed;
    `debian` is locked with `nologin` and its sudoers entry removed.
  - systemd-resolved uses DNS-over-TLS and DNSSEC (`allow-downgrade`); LLMNR and
    mDNS are off.
- A 5-minute post-hardening production soak completed: 113/115 requests
  succeeded; non-H3 was 87/87. Large HTTP/3 was 12/14 with two 45 s timeouts.
  There was no restart, RSS stayed at ~10.2 MiB, and FDs went 124 → 154 → 134
  (peak → +60 s). The previous audit and soak reports are in `/tmp/opencode/`.

## Deployed hardening

- On 2026-10-23 12:46 UTC the first hardening binary was deployed: SHA-256
  `5379e6823944fb6e3c2a3e14fbbe12a5b394e4c50a5597f25ac9ceb5c276d951`.
- On 2026-10-23 18:10 UTC the deep-audit follow-up was deployed: SHA-256
  `bd17ac26928d4e659a0f7596f959b5a66f0f8314288c7720220882e4ea88287b`.
  It includes the accept-loop, relay-cancellation, replay-cache, TCP idle,
  XUDP retained/queue, GlobalID migration, packetaddr isolation, VLESS route,
  TOML redaction, and legacy-config fixes.
- The global XUDP cap (256), cover concurrency cap (32), and systemd
  `MemoryHigh=512M` / `MemoryMax=768M` / `MemorySwapMax=512M` are live.
- The live config was **not overwritten**; the existing 1024-connection,
  `info`-level config was preserved. The latest unit and binary backups are
  timestamped `20261023T181052Z`.
- Post-deploy IPv4/IPv6 egress, HTTPS, HTTP, DNS, the cover certificate, and
  `NRestarts=0` were verified. See `docs/17-resource-hardening.md`.

## 2026-10-24 optimization pass

Local changes and measurements are recorded in
`docs/18-optimization-2026-10-24.md`. Highlights:

- Pre-auth admission is separated from authenticated capacity; an idle-socket
  regression that timed out the old binary now returns HTTP 200 in 5 ms.
- Non-TLS and over-limit first records are forwarded to the cover instead of
  waiting for a bogus record body.
- Vision splice threads are capped with an async fallback; keepalive and a 30 s
  post-half-close bound release stale mobile flows.
- TLS `close_notify` is honored as EOF; unknown VLESS flows are rejected.
- Vision reads are linear and coalesced; partial inner TLS records no longer
  prevent Direct.
- XUDP stop/teardown leaks, stale 300 s sessions, retained-socket stale data,
  and per-frame reply flushes are fixed.
- SIGTERM drains for 2 s and exits through a 3 s runtime bound.
- Local capacity remains **1.402x** stock (913.7 vs 651.8 MB/s); full-TUN is
  8/8 with a 1.33 MiB H3 body; UDP echo is 1.232x stock in the latest quick
  run (host was noisy).

The live VPS was updated on 2026-10-24 02:08 UTC with
`BEAM_KEEP_CONFIG=1`: binary
`615ef24d2c8d10b5c4507476e41fc7b02758e4ce173d96117389028163f2c71a`,
unchanged config hash
`c0abace24e0f839a3ae3c1300d3f79b94ccfee437df5e7a4d8ec67b1b2722a02`,
`NRestarts=0`, no warning entries, cover certificate and IPv4/IPv6/DNS
verified. Host conntrack was raised to 65536 with a 1 h established timeout.

## In progress

- A light 24-hour background soak started on 2026-10-22 12:52 UTC from the
  laptop: 1 MiB HTTPS, DNS, small H3 and IPv6 every 5 minutes, with server
  RSS/fd/thread samples. It was paused for the detailed benchmark and resumed
  at 15:42 UTC. Logs: `/tmp/opencode/soak-24h-live3/`; stop with
  `kill 2089354`. This is not the privileged quiet syscall/wakeup acceptance.
- H3 over the TCP tunnel can still show ~10.5 s Google completion outliers at
  TUN MTU 1500 even though HTTP/2 is stable and TUN/server drop counters stay
  at zero; this is QUIC PTO/TCP HOL, not an MTU drop. gVisor still stalls large
  H3 bodies; the production client uses `system`. See
  `docs/14-tun-harness.md`.

## Known gaps / not started

- TLS extension-order and encrypted-flight-size parity.
- The early upload splice depends on the client sending Direct before the
  body; fully framed uploads stay on the async path.
- A 24-hour soak and privileged syscall/wakeup gates remain.
- No per-IP connection cap; the global 1024-connection cap, 10 s pre-auth
  timeout, 30 s cover timeout and provider firewall are the current mitigation.
- `max_connections=1024` is admission headroom, not bulk capacity: the 160
  blocking-thread pool is about 80 active Vision Direct pairs; the listener
  backlog is 128 and historical `ListenOverflows=102`. The 512/1024×1 MB load
  logs show 49.7 s median and 937 timeouts respectively. Current normal load is
  tens of connections. The global XUDP cap (256) and cover cap (32) reduce the
  burst memory/thread exposure and are deployed on the live host.
- The provider L4 firewall/rate limit was not independently verified; the host
  nftables rules are.
- The local `sing-box` service is not enabled at boot.
- Large H3 bodies can occasionally stall through the production TUN. The
  original 20–45 s stalls were consistent with the 1400 MTU failure; at 1500
  the 2026-10-24 mobile run passed 1.33 MiB H3 and 64 MiB TCP, but Google H3
  still showed
  1–4/10 ~10.5 s completion outliers while HTTP/2 stayed stable. TUN and
  server drop counters stayed at zero, so this is H3-over-TCP/QUIC PTO rather
  than an MTU drop. The updated `deploy/update-client.py` sets `system` and
  MTU 1500; Hiddify users must set both manually.
- **Production TUN MTU is 1500.** H3 needs at least 1480 for IPv4 and 1500 for
  IPv6; at 1400 Google and YouTube H3 time out. The 2026-10-24 TT Mobil
  hotspot run with outer MSS 1388 passed 64 MiB TCP at 14.27 MB/s, 1.33 MiB
  H3, IPv6 H3, and 16 MiB upload with zero TUN drops. See
  `docs/14-tun-harness.md`.
- `XudpSessionLimiter` now evicts a retained GlobalID socket from any mux
  stream when the 256-slot global limit is full, instead of rejecting a new
  live session while optional retention state exists. The cross-stream
  regression test is in `crates/beam-core/src/xudp/server.rs`.

## Evidence

- `docs/07-reality-spec.md`: REALITY envelope and stock cover behavior.
- `docs/08-vision-xudp-spec.md`: VLESS, Vision, XUDP, legacy UDP, packetaddr.
- `docs/09-tls-stack-spike.md`: rustls/BoringSSL measurements.
- `docs/10-cover-parity.md`: whatsapp.net cover measurements and gaps.
- `docs/06-benchmark-harness.md`: local benchmark topology and gates.
- `docs/12-custom-tls-design.md`: reference-only exact-mirroring design.
- `docs/13-vision-direct-design.md`: Direct raw-handoff design.
- `docs/14-tun-harness.md`: full-TUN topology, probes, and control results.
- `docs/15-production-runbook.md`: live operations, rotation, rollback, and
  monitoring.
- `docs/17-resource-hardening.md`: XUDP/cover/fuzz hardening audit, deployment
  record, and local follow-up tests.
- `docs/16-local-comparison-2026-10-22.md`: detailed local stock-Xray vs beam
  capacity, full-TUN, compatibility, and cover comparison.
- `bench/README.md`: benchmark and no-TUN smoke usage.

## Current verification

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --release
cargo check --manifest-path fuzz/Cargo.toml
cargo +nightly fuzz build
bash scripts/cover-parity.sh
bash tests/tun/run.sh
bash tests/tun/run.sh --udp-mode packetaddr
bash tests/tun/run.sh --udp-mode legacy
bash bench/no-tun.sh
```

The workspace currently has 249 `beam-core` unit tests, two integration tests,
and 23 `beam-sys` tests (274 total). The full-TUN harness passes all eight
probes for XUDP, packetaddr, and legacy VLESS UDP. A 1.3 MiB HTTP/3 body also
passes through the local `system`-stack TUN; the same large body fails with a
gVisor TUN on both beam and stock Xray. The no-TUN server-capacity smoke is
~1.5x stock.
