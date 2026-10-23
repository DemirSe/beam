# Resource hardening audit: XUDP, cover, and fuzzing

Date: 2026-10-23. Scope: the first three findings from the production audit.
This document records the design decisions and the implemented code. **Nothing
in this change has been deployed to the VPS yet.**

## 1. XUDP memory and session bounds

### Observed shape

- `xudp/server.rs` requests a **1 MiB** `SO_RCVBUF` for every XUDP session.
- Linux clamps that request to `net.core.rmem_max` and then doubles the stored
  value. The live host has `rmem_max=4194304`, so a session can reserve about
  **2 MiB** of kernel socket memory.
- `limits.max_udp_destinations` is per mux stream. With `max_connections=1024`,
  the per-stream limit alone does not bound aggregate process or kernel memory.
- The live host currently has no beam UDP sessions; this is a worst-case and
  burst-risk finding, not a measured current leak.
- The 1 MiB buffer was chosen for large HTTP/3 bodies while the outer TLS stream
  drains. Reducing it blindly would trade memory for QUIC/H3 drops.

### Decision

1. Keep the 1 MiB receive-buffer request. Do not regress H3/QUIC buffering
   without a measured replacement.
2. Add a **process-wide XUDP session limiter** with **256** permits. A permit is
   held by both active sessions and retained GlobalID sockets, released only
   when the kernel socket is finally dropped.
3. Keep the per-stream `max_sessions` limit; the global limiter is an additional
   aggregate bound, not a replacement for the stream-local table bound.
4. Add systemd memory protection:
   - `MemoryHigh=512M`
   - `MemoryMax=768M`
   - `MemorySwapMax=512M`

   The current peak observed on the live service was 72.9 MiB. The cgroup limits
   are deliberately above normal operation and below the 1 GiB host size.

### Worst-case arithmetic

At 256 sessions × approximately 2 MiB of receive buffer, the dominant kernel
socket budget is about **512 MiB**. The cgroup cap is 768 MiB, leaving room for
the Rust heap, TLS buffers, and the rest of the host. Actual memory is lower
when the sockets are not full. The previous 1024-session configuration could
theoretically reach about 2 GiB of socket memory.

### Performance impact

- The limiter is checked only on `New`, not per packet or per reply.
- Normal full-TUN traffic with fewer than 256 destinations sees no added
  datagram-path work.
- At the limit, the next `New` receives `End + Error`; this is a deliberate
  capacity trade-off, not a CPU regression.
- Keeping the 1 MiB buffer preserves the existing H3 behavior.
- `MemoryMax` adds no CPU work in normal operation. If set too low it would
  cause reclaim or OOM; the chosen values are above the observed peak and will
  be validated on the host before deployment.

## 2. Cover concurrency

### Observed shape

- Unauthenticated cover relays use `spawn_blocking` and `copy_bidirectional`.
- Authenticated Vision Direct relays also use the same 160-thread Tokio
  blocking pool.
- The cover idle timeout is 30 s, but there was no global cover concurrency
  limit. A burst of valid ClientHello probes could occupy the blocking pool and
  delay VPN relays.
- Per-IP filtering is intentionally not used.

### Decision

Add a process-wide **32-permit** semaphore around the complete cover path:

1. Acquire before dialing the cover.
2. Hold the permit through the ClientHello write and the splice relay.
3. If no permit is available, close the probe immediately as
   `ConnectionOutcome::CoverLimited`; do not queue an unbounded number of cover
   tasks.

No separate runtime or thread pool is added. A separate pool would consume more
threads on the 1 vCPU host and would not protect the shared blocking pool any
better than a shared semaphore.

### Performance impact

- Normal traffic: one semaphore acquisition per unauthenticated connection only;
  no effect on authenticated packet processing.
- Cover flood: cover forwarding is capped at 32; the remaining blocking threads
  are available to authenticated Vision relays. VPN latency should improve under
  that specific load.
- Trade-off: unauthenticated cover probes above the cap are closed. This is
  intentional; cover traffic is not the VPN data path.

## 3. Fuzz targets and CI

### Observed shape

- The parser code has proptest coverage, but the repository had no
  `cargo-fuzz` workspace or targets.
- `docs/03-test-plan.md` and `AGENTS.md` require fuzz coverage for parsers.
- CI ran format, clippy, and debug tests only.

### Decision

Add a separate `fuzz/` workspace with targets for:

| Target | Entry point |
|---|---|
| `client_hello` | TLS ClientHello parser |
| `reality_auth` | ClientHello parse + REALITY authentication |
| `vless` | VLESS request/addons parser |
| `vision` | Vision block parser + TLS detector |
| `xudp` | XUDP frame parser |
| `legacy_udp` | Legacy frame reassembly + packetaddr parser |
| `config` | TOML configuration parser |

`legacy_udp` uses a test-only, feature-gated helper in `beam-core`; it opens no
sockets. The fuzz workspace is excluded from the production workspace, and the
`fuzz` feature is not enabled in release builds.

CI now also runs `cargo test --workspace --release`. A separate scheduled
workflow builds and runs each target for a short budget. Fuzzing does not touch
the production binary or server.

## Verification

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --release
cargo check --manifest-path fuzz/Cargo.toml
```

The fuzz check requires a C++ compiler for `libfuzzer-sys`; the CI image
provides one. Local checks used the portable GCC toolchain under
`/tmp/opencode/tools`.

Results after the change:

- `cargo test --workspace`: 237 beam-core unit tests, 2 integration tests, and
  23 beam-sys tests pass.
- `cargo test --workspace --release`: pass.
- `cargo check --manifest-path fuzz/Cargo.toml`: pass with the portable C++
  compiler.
- Local full-TUN `xudp` at **MTU 1500**: 8/8 PASS.
- Local full-TUN `xudp` at **MTU 1400**: 7/8 PASS; only `quic-udp` failed.
  The HTTP/3 origin saw the QUIC connection, and the failure is consistent with
  the known client/MTU H3 stall, not with the new session limiter. It is
  recorded as a client-TUN issue to investigate separately.

## Deployment note

The live VPS still runs the previous unit and binary. Deployment must apply the
new unit (memory limits) and binary together, then verify:

- `systemctl show beam -p MemoryHigh -p MemoryMax -p MemorySwapMax`
- `cat /sys/fs/cgroup/system.slice/beam.service/memory.current`
- `cat /sys/fs/cgroup/system.slice/beam.service/memory.peak`
- `ss -uanp | grep beam` under a full-TUN workload
- `nstat -az` for `UdpRcvbufErrors`/`UdpSndbufErrors`
- authenticated p95 while a cover-probe burst is running

No deployment is performed by this change.
