# Android TUN prep

This document describes the push-safe always-on TUN profile for the future
Android client. JNI and UniFFI bindings are out of scope for this phase. The
Rust core exposes every hook that the Android phase needs.

## What this phase delivers

- `TcpStackConfig::mobile` and `UdpBridgeConfig::mobile` in `beam-tun`. These
  presets bound RAM use and keep push sockets alive.
- `TunEngineConfig::tcp_relay_idle_timeout` in `beam-tun`. `None` removes the
  redundant relay *read* cap only; relay writes always keep a deadline. `Some`
  keeps the classic per-direction cap on reads and writes.
- `EngineTelemetry`, `TelemetrySnapshot`, and
  `run_tun_engine_with_telemetry` in `beam-tun`. The Android UI polls these in
  pure Rust. It never reads the Linux `/run/beam-client/status` file.
- `DnsConfig::local_socket_protector` in `beam-tun`. It takes
  `beam_core::client::SocketProtector`, the same hook type as
  `BeamClientConfig::socket_protector`, so one JNI callback covers both. The
  engine calls it after `bind` and before `connect` on each fresh local-DNS
  socket.
- `BeamClientConfig::socket_protector` in `beam-core`. The dial path calls it
  on the unconnected upstream socket before `connect`. Done.
- `beam_core::client::{parse_client_link, ParsedClientLink, ClientLinkError}`
  in `beam-core`. Strict `vless://` parser mirroring
  `identity::client_link`. Done.
- This document and its link from `docs/CLIENT.md`.

## `VpnService` wiring map

| Android side | Rust core side | State |
|---|---|---|
| `VpnService.Builder` TUN fd, after `detachFd` | `TunDevice` trait | Implement in the Android phase. `MemoryTun` covers tests. |
| `VpnService.protect(fd)` on the upstream socket | `BeamClientConfig::socket_protector` | Done. Runs before `connect` on the unconnected socket. |
| `VpnService.protect(fd)` on the local-DNS socket | `DnsConfig::local_socket_protector` | Done. Runs after `bind` and before `connect`. |
| `vless://` import in the UI | `beam_core::client::{parse_client_link, ParsedClientLink, ClientLinkError}` | Done. Strict parser mirroring `identity::client_link`. |
| `ConnectivityManager` network callbacks | `TunEngineConfig::network_reset` | Done. Send a new generation on each switch. |

Wire both protectors in the Android phase before any field test: call
`VpnService.protect(fd)` inside `BeamClientConfig::socket_protector` for
every upstream socket and inside `DnsConfig::local_socket_protector` for every
local-DNS socket. An unprotected upstream socket enters the tunnel routing
loop; the local-DNS hook alone does not protect the upstream path.

On each network switch, send a new `network_reset` generation. The engine then
resets all TCP flows with `RST`, drops the XUDP mux, and clears local DNS
state. Local applications reconnect at once instead of hanging on dead sockets.

## Always-on and low-battery design

An idle phone must cause zero timer wakeups. The engine arms its timer only
when a TCP or UDP sweep is pending. With no flows and no queued datagrams, the
timer stays disarmed and the loop sleeps on device and socket events only.

The mobile presets implement this design:

- `TcpStackConfig::mobile`: MTU 1500, 128 connections, 128 KiB per-direction
  socket buffers, 10 s handshake timeout, 1800 s idle timeout.
- `UdpBridgeConfig::mobile`: 128 NAT sessions, 60 s idle expiry.
- `tcp_relay_idle_timeout: None`: no relay read cap. The 1800 s stack idle
  timeout governs flow lifetime. Relay writes still time out after
  `BeamClientConfig::idle_timeout`, so a peer that stops draining is bounded.
  The Linux `beam-client` profile keeps `Some(idle_timeout_ms)` and therefore
  keeps its exact previous read and write caps.

Worst-case TCP buffer use is 128 flows times 128 KiB times two directions.
That 32 MiB is the TCP ring buffer ceiling (`128 x 128 KiB x 2`). Relay adds
per-active-flow buffers on top: 64 KiB S2C plus up to 64 KiB C2S scratch,
about 48 MiB total at full 128-flow concurrency. Size the Android
`VpnService` RAM budget for the combined total.

Push-notification alignment:

- FCM and MTalk hold sockets idle for about 15 minutes. The 1800 s stack
  idle timeout covers that window with margin.
- Upstream TCP keepalive starts after 30 s idle and probes every 10 s.
  `TCP_USER_TIMEOUT` is 30 s. Dead peers therefore fail fast while live push
  sockets stay open.
- `None` relay read timeout is required for this alignment. A 300 s read cap
  would kill a healthy 15-minute push socket from the middle. The write
  deadline stays in force and no live push socket reaches it.

## Flap backoff compared with short-outage retry

A moving phone flaps between networks. A steady outage needs fast recovery.
The core treats these cases differently:

- Dial failures more than 30 s apart start a fresh streak
  (`FAILURE_STREAK_WINDOW`). One old blip never keeps the link degraded.
- XUDP mux reconnect backs off from 250 ms to 10 s while datagrams wait.
  Queued datagrams flush on the next successful connect.
- A cache-miss DNS bypass route installs before the reply goes out, bounded
  by a 500 ms timeout. The follow-up SYN then takes the physical gateway.

## Telemetry API for the UI

Build the handle with `EngineTelemetry::with_dns` when DNS is enabled, or
with `EngineTelemetry::new` when it is not. Pass it to
`run_tun_engine_with_telemetry`. Poll `EngineTelemetry::snapshot` from the UI
or notification thread at any rate.

`TelemetrySnapshot` carries `drops`, optional `dns`, `last_dial_success_age`,
`consecutive_dial_failures`, and `last_dial_failure`. All counters are
lock-free. Polling allocates nothing beyond the snapshot itself.

`run_tun_engine` and `run_tun_engine_with_activity` keep their exact
signatures. Existing Linux callers do not change behavior.

## Cross-compile plan

Build the Rust core for `aarch64-linux-android` first. Add
`armv7-linux-androideabi` and `x86_64-linux-android` only for emulator and
legacy-device tests. Use the Android NDK toolchains. Cross-compile status:
`cargo check -p beam-sys --target aarch64-linux-android` passes without the
NDK; `beam-core` (`aws-lc-sys`) requires the Android NDK
`CC_aarch64_linux_android` compiler. No JNI or UniFFI
surface exists yet. Define that surface in the Android phase.

## Congestion control note

`clients/TODO.md` records the device evidence: a rootless Android phone keeps
the REALITY TCP cover but cannot enable BBR. The kernel offers only CUBIC.
Cover-preserving paths are a rooted BBR kernel or an external BBR gateway.
A custom client can add queueing and pacing, but it cannot replace missing
kernel BBR. Do not promise BBR-class upload performance on stock phones.

## Next steps

1. Implement `TunDevice` over the detached `VpnService` fd.
2. Define the JNI or UniFFI surface for engine control and telemetry polling.
3. Field-test Doze, app standby, and network switches against the hooks.
