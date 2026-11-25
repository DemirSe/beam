# Android TUN prep

This document describes the push-safe always-on TUN profile for the future
Android client. JNI and UniFFI bindings are out of scope for this phase. The
Rust core exposes every hook that the Android phase needs.

## What this phase delivers

- `TcpStackConfig::mobile` and `UdpBridgeConfig::mobile` in `beam-tun`. These
  presets bound RAM use and keep push sockets alive.
- `TunEngineConfig::tcp_relay_idle_timeout` in `beam-tun`. `None` removes the
  redundant relay read cap. `Some` keeps the classic per-direction cap.
- `EngineTelemetry`, `TelemetrySnapshot`, and
  `run_tun_engine_with_telemetry` in `beam-tun`. The Android UI polls these in
  pure Rust. It never reads the Linux `/run/beam-client/status` file.
- `DnsConfig::local_socket_protector` in `beam-tun` (Unix only). The engine
  calls it after `bind` and before `connect` on each fresh local-DNS socket.
- This document and its link from `docs/CLIENT.md`.

## `VpnService` wiring map

| Android side | Rust core side | State |
|---|---|---|
| `VpnService.Builder` TUN fd, after `detachFd` | `TunDevice` trait | Implement in the Android phase. `MemoryTun` covers tests. |
| `VpnService.protect(fd)` on the upstream socket | `BeamClientConfig` dial path | Open. The dial path has no protector hook yet. |
| `VpnService.protect(fd)` on the local-DNS socket | `DnsConfig::local_socket_protector` | Done. Runs after `bind` and before `connect`. |
| `ConnectivityManager` network callbacks | `TunEngineConfig::network_reset` | Done. Send a new generation on each switch. |
| `vless://` import in the UI | `beam_core::identity::client_link` link format | Partial. The link renderer exists. No parser exists yet. |

If the upstream protector hook is missing, the upstream socket can enter the
tunnel routing loop. Add the hook in the Android phase before any field test.
The local-DNS hook alone does not protect the upstream path.

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
- `tcp_relay_idle_timeout: None`: no per-direction relay cap. The 1800 s
  stack idle timeout governs flow lifetime.

Worst-case TCP buffer use is 128 flows times 128 KiB times two directions.
That is 32 MiB, which fits the Android `VpnService` RAM budget.

Push-notification alignment:

- FCM and MTalk hold sockets idle for about 15 minutes. The 1800 s stack
  idle timeout covers that window with margin.
- Upstream TCP keepalive starts after 30 s idle and probes every 10 s.
  `TCP_USER_TIMEOUT` is 30 s. Dead peers therefore fail fast while live push
  sockets stay open.
- `None` relay timeout is required for this alignment. A 300 s relay cap
  would kill a healthy 15-minute push socket from the middle.

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
legacy-device tests. Use the Android NDK toolchains. No JNI or UniFFI
surface exists yet. Define that surface in the Android phase, after the
upstream protector hook and the `vless://` parser land.

## Congestion control note

`clients/TODO.md` records the device evidence: a rootless Android phone keeps
the REALITY TCP cover but cannot enable BBR. The kernel offers only CUBIC.
Cover-preserving paths are a rooted BBR kernel or an external BBR gateway.
A custom client can add queueing and pacing, but it cannot replace missing
kernel BBR. Do not promise BBR-class upload performance on stock phones.

## Next steps

1. Add the upstream `protect(fd)` hook to the `beam-core` dial path.
2. Add a `vless://` link parser that mirrors `identity::client_link`.
3. Implement `TunDevice` over the detached `VpnService` fd.
4. Define the JNI or UniFFI surface for engine control and telemetry polling.
5. Field-test Doze, app standby, and network switches against the hooks.
