# Native Windows client (`beam-client.exe` + `beam-tray.exe`)

`clients/windows-tray/` packages the native Windows client for `beam`: the Rust
`beam-client.exe` Windows Service, the unelevated `beam-tray.exe` system tray
UI, and the signed `wintun.dll` driver — with **zero `sing-box.exe`
dependency**.

## Architecture

- **`BeamClient` Windows Service (`beam-client.exe`):** runs as `LocalSystem`
  and starts automatically at boot. It owns the WinTun adapter, IP Helper
  routes, dynamic Windows Filtering Platform (WFP) DNS and kill-switch filters,
  and `%ProgramData%\beam\client.toml` (ACL-locked to `SYSTEM` and
  `Administrators` only).
- **Unelevated tray (`beam-tray.exe`):** runs with an `asInvoker` manifest
  (**zero UAC prompts after install**). It communicates with `BeamClient` over
  the Named Pipe `\\.\pipe\beam-client-ipc`, whose DACL is restricted to
  `SYSTEM` (`SY`), `Administrators` (`BA`), and the installing user's SID
  recorded in `%ProgramData%\beam\allowed-user.sid`.

## Status icons and states

| Icon | State | Meaning |
|---|---|---|
| Gray (`-`) | Disconnected / Unavailable | Tunnel is stopped, or `BeamClient` is unreachable. |
| Amber (`...`) | Connecting / Reconnecting / WaitingNetwork / Stopping / Degraded | Tunnel is starting, recovering, waiting for network, stopping, or degraded (for example, missing bypass or dial failures). |
| Green (`✓`) | Connected | Tunnel is up and healthy; tooltip shows live RTT. |
| Red (`!`) | Error | Service reported a fatal or configuration error. |

## Install and uninstall (easy path)

Put `beam-client.exe`, `beam-tray.exe`, `wintun.dll`, `install.ps1`,
`install.cmd`, and `uninstall.cmd` in one folder. No pre-edited config file is
required beforehand.

1. Double-click **`install.cmd`** and accept the single UAC prompt. The
   installer deploys the binaries into `%ProgramFiles%\beam\`, registers and
   starts the `BeamClient` Windows Service, records the desktop user's SID in
   `%ProgramData%\beam\allowed-user.sid`, and launches `beam-tray.exe`.
2. Click the tray icon → **`Import vless:// link...`**, paste your `vless://`
   URI, and save. The service writes `%ProgramData%\beam\client.toml` with
   `SYSTEM`/`Administrators`-only ACLs.
3. Click **`Connect`**.

To remove everything cleanly, double-click **`uninstall.cmd`** (or run
`install.ps1 -Uninstall`; pass `-KeepConfig` to preserve
`%ProgramData%\beam\client.toml`).

## Crash safety and DNS leak protection

- **Dynamic WFP session:** all WFP kill-switch and DNS filters are installed in
  a session created with `FWPM_SESSION_FLAG_DYNAMIC`. If `beam-client.exe`
  crashes or is terminated abruptly, the Windows kernel automatically removes
  the filters so the host is never left bricked offline.
- **Process-scoped WinTun adapter:** the WinTun interface is tied to the
  service process lifetime and tears down automatically on exit.
- **Orphaned route recovery:** `beam-client.exe --cleanup-routes` removes any
  leftover bypass routes recorded in `%ProgramData%\beam\routes.state` without
  touching pre-existing host routes.
- **SMHNR DNS leak protection:** WFP blocks plaintext UDP/TCP port 53 outside
  the WinTun adapter while connected, preventing Windows Smart Multi-Homed Name
  Resolution (SMHNR) from leaking DNS queries onto physical interfaces.

- **Pre-VPN resolver exception:** while connected, plaintext port 53 is
  blocked for every destination except the pre-VPN resolver, which the client
  needs for `.lan`, `.local`, `.internal`, and `bypass.domains`. That exception
  is machine-wide on purpose. Scoping it to `beam-client.exe` was tried and
  reverted: ordinary Windows resolver lookups then stalled for about 12 s
  (run 46065050437), because Windows waits out its blocked parallel queries
  instead of falling back to the tunnel resolver. Scoping needs a fail-fast
  block first.
- **Resolver latency:** a name resolved through the tunnel resolver answers in
  under 1 ms. `Resolve-DnsName` also reports about 18 ms because Windows races
  every adapter's resolver; that time is the Windows resolver, not the tunnel.
  The live comparison reports both `dns_ms` and `dns_direct_ms` for this reason.

## Live verification

`windows-live-e2e` (manual dispatch) installs the packaged client on a Windows
runner, connects to a real VPS, and proves six checks: `route_fail_closed`,
`dns_leak`, `ipv6_egress`, `service_restart`, `hang_recovery`, and
`crash_recovery`. The same run compares `beam-client` with `sing-box` over three
interleaved rounds of a 100 MiB download.

Last measurement (run 46066033000, median of three rounds):

| Metric | beam-client | sing-box |
|---|---|---|
| connect_ms | 2016 | 2813 |
| ram_mb | 23.7 | 64.8 |
| download_mbps | 154.8 | 158.8 |
| dns_ms | 1 | 1 |
| cpu_s per 100 MiB | 1.1 | 0.8 |
| sys_core_s per 100 MiB | 18.1 | 12.3 |

Throughput is at parity. Process CPU is higher for `beam-client` because it
reads and writes every packet in user space; whole-machine core-seconds include
the kernel stack that `sing-box` does not pay in its own process, and on a
shared four-vCPU runner those figures overlap between clients, so neither side
is shown to be cheaper.

## Build

1. **Rust service (`beam-client.exe`):**
   ```powershell
   cargo build --release -p beam-client --target x86_64-pc-windows-msvc
   ```
   (or `x86_64-pc-windows-gnu` with MinGW-w64).
2. **Tray executable (`beam-tray.exe`):** build from `clients/windows-tray/`
   with MSVC (`cl` / `rc`) or MinGW-w64 (`./build.sh` using
   `x86_64-w64-mingw32-gcc` and `x86_64-w64-mingw32-windres`). The embedded
   manifest requests `asInvoker` and `PerMonitorV2` DPI awareness.
3. **WinTun (`wintun.dll`):** bundle the pinned signed **WinTun 0.14.1**
   `amd64/wintun.dll` beside `beam-client.exe`.

## Troubleshooting

- **Service log:** `%ProgramData%\beam\beam-client.log`
- **Service status:** `sc query BeamClient`
- **Validate config:**
  ```powershell
  "%ProgramFiles%\beam\beam-client.exe" --check -c "%ProgramData%\beam\client.toml"
  ```
- **Clean up orphaned routes after an abnormal shutdown:**
  ```powershell
  "%ProgramFiles%\beam\beam-client.exe" --cleanup-routes
  ```
