# Windows tray client

`clients/windows-tray/` builds a small, event-driven Windows tray launcher for
sing-box. It does not build the server. It is Windows-only.

## Status icons and behavior

The tray icon reflects real tunnel state by combining `sing-box.exe` process
liveness (`RegisterWaitForSingleObject`) with the Windows TUN adapter state
(`GetIfTable2` / `NotifyIpInterfaceChange`, checking `IfOperStatusUp`):

| Icon | State | Meaning |
|---|---|---|
| Gray (`-`) | Disconnected | `sing-box.exe` is stopped. |
| Amber (`...`) | Connecting / Disconnecting | `sing-box.exe` is starting (waiting for TUN `Up`) or shutting down gracefully. |
| Green (`✓`) | Connected | `sing-box.exe` is running **and** the TUN adapter is `IfOperStatusUp`. |
| Red (`!`) | Error | `sing-box.exe` exited unexpectedly, failed to launch, or TUN did not come up within 15 s. |

- Single left-click or right-click opens the tray menu.
- Launching `beam-tray.exe` connects automatically.
- `Restart` runs `sing-box.exe check -c config.json` before stopping the active
  tunnel, so a syntax error in `config.json` does not drop a working session.
- `Disconnect`, `Exit`, and Windows shutdown (`WM_ENDSESSION`) send
  `CTRL_BREAK_EVENT` first so sing-box can cleanly remove WFP filters and TUN
  DNS settings before exiting.
- `sing-box.log` rotates to `sing-box.log.1` on start once it reaches 2 MiB.

## sing-box 1.15+ TUN profile

[`config.example.json`](config.example.json) is a placeholder profile targeting
**sing-box 1.15+ (beta/release)**:

- Omits the deprecated `stack` field (`gvisor`/`system`/`mixed`) so `sing-tun`
  uses its built-in TCP/IP stack by default.
- Uses `dns_mode: "hijack"` and `strict_route: true` (Windows Filtering
  Platform) for native per-interface DNS and leak protection.
- Keeps the WAN wire behavior unchanged: TCP/443 VLESS + REALITY
  (`server_name: "whatsapp.net"`) + `xtls-rprx-vision` + `xudp`, with IPv4-only
  routing and fast UDP/443 rejection.

Replace every placeholder (`203.0.113.10`, `198.51.100.20`, `uuid`,
`public_key`, `short_id`, `<PROFILE_ID>`, `dns.example`) in your local
`config.json` and never commit it.

## Install on Windows (easy path)

Put these files in one folder on Windows:

- `beam-tray.exe` (built by `./build.sh`)
- `sing-box.exe` (1.15+ beta/release; include `wintun.dll` next to it if not embedded)
- `config.json` (your filled-in copy of `config.example.json`)
- `install.ps1`, `install.cmd`, and `uninstall.cmd`

Double-click **`install.cmd`** (accept the single UAC prompt). The installer:

1. Validates `config.json` with `sing-box.exe check` before touching any live
   files or stopping a running tunnel.
2. Installs into `%ProgramFiles%\beam\` and locks down `config.json` ACLs to
   `SYSTEM` and `Administrators` only.
3. Creates a **beam** Start Menu shortcut.
4. Optionally registers a logon Scheduled Task (`\beam-tray`, `RunLevel Highest`)
   so `beam-tray.exe` starts automatically at Windows login without a UAC prompt.
5. Launches `beam-tray.exe` right away.

To upgrade later without touching your live config, run `install.cmd` from a
folder containing the new `beam-tray.exe` and `sing-box.exe` (without a
`config.json` beside them): the installer preserves `%ProgramFiles%\beam\config.json`.

To remove everything cleanly, double-click **`uninstall.cmd`** (or run
`install.ps1 -Uninstall`; pass `-KeepConfig` to keep `config.json`).

For unattended installs:

```powershell
.\install.ps1 -AutoStart -StartNow -NonInteractive
```

## Build

A MinGW-w64 toolchain is required. `build.sh` uses
`x86_64-w64-mingw32-gcc` and `x86_64-w64-mingw32-windres` by default. Set `CC`
and `WINDRES` to use other tools. The script lists an LLVM-MinGW example.

From this directory, run `./build.sh`. The output is `beam-tray.exe` here.
The executable carries a `requireAdministrator` and `PerMonitorV2` DPI manifest
because the TUN inbound needs elevation.

## Files beside the executable

`main.c` starts `sing-box.exe run -c config.json`. It expects `sing-box.exe`
(with `wintun.dll` if not embedded) and `config.json` next to `beam-tray.exe`.
The tray reads `interface_name` from the TUN inbound in `config.json` (falling
back to matching the Wintun adapter description when omitted).
