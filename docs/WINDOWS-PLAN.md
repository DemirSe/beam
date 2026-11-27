# Beam Native Windows Client — Implementation & Orchestration Plan

This document is the single source of truth for the native **beam** Windows
client (`crates/beam-sys` Windows layer + `crates/beam-core`/`beam-tun`
cross-platform support + `crates/beam-client` Windows Service/WinTun/WFP/IPC +
`clients/windows-tray` unelevated Win32 tray with `vless://` import).

Remove this file and point links to `clients/windows-tray/README.md` once all
phases are complete and verified.

---

## Approved Product & Architecture Decisions

| Area | Approved Decision |
|---|---|
| **Core Engine** | Native Rust (`beam-core` + `beam-tun` + `beam-sys` + `beam-client`). Removes `sing-box.exe` dependency completely. |
| **TUN Driver** | Official WHQL-signed WireGuard **WinTun 0.14.1** (`wintun.dll`, `amd64`), SHA-256 pinned, loaded strictly from install directory (`LOAD_LIBRARY_SEARCH_APPLICATION_DIR`). No binary `.dll` committed to git. |
| **Process & Privilege Model** | **Windows Service (`BeamClient`, `LocalSystem`) + Unelevated Tray (`beam-tray.exe`, `asInvoker`)**. Starts at boot, survives logoff, zero UAC after install for Connect/Disconnect/Restart/`vless://` import. |
| **IPC & Security** | Named Pipe `\\.\pipe\beam-client-ipc` (`FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, explicit SDDL DACL: `SYSTEM` + `Administrators` + `%ProgramData%\beam\allowed-user.sid`, fail-closed to `SY`+`BA` if missing). Secrets are never returned over IPC or logged. |
| **Tray UI** | Upgraded `clients/windows-tray/` (Win32 C, ~2 MB RAM, zero WebView2/Electron): Linux `beam-tray` status parity (`Connected + RTT`, `Degraded`, `Reconnecting`, `WaitingNetwork`, `Error`, `drops`) + native Win32 **`Import vless:// link...`** modal dialog (`SecureZeroMemory` after send). |
| **Routing, DNS & Leak Protection** | Pure IP Helper API (`CreateIpForwardEntry2` / `NotifyRouteChange2`, zero shell-out), fail-closed split routes (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1`), dynamic WFP (`FWPM_SESSION_FLAG_DYNAMIC`) blocking physical port 53 SMHNR DNS leaks + optional `strict_kill_switch`, `DnsFlushResolverCache`, and `IP_UNICAST_IF`/`IPV6_UNICAST_IF` upstream socket binding. |
| **Config Format** | Same TOML schema as Linux (`config.client.example.toml`, `%ProgramData%\beam\client.toml`, ACL: `SYSTEM` + `Administrators` only), with backward-compatible optional `tun.strict_kill_switch = true` and `tun.auto_connect = true`. |
| **`unsafe` Boundary** | All Windows FFI/WinTun/WFP/IP Helper/Service/Pipe `unsafe` stays exclusively in `crates/beam-sys` with `// SAFETY:` comments. `beam-core`, `beam-tun`, and `beam-client` remain `#![forbid(unsafe_code)]`. |
| **Build & Test** | GitHub Actions `windows-latest` (`x86_64-pc-windows-msvc`) build, unit tests, Admin WinTun/IP Helper/WFP/IPC smoke test, zip artifact + live Windows PC verification. |

---

## Orchestration & Quality Control Cadence

Every phase follows this exact workflow:

1. **Implementation:** **Gemini 4 Neon (Low)** (`antigravity` -> `gemini-4-neon`, `thought_level: low`) writes the phase code (parallel workers on non-overlapping files where beneficial).
2. **2-Round Independent Feedback Loop:**
   - Each round launches **1 independent Muse Spark** (`pi` -> `opencode-go/muse-spark-1.3-contributor`, `thinking: xhigh`) as a fresh read-only reviewer.
   - Valid findings are fixed between rounds until both rounds complete cleanly.
3. **Orchestrator Final Control:** **Gemini 4 Neon** audits the final diff, runs `make verify` (Linux) and Windows CI verification, updates the checklist below, and commits locally on `main` (pushing only with owner approval).

---

## Phase Checklist

| Phase | Scope | Files Owned | Status | Verification / Notes |
|---|---|---|---|---|
| **Phase 1** | Cross-platform core (`beam-sys` Windows skeleton + `beam-core`/`beam-tun` Windows build + initial `windows-build.yml`) | `crates/beam-sys/`, `crates/beam-core/`, `crates/beam-tun/`, `.github/workflows/windows-build.yml` | Done | Local `make verify` + `beam-sys` Windows MSVC clippy + 3-round (DeepSeek+Muse) QC clean; full Windows CI pending push |
| **Phase 2** | Windows OS primitives in `beam-sys` (`wintun.rs`, `wfp.rs`, `iphelper.rs`, `service.rs`, `pipe.rs`) | `crates/beam-sys/src/windows/*` | Done | Local `make verify` + `beam-sys` Windows MSVC clippy + 3-round (DeepSeek+Muse) QC clean; runtime Windows tests pending CI |
| **Phase 3** | Native Windows `beam-client.exe` (`win_tun.rs`, `win_routes.rs`, `win_health.rs`, `win_service.rs`, `win_ipc.rs`, `config.rs`, `main.rs`) | `crates/beam-client/src/*` | Done | Local `make verify` + `beam-sys` Windows MSVC clippy + 3-round (DeepSeek+Muse) QC clean; full Windows CI pending push |
| **Phase 4** | Unelevated `beam-tray.exe` + `vless://` import dialog + C unit tests | `clients/windows-tray/*`, `tests/windows-tray/*` | Done | Local `make verify` + `test_tray_logic.sh` + MinGW/Clang/ASAN/UBSAN + 2-round Muse Spark `xhigh` QC (`NO FINDINGS`) |
| **Phase 5** | Installer (`install.ps1`/`.cmd`), release packaging (`release.yml`, `release-windows-tray.sh`), contract tests & docs | `clients/windows-tray/install*`, `scripts/release-windows-tray.sh`, `.github/workflows/*`, `tests/release/*`, `docs/*`, `README.md`, `AGENTS.md` | Done | Local `make verify` (12 script suites + 829 Rust tests) + 2-round Muse Spark `xhigh` QC clean |
| **Phase 6** | Live Windows PC verification (install, `vless://` import, leaks, roaming, sleep/wake, kill recovery, uninstall) & cleanup | Live Windows host + GitHub Actions `windows-build.yml` + remove `docs/WINDOWS-PLAN.md` | In Progress | Six automated live checks pass in CI run 46063427533 (`windows-latest` + live VPS): `route_fail_closed`, `dns_leak` (`public_dns_blocked`, pre-connect control, the documented local-resolver permit), `ipv6_egress` (`ula_only`), `service_restart`, `crash_recovery`, and `hang_recovery` (unreachable server → `reconnecting`/`dial_failures`, no CPU spin, then recovery). The same run compares both clients over three interleaved rounds. Sleep/wake, roaming and a by-hand install still need the owner's PC. |
