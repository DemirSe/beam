#!/usr/bin/env bash
# Rootless host tests for clients/windows-tray:
# - Compiles and runs tray_logic.h unit tests (named-pipe IPC parsing, tray state
#   mapping, vless:// import request)
# - Validates the 4 multi-resolution .ico resources
# - Validates app.manifest (asInvoker, no requireAdministrator)
# - Validates legacy config.example.json is removed
# - Validates the native Windows installer scripts contract
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP_BIN="$(mktemp -t beam-win-tray-test.XXXXXX)"
trap 'rm -f "$TMP_BIN"' EXIT

CC="${CC:-cc}"
"$CC" -std=c11 -Wall -Wextra -Werror -O2 \
    -o "$TMP_BIN" tests/windows-tray/test_tray_logic.c
"$TMP_BIN"

python3 - <<'PY'
import struct
from pathlib import Path

# 1. Verify all 4 status .ico files have the expected 5 sizes (16, 20, 24, 32, 48).
expected_sizes = [16, 20, 24, 32, 48]
for name in ("disconnected", "connecting", "connected", "error"):
    path = Path("clients/windows-tray/icons") / f"{name}.ico"
    data = path.read_bytes()
    reserved, ico_type, count = struct.unpack_from("<HHH", data, 0)
    assert reserved == 0 and ico_type == 1, f"{path}: invalid ICO header"
    assert count == len(expected_sizes), f"{path}: expected {len(expected_sizes)} images, got {count}"
    sizes = []
    for i in range(count):
        w, h, _cc, _res, _planes, bpp, size, offset = struct.unpack_from("<BBBBHHII", data, 6 + i * 16)
        assert w == h, f"{path}: non-square icon {w}x{h}"
        assert bpp == 32, f"{path}: expected 32bpp, got {bpp}"
        assert offset + size <= len(data), f"{path}: truncated image {i}"
        sizes.append(w)
    assert sizes == expected_sizes, f"{path}: sizes {sizes} != {expected_sizes}"

# 2. Verify app.manifest is unelevated (asInvoker) and does not requireAdministrator.
manifest = Path("clients/windows-tray/app.manifest").read_text(encoding="utf-8")
assert "asInvoker" in manifest, "app.manifest must specify asInvoker"
assert "requireAdministrator" not in manifest, "app.manifest must not specify requireAdministrator"

# 3. Verify legacy sing-box config.example.json is removed.
legacy_cfg = Path("clients/windows-tray/config.example.json")
assert not legacy_cfg.exists(), "legacy clients/windows-tray/config.example.json must be removed"

print("windows-tray icons, manifest, and legacy cleanup: OK")

# 4. Verify native Windows installer scripts contract.
install_ps1 = Path("clients/windows-tray/install.ps1").read_text(encoding="utf-8")
for required in (
    "beam-client.exe",
    "wintun.dll",
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
    "BeamClient",
    "allowed-user.sid",
    "--check",
    "--cleanup-routes",
    "S-1-5-18",
    "S-1-5-32-544",
    "-Uninstall",
    "Set-RestrictedFileAcl",
    "Invoke-SelfElevate -BoundParameters $PSBoundParameters",
    '"--stop"',
):
    assert required in install_ps1, f"install.ps1 missing required contract token: {required}"

assert "sing-box.exe" not in install_ps1, "install.ps1 must not reference or launch sing-box.exe"

install_cmd = Path("clients/windows-tray/install.cmd").read_text(encoding="utf-8")
assert "install.ps1" in install_cmd and "-ExecutionPolicy Bypass" in install_cmd

uninstall_cmd = Path("clients/windows-tray/uninstall.cmd").read_text(encoding="utf-8")
assert "install.ps1" in uninstall_cmd and "-Uninstall" in uninstall_cmd

print("windows-tray installer contract: OK")
PY
