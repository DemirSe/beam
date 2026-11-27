#!/usr/bin/env bash
# Rootless host tests for clients/windows-tray:
# - Compiles and runs tray_logic.h unit tests (named-pipe IPC parsing, tray state
#   mapping, vless:// import request)
# - Validates the 4 multi-resolution .ico resources
# - Validates config.example.json and the installer scripts (Phase 4 transition:
#   Phase 5 replaces both with the native client config and installer)
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
import json, struct
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

# 2. Verify config.example.json matches sing-box 1.15+ built-in TUN stack & repo policy.
cfg = json.loads(Path("clients/windows-tray/config.example.json").read_text(encoding="utf-8"))
assert cfg["dns"]["strategy"] == "ipv4_only"
tuns = [ib for ib in cfg["inbounds"] if ib.get("type") == "tun"]
assert len(tuns) == 1
tun = tuns[0]
assert "stack" not in tun, "sing-box 1.15+ built-in TUN stack must omit deprecated 'stack'"
assert tun["interface_name"] == "beam-tun"
assert tun["mtu"] == 1500
assert tun["auto_route"] is True
assert tun["strict_route"] is True
assert tun["dns_mode"] == "hijack"
assert tun["address"] == ["172.19.0.1/30"]

proxy = [ob for ob in cfg["outbounds"] if ob.get("tag") == "proxy"][0]
assert proxy["type"] == "vless"
assert proxy["flow"] == "xtls-rprx-vision"
assert proxy["packet_encoding"] == "xudp"
assert proxy["tls"]["server_name"] == "whatsapp.net"
assert proxy["uuid"] == "00000000-0000-0000-0000-000000000000"

rules = cfg["route"]["rules"]
assert rules[0] == {"ip_version": 6, "action": "reject"}
assert rules[1] == {"ip_is_private": True, "outbound": "direct"}
assert rules[2]["network"] == "udp" and rules[2]["port"] == [443] and rules[2]["action"] == "reject"

print("windows-tray icons and config.example.json: OK")

# 3. Verify Windows installer scripts contract (no secrets, preflight check, ACL lockdown, clean wrappers).
install_ps1 = Path("clients/windows-tray/install.ps1").read_text(encoding="utf-8")
for required in (
    "sing-box",
    '"check"',
    "Set-RestrictedConfigAcl",
    "S-1-5-18",
    "S-1-5-32-544",
    "Register-ScheduledTask",
    "Unregister-ScheduledTask",
    "Invoke-SelfElevate -BoundParameters $PSBoundParameters",
    '"--stop"',
    "-Uninstall",
):
    assert required in install_ps1, f"install.ps1 missing required contract token: {required}"

install_cmd = Path("clients/windows-tray/install.cmd").read_text(encoding="utf-8")
assert "install.ps1" in install_cmd and "-ExecutionPolicy Bypass" in install_cmd

uninstall_cmd = Path("clients/windows-tray/uninstall.cmd").read_text(encoding="utf-8")
assert "install.ps1" in uninstall_cmd and "-Uninstall" in uninstall_cmd

print("windows-tray installer contract: OK")
PY
