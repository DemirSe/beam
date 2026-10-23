#!/usr/bin/env python3
"""Update the local sing-box client from the new beam identity.

Run with sudo:  sudo python3 deploy/update-client.py
"""
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

IDENTITY = Path("/home/demir/.config/beam/client-identity.json")
CONFIG = Path("/etc/sing-box/config.json")


def main() -> int:
    if os.geteuid() != 0:
        print("update-client: run with sudo", file=sys.stderr)
        return 2
    if not IDENTITY.is_file():
        print(f"update-client: missing {IDENTITY}", file=sys.stderr)
        return 2
    if not CONFIG.is_file():
        print(f"update-client: missing {CONFIG}", file=sys.stderr)
        return 2

    identity = json.loads(IDENTITY.read_text())
    config = json.loads(CONFIG.read_text())
    tun_inbounds = [
        inbound for inbound in config.get("inbounds", []) if inbound.get("type") == "tun"
    ]
    if not tun_inbounds:
        print("update-client: expected at least one TUN inbound", file=sys.stderr)
        return 2
    # The kernel TUN stack is stable for large HTTP/3 bodies through this
    # server. The gVisor stack intermittently resets/stalls large H3 streams.
    # MTU 1500 matches the server's 1500-byte egress path. The outer TCP
    # connection still segments for smaller mobile/hotspot paths; 1400 loses
    # Google/YouTube H3 because their QUIC packets exceed the inner MTU.
    for tun in tun_inbounds:
        tun["stack"] = "system"
        tun["mtu"] = 1500

    outbounds = config.get("outbounds", [])
    vless = [o for o in outbounds if o.get("type") == "vless"]
    if len(vless) != 1:
        print(f"update-client: expected one VLESS outbound, found {len(vless)}", file=sys.stderr)
        return 2

    outbound = vless[0]
    outbound["server"] = identity["server"]
    outbound["server_port"] = int(identity["port"])
    outbound["uuid"] = identity["user_id"]
    outbound["flow"] = identity["flow"]
    outbound["packet_encoding"] = "xudp"
    tls = outbound.setdefault("tls", {})
    tls["enabled"] = True
    tls["server_name"] = identity["server_name"]
    tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
    reality = tls.setdefault("reality", {})
    reality["enabled"] = True
    reality["public_key"] = identity["public_key"]
    reality["short_id"] = identity["short_id"]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = CONFIG.with_name(f"config.json.bak-{stamp}")
    shutil.copy2(CONFIG, backup)
    os.chmod(backup, 0o600)

    CONFIG.write_text(json.dumps(config, indent=2) + "\n")
    os.chmod(CONFIG, 0o600)

    result = subprocess.run(["systemctl", "restart", "sing-box"], capture_output=True, text=True)
    active = subprocess.run(["systemctl", "is-active", "--quiet", "sing-box"])
    if result.returncode != 0 or active.returncode != 0:
        shutil.copy2(backup, CONFIG)
        subprocess.run(["systemctl", "restart", "sing-box"], check=False)
        print("update-client: restart failed; previous config restored", file=sys.stderr)
        print(result.stderr.strip(), file=sys.stderr)
        return 1

    enabled = subprocess.run(
        ["systemctl", "enable", "sing-box"], capture_output=True, text=True
    )
    if enabled.returncode != 0:
        print(
            "update-client: warning: could not enable sing-box at boot",
            file=sys.stderr,
        )
        print(enabled.stderr.strip(), file=sys.stderr)

    print(f"update-client: updated {CONFIG}; backup={backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
