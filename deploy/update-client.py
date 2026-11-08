#!/usr/bin/env python3
"""Update the local sing-box client from the new beam identity.

Run with sudo:  sudo python3 deploy/update-client.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

IDENTITY = Path("/home/demir/.config/beam/client-identity.json")
CONFIG = Path("/etc/beam/config.json")
SERVICE = "beam-client"
SING_BOX = "/usr/local/lib/beam/sing-box"


# sing-box rejects a string port (route rules take Listable[uint16]); accept
# any shape so an invalid profile fails at `sing-box check`, not here.
def _is_exact_udp_443_port(raw: object) -> bool:
    if isinstance(raw, int):
        return raw == 443
    if isinstance(raw, list):
        return len(raw) == 1 and raw[0] == 443
    if isinstance(raw, str):
        return raw.strip() == "443"
    return False


def is_udp443_reject(rule: dict) -> bool:
    return (
        rule.get("action") == "reject"
        and rule.get("network") == "udp"
        and _is_exact_udp_443_port(rule.get("port"))
    )


def _is_ipv6_literal(value: object) -> bool:
    return isinstance(value, str) and ":" in value


def ensure_ipv4_only(config: dict) -> None:
    dns = config.setdefault("dns", {})
    dns["strategy"] = "ipv4_only"

    for server in dns.get("servers", []):
        predefined = server.get("predefined") if isinstance(server, dict) else None
        if isinstance(predefined, dict):
            for host, addresses in list(predefined.items()):
                if isinstance(addresses, str):
                    predefined[host] = [] if _is_ipv6_literal(addresses) else [addresses]
                elif isinstance(addresses, list):
                    predefined[host] = [
                        address for address in addresses
                        if not _is_ipv6_literal(address)
                    ]

    for inbound in config.get("inbounds", []):
        if not isinstance(inbound, dict) or inbound.get("type") != "tun":
            continue
        addresses = inbound.get("address", [])
        if isinstance(addresses, str):
            addresses = [addresses]
        if not isinstance(addresses, list):
            continue
        kept = [address for address in addresses if not _is_ipv6_literal(address)]
        if not kept:
            raise ValueError("TUN inbound has no IPv4 address")
        inbound["address"] = kept

    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])
    rules = [
        rule for rule in rules
        if not (
            isinstance(rule, dict)
            and str(rule.get("ip_version")) == "6"
            and rule.get("action") == "reject"
        )
    ]
    route["rules"] = [{"ip_version": 6, "action": "reject"}, *rules]


def ensure_quic_policy(config: dict) -> None:
    """Keep the stock-client H2 fallback policy canonical."""
    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])
    private = next((r for r in rules if r.get("ip_is_private") is True), None)
    sniff = next((r for r in rules if r.get("action") == "sniff"), None)
    dns = next((r for r in rules if r.get("protocol") == "dns"), None)
    reject = {
        "action": "reject",
        "network": "udp",
        "port": [443],
        "method": "default",
        "no_drop": True,
    }

    route["rules"] = [
        r
        for r in (private, reject, sniff, dns)
        if r is not None
    ]
    route["rules"].extend(r for r in rules if not is_udp443_reject(r) and r not in route["rules"])


def stage_config(config: dict, destination: Path) -> Path:
    """Write a private temp file and return it for validation/rename."""
    fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent))
    staged = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return staged


def check_config(path: Path) -> bool:
    result = subprocess.run(
        [SING_BOX, "check", "-c", str(path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        print("update-client: config check failed; live config unchanged", file=sys.stderr)
        if detail:
            print(detail, file=sys.stderr)
        return False
    return True


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
    ensure_quic_policy(config)
    try:
        ensure_ipv4_only(config)
    except ValueError as error:
        print(f"update-client: {error}", file=sys.stderr)
        return 2

    staged = stage_config(config, CONFIG)
    try:
        if not check_config(staged):
            return 1

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = CONFIG.with_name(f"config.json.bak-{stamp}")
        shutil.copy2(CONFIG, backup)
        os.chmod(backup, 0o600)

        os.replace(staged, CONFIG)
        dir_fd = os.open(CONFIG.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        staged.unlink(missing_ok=True)

    result = subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, text=True)
    active = subprocess.run(["systemctl", "is-active", "--quiet", SERVICE])
    if result.returncode != 0 or active.returncode != 0:
        shutil.copy2(backup, CONFIG)
        os.chmod(CONFIG, 0o600)
        subprocess.run(["systemctl", "restart", SERVICE], check=False)
        print("update-client: restart failed; previous config restored", file=sys.stderr)
        print(result.stderr.strip(), file=sys.stderr)
        return 1

    enabled = subprocess.run(
        ["systemctl", "enable", SERVICE], capture_output=True, text=True
    )
    if enabled.returncode != 0:
        print(
            "update-client: warning: could not enable beam-client at boot",
            file=sys.stderr,
        )
        print(enabled.stderr.strip(), file=sys.stderr)

    print(f"update-client: updated {CONFIG}; backup={backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
