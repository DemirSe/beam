#!/usr/bin/env python3
"""Render the configs used by the local full-TUN harness.

This script is test-only. It reads the throwaway REALITY fixture from
``TEST_CONFIG``, derives the matching X25519 public key, and writes:

* ``beam.toml``          -- beam server config for the lab topology
* ``singbox.json``       -- sing-box full-TUN client config
* ``xray-server.json``   -- optional stock-Xray control server config

No value is printed; the caller only needs the file paths.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import tomllib
from pathlib import Path

# X25519 constants (RFC 7748).
_P = 2**255 - 19
_A24 = 121665


def _x25519(scalar: bytes, u: bytes = (9).to_bytes(32, "little")) -> bytes:
    """Return the X25519 public key for a 32-byte scalar."""
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for bit in reversed(range(255)):
        kt = (k_int >> bit) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def _decode_key(value: str) -> bytes:
    raw = value.strip()
    try:
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except ValueError as error:
        raise SystemExit(f"invalid REALITY private key: {error}") from error
    if len(decoded) != 32:
        raise SystemExit("REALITY private key must decode to 32 bytes")
    return decoded


def _public_key(private_key: str) -> str:
    return base64.urlsafe_b64encode(_x25519(_decode_key(private_key))).decode().rstrip("=")


def _require(mapping: dict, *path: str):
    value = mapping
    for part in path:
        if not isinstance(value, dict) or part not in value:
            raise SystemExit(f"test config is missing {'.'.join(path)}")
        value = value[part]
    return value


def _render_beam(
    source: str, listen: str, cover: str, log_level: str, destination: Path
) -> None:
    text = source

    def replace(pattern: str, replacement: str) -> None:
        nonlocal text
        updated, count = re.subn(pattern, replacement, text, count=1, flags=re.M)
        if count != 1:
            raise SystemExit(f"could not rewrite {pattern!r} in the test config")
        text = updated

    replace(r"^listen = .*$", f'listen = "{listen}"')
    replace(r"^dest = .*$", f'dest = "{cover}"')
    replace(r"^handshake_timeout_ms = .*$", "handshake_timeout_ms = 15000")
    replace(r"^idle_timeout_ms = .*$", "idle_timeout_ms = 300000")
    replace(r"^level = .*$", f'level = "{log_level}"')
    destination.write_text(text, encoding="utf-8")
    destination.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-config", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--listen", required=True, help="beam listen address, e.g. 10.10.1.1:443")
    parser.add_argument("--cover", required=True, help="REALITY cover address")
    parser.add_argument("--singbox", action="store_true", help="also render singbox.json")
    parser.add_argument("--xray", action="store_true", help="also render xray-server.json")
    parser.add_argument(
        "--xray-client",
        action="store_true",
        help="also render xray-client.json (SOCKS inbound, no TUN)",
    )
    parser.add_argument(
        "--packet-encoding",
        choices=("xudp", "packetaddr", "legacy"),
        default="xudp",
        help="sing-box UDP mode: xudp, packetaddr, or legacy (empty string)",
    )
    parser.add_argument(
        "--log-level",
        default="debug",
        choices=("error", "warn", "info", "debug", "trace"),
        help="log level for every rendered config (benchmark runs use warn)",
    )
    args = parser.parse_args()

    source = args.test_config.read_text(encoding="utf-8")
    try:
        config = tomllib.loads(source)
    except tomllib.TOMLDecodeError as error:
        raise SystemExit(f"invalid test config: {error}") from error

    user_id = _require(config, "user", "id")
    flow = _require(config, "user", "flow")
    private_key = _require(config, "reality", "private_key")
    short_ids = _require(config, "reality", "short_ids")
    server_names = _require(config, "reality", "server_names")
    if not isinstance(short_ids, list) or not short_ids:
        raise SystemExit("test config needs at least one REALITY short id")
    if not isinstance(server_names, list) or not server_names:
        raise SystemExit("test config needs at least one REALITY server name")

    public_key = _public_key(private_key)
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    _render_beam(source, args.listen, args.cover, args.log_level, out / "beam.toml")

    if args.singbox:
        singbox = {
            "log": {"level": args.log_level, "timestamp": True},
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "tun0",
                    "address": ["198.18.0.1/15", "fd00:1::1/64"],
                    "mtu": 1500,
                    "auto_route": False,
                    "strict_route": False,
                    "stack": "system",
                }
            ],
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "proxy",
                    "server": args.listen.rsplit(":", 1)[0],
                    "server_port": int(args.listen.rsplit(":", 1)[1]),
                    "uuid": user_id,
                    "flow": flow,
                    "packet_encoding": (
                        "" if args.packet_encoding == "legacy" else args.packet_encoding
                    ),
                    "tls": {
                        "enabled": True,
                        "server_name": server_names[0],
                        "utls": {"enabled": True, "fingerprint": "chrome"},
                        "reality": {
                            "enabled": True,
                            "public_key": public_key,
                            "short_id": short_ids[0],
                        },
                    },
                }
            ],
            "route": {"auto_detect_interface": False, "final": "proxy"},
        }
        (out / "singbox.json").write_text(
            json.dumps(singbox, indent=2) + "\n", encoding="utf-8"
        )
        (out / "singbox.json").chmod(0o600)

    if args.xray:
        xray_level = "warning" if args.log_level == "warn" else args.log_level
        xray = {
            "log": {"loglevel": xray_level},
            "inbounds": [
                {
                    "listen": args.listen.rsplit(":", 1)[0],
                    "port": int(args.listen.rsplit(":", 1)[1]),
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": user_id, "flow": flow}],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": args.cover,
                            "serverNames": [server_names[0]],
                            "privateKey": private_key,
                            "shortIds": [short_ids[0]],
                        },
                    },
                }
            ],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        }
        (out / "xray-server.json").write_text(
            json.dumps(xray, indent=2) + "\n", encoding="utf-8"
        )
        (out / "xray-server.json").chmod(0o600)

    if args.xray_client:
        host, port = args.listen.rsplit(":", 1)
        client = {
            "log": {"loglevel": "warning" if args.log_level == "warn" else args.log_level},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": 11080,
                    "protocol": "socks",
                    "settings": {"udp": True},
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": host,
                                "port": int(port),
                                "users": [
                                    {
                                        "id": user_id,
                                        "encryption": "none",
                                        "flow": flow,
                                    }
                                ],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": server_names[0],
                            "fingerprint": "chrome",
                            "publicKey": public_key,
                            "shortId": short_ids[0],
                            "spiderX": "/",
                        },
                    },
                }
            ],
        }
        (out / "xray-client.json").write_text(
            json.dumps(client, indent=2) + "\n", encoding="utf-8"
        )
        (out / "xray-client.json").chmod(0o600)

    return 0


if __name__ == "__main__":
    sys.exit(main())
