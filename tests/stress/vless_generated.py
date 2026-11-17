#!/usr/bin/env python3
"""Compatibility check for the identity and link from `beam generate`.

`beam generate` writes a server fragment and one `vless://` link. Neither stock
Xray nor sing-box accepts a share link on its command line, so this harness
parses the link and builds each client's native configuration from the link
values only. The server runs from the generated fragment. A real client that
connects therefore proves that the link's host, port, UUID, REALITY public key,
short id, SNI, and Vision flow agree with the generated server identity.

Usage:
    python3 tests/stress/vless_generated.py --beam target/release/beam \
        --sing-box /usr/local/bin/sing-box --xray /usr/local/bin/xray
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from loopback import SilentCover, free_port  # noqa: E402
from vless_client import (  # noqa: E402
    Echo,
    reality_public_key,
    recv_exact,
    socks5_connect,
    wait_listen,
)

FAILURES = 0
HOST = "127.0.0.1"
REMARK = "beam-generated"
SNI = "whatsapp.net"


def check(name: str, ok: bool, detail: str) -> bool:
    global FAILURES
    FAILURES += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)
    return ok


def generate_identity(beam: Path, port: int) -> tuple[dict, str, str]:
    result = subprocess.run(
        [
            str(beam),
            "generate",
            "--host",
            HOST,
            "--port",
            str(port),
            "--sni",
            SNI,
            "--remark",
            REMARK,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"beam generate exited {result.returncode}: {result.stderr.strip()}")

    lines = result.stdout.splitlines()
    links = [line for line in lines if line.startswith("vless://")]
    if len(links) != 1:
        raise RuntimeError(f"expected exactly one vless link, found {len(links)}")
    fragment = "\n".join(line for line in lines if not line.startswith("vless://"))
    return tomllib.loads(fragment), links[0], result.stderr


def parse_link(link: str) -> dict[str, str]:
    parts = urlsplit(link)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if len(pairs) != len(dict(pairs)):
        raise RuntimeError(f"duplicate query parameters in {link}")
    values = dict(pairs)
    values.update(
        {
            "scheme": parts.scheme,
            "uuid": parts.username or "",
            "host": parts.hostname or "",
            "port": str(parts.port or ""),
            "fragment": unquote(parts.fragment),
        }
    )
    return values


def replace_once(text: str, pattern: str, replacement: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.M)
    if count != 1:
        raise RuntimeError(f"cannot replace {pattern!r} in the example config")
    return updated


def write_server_config(
    path: Path, template: Path, identity: dict, port: int, cover_port: int
) -> None:
    text = template.read_text(encoding="utf-8")
    text = replace_once(text, r"^listen\s*=.*$", f'listen = "127.0.0.1:{port}"')
    text = replace_once(text, r"^dest\s*=.*$", f'dest = "127.0.0.1:{cover_port}"')
    text = replace_once(text, r"^level\s*=.*$", 'level = "warn"')
    text = replace_once(text, r"^id\s*=.*$", f'id = "{identity["user"]["id"]}"')
    text = replace_once(
        text, r"^private_key\s*=.*$", f'private_key = "{identity["reality"]["private_key"]}"'
    )
    text = replace_once(
        text,
        r"^short_ids\s*=.*$",
        f'short_ids = ["{identity["reality"]["short_ids"][0]}"]',
    )
    text = replace_once(
        text,
        r"^server_names\s*=.*$",
        f'server_names = ["{identity["reality"]["server_names"][0]}"]',
    )
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def write_sing_box(path: Path, link: dict[str, str], socks_port: int) -> None:
    outbound = {
        "type": "vless",
        "server": link["host"],
        "server_port": int(link["port"]),
        "uuid": link["uuid"],
        "packet_encoding": "xudp",
        "tls": {
            "enabled": True,
            "server_name": link["sni"],
            "utls": {"enabled": True, "fingerprint": link["fp"]},
            "reality": {
                "enabled": True,
                "public_key": link["pbk"],
                "short_id": link["sid"],
            },
        },
        "flow": link["flow"],
    }
    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
                "users": [],
            }
        ],
        "outbounds": [outbound],
    }
    path.write_text(json.dumps(config, indent=1), encoding="utf-8")


def write_xray(path: Path, link: dict[str, str], socks_port: int) -> None:
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": link["host"],
                            "port": int(link["port"]),
                            "users": [
                                {
                                    "id": link["uuid"],
                                    "encryption": "none",
                                    "flow": link["flow"],
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": link["sni"],
                        "fingerprint": link["fp"],
                        "publicKey": link["pbk"],
                        "shortId": link["sid"],
                    },
                },
            }
        ],
    }
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def run_client(
    label: str, binary: Path, config: Path, socks_port: int, echo: Echo, out: Path
) -> None:
    log_path = out / f"{label}.log"
    payload = bytes(range(256)) * 1024
    with log_path.open("wb") as log:
        client = subprocess.Popen(
            [str(binary), "run", "-c", str(config)],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_listen(socks_port, 20.0)
            sock = socks5_connect(
                ("127.0.0.1", socks_port), "127.0.0.1", echo.port, timeout=20.0
            )
            try:
                sock.settimeout(20.0)
                sock.sendall(payload)
                received = recv_exact(sock, len(payload))
            finally:
                sock.close()
            check(
                f"{label}_tcp_integrity",
                received == payload,
                f"bytes={len(received)}/{len(payload)}",
            )
        except Exception as error:  # noqa: BLE001 - any client failure is a test failure
            check(f"{label}_tcp_integrity", False, f"{type(error).__name__}: {error}")
        finally:
            client.terminate()
            try:
                client.wait(timeout=10)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait(timeout=5)


def log_tail(path: Path, lines: int = 15) -> None:
    if path.exists():
        print(f"--- {path.name} tail ---")
        for line in path.read_text(errors="replace").splitlines()[-lines:]:
            print(f"  {line}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--beam", required=True, type=Path)
    parser.add_argument("--sing-box", type=Path)
    parser.add_argument("--xray", type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    if not args.sing_box and not args.xray:
        parser.error("give --sing-box, --xray, or both")

    out = Path(tempfile.mkdtemp(prefix="generated-"))
    template = args.repo / "config.example.toml"
    cover = SilentCover()
    echo = Echo("tcp")
    port = free_port()
    server = None
    server_log = None
    try:
        try:
            identity, link, stderr = generate_identity(args.beam, port)
            values = parse_link(link)
        except (RuntimeError, ValueError, tomllib.TOMLDecodeError) as error:
            print(f"FAIL generate: {error}")
            return 1

        check(
            "generate_warns_about_the_private_key",
            "umask 077" in stderr,
            "stderr carries the private-key warning",
        )

        private_key = identity["reality"]["private_key"]
        public_key = reality_public_key(private_key)
        short_id = identity["reality"]["short_ids"][0]
        server_name = identity["reality"]["server_names"][0]
        user_id = identity["user"]["id"]
        flow = identity["user"]["flow"]

        if not check(
            "fragment_flow",
            flow == "xtls-rprx-vision",
            f"flow={flow}",
        ):
            return 1
        if not check(
            "fragment_one_short_id_and_name",
            len(identity["reality"]["short_ids"]) == 1
            and len(identity["reality"]["server_names"]) == 1,
            f"short_ids={len(identity['reality']['short_ids'])} "
            f"server_names={len(identity['reality']['server_names'])}",
        ):
            return 1

        envelope_ok = (
            values["scheme"] == "vless"
            and values["uuid"] == user_id
            and values["host"] == HOST
            and values["port"] == str(port)
            and values["fragment"] == REMARK
        )
        check(
            "link_envelope",
            envelope_ok,
            f"scheme={values['scheme']} user={values['uuid']} "
            f"host={values['host']} port={values['port']} fragment={values['fragment']!r}",
        )

        expected = {
            "encryption": "none",
            "security": "reality",
            "sni": server_name,
            "fp": "chrome",
            "pbk": public_key,
            "sid": short_id,
            "type": "tcp",
            "flow": flow,
        }
        envelope = {"scheme", "uuid", "host", "port", "fragment"}
        actual = {key: value for key, value in values.items() if key not in envelope}
        check("link_query", actual == expected, f"params={actual}")

        check(
            "link_omits_private_key",
            private_key not in link,
            "private key absent from the link",
        )

        server_cfg = out / "beam.toml"
        write_server_config(server_cfg, template, identity, port, cover.port)
        validated = subprocess.run(
            [str(args.beam), "--check", "-c", str(server_cfg)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if not check(
            "server_config_validates",
            validated.returncode == 0,
            (validated.stdout.strip() or validated.stderr.strip() or "no output"),
        ):
            return 1

        server_log = (out / "beam.log").open("wb")
        server = subprocess.Popen(
            [str(args.beam), "-c", str(server_cfg)],
            stdout=server_log,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_listen(port)
        except RuntimeError as error:
            check("server_started", False, str(error))
            return 1
        time.sleep(0.2)

        if args.sing_box:
            config = out / "sing-box.json"
            socks_port = free_port()
            write_sing_box(config, values, socks_port)
            run_client("sing_box", args.sing_box, config, socks_port, echo, out)
        if args.xray:
            config = out / "xray.json"
            socks_port = free_port()
            write_xray(config, values, socks_port)
            run_client("xray", args.xray, config, socks_port, echo, out)

        check(
            "server_alive_after_clients",
            server.poll() is None,
            f"exit={server.poll()}",
        )
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        if server_log is not None:
            server_log.close()
        echo.close()
        cover.close()
        if FAILURES:
            log_tail(out / "beam.log")
            log_tail(out / "sing_box.log")
            log_tail(out / "xray.log")
            print(f"artifacts: {out}")

    print("generated-link:", "PASS" if FAILURES == 0 else "FAIL")
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
