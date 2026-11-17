#!/usr/bin/env python3
"""Client-side probes for the full-TUN harness.

Every probe writes a small JSON object to ``--out`` and exits 0 on success,
1 on a probe failure. The harness treats exit 1 as a test result, not as a
harness error.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path

MARKER = b"beam-tun-ok"


def _family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _http(host: str, port: int, use_tls: bool, timeout: float) -> dict:
    started = time.monotonic()
    sock = None
    version = None
    try:
        sock = socket.socket(_family(host), socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if use_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
            version = sock.version()
        request = (
            f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        chunks = []
        total = 0
        while total < 65536:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            total += len(data)
        raw = b"".join(chunks)
        status = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
        ok = status.startswith("HTTP/1.") and " 200 " in status and MARKER in raw
        detail = f"{status or 'empty response'}; body={body[:64]!r}"
        if version:
            detail += f"; tls={version}"
        return {
            "ok": ok,
            "detail": detail,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except Exception as error:  # noqa: BLE001 - report the exact failure
        return {
            "ok": False,
            "detail": f"{type(error).__name__}: {error}",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _udp(host: str, port: int, timeout: float) -> dict:
    started = time.monotonic()
    sock = None
    payload = b"beam-udp-probe-" + os.urandom(4).hex().encode("ascii")
    try:
        sock = socket.socket(_family(host), socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(payload)
        data = sock.recv(65535)
        ok = data == payload
        detail = f"sent={payload.decode()} received={data[:64]!r}"
        return {
            "ok": ok,
            "detail": detail,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
    except Exception as error:  # noqa: BLE001 - report the exact failure
        return {
            "ok": False,
            "detail": f"{type(error).__name__}: {error}",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    http = sub.add_parser("http")
    http.add_argument("--host", required=True)
    http.add_argument("--port", required=True, type=int)
    http.add_argument("--tls", action="store_true")
    http.add_argument("--timeout", type=float, default=10.0)

    udp = sub.add_parser("udp")
    udp.add_argument("--host", required=True)
    udp.add_argument("--port", required=True, type=int)
    udp.add_argument("--timeout", type=float, default=5.0)

    for item in (http, udp):
        item.add_argument("--out", required=True, type=Path)

    args = parser.parse_args()
    if args.mode == "http":
        result = _http(args.host, args.port, args.tls, args.timeout)
    else:
        result = _udp(args.host, args.port, args.timeout)

    args.out.write_text(json.dumps(result) + "\n", encoding="utf-8")
    print(json.dumps(result), flush=True)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
