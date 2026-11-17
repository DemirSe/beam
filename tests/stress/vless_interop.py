#!/usr/bin/env python3
"""Authenticated interop campaign: real sing-box client through a real beam server.

Measures the properties the unit tests cannot: byte integrity through Vision
framing, XUDP datagram integrity, the legacy packetaddr UDP path, descriptor
behaviour under connection churn, and teardown when the client goes away.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vless_client import (  # noqa: E402
    Echo,
    beam_fds,
    free_port,
    reality_public_key,
    socks5_connect,
    socks5_udp_associate,
    socks5_udp_send,
    wait_listen,
    write_client_config,
    write_server_config,
)

FAILURES = 0


def check(name: str, ok: bool, detail: str) -> None:
    global FAILURES
    FAILURES += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)


def wait_fds(pid: int, target: int, limit: float = 8.0) -> int:
    deadline = time.time() + limit
    last = beam_fds(pid)
    while time.time() < deadline and last > target:
        time.sleep(0.1)
        last = beam_fds(pid)
    return last


def tcp_roundtrip(proxy: tuple[str, int], echo_port: int, payload: bytes, timeout: float = 10.0) -> bytes:
    sock = socks5_connect(proxy, "127.0.0.1", echo_port, timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        got = bytearray()
        while len(got) < len(payload):
            chunk = sock.recv(65536)
            if not chunk:
                break
            got.extend(chunk)
        return bytes(got)
    finally:
        sock.close()


def run_campaign(
    label: str,
    beam: Path,
    sing_box: Path,
    repo: Path,
    encoding: str,
    seed: int,
) -> None:
    rng = random.Random(seed)
    template = repo / "config.example.toml"
    priv = None
    for line in template.read_text(encoding="utf-8").splitlines():
        if line.startswith("private_key"):
            priv = line.split('"')[1]
            break
    assert priv, "example fixture carries no REALITY private key"
    pubkey = reality_public_key(priv)

    out = Path(tempfile.mkdtemp(prefix=f"interop-{label}-"))
    cover_port = free_port()
    cover = socket.socket()
    cover.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cover.bind(("127.0.0.1", cover_port))
    cover.listen(64)

    port = free_port()
    socks_port = free_port()
    server_cfg = out / "beam.toml"
    client_cfg = out / "client.json"
    write_server_config(server_cfg, port, cover_port, template)
    write_client_config(client_cfg, port, socks_port, pubkey, packet_encoding=encoding)

    server_log = (out / "beam.log").open("wb")
    server = subprocess.Popen([str(beam), "-c", str(server_cfg)], stdout=server_log, stderr=subprocess.STDOUT)
    client_log = (out / "client.log").open("wb")
    client = subprocess.Popen([str(sing_box), "run", "-c", str(client_cfg)], stdout=client_log, stderr=subprocess.STDOUT)

    echo = Echo("tcp")
    udp_echo = Echo("udp")
    try:
        wait_listen(port)
        wait_listen(socks_port, 15.0)
        time.sleep(0.4)
        baseline = beam_fds(server.pid)
        proxy = ("127.0.0.1", socks_port)

        # 1. Byte integrity through Vision, including a payload large enough to
        #    cross the 64 KiB raw-handoff boundary.
        for size in (1 << 10, 64 << 10, 1 << 20):
            payload = bytes(rng.randrange(256) for _ in range(size))
            got = tcp_roundtrip(proxy, echo.port, payload)
            want = hashlib.sha256(payload).hexdigest()[:16]
            have = hashlib.sha256(got).hexdigest()[:16]
            check(
                f"{label}_tcp_integrity_{size}",
                got == payload,
                f"want={want} got={have} bytes={len(got)}",
            )

        # 2. Connection churn: descriptors must come back between flows.
        churn_start = beam_fds(server.pid)
        for _ in range(30):
            tcp_roundtrip(proxy, echo.port, b"churn")
        settled = wait_fds(server.pid, churn_start)
        check(
            f"{label}_tcp_churn_fds",
            settled <= churn_start + 2,
            f"before={churn_start} after={settled}",
        )

        # 3. Datagram integrity through the negotiated encoding (xudp or packetaddr).
        control, (udp, relay) = socks5_udp_associate(proxy)
        ok_count = 0
        total = 120
        for index in range(total):
            size = 1 + (index % 900)
            payload = bytes([index % 256]) * size
            socks5_udp_send(udp, relay, ("127.0.0.1", udp_echo.port), payload)
            udp.settimeout(3.0)
            try:
                reply, _ = udp.recvfrom(2048)
            except socket.timeout:
                continue
            body = reply[10:] if len(reply) > 10 else b""
            if body == payload:
                ok_count += 1
        udp.close()
        control.close()
        check(
            f"{label}_udp_integrity",
            ok_count == total,
            f"echoed={ok_count}/{total} encoding={encoding}",
        )

        # 4. Retained sockets are bounded, not unbounded: after the flows above
        #    the descriptor count may sit above baseline for `close_expiry`, but
        #    it must stay near the session count rather than grow per datagram.
        burst = beam_fds(server.pid)
        check(
            f"{label}_udp_retention_bounded",
            burst <= baseline + 16,
            f"baseline={baseline} after_udp={burst}",
        )

        # 5. Teardown: when the client disappears the mux must release
        #    everything promptly (this is the path the unit test aborts in-process).
        client.terminate()
        try:
            client.wait(timeout=10)
        except subprocess.TimeoutExpired:
            client.kill()
        after = wait_fds(server.pid, baseline + 2, limit=10.0)
        check(
            f"{label}_fds_after_client_exit",
            after <= baseline + 2,
            f"baseline={baseline} after={after}",
        )
        check(f"{label}_server_alive", server.poll() is None, "running")
    finally:
        for proc in (client, server):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        echo.close()
        udp_echo.close()
        cover.close()
        server_log.close()
        client_log.close()
        if FAILURES:
            for name in ("beam.log", "client.log"):
                path = out / name
                if path.exists():
                    print(f"--- {name} tail ---")
                    for line in path.read_text(errors="replace").splitlines()[-15:]:
                        print(f"  {line}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--beam", required=True, type=Path)
    ap.add_argument("--sing-box", required=True, type=Path)
    ap.add_argument("--repo", default=".", type=Path)
    ap.add_argument("--encoding", default="xudp", choices=("xudp", "packetaddr"))
    ap.add_argument("--seed", default=20261111, type=int)
    args = ap.parse_args()
    run_campaign("xudp", args.beam, args.sing_box, args.repo.resolve(), args.encoding, args.seed)
    print("interop:", "PASS" if FAILURES == 0 else "FAIL")
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
