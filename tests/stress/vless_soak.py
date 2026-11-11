#!/usr/bin/env python3
"""Twenty-minute soak: sustained mixed traffic with periodic client restarts.

Samples the server's descriptors, RSS, and thread count every two minutes and
requires the end state to be bounded, which is what a slow leak would break.
Every few minutes the client is restarted to exercise session teardown.
"""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vless_client import (  # noqa: E402
    Echo,
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
DURATION = float(os.environ.get("SOAK_SECONDS", "1200"))
RESTART_EVERY = 300.0


def check(name: str, ok: bool, detail: str) -> None:
    global FAILURES
    FAILURES += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)


def sample(pid: int) -> tuple[int, int, int]:
    fds = len(os.listdir(f"/proc/{pid}/fd"))
    rss = 0
    threads = 0
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            rss = int(line.split()[1])
        elif line.startswith("Threads:"):
            threads = int(line.split()[1])
    return fds, rss, threads


def tcp_flow(proxy, port: int, size: int) -> bool:
    payload = bytes((index * 17) % 256 for index in range(size))
    try:
        sock = socks5_connect(proxy, "127.0.0.1", port, timeout=15.0)
        sock.settimeout(15.0)
        sock.sendall(payload)
        got = bytearray()
        while len(got) < len(payload):
            chunk = sock.recv(1 << 16)
            if not chunk:
                break
            got.extend(chunk)
        sock.close()
        return hashlib.sha256(payload).digest() == hashlib.sha256(bytes(got)).digest()
    except OSError:
        return False


def udp_flow(proxy, port: int, count: int) -> int:
    good = 0
    try:
        control, (udp, relay) = socks5_udp_associate(proxy)
    except OSError:
        return 0
    try:
        for index in range(count):
            body = f"soak-{index}".encode()
            socks5_udp_send(udp, relay, ("127.0.0.1", port), body)
            udp.settimeout(2.0)
            try:
                reply, _ = udp.recvfrom(2048)
            except socket.timeout:
                continue
            if (reply[10:] if len(reply) > 10 else b"") == body:
                good += 1
    finally:
        udp.close()
        control.close()
    return good


def main() -> int:
    beam, sing_box = Path(sys.argv[1]), Path(sys.argv[2])
    repo = Path(".").resolve()
    template = repo / "config.example.toml"
    priv = next(l.split('"')[1] for l in template.read_text().splitlines() if l.startswith("private_key"))
    pubkey = reality_public_key(priv)

    out = Path(tempfile.mkdtemp(prefix="soak-"))
    cover_port = free_port()
    cover = socket.socket()
    cover.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cover.bind(("127.0.0.1", cover_port))
    cover.listen(64)
    port, socks_port = free_port(), free_port()
    server_cfg = out / "beam.toml"
    client_cfg = out / "client.json"
    write_server_config(server_cfg, port, cover_port, template)
    write_client_config(client_cfg, port, socks_port, pubkey)

    server_log = (out / "beam.log").open("wb")
    server = subprocess.Popen([str(beam), "-c", str(server_cfg)], stdout=server_log, stderr=subprocess.STDOUT)

    def spawn_client() -> tuple[subprocess.Popen, object]:
        handle = (out / f"client-{time.time():.0f}.log").open("wb")
        proc = subprocess.Popen([str(sing_box), "run", "-c", str(client_cfg)], stdout=handle, stderr=subprocess.STDOUT)
        return proc, handle

    client, client_log = spawn_client()
    tcp_echo = Echo("tcp")
    udp_echo = Echo("udp")
    try:
        wait_listen(port)
        wait_listen(socks_port, 20.0)
        time.sleep(0.5)
        proxy = ("127.0.0.1", socks_port)
        base_fds, base_rss, base_threads = sample(server.pid)
        print(
            f"baseline fds={base_fds} rss_kb={base_rss} threads={base_threads} "
            f"duration_s={DURATION:.0f}",
            flush=True,
        )

        started = time.time()
        last_restart = started
        last_sample = started
        rounds = 0
        tcp_ok = 0
        tcp_total = 0
        udp_ok = 0
        udp_total = 0
        while time.time() - started < DURATION:
            for _ in range(8):
                tcp_total += 1
                tcp_ok += 1 if tcp_flow(proxy, tcp_echo.port, 64 << 10) else 0
            udp_ok += udp_flow(proxy, udp_echo.port, 20)
            udp_total += 20
            rounds += 1

            now = time.time()
            if now - last_restart >= RESTART_EVERY:
                client.terminate()
                try:
                    client.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    client.kill()
                client_log.close()
                client, client_log = spawn_client()
                wait_listen(socks_port, 20.0)
                last_restart = now
                print(f"++ client restarted after {rounds} rounds", flush=True)

            if now - last_sample >= 120:
                fds, rss, threads = sample(server.pid)
                print(
                    f"sample t={now - started:.0f}s rounds={rounds} fds={fds} rss_kb={rss} "
                    f"threads={threads} tcp_ok={tcp_ok}/{tcp_total} udp_ok={udp_ok}/{udp_total}",
                    flush=True,
                )
                last_sample = now

        time.sleep(2.0)
        end_fds, end_rss, end_threads = sample(server.pid)
        print(
            f"final fds={end_fds} rss_kb={end_rss} threads={end_threads} "
            f"rounds={rounds} tcp_ok={tcp_ok}/{tcp_total} udp_ok={udp_ok}/{udp_total}",
            flush=True,
        )
        check("soak_tcp_integrity", tcp_ok == tcp_total, f"{tcp_ok}/{tcp_total}")
        check("soak_udp_integrity", udp_ok >= udp_total - max(1, udp_total // 100), f"{udp_ok}/{udp_total}")
        check("soak_fds_bounded", end_fds <= base_fds + 8, f"baseline={base_fds} final={end_fds}")
        check(
            "soak_rss_bounded",
            end_rss <= base_rss + 24 * 1024,
            f"baseline_kb={base_rss} final_kb={end_rss} growth_kb={end_rss - base_rss}",
        )
        check(
            "soak_threads_bounded",
            end_threads <= base_threads + 32,
            f"baseline={base_threads} final={end_threads}",
        )
        check("soak_server_alive", server.poll() is None, "running")
    finally:
        for proc in (client, server):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        tcp_echo.close()
        udp_echo.close()
        cover.close()
        server_log.close()
        client_log.close()
        if FAILURES:
            for name in ("beam.log",):
                path = out / name
                if path.exists():
                    print(f"--- {name} tail ---")
                    for line in path.read_text(errors="replace").splitlines()[-15:]:
                        print(f"  {line}")
    print("soak:", "PASS" if FAILURES == 0 else "FAIL")
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
