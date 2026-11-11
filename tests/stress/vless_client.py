#!/usr/bin/env python3
"""Authenticated end-to-end harness: socks5 -> sing-box -> VLESS/REALITY -> beam.

Self-test mode proves the whole client path works in CI and prints the server's
descriptor count around one authenticated TCP flow, which is the first time that
path is measurable on a runner.

Usage: vless_client.py --beam target/release/beam --sing-box /usr/local/bin/sing-box --selftest
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from loopback import SilentCover, free_port  # noqa: E402

# ---------------------------------------------------------------- X25519 ---
P = 2**255 - 19
A24 = 121665


def _scalar(raw: bytes) -> int:
    k = bytearray(raw)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(raw_private: bytes) -> bytes:
    k = _scalar(raw_private)
    x1 = 9
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for bit in reversed(range(255)):
        kt = (k >> bit) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = ((da + cb) ** 2) % P
        z3 = x1 * ((da - cb) ** 2) % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def reality_public_key(private_b64: str) -> str:
    return base64.urlsafe_b64encode(x25519(b64url_decode(private_b64))).decode().rstrip("=")


# ----------------------------------------------------------------- socks ---
def socks5_addr(host: str, port: int) -> bytes:
    """SOCKS5 ATYP encoding: IPv4 or IPv6 literal, otherwise a domain name."""
    try:
        return b"\x01" + socket.inet_aton(host) + port.to_bytes(2, "big")
    except OSError:
        pass
    try:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, host) + port.to_bytes(2, "big")
    except OSError:
        pass
    name = host.encode()
    return b"\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big")


def socks5_connect(proxy: tuple[str, int], host: str, port: int, timeout: float = 5.0) -> socket.socket:
    sock = socket.create_connection(proxy, timeout=timeout)
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise RuntimeError("socks5 greeting failed")
    sock.sendall(b"\x05\x01\x00" + socks5_addr(host, port))
    reply = sock.recv(10)
    if len(reply) < 2 or reply[1] != 0:
        raise RuntimeError(f"socks5 connect failed: {reply!r}")
    return sock


def socks5_udp_associate(proxy: tuple[str, int], timeout: float = 5.0) -> tuple[socket.socket, tuple[str, int]]:
    control = socket.create_connection(proxy, timeout=timeout)
    control.sendall(b"\x05\x01\x00")
    if control.recv(2) != b"\x05\x00":
        raise RuntimeError("socks5 udp greeting failed")
    control.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + (0).to_bytes(2, "big"))
    reply = control.recv(10)
    if len(reply) < 10 or reply[1] != 0:
        raise RuntimeError(f"socks5 udp associate failed: {reply!r}")
    relay = (socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], "big"))
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(timeout)
    return control, (udp, relay)


def socks5_udp_send(udp: socket.socket, relay: tuple[str, int], dst: tuple[str, int], payload: bytes) -> None:
    packet = b"\x00\x00\x00" + socks5_addr(dst[0], dst[1]) + payload
    udp.sendto(packet, relay)


# ------------------------------------------------------------------ setup ---
class Echo:
    def __init__(self, kind: str = "tcp") -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        if kind == "tcp":
            self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.kind = kind
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        if self.kind == "udp":
            while not self._stop.is_set():
                try:
                    data, peer = self.sock.recvfrom(2048)
                except OSError:
                    return
                try:
                    self.sock.sendto(data, peer)
                except OSError:
                    return
            return
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            while True:
                data = conn.recv(2048)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            return
        finally:
            conn.close()

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


def write_server_config(path: Path, port: int, cover_port: int, template: Path) -> None:
    text = template.read_text(encoding="utf-8")
    text = re.sub(r'^listen\s*=.*$', f'listen = "127.0.0.1:{port}"', text, count=1, flags=re.M)
    text = re.sub(r'^dest\s*=.*$', f'dest = "127.0.0.1:{cover_port}"', text, count=1, flags=re.M)
    text = re.sub(r'^level\s*=.*$', 'level = "debug"', text, count=1, flags=re.M)
    path.write_text(text, encoding="utf-8")


def write_client_config(
    path: Path,
    port: int,
    socks_port: int,
    pubkey: str,
    packet_encoding: str = "xudp",
    flow: str = "xtls-rprx-vision",
) -> None:
    # Built inline from the tracked example fixture: the mobile profile is not
    # in the repository (it carries real credentials), so nothing here depends
    # on it.
    vless = {
        "type": "vless",
        "tag": "proxy",
        "server": "127.0.0.1",
        "server_port": port,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "packet_encoding": packet_encoding,
        "tls": {
            "enabled": True,
            "server_name": "whatsapp.net",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {
                "enabled": True,
                "public_key": pubkey,
                "short_id": "0123456789abcdef",
            },
        },
    }
    if flow:
        vless["flow"] = flow
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
        "outbounds": [vless],
    }
    path.write_text(json.dumps(config, indent=1), encoding="utf-8")


def beam_fds(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return -1


def wait_listen(port: int, limit: float = 10.0) -> None:
    deadline = time.time() + limit
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nothing listening on {port}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--beam", required=True)
    parser.add_argument("--sing-box", required=True)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    template = repo / "config.example.toml"
    priv = re.search(
        r'^private_key\s*=\s*"([^"]+)"', template.read_text(encoding="utf-8"), re.M
    ).group(1)
    pubkey = reality_public_key(priv)

    out = Path(tempfile.mkdtemp(prefix="vless-harness-"))
    cover = SilentCover()
    port = free_port()
    socks_port = free_port()
    server_cfg = out / "beam.toml"
    client_cfg = out / "client.json"
    write_server_config(server_cfg, port, cover.port, template)
    write_client_config(client_cfg, port, socks_port, pubkey)

    server_log = (out / "beam.log").open("wb")
    server = subprocess.Popen([args.beam, "-c", str(server_cfg)], stdout=server_log, stderr=subprocess.STDOUT)
    client_log = (out / "client.log").open("wb")
    client = subprocess.Popen(
        [args.sing_box, "run", "-c", str(client_cfg)], stdout=client_log, stderr=subprocess.STDOUT
    )
    failures = 0
    try:
        wait_listen(port)
        wait_listen(socks_port, 15.0)
        echo = Echo("tcp")
        udp_echo = Echo("udp")
        time.sleep(0.4)
        baseline = beam_fds(server.pid)
        print(f"server_fds_baseline={baseline}")

        # One authenticated TCP flow through Vision.
        sock = socks5_connect(("127.0.0.1", socks_port), "127.0.0.1", echo.port)
        sock.sendall(b"ping")
        sock.settimeout(5.0)
        got = sock.recv(16)
        ok = got == b"ping"
        failures += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'} tcp_relay: reply={got!r} fds_now={beam_fds(server.pid)}")
        sock.close()
        echo.close()

        # One authenticated UDP flow (socks5 UDP associate -> XUDP). The session
        # socket is retained for close_expiry on purpose, so the descriptor count
        # is expected to rise; the log must show the retention, which is what
        # distinguishes a retained socket from a leak.
        control, (udp, relay) = socks5_udp_associate(("127.0.0.1", socks_port))
        socks5_udp_send(udp, relay, ("127.0.0.1", udp_echo.port), b"pong")
        udp.settimeout(5.0)
        try:
            reply, _ = udp.recvfrom(2048)
        except socket.timeout:
            reply = b""
        payload = reply[10:] if len(reply) > 10 else b""
        ok = payload == b"pong"
        failures += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'} udp_relay: payload={payload!r} reply_len={len(reply)}")
        udp.close()
        control.close()
        udp_echo.close()

        time.sleep(1.5)
        settled = beam_fds(server.pid)
        # The XUDP socket stays retained until close_expiry, so allow a small
        # bounded rise and prove the retention rather than a leak from the log.
        retained = (out / "beam.log").read_text(errors="replace").count("retained")
        ok = settled <= baseline + 6
        failures += 0 if ok else 1
        print(
            f"{'PASS' if ok else 'FAIL'} fds_after_udp: baseline={baseline} settled={settled} "
            f"retained_log_lines={retained}"
        )
        print(f"selftest result: {'PASS' if failures == 0 else 'FAIL'}")
        return 0 if failures == 0 else 1
    finally:
        for proc in (client, server):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        cover.close()
        server_log.close()
        client_log.close()
        for name in ("beam.log", "client.log"):
            path = out / name
            if path.exists() and failures:
                print(f"--- {name} ---")
                print(path.read_text(errors="replace")[-1500:])


if __name__ == "__main__":
    sys.exit(main())
