#!/usr/bin/env python3
"""Target-initiated half-close: the destination sends, shuts its write side, and
keeps reading. The client must see that data plus EOF, and its later writes must
still reach the destination.

This isolates beam's relay from the client's own half-close support, which
sing-box handles by resetting the stream.
"""
from __future__ import annotations
import socket, sys, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vless_client import (  # noqa: E402
    free_port, reality_public_key, socks5_connect, wait_listen, write_client_config, write_server_config,
)

import subprocess, tempfile

FAILURES = 0


def check(name: str, ok: bool, detail: str) -> None:
    global FAILURES
    FAILURES += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)


def main() -> int:
    beam, sing_box = Path(sys.argv[1]), Path(sys.argv[2])
    repo = Path(".").resolve()
    template = repo / "config.example.toml"
    priv = next(l.split('"')[1] for l in template.read_text().splitlines() if l.startswith("private_key"))
    pubkey = reality_public_key(priv)
    out = Path(tempfile.mkdtemp(prefix="half-"))
    cover_port = free_port()
    cover = socket.socket(); cover.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cover.bind(("127.0.0.1", cover_port)); cover.listen(32)
    port, socks_port = free_port(), free_port()
    write_server_config(out / "beam.toml", port, cover_port, template)
    write_client_config(out / "client.json", port, socks_port, pubkey)
    sl = (out / "beam.log").open("wb")
    server = subprocess.Popen([str(beam), "-c", str(out / "beam.toml")], stdout=sl, stderr=subprocess.STDOUT)
    cl = (out / "client.log").open("wb")
    client = subprocess.Popen([str(sing_box), "run", "-c", str(out / "client.json")], stdout=cl, stderr=subprocess.STDOUT)

    target = socket.socket(); target.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    target.bind(("127.0.0.1", 0)); target.listen(4)
    target_port = target.getsockname()[1]
    received = {}

    def serve() -> None:
        conn, _ = target.accept()
        conn.sendall(b"greeting-before-fin")
        conn.shutdown(socket.SHUT_WR)
        body = bytearray()
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body.extend(chunk)
        except OSError as error:
            received["error"] = str(error)
        received["body"] = bytes(body)
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    try:
        wait_listen(port)
        wait_listen(socks_port, 15.0)
        time.sleep(0.4)
        sock = socks5_connect(("127.0.0.1", socks_port), "127.0.0.1", target_port, timeout=15.0)
        sock.settimeout(10.0)
        got = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            got.extend(chunk)
        check("target_fin_delivers_data", bytes(got) == b"greeting-before-fin", f"got={bytes(got)!r}")
        time.sleep(0.2)
        try:
            sock.sendall(b"client-after-target-fin")
            sent = True
        except OSError as error:
            sent = False
            received["send_error"] = str(error)
        check("client_can_write_after_target_fin", sent, f"sent={sent}")
        sock.close()
        time.sleep(0.5)
        body = received.get("body", b"")
        check("target_receives_post_fin_bytes", body == b"client-after-target-fin", f"body={body!r} recv_err={received.get('error')}")
        check("server_alive", server.poll() is None, "running")
    finally:
        for proc in (client, server):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        target.close(); cover.close(); sl.close(); cl.close()
        if FAILURES:
            for name in ("beam.log", "client.log"):
                path = out / name
                if path.exists():
                    print(f"--- {name} tail ---")
                    for line in path.read_text(errors="replace").splitlines()[-10:]:
                        print(f"  {line}")
    print("halfclose:", "PASS" if FAILURES == 0 else "FAIL")
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
