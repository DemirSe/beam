#!/usr/bin/env python3
"""IPv6 destinations through both datagram encodings and the TCP relay."""
from __future__ import annotations
import hashlib, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vless_client import (  # noqa: E402
    beam_fds, free_port, reality_public_key, socks5_connect, socks5_udp_associate,
    socks5_udp_send, wait_listen, write_client_config, write_server_config,
)

FAILURES = 0


def check(name, ok, detail):
    global FAILURES
    FAILURES += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)


class V6Echo:
    def __init__(self, kind="udp", tag=11):
        self.kind = kind
        self.tag = tag
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("::1", 0))
        if kind != "udp":
            self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        if self.kind == "udp":
            while not self._stop.is_set():
                try:
                    data, peer = self.sock.recvfrom(2048)
                except OSError:
                    return
                try:
                    self.sock.sendto(bytes([self.tag]) + data, peer)
                except OSError:
                    return
        else:
            while not self._stop.is_set():
                try:
                    conn, _ = self.sock.accept()
                except OSError:
                    return
                threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            return

    def close(self):
        self._stop.set()
        self.sock.close()


def udp_payload(reply: bytes) -> bytes:
    if len(reply) < 5:
        return b""
    atyp = reply[3]
    off = 10 if atyp == 1 else 22 if atyp == 4 else 4 + 1 + reply[4] + 2 if atyp == 3 else 0
    return reply[off:] if off else b""


def main() -> int:
    beam, sing_box = Path(sys.argv[1]), Path(sys.argv[2])
    repo = Path(".").resolve()
    template = repo / "config.example.toml"
    priv = next(l.split('"')[1] for l in template.read_text().splitlines() if l.startswith("private_key"))
    pubkey = reality_public_key(priv)
    for encoding in ("xudp", "packetaddr"):
        out = Path(tempfile.mkdtemp(prefix=f"ipv6-{encoding}-"))
        cover_port = free_port()
        cover = socket.socket(); cover.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cover.bind(("127.0.0.1", cover_port)); cover.listen(32)
        port, socks_port = free_port(), free_port()
        write_server_config(out / "beam.toml", port, cover_port, template)
        write_client_config(out / "client.json", port, socks_port, pubkey, packet_encoding=encoding)
        sl = (out / "beam.log").open("wb")
        server = subprocess.Popen([str(beam), "-c", str(out / "beam.toml")], stdout=sl, stderr=subprocess.STDOUT)
        cl = (out / "client.log").open("wb")
        client = subprocess.Popen([str(sing_box), "run", "-c", str(out / "client.json")], stdout=cl, stderr=subprocess.STDOUT)
        tcp6 = V6Echo("tcp")
        udp6 = V6Echo("udp")
        try:
            wait_listen(port); wait_listen(socks_port, 15.0); time.sleep(0.4)
            proxy = ("127.0.0.1", socks_port)
            payload = bytes((i * 11) % 256 for i in range(64 << 10))
            sock = socks5_connect(proxy, "::1", tcp6.port, timeout=15.0)
            sock.settimeout(15.0)
            sock.sendall(payload)
            got = bytearray()
            while len(got) < len(payload):
                chunk = sock.recv(1 << 16)
                if not chunk:
                    break
                got.extend(chunk)
            sock.close()
            check(f"{encoding}_tcp_v6", bytes(got) == payload, f"bytes={len(got)}/{len(payload)}")

            control, (udp, relay) = socks5_udp_associate(proxy)
            good = 0
            for i in range(30):
                body = f"v6-{i}".encode()
                socks5_udp_send(udp, relay, ("::1", udp6.port), body)
                udp.settimeout(3.0)
                try:
                    reply, _ = udp.recvfrom(2048)
                except socket.timeout:
                    continue
                if udp_payload(reply)[1:] == body:
                    good += 1
            udp.close(); control.close()
            check(f"{encoding}_udp_v6", good == 30, f"echoed={good}/30")
            check(f"{encoding}_alive", server.poll() is None, "running")
        finally:
            for proc in (client, server):
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            tcp6.close(); udp6.close(); cover.close(); sl.close(); cl.close()
            if FAILURES:
                for name in ("beam.log", "client.log"):
                    path = out / name
                    if path.exists():
                        print(f"--- {name} tail ---")
                        for line in path.read_text(errors="replace").splitlines()[-10:]:
                            print(f"  {line}")
    print("ipv6:", "PASS" if FAILURES == 0 else "FAIL")
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
