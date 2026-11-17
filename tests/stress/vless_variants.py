#!/usr/bin/env python3
"""Transport variants: Vision vs plain flow, xudp/packetaddr vs legacy VLESS UDP."""
from __future__ import annotations
import hashlib, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vless_client import (  # noqa: E402
    Echo, beam_fds, free_port, reality_public_key, socks5_connect,
    socks5_udp_associate, socks5_udp_send, wait_listen, write_client_config, write_server_config,
)

FAILURES = 0


def check(name, ok, detail):
    global FAILURES
    FAILURES += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)


class UdpTag:
    def __init__(self, tag):
        self.tag = tag
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(2048)
            except OSError:
                return
            try:
                self.sock.sendto(bytes([self.tag]) + data, peer)
            except OSError:
                return

    def close(self):
        self._stop.set()
        self.sock.close()


def udp_payload(reply: bytes) -> bytes:
    if len(reply) < 5:
        return b""
    atyp = reply[3]
    if atyp == 1:
        off = 10
    elif atyp == 4:
        off = 22
    elif atyp == 3:
        off = 4 + 1 + reply[4] + 2
    else:
        return b""
    return reply[off:]


def run_variant(label, beam, sing_box, repo, flow, encoding, template, pubkey):
    out = Path(tempfile.mkdtemp(prefix=f"var-{label}-"))
    cover_port = free_port()
    cover = socket.socket(); cover.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cover.bind(("127.0.0.1", cover_port)); cover.listen(32)
    port, socks_port = free_port(), free_port()
    write_server_config(out / "beam.toml", port, cover_port, template)
    write_client_config(out / "client.json", port, socks_port, pubkey, packet_encoding=encoding, flow=flow)
    sl = (out / "beam.log").open("wb")
    server = subprocess.Popen([str(beam), "-c", str(out / "beam.toml")], stdout=sl, stderr=subprocess.STDOUT)
    cl = (out / "client.log").open("wb")
    client = subprocess.Popen([str(sing_box), "run", "-c", str(out / "client.json")], stdout=cl, stderr=subprocess.STDOUT)
    tcp_echo = Echo("tcp")
    udp_echo = UdpTag(3)
    proxy = ("127.0.0.1", socks_port)
    try:
        wait_listen(port); wait_listen(socks_port, 15.0); time.sleep(0.4)
        payload = bytes((i * 13) % 256 for i in range(512 << 10))
        sock = socks5_connect(proxy, "127.0.0.1", tcp_echo.port, timeout=20.0)
        sock.settimeout(20.0)
        sock.sendall(payload)
        got = bytearray()
        while len(got) < len(payload):
            chunk = sock.recv(1 << 16)
            if not chunk:
                break
            got.extend(chunk)
        sock.close()
        check(f"{label}_tcp", bytes(got) == payload, f"bytes={len(got)}/{len(payload)}")

        control, (udp, relay) = socks5_udp_associate(proxy)
        good = 0
        for i in range(40):
            body = f"{label}-{i}".encode()
            socks5_udp_send(udp, relay, ("127.0.0.1", udp_echo.port), body)
            udp.settimeout(3.0)
            try:
                reply, _ = udp.recvfrom(2048)
            except socket.timeout:
                continue
            if udp_payload(reply)[1:] == body:
                good += 1
        udp.close(); control.close()
        check(f"{label}_udp", good == 40, f"echoed={good}/40 encoding={encoding or 'legacy'}")
        check(f"{label}_alive", server.poll() is None, "running")
        return server, client, tcp_echo, udp_echo, cover, sl, cl
    except Exception:
        for proc in (client, server):
            if proc.poll() is None:
                proc.kill()
        raise


def main() -> int:
    beam, sing_box = Path(sys.argv[1]), Path(sys.argv[2])
    repo = Path(".").resolve()
    template = repo / "config.example.toml"
    priv = next(l.split('"')[1] for l in template.read_text().splitlines() if l.startswith("private_key"))
    pubkey = reality_public_key(priv)
    for label, flow, encoding in (
        ("vision_xudp", "xtls-rprx-vision", "xudp"),
        ("vision_legacy", "xtls-rprx-vision", None),
        ("plain_xudp", "", "xudp"),
        ("plain_legacy", "", None),
    ):
        handles = None
        try:
            handles = run_variant(label, beam, sing_box, repo, flow, encoding, template, pubkey)
        except Exception as error:
            check(f"{label}_setup", False, str(error))
        finally:
            if handles:
                server, client, tcp_echo, udp_echo, cover, sl, cl = handles
                for proc in (client, server):
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                tcp_echo.close(); udp_echo.close(); cover.close(); sl.close(); cl.close()
    print("variants:", "PASS" if FAILURES == 0 else "FAIL")
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
