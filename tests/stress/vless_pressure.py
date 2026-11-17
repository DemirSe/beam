#!/usr/bin/env python3
"""Pressure campaign: session-limit saturation and a datagram blast."""
from __future__ import annotations
import re, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vless_client import (  # noqa: E402
    beam_fds, free_port, reality_public_key, socks5_connect, socks5_udp_associate,
    socks5_udp_send, wait_listen, write_client_config,
)

FAILURES = 0


def check(name, ok, detail):
    global FAILURES
    FAILURES += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)


def server_config(path: Path, template: Path, port: int, cover_port: int, max_sessions: int) -> None:
    text = template.read_text(encoding="utf-8")
    text = re.sub(r'^listen\s*=.*$', f'listen = "127.0.0.1:{port}"', text, count=1, flags=re.M)
    text = re.sub(r'^dest\s*=.*$', f'dest = "127.0.0.1:{cover_port}"', text, count=1, flags=re.M)
    text = re.sub(r'^level\s*=.*$', 'level = "debug"', text, count=1, flags=re.M)
    text = re.sub(r'^max_udp_destinations\s*=.*$', f"max_udp_destinations = {max_sessions}", text, count=1, flags=re.M)
    path.write_text(text, encoding="utf-8")


class Sink:
    """UDP sink that never replies, to force queue pressure."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.count = 0
        self._stop = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.sock.recvfrom(65536)
            except OSError:
                return
            self.count += 1

    def close(self):
        self._stop.set()
        self.sock.close()


def echo_udp() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def run():
        while True:
            try:
                data, peer = sock.recvfrom(2048)
            except OSError:
                return
            try:
                sock.sendto(b"E" + data, peer)
            except OSError:
                return

    threading.Thread(target=run, daemon=True).start()
    return sock, port


def main() -> int:
    beam, sing_box = Path(sys.argv[1]), Path(sys.argv[2])
    repo = Path(".").resolve()
    template = repo / "config.example.toml"
    priv = next(l.split('"')[1] for l in template.read_text().splitlines() if l.startswith("private_key"))
    pubkey = reality_public_key(priv)
    out = Path(tempfile.mkdtemp(prefix="pressure-"))
    cover_port = free_port()
    cover = socket.socket(); cover.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cover.bind(("127.0.0.1", cover_port)); cover.listen(32)
    port, socks_port = free_port(), free_port()
    server_config(out / "beam.toml", template, port, cover_port, max_sessions=3)
    write_client_config(out / "client.json", port, socks_port, pubkey)
    sl = (out / "beam.log").open("wb")
    server = subprocess.Popen([str(beam), "-c", str(out / "beam.toml")], stdout=sl, stderr=subprocess.STDOUT)
    cl = (out / "client.log").open("wb")
    client = subprocess.Popen([str(sing_box), "run", "-c", str(out / "client.json")], stdout=cl, stderr=subprocess.STDOUT)
    sink = Sink()
    echo_sock, echo_port = echo_udp()
    try:
        wait_listen(port); wait_listen(socks_port, 15.0); time.sleep(0.4)
        proxy = ("127.0.0.1", socks_port)
        base = beam_fds(server.pid)

        # A. Session saturation: eight flows against a three-session limit.
        flows = []
        for _ in range(8):
            try:
                flows.append(socks5_udp_associate(proxy))
            except OSError:
                flows.append(None)
        time.sleep(1.0)
        alive_after_saturation = server.poll() is None
        check("limit_saturation_survives", alive_after_saturation, f"flows={sum(1 for f in flows if f)}")
        for entry in flows:
            if entry:
                control, (udp, _relay) = entry
                udp.close(); control.close()
        time.sleep(1.0)

        # New flows must work again after the limit was hit.
        control, (udp, relay) = socks5_udp_associate(proxy)
        socks5_udp_send(udp, relay, ("127.0.0.1", echo_port), b"after-limit")
        udp.settimeout(4.0)
        try:
            reply, _ = udp.recvfrom(2048)
            body = reply[10:] if len(reply) > 10 else b""
        except socket.timeout:
            body = b""
        check("flow_after_limit", body == b"Eafter-limit", f"reply={body!r}")

        # B. Datagram blast at an unresponsive sink: 4000 x 8 KiB as fast as possible.
        blast = bytes([7]) * 8192
        sent = 0
        started = time.time()
        for _ in range(4000):
            try:
                socks5_udp_send(udp, relay, ("127.0.0.1", sink.port), blast)
                sent += 1
            except OSError:
                break
        elapsed = time.time() - started
        time.sleep(1.5)
        # The periodic counter line is emitted at most once a minute, so wait
        # for it: this is the only end-to-end proof that the new drop counter
        # reaches an operator.
        log_text = (out / "beam.log").read_text(errors="replace")
        deadline = time.time() + 130
        while time.time() < deadline and "xudp_send_dropped=" not in log_text:
            time.sleep(5)
            log_text = (out / "beam.log").read_text(errors="replace")
        dropped = re.findall(r"xudp_send_dropped=(\d+)", log_text)
        after = beam_fds(server.pid)
        check("blast_stayed_up", server.poll() is None, f"sent={sent} elapsed_s={elapsed:.1f} sink_got={sink.count}")
        check("blast_fds_bounded", after <= base + 8, f"baseline={base} after={after}")
        check(
            "blast_drop_counter_visible",
            bool(dropped),
            f"send_dropped_lines={dropped[:3]} counter_logged={bool(dropped)}",
        )
        udp.close(); control.close()

        # C. The tunnel still serves after the blast.
        control, (udp, relay) = socks5_udp_associate(proxy)
        socks5_udp_send(udp, relay, ("127.0.0.1", echo_port), b"still-there")
        udp.settimeout(4.0)
        try:
            reply, _ = udp.recvfrom(2048)
            body = reply[10:] if len(reply) > 10 else b""
        except socket.timeout:
            body = b""
        check("alive_after_blast", body == b"Estill-there", f"reply={body!r}")
        udp.close(); control.close()
    finally:
        for proc in (client, server):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        sink.close(); echo_sock.close(); cover.close(); sl.close(); cl.close()
        if FAILURES:
            for name in ("beam.log", "client.log"):
                path = out / name
                if path.exists():
                    print(f"--- {name} tail ---")
                    for line in path.read_text(errors="replace").splitlines()[-12:]:
                        print(f"  {line}")
    print("pressure:", "PASS" if FAILURES == 0 else "FAIL")
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
