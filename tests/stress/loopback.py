#!/usr/bin/env python3
"""Loopback stress probes for the beam server.

These probes exercise the unauthenticated edges of the server without root,
network namespaces, TUN, or CPU pinning: per-source and global pre-auth
admission, the ClientHello deadline, fd/memory behavior under churn, and the
cover fallback (slot cap, slot release on client disconnect, refused cover).
They start their own server on 127.0.0.1 with reduced limits so the whole run
takes seconds, then assert the bounds the server promises.

The server config embeds the public placeholder key from
`config.example.toml`; it is only ever bound to loopback. Linux is required
because the probes bind source addresses in 127.0.0.0/8.

Usage:
    python3 tests/stress/loopback.py --beam target/release/beam
    python3 tests/stress/loopback.py --beam target/release/beam --out /tmp/stress

Exit status is non-zero if any check fails. `summary.json` and `summary.md`
are written to the output directory.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

MAX_CONNECTIONS = 256
MAX_PREAUTH_PER_IP = 8
HANDSHAKE_MS = 1000
DRAIN_MS = 2000
COVER_MAX_CONCURRENCY = 32
COVER_MAX_PER_IP = 8

CONFIG_TEMPLATE = """\
[server]
listen = "127.0.0.1:{port}"

[user]
id = "00000000-0000-0000-0000-000000000000"
flow = "xtls-rprx-vision"

[reality]
private_key = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo"
short_ids = ["0123456789abcdef"]
server_names = ["whatsapp.net"]
dest = "{cover}"

[log]
level = "debug"

[limits]
max_connections = {max_connections}
max_udp_destinations = 128
max_preauth_per_ip = {max_preauth_per_ip}
max_xudp_sessions = 64
xudp_recv_buffer_bytes = 131072
listen_backlog = 1024
shutdown_drain_ms = {drain_ms}
handshake_timeout_ms = {handshake_ms}
idle_timeout_ms = 5000
"""


class SilentCover:
    """A cover target that accepts connections and never reads or closes."""

    def __init__(self) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(128)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.held: list[socket.socket] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                self.held.append(conn)

    def accepted(self) -> int:
        with self._lock:
            return len(self.held)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1)
        with self._lock:
            for conn in self.held:
                try:
                    conn.close()
                except OSError:
                    pass
            self.held.clear()
        self.listener.close()


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def connect(port: int, src: str | None = None, timeout: float = 2.0) -> socket.socket:
    sock = socket.socket()
    if src is not None:
        sock.bind((src, 0))
    sock.settimeout(timeout)
    sock.connect(("127.0.0.1", port))
    return sock


def is_open(sock: socket.socket) -> bool:
    sock.setblocking(False)
    try:
        return sock.recv(1) != b""
    except BlockingIOError:
        return True
    except OSError:
        return False


def wait_closed(sock: socket.socket, limit: float) -> str:
    """Classify how a socket ends within an absolute deadline.

    Returns "timeout" if it is still open at the deadline, otherwise "eof"
    (FIN), "reset" (RST), or "data" when payload arrived before the close.
    The deadline is absolute: a peer that drips bytes cannot extend it.
    """
    deadline = time.monotonic() + limit
    saw_data = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "data" if saw_data else "timeout"
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return "data" if saw_data else "timeout"
        except ConnectionResetError:
            return "reset"
        except OSError:
            return "reset"
        if not chunk:
            return "data" if saw_data else "eof"
        saw_data = True


def close_all(socks: list[socket.socket]) -> None:
    for sock in socks:
        try:
            sock.close()
        except OSError:
            pass


def rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return -1


def fd_count(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return -1


class Server:
    def __init__(
        self,
        beam: Path,
        out: Path,
        name: str,
        cover: str,
        handshake_ms: int = HANDSHAKE_MS,
    ) -> None:
        self.name = name
        self.port = free_port()
        config = out / f"{name}.toml"
        config.write_text(
            CONFIG_TEMPLATE.format(
                port=self.port,
                cover=cover,
                max_connections=MAX_CONNECTIONS,
                max_preauth_per_ip=MAX_PREAUTH_PER_IP,
                drain_ms=DRAIN_MS,
                handshake_ms=handshake_ms,
            ),
            encoding="utf-8",
        )
        self.log_path = out / f"{name}.log"
        self.log = self.log_path.open("wb")
        self.proc = subprocess.Popen(
            [str(beam), "-c", str(config)],
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"{self.name} exited during startup; see {self.log_path}"
                )
            try:
                probe = connect(self.port, timeout=0.2)
                probe.close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"{self.name} did not listen on 127.0.0.1:{self.port}")

    @property
    def pid(self) -> int:
        return self.proc.pid

    def fds(self) -> int:
        return fd_count(self.pid)

    def rss(self) -> int:
        return rss_kb(self.pid)

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.log.close()


def check(results: list[dict], name: str, ok: bool, detail: str) -> None:
    results.append({"name": name, "ok": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")


def wait_for_slots(server: Server, expected: int, timeout_s: float = 2.0) -> int:
    """Return the first fd count at or below the expected cover-slot level."""
    deadline = time.time() + timeout_s
    last = server.fds()
    while time.time() < deadline:
        if last <= expected:
            return last
        time.sleep(0.05)
        last = server.fds()
    return last


def probe_basic(
    server: Server, cover: SilentCover, results: list[dict]
) -> None:
    port = server.port

    # 1. Per-source pre-auth cap.
    socks = []
    for _ in range(40):
        try:
            socks.append(connect(port))
        except OSError:
            break
    time.sleep(0.4)
    held = sum(1 for sock in socks if is_open(sock))
    check(
        results,
        "preauth_per_ip_cap",
        held == MAX_PREAUTH_PER_IP,
        f"{len(socks)} accepted, {held} held (cap {MAX_PREAUTH_PER_IP})",
    )
    close_all(socks)
    time.sleep(0.3)

    # 2. The pre-auth deadline bounds how long a probe may hold a slot: an
    #    idle probe closes, and a partial or trickled ClientHello is handed
    #    to the cover at the deadline instead of waiting for more bytes.
    idle = connect(port)
    t0 = time.monotonic()
    idle_state = wait_closed(idle, 3.0)
    idle_s = round(time.monotonic() - t0, 3)
    idle.close()
    check(
        results,
        "handshake_deadline_idle",
        idle_state in ("eof", "reset") and idle_s < 2.0,
        f"state={idle_state} after {idle_s}s",
    )

    before = cover.accepted()
    one = connect(port)
    one.sendall(b"\x16")
    t0 = time.time()
    while time.time() - t0 < 2.5 and cover.accepted() == before:
        time.sleep(0.05)
    one_handoff = cover.accepted() > before
    one_s = round(time.time() - t0, 3)
    one.close()
    check(
        results,
        "handshake_deadline_partial",
        one_handoff and one_s < 2.0,
        f"cover_handoff={one_handoff} after {one_s}s",
    )

    before = cover.accepted()
    trickle = connect(port)
    trickle.sendall(b"\x16\x03\x01\x40\x00")
    t0 = time.time()
    while time.time() - t0 < 3.0 and cover.accepted() == before:
        try:
            trickle.sendall(b"Z")
        except OSError:
            break
        time.sleep(0.2)
    trickle_handoff = cover.accepted() > before
    trickle_s = round(time.time() - t0, 3)
    trickle.close()
    check(
        results,
        "handshake_deadline_trickle",
        trickle_handoff and trickle_s < 2.5,
        f"cover_handoff={trickle_handoff} after {trickle_s}s",
    )
    time.sleep(0.3)

    # 3. RST churn must not leak descriptors.
    before = server.fds()
    accepted = 0
    for _ in range(2000):
        try:
            sock = connect(port)
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
            sock.close()
            accepted += 1
        except OSError:
            pass
    time.sleep(0.6)
    after = server.fds()
    check(
        results,
        "churn_fd_stable",
        server.proc.poll() is None and after <= before + 2,
        f"accepted={accepted} fds {before}->{after} rss={server.rss()}KiB",
    )


def probe_admission(beam: Path, out: Path, results: list[dict]) -> None:
    # 4. Global admission: fill every permit on a server whose pre-auth
    #    deadline (min(handshake, 5 s)) comfortably outlives this check, so a
    #    naturally expired holder cannot fake a released permit.
    server = Server(beam, out, "admission", "127.0.0.1:9", handshake_ms=10_000)
    holders: list[socket.socket] = []
    try:
        sources = MAX_CONNECTIONS // MAX_PREAUTH_PER_IP
        for index in range(sources):
            src = f"127.0.0.{index + 1}"
            for _ in range(MAX_PREAUTH_PER_IP + 2):
                try:
                    holders.append(connect(server.port, src))
                except OSError:
                    pass
        time.sleep(0.5)
        open_holders = [sock for sock in holders if is_open(sock)]
        full = len(open_holders) == MAX_CONNECTIONS
        rejected = False
        admitted = False
        still = 0
        if open_holders:
            fresh = connect(server.port, "127.0.0.250")
            rejected = wait_closed(fresh, 0.5) != "timeout"
            fresh.close()
            open_holders[0].close()
            time.sleep(0.3)
            retry = connect(server.port, "127.0.0.250")
            admitted = wait_closed(retry, 0.5) == "timeout"
            retry.close()
            still = sum(1 for sock in open_holders[1:] if is_open(sock))
        check(
            results,
            "admission_global_exhaustion",
            full
            and rejected
            and admitted
            and still >= len(open_holders) - 2,
            f"held={len(open_holders)}/{MAX_CONNECTIONS} "
            f"fresh_rejected={rejected} readmitted_after_release={admitted} "
            f"other_holders_open={still}",
        )
    finally:
        close_all(holders)
        server.stop()


def probe_cover(server: Server, cover: SilentCover, results: list[dict]) -> None:
    port = server.port
    baseline_fds = server.fds()

    # 5. Cover slot cap and the global-limit response.
    before_upstream = cover.accepted()
    holders: list[socket.socket] = []
    for index in range(COVER_MAX_CONCURRENCY // COVER_MAX_PER_IP):
        src = f"127.0.0.{index + 1}"
        for _ in range(COVER_MAX_PER_IP):
            sock = connect(port, src)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: stress\r\n\r\n")
            holders.append(sock)
    time.sleep(1.0)
    open_cover = sum(1 for sock in holders if is_open(sock))
    upstream = cover.accepted() - before_upstream
    check(
        results,
        "cover_slot_cap",
        open_cover == COVER_MAX_CONCURRENCY
        and upstream == COVER_MAX_CONCURRENCY,
        f"relays={open_cover} new_upstream={upstream} "
        f"cap={COVER_MAX_CONCURRENCY}",
    )

    limited = connect(port, "127.0.0.10")
    limited.sendall(b"GET / HTTP/1.1\r\nHost: stress\r\n\r\n")
    limited_state = wait_closed(limited, 0.5)
    limited_closed = limited_state != "timeout"
    limited.close()
    log = server.log_path.read_text(encoding="utf-8", errors="replace")
    limited_logged = "cover limit reached" in log
    check(
        results,
        "cover_limit_fingerprint",
        limited_closed and limited_logged,
        f"fresh_probe_closed={limited_closed} state={limited_state} "
        f"logged={limited_logged}",
    )

    # 6. Regression: slots are released when the probes disconnect, not at the
    #    30 s cover idle timeout. The replacement probe must reach cover, not
    #    merely stay open.
    close_all(holders)
    released_fds = wait_for_slots(server, baseline_fds + 2, timeout_s=3.0)
    before_accept = cover.accepted()
    after = connect(port, "127.0.0.11")
    after.sendall(b"GET / HTTP/1.1\r\nHost: stress\r\n\r\n")
    after_state = wait_closed(after, 0.5)
    forwarded = after_state == "timeout" and cover.accepted() > before_accept
    after.close()
    check(
        results,
        "cover_eof_release",
        released_fds <= baseline_fds + 2 and forwarded,
        f"fds {baseline_fds}->{released_fds} state={after_state} "
        f"new_probe_forwarded={forwarded}",
    )
    time.sleep(0.3)


def probe_refused_cover(beam: Path, out: Path, results: list[dict]) -> None:
    # 7. A refused cover dial must close the probe immediately.
    refused_port = free_port()
    server = Server(
        beam,
        out,
        "refused",
        f"127.0.0.1:{refused_port}",
    )
    try:
        baseline = server.fds()
        sock = connect(server.port)
        sock.sendall(b"GET / HTTP/1.1\r\nHost: stress\r\n\r\n")
        state = wait_closed(sock, 1.0)
        closed = state != "timeout"
        sock.close()
        time.sleep(0.3)
        after = server.fds()
        check(
            results,
            "cover_refused_closes",
            closed and after <= baseline + 1,
            f"closed={closed} state={state} fds {baseline}->{after}",
        )
    finally:
        server.stop()


def probe_shutdown(beam: Path, out: Path, results: list[dict]) -> None:
    # 8. Graceful shutdown under a full pre-auth pool: the drain deadline must
    #    close the pool before the 5 s pre-auth deadline expires, with a zero
    #    exit status. A server that exits instantly, ignores the drain, or
    #    crashes fails the bounds, the exit code, or the drain log check.
    server = Server(beam, out, "shutdown", "127.0.0.1:9", handshake_ms=10_000)
    holders: list[socket.socket] = []
    try:
        sources = MAX_CONNECTIONS // MAX_PREAUTH_PER_IP
        for index in range(sources):
            src = f"127.0.0.{index + 1}"
            for _ in range(MAX_PREAUTH_PER_IP + 2):
                try:
                    holders.append(connect(server.port, src))
                except OSError:
                    pass
        time.sleep(0.4)
        held = sum(1 for sock in holders if is_open(sock))
        t0 = time.monotonic()
        os.kill(server.pid, signal.SIGTERM)
        exited = None
        while time.monotonic() - t0 < DRAIN_MS / 1000 + 6:
            if server.proc.poll() is not None:
                exited = round(time.monotonic() - t0, 3)
                break
            time.sleep(0.05)
        states = [wait_closed(sock, 0.5) for sock in holders]
        gone = sum(1 for state in states if state != "timeout")
        log = server.log_path.read_text(encoding="utf-8", errors="replace")
        drain_logged = "shutdown drain deadline reached" in log
        preauth_logged = f"preauth_remaining={MAX_CONNECTIONS}" in log
        in_bounds = (
            exited is not None and 1.5 <= exited <= DRAIN_MS / 1000 + 1.0
        )
        check(
            results,
            "shutdown_drain",
            held == MAX_CONNECTIONS
            and server.proc.returncode == 0
            and in_bounds
            and gone == len(holders)
            and drain_logged
            and preauth_logged,
            f"held={held} exit={exited}s code={server.proc.returncode} "
            f"drain={DRAIN_MS}ms closed={gone}/{len(holders)} "
            f"drain_logged={drain_logged} preauth_logged={preauth_logged}",
        )
    finally:
        close_all(holders)
        server.stop()


def write_reports(out: Path, results: list[dict]) -> bool:
    ok = all(item["ok"] for item in results)
    summary = {
        "ok": ok,
        "checks": results,
        "limits": {
            "max_connections": MAX_CONNECTIONS,
            "max_preauth_per_ip": MAX_PREAUTH_PER_IP,
            "handshake_timeout_ms": HANDSHAKE_MS,
            "long_handshake_timeout_ms": 10_000,
            "shutdown_drain_ms": DRAIN_MS,
            "cover_max_concurrency": COVER_MAX_CONCURRENCY,
            "cover_max_per_ip": COVER_MAX_PER_IP,
        },
    }
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# Loopback stress probes",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for item in results:
        status = "PASS" if item["ok"] else "FAIL"
        detail = item["detail"].replace("|", "\\|")
        lines.append(f"| {item['name']} | {status} | {detail} |")
    lines.append("")
    lines.append("Result: **PASS**" if ok else "Result: **FAIL**")
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--beam", required=True, help="path to the beam binary")
    parser.add_argument(
        "--out",
        default=None,
        help="output directory (default: a temporary directory)",
    )
    args = parser.parse_args()

    beam = Path(args.beam).resolve()
    if not beam.is_file():
        print(f"beam binary not found: {beam}", file=sys.stderr)
        return 2
    if args.out is None:
        import tempfile

        out = Path(tempfile.mkdtemp(prefix="beam-stress-"))
    else:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    cover = SilentCover()
    server = Server(beam, out, "basic", f"127.0.0.1:{cover.port}")
    try:
        probe_basic(server, cover, results)
        probe_cover(server, cover, results)
    finally:
        server.stop()
        cover.close()
    probe_admission(beam, out, results)
    probe_refused_cover(beam, out, results)
    probe_shutdown(beam, out, results)

    ok = write_reports(out, results)
    print(f"summary: {out / 'summary.json'}")
    print("stress result:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
