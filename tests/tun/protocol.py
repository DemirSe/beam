#!/usr/bin/env python3
"""Client-side protocol cases for the full-TUN harness.

One subcommand per case. Every case writes one JSON object to ``--out`` and
exits 0 only when the case is a correctness pass. ``status`` is ``FAIL`` when a
correctness contract is broken, ``WARN`` when correctness holds but a metric
budget is missed, and ``PASS`` otherwise. A metric row without a budget is
``INFO`` in the human report and still reports ``PASS`` here.

The JSON contract consumed by ``protocol_report.py`` is::

    {
      "name": str,                 # report key, identical to the subcommand
      "status": "PASS|WARN|FAIL",
      "correctness": bool,
      "ok": bool,                  # same as correctness; the harness exit gate
      "planned": int,
      "completed": int,
      "deadline_ms": int,
      "started": float,            # epoch seconds
      "ended": float,
      "metrics": {...},
      "warnings": [str],
      "detail": str,
      "samples": [float]           # optional raw samples for percentiles
    }

All percentiles use the nearest-rank method on the raw sample list. UDP loss
uses sent unique sequences as the denominator and drains late packets for two
seconds after the last send.

This is test-only code; it never reaches an external network.
"""

from __future__ import annotations

import argparse
import enum
import hashlib
import http.client
import json
import math
import os
import re
import select
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

MARKER_H3 = b"beam-tun-h3-ok\n"
MARKER_HTTP = b"beam-tun-ok\n"
UDP_HEADER = 4


class Outcome(enum.Enum):
    """Explicit result of one unit of mixed-case work.

    OK and INVALID units completed; INVALID also counts a correctness failure.
    INCOMPLETE units (lost reply, refused flow, deadline) lower the completion
    ratio and are never counted as invalid.
    """

    OK = "ok"
    INVALID = "invalid"
    INCOMPLETE = "incomplete"


def apply_outcome(counts: dict[str, int], key: str, outcome: Outcome) -> None:
    """Apply one unit outcome to a counter map; the caller holds the lock.

    OK and INVALID units completed; INVALID also increments the matching
    ``<class>_invalid`` counter. INCOMPLETE units are not completed.
    """
    if outcome is Outcome.INCOMPLETE:
        return
    counts[key] += 1
    if outcome is Outcome.INVALID:
        counts[key.replace("_completed", "_invalid")] += 1


def tcp_unit_outcome(result: dict) -> Outcome:
    """Classify one echo transfer.

    A complete echo with wrong bytes is INVALID; an error, timeout or early
    close is INCOMPLETE because the transfer never produced a verdict.
    """
    if result.get("ok"):
        return Outcome.OK
    return Outcome.INCOMPLETE if result.get("errors") else Outcome.INVALID


def sequence_outcomes(
    sent: dict[int, bytes], verified: set[int], corrupt: set[int]
) -> list[Outcome]:
    """Per-sequence UDP outcomes: corrupt, verified, or unanswered.

    Corruption is sticky: a sequence that ever produced a wrong payload stays
    INVALID even if a correct reply also arrives, in either order. The sets are
    order-free, so arrival order cannot change the outcome.
    """
    return [
        Outcome.INVALID
        if sequence in corrupt
        else Outcome.OK
        if sequence in verified
        else Outcome.INCOMPLETE
        for sequence in sent
    ]


def note_reply(
    sent: dict[int, bytes],
    verified: set[int],
    corrupt: set[int],
    sequence: int,
    data: bytes,
) -> None:
    """Record one inbound datagram for a sent sequence.

    The sets are order-free, so a corrupt reply before or after a valid one
    leaves the same evidence: the sequence is corrupt.
    """
    if sent.get(sequence) == data:
        verified.add(sequence)
    elif sequence in sent:
        corrupt.add(sequence)


def mixed_verdict(counts: dict, duration: int) -> tuple[bool, dict]:
    """The mixed case's correctness gate and its derived counters.

    A unit that never reported lowers the completion ratio; a unit that reported
    wrong bytes fails correctness. The floors keep a silent path from passing on
    an empty or partially working class.
    """
    planned = (
        counts["h1_attempted"]
        + counts["udp_sent"]
        + counts["dns_planned"]
        + counts["tcp_planned"]
    )
    completed = (
        counts["h1_completed"]
        + counts["udp_completed"]
        + counts["dns_completed"]
        + counts["tcp_completed"]
    )
    invalid = (
        counts["h1_invalid"]
        + counts["h2_invalid"]
        + counts["udp_invalid"]
        + counts["dns_invalid"]
        + counts["tcp_invalid"]
    )
    ratio = completed / planned if planned else 1.0
    h1_floor = 4 * duration
    ok = (
        invalid == 0
        and ratio >= 0.95
        and counts["tcp_completed"] >= 1
        and counts["h1_completed"] >= h1_floor
        and counts["udp_completed"] >= 0.95 * counts["udp_sent"]
    )
    return ok, {
        "planned": planned,
        "completed": completed,
        "completion_ratio": round(ratio, 4),
        "invalid": invalid,
        "h1_floor": h1_floor,
    }


def log(message: str) -> None:
    print(f"protocol: {message}", file=sys.stderr, flush=True)


def split_addr(value: str) -> tuple[str, int]:
    host, port = value.rsplit(":", 1)
    return host.strip("[]"), int(port)


def family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def expected_body(size: int, marker: bytes = MARKER_H3) -> bytes:
    repeats = (size + len(marker) - 1) // len(marker)
    return (marker * repeats)[:size]


def nearest_rank(samples: list[float], percentile: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    rank = math.ceil(percentile / 100.0 * len(ordered))
    return ordered[min(max(rank - 1, 0), len(ordered) - 1)]


def emit(
    args,
    name: str,
    ok: bool,
    detail: str,
    metrics: dict,
    *,
    warnings: list[str] | None = None,
    planned: int = 1,
    completed: int = 1,
    deadline_ms: int = 0,
    started: float | None = None,
    ended: float | None = None,
    samples: list[float] | None = None,
) -> int:
    warnings = list(warnings or [])
    status = "FAIL" if not ok else ("WARN" if warnings else "PASS")
    payload = {
        "name": name,
        "status": status,
        "correctness": bool(ok),
        "ok": bool(ok),
        "planned": planned,
        "completed": completed,
        "deadline_ms": int(deadline_ms),
        "started": round(started if started is not None else time.time(), 3),
        "ended": round(ended if ended is not None else time.time(), 3),
        "metrics": metrics,
        "warnings": warnings,
        "detail": detail,
    }
    if samples:
        payload["samples"] = [round(value, 4) for value in samples]
    text = json.dumps(payload, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text, flush=True)
    if not ok:
        log(f"{name} FAIL: {detail}")
    return 0 if ok else 1


def recv_exact(sock: socket.socket, size: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks = bytearray()
    while len(chunks) < size:
        data = sock.recv(size - len(chunks))
        if not data:
            raise ConnectionError(f"connection closed after {len(chunks)} of {size} bytes")
        chunks.extend(data)
    return bytes(chunks)


def origin_stats(path: str | None, offset: int | None, label: str) -> tuple[int, int] | None:
    """Connection count and peak concurrent requests the origin logged."""
    if not path or not os.path.exists(path):
        return None
    with open(path, "rb") as handle:
        handle.seek(offset or 0)
        text = handle.read().decode("utf-8", "replace")
    connections = len(re.findall(rf"{re.escape(label)}: connection conn=", text))
    peak = 0
    for match in re.finditer(r"active=(\d+)", text):
        peak = max(peak, int(match.group(1)))
    return connections, peak


# ---------------------------------------------------------------------------
# HTTP/2 and HTTP/3 origins
# ---------------------------------------------------------------------------


def _curl_run(args, extra: list[str], timeout: float) -> subprocess.CompletedProcess:
    command = [args.curl, "-sS", "-k", "--noproxy", "*", *extra]
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def _bulk(args, version: str) -> int:
    name = "h2-bulk-8m" if version == "2" else "h3-bulk-8m"
    started = time.time()
    # A 1% loss link stretched the 8 MiB transfer to ~85 s; the transfer
    # deadline must not be the thing that fails the case.
    timeout_s = 180.0
    url = f"https://{args.https}/?bytes={args.bytes}"
    flag = "--http2" if version == "2" else "--http3-only"
    with tempfile.NamedTemporaryFile(prefix="protocol-bulk-", delete=False) as handle:
        body_path = handle.name
    try:
        proc = _curl_run(
            args,
            [
                flag,
                "--max-time",
                str(int(timeout_s)),
                "-o",
                body_path,
                "-w",
                "%{http_code} %{http_version} %{time_starttransfer} %{time_total} %{size_download}",
                url,
            ],
            timeout_s + 30,
        )
        fields = proc.stdout.split()
        metrics: dict = {"bytes": args.bytes, "http_version": version}
        if proc.returncode != 0 or len(fields) != 5:
            error = (proc.stderr or proc.stdout or "no output").strip().replace("\n", " ")
            return emit(
                args,
                name,
                False,
                f"curl failed rc={proc.returncode}: {error[:200]}",
                metrics,
                deadline_ms=int(timeout_s * 1000),
                started=started,
            )
        code, reported_version, ttfb, total, downloaded = fields
        ttfb_ms = float(ttfb) * 1000.0
        total_ms = float(total) * 1000.0
        with open(body_path, "rb") as handle:
            body = handle.read()
        digest_ok = hashlib.sha256(body).digest() == hashlib.sha256(
            expected_body(args.bytes)
        ).digest()
        metrics.update(
            {
                "http_code": int(code),
                "ttfb_ms": round(ttfb_ms, 3),
                "total_ms": round(total_ms, 3),
                "size_download": int(downloaded),
                "sha256_ok": digest_ok,
                "reported_version": reported_version,
            }
        )
        ok = (
            code == "200"
            and reported_version == version
            and int(downloaded) == args.bytes
            and len(body) == args.bytes
            and digest_ok
        )
        detail = (
            f"HTTP/{reported_version} {code} {len(body)} B sha256_ok={digest_ok} "
            f"ttfb={ttfb_ms:.1f}ms total={total_ms:.1f}ms"
        )
        return emit(
            args,
            name,
            ok,
            detail if ok else f"{detail} (wanted HTTP/{version} 200 {args.bytes} B)",
            metrics,
            deadline_ms=int(timeout_s * 1000),
            started=started,
        )
    finally:
        try:
            os.unlink(body_path)
        except OSError:
            pass


def case_h2_bulk(args) -> int:
    return _bulk(args, "2")


def case_h3_bulk(args) -> int:
    return _bulk(args, "3")


def case_h2_multiplex(args) -> int:
    """Wraps the deterministic Rust h2-client result into a report case."""
    started = time.time()
    try:
        with open(args.client, encoding="utf-8") as handle:
            client = json.load(handle)
    except (OSError, ValueError) as error:
        return emit(
            args,
            "h2-multiplex-16",
            False,
            f"could not read the h2-client result {args.client}: {error}",
            {"streams": args.streams},
        )
    metrics = {
        "connections": client.get("connections"),
        "streams": client.get("streams"),
        "completed": client.get("completed"),
        "peak_active": client.get("peak_active"),
        "bytes": client.get("bytes"),
        "hash_ok": client.get("hash_ok"),
        "ttfb_ms": client.get("ttfb_ms"),
        "total_ms": client.get("total_ms"),
    }
    warnings: list[str] = []
    problems: list[str] = []
    if client.get("errors"):
        problems.append(f"client errors: {client['errors']}")
    if client.get("connections") != 1:
        problems.append(f"client opened {client.get('connections')} connections, wanted 1")
    if client.get("streams") != args.streams:
        problems.append(f"client ran {client.get('streams')} streams, wanted {args.streams}")
    if client.get("completed") != args.streams:
        problems.append(f"only {client.get('completed')} of {args.streams} streams completed")
    if not client.get("hash_ok"):
        problems.append("at least one body differed from the marker")

    origin = origin_stats(args.origin_log, args.origin_offset, "h2-origin")
    if origin is None:
        warnings.append("origin log unavailable; server-side multiplexing unverified")
    else:
        connections, peak = origin
        metrics["origin_connections"] = connections
        metrics["origin_peak_active"] = peak
        if connections != 1:
            problems.append(f"origin saw {connections} HTTP/2 connections, wanted 1")
        if peak < args.min_peak:
            warnings.append(f"origin peak_active {peak} < {args.min_peak}")
    if (client.get("peak_active") or 0) < args.min_peak:
        warnings.append(f"client peak_active {client.get('peak_active')} < {args.min_peak}")

    ok = not problems
    detail = (
        f"connections={metrics['connections']} streams={metrics['completed']} "
        f"peak_active={metrics['peak_active']} bytes={metrics['bytes']} "
        f"hash_ok={metrics['hash_ok']}"
    )
    if origin is not None:
        detail += f" origin=({metrics['origin_connections']} conns, peak {metrics['origin_peak_active']})"
    if problems:
        detail += "; " + "; ".join(problems)
    return emit(
        args,
        "h2-multiplex-16",
        ok,
        detail,
        metrics,
        warnings=warnings,
        planned=args.streams,
        completed=client.get("completed") or 0,
        deadline_ms=120_000,
        started=started,
    )


def case_h3_concurrent(args) -> int:
    started = time.time()
    timeout_s = 120.0
    url = f"https://{args.https}/?bytes={args.bytes}"
    files: list[str] = []
    command = [
        args.curl,
        "-sS",
        "-k",
        "--noproxy",
        "*",
        "--http3-only",
        "--parallel",
        "--parallel-max",
        str(args.streams),
        "--parallel-max-host",
        "1",
        "--max-time",
        str(int(timeout_s)),
        "-w",
        "%{http_code} %{http_version}\n",
    ]
    for _ in range(args.streams):
        handle = tempfile.NamedTemporaryFile(prefix="protocol-h3-par-", delete=False)
        handle.close()
        files.append(handle.name)
        command += ["-o", handle.name, url]
    metrics: dict = {"planned": args.streams, "bytes": args.bytes}
    warnings: list[str] = []
    problems: list[str] = []
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout_s + 30)
        lines = [line.split() for line in proc.stdout.strip().splitlines() if line.strip()]
        expected = expected_body(args.bytes)
        verified = 0
        for path in files:
            try:
                with open(path, "rb") as handle:
                    body = handle.read()
            except OSError:
                continue
            if body == expected:
                verified += 1
        metrics["completed"] = verified
        metrics["responses"] = len(lines)
        bad = [
            line
            for line in lines
            if len(line) != 2 or line[0] != "200" or line[1] != "3"
        ]
        if proc.returncode != 0:
            problems.append(
                f"curl rc={proc.returncode}: {(proc.stderr or '').strip()[:200]}"
            )
        if len(lines) != args.streams:
            problems.append(f"{len(lines)} of {args.streams} transfers reported")
        if bad:
            problems.append(f"{len(bad)} transfers were not HTTP/3 200: {bad[:3]}")
        if verified != args.streams:
            problems.append(f"{verified} of {args.streams} bodies were exact")

        origin = origin_stats(args.origin_log, args.origin_offset, "h3-origin")
        if origin is None:
            warnings.append("origin log unavailable; connection reuse unverified")
        else:
            connections, peak = origin
            metrics["connections"] = connections
            metrics["peak_active"] = peak
            if connections > args.max_connections:
                warnings.append(
                    f"origin saw {connections} HTTP/3 connections for {args.streams} "
                    f"requests (client behavior, not a beam failure)"
                )
            if peak < args.min_peak:
                warnings.append(f"origin peak_active {peak} < {args.min_peak}")
    finally:
        for path in files:
            try:
                os.unlink(path)
            except OSError:
                pass

    ok = not problems
    detail = (
        f"HTTP/3 responses={metrics.get('responses')} exact={metrics.get('completed')} "
        f"origin_conns={metrics.get('connections')} peak={metrics.get('peak_active')}"
    )
    if problems:
        detail += "; " + "; ".join(problems)
    return emit(
        args,
        "h3-concurrent-8",
        ok,
        detail,
        metrics,
        warnings=warnings,
        planned=args.streams,
        completed=metrics.get("completed") or 0,
        deadline_ms=int(timeout_s * 1000),
        started=started,
    )


# ---------------------------------------------------------------------------
# Plain HTTP and TCP
# ---------------------------------------------------------------------------


def case_http1_persistent(args) -> int:
    started = time.time()
    host, port = split_addr(args.http)
    requests = args.requests
    latencies: list[float] = []
    identity: set[int] = set()
    errors: list[str] = []
    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        for _ in range(requests):
            requested = time.monotonic()
            try:
                conn.request("GET", "/keepalive")
                response = conn.getresponse()
                body = response.read()
            except Exception as error:  # noqa: BLE001 - exact failure in the report
                errors.append(f"{type(error).__name__}: {error}")
                break
            latencies.append((time.monotonic() - requested) * 1000.0)
            identity.add(id(conn.sock))
            if response.status != 200:
                errors.append(f"status {response.status}")
            elif body != MARKER_HTTP:
                errors.append(f"body mismatch: {body[:32]!r}")
            connection_header = (response.getheader("Connection") or "").lower()
            if connection_header != "keep-alive":
                errors.append(f"Connection header {connection_header!r}, wanted keep-alive")
    finally:
        conn.close()
    completed = requests - len(errors)
    ok = not errors and completed == requests and len(identity) == 1
    metrics = {
        "requests": requests,
        "completed": completed,
        "connections": len(identity),
        "p50_ms": round(nearest_rank(latencies, 50), 3),
        "p95_ms": round(nearest_rank(latencies, 95), 3),
        "samples": len(latencies),
    }
    detail = (
        f"{completed}/{requests} requests on {len(identity)} connection(s), "
        f"p50={metrics['p50_ms']}ms p95={metrics['p95_ms']}ms"
    )
    if errors:
        detail += "; " + "; ".join(errors[:3])
    return emit(
        args,
        "http1-persistent-20",
        ok,
        detail,
        metrics,
        planned=requests,
        completed=completed,
        deadline_ms=30_000,
        started=started,
        samples=latencies,
    )


def _tcp_echo(payload: bytes, host: str, port: int, timeout: float, chunk: int) -> dict:
    started = time.monotonic()
    sock = socket.create_connection((host, port), timeout=timeout)
    result: dict = {"bytes": len(payload)}
    errors: list[str] = []

    def writer() -> None:
        try:
            for offset in range(0, len(payload), chunk):
                sock.sendall(payload[offset : offset + chunk])
        except Exception as error:  # noqa: BLE001
            errors.append(f"send: {error}")

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    received = bytearray()
    try:
        while len(received) < len(payload):
            data = sock.recv(min(chunk, len(payload) - len(received)))
            if not data:
                errors.append("connection closed before the echo completed")
                break
            received.extend(data)
    except Exception as error:  # noqa: BLE001
        errors.append(f"recv: {error}")
    finally:
        thread.join(timeout=timeout)
        sock.close()
    elapsed = time.monotonic() - started
    result["ok"] = not errors and hashlib.sha256(received).digest() == hashlib.sha256(
        payload
    ).digest()
    result["seconds"] = elapsed
    result["mib_per_s"] = (len(payload) / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0
    result["errors"] = errors
    return result


def case_tcp_upload(args) -> int:
    started = time.time()
    host, port = split_addr(args.tcp)
    payload = bytes(range(256)) * (args.bytes // 256 + 1)
    payload = payload[: args.bytes]
    outcome = _tcp_echo(payload, host, port, timeout=60.0, chunk=1 << 20)
    metrics = {
        "bytes": args.bytes,
        "sha256_ok": outcome["ok"],
        "mib_per_s": round(outcome["mib_per_s"], 3),
        "seconds": round(outcome["seconds"], 3),
    }
    detail = (
        f"{args.bytes} B echoed in {outcome['seconds']:.2f}s "
        f"({metrics['mib_per_s']:.1f} MiB/s) sha256_ok={outcome['ok']}"
    )
    if outcome["errors"]:
        detail += "; " + "; ".join(outcome["errors"][:3])
    return emit(
        args,
        "tcp-upload-8m",
        outcome["ok"],
        detail,
        metrics,
        planned=1,
        completed=1 if outcome["ok"] else 0,
        deadline_ms=90_000,
        started=started,
    )


def case_idle_tcp(args) -> int:
    started = time.time()
    host, port = split_addr(args.tcp)
    first = b"idle-first-nonce"
    second = b"idle-second-nonce"
    errors: list[str] = []
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=10)
        sock.sendall(first)
        if recv_exact(sock, len(first), 10) != first:
            errors.append("first echo differed")
        time.sleep(args.idle)
        sock.sendall(second)
        if recv_exact(sock, len(second), 10) != second:
            errors.append("second echo differed")
    except Exception as error:  # noqa: BLE001
        errors.append(f"{type(error).__name__}: {error}")
    finally:
        if sock is not None:
            sock.close()
    ok = not errors
    metrics = {
        "idle_s": args.idle,
        "echo_ok": ok,
        "bytes": len(first) + len(second),
    }
    detail = f"{args.idle}s idle on one TCP socket, both echoes exact={ok}"
    if errors:
        detail += "; " + "; ".join(errors)
    return emit(
        args,
        "idle-tcp-35s",
        ok,
        detail,
        metrics,
        planned=2,
        completed=2 if ok else 0,
        deadline_ms=int((args.idle + 30) * 1000),
        started=started,
    )


# ---------------------------------------------------------------------------
# Cancellation and restart
# ---------------------------------------------------------------------------


def case_h2_cancel(args) -> int:
    started = time.time()
    url = f"https://{args.https}/?bytes={args.bytes}"
    proc = subprocess.Popen(
        [
            args.curl,
            "-sS",
            "-k",
            "--noproxy",
            "*",
            "--http2",
            "--max-time",
            "120",
            url,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    cancelled = 0
    try:
        assert proc.stdout is not None
        while cancelled < args.read_bytes:
            chunk = proc.stdout.read(min(65536, args.read_bytes - cancelled))
            if not chunk:
                break
            cancelled += len(chunk)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()

    host, port = split_addr(args.http)
    latencies: list[float] = []
    errors: list[str] = []
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        for _ in range(args.requests):
            requested = time.monotonic()
            try:
                conn.request("GET", "/keepalive")
                response = conn.getresponse()
                body = response.read()
            except Exception as error:  # noqa: BLE001
                errors.append(f"{type(error).__name__}: {error}")
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
                conn = http.client.HTTPConnection(host, port, timeout=5)
                continue
            latencies.append((time.monotonic() - requested) * 1000.0)
            if response.status != 200:
                errors.append(f"status {response.status}")
            elif body != MARKER_HTTP:
                errors.append("body mismatch")
    finally:
        conn.close()
    completed = args.requests - len(errors)
    p95 = nearest_rank(latencies, 95)
    warnings: list[str] = []
    if p95 > 2000:
        warnings.append(f"small-request p95 {p95:.0f}ms > 2000ms after a cancelled bulk stream")
    ok = completed == args.requests and not errors
    metrics = {
        "cancelled_bytes": cancelled,
        "keepalive_ok": completed,
        "requests": args.requests,
        "p95_ms": round(p95, 3),
        "samples": len(latencies),
    }
    detail = (
        f"cancelled a {args.bytes} B stream after {cancelled} B; "
        f"{completed}/{args.requests} follow-up requests ok, p95={p95:.0f}ms"
    )
    if errors:
        detail += "; " + "; ".join(errors[:3])
    return emit(
        args,
        "h2-cancel-64m",
        ok,
        detail,
        metrics,
        warnings=warnings,
        planned=args.requests,
        completed=completed,
        deadline_ms=60_000,
        started=started,
        samples=latencies,
    )


def case_restart_recovery(args) -> int:
    started = time.time()
    since = args.since_ms / 1000.0 if args.since_ms else started
    deadline = since + args.deadline_ms / 1000.0
    http_host, http_port = split_addr(args.http)
    udp_host, udp_port = split_addr(args.udp)
    tcp_recovery = None
    udp_recovery = None
    attempt_timeout = 1.0
    udp_sock = socket.socket(family(udp_host), socket.SOCK_DGRAM)
    try:
        while time.time() < deadline and (tcp_recovery is None or udp_recovery is None):
            if tcp_recovery is None:
                try:
                    conn = http.client.HTTPConnection(
                        http_host, http_port, timeout=attempt_timeout
                    )
                    conn.request("GET", "/")
                    response = conn.getresponse()
                    body = response.read()
                    conn.close()
                    if response.status == 200 and body == MARKER_HTTP:
                        tcp_recovery = max((time.time() - since) * 1000.0, 0.0)
                except Exception:  # noqa: BLE001 - retried until the deadline
                    pass
            if udp_recovery is None:
                nonce = b"restart-nonce"
                try:
                    udp_sock.settimeout(attempt_timeout)
                    udp_sock.sendto(nonce, (udp_host, udp_port))
                    data, _ = udp_sock.recvfrom(2048)
                    if data == nonce:
                        udp_recovery = max((time.time() - since) * 1000.0, 0.0)
                except OSError:
                    pass
            if tcp_recovery is None or udp_recovery is None:
                time.sleep(0.1)
    finally:
        udp_sock.close()

    hash_ok = False
    hash_detail = "not attempted"
    if tcp_recovery is not None and udp_recovery is not None:
        url = f"https://{args.https}/?bytes={args.hash_bytes}"
        with tempfile.NamedTemporaryFile(prefix="protocol-restart-", delete=False) as handle:
            body_path = handle.name
        try:
            proc = _curl_run(
                args,
                [
                    "--http2",
                    "--max-time",
                    "60",
                    "-o",
                    body_path,
                    "-w",
                    "%{http_code}",
                    url,
                ],
                90.0,
            )
            try:
                with open(body_path, "rb") as handle:
                    body = handle.read()
            except OSError:
                body = b""
            hash_ok = (
                proc.returncode == 0
                and proc.stdout.strip() == "200"
                and body == expected_body(args.hash_bytes)
            )
            hash_detail = f"HTTP/2 {proc.stdout.strip() or proc.returncode} {len(body)} B"
        finally:
            try:
                os.unlink(body_path)
            except OSError:
                pass

    warnings: list[str] = []
    slowest = max(value for value in (tcp_recovery, udp_recovery) if value is not None) if (
        tcp_recovery is not None or udp_recovery is not None
    ) else None
    if slowest is not None and slowest > 5000:
        warnings.append(f"recovery took {slowest:.0f}ms > 5000ms")
    ok = (
        tcp_recovery is not None
        and udp_recovery is not None
        and hash_ok
        and max(tcp_recovery, udp_recovery) <= args.deadline_ms
    )
    metrics = {
        "tcp_recovery_ms": round(tcp_recovery, 3) if tcp_recovery is not None else None,
        "udp_recovery_ms": round(udp_recovery, 3) if udp_recovery is not None else None,
        "post_restart_hash_ok": hash_ok,
        "deadline_ms": args.deadline_ms,
        "hash_bytes": args.hash_bytes,
    }
    detail = (
        f"tcp_recovery={metrics['tcp_recovery_ms']}ms "
        f"udp_recovery={metrics['udp_recovery_ms']}ms "
        f"post_restart_hash_ok={hash_ok} ({hash_detail})"
    )
    return emit(
        args,
        "restart-recovery",
        ok,
        detail,
        metrics,
        warnings=warnings,
        planned=3,
        completed=sum(
            [tcp_recovery is not None, udp_recovery is not None, hash_ok]
        ),
        deadline_ms=args.deadline_ms,
        started=started,
    )


# ---------------------------------------------------------------------------
# UDP and DNS
# ---------------------------------------------------------------------------


def _payload(sequence: int, size: int) -> bytes:
    filler = bytes(((sequence + index) & 0xFF) for index in range(size - UDP_HEADER))
    return struct.pack("!I", sequence) + filler


def case_udp_realtime(args) -> int:
    started = time.time()
    host, port = split_addr(args.udp)
    sock = socket.socket(family(host), socket.SOCK_DGRAM)
    sock.setblocking(False)
    interval = 1.0 / args.pps
    sent_at: dict[int, float] = {}
    received: dict[int, int] = {}
    corrupted = 0
    reorder = 0
    highest = -1
    rtts: list[float] = []
    duplicates = 0

    def drain(deadline: float) -> None:
        nonlocal corrupted, reorder, highest, duplicates
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            ready, _, _ = select.select([sock], [], [], min(remaining, 0.02))
            if not ready:
                continue
            try:
                data, _ = sock.recvfrom(65535)
            except OSError:
                continue
            if len(data) < UDP_HEADER:
                corrupted += 1
                continue
            (sequence,) = struct.unpack("!I", data[:UDP_HEADER])
            if data != _payload(sequence, len(data)) or len(data) != args.size:
                corrupted += 1
            if sequence in received:
                duplicates += 1
            else:
                received[sequence] = 1
                if sequence < highest:
                    reorder += 1
                highest = max(highest, sequence)
                if sequence in sent_at:
                    rtts.append((time.monotonic() - sent_at[sequence]) * 1000.0)

    last = time.monotonic()
    try:
        for sequence in range(args.packets):
            now = time.monotonic()
            if now < last:
                time.sleep(last - now)
            try:
                sock.sendto(_payload(sequence, args.size), (host, port))
            except OSError as error:
                log(f"udp send {sequence} failed: {error}")
                continue
            sent_at[sequence] = time.monotonic()
            last += interval
            drain(min(last, time.monotonic() + 0.01))
        drain(time.monotonic() + args.drain)
    finally:
        sock.close()

    lost = [sequence for sequence in range(args.packets) if sequence not in received]
    loss_pct = 100.0 * len(lost) / args.packets
    reorder_pct = 100.0 * reorder / max(len(received), 1)
    p95 = nearest_rank(rtts, 95)
    warnings: list[str] = []
    if loss_pct > 2.0:
        warnings.append(f"loss {loss_pct:.1f}% > 2%")
    if reorder_pct > 1.0:
        warnings.append(f"reorder {reorder_pct:.2f}% > 1%")
    if duplicates:
        warnings.append(f"{duplicates} duplicate replies")
    if p95 > 1000:
        warnings.append(f"p95 {p95:.0f}ms > 1000ms")
    if len(received) == 0:
        ok = False
    else:
        ok = corrupted == 0
    metrics = {
        "packets": args.packets,
        "size": args.size,
        "received": len(received),
        "lost": len(lost),
        "loss_pct": round(loss_pct, 3),
        "reorder": reorder,
        "reorder_pct": round(reorder_pct, 3),
        "duplicates": duplicates,
        "corrupt": corrupted,
        "p50_ms": round(nearest_rank(rtts, 50), 3),
        "p95_ms": round(p95, 3),
        "lost_sequences": lost[:64],
        "samples": len(rtts),
    }
    detail = (
        f"{len(received)}/{args.packets} sequences echoed, loss={loss_pct:.1f}% "
        f"reorder={reorder} dup={duplicates} corrupt={corrupted} p95={p95:.0f}ms"
    )
    return emit(
        args,
        "udp-realtime-1200",
        ok,
        detail,
        metrics,
        warnings=warnings,
        planned=args.packets,
        completed=len(received),
        deadline_ms=int((args.packets / args.pps + args.drain + 10) * 1000),
        started=started,
        samples=rtts,
    )


def case_udp_multidest(args) -> int:
    """Four destinations through one UDP socket, in two phases.

    Phase one sends to the echo ports and verifies every echo. Phase two sends
    to the alternate-source port, whose replies come from a different port than
    the one addressed. Both arms (beam and stock Xray) stop delivering replies
    once an alternate-source reply arrives in a shared association, so the alt
    phase is a WARN-shaped observation: correctness only covers the echo ports.
    """
    started = time.time()
    host, _ = split_addr(args.udp)
    ports = [int(value) for value in args.ports.split(",")]
    echo_ports = [port for port in ports if port != args.alt_port]
    sock = socket.socket(family(host), socket.SOCK_DGRAM)
    sock.settimeout(0.05)
    expected: dict[bytes, tuple[int, int]] = {}
    for port in echo_ports + [args.alt_port]:
        for index in range(args.packets):
            payload = f"multidest-{port}-{index}-".encode() * 3
            expected[payload] = (port, index)
    replies: dict[int, int] = {port: 0 for port in ports}
    peers: dict[int, set[int]] = {port: set() for port in ports}
    corrupted = 0

    def drain(seconds: float) -> None:
        nonlocal corrupted
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                data, peer = sock.recvfrom(65535)
            except OSError:
                continue
            entry = expected.get(data)
            if entry is None:
                corrupted += 1
                continue
            port = entry[0]
            replies[port] += 1
            peers[port].add(peer[1])

    def destination(port: int, drain_seconds: float) -> None:
        # One burst per destination, then a drain: sing-box drops the tail of a
        # burst when the association retargets several destinations within one
        # RTT (both arms behave identically), so the destinations are separated
        # by their own reply window. The association, socket and server are
        # shared for the whole case.
        for index in range(args.packets):
            payload = f"multidest-{port}-{index}-".encode() * 3
            sock.sendto(payload, (host, port))
        drain(drain_seconds)

    try:
        for port in echo_ports:
            destination(port, args.per_destination_drain)
        destination(args.alt_port, args.drain)
    finally:
        sock.close()

    missing = [port for port in echo_ports if replies[port] < args.packets]
    alt_replies = replies.get(args.alt_port, 0)
    warnings: list[str] = []
    if alt_replies < args.packets:
        warnings.append(
            f"{args.packets - alt_replies}/{args.packets} replies from {args.alt_port} "
            "were dropped once the alternate source answered; both arms behave this "
            "way (client-side demux, recorded as a behavior limitation)"
        )
    ok = not missing and corrupted == 0
    metrics = {
        "packets": len(expected),
        "echoed": sum(replies[port] for port in echo_ports),
        "echo_expected": args.packets * len(echo_ports),
        "alt_replies": alt_replies,
        "corrupt": corrupted,
        "ports": ports,
        "replies_per_port": {str(port): replies[port] for port in ports},
        "alt_source_ports": {port: sorted(value) for port, value in peers.items() if value},
    }
    detail = (
        f"{metrics['echoed']}/{metrics['echo_expected']} echo replies exact across "
        f"{len(echo_ports)} ports, alt-source replies={alt_replies}/{args.packets}, "
        f"corrupt={corrupted}"
    )
    if missing:
        detail += f"; incomplete echo ports: {missing}"
    return emit(
        args,
        "udp-multidest-4",
        ok,
        detail,
        metrics,
        warnings=warnings,
        planned=len(expected),
        completed=metrics["echoed"] + alt_replies,
        deadline_ms=int(
            (args.drain + len(echo_ports) * args.per_destination_drain + 10) * 1000
        ),
        started=started,
    )


def case_udp_alt_source(args) -> int:
    started = time.time()
    host, port = split_addr(args.udp)
    sock = socket.socket(family(host), socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    payloads = [f"alt-source-{index}".encode() * 2 for index in range(args.packets)]
    replies = 0
    sources: set[int] = set()
    mismatched = 0
    try:
        for payload in payloads:
            sock.sendto(payload, (host, port))
        deadline = time.monotonic() + args.timeout * args.packets
        pending = set(payloads)
        while pending and time.monotonic() < deadline:
            try:
                data, peer = sock.recvfrom(2048)
            except OSError:
                continue
            if data in pending:
                pending.discard(data)
                replies += 1
                sources.add(peer[1])
            else:
                mismatched += 1
    finally:
        sock.close()
    alt_source = sources == {args.expected_source}
    warnings: list[str] = []
    if replies == 0:
        warnings.append(
            "the alternate-source reply was dropped (XUDP full-cone limitation)"
        )
    elif not alt_source:
        warnings.append(f"replies came from {sorted(sources)}, wanted {args.expected_source}")
    elif replies != args.packets:
        warnings.append(f"{args.packets - replies} of {args.packets} replies lost")
    metrics = {
        "packets": args.packets,
        "replies": replies,
        "sources": sorted(sources),
        "expected_source": args.expected_source,
        "alt_source": alt_source,
        "unexpected": mismatched,
    }
    detail = (
        f"{replies}/{args.packets} replies from port(s) {sorted(sources)} "
        f"(wanted {args.expected_source})"
    )
    return emit(
        args,
        "udp-alt-source",
        True,
        detail,
        metrics,
        warnings=warnings,
        planned=args.packets,
        completed=replies,
        deadline_ms=int(args.timeout * args.packets * 1000 + 5000),
        started=started,
    )


def _dig(args, name: str, qtype: str, *, tcp: bool) -> tuple[bool, str, float]:
    """Run one dig query.

    ``+tries=2`` is dig's default: a stub resolver retries a lost UDP datagram.
    Without the retry a link that loses one packet in a hundred would fail a
    correctness case for behaviour no resolver exposes; the retry still
    requires every query to be answered, and a lost-and-retried query shows up
    as latency instead.
    """
    started = time.monotonic()
    host, port = split_addr(args.dns)
    command = [
        "dig",
        "+tcp" if tcp else "+notcp",
        "+time=2",
        "+tries=2",
        "-p",
        str(port),
        f"@{host}",
        name,
        qtype,
    ]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, f"dig failed: {error}", (time.monotonic() - started) * 1000.0
    output = proc.stdout + proc.stderr
    return proc.returncode == 0, output, (time.monotonic() - started) * 1000.0


def _dns_status(output: str) -> str:
    match = re.search(r"status:\s*([A-Z]+)", output)
    return match.group(1) if match else "?"


def _dns_answer(output: str, qtype: str) -> str | None:
    match = re.search(rf"\bIN\s+{re.escape(qtype)}\s+([0-9a-fA-F:.]+)", output)
    return match.group(1) if match else None


def case_dns_udp(args) -> int:
    started = time.time()
    latencies: list[float] = []
    errors: list[str] = []

    def query() -> tuple[bool, float, str]:
        ok, output, elapsed = _dig(args, args.name, "A", tcp=False)
        if not ok:
            return False, elapsed, output.strip().splitlines()[-1] if output.strip() else "dig failed"
        if _dns_status(output) != "NOERROR":
            return False, elapsed, f"status {_dns_status(output)}"
        answer = _dns_answer(output, "A")
        if answer != args.expect:
            return False, elapsed, f"A={answer}, wanted {args.expect}"
        return True, elapsed, answer or ""

    for _ in range(args.sequential):
        ok, elapsed, detail = query()
        latencies.append(elapsed)
        if not ok:
            errors.append(detail)
    remaining = args.queries - args.sequential
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for ok, elapsed, detail in pool.map(lambda _: query(), range(remaining)):
            latencies.append(elapsed)
            if not ok:
                errors.append(detail)
    answered = args.queries - len(errors)
    p95 = nearest_rank(latencies, 95)
    warnings: list[str] = []
    if p95 > 1000:
        warnings.append(f"p95 {p95:.0f}ms > 1000ms")
    metrics = {
        "queries": args.queries,
        "answered": answered,
        "p50_ms": round(nearest_rank(latencies, 50), 3),
        "p95_ms": round(p95, 3),
        "samples": len(latencies),
    }
    detail = (
        f"{answered}/{args.queries} NOERROR with {args.expect} "
        f"(p50={metrics['p50_ms']}ms p95={p95:.0f}ms); direct target DNS, "
        "not production DoH/hijack"
    )
    if errors:
        detail += f"; first errors: {errors[:3]}"
    return emit(
        args,
        "dns-udp-200",
        answered == args.queries,
        detail,
        metrics,
        warnings=warnings,
        planned=args.queries,
        completed=answered,
        deadline_ms=120_000,
        started=started,
        samples=latencies,
    )


def case_dns_tcp(args) -> int:
    started = time.time()
    errors: list[str] = []
    a_ok = 0
    for _ in range(args.queries):
        ok, output, _ = _dig(args, args.name, "A", tcp=True)
        if not ok or _dns_status(output) != "NOERROR" or _dns_answer(output, "A") != args.expect_a:
            errors.append(f"A: status={_dns_status(output)} answer={_dns_answer(output, 'A')}")
        else:
            a_ok += 1
    ok6, output6, _ = _dig(args, args.name, "AAAA", tcp=True)
    aaaa_ok = (
        ok6
        and _dns_status(output6) == "NOERROR"
        and (_dns_answer(output6, "AAAA") or "").lower() == args.expect_aaaa.lower()
    )
    ok_missing, output_missing, _ = _dig(args, args.missing, "A", tcp=True)
    nxdomain_ok = ok_missing and _dns_status(output_missing) == "NXDOMAIN"
    ok = a_ok == args.queries and aaaa_ok and nxdomain_ok
    metrics = {
        "queries": args.queries,
        "a_ok": a_ok,
        "aaaa_ok": aaaa_ok,
        "nxdomain_ok": nxdomain_ok,
        "expect_a": args.expect_a,
        "expect_aaaa": args.expect_aaaa,
        "missing": args.missing,
    }
    detail = (
        f"TCP DNS: A {a_ok}/{args.queries}, AAAA={aaaa_ok}, NXDOMAIN={nxdomain_ok}; "
        "direct target DNS, not production DoH/hijack"
    )
    if errors:
        detail += f"; first errors: {errors[:3]}"
    return emit(
        args,
        "dns-tcp-fallback",
        ok,
        detail,
        metrics,
        planned=args.queries + 2,
        completed=a_ok + int(bool(aaaa_ok)) + int(bool(nxdomain_ok)),
        deadline_ms=60_000,
        started=started,
    )


# ---------------------------------------------------------------------------
# TLS fallback and datagram continuity
# ---------------------------------------------------------------------------


def case_tls12(args) -> int:
    started = time.time()
    host, port = split_addr(args.tls)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    version = None
    body = b""
    error = ""
    conn = None
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=30, context=context)
        conn.connect()
        if conn.sock is not None:
            version = conn.sock.version()
        conn.request("GET", f"/?bytes={args.bytes}")
        response = conn.getresponse()
        body = response.read()
        if response.status != 200:
            error = f"status {response.status}"
    except Exception as failure:  # noqa: BLE001
        error = f"{type(failure).__name__}: {failure}"
    finally:
        if conn is not None:
            conn.close()
    digest_ok = body == expected_body(args.bytes, MARKER_HTTP)
    ok = error == "" and digest_ok and version == "TLSv1.2"
    metrics = {
        "bytes": len(body),
        "tls_version": version,
        "sha256_ok": digest_ok,
        "bytes_requested": args.bytes,
    }
    detail = (
        f"TLS 1.2 forced, negotiated {version}, {len(body)} B sha256_ok={digest_ok}; "
        "no 'Direct' transition is claimed from this alone"
    )
    if error:
        detail += f"; {error}"
    return emit(
        args,
        "tls12-fallback",
        ok,
        detail,
        metrics,
        deadline_ms=60_000,
        started=started,
    )


def case_datagram_size(args) -> int:
    started = time.time()
    udp_host, udp_port = split_addr(args.udp)
    results: dict[str, bool] = {}
    errors: list[str] = []
    sock = socket.socket(family(udp_host), socket.SOCK_DGRAM)
    try:
        for size in (1200, 1400):
            ok = True
            for index in range(args.repeats):
                payload = _payload(index, size)
                try:
                    sock.settimeout(args.timeout)
                    sock.sendto(payload, (udp_host, udp_port))
                    data, _ = sock.recvfrom(65535)
                    if data != payload:
                        ok = False
                        errors.append(f"{size} B echo differed")
                except OSError as error:
                    ok = False
                    errors.append(f"{size} B: {type(error).__name__}: {error}")
            results[f"udp_{size}_ok"] = ok
    finally:
        sock.close()

    tls_host, tls_port = split_addr(args.tls)
    http_ok = False
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = None
    try:
        conn = http.client.HTTPSConnection(tls_host, tls_port, timeout=30, context=context)
        conn.request("GET", f"/?bytes={args.http_bytes}")
        response = conn.getresponse()
        body = response.read()
        http_ok = response.status == 200 and body == expected_body(
            args.http_bytes, MARKER_HTTP
        )
        if not http_ok:
            errors.append(f"{args.http_bytes} B HTTPS body mismatch")
    except Exception as failure:  # noqa: BLE001
        errors.append(f"{args.http_bytes} B HTTPS: {type(failure).__name__}: {failure}")
    finally:
        if conn is not None:
            conn.close()

    ok = all(results.values()) and http_ok
    metrics = {
        "udp_1200_ok": results.get("udp_1200_ok", False),
        "udp_1400_ok": results.get("udp_1400_ok", False),
        "http_16384_ok": http_ok,
        "http_bytes": args.http_bytes,
    }
    detail = (
        f"UDP 1200 B={metrics['udp_1200_ok']} 1400 B={metrics['udp_1400_ok']}, "
        f"HTTPS {args.http_bytes} B={http_ok}; no DF/PMTU claim is made"
    )
    if errors:
        detail += "; " + "; ".join(errors[:3])
    return emit(
        args,
        "datagram-size-continuity",
        ok,
        detail,
        metrics,
        planned=args.repeats * 2 + 1,
        completed=sum(
            [
                args.repeats if metrics["udp_1200_ok"] else 0,
                args.repeats if metrics["udp_1400_ok"] else 0,
                int(http_ok),
            ]
        ),
        deadline_ms=60_000,
        started=started,
    )


# ---------------------------------------------------------------------------
# Mixed load
# ---------------------------------------------------------------------------


def case_mixed(args) -> int:
    started = time.time()
    duration = args.seconds
    deadline = time.monotonic() + duration
    lock = threading.Lock()
    counts = {
        "h1_attempted": 0,
        "h1_completed": 0,
        "h1_invalid": 0,
        "h2_completed": 0,
        "h2_invalid": 0,
        "udp_sent": 0,
        "udp_completed": 0,
        "udp_invalid": 0,
        "udp_stray": 0,
        "dns_planned": 5 * duration,
        "dns_completed": 0,
        "dns_invalid": 0,
        "tcp_planned": 1,
        "tcp_completed": 0,
        "tcp_invalid": 0,
    }
    small: list[float] = []
    h2_throughput: list[float] = []
    errors: list[str] = []
    barrier = threading.Barrier(15)

    def add(key: str, count: int = 1) -> None:
        """Raw counter for attempts and sends; outcomes go through record()."""
        with lock:
            counts[key] += count

    def record(key: str, outcome: Outcome = Outcome.OK) -> None:
        with lock:
            apply_outcome(counts, key, outcome)

    def h2_worker() -> None:
        url = f"https://{args.https}/?bytes={args.h2_bytes}"
        expected = expected_body(args.h2_bytes)
        with tempfile.NamedTemporaryFile(prefix="protocol-mixed-h2-", delete=False) as handle:
            body_path = handle.name
        barrier.wait()
        try:
            while time.monotonic() < deadline:
                requested = time.monotonic()
                try:
                    proc = _curl_run(
                        args,
                        [
                            "--http2",
                            "--max-time",
                            "20",
                            "-o",
                            body_path,
                            "-w",
                            "%{http_code}",
                            url,
                        ],
                        40.0,
                    )
                except (OSError, subprocess.TimeoutExpired) as error:
                    record("h2_completed", Outcome.INCOMPLETE)
                    with lock:
                        errors.append(f"h2: {type(error).__name__}: {error}")
                    continue
                try:
                    with open(body_path, "rb") as handle:
                        body = handle.read()
                except OSError:
                    body = b""
                if proc.returncode != 0:
                    record("h2_completed", Outcome.INCOMPLETE)
                    with lock:
                        errors.append(
                            f"h2: curl rc={proc.returncode}: "
                            f"{(proc.stderr or '').strip()[:120]}"
                        )
                    continue
                if proc.stdout.strip() == "200" and body == expected:
                    record("h2_completed")
                    with lock:
                        h2_throughput.append(len(expected) / (time.monotonic() - requested))
                else:
                    record("h2_completed", Outcome.INVALID)
        finally:
            try:
                os.unlink(body_path)
            except OSError:
                pass

    def h1_worker() -> None:
        """One persistent HTTP/1.1 connection issuing a request every 200 ms.

        A sequential keep-alive connection cannot exceed one request per RTT, so
        the planned count is what the worker actually attempted on this link;
        the target rate stays in the metrics as INFO.
        """
        host, port = split_addr(args.http)
        interval = 0.2
        barrier.wait()
        conn = http.client.HTTPConnection(host, port, timeout=10)
        while time.monotonic() < deadline:
            tick = time.monotonic()
            add("h1_attempted")
            try:
                conn.request("GET", "/keepalive")
                response = conn.getresponse()
                body = response.read()
                outcome = (
                    Outcome.OK
                    if response.status == 200 and body == MARKER_HTTP
                    else Outcome.INVALID
                )
            except Exception as error:  # noqa: BLE001
                outcome = Outcome.INCOMPLETE
                with lock:
                    errors.append(f"h1: {type(error).__name__}: {error}")
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
                conn = http.client.HTTPConnection(host, port, timeout=10)
            if outcome is Outcome.OK:
                record("h1_completed")
                with lock:
                    small.append((time.monotonic() - tick) * 1000.0)
            elif outcome is Outcome.INVALID:
                record("h1_completed", Outcome.INVALID)
            sleep = interval - (time.monotonic() - tick)
            if sleep > 0:
                time.sleep(sleep)

    def udp_worker() -> None:
        """10 echo probes per second, matched by sequence number.

        Replies arrive one RTT later, so each tick drains whatever is available
        instead of assuming the reply matches the request just sent.
        """
        host, port = split_addr(args.udp)
        sock = socket.socket(family(host), socket.SOCK_DGRAM)
        sock.setblocking(False)
        barrier.wait()
        sent: dict[int, bytes] = {}
        verified: set[int] = set()
        corrupt: set[int] = set()
        stray = 0

        def drain(until: float) -> None:
            nonlocal stray
            while True:
                remaining = until - time.monotonic()
                if remaining <= 0:
                    return
                ready, _, _ = select.select([sock], [], [], min(remaining, 0.02))
                if not ready:
                    return
                try:
                    data, _ = sock.recvfrom(65535)
                except OSError:
                    return
                if len(data) < UDP_HEADER:
                    stray += 1
                    continue
                (sequence,) = struct.unpack("!I", data[:UDP_HEADER])
                note_reply(sent, verified, corrupt, sequence, data)

        try:
            while time.monotonic() < deadline and len(sent) < 10 * duration:
                tick = time.monotonic()
                sequence = len(sent)
                payload = _payload(sequence, 512)
                try:
                    sock.sendto(payload, (host, port))
                except OSError as error:
                    with lock:
                        errors.append(f"udp: send {sequence}: {error}")
                    break
                sent[sequence] = payload
                drain(tick + 0.08)
                sleep = 0.1 - (time.monotonic() - tick)
                if sleep > 0:
                    time.sleep(sleep)
            drain(time.monotonic() + 1.5)
        finally:
            sock.close()
        with lock:
            counts["udp_sent"] += len(sent)
            # One outcome per sent sequence, through the same rule as every
            # other unit: verified -> OK, wrong payload -> INVALID (completed
            # and invalid, counted once and sticky), no reply -> INCOMPLETE
            # (neither counter). A datagram too short to carry a sequence
            # number cannot be attributed to planned work: it is recorded as
            # corruption evidence (invalid) without inflating `completed`, so
            # the completion ratio can never exceed one.
            for outcome in sequence_outcomes(sent, verified, corrupt):
                apply_outcome(counts, "udp_completed", outcome)
            counts["udp_stray"] += stray
            counts["udp_invalid"] += stray

    def dns_worker() -> None:
        per_worker = max(1, counts["dns_planned"] // 5)
        barrier.wait()
        index = 0
        while time.monotonic() < deadline and index < per_worker:
            index += 1
            ok, output, _ = _dig(args, "target.test", "A", tcp=False)
            if ok and _dns_status(output) == "NOERROR" and _dns_answer(output, "A") == args.dns_expect:
                record("dns_completed")
            elif ok:
                record("dns_completed", Outcome.INVALID)
            else:
                record("dns_completed", Outcome.INCOMPLETE)
            time.sleep(0.2)

    def tcp_worker() -> None:
        host, port = split_addr(args.tcp)
        payload = bytes(range(256)) * (args.tcp_bytes // 256 + 1)
        payload = payload[: args.tcp_bytes]
        barrier.wait()
        outcome = _tcp_echo(payload, host, port, timeout=90.0, chunk=1 << 20)
        record("tcp_completed", tcp_unit_outcome(outcome))
        if not outcome["ok"]:
            with lock:
                errors.append("tcp: " + "; ".join(outcome["errors"][:2] or ["hash mismatch"]))

    workers = (
        [threading.Thread(target=h2_worker) for _ in range(4)]
        + [threading.Thread(target=h1_worker) for _ in range(4)]
        + [threading.Thread(target=udp_worker)]
        + [threading.Thread(target=dns_worker) for _ in range(5)]
        + [threading.Thread(target=tcp_worker)]
    )
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=duration + 180)

    ok, derived = mixed_verdict(counts, duration)
    planned = derived["planned"]
    completed = derived["completed"]
    invalid = derived["invalid"]
    completion_ratio = derived["completion_ratio"]
    h1_floor = derived["h1_floor"]
    small_p95 = nearest_rank(small, 95)
    warnings: list[str] = []
    if small_p95 > 2000:
        warnings.append(f"small-request p95 {small_p95:.0f}ms > 2000ms under bulk load")
    metrics = {
        "planned": planned,
        "completed": completed,
        "completion_ratio": round(completion_ratio, 4),
        "invalid": invalid,
        "h1_target": 4 * 5 * duration,
        "h1_attempted": counts["h1_attempted"],
        "h1_completed": counts["h1_completed"],
        "h1_floor": h1_floor,
        "h2_completed": counts["h2_completed"],
        "udp_planned": counts["udp_sent"],
        "udp_completed": counts["udp_completed"],
        "udp_stray": counts["udp_stray"],
        "dns_planned": counts["dns_planned"],
        "dns_completed": counts["dns_completed"],
        "tcp_completed": counts["tcp_completed"],
        "small_p95_ms": round(small_p95, 3),
        "samples": len(small),
        "h2_mib_per_s": round(
            sum(h2_throughput) / len(h2_throughput) / (1024 * 1024), 3
        )
        if h2_throughput
        else 0.0,
    }
    detail = (
        f"{duration}s mixed load: h1 {counts['h1_completed']}/{counts['h1_attempted']}, "
        f"h2 {counts['h2_completed']} bulk, "
        f"udp {counts['udp_completed']}/{counts['udp_sent']}, "
        f"dns {counts['dns_completed']}/{counts['dns_planned']}, "
        f"tcp {counts['tcp_completed']}/1, invalid={invalid}, "
        f"small p95={small_p95:.0f}ms"
    )
    if errors:
        detail += f"; first errors: {errors[:3]}"
    return emit(
        args,
        "mixed-hol-60s",
        ok,
        detail,
        metrics,
        warnings=warnings,
        planned=planned,
        completed=completed,
        deadline_ms=duration * 1000,
        started=started,
        samples=small,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="case", required=True)

    def common(name: str, handler) -> argparse.ArgumentParser:
        item = sub.add_parser(name)
        item.add_argument("--out", default="")
        item.add_argument("--curl", default="curl")
        item.set_defaults(handler=handler)
        return item

    item = common("h2-bulk-8m", case_h2_bulk)
    item.add_argument("--https", default="10.10.2.2:8443")
    item.add_argument("--bytes", type=int, default=8 * 1024 * 1024)

    item = common("h3-bulk-8m", case_h3_bulk)
    item.add_argument("--https", default="10.10.2.2:4443")
    item.add_argument("--bytes", type=int, default=8 * 1024 * 1024)

    item = common("h2-multiplex-16", case_h2_multiplex)
    item.add_argument("--client", required=True, help="h2-client JSON result")
    item.add_argument("--streams", type=int, default=16)
    item.add_argument("--min-peak", type=int, default=8)
    item.add_argument("--origin-log", default="")
    item.add_argument("--origin-offset", type=int, default=0)

    item = common("h3-concurrent-8", case_h3_concurrent)
    item.add_argument("--https", default="10.10.2.2:4443")
    item.add_argument("--bytes", type=int, default=65536)
    item.add_argument("--streams", type=int, default=8)
    item.add_argument("--min-peak", type=int, default=4)
    item.add_argument("--max-connections", type=int, default=1)
    item.add_argument("--origin-log", default="")
    item.add_argument("--origin-offset", type=int, default=0)

    item = common("http1-persistent-20", case_http1_persistent)
    item.add_argument("--http", default="10.10.2.2:8080")
    item.add_argument("--requests", type=int, default=20)

    item = common("tcp-upload-8m", case_tcp_upload)
    item.add_argument("--tcp", default="10.10.2.2:9000")
    item.add_argument("--bytes", type=int, default=8 * 1024 * 1024)

    item = common("h2-cancel-64m", case_h2_cancel)
    item.add_argument("--https", default="10.10.2.2:8443")
    item.add_argument("--http", default="10.10.2.2:8080")
    item.add_argument("--bytes", type=int, default=64 * 1024 * 1024)
    item.add_argument("--read-bytes", type=int, default=1024 * 1024)
    item.add_argument("--requests", type=int, default=10)

    item = common("udp-realtime-1200", case_udp_realtime)
    item.add_argument("--udp", default="10.10.2.2:9999")
    item.add_argument("--packets", type=int, default=1200)
    item.add_argument("--size", type=int, default=512)
    item.add_argument("--pps", type=float, default=100.0)
    item.add_argument("--drain", type=float, default=2.0)

    item = common("udp-multidest-4", case_udp_multidest)
    item.add_argument("--udp", default="10.10.2.2:9999")
    item.add_argument("--ports", default="9996,9997,9998,9999")
    item.add_argument("--alt-port", type=int, default=9998)
    item.add_argument("--packets", type=int, default=25)
    item.add_argument("--drain", type=float, default=5.0)
    item.add_argument("--per-destination-drain", type=float, default=1.5)

    item = common("udp-alt-source", case_udp_alt_source)
    item.add_argument("--udp", default="10.10.2.2:9998")
    item.add_argument("--packets", type=int, default=5)
    item.add_argument("--timeout", type=float, default=1.0)
    item.add_argument("--expected-source", type=int, default=9995)

    item = common("dns-udp-200", case_dns_udp)
    item.add_argument("--dns", default="10.10.2.2:53")
    item.add_argument("--name", default="target.test")
    item.add_argument("--expect", default="10.10.2.2")
    item.add_argument("--queries", type=int, default=200)
    item.add_argument("--sequential", type=int, default=10)
    item.add_argument("--workers", type=int, default=16)

    item = common("dns-tcp-fallback", case_dns_tcp)
    item.add_argument("--dns", default="10.10.2.2:53")
    item.add_argument("--name", default="target.test")
    item.add_argument("--missing", default="missing.test")
    item.add_argument("--expect-a", default="10.10.2.2")
    item.add_argument("--expect-aaaa", default="fd00:2::2")
    item.add_argument("--queries", type=int, default=20)

    item = common("tls12-fallback", case_tls12)
    item.add_argument("--tls", default="10.10.2.2:8444")
    item.add_argument("--bytes", type=int, default=1024 * 1024)

    item = common("datagram-size-continuity", case_datagram_size)
    item.add_argument("--udp", default="10.10.2.2:9999")
    item.add_argument("--tls", default="10.10.2.2:4443")
    item.add_argument("--repeats", type=int, default=5)
    item.add_argument("--timeout", type=float, default=2.0)
    item.add_argument("--http-bytes", type=int, default=16 * 1024)

    item = common("mixed-hol-60s", case_mixed)
    item.add_argument("--https", default="10.10.2.2:8443")
    item.add_argument("--http", default="10.10.2.2:8080")
    item.add_argument("--udp", default="10.10.2.2:9999")
    item.add_argument("--tcp", default="10.10.2.2:9000")
    item.add_argument("--dns", default="10.10.2.2:53")
    item.add_argument("--dns-expect", default="10.10.2.2")
    item.add_argument("--h2-bytes", type=int, default=1024 * 1024)
    item.add_argument("--tcp-bytes", type=int, default=16 * 1024 * 1024)
    item.add_argument("--seconds", type=int, default=60)

    item = common("idle-tcp-35s", case_idle_tcp)
    item.add_argument("--tcp", default="10.10.2.2:9000")
    item.add_argument("--idle", type=float, default=35.0)

    item = common("restart-recovery", case_restart_recovery)
    item.add_argument("--http", default="10.10.2.2:8080")
    item.add_argument("--udp", default="10.10.2.2:9999")
    item.add_argument("--https", default="10.10.2.2:8443")
    item.add_argument("--deadline-ms", type=int, default=10000)
    item.add_argument("--since-ms", type=int, default=0)
    item.add_argument("--hash-bytes", type=int, default=1024 * 1024)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
