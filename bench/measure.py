#!/usr/bin/env python3
"""One timed benchmark scenario through the full-TUN client.

The script runs inside the client network namespace (and on the client CPU
core) and measures exactly one scenario. It snapshots the server process,
the sing-box client process, the target process and ``/proc/stat`` before and
after the timed window, so the resulting JSON has:

* application metrics (throughput, pps, latency percentiles, loss),
* server CPU seconds and CPU seconds per GiB,
* client and target core utilisation (saturation flags),
* server RSS, file descriptor and thread counts after the warm-up.

The harness deliberately keeps this file standard-library only: it runs inside
an unprivileged user namespace where installing packages is not possible.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

GIB = 1024.0 * 1024.0 * 1024.0
CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


# ---------------------------------------------------------------------------
# Process / CPU snapshots
# ---------------------------------------------------------------------------


def _read_status(pid: int) -> dict:
    fields: dict[str, int] = {}
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError:
        return fields
    for line in text.splitlines():
        if line.startswith(("VmRSS:", "VmHWM:", "Threads:")):
            name, _, rest = line.partition(":")
            value = rest.strip().split()
            if value and value[0].isdigit():
                fields[name] = int(value[0])
    return fields


def _read_proc(pid: int) -> dict | None:
    if not pid or pid <= 0:
        return None
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        tail = stat[stat.rfind(")") + 2 :].split()
        ticks = int(tail[11]) + int(tail[12])
    except (IndexError, ValueError):
        return None
    status = _read_status(pid)
    try:
        fds = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        fds = -1
    return {
        "pid": pid,
        "cpu_ticks": ticks,
        "rss_kib": status.get("VmRSS", -1),
        "hwm_kib": status.get("VmHWM", -1),
        "threads": status.get("Threads", -1),
        "fds": fds,
    }


def _read_cpu_times() -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    try:
        lines = Path("/proc/stat").read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    for line in lines:
        parts = line.split()
        if not parts or not parts[0].startswith("cpu") or parts[0] == "cpu":
            continue
        try:
            values = [int(value) for value in parts[1:9]]
        except ValueError:
            continue
        if len(values) < 5:
            continue
        total = sum(values)
        idle = values[3] + values[4]
        result[parts[0]] = {"total": total, "busy": total - idle}
    return result


def _read_mhz(core: int) -> float | None:
    try:
        khz = Path(
            f"/sys/devices/system/cpu/cpu{core}/cpufreq/scaling_cur_freq"
        ).read_text(encoding="utf-8")
        return round(int(khz) / 1000.0, 1)
    except (OSError, ValueError):
        return None


def _load1() -> float:
    try:
        return float(Path("/proc/loadavg").read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError):
        return 0.0


def snapshot(pids: dict[str, int], cores: dict[str, int]) -> dict:
    return {
        "t": time.time(),
        "pids": {name: _read_proc(pid) for name, pid in pids.items()},
        "cpu": _read_cpu_times(),
        "mhz": {name: _read_mhz(core) for name, core in cores.items()},
        "load1": _load1(),
    }


def _cpu_delta(
    before: dict[str, dict[str, int]], after: dict[str, dict[str, int]], core: int
) -> float | None:
    name = f"cpu{core}"
    first = before.get(name)
    last = after.get(name)
    if not first or not last:
        return None
    total = last["total"] - first["total"]
    if total <= 0:
        return None
    busy = last["busy"] - first["busy"]
    return round(max(0.0, busy) / total * 100.0, 2)


def _smt_siblings(core: int) -> set[int]:
    """The core plus its hyperthread siblings, if the topology exposes them.

    A role pinned to one thread still spills work onto its sibling thread, so
    the sibling is part of the role and must not be reported as host noise.
    """
    path = Path(f"/sys/devices/system/cpu/cpu{core}/topology/thread_siblings_list")
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return {core}
    cores = {core}
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        low, _, high = chunk.partition("-")
        try:
            if high:
                cores.update(range(int(low), int(high) + 1))
            else:
                cores.add(int(low))
        except ValueError:
            continue
    return cores



def _pct(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(percentile / 100.0 * (len(ordered) - 1)))))
    return ordered[index]


def latency_summary(samples_us: list[float]) -> dict:
    return {
        "count": len(samples_us),
        "p50_us": _pct(samples_us, 50),
        "p95_us": _pct(samples_us, 95),
        "p99_us": _pct(samples_us, 99),
        "min_us": min(samples_us) if samples_us else None,
        "max_us": max(samples_us) if samples_us else None,
        "median_us": _pct(samples_us, 50),
    }


# ---------------------------------------------------------------------------
# Scenario implementations
# ---------------------------------------------------------------------------


def run_iperf3(args: argparse.Namespace) -> tuple[dict, list[str]]:
    command = [
        args.iperf3_bin,
        "-c",
        args.target_host,
        "-p",
        str(args.iperf3_port),
        "-t",
        str(args.duration),
        "-P",
        str(args.flows),
        "-l",
        "128K",
        "-4",
        "--connect-timeout",
        "5000",
        "-J",
    ]
    if args.direction == "download":
        command.insert(1, "-R")
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=args.duration + 120,
        check=False,
    )
    warnings: list[str] = []
    metrics: dict = {}
    if completed.returncode != 0:
        return {
            "status": "fail",
            "reason": f"iperf3 exited {completed.returncode}: {completed.stderr.strip()[-400:]}",
            "command": command,
            "metrics": metrics,
            "warnings": warnings,
        }, warnings
    try:
        data = json.loads(completed.stdout)
        end = data["end"]
        received = end["sum_received"]
        sent = end["sum_sent"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        return {
            "status": "fail",
            "reason": f"could not parse iperf3 JSON: {error}",
            "command": command,
            "metrics": metrics,
            "warnings": warnings,
        }, warnings

    metrics = {
        "throughput_bps": float(received["bits_per_second"]),
        "bytes": int(received["bytes"]),
        "seconds": float(received["seconds"]),
        "sent_bytes": int(sent["bytes"]),
        "streams": len(end.get("streams") or []),
        "retransmits": sent.get("retransmits"),
        "local_cpu_pct": (end.get("cpu_utilization_percent") or {}).get("host_total"),
        "remote_cpu_pct": (end.get("cpu_utilization_percent") or {}).get("remote_total"),
    }
    if metrics["throughput_bps"] <= 0 or metrics["bytes"] <= 0:
        return {
            "status": "fail",
            "reason": "iperf3 reported zero throughput",
            "command": command,
            "metrics": metrics,
            "warnings": warnings,
        }, warnings
    if metrics["streams"] != args.flows:
        warnings.append(
            f"iperf3 reported {metrics['streams']} streams, expected {args.flows}"
        )
    return {
        "status": "ok",
        "reason": None,
        "command": command,
        "metrics": metrics,
        "warnings": warnings,
    }, warnings


def _curl(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_https(args: argparse.Namespace) -> tuple[dict, list[str]]:
    command = [
        "curl",
        "--http1.1",
        "--noproxy",
        "*",
        "-k",
        "-sS",
        "--max-time",
        str(args.max_time),
        "-o",
        "/dev/null",
        "-w",
        "%{http_code} %{size_download} %{time_total} %{speed_download}\\n",
        args.url,
    ]
    samples: list[dict] = []
    warnings: list[str] = []
    failure = None

    def run_one(_: int) -> subprocess.CompletedProcess:
        return _curl(command, timeout=args.max_time + 30)

    if args.https_parallel > 1:
        # Concurrent requests exist only to force the harness into the async
        # fallback; request-time rates under contention are not comparable with
        # the sequential workload, so say so in the result.
        warnings.append(
            f"concurrent HTTPS ({args.https_parallel} requests in flight); "
            "probe only, not a sequential gate measurement"
        )
        with ThreadPoolExecutor(max_workers=args.https_parallel) as pool:
            completed_iter = iter(list(pool.map(run_one, range(args.count))))
    else:
        completed_iter = (run_one(index) for index in range(args.count))

    for completed in completed_iter:
        if completed.returncode != 0:
            failure = f"curl exited {completed.returncode}: {completed.stderr.strip()[-300:]}"
            break
        parts = completed.stdout.strip().split()
        if len(parts) != 4:
            failure = f"unexpected curl output: {completed.stdout.strip()[:200]}"
            break
        code, size, seconds, speed = parts
        sample = {
            "http_code": int(code),
            "bytes": int(size),
            "seconds": float(seconds),
            "mib_per_s": round(int(size) / 1048576.0 / max(float(seconds), 1e-9), 3),
            "speed_download": float(speed),
        }
        samples.append(sample)
        if sample["http_code"] != 200:
            failure = f"HTTP {sample['http_code']}"
            break
        if args.expected_size and sample["bytes"] != args.expected_size:
            failure = (
                f"short body: {sample['bytes']} of {args.expected_size} bytes"
            )
            break

    metrics: dict = {"samples": samples}
    if samples:
        total_bytes = sum(item["bytes"] for item in samples)
        total_seconds = sum(item["seconds"] for item in samples)
        metrics["bytes"] = total_bytes
        metrics["seconds"] = round(total_seconds, 6)
        metrics["mib_per_s"] = round(
            total_bytes / 1048576.0 / max(total_seconds, 1e-9), 3
        )
        metrics["mib_per_s_samples"] = [item["mib_per_s"] for item in samples]
    if failure:
        return {
            "status": "fail",
            "reason": failure,
            "command": command,
            "metrics": metrics,
            "warnings": warnings,
        }, warnings
    return {
        "status": "ok",
        "reason": None,
        "command": command,
        "metrics": metrics,
        "warnings": warnings,
    }, warnings


def _udp_payload(seq: int, size: int) -> bytes:
    return struct.pack("!I", seq) + b"\xA5" * max(0, size - 4)


def _seq(data: bytes) -> int | None:
    if len(data) < 4:
        return None
    return struct.unpack("!I", data[:4])[0]


def _drain(sock: socket.socket) -> None:
    sock.setblocking(False)
    try:
        while True:
            try:
                sock.recv(65535)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
    finally:
        sock.setblocking(True)


def run_udp(args: argparse.Namespace) -> tuple[dict, list[str]]:
    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    warnings: list[str] = []
    samples_us: list[float] = []
    sent = 0
    received = 0
    failure = None
    started = 0.0
    finished = 0.0
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    try:
        sock.connect((args.host, args.port))
        pending: dict[int, int] = {}
        next_seq = 0
        started = time.monotonic_ns()
        finished = started
        while next_seq < args.packet_count or pending:
            while len(pending) < args.window and next_seq < args.packet_count:
                payload = _udp_payload(next_seq, args.payload)
                sock.send(payload)
                pending[next_seq] = time.monotonic_ns()
                next_seq += 1
                sent += 1
            readable, _, _ = select.select([sock], [], [], args.timeout)
            if not readable:
                break
            try:
                data = sock.recv(65535)
            except OSError as error:
                failure = f"UDP receive failed: {error}"
                break
            got = _seq(data)
            if got is None or got not in pending:
                continue
            sent_at = pending.pop(got)
            if data[4:] != b"\xA5" * max(0, args.payload - 4):
                failure = "UDP echo corrupted the payload"
                break
            samples_us.append((time.monotonic_ns() - sent_at) / 1000.0)
            received += 1
            finished = time.monotonic_ns()

        # Drain late replies, then measure clean sequential RTTs.
        _drain(sock)
        latency_us: list[float] = []
        for seq in range(args.latency_count):
            payload = _udp_payload(seq, min(args.payload, 256))
            send_at = time.monotonic_ns()
            sock.send(payload)
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            if data == payload:
                latency_us.append((time.monotonic_ns() - send_at) / 1000.0)
            else:
                failure = "UDP echo corrupted the latency payload"
                break
    except OSError as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        sock.close()

    elapsed_s = max((finished - started) / 1e9, 1e-9) if sent else 0.0
    metrics = {
        "sent": sent,
        "received": received,
        "loss_pct": round((sent - received) / sent * 100.0, 3) if sent else None,
        "payload_bytes": args.payload,
        "seconds": round(elapsed_s, 6),
        "pps": round(received / elapsed_s, 1) if elapsed_s else 0.0,
        "mbps": round(received * args.payload * 8 / elapsed_s / 1e6, 3)
        if elapsed_s
        else 0.0,
        "bytes": received * args.payload,
        **{f"rtt_{key}": value for key, value in latency_summary(latency_us).items()},
        "rtt_samples_us": latency_us,
        "window_rtt_samples_us": samples_us,
    }
    if received == 0:
        failure = failure or "no UDP echo replies"
    if sent and received < sent:
        warnings.append(f"UDP loss {metrics['loss_pct']}% ({sent - received}/{sent})")
    if failure:
        return {
            "status": "fail",
            "reason": failure,
            "command": ["udp-echo", args.host, str(args.port)],
            "metrics": metrics,
            "warnings": warnings,
        }, warnings
    return {
        "status": "ok",
        "reason": None,
        "command": ["udp-echo", args.host, str(args.port)],
        "metrics": metrics,
        "warnings": warnings,
    }, warnings


def _dns_query(qid: int) -> bytes:
    name = b"target.test"
    qname = b"".join(bytes([len(part)]) + part for part in name.split(b".")) + b"\x00"
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack("!HH", 1, 1)


def run_dns(args: argparse.Namespace) -> tuple[dict, list[str]]:
    family = socket.AF_INET6 if ":" in args.dns_server else socket.AF_INET
    warnings: list[str] = []
    samples_us: list[float] = []
    errors: list[str] = []
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    sent = 0
    received = 0
    try:
        sock.connect((args.dns_server, args.dns_port))
        for index in range(args.dns_count):
            qid = index & 0xFFFF
            query = _dns_query(qid)
            send_at = time.monotonic_ns()
            sock.send(query)
            sent += 1
            try:
                data = sock.recv(65535)
            except socket.timeout:
                errors.append("timeout")
                continue
            if len(data) < 12:
                errors.append("short response")
                continue
            got_id, flags = struct.unpack("!HH", data[:4])
            if got_id != qid:
                errors.append("id mismatch")
                continue
            if flags & 0x000F:
                errors.append(f"rcode={flags & 0x000F}")
                continue
            if b"\x0a\x0a\x02\x02" not in data:
                errors.append("missing A record")
                continue
            received += 1
            samples_us.append((time.monotonic_ns() - send_at) / 1000.0)
    except OSError as error:
        errors.append(f"{type(error).__name__}: {error}")
    finally:
        sock.close()

    summary = latency_summary(samples_us)
    metrics = {
        "sent": sent,
        "received": received,
        "loss_pct": round((sent - received) / sent * 100.0, 3) if sent else None,
        "errors": errors[:10],
        "latency_samples_us": samples_us,
        **{f"rtt_{key}": value for key, value in summary.items()},
    }
    if received == 0:
        return {
            "status": "fail",
            "reason": f"no DNS answers ({', '.join(errors[:3]) or 'timeout'})",
            "command": ["dns", args.dns_server, "target.test", "A"],
            "metrics": metrics,
            "warnings": warnings,
        }, warnings
    if received < sent:
        warnings.append(f"DNS loss {metrics['loss_pct']}% ({sent - received}/{sent})")
    return {
        "status": "ok",
        "reason": None,
        "command": ["dns", args.dns_server, "target.test", "A"],
        "metrics": metrics,
        "warnings": warnings,
    }, warnings


def run_h3(args: argparse.Namespace) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    samples_us: list[float] = []
    codes: list[int] = []
    commands: list[list[str]] = []
    failure = None
    body_path = args.out.with_suffix(args.out.suffix + ".body")
    failures = 0
    attempts_total = 0
    for _ in range(args.count):
        command = []
        request_ok = False
        last_error = None
        for attempt in range(max(1, args.h3_retries)):
            attempts_total += 1
            command = [
                "curl",
                "--http3-only",
                "--insecure",
                "--noproxy",
                "*",
                "-sS",
                "--max-time",
                str(args.max_time),
                "-o",
                str(body_path),
                "-w",
                "%{http_code} %{time_total}\n",
                args.url,
            ]
            commands.append(command)
            try:
                body_path.unlink()
            except FileNotFoundError:
                pass
            completed = _curl(command, timeout=args.max_time + 30)
            if completed.returncode != 0:
                last_error = (
                    f"curl exited {completed.returncode}: "
                    f"{completed.stderr.strip()[-300:]}"
                )
            else:
                parts = completed.stdout.strip().split()
                if len(parts) != 2:
                    last_error = (
                        f"unexpected curl output: "
                        f"{completed.stdout.strip()[:200]}"
                    )
                else:
                    code, seconds = int(parts[0]), float(parts[1])
                    try:
                        body = body_path.read_bytes()
                    except OSError as error:
                        last_error = f"could not read the HTTP/3 body: {error}"
                    else:
                        if code != 200:
                            last_error = f"HTTP/3 status code {code}"
                        elif b"beam-tun-h3-ok" not in body:
                            last_error = f"unexpected HTTP/3 body: {body[:64]!r}"
                        else:
                            codes.append(code)
                            samples_us.append(seconds * 1e6)
                            request_ok = True
                            break
            if attempt + 1 < args.h3_retries:
                time.sleep(max(0, args.h3_gap_ms) / 1000.0)
        if not request_ok:
            failures += 1
            failure = last_error or "HTTP/3 request failed"
            break
        time.sleep(max(0, args.h3_gap_ms) / 1000.0)
    metrics = {
        "codes": codes,
        "attempts": attempts_total,
        "failures": failures,
        "latency_samples_us": samples_us,
        "first_us": samples_us[0] if samples_us else None,
        "excluding_first": latency_summary(samples_us[1:]),
        **{f"rtt_{key}": value for key, value in latency_summary(samples_us).items()},
    }
    if failure:
        return {
            "status": "fail",
            "reason": failure,
            "command": commands[-1] if commands else [],
            "metrics": metrics,
            "warnings": warnings,
        }, warnings
    if len(samples_us) != args.count:
        return {
            "status": "fail",
            "reason": f"completed {len(samples_us)} of {args.count} HTTP/3 requests",
            "command": commands[-1] if commands else [],
            "metrics": metrics,
            "warnings": warnings,
        }, warnings
    return {
        "status": "ok",
        "reason": None,
        "command": commands[-1] if commands else [],
        "metrics": metrics,
        "warnings": warnings,
    }, warnings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", required=True, choices=("stock", "beam"))
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--rep", required=True, type=int)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--server-pid", type=int, default=0)
    parser.add_argument("--client-pid", type=int, default=0)
    parser.add_argument("--target-pid", type=int, default=0)
    parser.add_argument("--server-core", type=int, default=2)
    parser.add_argument("--client-core", type=int, default=1)
    parser.add_argument("--client-cores", default=None,
                        help="comma-separated client proxy cores; defaults to --client-core")
    parser.add_argument("--target-core", type=int, default=3)
    parser.add_argument("--driver-core", type=int, default=0)
    parser.add_argument("--all-cores", type=int, default=os.cpu_count() or 8)
    parser.add_argument(
        "--blocked-reason",
        default=None,
        help="record a BLOCKED result without running the scenario",
    )
    parser.add_argument("--kind", required=True, choices=("iperf3", "https", "udp", "dns", "h3"))
    parser.add_argument("--iperf3-bin", default="iperf3")
    parser.add_argument("--iperf3-port", type=int, default=5201)
    parser.add_argument("--target-host", default="10.10.2.2")
    parser.add_argument("--direction", choices=("download", "upload"), default="download")
    parser.add_argument("--flows", type=int, default=1)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--url", default="https://10.10.2.2:4443/")
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument(
        "--https-parallel",
        type=int,
        default=1,
        help="concurrent HTTPS requests; use >1 only for the fallback-permit probe",
    )
    parser.add_argument("--expected-size", type=int, default=0)
    parser.add_argument("--max-time", type=float, default=30.0)
    parser.add_argument("--host", default="10.10.2.2")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--payload", type=int, default=1200)
    parser.add_argument("--packet-count", type=int, default=5000)
    parser.add_argument("--window", type=int, default=32)
    parser.add_argument("--latency-count", type=int, default=200)
    parser.add_argument("--dns-server", default="10.10.2.2")
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--dns-count", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--h3-retries", type=int, default=3)
    parser.add_argument("--h3-gap-ms", type=int, default=50)
    args = parser.parse_args()
    if args.https_parallel < 1:
        parser.error("--https-parallel must be >= 1")

    run: dict = {
        "schema": "beam-bench-run/1",
        "run_id": args.run_id,
        "arm": args.arm,
        "scenario": args.scenario,
        "rep": args.rep,
        "kind": args.kind,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "ok",
        "reason": None,
        "command": [],
        "parameters": {},
        "elapsed_s": 0.0,
        "metrics": {},
        "cpu": {},
        "mem": {},
        "warnings": [],
    }

    if args.blocked_reason:
        run["status"] = "blocked"
        run["reason"] = args.blocked_reason
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
        print(f"{args.arm} {args.scenario} r{args.rep}: BLOCKED ({args.blocked_reason})")
        return 0

    pids = {
        "server": args.server_pid,
        "client": args.client_pid,
        "target": args.target_pid,
    }
    client_cores = [args.client_core]
    if args.client_cores:
        client_cores = [int(value) for value in args.client_cores.split(",") if value]
    role_cores = {
        "server": args.server_core,
        "client": args.client_core,
        "target": args.target_core,
        "driver": args.driver_core,
    }
    excluded_cores: set[int] = set()
    for core in (
        args.server_core,
        args.target_core,
        args.driver_core,
        *client_cores,
    ):
        excluded_cores |= _smt_siblings(core)
    before = snapshot(pids, role_cores)
    started = time.monotonic()
    try:
        if args.kind == "iperf3":
            outcome, warnings = run_iperf3(args)
        elif args.kind == "https":
            outcome, warnings = run_https(args)
        elif args.kind == "udp":
            outcome, warnings = run_udp(args)
        elif args.kind == "dns":
            outcome, warnings = run_dns(args)
        else:
            outcome, warnings = run_h3(args)
    except subprocess.TimeoutExpired as error:
        outcome = {
            "status": "fail",
            "reason": f"scenario timed out: {error}",
            "command": [],
            "metrics": {},
            "warnings": [],
        }
        warnings = []
    except Exception as error:  # noqa: BLE001 - report unexpected harness failures
        outcome = {
            "status": "fail",
            "reason": f"{type(error).__name__}: {error}",
            "command": [],
            "metrics": {},
            "warnings": [],
        }
        warnings = []
    elapsed = time.monotonic() - started
    after = snapshot(pids, role_cores)

    run.update(
        {
            "status": outcome["status"],
            "reason": outcome.get("reason"),
            "command": outcome.get("command", []),
            "metrics": outcome.get("metrics", {}),
            "warnings": warnings,
            "elapsed_s": round(elapsed, 3),
        }
    )

    server_before = before["pids"].get("server")
    server_after = after["pids"].get("server")
    client_before = before["pids"].get("client")
    client_after = after["pids"].get("client")
    target_before = before["pids"].get("target")
    target_after = after["pids"].get("target")

    def cpu_seconds(first: dict | None, last: dict | None) -> float | None:
        if not first or not last:
            return None
        return round((last["cpu_ticks"] - first["cpu_ticks"]) / CLK_TCK, 4)

    server_cpu = cpu_seconds(server_before, server_after)
    client_cpu = cpu_seconds(client_before, client_after)
    target_cpu = cpu_seconds(target_before, target_after)
    bytes_total = int(run["metrics"].get("bytes") or 0)

    run["cpu"] = {
        "server_s": server_cpu,
        "client_s": client_cpu,
        "target_s": target_cpu,
        "server_core_busy_pct": _cpu_delta(before["cpu"], after["cpu"], args.server_core),
        "client_core_busy_pct": max(
            (
                value
                for core in client_cores
                if (value := _cpu_delta(before["cpu"], after["cpu"], core))
                is not None
            ),
            default=None,
        ),
        "client_core_busy_pct_avg": (
            round(
                sum(
                    value
                    for core in client_cores
                    if (value := _cpu_delta(before["cpu"], after["cpu"], core))
                    is not None
                )
                / len(client_cores),
                2,
            )
            if client_cores
            else None
        ),
        "client_cores": client_cores,
        # The driver runs under `ip netns exec`, which remounts /sys and hides
        # the cgroup2 mount, so the harness passes the readback values instead
        # of letting this process chase /sys/fs/cgroup.
        "server_cpu_max": os.environ.get("BENCH_SERVER_CPU_MAX") or None,
        "server_cpu_max_harness": os.environ.get("BENCH_SERVER_CPU_MAX") or None,
        "server_memory_max": os.environ.get("BENCH_SERVER_MEMORY_MAX") or None,
        "server_memory_peak": os.environ.get("BENCH_SERVER_MEMORY_PEAK") or None,
        "server_memory_max_harness": os.environ.get("BENCH_SERVER_MEMORY_MAX") or None,
        "target_core_busy_pct": _cpu_delta(before["cpu"], after["cpu"], args.target_core),
        "driver_core_busy_pct": _cpu_delta(before["cpu"], after["cpu"], args.driver_core),
        "non_role_core_busy_pct_max": max(
            (
                value
                for core in range(args.all_cores)
                if core not in excluded_cores
                if (value := _cpu_delta(before["cpu"], after["cpu"], core)) is not None
            ),
            default=None,
        ),
        "server_core_mhz_before": before["mhz"].get("server"),
        "server_core_mhz_after": after["mhz"].get("server"),
        "client_core_mhz_before": before["mhz"].get("client"),
        "client_core_mhz_after": after["mhz"].get("client"),
        "target_core_mhz_before": before["mhz"].get("target"),
        "target_core_mhz_after": after["mhz"].get("target"),
        "driver_core_mhz_before": before["mhz"].get("driver"),
        "driver_core_mhz_after": after["mhz"].get("driver"),
    }
    if server_cpu is not None and bytes_total > 0:
        run["cpu"]["server_s_per_gib"] = round(server_cpu / (bytes_total / GIB), 4)
    if client_cpu is not None and bytes_total > 0:
        run["cpu"]["client_s_per_gib"] = round(client_cpu / (bytes_total / GIB), 4)

    if args.kind == "https":
        run["parameters"]["https_parallel"] = args.https_parallel
    run["mem"] = {
        "rss_after_warmup_kib": (server_before or {}).get("rss_kib"),
        "rss_kib": (server_after or {}).get("rss_kib"),
        "hwm_kib": (server_after or {}).get("hwm_kib"),
        "fds": (server_after or {}).get("fds"),
        "threads": (server_after or {}).get("threads"),
        "client_rss_kib": (client_after or {}).get("rss_kib"),
        "client_threads": (client_after or {}).get("threads"),
        "client_fds": (client_after or {}).get("fds"),
    }
    run["host_load1_before"] = before["load1"]
    run["host_load1_after"] = after["load1"]

    client_busy = run["cpu"].get("client_core_busy_pct")
    target_busy = run["cpu"].get("target_core_busy_pct")
    driver_busy = run["cpu"].get("driver_core_busy_pct")
    if client_busy is not None and client_busy >= 85:
        run["warnings"].append(f"client core saturated ({client_busy}%)")
        run["client_bound"] = True
    if target_busy is not None and target_busy >= 85:
        run["warnings"].append(f"target core saturated ({target_busy}%)")
        run["target_bound"] = True
    if (
        driver_busy is not None
        and driver_busy >= 85
        and args.driver_core not in client_cores
    ):
        run["warnings"].append(f"driver core saturated ({driver_busy}%)")
        run["driver_bound"] = True
    non_role = run["cpu"].get("non_role_core_busy_pct_max")
    if non_role is not None and non_role > 5:
        run["warnings"].append(f"non-role CPU busy ({non_role}%)")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
    throughput = run["metrics"].get("throughput_bps")
    detail = ""
    if throughput:
        detail = f" {throughput / 1e6:.1f} Mbit/s"
    elif "mib_per_s" in run["metrics"]:
        detail = f" {run['metrics']['mib_per_s']:.1f} MiB/s"
    elif "pps" in run["metrics"]:
        detail = f" {run['metrics']['pps']:.0f} pps"
    print(
        f"{args.arm} {args.scenario} r{args.rep}: {run['status'].upper()}{detail}"
        + (f" ({run['reason']})" if run["reason"] else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
