#!/usr/bin/env python3
"""Write the session manifest for a local benchmark run.

Only metadata and hashes are captured: no key material, no UUIDs, no packet
contents. The manifest is small enough to keep with the summary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path


def sha256(path: Path) -> str | None:
    if not path or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(command: list[str], cwd: Path | None = None) -> str | None:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def cpu_info() -> dict:
    model = None
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    siblings: dict[str, str] = {}
    for core in range(os.cpu_count() or 1):
        path = Path(f"/sys/devices/system/cpu/cpu{core}/topology/thread_siblings_list")
        try:
            siblings[str(core)] = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    try:
        load = Path("/proc/loadavg").read_text(encoding="utf-8").split()
    except OSError:
        load = []
    return {
        "model": model,
        "logical_cpus": os.cpu_count(),
        "thread_siblings": siblings,
        "loadavg": load[:3],
    }


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_qdisc_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    qdisc = data[0] if isinstance(data, list) and data else data
    if not isinstance(qdisc, dict):
        return None
    options = qdisc.get("options") or {}
    stats = qdisc.get("stats")
    if not isinstance(stats, dict):
        # `tc -j -s qdisc` puts counters at the top level of the qdisc object.
        stats = qdisc
    delay = (options.get("delay") or {}).get("delay")
    loss = (options.get("loss-random") or {}).get("loss")
    return {
        "source": "json",
        "kind": qdisc.get("kind"),
        "delay_ms": None if delay is None else round(float(delay) * 1000, 6),
        "loss_pct": None if loss is None else round(float(loss) * 100, 6),
        "drops": _int_or_none(stats.get("drops")),
        "overlimits": _int_or_none(stats.get("overlimits")),
        "qlen": _int_or_none(stats.get("qlen")),
        "backlog": _int_or_none(stats.get("backlog")),
    }


def parse_qdisc_text(path: Path) -> dict | None:
    try:
        # `tc -s qdisc show` prints counts like "dropped 123,".
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if "netem" not in text:
        return None
    result = {
        "source": "text",
        "kind": "netem",
        "delay_ms": None,
        "loss_pct": None,
        "drops": None,
        "overlimits": None,
        "qlen": None,
        "backlog": None,
    }
    delay = re.search(r"\bdelay\s+([0-9.]+)ms", text)
    if delay:
        result["delay_ms"] = float(delay.group(1))
    loss = re.search(r"\bloss\s+([0-9.]+)%", text)
    if loss:
        result["loss_pct"] = float(loss.group(1))
    drops = re.search(r"\bdropped\s+([0-9,]+)", text)
    if drops:
        result["drops"] = _int_or_none(drops.group(1).replace(",", ""))
    overlimits = re.search(r"\boverlimits\s+([0-9]+)", text)
    if overlimits:
        result["overlimits"] = _int_or_none(overlimits.group(1))
    return result


def qdisc_evidence(log_dir: Path | None) -> dict:
    if log_dir is None:
        return {}
    result: dict[str, dict] = {}
    for role in ("client", "server"):
        # Drops accumulate during the run, so the final dump is the counter
        # source; the initial dump is the fallback when the run never finished.
        parsed = parse_qdisc_json(log_dir / f"tc-{role}-final.json")
        if parsed is None:
            parsed = parse_qdisc_json(log_dir / f"tc-{role}-initial.json")
        if parsed is None:
            parsed = parse_qdisc_text(log_dir / f"tc-{role}-final.txt")
        if parsed is None:
            parsed = parse_qdisc_text(log_dir / f"tc-{role}.txt")
        result[role] = parsed or {"source": "unavailable"}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--finished-at", required=True)
    parser.add_argument("--arms", required=True)
    parser.add_argument("--reps", required=True, type=int)
    parser.add_argument("--duration", required=True, type=int)
    parser.add_argument("--server-cpu", required=True, type=int)
    parser.add_argument("--client-cpu", required=True, type=int)
    parser.add_argument("--client-cpus", default=None)
    parser.add_argument("--target-cpu", required=True, type=int)
    parser.add_argument("--driver-cpu", required=True, type=int)
    parser.add_argument("--rtt-ms", required=True, type=int)
    parser.add_argument("--loss", type=float, default=0.0)
    parser.add_argument("--max-load", type=float, default=0.3)
    parser.add_argument("--qdisc-logs", type=Path, default=None)
    parser.add_argument("--server-mask", default=None)
    parser.add_argument("--client-mask", default=None)
    parser.add_argument("--target-mask", default=None)
    parser.add_argument("--beam-bin", type=Path, default=None)
    parser.add_argument("--stock-bin", type=Path, default=None)
    parser.add_argument("--singbox", type=Path, default=None)
    parser.add_argument("--iperf3", type=Path, default=None)
    parser.add_argument("--h3-origin", type=Path, default=None)
    parser.add_argument("--large-file", type=Path, default=None)
    parser.add_argument("--h3-blocked-reason", default=None)
    parser.add_argument("--host-load-before", type=float, default=None)
    parser.add_argument("--host-load-after", type=float, default=None)
    parser.add_argument("--warning", action="append", default=[])
    args = parser.parse_args()

    worktree = Path(__file__).resolve().parent.parent
    commit = command_output(["git", "rev-parse", "HEAD"], cwd=worktree)
    status = command_output(["git", "status", "--porcelain"], cwd=worktree)
    kernel = command_output(["uname", "-srmo"])
    info = cpu_info()
    large = None
    if args.large_file and args.large_file.is_file():
        large = {
            "path": str(args.large_file),
            "bytes": args.large_file.stat().st_size,
            "sha256": sha256(args.large_file),
        }
    versions = {
        "rustc": command_output(["rustc", "--version"]),
        "cargo": command_output(["cargo", "--version"]),
        "go": command_output(["go", "version"]),
        "python": platform.python_version(),
        "singbox": command_output([str(args.singbox), "version"]) if args.singbox else None,
        "stock": command_output([str(args.stock_bin), "version"]) if args.stock_bin else None,
        "iperf3": command_output([str(args.iperf3), "--version"]) if args.iperf3 else None,
        "curl": command_output(["curl", "--version"]),
    }
    meta = {
        "schema": "beam-bench-meta/1",
        "run_id": args.run_id,
        "started_at": args.started_at,
        "finished_at": args.finished_at,
        "worktree": str(worktree),
        "git": {"commit": commit, "dirty": bool(status)},
        "kernel": kernel,
        "host": info,
        "cpu_roles": {
            "server": args.server_cpu,
            "client": args.client_cpu,
            "client_cores": (
                [int(value) for value in args.client_cpus.split(",") if value]
                if args.client_cpus
                else [args.client_cpu]
            ),
            "target": args.target_cpu,
            "driver": args.driver_cpu,
            "free": [
                core
                for core in range(info.get("logical_cpus") or 0)
                if core
                not in (
                    args.server_cpu,
                    args.target_cpu,
                    args.driver_cpu,
                    *(
                        [int(value) for value in args.client_cpus.split(",") if value]
                        if args.client_cpus
                        else [args.client_cpu]
                    ),
                )
            ],
            "masks": {
                "server": args.server_mask,
                "client": args.client_mask,
                "target": args.target_mask,
            },
        },
        "arms": args.arms.split(","),
        "reps": args.reps,
        "duration_s": args.duration,
        "rtt_ms": args.rtt_ms,
        "loss_pct": args.loss,
        "bench_max_load": args.max_load,
        "qdisc": qdisc_evidence(args.qdisc_logs),
        "host_load1_before": args.host_load_before,
        "host_load1_after": args.host_load_after,
        "binaries": {
            "beam": {
                "path": str(args.beam_bin) if args.beam_bin else None,
                "sha256": sha256(args.beam_bin) if args.beam_bin else None,
            },
            "stock": {
                "path": str(args.stock_bin) if args.stock_bin else None,
                "sha256": sha256(args.stock_bin) if args.stock_bin else None,
            },
            "singbox": {
                "path": str(args.singbox) if args.singbox else None,
                "sha256": sha256(args.singbox) if args.singbox else None,
            },
            "iperf3": {
                "path": str(args.iperf3) if args.iperf3 else None,
                "sha256": sha256(args.iperf3) if args.iperf3 else None,
            },
            "h3_origin": {
                "path": str(args.h3_origin) if args.h3_origin else None,
                "sha256": sha256(args.h3_origin) if args.h3_origin else None,
            },
        },
        "versions": versions,
        "large_file": large,
        "h3": {
            "available": args.h3_blocked_reason is None,
            "blocked_reason": args.h3_blocked_reason,
        },
        "warnings": args.warning,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
