#!/usr/bin/env python3
"""Acceptance gate for the hosted paired production rehearsal."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

from report import REQUIRED, TCP_SCENARIOS, load_results

ARMS = ("baseline", "beam")
REPS = (1, 2, 3)
MEMORY_MAX = 768 * 1024 * 1024
CPU_MAX = "50000 100000"


def failures(summary: dict, results: list[dict], resource_rows: str) -> list[str]:
    problems = []
    if summary.get("headline_eligible") is not True or summary.get("valid") is not True:
        detail = (summary.get("invalid_reasons") or []) + (summary.get("host_noise") or [])
        problems.append("benchmark evidence invalid or noisy: " + ", ".join(detail))
    if (summary.get("reference_arm"), summary.get("candidate_arm")) != ARMS:
        problems.append("benchmark arms must be baseline and beam")
    if summary.get("meta", {}).get("reps") != len(REPS):
        problems.append("benchmark requires three repetitions")

    comparisons = summary.get("comparisons", {})
    throughput = {
        scenario: comparisons.get(scenario, {}).get("ratio")
        for scenario in (*TCP_SCENARIOS, "https-bulk")
    }
    for scenario, value in throughput.items():
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0.98:
            problems.append(f"{scenario}: throughput ratio {value!r}, expected >= 0.98")
    for scenario in ("dns-a", "h3-latency", "udp-echo"):
        entry = comparisons.get("latency", {}).get(scenario, {})
        for percentile in ("p50", "p95", "p99"):
            value = entry.get(f"{percentile}_ratio")
            if not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 1.02:
                problems.append(f"{scenario}: {percentile} ratio {value!r}, expected <= 1.02")

    for arm in ARMS:
        for rep in REPS:
            for scenario in (*REQUIRED, "h3-latency"):
                label = f"{arm}/{rep}/{scenario}"
                rows = [
                    item for item in results
                    if (item.get("arm"), item.get("rep"), item.get("scenario")) == (arm, rep, scenario)
                ]
                if len(rows) != 1 or rows[0].get("status") != "ok":
                    problems.append(f"{label}: expected exactly one successful result")
                    continue
                row = rows[0]
                cpu = row.get("cpu", {})
                if cpu.get("server_cpu_max") != CPU_MAX or cpu.get("server_memory_max") != str(MEMORY_MAX):
                    problems.append(f"{label}: missing expected CPU or memory limit readback")
                metrics = row.get("metrics", {})
                if scenario in ("dns-a", "udp-echo"):
                    sent = metrics.get("sent")
                    if not isinstance(sent, int) or sent <= 0 or sent != metrics.get("received"):
                        problems.append(f"{label}: expected all UDP requests to receive a reply")
                if scenario == "dns-a":
                    planned = metrics.get("planned")
                    if type(planned) is not int or planned <= 0 or planned != metrics.get("sent"):
                        problems.append(
                            f"{label}: planned {planned!r} != sent {metrics.get('sent')!r}"
                        )
                    if metrics.get("errors") != []:
                        problems.append(f"{label}: DNS errors {metrics.get('errors')!r}")
                if scenario in ("dns-a", "h3-latency", "udp-echo"):
                    key = "rtt_samples_us" if scenario == "udp-echo" else "latency_samples_us"
                    samples = metrics.get(key, [])
                    if not samples or any(
                        not isinstance(sample, (int, float)) or not math.isfinite(sample) or sample <= 0
                        for sample in samples
                    ):
                        problems.append(f"{label}: missing or invalid latency samples")
                    count_key = {
                        "dns-a": "sent",
                        "h3-latency": "attempts",
                        "udp-echo": "latency_sent",
                    }[scenario]
                    if metrics.get(count_key) != len(samples):
                        problems.append(f"{label}: retries or incomplete latency samples")

            scope_rows = []
            for line in resource_rows.splitlines():
                fields = line.split("\t")
                if len(fields) == 5 and fields[:3] == [arm, str(rep), "server-resources"]:
                    scope_rows.append(dict(field.split("=", 1) for field in fields[4].split() if "=" in field))
            if len(scope_rows) != 1:
                problems.append(f"{arm}/{rep}: expected one server resource sample")
                continue
            scope = scope_rows[0]
            peak = scope.get("memory_peak", "")
            if (
                scope.get("memory_max") != str(MEMORY_MAX)
                or not peak.isdecimal()
                or not 0 < int(peak) <= MEMORY_MAX
                or scope.get("oom") != "0"
                or scope.get("oom_kill") != "0"
            ):
                problems.append(f"{arm}/{rep}: invalid memory or OOM evidence: {scope}")

    qdisc = summary.get("meta", {}).get("qdisc") or {}
    for role in ("client", "server"):
        info = qdisc.get(role) or {}
        drops = info.get("drops")
        if info.get("final") is not True or type(drops) is not int:
            problems.append(
                f"{role}: no final netem counters "
                f"(source={info.get('source')!r}, final={info.get('final')!r}, drops={drops!r})"
            )

    return problems


def main() -> int:
    run_dir = Path(sys.argv[1])
    try:
        summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
        resources = (run_dir / "masks.tsv").read_text(encoding="utf-8")
    except (OSError, ValueError) as error:
        print(f"::error::missing or invalid preprod evidence: {error}", file=sys.stderr)
        return 1
    problems = failures(summary, load_results(run_dir), resources)
    for problem in problems:
        print(f"::error::{problem}", file=sys.stderr)
    if not problems:
        print("Preprod benchmark passed throughput, latency, delivery and server resource gates")
    return int(bool(problems))


if __name__ == "__main__":
    sys.exit(main())
