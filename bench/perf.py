#!/usr/bin/env python3
"""Parse the `perf stat -x,` CSV files written next to the bench raw JSON.

The harness writes `raw/<arm>-<scenario>-r<rep>.json.perf.csv` when BENCH_PERF=1.
The report consumes medians per arm/scenario/event so a paired cell can compare
the reference and candidate binaries on the same runner.
"""

from __future__ import annotations

import re
from pathlib import Path

_NAME = re.compile(
    r"^(?P<arm>[a-z]+)-(?P<scenario>[a-z0-9-]+)-r(?P<rep>[0-9]+)\.json\.perf\.csv$"
)


def load_perf(run_dir: Path) -> dict[str, dict[str, dict[str, list[float]]]]:
    """Return `{arm: {scenario: {event: [values]}}}` from the raw CSV evidence."""
    raw = Path(run_dir) / "raw"
    out: dict[str, dict[str, dict[str, list[float]]]] = {}
    if not raw.is_dir():
        return out
    for path in sorted(raw.glob("*.json.perf.csv")):
        match = _NAME.match(path.name)
        if match is None:
            continue
        arm = match.group("arm")
        scenario = match.group("scenario")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(",")
            if len(fields) < 3:
                continue
            value = fields[0].strip()
            event = fields[2].strip()
            if not event or value.startswith("<"):
                continue
            try:
                number = float(value)
            except ValueError:
                continue
            out.setdefault(arm, {}).setdefault(scenario, {}).setdefault(
                event, []
            ).append(number)
    return out


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def summarize(
    perf: dict[str, dict[str, dict[str, list[float]]]],
    reference: str,
    candidate: str,
) -> dict[str, dict[str, dict[str, float | None]]]:
    """Return `{scenario: {event: {reference, candidate, ratio}}}` medians."""
    scenarios = set(perf.get(reference, {})) | set(perf.get(candidate, {}))
    summary: dict[str, dict[str, dict[str, float | None]]] = {}
    for scenario in sorted(scenarios):
        events = set(perf.get(reference, {}).get(scenario, {})) | set(
            perf.get(candidate, {}).get(scenario, {})
        )
        entry: dict[str, dict[str, float | None]] = {}
        for event in sorted(events):
            ref = _median(perf.get(reference, {}).get(scenario, {}).get(event, []))
            cand = _median(perf.get(candidate, {}).get(scenario, {}).get(event, []))
            item: dict[str, float | None] = {"reference": ref, "candidate": cand}
            if ref not in (None, 0.0) and cand is not None:
                item["ratio"] = round(cand / ref, 4)
            entry[event] = item
        summary[scenario] = entry
    return summary
