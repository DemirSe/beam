#!/usr/bin/env python3
"""Aggregate benchmark runs into summary.json and summary.md.

The report is deliberately conservative:

* throughput and latency use the median of the per-repetition values,
* latency percentiles pool the raw samples from every repetition,
* a scenario whose client or target core exceeded 85% is marked
  client-bound/target-bound and makes the measurement invalid for the headline,
* a missing or failed scenario is never replaced by a guessed value: it is
  reported as BLOCKED or FAIL with the exact reason.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path

TCP_SCENARIOS = ("tcp-dl-1", "tcp-dl-4", "tcp-ul-1", "tcp-ul-4")
REQUIRED = TCP_SCENARIOS + ("https-bulk", "udp-echo", "dns-a")
LATENCY_SCENARIOS = ("dns-a", "h3-latency", "udp-echo")

SCENARIO_META = {
    "tcp-dl-1": {"label": "TCP download, 1 flow", "unit": "Mbit/s"},
    "tcp-dl-4": {"label": "TCP download, 4 flows", "unit": "Mbit/s"},
    "tcp-ul-1": {"label": "TCP upload, 1 flow", "unit": "Mbit/s"},
    "tcp-ul-4": {"label": "TCP upload, 4 flows", "unit": "Mbit/s"},
    "https-bulk": {"label": "HTTPS Vision Direct, 64 MiB", "unit": "MiB/s"},
    "udp-echo": {"label": "UDP echo", "unit": "kpps"},
    "dns-a": {"label": "DNS A over UDP", "unit": "ms"},
    "h3-latency": {"label": "QUIC/HTTP3 requests", "unit": "ms"},
}


def load_meta(run_dir: Path) -> dict:
    path = run_dir / "meta.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def load_results(run_dir: Path) -> list[dict]:
    results = []
    for path in sorted((run_dir / "raw").glob("*.json")):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if result.get("schema") == "beam-bench-run/1":
            results.append(result)
    return results


def stats(values: list[float]) -> dict | None:
    if not values:
        return None
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "median": statistics.median(ordered),
        "min": ordered[0],
        "max": ordered[-1],
    }


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(pct / 100.0 * (len(ordered) - 1)))))
    return ordered[index]


def by_arm(results: list[dict], scenario: str) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for result in results:
        if result.get("scenario") != scenario:
            continue
        grouped.setdefault(result.get("arm", "?"), []).append(result)
    for arm in grouped:
        grouped[arm].sort(key=lambda item: item.get("rep", 0))
    return grouped


def ok(results: list[dict]) -> list[dict]:
    return [item for item in results if item.get("status") == "ok"]


def scenario_values(
    results: list[dict], scenario: str, arm: str, extract
) -> list[float]:
    values: list[float] = []
    for result in ok(by_arm(results, scenario).get(arm, [])):
        value = extract(result)
        if value is not None:
            values.append(value)
    return values


def scenario_stats(results: list[dict], scenario: str, arm: str, extract) -> dict | None:
    return stats(scenario_values(results, scenario, arm, extract))


def pooled_latency(results: list[dict], scenario: str, arm: str) -> list[float]:
    samples: list[float] = []
    for result in ok(by_arm(results, scenario).get(arm, [])):
        metrics = result.get("metrics", {})
        key = "rtt_samples_us" if scenario == "udp-echo" else "latency_samples_us"
        samples.extend(float(value) for value in metrics.get(key, []))
    return samples


def fmt_value(value: float | None, unit: str | None = None) -> str:
    if value is None:
        return "n/a"
    if unit == "MiB/s":
        return f"{value:,.1f} MiB/s"
    if unit == "Mbit/s":
        return f"{value:,.1f} Mbit/s"
    if unit == "kpps":
        return f"{value:,.2f} kpps"
    if unit == "ms":
        return f"{value:,.3f} ms"
    if unit == "s/GiB":
        return f"{value:,.3f} s/GiB"
    if unit == "MiB":
        return f"{value:,.1f} MiB"
    if unit == "%":
        return f"{value:,.2f}%"
    return f"{value:,.2f}"


def fmt_stats(value: dict | None, unit: str | None = None) -> str:
    if value is None:
        return "n/a"
    return (
        f"{fmt_value(value['median'], unit)} "
        f"({fmt_value(value['min'])}–{fmt_value(value['max'])})"
    )


def fmt_ratio(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}x"


def ratio(beam: dict | None, stock: dict | None) -> float | None:
    if not beam or not stock or not stock.get("median"):
        return None
    return beam["median"] / stock["median"]


def gate_row(
    label: str,
    stock: dict | None,
    beam: dict | None,
    unit: str | None,
    comparison: float | None,
    requirement: str,
    passed: bool | None,
) -> dict:
    return {
        "label": label,
        "stock": fmt_stats(stock, unit),
        "beam": fmt_stats(beam, unit),
        "ratio": fmt_ratio(comparison),
        "requirement": requirement,
        "pass": passed,
    }


def geomean(values: list[float]) -> float | None:
    if not values or any(value <= 0 for value in values):
        return None
    return math.exp(sum(math.log(value) for value in values) / len(values))


def status_word(passed: bool | None, informational: bool = False) -> str:
    if passed is None:
        return "INFO" if informational else "BLOCKED"
    return "PASS" if passed else "FAIL"


def row_status(row: dict) -> str:
    if row.get("invalid"):
        return "INVALID"
    return status_word(row.get("pass"), bool(row.get("informational")))


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def build(run_dir: Path) -> dict:
    meta = load_meta(run_dir)
    results = load_results(run_dir)
    if meta.get("large_file"):
        mib = meta["large_file"].get("bytes", 0) / 1048576.0
        SCENARIO_META["https-bulk"]["label"] = f"HTTPS Vision Direct, {mib:.0f} MiB"
    arms_present = sorted({item.get("arm") for item in results if item.get("arm")})
    arms = [arm for arm in ("stock", "beam") if arm in arms_present]
    if not arms:
        raise SystemExit(f"no benchmark results under {run_dir / 'raw'}")

    comparisons: dict[str, dict] = {}
    rows: dict[str, list[dict]] = {
        "throughput": [],
        "latency": [],
        "udp": [],
        "resources": [],
    }
    blocked: list[dict] = []
    failed: list[dict] = []

    # Collect statuses once so blocked/failed rows are explicit.
    for scenario in SCENARIO_META:
        grouped = by_arm(results, scenario)
        for arm in ("stock", "beam"):
            for result in grouped.get(arm, []):
                status = result.get("status")
                if status == "blocked":
                    blocked.append(
                        {
                            "scenario": scenario,
                            "arm": arm,
                            "rep": result.get("rep"),
                            "reason": result.get("reason") or "blocked",
                        }
                    )
                elif status == "fail":
                    failed.append(
                        {
                            "scenario": scenario,
                            "arm": arm,
                            "rep": result.get("rep"),
                            "reason": result.get("reason") or "failed",
                        }
                    )

    # A saturated client/target makes the throughput number a property of the
    # harness, not of the server. Such a scenario is reported, but it cannot
    # pass a gate.
    invalid_scenarios: set[str] = set()
    for result in results:
        if result.get("scenario") not in TCP_SCENARIOS + ("https-bulk",):
            continue
        if result.get("status") != "ok":
            continue
        if (
            result.get("client_bound")
            or result.get("target_bound")
            or result.get("driver_bound")
        ):
            invalid_scenarios.add(result["scenario"])

    # --- Throughput -------------------------------------------------------
    tcp_ratios: dict[str, float | None] = {}
    for scenario in TCP_SCENARIOS:
        stock = scenario_stats(
            results, scenario, "stock", lambda item: item["metrics"]["throughput_bps"]
        )
        beam = scenario_stats(
            results, scenario, "beam", lambda item: item["metrics"]["throughput_bps"]
        )
        current = ratio(beam, stock)
        tcp_ratios[scenario] = current
        comparisons[scenario] = {
            "stock": stock,
            "beam": beam,
            "ratio": current,
            "unit": "Mbit/s",
        }
        scale = lambda value: value / 1e6  # noqa: E731 - local formatting only
        stock_m = stats([scale(value) for value in scenario_values(
            results, scenario, "stock", lambda item: item["metrics"]["throughput_bps"]
        )])
        beam_m = stats([scale(value) for value in scenario_values(
            results, scenario, "beam", lambda item: item["metrics"]["throughput_bps"]
        )])
        gate = 1.15 if scenario in ("tcp-dl-1", "tcp-ul-1") else 1.10
        invalid = scenario in invalid_scenarios
        passed = None if invalid or current is None else current >= gate
        row = gate_row(
            SCENARIO_META[scenario]["label"],
            stock_m,
            beam_m,
            "Mbit/s",
            current,
            f">= {gate:.2f}x",
            passed,
        )
        row["invalid"] = invalid
        rows["throughput"].append(row)

    https_stock = scenario_stats(
        results, "https-bulk", "stock", lambda item: item["metrics"].get("mib_per_s")
    )
    https_beam = scenario_stats(
        results, "https-bulk", "beam", lambda item: item["metrics"].get("mib_per_s")
    )
    https_ratio = ratio(https_beam, https_stock)
    comparisons["https-bulk"] = {
        "stock": https_stock,
        "beam": https_beam,
        "ratio": https_ratio,
        "unit": "MiB/s",
    }
    https_invalid = "https-bulk" in invalid_scenarios
    https_row = gate_row(
        SCENARIO_META["https-bulk"]["label"],
        https_stock,
        https_beam,
        "MiB/s",
        https_ratio,
        ">= 0.98x (no regression)",
        None if https_invalid or https_ratio is None else https_ratio >= 0.98,
    )
    https_row["invalid"] = https_invalid
    rows["throughput"].append(https_row)

    # --- Latency ----------------------------------------------------------
    latency_comparisons: dict[str, dict] = {}
    for scenario in LATENCY_SCENARIOS:
        stock_samples = pooled_latency(results, scenario, "stock")
        beam_samples = pooled_latency(results, scenario, "beam")
        entry = {
            "stock": latency_stats(stock_samples),
            "beam": latency_stats(beam_samples),
            "samples": {"stock": len(stock_samples), "beam": len(beam_samples)},
        }
        for percentile_name in ("p50", "p95", "p99"):
            stock_value = entry["stock"].get(percentile_name)
            beam_value = entry["beam"].get(percentile_name)
            entry[f"{percentile_name}_ratio"] = (
                beam_value / stock_value
                if stock_value and beam_value is not None
                else None
            )
        latency_comparisons[scenario] = entry
        gated = scenario in ("dns-a", "h3-latency")
        for percentile_name in ("p50", "p95", "p99"):
            stock_value = entry["stock"].get(percentile_name)
            beam_value = entry["beam"].get(percentile_name)
            current = entry[f"{percentile_name}_ratio"]
            is_gate = gated and percentile_name == "p99"
            rows["latency"].append(
                {
                    "label": f"{SCENARIO_META[scenario]['label']} {percentile_name}",
                    "stock": f"{stock_value:,.3f} ms" if stock_value is not None else "n/a",
                    "beam": f"{beam_value:,.3f} ms" if beam_value is not None else "n/a",
                    "ratio": fmt_ratio(current),
                    "requirement": "<= 1.00x" if is_gate else "informational",
                    "pass": None
                    if current is None or not is_gate
                    else current <= 1.0,
                    "informational": not is_gate,
                }
            )
    comparisons["latency"] = latency_comparisons

    # --- UDP --------------------------------------------------------------
    udp_metrics = {
        "pps": ("UDP echo packet rate", "kpps", lambda item: item["metrics"]["pps"] / 1000.0),
        "mbps": ("UDP echo throughput", "Mbit/s", lambda item: item["metrics"]["mbps"]),
        "loss_pct": ("UDP echo loss", "%", lambda item: item["metrics"]["loss_pct"]),
    }
    udp_comparisons: dict[str, dict] = {}
    for key, (label, unit, extract) in udp_metrics.items():
        stock = scenario_stats(results, "udp-echo", "stock", extract)
        beam = scenario_stats(results, "udp-echo", "beam", extract)
        current = ratio(beam, stock)
        udp_comparisons[key] = {"stock": stock, "beam": beam, "ratio": current}
        if key == "loss_pct":
            passed = None
            requirement = "informational"
        else:
            passed = None if current is None else current >= 0.98
            requirement = ">= 0.98x (no regression)"
        rows["udp"].append(
            {
                "label": label,
                "stock": fmt_stats(stock, unit),
                "beam": fmt_stats(beam, unit),
                "ratio": fmt_ratio(current),
                "requirement": requirement,
                "pass": passed,
                "informational": key == "loss_pct",
            }
        )
    comparisons["udp"] = udp_comparisons

    # --- Resources --------------------------------------------------------
    cpu_ratios: dict[str, float | None] = {}
    for scenario in TCP_SCENARIOS:
        stock = scenario_stats(
            results, scenario, "stock", lambda item: item["cpu"].get("server_s_per_gib")
        )
        beam = scenario_stats(
            results, scenario, "beam", lambda item: item["cpu"].get("server_s_per_gib")
        )
        current = ratio(beam, stock)
        cpu_ratios[scenario] = current
        rows["resources"].append(
            {
                "label": f"Server CPU per GiB, {SCENARIO_META[scenario]['label']}",
                "stock": fmt_stats(stock, "s/GiB"),
                "beam": fmt_stats(beam, "s/GiB"),
                "ratio": fmt_ratio(current),
                "requirement": "< 1.00x",
                "pass": None if current is None else current < 1.0,
            }
        )

    rss = {}
    for arm in ("stock", "beam"):
        arm_results = [
            item
            for item in results
            if item.get("arm") == arm and item.get("status") == "ok"
        ]
        warm = [item["mem"].get("rss_after_warmup_kib") for item in arm_results]
        warm = [value for value in warm if isinstance(value, int) and value > 0]
        peak = [item["mem"].get("rss_kib") for item in arm_results]
        peak = [value for value in peak if isinstance(value, int) and value > 0]
        rss[arm] = {
            "after_warmup_median_kib": statistics.median(warm) if warm else None,
            "after_warmup_max_kib": max(warm) if warm else None,
            "peak_max_kib": max(peak) if peak else None,
            "fds_max": max(
                (item["mem"].get("fds", -1) for item in arm_results), default=None
            ),
            "threads_max": max(
                (item["mem"].get("threads", -1) for item in arm_results), default=None
            ),
            "client_rss_max_kib": max(
                (
                    item["mem"].get("client_rss_kib", -1)
                    for item in arm_results
                    if item["mem"].get("client_rss_kib", -1) > 0
                ),
                default=None,
            ),
        }
    rss_ratio = None
    if (
        rss.get("stock", {}).get("after_warmup_max_kib")
        and rss.get("beam", {}).get("after_warmup_max_kib")
    ):
        rss_ratio = rss["beam"]["after_warmup_max_kib"] / rss["stock"]["after_warmup_max_kib"]
    https_cpu_stock = scenario_stats(
        results, "https-bulk", "stock", lambda item: item["cpu"].get("server_s_per_gib")
    )
    https_cpu_beam = scenario_stats(
        results, "https-bulk", "beam", lambda item: item["cpu"].get("server_s_per_gib")
    )
    rows["resources"].append(
        {
            "label": "Server CPU per GiB, HTTPS Vision Direct",
            "stock": fmt_stats(https_cpu_stock, "s/GiB"),
            "beam": fmt_stats(https_cpu_beam, "s/GiB"),
            "ratio": fmt_ratio(ratio(https_cpu_beam, https_cpu_stock)),
            "requirement": "informational",
            "pass": None,
            "informational": True,
        }
    )
    client_cpu = {}
    for arm in ("stock", "beam"):
        medians = []
        for scenario in TCP_SCENARIOS:
            value = scenario_stats(
                results,
                scenario,
                arm,
                lambda item: item["cpu"].get("client_s_per_gib"),
            )
            if value:
                medians.append(value["median"])
        client_cpu[arm] = statistics.median(medians) if medians else None
    client_cpu_ratio = None
    if client_cpu.get("stock") and client_cpu.get("beam"):
        client_cpu_ratio = client_cpu["beam"] / client_cpu["stock"]
    rows["resources"].append(
        {
            "label": "Client proxy CPU per GiB (TCP median)",
            "stock": f"{client_cpu['stock']:,.3f} s/GiB"
            if client_cpu.get("stock") is not None
            else "n/a",
            "beam": f"{client_cpu['beam']:,.3f} s/GiB"
            if client_cpu.get("beam") is not None
            else "n/a",
            "ratio": fmt_ratio(client_cpu_ratio),
            "requirement": "informational",
            "pass": None,
            "informational": True,
        }
    )
    rows["resources"].append(
        {
            "label": "Server RSS after warm-up (peak)",
            "stock": f"{rss.get('stock', {}).get('after_warmup_max_kib', 0) / 1024:,.1f} MiB"
            if rss.get("stock", {}).get("after_warmup_max_kib")
            else "n/a",
            "beam": f"{rss.get('beam', {}).get('after_warmup_max_kib', 0) / 1024:,.1f} MiB"
            if rss.get("beam", {}).get("after_warmup_max_kib")
            else "n/a",
            "ratio": fmt_ratio(rss_ratio),
            "requirement": "<= 0.50x",
            "pass": None if rss_ratio is None else rss_ratio <= 0.5,
        }
    )
    rows["resources"].append(
        {
            "label": "Server file descriptors (max)",
            "stock": str(rss.get("stock", {}).get("fds_max", "n/a")),
            "beam": str(rss.get("beam", {}).get("fds_max", "n/a")),
            "ratio": "n/a",
            "requirement": "no leak",
            "pass": None,
            "informational": True,
        }
    )
    rows["resources"].append(
        {
            "label": "Server threads (max)",
            "stock": str(rss.get("stock", {}).get("threads_max", "n/a")),
            "beam": str(rss.get("beam", {}).get("threads_max", "n/a")),
            "ratio": "n/a",
            "requirement": "no leak",
            "pass": None,
            "informational": True,
        }
    )

    # Core saturation is a validity condition, not a performance result.
    core_stats: dict[str, dict] = {}
    for arm in ("stock", "beam"):
        arm_results = [
            item
            for item in results
            if item.get("arm") == arm
            and item.get("status") == "ok"
            and item.get("scenario") in TCP_SCENARIOS
        ]
        core_stats[arm] = {}
        for role in ("server", "client", "target", "driver"):
            values = [
                item.get("cpu", {}).get(f"{role}_core_busy_pct")
                for item in arm_results
                if item.get("cpu", {}).get(f"{role}_core_busy_pct") is not None
            ]
            core_stats[arm][role] = stats(values)
    meta_roles = meta.get("cpu_roles", {})
    meta_client_cores = meta_roles.get("client_cores") or [meta_roles.get("client")]
    driver_shared = meta_roles.get("driver") in meta_client_cores
    rows["resources"].append(
        {
            "label": "Client + driver core busy (TCP scenarios)"
            if driver_shared
            else "Client proxy core busy (TCP scenarios)",
            "stock": fmt_stats(core_stats.get("stock", {}).get("client"), "%"),
            "beam": fmt_stats(core_stats.get("beam", {}).get("client"), "%"),
            "ratio": "n/a",
            "requirement": "< 85%",
            "pass": None
            if not core_stats.get("beam", {}).get("client")
            else core_stats["beam"]["client"]["max"] < 85,
        }
    )
    rows["resources"].append(
        {
            "label": "Target core busy (TCP scenarios)",
            "stock": fmt_stats(core_stats.get("stock", {}).get("target"), "%"),
            "beam": fmt_stats(core_stats.get("beam", {}).get("target"), "%"),
            "ratio": "n/a",
            "requirement": "< 85%",
            "pass": None
            if not core_stats.get("beam", {}).get("target")
            else core_stats["beam"]["target"]["max"] < 85,
        }
    )
    if not driver_shared:
        rows["resources"].append(
            {
                "label": "Driver core busy (TCP scenarios)",
                "stock": fmt_stats(core_stats.get("stock", {}).get("driver"), "%"),
                "beam": fmt_stats(core_stats.get("beam", {}).get("driver"), "%"),
                "ratio": "n/a",
                "requirement": "< 85%",
                "pass": None
                if not core_stats.get("beam", {}).get("driver")
                else core_stats["beam"]["driver"]["max"] < 85,
            }
        )
    rows["resources"].append(
        {
            "label": "Server core busy (TCP scenarios)",
            "stock": fmt_stats(core_stats.get("stock", {}).get("server"), "%"),
            "beam": fmt_stats(core_stats.get("beam", {}).get("server"), "%"),
            "ratio": "n/a",
            "requirement": "1-vCPU model",
            "pass": None,
            "informational": True,
        }
    )

    # --- Gates ------------------------------------------------------------
    single_ratios = [tcp_ratios.get("tcp-dl-1"), tcp_ratios.get("tcp-ul-1")]
    multi_ratios = [tcp_ratios.get("tcp-dl-4"), tcp_ratios.get("tcp-ul-4")]
    p99_ratios = {
        scenario: latency_comparisons.get(scenario, {}).get("p99_ratio")
        for scenario in ("dns-a", "h3-latency")
    }
    cpu_values = [value for value in cpu_ratios.values() if value is not None]
    throughput_ratios = [
        value
        for value in list(tcp_ratios.values()) + [https_ratio]
        if value is not None
    ]
    latency_all = [
        latency_comparisons.get(scenario, {}).get(f"{name}_ratio")
        for scenario in ("dns-a", "h3-latency")
        for name in ("p50", "p95", "p99")
    ]
    latency_all = [value for value in latency_all if value is not None]

    def all_at_least(values: list[float | None], threshold: float) -> bool | None:
        if not values or any(value is None for value in values):
            return None
        return all(value >= threshold for value in values if value is not None)

    def all_at_most(values: list[float | None], threshold: float) -> bool | None:
        if not values or any(value is None for value in values):
            return None
        return all(value <= threshold for value in values if value is not None)

    aggregate = geomean([value for value in tcp_ratios.values() if value is not None])
    no_regression = None
    if throughput_ratios and latency_all:
        no_regression = all(value >= 0.98 for value in throughput_ratios) and all(
            value <= 1.02 for value in latency_all
        )
    p99_gate = all_at_most(
        [value for value in p99_ratios.values() if value is not None], 1.0
    )

    def throughput_gate(ratios: list[float | None], threshold: float,
                        scenarios: tuple[str, ...]) -> tuple[bool | None, str]:
        if any(scenario in invalid_scenarios for scenario in scenarios):
            return None, "INVALID"
        result = all_at_least(ratios, threshold)
        return result, status_word(result)

    single_pass, single_status = throughput_gate(
        single_ratios, 1.15, ("tcp-dl-1", "tcp-ul-1")
    )
    multi_pass, multi_status = throughput_gate(
        multi_ratios, 1.10, ("tcp-dl-4", "tcp-ul-4")
    )
    aggregate_invalid = any(
        scenario in invalid_scenarios for scenario in TCP_SCENARIOS
    )
    aggregate_pass = None if aggregate_invalid or aggregate is None else aggregate > 1.0
    regression_invalid = bool(invalid_scenarios)
    no_regression_pass = None if regression_invalid else no_regression
    gates = {
        "single_flow_throughput": {
            "requirement": "beam >= 1.15x stock for 1-flow download and upload",
            "pass": single_pass,
            "status": single_status,
            "ratios": single_ratios,
        },
        "multi_flow_throughput": {
            "requirement": "beam >= 1.10x stock for 4-flow download and upload",
            "pass": multi_pass,
            "status": multi_status,
            "ratios": multi_ratios,
        },
        "p99_latency": {
            "requirement": "beam p99 <= stock p99 (DNS, HTTP/3)",
            "pass": p99_gate,
            "status": status_word(p99_gate),
            "ratios": p99_ratios,
        },
        "rss_after_warmup": {
            "requirement": "beam <= 50% of stock RSS after warm-up",
            "pass": None if rss_ratio is None else rss_ratio <= 0.5,
            "status": status_word(None if rss_ratio is None else rss_ratio <= 0.5),
            "ratio": rss_ratio,
        },
        "cpu_per_gib": {
            "requirement": "beam server CPU per GiB < stock in every TCP scenario",
            "pass": None if not cpu_values else all(value < 1.0 for value in cpu_values),
            "status": status_word(
                None if not cpu_values else all(value < 1.0 for value in cpu_values)
            ),
            "ratios": cpu_ratios,
        },
        "aggregate_throughput": {
            "requirement": "geometric mean of TCP throughput ratios > 1.0",
            "pass": aggregate_pass,
            "status": "INVALID" if aggregate_invalid else status_word(aggregate_pass),
            "geomean": aggregate,
        },
        "no_regression": {
            "requirement": "no throughput < 0.98x and no latency > 1.02x",
            "pass": no_regression_pass,
            "status": "INVALID" if regression_invalid else status_word(no_regression_pass),
        },
    }

    # --- Validity ---------------------------------------------------------
    qdisc_drops: dict[str, int] = {}
    for name in ("tc-client-final.txt", "tc-server-final.txt"):
        path = run_dir / "logs" / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        drops = 0
        for line in text.splitlines():
            if "dropped" in line:
                parts = line.split()
                for index, part in enumerate(parts):
                    if part == "dropped" and index + 1 < len(parts):
                        try:
                            drops += int(parts[index + 1])
                        except ValueError:
                            pass
        qdisc_drops[name] = drops
    invalid: dict[str, list[float | None]] = {}
    for scenario in TCP_SCENARIOS + ("https-bulk",):
        for arm in ("stock", "beam"):
            for result in ok(by_arm(results, scenario).get(arm, [])):
                if result.get("client_bound"):
                    invalid.setdefault(f"{scenario}/{arm}: client core saturated", []).append(
                        result["cpu"].get("client_core_busy_pct")
                    )
                if result.get("target_bound"):
                    invalid.setdefault(f"{scenario}/{arm}: target core saturated", []).append(
                        result["cpu"].get("target_core_busy_pct")
                    )
                if result.get("driver_bound"):
                    invalid.setdefault(f"{scenario}/{arm}: driver core saturated", []).append(
                        result["cpu"].get("driver_core_busy_pct")
                    )
    for scenario in REQUIRED:
        for arm in ("stock", "beam"):
            if not ok(by_arm(results, scenario).get(arm, [])):
                invalid.setdefault(f"{scenario}/{arm}: missing required data", [])
    if len(set(arms)) < 2:
        invalid.setdefault("both arms were not measured", [])
    for name, drops in qdisc_drops.items():
        if drops > 0:
            invalid.setdefault(f"{name}: netem qdisc dropped {drops} packets", [])

    invalid_reasons = []
    for key, values in invalid.items():
        numbers = [value for value in values if isinstance(value, (int, float))]
        if numbers:
            invalid_reasons.append(
                f"{key} ({min(numbers):.1f}-{max(numbers):.1f}%)"
            )
        else:
            invalid_reasons.append(key)

    host_keys: set[str] = set()
    non_role: dict[str, list[float]] = {}
    for key, label in (
        ("host_load1_before", "before"),
        ("host_load1_after", "after"),
    ):
        if meta.get(key) is not None and meta.get(key) > 0.3:
            host_keys.add(f"host load {label}={meta[key]} (warning threshold 0.3)")
    for warning in meta.get("warnings", []):
        if not str(warning).startswith("host load"):
            host_keys.add(str(warning))
    for result in results:
        for warning in result.get("warnings", []):
            if "non-role CPU busy" in warning:
                try:
                    value = float(warning.split("(")[-1].rstrip("%)"))
                except ValueError:
                    value = None
                if value is not None:
                    non_role.setdefault(
                        f"{result['scenario']}/{result['arm']}: non-role CPU busy", []
                    ).append(value)
    host_noise = sorted(host_keys)
    for key, values in sorted(non_role.items()):
        host_noise.append(f"{key} (max {max(values):.1f}%)")

    valid = not invalid_reasons
    headline_eligible = valid and not host_noise
    numeric_gates = [gate.get("pass") for gate in gates.values()]
    numeric_pass = (
        None if any(value is None for value in numeric_gates)
        else all(bool(value) for value in numeric_gates)
    )
    hard_requirements = {
        "aggregate_throughput": gates["aggregate_throughput"]["pass"],
        "no_regression": gates["no_regression"]["pass"],
        "valid": valid,
        "headline_eligible": headline_eligible,
    }
    hard_pass = (
        None
        if any(value is None for value in hard_requirements.values())
        else all(bool(value) for value in hard_requirements.values())
    )
    numeric_status = (
        "INVALID"
        if any(gate.get("status") == "INVALID" for gate in gates.values())
        else status_word(numeric_pass)
    )
    hard_status = (
        "INVALID"
        if not valid or any(gate.get("status") == "INVALID" for gate in gates.values())
        else status_word(hard_pass)
    )

    summary = {
        "schema": "beam-bench-summary/1",
        "run_dir": str(run_dir),
        "meta": meta,
        "arms": arms,
        "valid": valid,
        "headline_eligible": headline_eligible,
        "invalid_reasons": invalid_reasons,
        "host_noise": host_noise,
        "blocked": blocked,
        "failed": failed,
        "qdisc_drops": qdisc_drops,
        "gates": gates,
        "numeric_gates_pass": numeric_pass,
        "numeric_gates_status": numeric_status,
        "hard_requirements": hard_requirements,
        "hard_requirements_pass": hard_pass,
        "hard_requirements_status": hard_status,
        "comparisons": comparisons,
        "resources": {
            "rss": rss,
            "cores": core_stats,
            "cpu_per_gib_ratios": cpu_ratios,
            "client_cpu_per_gib_median": client_cpu,
        },
        "scenario_meta": SCENARIO_META,
        "table_rows": rows,
    }
    return summary


def latency_stats(samples_us: list[float]) -> dict:
    samples_ms = [value / 1000.0 for value in samples_us]
    return {
        "n": len(samples_ms),
        "p50": percentile(samples_ms, 50),
        "p95": percentile(samples_ms, 95),
        "p99": percentile(samples_ms, 99),
        "min": min(samples_ms) if samples_ms else None,
        "max": max(samples_ms) if samples_ms else None,
        "unit": "ms",
    }


def render_markdown(summary: dict) -> str:
    meta = summary.get("meta", {})
    host = meta.get("host", {})
    roles = meta.get("cpu_roles", {})
    lines: list[str] = []
    lines.append("# Local benchmark: stock Xray v26.3.27 vs beam")
    lines.append("")
    lines.append(f"Run: `{meta.get('run_id', 'unknown')}`  ")
    lines.append(f"Generated: {meta.get('finished_at', 'unknown')}  ")
    lines.append(f"Worktree: `{meta.get('worktree', 'unknown')}`  ")
    lines.append(
        f"Commit: `{meta.get('git', {}).get('commit', 'unknown')}`"
        f" (dirty={meta.get('git', {}).get('dirty', 'unknown')})  "
    )
    lines.append(
        f"Kernel: `{meta.get('kernel', 'unknown')}`  "
        f"CPU: {host.get('model', 'unknown')} "
        f"({host.get('logical_cpus', '?')} logical threads)"
    )
    lines.append("")
    lines.append("## Conditions")
    lines.append("")
    client_cores = roles.get("client_cores") or [roles.get("client")]
    shared_driver = roles.get("driver") in client_cores
    client_label = (
        f"client + driver `CPU {','.join(str(core) for core in client_cores)}`"
        if shared_driver
        else f"client proxy `CPU {','.join(str(core) for core in client_cores)}`"
    )
    driver_label = (
        ""
        if shared_driver
        else f", driver `CPU {roles.get('driver')}`"
    )
    lines.append(
        f"- CPU roles: server `CPU {roles.get('server')}`, "
        f"{client_label}, "
        f"target `CPU {roles.get('target')}`{driver_label}; free: "
        f"{', '.join(str(core) for core in roles.get('free', []))}"
    )
    masks = roles.get("masks") or {}
    if any(masks.values()):
        lines.append(
            f"- Actual affinity masks: server `{masks.get('server')}`, "
            f"client `{masks.get('client')}`, target `{masks.get('target')}`"
        )
    lines.append(
        f"- Repetitions: {meta.get('reps', '?')} per arm, "
        f"{meta.get('duration_s', '?')} s per bulk scenario, warm-up excluded."
    )
    lines.append(
        f"- netem RTT: {meta.get('rtt_ms', 0)} ms total "
        f"({meta.get('rtt_ms', 0) / 2:.3g} ms on each veth); target link clean."
    )
    lines.append(
        "- Client: sing-box v1.14.3 full TUN, utls chrome, "
        "VLESS + REALITY + Vision, XUDP; byte-identical config for both arms."
    )
    binaries = meta.get("binaries", {})
    for name in ("beam", "stock", "singbox", "iperf3", "h3_origin"):
        item = binaries.get(name) or {}
        if item.get("sha256"):
            lines.append(f"- {name}: `{item['path']}` sha256 `{item['sha256'][:16]}…`")
    lines.append(
        f"- Host load: before {meta.get('host_load1_before', 'n/a')}, "
        f"after {meta.get('host_load1_after', 'n/a')}."
    )
    if meta.get("large_file"):
        lines.append(
            f"- HTTPS payload: {meta['large_file']['bytes'] / 1048576:.0f} MiB, "
            f"sha256 `{(meta['large_file'].get('sha256') or '')[:16]}…`."
        )
    h3 = meta.get("h3", {})
    lines.append(
        f"- HTTP/3 origin: {'ready' if h3.get('available') else 'BLOCKED'}"
        + (f" ({h3.get('blocked_reason')})" if not h3.get("available") else "")
    )
    lines.append("")

    lines.append("## Gates")
    lines.append("")
    gate_rows = []
    for key, gate in summary["gates"].items():
        gate_rows.append(
            [
                key,
                gate.get("requirement", ""),
                gate.get("status", status_word(gate.get("pass"))),
            ]
        )
    lines.append(
        markdown_table(["Gate", "Requirement", "Result"], gate_rows)
    )
    lines.append("")

    lines.append("## Throughput (median, min–max over repetitions)")
    lines.append("")
    lines.append(
        markdown_table(
            ["Metric", "stock Xray", "beam", "ratio (beam/stock)", "Gate", "Result"],
            [
                [
                    row["label"],
                    row["stock"],
                    row["beam"],
                    row["ratio"],
                    row["requirement"],
                    row_status(row),
                ]
                for row in summary["table_rows"]["throughput"]
            ],
        )
    )
    lines.append("")

    lines.append("## UDP")
    lines.append("")
    lines.append(
        markdown_table(
            ["Metric", "stock Xray", "beam", "ratio (beam/stock)", "Requirement", "Result"],
            [
                [
                    row["label"],
                    row["stock"],
                    row["beam"],
                    row["ratio"],
                    row["requirement"],
                    row_status(row),
                ]
                for row in summary["table_rows"]["udp"]
            ],
        )
    )
    lines.append("")

    lines.append("## Latency (pooled samples, p50/p95/p99)")
    lines.append("")
    lines.append(
        markdown_table(
            ["Metric", "stock Xray", "beam", "ratio (beam/stock)", "Requirement", "Result"],
            [
                [
                    row["label"],
                    row["stock"],
                    row["beam"],
                    row["ratio"],
                    row["requirement"],
                    row_status(row),
                ]
                for row in summary["table_rows"]["latency"]
            ],
        )
    )
    lines.append("")

    lines.append("## Resources")
    lines.append("")
    lines.append(
        markdown_table(
            ["Metric", "stock Xray", "beam", "ratio", "Requirement", "Result"],
            [
                [
                    row["label"],
                    row["stock"],
                    row["beam"],
                    row["ratio"],
                    row["requirement"],
                    row_status(row),
                ]
                for row in summary["table_rows"]["resources"]
            ],
        )
    )
    lines.append("")

    lines.append("## Validity")
    lines.append("")
    lines.append(
        f"- Measurement valid (no client/target saturation, required data present): "
        f"**{'yes' if summary['valid'] else 'no'}**"
    )
    lines.append(
        f"- Headline eligible (also free of host noise): "
        f"**{'yes' if summary['headline_eligible'] else 'no'}**"
    )
    lines.append(
        f"- All numeric gates: **{summary.get('numeric_gates_status', 'BLOCKED')}**"
    )
    lines.append(
        f"- Hard requirements (aggregate + no regression + valid + clean host): "
        f"**{summary.get('hard_requirements_status', 'BLOCKED')}**"
    )
    if summary["invalid_reasons"]:
        lines.append("- Invalidating conditions:")
        for reason in summary["invalid_reasons"]:
            lines.append(f"  - {reason}")
    if summary["host_noise"]:
        lines.append("- Host noise:")
        for reason in summary["host_noise"]:
            lines.append(f"  - {reason}")
    if summary["blocked"]:
        lines.append("")
        lines.append("### BLOCKED")
        lines.append("")
        lines.append(markdown_table(
            ["Scenario", "Arm", "Reason"],
            [
                [item["scenario"], item["arm"], item["reason"]]
                for item in summary["blocked"]
            ],
        ))
    if summary["failed"]:
        lines.append("")
        lines.append("### FAILED")
        lines.append("")
        lines.append(markdown_table(
            ["Scenario", "Arm", "Reason"],
            [
                [item["scenario"], item["arm"], item["reason"]]
                for item in summary["failed"]
            ],
        ))
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    lines.append(
        "- Unprivileged user namespace: perf tracepoints, IRQ affinity and "
        "sysctls are unavailable, so syscall/wakeup/splice gates are not "
        "measured. Use the privileged acceptance run for those."
    )
    lines.append(
        "- A throughput scenario where the client or target core is at or above "
        "85% is reported as INVALID, not as a pass or fail."
    )
    lines.append(
        "- HTTP/3 uses the test-only local origin; it is not a general QUIC "
        "capacity test."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--markdown", type=Path, default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    summary = build(args.run)
    json_path = args.json or args.run / "summary.json"
    markdown_path = args.markdown or args.run / "summary.md"
    json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")

    if not args.quiet:
        print()
        print(f"== benchmark summary: {args.run} ==")
        print()
        print(render_markdown(summary))
    print(f"summary: {json_path}")
    print(f"markdown: {markdown_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
