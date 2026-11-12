#!/usr/bin/env python3
"""Merge and validate protocol-lab case reports.

``merge`` combines the per-case JSON written by ``protocol.py`` and the Rust
``h2-client`` wrapper, the harness-recorded rows (preflights, restart evidence,
origin accounting) and the run environment into one report:

    protocol-report-<arm>.json

``validate`` enforces the report contract: schema, completeness, the exact
required case manifest, one row per case, no FAIL/BLOCKED, the declared metrics
and the ``require_all`` completion rule. It exits 0 only for a valid report and
prints the WARN/INFO rows plus the beam/Xray attribution table.

This is test-only code; it never touches the network.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = 1

# Case outcomes. ACCEPTED includes WARN: a quality observation is accepted, not
# a gate failure. BLOCKED is never accepted because the workflow pins every
# tool the suite needs.
ACCEPTED_STATUSES = frozenset({"PASS", "WARN", "INFO"})
FAIL_STATUS = "FAIL"
BLOCKED_STATUS = "BLOCKED"
KNOWN_STATUSES = ACCEPTED_STATUSES | {FAIL_STATUS, BLOCKED_STATUS}

# The report's `required` field must equal this list exactly; the validator
# compares both so a truncated manifest can never look complete.
REQUIRED_CASES = [
    "preflight-h1",
    "preflight-h2",
    "preflight-h3",
    "h2-bulk-8m",
    "h2-multiplex-16",
    "h3-bulk-8m",
    "h3-concurrent-8",
    "http1-persistent-20",
    "tcp-upload-8m",
    "h2-cancel-64m",
    "udp-realtime-1200",
    "udp-multidest-4",
    "udp-alt-source",
    "dns-udp-200",
    "dns-tcp-fallback",
    "mixed-hol-60s",
    "idle-tcp-35s",
    "restart-recovery",
    "tls12-fallback",
    "datagram-size-continuity",
]

# Metrics every case must declare. A case that stops emitting one of these is a
# contract break, not a silent pass.
CASE_METRICS = {
    "preflight-h1": ("http_code", "http_version"),
    "preflight-h2": ("http_code", "http_version"),
    "preflight-h3": ("http_code", "http_version"),
    "h2-bulk-8m": ("bytes", "http_version", "sha256_ok", "ttfb_ms"),
    "h2-multiplex-16": (
        "connections",
        "streams",
        "peak_active",
        "bytes",
        "hash_ok",
        "origin_connections",
        "origin_peak_active",
    ),
    "h3-bulk-8m": ("bytes", "http_version", "sha256_ok", "ttfb_ms"),
    "h3-concurrent-8": ("responses", "completed", "connections", "peak_active"),
    "http1-persistent-20": ("requests", "completed", "connections", "p95_ms"),
    "tcp-upload-8m": ("bytes", "sha256_ok", "mib_per_s"),
    "h2-cancel-64m": ("cancelled_bytes", "keepalive_ok", "p95_ms"),
    "udp-realtime-1200": (
        "packets",
        "received",
        "lost",
        "loss_pct",
        "reorder",
        "duplicates",
        "corrupt",
        "p95_ms",
    ),
    "udp-multidest-4": ("packets", "echoed", "alt_replies", "corrupt"),
    "udp-alt-source": ("packets", "replies", "alt_source", "sources"),
    "dns-udp-200": ("queries", "answered", "p95_ms"),
    "dns-tcp-fallback": ("queries", "a_ok", "aaaa_ok", "nxdomain_ok"),
    "mixed-hol-60s": ("planned", "completed", "completion_ratio", "small_p95_ms", "invalid"),
    "idle-tcp-35s": ("idle_s", "echo_ok"),
    "restart-recovery": (
        "tcp_recovery_ms",
        "udp_recovery_ms",
        "post_restart_hash_ok",
        "old_pid",
        "new_pid",
        "old_reaped",
    ),
    "tls12-fallback": ("tls_version", "bytes", "sha256_ok"),
    "datagram-size-continuity": ("udp_1200_ok", "udp_1400_ok", "http_16384_ok"),
}

# Cases whose work is fixed in advance: every planned unit must complete. The
# loss- and throughput-shaped cases carry their own budgets instead.
REQUIRE_ALL = frozenset(
    {
        "preflight-h1",
        "preflight-h2",
        "preflight-h3",
        "h2-bulk-8m",
        "h2-multiplex-16",
        "h3-bulk-8m",
        "h3-concurrent-8",
        "http1-persistent-20",
        "tcp-upload-8m",
        "h2-cancel-64m",
        "dns-udp-200",
        "dns-tcp-fallback",
        "idle-tcp-35s",
        "restart-recovery",
        "tls12-fallback",
        "datagram-size-continuity",
    }
)

NUMERIC_ENVIRONMENT = frozenset(
    {
        "rtt_ms",
        "loss_pct",
        "tun_mtu",
        "baseline_rtt_ms",
        "baseline_target_rtt_ms",
    }
)


def _number(value: str):
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def restart_problems(metrics: dict) -> list[str]:
    """Restart evidence must show a replaced, reaped process and a working path.

    Presence alone is not enough: a report where the old process survived, the
    pid was reused, or the post-restart transfer failed is not a restart pass.
    """
    problems: list[str] = []
    if metrics.get("old_reaped") is not True:
        problems.append("restart-recovery: the old process was not reaped")
    old_pid = metrics.get("old_pid")
    new_pid = metrics.get("new_pid")
    if type(old_pid) is not int or type(new_pid) is not int or old_pid <= 0 or new_pid <= 0:
        problems.append("restart-recovery: pid evidence is missing or invalid")
    elif old_pid == new_pid:
        problems.append("restart-recovery: the old and new pid are identical")
    if metrics.get("post_restart_hash_ok") is not True:
        problems.append("restart-recovery: the post-restart transfer did not verify")
    return problems


def compute_complete(
    missing: list[str], duplicates: list[str], harness_complete: bool
) -> bool:
    """A report is complete only when every required case is present once and
    the harness itself did not fail."""
    return not missing and not duplicates and harness_complete


def read_environment(path: Path | None) -> dict:
    environment: dict = {}
    if path is None or not path.is_file():
        return environment
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        environment[key] = _number(value) if key in NUMERIC_ENVIRONMENT else value
    return environment


def load_cases(results_dir: Path) -> tuple[dict[str, dict], list[str]]:
    """Read every case JSON in a directory, ignoring non-case JSON."""
    cases: dict[str, dict] = {}
    duplicates: list[str] = []
    for path in sorted(results_dir.glob("*.json")):
        if path.name.startswith("protocol-report-"):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            print(f"protocol-report: ignoring unreadable case file {path}: {error}", file=sys.stderr)
            continue
        if not isinstance(payload, dict) or "name" not in payload:
            continue
        name = str(payload["name"])
        if name in cases:
            duplicates.append(name)
        cases[name] = payload
    return cases, duplicates


def build_report(
    cases: dict[str, dict],
    duplicates: list[str],
    extras: list[dict],
    environment: dict,
    arm: str,
    commit: str,
    binary_sha256: str,
) -> dict:
    merged = {name: dict(case) for name, case in cases.items()}
    environment = dict(environment)
    harness_complete = True
    for extra in extras:
        for case in extra.get("cases") or []:
            if not isinstance(case, dict) or "name" not in case:
                continue
            name = str(case["name"])
            if name in merged:
                duplicates.append(name)
            merged[name] = case
        for name, metrics in (extra.get("metrics") or {}).items():
            if name in merged and isinstance(metrics, dict):
                merged[name].setdefault("metrics", {}).update(metrics)
        environment.update(extra.get("environment") or {})
        if extra.get("complete") is False:
            harness_complete = False

    ordered = [merged[name] for name in REQUIRED_CASES if name in merged]
    ordered += [merged[name] for name in sorted(merged) if name not in REQUIRED_CASES]
    # Case-level summary: the manifest size and how many required cases are
    # present. Per-case work units live in the case rows; summing them would
    # mix byte-denominated and request-denominated cases.
    planned = len(REQUIRED_CASES)
    completed = sum(1 for name in REQUIRED_CASES if name in merged)
    missing = [name for name in REQUIRED_CASES if name not in merged]
    complete = compute_complete(missing, duplicates, harness_complete)
    return {
        "schema": SCHEMA,
        "complete": complete,
        "arm": arm,
        "commit": commit,
        "binary_sha256": binary_sha256,
        "environment": environment,
        "required": list(REQUIRED_CASES),
        "cases": ordered,
        "missing": missing,
        "duplicates": duplicates,
        "counts": {"planned": planned, "completed": completed},
    }


def check_report(report: dict, require_arm: str | None = None) -> list[str]:
    problems: list[str] = []
    if report.get("schema") != SCHEMA:
        problems.append(f"schema {report.get('schema')} != {SCHEMA}")
    if require_arm and report.get("arm") != require_arm:
        problems.append(f"arm {report.get('arm')!r} != required {require_arm!r}")
    if report.get("required") != REQUIRED_CASES:
        problems.append("required manifest does not match the contract")
    if report.get("complete") is not True:
        problems.append("report is not marked complete")
    if report.get("missing"):
        problems.append("report lists missing cases: " + ", ".join(report["missing"]))
    if report.get("duplicates"):
        problems.append("report lists duplicate cases: " + ", ".join(report["duplicates"]))

    by_name: dict[str, dict] = {}
    for case in report.get("cases") or []:
        name = str(case.get("name") or "")
        if not name:
            problems.append("a case has no name")
            continue
        if name in by_name:
            problems.append(f"duplicate case {name}")
        if name not in REQUIRED_CASES:
            problems.append(f"unknown case {name}")
        by_name[name] = case

    for name in REQUIRED_CASES:
        case = by_name.get(name)
        if case is None:
            problems.append(f"missing case {name}")
            continue
        status = case.get("status")
        if status == FAIL_STATUS:
            problems.append(f"{name}: FAIL: {case.get('detail') or 'no detail'}")
        elif status == BLOCKED_STATUS:
            problems.append(f"{name}: BLOCKED: {case.get('detail') or 'no detail'}")
        elif status not in ACCEPTED_STATUSES:
            problems.append(f"{name}: unexpected status {status!r}")
        if not str(case.get("detail") or "").strip():
            problems.append(f"{name}: empty detail")
        metrics = case.get("metrics")
        if not isinstance(metrics, dict):
            problems.append(f"{name}: no metrics object")
            metrics = {}
        for key in CASE_METRICS[name]:
            if metrics.get(key) is None:
                problems.append(f"{name}: missing metric {key}")
        if name in REQUIRE_ALL and case.get("completed") != case.get("planned"):
            problems.append(
                f"{name}: completed {case.get('completed')} != planned {case.get('planned')}"
            )
        if name == "restart-recovery":
            problems.extend(restart_problems(metrics))
    return problems


def _status_of(report: dict | None, name: str) -> str:
    if not report:
        return "-"
    for case in report.get("cases") or []:
        if case.get("name") == name:
            return str(case.get("status") or "-")
    return "MISSING"


def attribution(beam: dict, control: dict | None) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for name in REQUIRED_CASES:
        beam_status = _status_of(beam, name)
        control_status = _status_of(control, name) if control else "-"
        if beam_status == "PASS" and control_status in ("PASS", "-"):
            continue
        if beam_status == "FAIL" and control_status != "FAIL":
            owner = "beam"
        elif beam_status == "FAIL" and control_status == "FAIL":
            owner = "target/harness first"
        elif beam_status in ("WARN", "INFO") and control_status == "PASS":
            owner = "beam (quality)"
        elif beam_status in ("WARN", "INFO") and control_status == "FAIL":
            owner = "xray/control"
        elif beam_status in ("WARN", "INFO"):
            owner = "shared/client"
        elif beam_status == "PASS" and control_status != "PASS":
            owner = "xray/control"
        else:
            owner = "inspect"
        rows.append((name, beam_status, control_status, owner))
    return rows


def print_rows(report: dict) -> None:
    print(f"== protocol cases ({report.get('arm')}) ==")
    print(f"{'CASE':<26} {'STATUS':<8} DETAIL")
    for case in report.get("cases") or []:
        detail = str(case.get("detail") or "")
        if len(detail) > 96:
            detail = detail[:93] + "..."
        print(f"{str(case.get('name')):<26} {str(case.get('status')):<8} {detail}")
    warnings = [
        (case.get("name"), warning)
        for case in report.get("cases") or []
        for warning in (case.get("warnings") or [])
    ]
    if warnings:
        print("\n== WARN/INFO ==")
        for name, warning in warnings:
            print(f"{name}: {warning}")
    metrics = report.get("environment") or {}
    print("\n== environment ==")
    for key in (
        "rtt_ms",
        "loss_pct",
        "udp_mode",
        "tun_mtu",
        "baseline_rtt_ms",
        "baseline_target_rtt_ms",
        "client",
        "curl",
        "runner",
        "log_level",
    ):
        if key in metrics:
            print(f"{key}={metrics[key]}")


def merge(args) -> int:
    results = Path(args.results)
    if not results.is_dir():
        print(f"protocol-report: results directory missing: {results}", file=sys.stderr)
        return 1
    cases, duplicates = load_cases(results)
    extra_paths = args.extra if isinstance(args.extra, list) else [args.extra]
    extras: list[dict] = []
    for path in extra_paths:
        if not path:
            continue
        try:
            extras.append(json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, ValueError) as error:
            print(f"protocol-report: could not read {path}: {error}", file=sys.stderr)
            return 1
    environment = read_environment(Path(args.environment) if args.environment else None)
    report = build_report(
        cases, duplicates, extras, environment, args.arm, args.commit, args.binary_sha256
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.tsv:
        with open(args.tsv, "w", encoding="utf-8") as handle:
            for case in report["cases"]:
                detail = str(case.get("detail") or "").replace("\t", " ").replace("\n", " ")
                handle.write(
                    f"{case.get('name')}\t{case.get('status')}\t{detail}\n"
                )
    print(
        f"protocol-report: {args.arm}: {len(report['cases'])} cases, "
        f"{len(report['missing'])} missing, {len(report['duplicates'])} duplicate, "
        f"complete={str(report['complete']).lower()} -> {out}"
    )
    return 0


def validate(args) -> int:
    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"::error::protocol report unreadable: {args.report}: {error}")
        return 1
    control = None
    if args.control:
        try:
            control = json.loads(Path(args.control).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            print(f"::warning::control report unreadable: {args.control}: {error}")
    problems = check_report(report, args.require_arm)
    print_rows(report)
    if control is None:
        print("\n::warning::no control (Xray) report; beam-only attribution")
    rows = attribution(report, control)
    print("\n== attribution ==")
    print(f"{'CASE':<26} {'BEAM':<8} {'XRAY':<8} ATTRIBUTION")
    for name, beam_status, control_status, owner in rows:
        print(f"{name:<26} {beam_status:<8} {control_status:<8} {owner}")
    if not rows:
        print("(all beam and control rows PASS)")

    if problems:
        for problem in problems:
            print(f"::error::protocol: {problem}")
        print(f"protocol acceptance: {len(problems)} problem(s)")
        return 1
    # A WARN row is an accepted quality observation, not a gate failure; the
    # case manifest is complete when every required name is present and no row
    # is FAIL or BLOCKED.
    passed = sum(1 for case in report["cases"] if case.get("status") == "PASS")
    warned = sum(1 for case in report["cases"] if case.get("status") == "WARN")
    total = len(REQUIRED_CASES)
    print(
        f"\nprotocol acceptance: {passed + warned}/{total} cases "
        f"({passed} PASS, {warned} WARN), complete={report['complete']}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    item = sub.add_parser("merge", help="merge per-case JSON into one arm report")
    item.add_argument("--results", required=True, help="directory of case JSON files")
    item.add_argument(
        "--extra",
        action="append",
        default=[],
        metavar="FILE",
        help="harness-recorded rows, metrics and completeness (repeatable)",
    )
    item.add_argument("--environment", default="", help="environment.txt from the harness")
    item.add_argument("--arm", default="beam")
    item.add_argument("--commit", default="")
    item.add_argument("--binary-sha256", default="")
    item.add_argument("--out", required=True)
    item.add_argument("--tsv", default="")
    item.set_defaults(handler=merge)

    item = sub.add_parser("validate", help="enforce the report contract")
    item.add_argument("--report", required=True)
    item.add_argument("--control", default="", help="optional Xray arm report")
    item.add_argument("--require-arm", default="beam")
    item.set_defaults(handler=validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
