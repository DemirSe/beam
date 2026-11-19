#!/usr/bin/env python3
"""Record and check evidence from the four parallel preprod phases.

The phase jobs write one provenance file and their own report files. The final
gate reads those artifacts and fails closed when a phase is missing, failed,
duplicated, or tested different commits.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "beam-preprod-evidence/1"
PHASES = ("tun", "protocols", "bench", "stress")
MODES = ("xudp", "legacy", "packetaddr")
PROBES = (
    "tcp-http-v4", "tcp-http-v6", "udp-echo", "udp-echo-v6",
    "dns-udp", "dns-udp-v6", "quic-udp", "https-direct",
)
SHA = re.compile(r"^[0-9a-f]{40}$")


def _protocol_cases() -> list[str]:
    path = ROOT / "tests" / "tun" / "protocol_report.py"
    spec = importlib.util.spec_from_file_location("beam_protocol_report", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the protocol case contract")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return list(module.REQUIRED_CASES)


def record(out: Path, phase: str, commit: str, baseline: str, run_id: str) -> None:
    """Write the provenance file that a phase uploads after its gates pass."""
    if phase not in PHASES:
        raise ValueError(f"unknown preprod phase: {phase}")
    if not SHA.fullmatch(commit) or not SHA.fullmatch(baseline):
        raise ValueError("candidate and baseline must be full commit SHAs")
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": SCHEMA,
        "phase": phase,
        "commit": commit,
        "baseline": baseline,
        "suite": "preprod",
        "profile": "standard",
        "publish": False,
        "run_id": run_id,
    }
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _json(path: Path, problems: list[str]):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        problems.append(f"{path}: unreadable JSON: {error}")
        return None


def _text(path: Path, problems: list[str]):
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        problems.append(f"{path}: unreadable file: {error}")
        return None


def _tun(root: Path, commit: str, problems: list[str]) -> None:
    for mode in MODES:
        base = root / "tun" / mode
        env = _text(base / "environment.txt", problems)
        if env is not None:
            for expected in (f"commit={commit}", f"udp_mode={mode}"):
                if expected not in env.splitlines():
                    problems.append(f"tun/{mode}: environment.txt has no {expected}")
        rows = _text(base / "results-beam.tsv", problems)
        if rows is None:
            continue
        for probe in PROBES:
            statuses = [
                fields[1]
                for line in rows.splitlines()
                if len(fields := line.split("\t")) >= 2 and fields[0] == probe
            ]
            if statuses != ["PASS"]:
                problems.append(f"tun/{mode}: {probe}={statuses or ['MISSING']}")


def _protocols(root: Path, commit: str, problems: list[str]) -> None:
    report = _json(root / "protocols" / "protocol-report-beam.json", problems)
    if report is not None:
        for key, want in (
            ("commit", commit), ("arm", "beam"), ("complete", True),
            ("missing", []), ("duplicates", []),
        ):
            if report.get(key) != want:
                problems.append(f"protocols: {key}={report.get(key)!r}, expected {want!r}")
        try:
            required = _protocol_cases()
        except RuntimeError as error:
            problems.append(str(error))
            required = []
        cases = report.get("cases") or []
        names = [case.get("name") for case in cases]
        if len(names) != len(required) or len(set(names)) != len(names) or set(names) != set(required):
            problems.append(f"protocols: case manifest has {len(names)} rows, expected {len(required)} unique cases")
        bad = [case.get("name") for case in cases if case.get("status") not in ("PASS", "WARN", "INFO")]
        if bad:
            problems.append(f"protocols: rejected case statuses: {bad}")
    env = _text(root / "protocols" / "environment.txt", problems)
    if env is not None:
        for expected in ("rtt_ms=250", "loss_pct=0", "udp_mode=xudp"):
            if expected not in env.splitlines():
                problems.append(f"protocols: environment.txt has no {expected}")


def _bench(root: Path, commit: str, problems: list[str]) -> None:
    meta = _json(root / "bench" / "meta.json", problems)
    if meta is not None:
        if (meta.get("git") or {}).get("commit") != commit:
            problems.append("bench: meta.json does not name the candidate commit")
        if meta.get("arms") != ["baseline", "beam"] or meta.get("reps") != 3:
            problems.append("bench: meta.json does not name the three-repetition baseline cell")
    summary = _json(root / "bench" / "summary.json", problems)
    if summary is not None:
        if summary.get("valid") is not True or summary.get("headline_eligible") is not True:
            problems.append("bench: summary.json is not valid and headline eligible")
        if (summary.get("reference_arm"), summary.get("candidate_arm")) != ("baseline", "beam"):
            problems.append("bench: summary.json has the wrong arms")
    env = _text(root / "bench" / "environment.txt", problems)
    if env is not None:
        for expected in ("arms=baseline,beam", "rtt_ms=250", "loss_pct=0"):
            if expected not in env.splitlines():
                problems.append(f"bench: environment.txt has no {expected}")


def _stress(root: Path, problems: list[str]) -> None:
    summary = _json(root / "stress" / "summary.json", problems)
    if summary is None:
        return
    checks = summary.get("checks") or []
    names = [check.get("name") for check in checks]
    if summary.get("ok") is not True or len(checks) != 13 or len(set(names)) != 13:
        problems.append(f"stress: expected 13 unique passing gates, got {len(checks)} with ok={summary.get('ok')!r}")
    failed = [check.get("name") for check in checks if check.get("ok") is not True]
    if failed:
        problems.append(f"stress: failed checks: {failed}")


def check(root: Path, commit: str, baseline: str, run_id: str, lab_result: str = "success") -> list[str]:
    """Return all reasons why the final preprod gate must fail."""
    problems: list[str] = []
    if lab_result != "success":
        problems.append(f"lab matrix result is {lab_result!r}, not 'success'")
    if not SHA.fullmatch(commit or ""):
        problems.append(f"candidate {commit!r} is not a full commit SHA")
    if not SHA.fullmatch(baseline or ""):
        problems.append(f"baseline {baseline!r} is not a full commit SHA")

    files = sorted(root.glob("evidence-*.json"))
    if len(files) != len(PHASES):
        problems.append(f"expected {len(PHASES)} phase evidence files, found {len(files)}")
    seen: dict[str, dict] = {}
    for path in files:
        payload = _json(path, problems)
        if not isinstance(payload, dict):
            continue
        phase = payload.get("phase")
        if phase in seen:
            problems.append(f"duplicate evidence for phase {phase}: {path.name}")
        elif phase in PHASES:
            seen[phase] = payload
        else:
            problems.append(f"{path.name}: unknown phase {phase!r}")
        if phase in PHASES and path.name != f"evidence-{phase}.json":
            problems.append(f"{path.name}: file name does not match phase {phase}")
        expected = {
            "schema": SCHEMA, "phase": phase, "suite": "preprod",
            "profile": "standard", "publish": False,
            "commit": commit, "baseline": baseline, "run_id": run_id,
        }
        for key, want in expected.items():
            if payload.get(key) != want:
                problems.append(f"{path.name}: {key}={payload.get(key)!r}, expected {want!r}")

    for phase in PHASES:
        if phase not in seen:
            problems.append(f"missing evidence for phase {phase}")
    if "tun" in seen:
        _tun(root, commit, problems)
    if "protocols" in seen:
        _protocols(root, commit, problems)
    if "bench" in seen:
        _bench(root, commit, problems)
    if "stress" in seen:
        _stress(root, problems)
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    writer = commands.add_parser("record")
    writer.add_argument("--out", type=Path, required=True)
    writer.add_argument("--phase", required=True)
    writer.add_argument("--commit", required=True)
    writer.add_argument("--baseline", required=True)
    writer.add_argument("--run-id", required=True)
    reader = commands.add_parser("check")
    reader.add_argument("--root", type=Path, required=True)
    reader.add_argument("--commit", required=True)
    reader.add_argument("--baseline", required=True)
    reader.add_argument("--run-id", required=True)
    reader.add_argument("--lab-result", default="success")
    args = parser.parse_args(argv)

    if args.command == "record":
        try:
            record(args.out, args.phase, args.commit, args.baseline, args.run_id)
        except (ValueError, OSError) as error:
            print(f"::error::{error}", file=sys.stderr)
            return 1
        return 0

    problems = check(args.root, args.commit, args.baseline, args.run_id, args.lab_result)
    for problem in problems:
        print(f"::error::{problem}", file=sys.stderr)
    if problems:
        return 1
    print("preprod final gate: all four phases passed on the candidate and prod baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
