#!/usr/bin/env python3
"""Contract tests for the protocol-lab report merger and validator.

Fixtures are generated in a temporary directory: no network, no namespaces.
Every test pins one decision the hosted protocol lab depends on.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


report = _load("protocol_report", ROOT / "tests" / "tun" / "protocol_report.py")


def _case(name: str, **overrides) -> dict:
    case = {
        "name": name,
        "status": "PASS",
        "correctness": True,
        "ok": True,
        "planned": 1,
        "completed": 1,
        "deadline_ms": 1000,
        "started": 0.0,
        "ended": 1.0,
        "metrics": {key: 1 for key in report.CASE_METRICS[name]},
        "warnings": [],
        "detail": f"{name} passed",
    }
    if name == "restart-recovery":
        case["metrics"].update(
            old_pid=100, new_pid=200, old_reaped=True, post_restart_hash_ok=True
        )
    case.update(overrides)
    return case


def _valid_report(**overrides) -> dict:
    payload = {
        "schema": report.SCHEMA,
        "complete": True,
        "arm": "beam",
        "commit": "0" * 40,
        "binary_sha256": "1" * 64,
        "environment": {"rtt_ms": 250, "loss_pct": 0, "udp_mode": "xudp"},
        "required": list(report.REQUIRED_CASES),
        "cases": [_case(name) for name in report.REQUIRED_CASES],
        "missing": [],
        "duplicates": [],
        "counts": {"planned": len(report.REQUIRED_CASES), "completed": len(report.REQUIRED_CASES)},
    }
    payload.update(overrides)
    return payload


def _namespace(**values) -> argparse.Namespace:
    return argparse.Namespace(**values)


class ValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, payload) -> str:
        path = self.dir / "protocol-report-beam.json"
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8")
        else:
            path.write_text(json.dumps(payload), encoding="utf-8")
        return str(path)

    def _validate(self, path: str, control: str = "") -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = report.validate(
                _namespace(report=path, control=control, require_arm="beam")
            )
        return code, buffer.getvalue()

    def test_valid_report_passes(self) -> None:
        code, output = self._validate(self._write(_valid_report()))
        self.assertEqual(code, 0, output)
        self.assertIn(
            f"protocol acceptance: {len(report.REQUIRED_CASES)}"
            f"/{len(report.REQUIRED_CASES)} cases ({len(report.REQUIRED_CASES)} PASS, 0 WARN)",
            output,
        )

    def test_missing_required_case_fails(self) -> None:
        payload = _valid_report()
        payload["cases"] = [case for case in payload["cases"] if case["name"] != "h3-bulk-8m"]
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("missing case h3-bulk-8m", output)

    def test_duplicate_case_fails(self) -> None:
        payload = _valid_report()
        payload["cases"].append(_case("h2-bulk-8m"))
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("duplicate case h2-bulk-8m", output)

    def test_truncated_json_fails(self) -> None:
        path = self._write('{"schema": 1, "complete": tr')
        code, output = self._validate(path)
        self.assertEqual(code, 1)
        self.assertIn("protocol report unreadable", output)

    def test_incomplete_report_fails(self) -> None:
        code, output = self._validate(self._write(_valid_report(complete=False)))
        self.assertEqual(code, 1)
        self.assertIn("report is not marked complete", output)

    def test_missing_list_fails(self) -> None:
        code, output = self._validate(
            self._write(_valid_report(missing=["dns-udp-200"]))
        )
        self.assertEqual(code, 1)
        self.assertIn("report lists missing cases: dns-udp-200", output)

    def test_fail_case_fails(self) -> None:
        payload = _valid_report()
        payload["cases"][3] = _case("h2-bulk-8m", status="FAIL", detail="sha256 differed")
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("h2-bulk-8m: FAIL: sha256 differed", output)

    def test_blocked_case_fails(self) -> None:
        payload = _valid_report()
        payload["cases"][5] = _case("h3-bulk-8m", status="BLOCKED", detail="no HTTP/3")
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("h3-bulk-8m: BLOCKED: no HTTP/3", output)

    def test_incomplete_require_all_case_fails(self) -> None:
        payload = _valid_report()
        payload["cases"][3] = _case("h2-bulk-8m", planned=2, completed=1)
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("h2-bulk-8m: completed 1 != planned 2", output)

    def test_warn_case_is_accepted(self) -> None:
        payload = _valid_report()
        index = report.REQUIRED_CASES.index("h2-multiplex-16")
        payload["cases"][index] = _case(
            "h2-multiplex-16", status="WARN", warnings=["origin peak_active 4 < 8"]
        )
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 0, output)
        total = len(report.REQUIRED_CASES)
        self.assertIn(
            f"protocol acceptance: {total}/{total} cases ({total - 1} PASS, 1 WARN)",
            output,
        )

    def test_partial_mixed_case_is_allowed(self) -> None:
        payload = _valid_report()
        index = report.REQUIRED_CASES.index("mixed-hol-60s")
        payload["cases"][index] = _case("mixed-hol-60s", planned=100, completed=96)
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 0, output)

    def test_unreaped_restart_fails(self) -> None:
        payload = _valid_report()
        index = report.REQUIRED_CASES.index("restart-recovery")
        payload["cases"][index]["metrics"]["old_reaped"] = False
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("restart-recovery: the old process was not reaped", output)

    def test_reused_pid_fails(self) -> None:
        payload = _valid_report()
        index = report.REQUIRED_CASES.index("restart-recovery")
        payload["cases"][index]["metrics"]["new_pid"] = 100
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("restart-recovery: the old and new pid are identical", output)

    def test_failed_post_restart_transfer_fails(self) -> None:
        payload = _valid_report()
        index = report.REQUIRED_CASES.index("restart-recovery")
        payload["cases"][index]["metrics"]["post_restart_hash_ok"] = False
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("restart-recovery: the post-restart transfer did not verify", output)

    def test_unknown_case_fails(self) -> None:
        payload = _valid_report()
        unknown = _case("h2-bulk-8m")
        unknown["name"] = "h4-bulk-8m"
        payload["cases"].append(unknown)
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("unknown case h4-bulk-8m", output)

    def test_missing_metric_fails(self) -> None:
        payload = _valid_report()
        case = payload["cases"][0]
        del case["metrics"]["http_version"]
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("preflight-h1: missing metric http_version", output)

    def test_empty_detail_fails(self) -> None:
        payload = _valid_report()
        payload["cases"][1]["detail"] = "  "
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("preflight-h2: empty detail", output)

    def test_truncated_manifest_fails(self) -> None:
        payload = _valid_report(required=list(report.REQUIRED_CASES[:5]))
        code, output = self._validate(self._write(payload))
        self.assertEqual(code, 1)
        self.assertIn("required manifest does not match the contract", output)

    def test_wrong_arm_fails(self) -> None:
        code, output = self._validate(
            self._write(_valid_report(arm="xray")), control=""
        )
        self.assertEqual(code, 1)
        self.assertIn("arm 'xray' != required 'beam'", output)

    def test_missing_control_is_a_warning_only(self) -> None:
        path = self._write(_valid_report())
        code, output = self._validate(path, control=str(self.dir / "absent.json"))
        self.assertEqual(code, 0, output)
        self.assertIn("no control (Xray) report", output)

    def test_control_report_adds_attribution(self) -> None:
        beam = _valid_report()
        beam["cases"][3] = _case("h2-bulk-8m", status="FAIL", detail="hash differed")
        control = _valid_report(arm="xray")
        control_path = self.dir / "protocol-report-xray.json"
        control_path.write_text(json.dumps(control), encoding="utf-8")
        code, output = self._validate(self._write(beam), control=str(control_path))
        self.assertEqual(code, 1)
        self.assertIn("h2-bulk-8m", output)
        self.assertIn("beam", output)


protocol = _load("protocol_driver", ROOT / "tests" / "tun" / "protocol.py")


class AccountingTests(unittest.TestCase):
    """One outcome rule for every mixed-case unit."""

    def _counts(self) -> dict:
        return {"x_completed": 0, "x_invalid": 0}

    def test_outcome_rule(self) -> None:
        counts = self._counts()
        protocol.apply_outcome(counts, "x_completed", protocol.Outcome.OK)
        self.assertEqual(counts, {"x_completed": 1, "x_invalid": 0})
        protocol.apply_outcome(counts, "x_completed", protocol.Outcome.INVALID)
        self.assertEqual(counts, {"x_completed": 2, "x_invalid": 1})
        protocol.apply_outcome(counts, "x_completed", protocol.Outcome.INCOMPLETE)
        self.assertEqual(counts, {"x_completed": 2, "x_invalid": 1})

    def test_tcp_transfer_classification(self) -> None:
        self.assertIs(protocol.tcp_unit_outcome({"ok": True, "errors": []}), protocol.Outcome.OK)
        # A complete echo whose bytes differ is a correctness failure.
        self.assertIs(
            protocol.tcp_unit_outcome({"ok": False, "errors": []}), protocol.Outcome.INVALID
        )
        # An error, timeout or early close never produced a verdict.
        self.assertIs(
            protocol.tcp_unit_outcome({"ok": False, "errors": ["recv: timed out"]}),
            protocol.Outcome.INCOMPLETE,
        )

    def test_aggregate_keeps_completed_invalid_incomplete_distinct(self) -> None:
        counts = {"x_completed": 0, "x_invalid": 0}
        outcomes = [
            protocol.Outcome.OK,
            protocol.Outcome.OK,
            protocol.Outcome.INVALID,
            protocol.Outcome.INCOMPLETE,
        ]
        for outcome in outcomes:
            protocol.apply_outcome(counts, "x_completed", outcome)
        self.assertEqual(counts, {"x_completed": 3, "x_invalid": 1})
        self.assertEqual(len(outcomes) - counts["x_completed"], 1)

    def test_udp_sequence_outcomes(self) -> None:
        sent = {0: b"a", 1: b"b", 2: b"c"}
        outcomes = protocol.sequence_outcomes(sent, {0, 2}, {1})
        self.assertEqual(
            outcomes, [protocol.Outcome.OK, protocol.Outcome.INVALID, protocol.Outcome.OK]
        )
        # An unanswered sequence is incomplete, not invalid.
        self.assertIs(protocol.sequence_outcomes({3: b"d"}, set(), set())[0], protocol.Outcome.INCOMPLETE)

    def test_corruption_is_sticky_in_both_orders(self) -> None:
        for first, second in ((b"bad", b"good"), (b"good", b"bad")):
            sent = {0: b"good"}
            verified: set[int] = set()
            corrupt: set[int] = set()
            protocol.note_reply(sent, verified, corrupt, 0, first)
            protocol.note_reply(sent, verified, corrupt, 0, second)
            self.assertEqual(
                protocol.sequence_outcomes(sent, verified, corrupt),
                [protocol.Outcome.INVALID],
                f"order {first!r} then {second!r}",
            )
        # Repeating the corrupt reply records one invalid unit, not two.
        sent = {0: b"good"}
        verified = set()
        corrupt = set()
        protocol.note_reply(sent, verified, corrupt, 0, b"bad")
        protocol.note_reply(sent, verified, corrupt, 0, b"bad")
        counts = {"x_completed": 0, "x_invalid": 0}
        for outcome in protocol.sequence_outcomes(sent, verified, corrupt):
            protocol.apply_outcome(counts, "x_completed", outcome)
        self.assertEqual(counts, {"x_completed": 1, "x_invalid": 1})

    def _mixed(self) -> dict:
        return {
            "h1_attempted": 480,
            "h1_completed": 480,
            "h1_invalid": 0,
            "h2_completed": 96,
            "h2_invalid": 0,
            "udp_sent": 600,
            "udp_completed": 600,
            "udp_invalid": 0,
            "udp_stray": 0,
            "dns_planned": 300,
            "dns_completed": 300,
            "dns_invalid": 0,
            "tcp_planned": 1,
            "tcp_completed": 1,
            "tcp_invalid": 0,
        }

    def test_clean_mixed_counts_pass(self) -> None:
        ok, derived = protocol.mixed_verdict(self._mixed(), 60)
        self.assertTrue(ok)
        self.assertEqual(derived["completed"], derived["planned"])
        self.assertEqual(derived["completion_ratio"], 1.0)

    def test_corrupt_unit_fails_the_verdict(self) -> None:
        counts = self._mixed()
        counts["udp_invalid"] = 1
        ok, derived = protocol.mixed_verdict(counts, 60)
        self.assertFalse(ok)
        self.assertEqual(derived["invalid"], 1)

    def test_stray_datagram_does_not_inflate_completion(self) -> None:
        counts = self._mixed()
        counts["udp_stray"] = 3
        counts["udp_invalid"] = 3
        ok, derived = protocol.mixed_verdict(counts, 60)
        self.assertFalse(ok)
        self.assertEqual(derived["completed"], derived["planned"])
        self.assertEqual(derived["invalid"], 3)


class LatticeTests(unittest.TestCase):
    def test_complete_truth_table(self) -> None:
        self.assertTrue(report.compute_complete([], [], True))
        self.assertFalse(report.compute_complete(["h2-bulk-8m"], [], True))
        self.assertFalse(report.compute_complete([], ["h2-bulk-8m"], True))
        self.assertFalse(report.compute_complete([], [], False))

    def test_status_sets_are_explicit(self) -> None:
        self.assertIn("WARN", report.ACCEPTED_STATUSES)
        self.assertNotIn(report.FAIL_STATUS, report.ACCEPTED_STATUSES)
        self.assertNotIn(report.BLOCKED_STATUS, report.ACCEPTED_STATUSES)
        self.assertEqual(
            report.KNOWN_STATUSES,
            {"PASS", "WARN", "INFO", report.FAIL_STATUS, report.BLOCKED_STATUS},
        )


class MergeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.results = self.dir / "results"
        self.results.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_case(self, payload: dict, name: str) -> None:
        (self.results / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")

    def _merge(self, extra: dict | None = None, environment: str = "") -> tuple[int, dict]:
        extra_path = self.dir / "extra.json"
        if extra is not None:
            extra_path.write_text(json.dumps(extra), encoding="utf-8")
        environment_path = self.dir / "environment.txt"
        environment_path.write_text(environment, encoding="utf-8")
        out = self.dir / "protocol-report-beam.json"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = report.merge(
                _namespace(
                    results=str(self.results),
                    extra=[str(extra_path)] if extra is not None else [],
                    environment=str(environment_path),
                    arm="beam",
                    commit="a" * 40,
                    binary_sha256="b" * 64,
                    out=str(out),
                    tsv=str(self.dir / "results.tsv"),
                )
            )
        self.assertEqual(code, 0, buffer.getvalue())
        return code, json.loads(out.read_text(encoding="utf-8"))

    def test_merge_builds_a_valid_report(self) -> None:
        for name in report.REQUIRED_CASES:
            if name.startswith("preflight") or name == "restart-recovery":
                continue
            self._write_case(_case(name), name)
        extra = {
            "complete": True,
            "cases": [
                _case("preflight-h1"),
                _case("preflight-h2"),
                _case("preflight-h3"),
                _case("restart-recovery"),
            ],
            "metrics": {"h2-multiplex-16": {"origin_connections": 1, "origin_peak_active": 12}},
            "environment": {"baseline_rtt_ms": 250, "baseline_target_rtt_ms": 0},
        }
        _, merged = self._merge(
            extra=extra,
            environment="rtt_ms=250\nloss_pct=1\nudp_mode=xudp\ntun_mtu=1500\n",
        )
        self.assertTrue(merged["complete"])
        self.assertEqual(merged["missing"], [])
        self.assertEqual(merged["required"], report.REQUIRED_CASES)
        self.assertEqual(merged["environment"]["loss_pct"], 1)
        self.assertEqual(merged["environment"]["baseline_rtt_ms"], 250)
        multiplex = next(
            case for case in merged["cases"] if case["name"] == "h2-multiplex-16"
        )
        self.assertEqual(multiplex["metrics"]["origin_peak_active"], 12)
        self.assertEqual(report.check_report(merged, "beam"), [])

    def test_merge_marks_missing_cases_incomplete(self) -> None:
        self._write_case(_case("h2-bulk-8m"), "h2-bulk-8m")
        _, merged = self._merge(extra={"complete": True})
        self.assertFalse(merged["complete"])
        self.assertIn("h3-bulk-8m", merged["missing"])
        problems = report.check_report(merged, "beam")
        self.assertTrue(any("missing case h3-bulk-8m" in problem for problem in problems))

    def test_merge_ignores_non_case_json(self) -> None:
        (self.results / "h2-client-raw.json").write_text(
            json.dumps({"ok": True, "connections": 1}), encoding="utf-8"
        )
        for name in report.REQUIRED_CASES:
            if name.startswith("preflight") or name == "restart-recovery":
                continue
            self._write_case(_case(name), name)
        extra = {
            "complete": True,
            "cases": [
                _case("preflight-h1"),
                _case("preflight-h2"),
                _case("preflight-h3"),
                _case("restart-recovery"),
            ],
        }
        _, merged = self._merge(extra=extra)
        self.assertEqual(merged["duplicates"], [])
        self.assertTrue(merged["complete"])

    def test_merge_detects_duplicate_cases(self) -> None:
        self._write_case(_case("h2-bulk-8m"), "h2-bulk-8m")
        self._write_case(_case("h2-bulk-8m"), "h2-bulk-8m-copy")
        _, merged = self._merge(extra={"complete": True})
        self.assertEqual(merged["duplicates"], ["h2-bulk-8m"])
        self.assertFalse(merged["complete"])

    def test_merge_requires_a_results_directory(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = report.merge(
                _namespace(
                    results=str(self.dir / "absent"),
                    extra=[],
                    environment="",
                    arm="beam",
                    commit="",
                    binary_sha256="",
                    out=str(self.dir / "out.json"),
                    tsv="",
                )
            )
        self.assertEqual(code, 1)
        self.assertIn("results directory missing", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
