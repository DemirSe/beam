#!/usr/bin/env python3
"""Rootless contract tests for the parallel preprod workflow and final gate."""

from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("beam_preprod_gate", ROOT / "tests" / "preprod" / "gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

COMMIT = "a" * 40
BASELINE = "b" * 40
RUN_ID = "12345"
WORKFLOW = ROOT / ".github" / "workflows" / "lab-hosted.yml"


def _job(name: str) -> str:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"  {name}:")
    end = next(
        (index for index in range(start + 1, len(lines))
         if re.fullmatch(r"  [a-z][a-z-]+:", lines[index])),
        len(lines),
    )
    return "\n".join(lines[start:end])


class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _good(self) -> None:
        for phase in gate.PHASES:
            gate.record(self.root / f"evidence-{phase}.json", phase, COMMIT, BASELINE, RUN_ID)
        for mode in gate.MODES:
            base = self.root / "tun" / mode
            base.mkdir(parents=True)
            (base / "environment.txt").write_text(
                f"commit={COMMIT}\nudp_mode={mode}\nrtt_ms=250\nloss_pct=0\n", encoding="utf-8"
            )
            (base / "results-beam.tsv").write_text(
                "".join(f"{probe}\tPASS\tdetail\n" for probe in gate.PROBES), encoding="utf-8"
            )
        protocols = self.root / "protocols"
        protocols.mkdir()
        (protocols / "protocol-report-beam.json").write_text(json.dumps({
            "commit": COMMIT, "arm": "beam", "complete": True,
            "missing": [], "duplicates": [],
            "cases": [{"name": name, "status": "PASS"} for name in gate._protocol_cases()],
        }), encoding="utf-8")
        (protocols / "environment.txt").write_text(
            "rtt_ms=250\nloss_pct=0\nudp_mode=xudp\n", encoding="utf-8"
        )
        bench = self.root / "bench"
        bench.mkdir()
        (bench / "meta.json").write_text(json.dumps({
            "git": {"commit": COMMIT}, "arms": ["baseline", "beam"], "reps": 3,
        }), encoding="utf-8")
        (bench / "summary.json").write_text(json.dumps({
            "valid": True, "headline_eligible": True,
            "reference_arm": "baseline", "candidate_arm": "beam",
        }), encoding="utf-8")
        (bench / "environment.txt").write_text(
            "arms=baseline,beam\nrtt_ms=250\nloss_pct=0\n", encoding="utf-8"
        )
        stress = self.root / "stress"
        stress.mkdir()
        (stress / "summary.json").write_text(json.dumps({
            "ok": True,
            "checks": [{"name": f"check-{index}", "ok": True} for index in range(13)],
        }), encoding="utf-8")

    def _check(self, **overrides) -> list[str]:
        options = {
            "commit": COMMIT, "baseline": BASELINE, "run_id": RUN_ID,
            "lab_result": "success",
        }
        options.update(overrides)
        return gate.check(self.root, **options)

    def test_complete_evidence_passes(self) -> None:
        self._good()
        self.assertEqual(self._check(), [])

    def test_missing_phase_or_cancelled_matrix_fails(self) -> None:
        self._good()
        (self.root / "evidence-stress.json").unlink()
        problems = self._check()
        self.assertTrue(any("missing evidence for phase stress" in item for item in problems))
        self.assertTrue(any("lab matrix result is 'cancelled'" in item
                            for item in self._check(lab_result="cancelled")))

    def test_wrong_commit_or_baseline_fails(self) -> None:
        self._good()
        path = self.root / "evidence-protocols.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["commit"] = "c" * 40
        path.write_text(json.dumps(payload), encoding="utf-8")
        problems = self._check()
        self.assertTrue(any("evidence-protocols.json: commit" in item for item in problems))
        self.assertTrue(any("protocols: commit=" in item
                            for item in self._check(commit="c" * 40)))

        payload["commit"] = COMMIT
        payload["baseline"] = "d" * 40
        path.write_text(json.dumps(payload), encoding="utf-8")
        problems = self._check()
        self.assertTrue(any("evidence-protocols.json: baseline" in item for item in problems))

    def test_duplicate_phase_evidence_fails(self) -> None:
        self._good()
        (self.root / "evidence-extra.json").write_text(
            (self.root / "evidence-tun.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        problems = self._check()
        self.assertTrue(any("duplicate evidence for phase tun" in item for item in problems))

    def test_failed_component_report_fails(self) -> None:
        self._good()
        path = self.root / "stress" / "summary.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["checks"][0]["ok"] = False
        path.write_text(json.dumps(payload), encoding="utf-8")
        problems = self._check()
        self.assertTrue(any("stress: failed checks" in item for item in problems))

        path = self.root / "tun" / "legacy" / "results-beam.tsv"
        rows = path.read_text(encoding="utf-8")
        path.write_text(rows.replace(f"{gate.PROBES[0]}\tPASS", f"{gate.PROBES[0]}\tFAIL"), encoding="utf-8")
        problems = self._check()
        self.assertTrue(any(f"tun/legacy: {gate.PROBES[0]}" in item for item in problems))

    def test_wrong_sha_in_a_report_fails(self) -> None:
        self._good()
        path = self.root / "bench" / "meta.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["git"]["commit"] = "e" * 40
        path.write_text(json.dumps(payload), encoding="utf-8")
        problems = self._check()
        self.assertTrue(any("bench: meta.json does not name" in item for item in problems))


class WorkflowTests(unittest.TestCase):
    def test_parallel_phases_keep_every_preprod_gate(self) -> None:
        lab = _job("lab")
        for phase in gate.PHASES:
            self.assertIn(f"matrix.phase == '{phase}'", lab)
        self.assertIn("fromJSON(inputs.suite == 'preprod' && '[\"tun\",\"protocols\",\"bench\",\"stress\"]'", lab)
        self.assertIn("fail-fast: false", lab)
        self.assertIn("timeout-minutes: ${{ fromJSON(inputs.job_timeout_minutes) }}", lab)
        self.assertIn("make verify", lab)
        self.assertIn("config_matrix.py", lab)
        self.assertIn("python3 bench/preprod.py", lab)
        self.assertIn("protocol_report.py", lab)
        self.assertEqual(lab.count("if: inputs.suite != 'stress'"), 2)
        self.assertIn("inputs.baseline_ref != '' && (inputs.suite != 'preprod' || matrix.phase == 'bench')", lab)
        self.assertIn("name: preprod-gate-${{ github.run_id }}-${{ matrix.phase }}", lab)
        self.assertIn("if: always() && inputs.publish && inputs.suite != 'preprod'", lab)

    def test_final_gate_is_fail_closed_and_pinned(self) -> None:
        gate_job = _job("preprod-gate")
        self.assertIn("needs: lab", gate_job)
        self.assertIn("if: ${{ always() && inputs.suite == 'preprod' }}", gate_job)
        self.assertIn("ref: ${{ github.sha }}", gate_job)
        self.assertIn("refs/remotes/origin/prod", gate_job)
        self.assertIn("pattern: preprod-gate-${{ github.run_id }}-*", gate_job)
        self.assertIn("merge-multiple: true", gate_job)
        self.assertIn("LAB_RESULT: ${{ needs.lab.result }}", gate_job)
        self.assertIn('tests/preprod/gate.py" check', gate_job)
        self.assertNotIn("git push", gate_job)


if __name__ == "__main__":
    unittest.main()
