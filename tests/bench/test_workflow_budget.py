#!/usr/bin/env python3
"""Rootless contract tests for lab-hosted profile and bench budget resolution."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "lab-hosted.yml"

INPUT_KEYS = (
    "SCENARIOS", "HTTPS_MIB", "HTTPS_PARALLEL", "RTT_MS", "LOSS_PCT",
    "REPS", "DURATION", "BASELINE_REF", "PERF", "PERF_EVENTS", "UDP_COUNT",
    "UDP_WINDOW", "PIPE_PAGES_SOFT", "LOG_LEVEL", "SUITE", "PUBLISH",
)


def _resolve(profile: str, reps: str = "") -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    step = lines.index("      - name: Resolve profile")
    run = lines.index("        run: |", step)
    end = next(index for index in range(run + 1, len(lines))
               if lines[index] and not lines[index].startswith("          "))
    script = "\n".join(line[10:] if line else "" for line in lines[run + 1:end])

    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp) / "github-env"
        env = {key: value for key, value in os.environ.items() if key in ("PATH", "HOME")}
        env.update({f"INPUT_{key}": "" for key in INPUT_KEYS})
        env.update({
            "INPUT_PROFILE": profile,
            "INPUT_REPS": reps,
            "INPUT_SUITE": "bench",
            "INPUT_PUBLISH": "false",
            "INPUT_PERF": "false",
            "GITHUB_ENV": str(env_file),
            "GITHUB_SHA": "a" * 40,
        })
        result = subprocess.run(
            ["bash", "-c", script], cwd=tmp, env=env,
            capture_output=True, text=True, check=False,
        )
        values = {}
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                name, separator, value = line.partition("=")
                if separator:
                    values[name] = value
    return result, values


class ResolveProfileTests(unittest.TestCase):
    def _ok(self, profile: str, reps: str = "") -> dict[str, str]:
        result, values = _resolve(profile, reps)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return values

    def test_standard_budget_scales_only_with_a_reps_override(self) -> None:
        self.assertEqual(self._ok("standard")["BENCH_TIMEOUT"], "2400")
        self.assertEqual(self._ok("standard", "3")["BENCH_TIMEOUT"], "2400")
        self.assertEqual(self._ok("standard", "5")["BENCH_TIMEOUT"], "4000")
        self.assertEqual(self._ok("standard", "7")["BENCH_TIMEOUT"], "5600")
        self.assertEqual(self._ok("standard", "10")["BENCH_TIMEOUT"], "6000")
        self.assertEqual(self._ok("standard", "6000")["BENCH_TIMEOUT"], "6000")
        self.assertEqual(self._ok("standard", "0005")["BENCH_TIMEOUT"], "4000")

    def test_other_measurement_inputs_stay_unchanged(self) -> None:
        values = self._ok("standard", "5")
        self.assertEqual(values["REPS"], "5")
        self.assertEqual(values["DURATION"], "10")
        self.assertEqual(values["RTT_MS"], "250")
        self.assertEqual(values["LOSS"], "0")
        self.assertEqual(values["BENCH_SCENARIOS"], "all")
        self.assertEqual(values["BENCH_ARMS"], "stock,beam")
        self.assertEqual(values["BENCH_REQUIRE_COMPLETE"], "1")
        self.assertEqual(values["QUICK"], "0")
        self.assertEqual(values["TUN_TIMEOUT"], "600")
        self.assertEqual(values["SERVER_CPU_QUOTA"], "50%")

    def test_smoke_and_claim_budgets_stay_fixed(self) -> None:
        self.assertEqual(self._ok("smoke")["BENCH_TIMEOUT"], "900")
        self.assertEqual(self._ok("smoke", "5")["BENCH_TIMEOUT"], "900")
        self.assertEqual(self._ok("claim")["BENCH_TIMEOUT"], "6000")
        self.assertEqual(self._ok("claim", "5")["BENCH_TIMEOUT"], "6000")

    def test_invalid_reps_fail_before_a_budget_is_exported(self) -> None:
        for reps in ("abc", "-1", "1.5", "0", "0000", "6001", "99999", "9" * 30):
            with self.subTest(reps=reps):
                result, values = _resolve("standard", reps)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("::error::reps", result.stdout + result.stderr)
                self.assertNotIn("BENCH_TIMEOUT", values)


if __name__ == "__main__":
    unittest.main()
