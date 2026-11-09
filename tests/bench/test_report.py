#!/usr/bin/env python3
"""Contract tests for the benchmark report and metadata parsers.

Fixtures are generated in a temporary directory: no network, no namespaces,
no keys. Every test pins one decision that the hosted lab depends on.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


report = _load("bench_report", ROOT / "bench" / "report.py")
meta = _load("bench_meta", ROOT / "bench" / "meta.py")

SCENARIOS = (
    "tcp-dl-1",
    "tcp-dl-4",
    "tcp-ul-1",
    "tcp-ul-4",
    "https-bulk",
    "udp-echo",
    "dns-a",
    "h3-latency",
)


def _result(scenario, arm, rep, *, busy=30.0, throughput=1.2e9):
    return {
        "schema": "beam-bench-run/1",
        "scenario": scenario,
        "arm": arm,
        "rep": rep,
        "status": "ok",
        "reason": None,
        "metrics": {
            "throughput_bps": throughput,
            "mib_per_s": 120.0,
            "pps": 90000.0,
            "mbps": 900.0,
            "loss_pct": 0.0,
            "rtt_samples_us": [250000.0, 251000.0],
            "latency_samples_us": [250000.0, 251000.0],
        },
        "cpu": {
            "server_s": 1.0,
            "client_s": 0.5,
            "target_s": 0.2,
            "server_core_busy_pct": 40.0,
            "client_core_busy_pct": busy,
            "target_core_busy_pct": busy,
            "driver_core_busy_pct": busy,
            "server_s_per_gib": 0.5,
            "client_s_per_gib": 0.2,
            "server_cpu_max": "50000 100000",
            "server_memory_max": "1073741824",
            "server_memory_peak": "33554432",
        },
        "mem": {
            "rss_after_warmup_kib": 9000,
            "rss_kib": 9500,
            "fds": 30,
            "threads": 4,
        },
    }


def _qdisc(rtt_ms, loss_pct, drops=0):
    entry = {
        "source": "json",
        "kind": "netem",
        "delay_ms": rtt_ms / 2 if rtt_ms else None,
        "loss_pct": loss_pct if loss_pct else None,
        "drops": drops,
        "overlimits": 0,
        "qlen": 0,
        "backlog": 0,
    }
    return {"client": dict(entry), "server": dict(entry)}


def _meta(reps, **overrides):
    data = {
        "schema": "beam-bench-meta/1",
        "run_id": "fixture",
        "reps": reps,
        "duration_s": 5,
        "rtt_ms": 250,
        "loss_pct": 0.0,
        "bench_max_load": 4.0,
        "arms": ["stock", "beam"],
        "cpu_roles": {
            "server": 0,
            "client": 1,
            "client_cores": [1],
            "target": 2,
            "driver": 1,
        },
        "host": {"logical_cpus": 4, "model": "test"},
        "git": {"commit": "0" * 40, "dirty": False},
        "binaries": {},
        "versions": {},
        "h3": {"available": True, "blocked_reason": None},
        "warnings": [],
        "host_load1_before": 0.05,
        "host_load1_after": 0.05,
        "qdisc": _qdisc(250, 0.0),
    }
    data.update(overrides)
    return data


def _results(reps, *, busy=30.0, busy_overrides=None, skip=(), scenarios=SCENARIOS):
    overrides = busy_overrides or {}
    items = []
    for arm in ("stock", "beam"):
        for scenario in scenarios:
            for rep in range(1, reps + 1):
                if (scenario, arm, rep) in skip:
                    continue
                value = overrides.get((scenario, arm, rep), busy)
                items.append(_result(scenario, arm, rep, busy=value))
    return items


def _write(tmp, results, meta_data):
    root = Path(tmp)
    (root / "raw").mkdir(parents=True)
    (root / "logs").mkdir()
    for index, item in enumerate(results):
        (root / "raw" / f"{index:03d}.json").write_text(
            json.dumps(item), encoding="utf-8"
        )
    (root / "meta.json").write_text(json.dumps(meta_data), encoding="utf-8")
    return root


def _section(markdown, title, next_title):
    start = markdown.index(title)
    end = markdown.index(next_title, start)
    return markdown[start:end]


class ReportContractTests(unittest.TestCase):
    def test_median_saturation_decides(self):
        import tempfile

        overrides = {("tcp-dl-1", "beam", 10): 99.0}
        results = _results(10, busy_overrides=overrides)
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, results, _meta(10))
            summary = report.build(root)
        self.assertTrue(summary["valid"], summary["invalid_reasons"])

        results = _results(10, busy_overrides={
            ("tcp-dl-1", "beam", rep): 90.0 for rep in range(1, 11)
        })
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, results, _meta(10))
            summary = report.build(root)
        self.assertFalse(summary["valid"])
        self.assertTrue(
            any("role core saturated" in reason for reason in summary["invalid_reasons"])
        )

    def test_paired_latency_drops_unmatched_repetitions(self):
        import tempfile

        results = _results(2, skip={("dns-a", "beam", 2)})
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, results, _meta(2))
            summary = report.build(root)
        details = summary["latency_repetitions"]["dns-a"]
        self.assertEqual(details["paired_repetitions"], 1)
        self.assertEqual(details["dropped_repetitions"], [2])
        self.assertEqual(
            summary["comparisons"]["latency"]["dns-a"]["samples"]["stock"],
            summary["comparisons"]["latency"]["dns-a"]["samples"]["beam"],
        )

    def test_drop_rule_is_loss_aware(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, _results(2), _meta(2, qdisc=_qdisc(250, 0.0, drops=5)))
            summary = report.build(root)
        self.assertTrue(
            any("netem qdisc dropped 5 packets" in reason
                for reason in summary["invalid_reasons"]),
            summary["invalid_reasons"],
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = _write(
                tmp,
                _results(2),
                _meta(2, loss_pct=1.0, qdisc=_qdisc(250, 1.0, drops=50)),
            )
            summary = report.build(root)
        self.assertEqual(summary["qdisc_drops"]["client"], 50)
        self.assertFalse(
            any("dropped" in reason for reason in summary["invalid_reasons"]),
            summary["invalid_reasons"],
        )

        text = (
            "qdisc netem 8001: root refcnt 2 limit 20000 "
            "delay 12.5ms loss 1%\n"
            " Sent 100 bytes 1 pkt (dropped 123, overlimits 0 requeues 0)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tc.txt"
            path.write_text(text, encoding="utf-8")
            parsed = meta.parse_qdisc_text(path)
        self.assertEqual(parsed["drops"], 123)
        self.assertEqual(parsed["delay_ms"], 12.5)
        self.assertEqual(parsed["loss_pct"], 1.0)
        self.assertEqual(parsed["source"], "text")

        # `tc -j -s qdisc show` keeps the counters at the top level of the
        # qdisc object; do not lose them behind a non-existent "stats" key.
        payload = [
            {
                "kind": "netem",
                "options": {
                    "limit": 20000,
                    "delay": {"delay": 0.025, "jitter": 0},
                    "loss-random": {"loss": 0.01},
                },
                "drops": 7,
                "overlimits": 1,
                "qlen": 0,
                "backlog": 0,
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tc.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            parsed = meta.parse_qdisc_json(path)
        self.assertEqual(parsed["drops"], 7)
        self.assertEqual(parsed["overlimits"], 1)
        self.assertEqual(parsed["delay_ms"], 25.0)
        self.assertEqual(parsed["loss_pct"], 1.0)
        self.assertEqual(parsed["source"], "json")

    def test_qdisc_evidence_prefers_final_counters(self):
        import tempfile

        initial = [{
            "kind": "netem",
            "options": {"delay": {"delay": 0.025}, "loss-random": {"loss": 0.01}},
            "drops": 0, "overlimits": 0, "qlen": 0, "backlog": 0,
        }]
        final = [{
            "kind": "netem",
            "options": {"delay": {"delay": 0.025}, "loss-random": {"loss": 0.01}},
            "drops": 732, "overlimits": 0, "qlen": 0, "backlog": 0,
        }]
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp)
            for role in ("client", "server"):
                (logs / f"tc-{role}-initial.json").write_text(
                    json.dumps(initial), encoding="utf-8"
                )
                (logs / f"tc-{role}-final.json").write_text(
                    json.dumps(final), encoding="utf-8"
                )
            evidence = meta.qdisc_evidence(logs)
        for role in ("client", "server"):
            self.assertEqual(evidence[role]["drops"], 732)
            self.assertEqual(evidence[role]["delay_ms"], 25.0)

    def test_qdisc_evidence_is_verified(self):
        import tempfile

        matching = _qdisc(25, 0.0)
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, _results(2), _meta(2, rtt_ms=25, qdisc=matching))
            summary = report.build(root)
        self.assertFalse(
            any("netem delay" in reason for reason in summary["invalid_reasons"]),
            summary["invalid_reasons"],
        )

        wrong = _qdisc(25, 0.0)
        wrong["client"]["delay_ms"] = 20.0
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, _results(2), _meta(2, rtt_ms=25, qdisc=wrong))
            summary = report.build(root)
        self.assertTrue(
            any("client: netem delay 20.0ms" in reason
                for reason in summary["invalid_reasons"]),
            summary["invalid_reasons"],
        )

        unavailable = {
            "client": {"source": "unavailable"},
            "server": {"source": "unavailable"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, _results(2), _meta(2, qdisc=unavailable))
            summary = report.build(root)
        self.assertTrue(
            any("client: netem evidence unavailable" in reason
                for reason in summary["invalid_reasons"]),
            summary["invalid_reasons"],
        )

    def test_require_complete_rejects_missing_repetitions(self):
        import tempfile

        results = _results(2)
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, results, _meta(3))
            permissive = report.build(root)
            strict = report.build(root, require_complete=True)
        self.assertTrue(permissive["valid"], permissive["invalid_reasons"])
        self.assertFalse(strict["valid"])
        self.assertTrue(
            any("2/3 repetitions" in reason for reason in strict["invalid_reasons"]),
            strict["invalid_reasons"],
        )

        without_h3 = _results(2, scenarios=SCENARIOS[:-1])
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, without_h3, _meta(2))
            missing = report.build(root, require_complete=True)
        self.assertTrue(
            any(reason == "h3-latency: missing repetitions"
                for reason in missing["invalid_reasons"]),
            missing["invalid_reasons"],
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = _write(
                tmp,
                without_h3,
                _meta(2, h3={"available": False, "blocked_reason": "no HTTP/3"}),
            )
            blocked = report.build(root, require_complete=True)
        self.assertFalse(
            any("h3-latency" in reason for reason in blocked["invalid_reasons"]),
            blocked["invalid_reasons"],
        )

    def test_scenario_filter_validates_only_measured_scenarios(self):
        import tempfile

        results = _results(3, scenarios=("https-bulk",))
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, results, _meta(3))
            filtered = report.build(root, scenarios=("https-bulk",))
            unfiltered = report.build(root)
        self.assertTrue(filtered["valid"], filtered["invalid_reasons"])
        self.assertFalse(unfiltered["valid"])
        self.assertTrue(
            any(
                "missing required data" in reason
                for reason in unfiltered["invalid_reasons"]
            )
        )

    def test_ratio_only_keeps_json_but_hides_verdicts(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, _results(2), _meta(2))
            summary = report.build(root)
            again = report.build(root)
        strict = report.render_markdown(summary)
        soft = report.render_markdown(summary, ratio_only=True)

        self.assertIn("FAIL", _section(strict, "## Gates", "## Throughput"))
        gates = _section(soft, "## Gates", "## Throughput")
        self.assertNotIn("PASS", gates)
        self.assertNotIn("FAIL", gates)
        self.assertIn("INFO", gates)
        self.assertNotIn("Headline eligible", soft)
        self.assertEqual(summary["valid"], again["valid"])
        self.assertEqual(summary["gates"], again["gates"])
        self.assertIn("hard_requirements_status", summary)

    def test_load_threshold_comes_from_meta(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, _results(2), _meta(2, bench_max_load=4.0,
                                                 host_load1_after=2.5))
            quiet = report.build(root)
        self.assertEqual(quiet["host_noise"], [])

        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, _results(2), _meta(2, bench_max_load=4.0,
                                                 host_load1_after=4.5))
            noisy = report.build(root)
        self.assertTrue(
            any("threshold 4" in reason for reason in noisy["host_noise"]),
            noisy["host_noise"],
        )

    def test_resource_rows_are_informational(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = _write(tmp, _results(2), _meta(2))
            (root / "masks.tsv").write_text(
                "beam\t1\tserver-resources\t-\t"
                "memory_peak=33554432 oom=0 oom_kill=0 "
                "memory_max=1073741824 cgroup=/test.scope\n",
                encoding="utf-8",
            )
            summary = report.build(root)
        rows = {row["label"]: row for row in summary["table_rows"]["resources"]}
        for label in (
            "Server cgroup CPU ceiling (cpu.max)",
            "Server cgroup memory ceiling (memory.max)",
            "Server memory peak (memory.peak)",
            "Server OOM kills (memory.events)",
        ):
            self.assertIn(label, rows)
            self.assertEqual(report.row_status(rows[label]), "INFO", label)
        self.assertEqual(rows["Server memory peak (memory.peak)"]["beam"], "32.0 MiB")
        self.assertEqual(rows["Server OOM kills (memory.events)"]["beam"], "0")


if __name__ == "__main__":
    unittest.main()
