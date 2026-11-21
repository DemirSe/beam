#!/usr/bin/env python3
"""Contract tests for the general systemd deploy units and client docs.

These tests verify the restart/liveness invariants of `deploy/beam.service`
and `deploy/beam-liveness.timer`, plus the documented Linux client pins.
No network, root, or host service is needed.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
CLIENT_DOC = ROOT / "docs" / "CLIENT.md"


class RestartPolicyTest(unittest.TestCase):
    """A crash must recover, and a persistent failure must stay bounded."""

    def settings(self, path):
        section = None
        values = {}
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                values[(section, key)] = value.strip()
        return values

    def seconds(self, value):
        factors = {"s": 1, "m": 60}
        if value[-1] in factors:
            return int(value[:-1]) * factors[value[-1]]
        return int(value)

    def unit(self):
        return self.settings(DEPLOY / "beam.service")

    def test_beam_restarts_are_bounded(self):
        unit = self.unit()
        self.assertEqual(unit[("Service", "Restart")], "always")
        interval = self.seconds(unit[("Unit", "StartLimitIntervalSec")])
        burst = int(unit[("Unit", "StartLimitBurst")])
        self.assertGreater(interval, 0, "a zero interval disables the limit")
        self.assertGreater(burst, 1)

    def test_the_window_covers_the_slowest_start(self):
        unit = self.unit()
        interval = self.seconds(unit[("Unit", "StartLimitIntervalSec")])
        burst = int(unit[("Unit", "StartLimitBurst")])
        period = self.seconds(unit[("Service", "TimeoutStartSec")])
        period += self.seconds(unit[("Service", "RestartSec")])
        # A shorter window lets old attempts age out before the burst is
        # reached, so the slowest allowed start would loop forever.
        self.assertGreaterEqual(interval, (burst - 1) * period)

    def test_every_restarting_unit_is_bounded(self):
        for path in sorted(DEPLOY.glob("*.service")):
            unit = self.settings(path)
            if unit.get(("Service", "Restart"), "no") == "no":
                continue
            with self.subTest(unit=path.name):
                self.assertIn(("Unit", "StartLimitIntervalSec"), unit)
                self.assertIn(("Unit", "StartLimitBurst"), unit)
                interval = self.seconds(
                    unit[("Unit", "StartLimitIntervalSec")]
                )
                self.assertGreater(interval, 0)
                self.assertGreater(int(unit[("Unit", "StartLimitBurst")]), 0)

    def test_liveness_retry_clears_the_limit_window(self):
        interval = self.seconds(self.unit()[("Unit", "StartLimitIntervalSec")])
        timer = (DEPLOY / "beam-liveness.timer").read_text()
        self.assertIn("OnUnitActiveSec=5min", timer)
        limit = re.search(
            r"^LIMIT = (\d+)$",
            (DEPLOY / "liveness-check.py").read_text(),
            re.MULTILINE,
        )
        self.assertIsNotNone(limit, "liveness-check.py has no LIMIT")
        # systemd refuses a start until the window clears, so the timer's
        # retry must land after it.
        self.assertGreater(int(limit.group(1)) * 5 * 60, interval)


class LinuxClientDocsTest(unittest.TestCase):
    """The Linux client inputs and DNS limits must stay documented as tested."""

    def section(self):
        client = CLIENT_DOC.read_text()
        return client.split("## Linux tray and DNS switch", 1)[1].split(
            "## Mobile profile", 1
        )[0]

    def test_client_inputs_are_documented(self):
        section = self.section()
        for token in ("CONFIG_SRC", "CORE_DIR", "python3", "INSTALL_USER",
                      "libcronet.so", "LICENSE", "beam.toml"):
            self.assertIn(token, section, token)

    def test_core_pins_match_the_installer(self):
        installer = (ROOT / "clients/linux-tray/install.sh").read_text()
        pins = re.findall(
            r"^CORE_(?:SING|LIB)_SHA=([0-9a-f]{64})$", installer, re.M
        )
        self.assertEqual(len(pins), 2, "install.sh must pin both core files")
        section = self.section()
        for pin in pins:
            self.assertIn(pin, section, pin)

    def test_dns_claims_stay_within_the_isolated_test(self):
        flat = " ".join(self.section().split())
        # Content is not ownership: a host file can hold the same bytes.
        self.assertNotIn("cannot restore a DNS hijack", flat)
        self.assertIn("Content alone never proves ownership", flat)
        self.assertIn("99-beam.conf.beam-own", flat)
        self.assertIn("safe to run by hand", flat)
        # The resolver path and the live DNS effect are not proven by the
        # rootless state test, and the docs must say so.
        self.assertIn("does not prove that live path", flat)
        self.assertIn("not tested", flat)


if __name__ == "__main__":
    unittest.main(verbosity=2)
