#!/usr/bin/env python3
"""Restart policy tests for beam.service.

A host that nobody touches must recover from a crash by itself, and a process
that crashes at once must not be restarted in a hot loop. These tests pin the
systemd settings that give both: `Restart=always` with exponential backoff,
inside a start limit that the backoff cannot fill.

Why this works, from systemd source and manual:

- `RestartSteps=` and `RestartMaxDelaySec=` were added in systemd 254. Debian
  13 ships systemd 257.13 and AlmaLinux 10 ships systemd 257, so both
  supported platforms have them. Either setting alone is verified and then
  ignored, so the tests require both.
- The delay grows geometrically from `RestartSec=` to `RestartMaxDelaySec=`
  and then stays at that maximum (systemd.service(5), service.c).
- Start rate limiting counts starts in a fixed window that opens at the first
  start (ratelimit.c). With a 60 s delay, ten starts no longer fit in the
  300 s window, so an automatic restart is never refused and the unit never
  needs `systemctl reset-failed`.

These tests read the unit file only. No systemd, root, or network is needed.
"""

import configparser
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "deploy" / "beam.service"

# A restart must never be delayed longer than this, so a fixed unit comes back
# without an operator waiting.
MAX_RECOVERY_SECONDS = 120


def seconds(value):
    """Convert a systemd time span with the default unit of seconds."""
    value = value.strip()
    for suffix, factor in (("ms", 0.001), ("min", 60), ("h", 3600), ("s", 1)):
        if value.endswith(suffix):
            return float(value[: -len(suffix)]) * factor
    return float(value)


class RestartPolicyTest(unittest.TestCase):
    def setUp(self):
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.optionxform = str  # systemd keys are case-sensitive
        parser.read_string(UNIT.read_text())
        self.unit = parser

    def service(self, key):
        self.assertIn(key, self.unit["Service"], f"beam.service has no {key}=")
        return self.unit["Service"][key]

    def limit(self, key):
        self.assertIn(key, self.unit["Unit"], f"beam.service has no {key}=")
        return self.unit["Unit"][key]

    def delays(self):
        """The restart intervals systemd will use, in order."""
        base = seconds(self.service("RestartSec"))
        steps = int(self.service("RestartSteps"))
        cap = seconds(self.service("RestartMaxDelaySec"))
        ratio = (cap / base) ** (1 / steps)
        return [base * ratio**step for step in range(steps)] + [cap]

    def test_a_crash_restarts_and_the_backoff_is_active(self):
        self.assertEqual(self.service("Restart").strip(), "always")
        base = seconds(self.service("RestartSec"))
        self.assertGreater(base, 0, "backoff needs a non-zero RestartSec")
        self.assertGreater(
            int(self.service("RestartSteps")), 0, "no steps means no backoff"
        )
        cap = seconds(self.service("RestartMaxDelaySec"))
        self.assertGreater(
            cap, base, "systemd resets RestartSec= to RestartMaxDelaySec="
        )

    def test_the_delay_grows_and_stays_bounded(self):
        delays = self.delays()
        self.assertEqual(delays, sorted(delays), "the delay must not shrink")
        self.assertGreater(delays[-1], delays[0], "the delay never grows")
        self.assertLessEqual(
            delays[-1],
            MAX_RECOVERY_SECONDS,
            "a fixed unit must come back without an operator waiting",
        )

    def test_automatic_starts_cannot_hit_the_start_limit(self):
        interval = seconds(self.limit("StartLimitIntervalSec"))
        burst = int(self.limit("StartLimitBurst"))
        self.assertGreater(interval, 0, "a zero interval disables the limit")
        self.assertGreater(burst, 1)

        # systemd opens one window at the first start and refuses a start once
        # the window holds more than `burst` of them. Count what fits.
        starts, elapsed = 1, 0.0
        delays = self.delays()
        while True:
            elapsed += delays[min(starts - 1, len(delays) - 1)]
            if elapsed > interval:
                break
            starts += 1
        self.assertLessEqual(
            starts,
            burst,
            f"{starts} starts fit in {interval:.0f} s with a {burst} start "
            "limit, so a broken unit would end in start-limit-hit and need an "
            "operator",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
