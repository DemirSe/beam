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
TRAY_README = ROOT / "clients" / "linux-tray" / "README.md"
CLIENT_CONFIG = ROOT / "config.client.example.toml"


def unit_settings(path):
    """Parses a systemd unit file into `{(section, key): value}` (last wins)."""
    return {k: v[-1] for k, v in unit_settings_all(path).items()}


def unit_settings_all(path):
    """Parses a systemd unit file into `{(section, key): [values...]}`."""
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
            values.setdefault((section, key), []).append(value.strip())
    return values


def parse_seconds(value):
    return int(value[:-1]) if value[-1] == "s" else int(value)


def config_values(text):
    """Parses the top-level TOML sections used by the tests into a dict."""
    section = None
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            values[(section, key.strip())] = value.strip()
    return values


class RestartPolicyTest(unittest.TestCase):
    """A crash must recover, and a persistent failure must stay bounded."""

    def settings(self, path):
        return unit_settings(path)

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


class NativeClientUnitTest(unittest.TestCase):
    """`deploy/beam-client.service` must keep its device access and sandbox."""

    def unit(self):
        return unit_settings(DEPLOY / "beam-client.service")

    def test_tun_access_is_the_only_granted_device(self):
        unit = self.unit()
        self.assertEqual(unit[("Service", "DevicePolicy")], "closed")
        self.assertEqual(unit[("Service", "DeviceAllow")], "/dev/net/tun rw")
        self.assertEqual(unit[("Service", "CapabilityBoundingSet")], "CAP_NET_ADMIN")
        self.assertEqual(unit[("Service", "AmbientCapabilities")], "CAP_NET_ADMIN")

    def test_runtime_directory_matches_the_coded_state_paths(self):
        unit = self.unit()
        self.assertEqual(unit[("Service", "RuntimeDirectory")], "beam-client")
        source = (ROOT / "crates/beam-client/src/linux_tun.rs").read_text()
        self.assertIn('/run/beam-client/routes.state', source)
        source = (ROOT / "crates/beam-client/src/health.rs").read_text()
        self.assertIn('/run/beam-client/status', source)

    def test_check_and_cleanup_run_around_the_service(self):
        all_settings = unit_settings_all(DEPLOY / "beam-client.service")
        exec_start = all_settings[("Service", "ExecStart")]
        exec_pre = all_settings[("Service", "ExecStartPre")]
        exec_stop_post = all_settings[("Service", "ExecStopPost")]
        self.assertEqual(len(exec_start), 1)
        self.assertTrue(
            any("--check -c /etc/beam/client.toml" in cmd for cmd in exec_pre)
        )
        self.assertIn("-c /etc/beam/client.toml", exec_start[0])
        self.assertEqual(exec_start[0].split()[0], exec_pre[0].split()[0])
        self.assertTrue(
            any("--cleanup-routes" in cmd for cmd in exec_stop_post)
        )

    def test_memory_and_descriptor_bounds_are_explicit(self):
        unit = self.unit()
        self.assertEqual(unit[("Service", "MemoryHigh")], "384M")
        self.assertEqual(unit[("Service", "MemoryMax")], "512M")
        self.assertEqual(unit[("Service", "LimitNOFILE")], "65536")
        self.assertEqual(unit[("Service", "OOMPolicy")], "stop")
        self.assertEqual(unit[("Service", "Restart")], "always")
        self.assertGreater(int(unit[("Unit", "StartLimitBurst")]), 1)
        self.assertGreater(parse_seconds(unit[("Unit", "StartLimitIntervalSec")]), 0)

    def test_sandbox_directives_are_present(self):
        unit = self.unit()
        required = {
            "NoNewPrivileges": "yes",
            "ProtectSystem": "strict",
            "ProtectHome": "yes",
            "PrivateTmp": "yes",
            "ProtectKernelTunables": "yes",
            "ProtectKernelModules": "yes",
            "ProtectKernelLogs": "yes",
            "ProtectControlGroups": "yes",
            "ProtectClock": "yes",
            "ProtectHostname": "yes",
            "RestrictNamespaces": "yes",
            "RestrictSUIDSGID": "yes",
            "LockPersonality": "yes",
            "SystemCallArchitectures": "native",
            "MemoryDenyWriteExecute": "yes",
        }
        for key, value in required.items():
            self.assertEqual(unit[("Service", key)], value, key)
        self.assertIn("@system-service", unit[("Service", "SystemCallFilter")])
        families = unit[("Service", "RestrictAddressFamilies")].split()
        # TUN, netlink route watching, and loopback control all need a family.
        for family in ("AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK"):
            self.assertIn(family, families)

    def test_config_example_parity_with_the_unit(self):
        unit = self.unit()
        cfg = config_values(CLIENT_CONFIG.read_text())
        tun_name = cfg[("tun", "name")].strip('"')
        self.assertEqual(tun_name, "beamtun0")
        self.assertTrue(unit[("Service", "ExecStart")].endswith("/beam-client -c /etc/beam/client.toml"))

        for section in ("server", "tun", "dns", "bypass", "limits", "log"):
            self.assertTrue(
                any(name == section for name, _ in cfg),
                f"{section} section missing from the example config",
            )

        mtu = int(cfg[("tun", "mtu")])
        self.assertGreaterEqual(mtu, 576)
        self.assertLessEqual(mtu, 9000)

        # The example's TCP socket budget must fit inside the unit's MemoryMax.
        # Mirrors `derive_tcp_socket_buffer_bytes` in `crates/beam-client/src/config.rs`.
        connections = int(cfg[("limits", "max_tcp_connections")])
        self.assertLessEqual(connections, 4096)
        per_direction = min(
            max((256 * 1024 * 1024) // (2 * max(connections, 1)), 64 * 1024),
            4 * 1024 * 1024,
        )
        budget_mib = 2 * connections * per_direction // (1024 * 1024)
        memory_max_mib = int(unit[("Service", "MemoryMax")].rstrip("M"))
        self.assertLessEqual(budget_mib, memory_max_mib)

    def test_bypass_domains_requirement_is_documented_in_the_example(self):
        text = CLIENT_CONFIG.read_text()
        self.assertIn("dns.enabled", text)


class ClientInstallPathTest(unittest.TestCase):
    """The native and the sing-box tray installs must never be mixed."""

    def test_both_installs_claim_the_same_unit_name(self):
        native = unit_settings(DEPLOY / "beam-client.service")
        self.assertTrue(native[("Service", "ExecStart")].startswith("/usr/local/bin/beam-client"))
        installer = (ROOT / "clients/linux-tray/install.sh").read_text()
        self.assertIn("/etc/systemd/system/beam-client.service", installer)
        self.assertIn("sing-box run -c /etc/beam/config.json", installer)
        self.assertIn("beam-helper dns-on", installer)

    def test_the_install_paths_are_documented_as_exclusive(self):
        tray = " ".join(TRAY_README.read_text().split()).lower()
        for token in ("beamtun0", "sbtun0", "99-beam.conf", "per-link", "do not"):
            self.assertIn(token, tray, token)
        client = " ".join(CLIENT_DOC.read_text().split()).lower()
        self.assertIn("sbtun0", client)
        self.assertIn("beamtun0", client)
        self.assertIn("clients/linux-tray/readme.md", client)


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
