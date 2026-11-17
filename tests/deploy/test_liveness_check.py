#!/usr/bin/env python3
"""Contract tests for deploy/liveness-check.py.

The watchdog has three jobs, and each one has a failure that costs the owner
a live tunnel. It must restart a beam that answers nothing. It must not
restart a healthy beam only because the cover is unreachable, and it must not
target an address or a cover name that the installed config does not use.
And it must not report a restart that did not happen.

The probe and `systemctl` are stubbed, so no root, network, or host service is
needed. The tests assert the reported verdict and the counter state, not how
the script is written.
"""

import configparser
import importlib.util
import io
import re
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
SCRIPT = DEPLOY / "liveness-check.py"
UNIT = DEPLOY / "beam-liveness.service"
BEAM_UNIT = DEPLOY / "beam.service"
SERVER_RS = ROOT / "crates" / "beam-core" / "src" / "tls" / "server.rs"

# The production config in one line, and the probe target that it implies.
CONFIG_TEXT = """
[server]
listen = "0.0.0.0:443"

[reality]
server_names = ["whatsapp.net"]
dest = "whatsapp.net:443"
"""
TARGET = ("127.0.0.1", 443, "whatsapp.net")


def load():
    """Import the hyphenated script as a module, fresh for each test."""
    spec = importlib.util.spec_from_file_location("beam_liveness_check", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unit_settings(path):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str  # systemd keys are case-sensitive
    parser.read_string(path.read_text())
    return parser


def seconds(value):
    value = value.strip()
    for suffix, factor in (("ms", 0.001), ("min", 60), ("h", 3600), ("s", 1)):
        if value.endswith(suffix):
            return float(value[: -len(suffix)]) * factor
    return float(value)


def rust_seconds(name):
    """Read one `const NAME: Duration = Duration::from_secs(n);` from beam."""
    match = re.search(
        rf"const {name}: Duration = Duration::from_secs\((\d+)\);",
        SERVER_RS.read_text(),
    )
    if match is None:
        raise AssertionError(f"{SERVER_RS} has no {name} constant")
    return float(match.group(1))


class FakeSystemctl:
    """Collect the systemctl calls the script makes."""

    def __init__(self, restart_rc=0, state="active"):
        self.restart_rc = restart_rc
        self.state = state
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if args == ["systemctl", "restart", "beam"]:
            return subprocess.CompletedProcess(args, self.restart_rc, "", "")
        if args == ["systemctl", "is-active", "beam"]:
            return subprocess.CompletedProcess(args, 0, f"{self.state}\n", "")
        raise AssertionError(f"unexpected command: {args}")

    @property
    def restarts(self):
        return [call for call in self.calls if call == ["systemctl", "restart", "beam"]]


class LivenessCheckTest(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.counter = Path(self.tmp.name) / "failures"
        self.config = Path(self.tmp.name) / "config.toml"
        self.config.write_text(CONFIG_TEXT)
        for name, value in (("COUNTER", str(self.counter)), ("CONFIG", str(self.config))):
            patcher = mock.patch.object(self.module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def seed(self, count):
        self.counter.write_text(str(count))

    def count(self):
        return int(self.counter.read_text() or 0)

    def run_main(self, exc=None, version="TLSv1.3", restart_rc=0, state="active"):
        """Run one probe cycle with a stubbed probe and systemctl."""
        systemctl = FakeSystemctl(restart_rc=restart_rc, state=state)
        out = io.StringIO()
        with mock.patch.object(
            self.module, "probe", side_effect=exc, return_value=version
        ), mock.patch.object(self.module.subprocess, "run", systemctl):
            with redirect_stdout(out):
                code = self.module.main()
        return code, out.getvalue(), systemctl

    # The restart decision.

    def test_a_success_resets_the_counter(self):
        self.seed(2)
        code, out, systemctl = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("OK TLSv1.3", out)
        self.assertEqual(self.count(), 0)
        self.assertEqual(systemctl.calls, [])

    def test_a_third_local_failure_restarts_once(self):
        self.seed(self.module.LIMIT - 1)
        code, out, systemctl = self.run_main(exc=TimeoutError())
        self.assertEqual(code, 0)
        self.assertIn("restarted beam", out)
        self.assertEqual(len(systemctl.restarts), 1)
        self.assertEqual(self.count(), 0)

    def test_a_shorter_streak_does_not_restart(self):
        self.seed(0)
        code, out, systemctl = self.run_main(exc=ConnectionRefusedError())
        self.assertEqual(code, 0)
        self.assertIn(f"FAIL 1/{self.module.LIMIT}", out)
        self.assertEqual(self.count(), 1)
        self.assertEqual(systemctl.restarts, [])

    # The cover-path exception: a healthy beam must survive it.

    def test_a_cover_fault_never_restarts_beam(self):
        self.seed(self.module.LIMIT - 1)
        for exc in (
            self.module.ssl.SSLError("handshake failure"),
            self.module.ssl.SSLEOFError("unexpected EOF"),
            ConnectionResetError(),
            BrokenPipeError(),
        ):
            with self.subTest(exc=type(exc).__name__):
                self.seed(self.module.LIMIT - 1)
                code, out, systemctl = self.run_main(exc=exc)
                self.assertEqual(code, 0, out)
                self.assertIn("SKIP", out)
                self.assertNotIn("FAIL", out)
                self.assertEqual(systemctl.restarts, [])
                # beam answered, so the streak of unanswered probes is over.
                self.assertEqual(self.count(), 0)

    def test_a_local_fault_still_counts(self):
        for exc in (
            TimeoutError(),
            ConnectionRefusedError(),
            OSError("local socket error"),
        ):
            with self.subTest(exc=type(exc).__name__):
                self.assertTrue(
                    not self.module.is_cover_fault(exc),
                    f"{type(exc).__name__} would skip the restart",
                )

    # An unverified restart must never be reported as success.

    def test_a_failed_restart_is_reported_and_retried(self):
        self.seed(self.module.LIMIT - 1)
        code, out, systemctl = self.run_main(exc=TimeoutError(), restart_rc=1)
        self.assertEqual(code, 1, "a failed restart must fail the unit")
        self.assertIn("restart FAILED", out)
        self.assertNotIn("restarted beam", out)
        # The next run retries instead of waiting for three failures again.
        self.assertEqual(self.count(), self.module.LIMIT)

    def test_a_restart_that_leaves_the_unit_inactive_is_a_failure(self):
        self.seed(self.module.LIMIT - 1)
        code, out, systemctl = self.run_main(
            exc=TimeoutError(), restart_rc=0, state="activating"
        )
        self.assertEqual(code, 1)
        self.assertIn("restart FAILED", out)
        self.assertIn("activating", out)
        self.assertNotIn("restarted beam", out)
        self.assertEqual(self.count(), self.module.LIMIT)

    def test_a_restart_that_cannot_run_is_reported(self):
        self.seed(self.module.LIMIT - 1)
        out = io.StringIO()
        with mock.patch.object(self.module, "probe", side_effect=TimeoutError()):
            with mock.patch.object(
                self.module.subprocess, "run", side_effect=FileNotFoundError("no systemctl")
            ):
                with redirect_stdout(out):
                    code = self.module.main()
        self.assertEqual(code, 1)
        self.assertIn("restart FAILED", out.getvalue())
        self.assertNotIn("restarted beam", out.getvalue())

    # The probe itself.

    def test_the_cover_bound_matches_the_server(self):
        # beam ends a failing cover relay after the ClientHello read, the dial,
        # the ClientHello write, and the relay idle timeout.
        bound = (
            rust_seconds("PREAUTH_HANDSHAKE_TIMEOUT")
            + 2 * rust_seconds("MAX_DIAL_TIMEOUT")
            + rust_seconds("COVER_IDLE_TIMEOUT")
        )
        self.assertGreaterEqual(
            self.module.COVER_BOUND_SECONDS,
            bound,
            "beam can hold a failing cover relay longer than the probe assumes",
        )
        self.assertGreater(
            self.module.TIMEOUT,
            bound,
            "a timeout must mean that beam did not answer, not that the cover "
            "relay is still running",
        )

    def test_the_unit_allows_the_probe_and_a_hung_restart(self):
        start = seconds(unit_settings(UNIT)["Service"]["TimeoutStartSec"])
        stop = seconds(unit_settings(BEAM_UNIT)["Service"]["TimeoutStopSec"])
        self.assertGreaterEqual(
            start,
            self.module.TIMEOUT + stop,
            "systemd would kill the probe before it could report a restart",
        )

    def test_the_counter_lives_across_runs(self):
        self.run_main(exc=TimeoutError())
        self.run_main(exc=TimeoutError())
        self.assertEqual(self.count(), self.module.LIMIT - 1)
        _, out, systemctl = self.run_main(exc=TimeoutError())
        self.assertEqual(len(systemctl.restarts), 1)
        self.assertEqual(self.count(), 0)
        self.assertIn("restarted beam", out)

    # The target comes from the installed config, never from this file.

    def test_the_target_comes_from_the_installed_config(self):
        self.assertEqual(self.module.probe_target(), TARGET)

    def test_a_wildcard_listen_is_probed_on_loopback(self):
        for listen, host in (
            ("0.0.0.0:443", "127.0.0.1"),
            ("[::]:443", "::1"),
            ("127.0.0.1:8443", "127.0.0.1"),
            ("127.0.0.2:443", "127.0.0.2"),
        ):
            with self.subTest(listen=listen):
                self.assertEqual(
                    self.module.split_listen(listen), (host, int(listen.rsplit(":", 1)[1]))
                )

    def test_a_port_other_than_443_is_followed(self):
        # A fixed 443 would probe a port this host does not serve, and the
        # refused connection would restart a healthy beam every 15 minutes.
        self.config.write_text(CONFIG_TEXT.replace("0.0.0.0:443", "0.0.0.0:8443"))
        self.assertEqual(
            self.module.probe_target(), ("127.0.0.1", 8443, "whatsapp.net")
        )

    def test_a_broken_config_never_restarts(self):
        for text in (
            "not toml at all",
            "[server]\nlisten = 'no port'\n[reality]\nserver_names = ['whatsapp.net']\n",
            "[server]\nlisten = '0.0.0.0:443'\n",
            "[server]\nlisten = '0.0.0.0:443'\n[reality]\nserver_names = []\n",
            "[server]\nlisten = '0.0.0.0:0'\n[reality]\nserver_names = ['whatsapp.net']\n",
        ):
            with self.subTest(text=text):
                self.seed(self.module.LIMIT - 1)
                self.config.write_text(text)
                code, out, systemctl = self.run_main(exc=TimeoutError())
                self.assertEqual(code, 1, out)
                self.assertIn("no usable probe target", out)
                self.assertEqual(systemctl.restarts, [])
                # An unprobed run is no evidence either way, so it must not
                # touch the streak.
                self.assertEqual(self.count(), self.module.LIMIT - 1)

    def test_a_missing_config_never_restarts(self):
        self.seed(self.module.LIMIT - 1)
        self.config.unlink()
        code, out, systemctl = self.run_main(exc=TimeoutError())
        self.assertEqual(code, 1, out)
        self.assertIn("no usable probe target", out)
        self.assertEqual(systemctl.restarts, [])
        self.assertEqual(self.count(), self.module.LIMIT - 1)

    def test_probe_uses_the_target_it_is_given(self):
        fake_tls = mock.MagicMock()
        fake_tls.version.return_value = "TLSv1.3"
        fake_ctx = mock.MagicMock()
        fake_ctx.wrap_socket.return_value.__enter__.return_value = fake_tls
        with mock.patch.object(
            self.module.socket, "create_connection"
        ) as connect, mock.patch.object(
            self.module.ssl, "create_default_context", return_value=fake_ctx
        ):
            self.assertEqual(self.module.probe(*TARGET), "TLSv1.3")
        connect.assert_called_once_with(
            (TARGET[0], TARGET[1]), timeout=self.module.TIMEOUT
        )
        fake_ctx.wrap_socket.assert_called_once()
        self.assertEqual(
            fake_ctx.wrap_socket.call_args.kwargs["server_hostname"], TARGET[2]
        )
        self.assertEqual(fake_ctx.verify_mode, self.module.ssl.CERT_NONE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
