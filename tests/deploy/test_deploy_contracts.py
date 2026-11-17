#!/usr/bin/env python3
"""Contract tests for the post-boot check and the deploy payload.

The post-boot check is the first verdict an operator sees after a reboot.
These tests pin the platform unit names, the unit ordering, and the deploy
paths that the installers, the packaging script, and the docs must share.

The check runs against stub `systemctl`, `ss`, `chronyc`, and `df` commands on
PATH. The tests assert the reported verdicts, not how the script is written.
No network, root, or host service is needed.
"""

import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
SCRIPT = DEPLOY / "post-boot-check.sh"
UNIT = DEPLOY / "beam-post-boot-check.service"
RULES = DEPLOY / "maintenance-rules.md"
DEPLOY_DOC = ROOT / "docs" / "DEPLOY.md"

# Platform facts, not script internals. Debian 13 ships ssh.service and
# chrony.service; AlmaLinux 10 ships sshd.service and chronyd.service.
PLATFORM_UNITS = {
    "debian": {"ssh": "ssh", "chrony": "chrony"},
    "almalinux": {"ssh": "sshd", "chrony": "chronyd"},
}

STUBS = {
    "systemctl": """#!/bin/sh
case "$1" in
  is-active)
    for unit in ${ACTIVE_UNITS:-}; do
      if [ "$unit" = "$2" ]; then printf 'active\\n'; exit 0; fi
    done
    printf 'inactive\\n'
    exit 3
    ;;
  is-enabled) printf 'enabled\\n' ;;
  show) date -u '+%Y-%m-%dT%H:%M:%SZ' ;;
esac
exit 0
""",
    "ss": """#!/bin/sh
case "$*" in
  *-6*) exit 0 ;;
  *-4*) printf 'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\\n'
        printf 'LISTEN 0 4096 0.0.0.0:%s 0.0.0.0:*\\n' "${SSH_PORT:-22}" ;;
esac
exit 0
""",
    "chronyc": """#!/bin/sh
printf 'System time     : 0.000123 seconds fast of NTP time\\n'
""",
    "df": """#!/bin/sh
printf 'Use%%\\n 42%%\\n'
""",
}


class PostBootCheckTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.bin = Path(self._tmp.name)
        for name, body in STUBS.items():
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        self.addCleanup(self._tmp.cleanup)

    def run_check(self, active):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        env["ACTIVE_UNITS"] = " ".join(active)
        env["SSH_PORT"] = "22"
        proc = subprocess.run(
            ["/bin/sh", str(SCRIPT)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.splitlines()

    def assert_unit_ok(self, lines, unit):
        self.assertIn(f"post-boot: ok unit {unit}", lines)
        self.assertFalse(
            [line for line in lines if line.startswith(f"post-boot: FAIL unit {unit}=")],
            f"unexpected failure for {unit}",
        )

    def test_almalinux_units(self):
        units = PLATFORM_UNITS["almalinux"]
        lines = self.run_check(
            ["beam", units["chrony"], "fail2ban", "nftables", units["ssh"],
             "beam-liveness.timer"]
        )
        self.assert_unit_ok(lines, units["chrony"])
        self.assert_unit_ok(lines, units["ssh"])
        self.assertFalse([line for line in lines if "FAIL unit chrony" in line])

    def test_debian_units(self):
        units = PLATFORM_UNITS["debian"]
        lines = self.run_check(
            ["beam", units["chrony"], "fail2ban", "nftables", units["ssh"],
             "beam-liveness.timer"]
        )
        self.assert_unit_ok(lines, units["chrony"])
        self.assert_unit_ok(lines, units["ssh"])
        self.assertFalse([line for line in lines if "FAIL unit sshd" in line])

    def test_missing_ssh_fails(self):
        units = PLATFORM_UNITS["almalinux"]
        lines = self.run_check(["beam", units["chrony"], "fail2ban", "nftables"])
        self.assertTrue(
            [line for line in lines if re.match(r"post-boot: FAIL unit sshd?=", line)],
            lines,
        )
        self.assertEqual(lines[-1], "post-boot: FAIL")

    def test_unit_orders_against_both_platform_names(self):
        order = []
        collecting = False
        for line in UNIT.read_text().splitlines():
            if collecting:
                order.append(line.rstrip("\\").strip())
                collecting = line.endswith("\\")
            elif line.startswith("After="):
                value = line[len("After="):]
                order.append(value.rstrip("\\").strip())
                collecting = value.endswith("\\")
        self.assertTrue(order, "unit has no After= line")
        names = set(" ".join(order).split())
        required = {"beam.service", "network-online.target", "nftables.service",
                    "fail2ban.service"}
        for platform in PLATFORM_UNITS.values():
            required.update(f"{name}.service" for name in platform.values())
        self.assertLessEqual(required, names)


class RestartPolicyTest(unittest.TestCase):
    """A crash must recover, and a persistent failure must end failed."""

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


class PayloadTest(unittest.TestCase):
    def test_script_is_installed_from_deploy(self):
        exec_start = [
            line for line in UNIT.read_text().splitlines()
            if line.startswith("ExecStart=")
        ]
        self.assertEqual(len(exec_start), 1, "unit must have one ExecStart")
        installed = exec_start[0].split("=", 1)[1]
        self.assertEqual(installed, "/usr/local/lib/beam/post-boot-check.sh")
        self.assertEqual(SCRIPT.name, Path(installed).name)
        self.assertEqual(SCRIPT.read_text().splitlines()[0], "#!/bin/sh")
        check = subprocess.run(["/bin/sh", "-n", str(SCRIPT)], capture_output=True,
                               text=True)
        self.assertEqual(check.returncode, 0, check.stderr)

        # Both installers must place the same file at the same path the unit
        # runs, and register the unit where systemd reads it.
        for installer in ("bootstrap.sh", "bootstrap-alma.sh"):
            source = (DEPLOY / installer).read_text()
            self.assertIn(f"INSTALL_POSTBOOT={installed}", source, installer)
            self.assertIn(
                "INSTALL_POSTBOOT_UNIT=/etc/systemd/system/beam-post-boot-check.service",
                source,
                installer,
            )

    def test_package_bundles_every_installer_input(self):
        package = (DEPLOY / "package.sh").read_text()
        packaged = set()
        for array in ("TEXT_FILES", "EXEC_FILES"):
            body = re.search(rf"{array}=\((.*?)\)", package, re.S)
            self.assertIsNotNone(body, f"package.sh has no {array} array")
            packaged.update(re.findall(r"[A-Za-z0-9._-]+", body.group(1)))
        # package.sh stages these outside the arrays.
        packaged.update({"beam", "beam.toml", "chrony.conf", "chronyd-sysconfig"})
        required = set()
        for installer in ("bootstrap.sh", "bootstrap-alma.sh"):
            required.update(
                re.findall(
                    r'"\$HERE/([A-Za-z0-9._-]+)"',
                    (DEPLOY / installer).read_text(),
                )
            )
        self.assertLessEqual(
            required, packaged, f"package.sh misses {sorted(required - packaged)}"
        )

    def test_rules_alias_is_documented(self):
        for installer in ("bootstrap.sh", "bootstrap-alma.sh"):
            source = (DEPLOY / installer).read_text()
            self.assertIn(
                "INSTALL_RULES_ALIAS=/etc/host-rules.md", source, installer
            )
        # The alias points inside the traversable, non-listable directory.
        for name in ("motd", "sshrc"):
            self.assertIn("/etc/host-rules.md", (DEPLOY / name).read_text(), name)
        readme = DEPLOY_DOC.read_text()
        self.assertIn("mode 0751", readme)
        self.assertIn("/etc/beam/maintenance-rules.md", readme)

    def test_alma_recovery_uses_alma_names(self):
        rules = RULES.read_text()
        self.assertIn("/etc/chrony.conf", rules)
        self.assertNotIn("/etc/chrony/chrony.conf", rules)
        self.assertIn("chronyd", rules)
        self.assertIn("sshd", rules)
        self.assertIn("NetworkManager", rules)

        readme = DEPLOY_DOC.read_text()
        self.assertIn("systemctl reload sshd", readme)
        stale = [
            line for line in readme.splitlines()
            if line.strip().endswith("reload ssh") and "reload sshd" not in line
        ]
        self.assertEqual(stale, [], "Debian-only SSH reload command remains")


class PackageCommitBindingTest(unittest.TestCase):
    """A deploy bundle must carry only the binary built from HEAD.

    Each test runs in a throwaway git checkout. The stub `cargo` writes a
    `beam` that stamps `--version` the way `crates/beam/build.rs` does: the
    HEAD commit, or an override when one is set. That keeps the tests offline,
    rootless, and independent of the Rust toolchain.
    """

    VERSION = "0.1.0"
    MARKER = "staged-from-a-relative-path\n"
    CARGO_STUB = """#!/bin/bash
set -euo pipefail
hash="$(git -C "$STUB_ROOT" rev-parse --short=12 HEAD)"
if [ -n "${BEAM_BUILD_GIT_HASH:-}" ]; then hash="$BEAM_BUILD_GIT_HASH"; fi
if [ -n "${STUB_STAMP:-}" ]; then hash="$STUB_STAMP"; fi
bin="$STUB_ROOT/target/release/beam"
mkdir -p "$(dirname "$bin")"
printf '#!/bin/bash\ncase "$1" in\n  --version) echo "beam __VERSION__ (%s)" ;;\nesac\nexit 0\n' \
  "$hash" > "$bin"
chmod 0755 "$bin"
"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "repo"
        shutil.copytree(DEPLOY, self.root / "deploy")
        (self.root / "scripts").mkdir()
        shutil.copy(ROOT / "scripts/dev-env.sh", self.root / "scripts/dev-env.sh")
        (self.root / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{self.VERSION}"\n'
        )
        # target/ and a local config are ignored in this checkout, so the
        # commit check must look past them the way it does on a real host.
        (self.root / ".gitignore").write_text(
            "target/\n__pycache__/\nconfig.toml\n"
        )
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.config = self.root / "config.toml"
        self.config.write_text(self.MARKER)
        self.config.chmod(0o600)
        self.bundle = self.tmp / "bundle"
        self.stub_bin = self.tmp / "bin"
        self.stub_bin.mkdir()
        cargo = self.stub_bin / "cargo"
        cargo.write_text(self.CARGO_STUB.replace("__VERSION__", self.VERSION))
        cargo.chmod(0o755)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.test")
        self.git("config", "user.name", "t")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "fixture")
        self.head = self.git("rev-parse", "HEAD").stdout.strip()

    def git(self, *args):
        return subprocess.run(
            ["git", *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=True,
        )

    def run_package(self, config="fixture", keep_config=None, home=None,
                    bundle=None, env=None):
        """config="fixture" passes the repo config; None leaves it unset."""
        bundle = bundle or self.bundle
        cmd_env = {
            "HOME": str(home or self.home),
            "PATH": f"{self.stub_bin}:/usr/bin:/bin",
            "STUB_ROOT": str(self.root),
            "BEAM_BUNDLE_OUT": str(bundle),
        }
        if config == "fixture":
            cmd_env["BEAM_CONFIG"] = str(self.config)
        elif config is not None:
            cmd_env["BEAM_CONFIG"] = config
        if keep_config is not None:
            cmd_env["BEAM_KEEP_CONFIG"] = keep_config
        cmd_env.update(env or {})
        return subprocess.run(
            ["/bin/bash", str(self.root / "deploy/package.sh")],
            cwd=self.root,
            env=cmd_env,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def report(result):
        return dict(
            line.split("=", 1)
            for line in result.stdout.splitlines()
            if "=" in line
        )

    def bundle_member(self, name):
        with tarfile.open(self.bundle / "beam-deploy.tar.gz") as archive:
            return archive.getmember(name), archive.extractfile(name).read()

    def test_clean_tree_reports_the_exact_commit(self):
        result = self.run_package()
        self.assertEqual(result.returncode, 0, result.stderr)
        reported = self.report(result)
        self.assertEqual(reported["commit"], self.head[:12])
        self.assertEqual(reported["version"], self.VERSION)
        self.assertEqual(
            reported["bundle"], str(self.bundle / "beam-deploy.tar.gz")
        )
        member, binary = self.bundle_member("beam")
        self.assertEqual(member.mode, 0o755)
        self.assertEqual(
            reported["binary_sha256"], hashlib.sha256(binary).hexdigest()
        )

    def test_staged_change_is_refused(self):
        # `git diff --quiet` alone reports this tree clean: the change is only
        # in the index, so the deploy check must read porcelain status.
        with (self.root / "deploy/motd").open("a") as handle:
            handle.write("changed\n")
        self.git("add", "deploy/motd")
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing a dirty tree", result.stderr)
        self.assertIn("deploy/motd", result.stderr)
        self.assertFalse(self.bundle.exists())

    def test_unstaged_change_is_refused(self):
        with (self.root / "deploy/motd").open("a") as handle:
            handle.write("changed\n")
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deploy/motd", result.stderr)
        self.assertFalse(self.bundle.exists())

    def test_untracked_file_is_refused(self):
        (self.root / "notes.txt").write_text("not committed\n")
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("notes.txt", result.stderr)
        self.assertFalse(self.bundle.exists())

    def test_hidden_untracked_file_is_refused_and_kept(self):
        hidden = self.root / ".local/state/secret"
        hidden.parent.mkdir(parents=True)
        hidden.write_text("keep me\n")
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing a dirty tree", result.stderr)
        self.assertEqual(hidden.read_text(), "keep me\n")

    def test_inherited_stamp_is_ignored(self):
        # An exported override would label the binary with another commit, so
        # package.sh must drop it and stamp HEAD.
        result = self.run_package(env={"BEAM_BUILD_GIT_HASH": "0123456789ab"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("the stamp comes from HEAD", result.stderr)
        self.assertEqual(self.report(result)["commit"], self.head[:12])
        _, binary = self.bundle_member("beam")
        self.assertNotIn(b"0123456789ab", binary)

    def test_wrong_stamp_is_refused(self):
        result = self.run_package(env={"STUB_STAMP": "000000000000"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"expected 'beam {self.VERSION} ({self.head[:12]})'", result.stderr
        )
        self.assertFalse(self.bundle.exists())

    def test_non_git_checkout_is_refused(self):
        shutil.rmtree(self.root / ".git")
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a git checkout", result.stderr)
        self.assertFalse(self.bundle.exists())

    def test_relative_config_is_bundled_and_untouched(self):
        """The documented `BEAM_CONFIG=./config.toml` must keep working."""
        before = self.config.read_bytes()
        mode = self.config.stat().st_mode & 0o777
        result = self.run_package(config="./config.toml")
        self.assertEqual(result.returncode, 0, result.stderr)
        member, staged = self.bundle_member("beam.toml")
        self.assertEqual(member.mode, 0o600)
        self.assertEqual(staged, before)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.config.stat().st_mode & 0o777, mode)

    def test_default_hidden_config_is_bundled_and_untouched(self):
        config = self.home / ".config/beam/beam.toml"
        config.parent.mkdir(parents=True)
        config.write_text(self.MARKER)
        config.chmod(0o600)
        result = self.run_package(config=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        member, staged = self.bundle_member("beam.toml")
        self.assertEqual(member.mode, 0o600)
        self.assertEqual(staged, self.MARKER.encode())
        self.assertEqual(config.read_text(), self.MARKER)
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)

    def test_keep_config_bundle_carries_no_config(self):
        result = self.run_package(config=None, keep_config="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(self.bundle / "beam-deploy.tar.gz") as archive:
            self.assertNotIn("beam.toml", archive.getnames())

    def test_existing_output_is_not_replaced(self):
        self.bundle.mkdir()
        hidden = self.bundle / ".keep"
        hidden.write_text("existing\n")
        result = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to replace", result.stderr)
        self.assertEqual(hidden.read_text(), "existing\n")


class LinuxClientDocsTest(unittest.TestCase):
    """The Linux client inputs and DNS limits must stay documented as tested."""

    def section(self):
        readme = DEPLOY_DOC.read_text()
        return readme.split("## Linux tray and DNS switch", 1)[1].split(
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


class StagingDocsTest(unittest.TestCase):
    """The docs/DEPLOY.md staging commands carry a secret; they must be safe as written."""

    def sections(self):
        readme = DEPLOY_DOC.read_text()
        stage = readme.split("#### Stage the archive on the host", 1)[1]
        stage = stage.split("#### Fresh host", 1)[0]
        fresh = readme.split("#### Fresh host", 1)[1]
        fresh = fresh.split("#### Update an existing host", 1)[0]
        update = readme.split("#### Update an existing host", 1)[1]
        update = update.split("\n### ", 1)[0]
        return stage, fresh, update

    def test_stage_block_guards_the_bundle(self):
        stage, _, _ = self.sections()
        # An unset BUNDLE must stop before scp copies a wrong or empty path.
        self.assertIn('BUNDLE:?', stage)
        self.assertIn('test -f "$BUNDLE"', stage)
        self.assertIn("mktemp -d /tmp/beam-deploy.XXXXXXXX", stage)
        self.assertIn("stat -c %a '$STAGE'", stage)

    def test_both_paths_remove_the_secret_stage(self):
        _, fresh, update = self.sections()
        for name, section in (("fresh", fresh), ("update", update)):
            self.assertIn("rm -rf -- '$STAGE'", section, name)


class VerifierFirewallTest(unittest.TestCase):
    """A missing firewalld unit cannot bypass the nftables check."""

    def test_absent_firewalld_is_scoped(self):
        text = (DEPLOY / "verify-production.sh").read_text()
        self.assertLess(
            text.index("nft_input_chain"), text.index("firewalld_raw"),
            "nftables must be checked before firewalld absence is accepted",
        )
        self.assertIn('firewalld_rc" -eq 4', text)
        self.assertIn('[ -z "$nft_input" ]', text)
        self.assertIn('[ "$firewalld" = "inactive" ]', text)
        self.assertIn('[ "$firewalld" = "active" ]', text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
