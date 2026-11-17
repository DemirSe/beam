#!/usr/bin/env python3
"""Contract tests for the release artifact and the release workflow.

The release workflow builds the deployed `prod` commit with
`scripts/release-artifact.sh` and publishes the result as a GitHub Release
asset. These tests run the real script against a stub binary, so they need no
cargo, no network, and no root. They pin the artifact name, the archive members
and modes, both checksum files, the refusal paths, and the workflow rules: the
tip of `prod` is the only source, a `v*` tag builds only when it names that
commit, `main` is refused, a release is published only by a manual dispatch
with `publish` set on `refs/heads/prod`, and a tag ref never publishes.

The build gate and the publish step are run for real against a stub `gh`, so
the ref checks, the field checks, the draft, the downloaded-asset check, and the
refusal paths are covered without a release and without the network.
"""

import hashlib
import os
import re
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release-artifact.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
MAKEFILE = ROOT / "Makefile"
DEPLOY = ROOT / "deploy"
EXAMPLE_CONFIG = ROOT / "config.example.toml"

VERSION = "9.9.9"
COMMIT = "abcdef123456"
TARGET = "x86_64-unknown-linux-gnu"
NAME = f"beam-{VERSION}-{COMMIT}-{TARGET}"
FULL_SHA = COMMIT + "0123456789abcdef0123456789abcdef01234567"

# Every member the archive must carry, with the mode the installer relies on.
MEMBERS = {
    "beam": 0o755,
    "beam.service": 0o644,
    "beam-install.sh": 0o755,
    "config.example.toml": 0o600,
    "liveness-check.py": 0o755,
    "beam-liveness.service": 0o644,
    "beam-liveness.timer": 0o644,
    "SHA256SUMS": 0o644,
}

STUB = """#!/bin/bash
case "$1" in
  --version) echo "beam {version} ({commit})" ;;
  *) exit 0 ;;
esac
"""

# Answers only the gh calls the publish step makes. `GH_HAVE_RELEASE` and
# `GH_HAVE_TAG` simulate refs that already exist, `GH_CORRUPT` simulates an
# upload that changed the bytes.
GH_STUB = """#!/bin/bash
set -uo pipefail
printf '%s\\n' "$*" >>"$GH_LOG"
args=("$@")
if [ "${1:-}" = api ]; then
  [ "${GH_HAVE_TAG:-0}" = 1 ] && exit 0
  exit 1
fi
[ "${1:-}" = release ] || exit 1
case "${2:-}" in
  view)
    for arg in "${args[@]}"; do
      if [ "$arg" = --json ]; then
        echo "https://example.test/release"
        exit 0
      fi
    done
    [ "${GH_HAVE_RELEASE:-0}" = 1 ] && exit 0
    exit 1 ;;
  create)
    mkdir -p "$GH_STORE" || exit 1
    n=${#args[@]}
    cp -- "${args[$((n - 2))]}" "${args[$((n - 1))]}" "$GH_STORE"/ || exit 1
    if [ "${GH_CORRUPT:-0}" = 1 ]; then
      echo corrupt >>"$GH_STORE/$(basename "${args[$((n - 2))]}")"
    fi
    exit 0 ;;
  download)
    dir=""
    for ((i = 0; i < ${#args[@]}; i++)); do
      [ "${args[i]}" = --dir ] && dir="${args[$((i + 1))]}"
    done
    [ -n "$dir" ] || exit 1
    mkdir -p "$dir" || exit 1
    cp -- "$GH_STORE"/* "$dir"/ || exit 1
    exit 0 ;;
  delete|edit)
    exit 0 ;;
esac
exit 1
"""


def write_stub(path: Path, version: str = VERSION, commit: str = COMMIT) -> Path:
    path.write_text(STUB.format(version=version, commit=commit))
    path.chmod(0o755)
    return path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def workflow_code() -> str:
    """The workflow without comment lines, so a comment cannot satisfy a rule."""
    lines = [
        line
        for line in WORKFLOW.read_text().splitlines()
        if not line.lstrip().startswith("#")
    ]
    return "\n".join(lines)


def step_run(name: str) -> str:
    """The `run: |` body of one workflow step, dedented."""
    lines = WORKFLOW.read_text().splitlines()
    start = next(
        index
        for index, line in enumerate(lines)
        if line.strip() == f"- name: {name}"
    )
    step_indent = len(lines[start]) - len(lines[start].lstrip())
    run_indent = None
    body = []
    for line in lines[start + 1 :]:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if stripped and indent <= step_indent:
            break
        if run_indent is None:
            if stripped == "run: |":
                run_indent = indent + 2
            continue
        if stripped and indent < run_indent:
            break
        body.append(line[run_indent:] if stripped else "")
    assert run_indent is not None, f"step {name} has no `run: |` block"
    return "\n".join(body) + "\n"


def make_recipes(target: str) -> str:
    """The recipe lines of `target` and every prerequisite it reaches."""
    rules = {}
    current = None
    for line in MAKEFILE.read_text().splitlines():
        if line.startswith("\t"):
            if current:
                rules[current][1].append(line)
        elif line.strip() and not line.startswith("#") and ":" in line:
            name, _, prereqs = line.partition(":")
            current = name.strip()
            before, after = rules.get(current, ([], []))
            rules[current] = (before + prereqs.split(), after)
        else:
            current = None

    seen, pending, recipes = set(), [target], []
    while pending:
        name = pending.pop()
        if name in seen or name not in rules:
            continue
        seen.add(name)
        prereqs, body = rules[name]
        recipes.extend(body)
        pending.extend(prereqs)
    return "\n".join(recipes)


class ReleaseArtifactTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.out = self.tmp / "out"
        self.bin = write_stub(self.tmp / "beam")

    def run_script(self, **env_over):
        env = os.environ.copy()
        env.update(
            {
                "BEAM_RELEASE_BIN": str(self.bin),
                "BEAM_RELEASE_VERSION": VERSION,
                "BEAM_RELEASE_COMMIT": COMMIT,
                "BEAM_RELEASE_TARGET": TARGET,
                "BEAM_RELEASE_OUT": str(self.out),
            }
        )
        env.update(env_over)
        return subprocess.run(
            ["bash", str(SCRIPT)], capture_output=True, text=True, env=env
        )

    def test_archive_and_checksums(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)

        archive = self.out / f"{NAME}.tar.gz"
        pin = self.out / f"{NAME}.tar.gz.sha256"
        self.assertTrue(archive.is_file())
        self.assertTrue(pin.is_file())

        with tarfile.open(archive) as tar:
            self.assertEqual(sorted(tar.getnames()), sorted(MEMBERS))
            for name, mode in MEMBERS.items():
                member = tar.getmember(name)
                self.assertTrue(member.isfile(), f"{name} is not a regular file")
                self.assertEqual(
                    member.mode & 0o777, mode, f"{name} mode is {member.mode:o}"
                )
            tar.extractall(self.tmp / "extract", filter="data")
        extract = self.tmp / "extract"

        self.assertEqual((extract / "beam").read_bytes(), self.bin.read_bytes())
        # The installer, unit, and example config are the repository copies, so
        # a release cannot carry a stale install path.
        self.assertEqual(
            (extract / "beam-install.sh").read_bytes(),
            (DEPLOY / "beam-install.sh").read_bytes(),
        )
        self.assertEqual(
            (extract / "beam.service").read_bytes(),
            (DEPLOY / "beam.service").read_bytes(),
        )
        self.assertEqual(
            (extract / "config.example.toml").read_bytes(), EXAMPLE_CONFIG.read_bytes()
        )
        # The liveness probe, unit, and timer are the repository copies too, so
        # the archive cannot drift from the deploy directory.
        self.assertEqual(
            (extract / "liveness-check.py").read_bytes(),
            (DEPLOY / "liveness-check.py").read_bytes(),
        )
        self.assertEqual(
            (extract / "beam-liveness.service").read_bytes(),
            (DEPLOY / "beam-liveness.service").read_bytes(),
        )
        self.assertEqual(
            (extract / "beam-liveness.timer").read_bytes(),
            (DEPLOY / "beam-liveness.timer").read_bytes(),
        )

        # SHA256SUMS pins only the binary, so an edited example config still
        # verifies. The pin file names the archive by basename, so
        # `sha256sum -c <name>.sha256` works in the download directory.
        self.assertEqual(
            (extract / "SHA256SUMS").read_text(), f"{sha256(self.bin)}  beam\n"
        )
        self.assertEqual(pin.read_text(), f"{sha256(archive)}  {NAME}.tar.gz\n")

        extract_check = subprocess.run(
            ["sha256sum", "-c", "SHA256SUMS"],
            cwd=extract,
            capture_output=True,
            text=True,
        )
        self.assertEqual(extract_check.returncode, 0, extract_check.stdout + extract_check.stderr)

        pin_check = subprocess.run(
            ["sha256sum", "-c", pin.name], cwd=self.out, capture_output=True, text=True
        )
        self.assertEqual(pin_check.returncode, 0, pin_check.stdout + pin_check.stderr)

        reported = dict(
            line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
        )
        self.assertEqual(reported["artifact"], str(archive))
        self.assertEqual(reported["artifact_sha256"], sha256(archive))
        self.assertEqual(reported["binary_sha256"], sha256(self.bin))
        self.assertEqual(reported["version"], VERSION)
        self.assertEqual(reported["commit"], COMMIT)
        self.assertEqual(reported["target"], TARGET)

    def test_members_install_from_one_directory(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(self.out / f"{NAME}.tar.gz") as tar:
            tar.extractall(self.tmp / "extract", filter="data")
        extract = self.tmp / "extract"

        syntax = subprocess.run(
            ["bash", "-n", str(extract / "beam-install.sh")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        installer = (extract / "beam-install.sh").read_text()
        unit = (extract / "beam.service").read_text()
        bin_path = re.search(r"^INSTALL_BIN=(\S+)$", installer, re.MULTILINE).group(1)
        config_path = re.search(r"^INSTALL_CONFIG=(\S+)$", installer, re.MULTILINE).group(1)
        self.assertIn(f"ExecStart={bin_path} -c {config_path}", unit)
        self.assertIn(f"ExecStartPre={bin_path} --check -c {config_path}", unit)
        # The installer takes the unit from the archive when it is present.
        self.assertIn("beam.service", installer)

    def test_example_config_is_a_placeholder(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(self.out / f"{NAME}.tar.gz") as tar:
            text = tar.extractfile("config.example.toml").read().decode()
        self.assertIn("00000000-0000-0000-0000-000000000000", text)
        self.assertNotRegex(
            text,
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-(?!0{12})[0-9a-f]{12}",
            "the archive carries a non-placeholder user id",
        )

    def test_liveness_member_names_match_the_unit(self):
        # The unit starts the probe by absolute path; the installer copies the
        # archive member by its basename. A rename in one without the other
        # would install a unit whose ExecStart cannot start.
        unit = (DEPLOY / "beam-liveness.service").read_text()
        exec_start = re.search(r"^ExecStart=(\S+)$", unit, re.MULTILINE).group(1)
        probe = Path(exec_start).name
        self.assertIn(probe, MEMBERS)
        self.assertEqual(
            (DEPLOY / probe).read_text().splitlines()[0], "#!/usr/bin/env python3"
        )

    def test_wrong_version_refused(self):
        self.bin = write_stub(self.tmp / "beam", version="9.9.8")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected 'beam 9.9.9", result.stderr)
        self.assertFalse((self.out / f"{NAME}.tar.gz").exists())

    def test_wrong_commit_refused(self):
        self.bin = write_stub(self.tmp / "beam", commit="000000000000")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"commit stamp does not match {COMMIT}", result.stderr)
        self.assertFalse((self.out / f"{NAME}.tar.gz").exists())

    def test_refuses_to_replace_an_artifact(self):
        self.assertEqual(self.run_script().returncode, 0)
        archive = self.out / f"{NAME}.tar.gz"
        before = sha256(archive)
        second = self.run_script()
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("refusing to replace", second.stderr)
        self.assertEqual(sha256(archive), before)

    def test_unsafe_names_refused(self):
        # These values name files, a tag, and release assets, so a path
        # separator or a newline must not survive.
        cases = [
            ("BEAM_RELEASE_VERSION", "1.0.0/../../escape"),
            ("BEAM_RELEASE_VERSION", "1.0.0\nartifact=/tmp/evil"),
            ("BEAM_RELEASE_VERSION", ""),
            ("BEAM_RELEASE_COMMIT", "../abcdef1"),
            ("BEAM_RELEASE_COMMIT", "ABCDEF123456"),
            ("BEAM_RELEASE_TARGET", "../../x86_64"),
            ("BEAM_RELEASE_TARGET", "x86 64"),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                result = self.run_script(**{key: value})
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("release:", result.stderr)
                self.assertEqual(list(self.tmp.rglob("*.tar.gz")), [])

    def test_prebuilt_binary_needs_its_commit(self):
        # Stamping a prebuilt binary with HEAD would claim a source it may not
        # come from, so the commit must be explicit.
        result = self.run_script(BEAM_RELEASE_COMMIT="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BEAM_RELEASE_COMMIT", result.stderr)
        self.assertEqual(list(self.tmp.rglob("*.tar.gz")), [])


class ReleaseWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.code = workflow_code()

    def test_prod_is_the_only_branch_source(self):
        self.assertIn("branches: [prod]", self.code)
        self.assertNotIn("branches: [release]", self.code)
        self.assertNotIn("branches: [main]", self.code)

    def test_tag_push_runs_the_workflow(self):
        # README: a push to prod, or a push of a v* tag, runs it.
        self.assertRegex(
            self.code, r"push:\n\s+branches: \[prod\]\n\s+tags: \['v\*'\]"
        )

    def test_main_is_refused(self):
        self.assertIn("refs/heads/main)", self.code)
        self.assertIn("refs/heads/prod|refs/tags/v*", self.code)
        self.assertIn("main is the development line", self.code)

    def test_publishes_a_github_release_not_an_actions_artifact(self):
        self.assertIn("gh release create", self.code)
        self.assertIn("contents: write", self.code)
        self.assertIn('"$artifact" "$pin"', self.code)
        self.assertNotIn("upload-artifact", self.code)
        self.assertNotIn("retention-days", self.code)

    def test_publishing_needs_a_manual_dispatch(self):
        self.assertIn("workflow_dispatch:", self.code)
        self.assertIn("publish:", self.code)
        publish = re.search(
            r"- name: Publish the GitHub Release\n\s+if: (.+)\n", self.code
        )
        self.assertIsNotNone(publish, "no publish step with a condition")
        condition = publish.group(1)
        self.assertIn("workflow_dispatch", condition)
        self.assertIn("publish", condition)
        self.assertIn("gh release view", self.code)
        self.assertIn("refs/heads/prod", self.code)

    def test_never_pushes(self):
        self.assertNotIn("git push", self.code)
        self.assertNotIn(":prod", self.code)

    def test_make_verify_is_the_only_gate_step(self):
        self.assertIn("make verify", self.code)
        # `make verify` reaches `test-scripts`, which runs this suite. A second,
        # direct run in the workflow would test the same files twice.
        self.assertNotIn("test-scripts", self.code)
        self.assertNotIn("test_release_artifact", self.code)

    def test_make_verify_runs_the_contract_tests(self):
        # `verify` -> `check` -> `test` -> `test-scripts`, so the single gate
        # step still covers this file.
        self.assertIn("tests/release/test_release_artifact.py", make_recipes("verify"))

    def test_build_writes_outside_the_cached_target_dir(self):
        # A restored cargo cache must not leave an archive that makes a rerun
        # stop at "refusing to replace".
        self.assertRegex(
            self.code,
            r"BEAM_RELEASE_OUT: \$\{\{ runner\.temp \}\}/release-artifact",
        )


class ReleaseGateStepTest(unittest.TestCase):
    """Runs the build gate against a real git repo and a stub gh."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        for command in (
            ["git", "init", "-q", "-b", "prod"],
            ["git", "config", "user.email", "t@example.test"],
            ["git", "config", "user.name", "t"],
            ["git", "commit", "-q", "--allow-empty", "-m", "x"],
        ):
            subprocess.run(command, cwd=self.repo, check=True)
        self.head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        stub_dir = self.tmp / "bin"
        stub_dir.mkdir()
        gh = stub_dir / "gh"
        gh.write_text(
            "#!/bin/bash\n"
            '[ "${1:-}" = api ] || exit 1\n'
            '[ "${GATE_FAIL:-0}" = 1 ] && exit 1\n'
            "printf '%s\\n' \"${GATE_TIP:?}\"\n"
        )
        gh.chmod(0o755)
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": f"{stub_dir}:{self.env['PATH']}",
                "GITHUB_REPOSITORY": "owner/repo",
                "GITHUB_REF": "refs/tags/v9.9.9",
                "GATE_TIP": self.head,
            }
        )

    def run_gate(self, **env_over):
        env = dict(self.env)
        env.update(env_over)
        return subprocess.run(
            ["bash", "-c", step_run("Require the prod tip")],
            cwd=self.repo,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_accepts_the_prod_tip(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_a_tag_off_the_prod_tip(self):
        result = self.run_gate(GATE_TIP="0" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refs/tags/v9.9.9 is at", result.stderr)
        self.assertIn("prod is at", result.stderr)

    def test_refuses_when_the_prod_branch_is_unreadable(self):
        result = self.run_gate(GATE_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot read the prod branch", result.stderr)

    def test_refuses_a_malformed_tip(self):
        result = self.run_gate(GATE_TIP="prod")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bad prod tip", result.stderr)


class ReleaseRefStepTest(unittest.TestCase):
    """Runs the ref gate that runs before a checkout."""

    def run_ref(self, ref):
        env = os.environ.copy()
        env["GITHUB_REF"] = ref
        return subprocess.run(
            ["bash", "-c", step_run("Require the prod branch or a v* tag")],
            capture_output=True,
            text=True,
            env=env,
        )

    def test_accepts_prod_and_a_v_star_tag(self):
        for ref in ("refs/heads/prod", "refs/tags/v9.9.9"):
            with self.subTest(ref=ref):
                result = self.run_ref(ref)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_main_and_any_other_ref(self):
        main = self.run_ref("refs/heads/main")
        self.assertNotEqual(main.returncode, 0)
        self.assertIn("main is the development line", main.stderr)
        other = self.run_ref("refs/heads/release")
        self.assertNotEqual(other.returncode, 0)
        self.assertIn("build from prod or a v* tag", other.stderr)
        self.assertIn("not refs/heads/release", other.stderr)


class ReleasePublishStepTest(unittest.TestCase):
    """Runs the publish step against a stub gh, never a real repository."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.out = self.tmp / "out"
        self.bin = write_stub(self.tmp / "beam")
        self.archive = self.out / f"{NAME}.tar.gz"

        stub_dir = self.tmp / "bin"
        stub_dir.mkdir()
        gh = stub_dir / "gh"
        gh.write_text(GH_STUB)
        gh.chmod(0o755)

        self.runner_temp = self.tmp / "runner-temp"
        self.runner_temp.mkdir()
        self.report = self.runner_temp / "release-artifact.txt"
        self.report.write_text(self.build_artifact().stdout)
        self.summary = self.tmp / "summary.md"
        self.summary.write_text("")
        self.store = self.tmp / "store"
        self.log = self.tmp / "gh.log"
        self.log.write_text("")

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{stub_dir}:{env['PATH']}",
                "RUNNER_TEMP": str(self.runner_temp),
                "GITHUB_STEP_SUMMARY": str(self.summary),
                "GITHUB_REF": "refs/heads/prod",
                "GITHUB_SHA": FULL_SHA,
                "GITHUB_REPOSITORY": "owner/repo",
                "GH_LOG": str(self.log),
                "GH_STORE": str(self.store),
            }
        )
        self.env = env

    def build_artifact(self):
        env = os.environ.copy()
        env.update(
            {
                "BEAM_RELEASE_BIN": str(self.bin),
                "BEAM_RELEASE_VERSION": VERSION,
                "BEAM_RELEASE_COMMIT": COMMIT,
                "BEAM_RELEASE_TARGET": TARGET,
                "BEAM_RELEASE_OUT": str(self.out),
            }
        )
        result = subprocess.run(
            ["bash", str(SCRIPT)], capture_output=True, text=True, env=env
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def run_publish(self, **env_over):
        env = dict(self.env)
        env.update(env_over)
        return subprocess.run(
            ["bash", "-c", step_run("Publish the GitHub Release")],
            capture_output=True,
            text=True,
            env=env,
        )

    def gh_calls(self):
        return [line for line in self.log.read_text().splitlines() if line]

    def test_publishes_only_after_the_downloaded_assets_match(self):
        result = self.run_publish()
        self.assertEqual(result.returncode, 0, result.stderr)

        calls = self.gh_calls()
        joined = "\n".join(calls)
        tag = f"v{VERSION}-{COMMIT}"
        create = next(call for call in calls if call.startswith("release create "))
        self.assertIn(f" {tag} ", create)
        self.assertIn("--draft", create)
        self.assertIn(f"--target {FULL_SHA}", create)
        self.assertTrue(create.endswith(f" {self.archive} {self.archive}.sha256"))
        # Draft, then verify its download, then publish, then print the URL.
        self.assertLess(joined.index("release create "), joined.index("release download "))
        self.assertLess(joined.index("release download "), joined.index("release edit "))
        self.assertIn(f"release edit {tag} --draft=false", joined)
        self.assertIn("https://example.test/release", self.summary.read_text())

        notes = (self.runner_temp / "release-notes.md").read_text()
        self.assertIn(f"sha256sum -c {NAME}.tar.gz.sha256", notes)
        self.assertIn(f"tar -xzf {NAME}.tar.gz", notes)
        self.assertIn("bash beam-install.sh install", notes)
        self.assertIn("chmod 600 config.example.toml", notes)

    def test_refuses_an_existing_release(self):
        result = self.run_publish(GH_HAVE_RELEASE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)
        self.assertNotIn("release create", "\n".join(self.gh_calls()))

    def test_refuses_an_existing_tag(self):
        result = self.run_publish(GH_HAVE_TAG="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tag v", result.stderr)
        self.assertIn("already exists", result.stderr)
        self.assertNotIn("release create", "\n".join(self.gh_calls()))

    def test_refuses_a_publish_from_a_tag(self):
        # Even a tag on the prod tip is a tag ref, not the prod branch.
        result = self.run_publish(GITHUB_REF=f"refs/tags/v{VERSION}-{COMMIT}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("publish only from refs/heads/prod", result.stderr)
        self.assertEqual(self.gh_calls(), [])

    def test_refuses_a_publish_from_main(self):
        # `main` develops ahead of the host; only the deployed commit releases.
        result = self.run_publish(GITHUB_REF="refs/heads/main")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("publish only from refs/heads/prod", result.stderr)
        self.assertEqual(self.gh_calls(), [])

    def test_refuses_a_report_from_another_commit(self):
        result = self.run_publish(GITHUB_SHA="f" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not the checked-out", result.stderr)
        self.assertNotIn("release create", "\n".join(self.gh_calls()))

    def test_refuses_an_artifact_that_changed_after_the_report(self):
        with self.archive.open("ab") as handle:
            handle.write(b"tampered")
        result = self.run_publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the reported SHA-256", result.stderr)
        self.assertNotIn("release create", "\n".join(self.gh_calls()))

    def test_deletes_the_draft_when_the_download_does_not_match(self):
        result = self.run_publish(GH_CORRUPT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("downloaded asset does not match", result.stderr)
        joined = "\n".join(self.gh_calls())
        self.assertIn("release delete ", joined)
        self.assertNotIn("release edit", joined)

    def test_refuses_a_missing_report(self):
        self.report.unlink()
        result = self.run_publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no artifact report", result.stderr)
        self.assertEqual(self.gh_calls(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
