#!/usr/bin/env python3
"""Config-matrix gate: `beam --check` must always answer, never panic or hang.

For each numeric limit it tries boundary values (0, 1, max, max+1, huge) and for
each text field malformed values, then requires the expected exit status: 0
for accepted settings, 1 with a diagnostic for rejected settings. Exit 101 (panic), a signal, or a timeout is a
bug: `--check` is what a rollout runs before it touches a live server.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "config.example.toml"

# Each pair lists accepted then rejected values with the rest of the example
# configuration intact. The socket budget rejects a 4 MiB buffer at 256 sessions;
# the packetaddr table budget permits 16384 destinations at those 256 sessions.
LIMITS = {
    "max_connections": ([1, 2], [0, 4294967295, 18446744073709551615]),
    "max_udp_destinations": ([1, 16384], [0, 16385, 65536, 65537, 18446744073709551615]),
    "max_preauth_per_ip": ([1, 65536], [0, 65537, 4294967295]),
    "max_xudp_sessions": ([1], [0, 4294967295, 18446744073709551615]),
    "xudp_recv_buffer_bytes": ([16384], [0, 1, 16383, 4194304, 4194305]),
    "listen_backlog": ([1, 65535], [0, 65536]),
    "shutdown_drain_ms": ([1, 3000], [0, 3001]),
    "handshake_timeout_ms": ([100, 86400000], [0, 1, 99, 86400001]),
    "idle_timeout_ms": ([1000, 86400000], [0, 1, 999, 86400001]),
}

TEXT_CASES = [
    ("listen", 'listen = "not-an-address"'),
    ("listen", 'listen = "127.0.0.1:0"'),
    ("listen", 'listen = "127.0.0.1:70000"'),
    ("dest", 'dest = "no-port"'),
    ("dest", 'dest = ":443"'),
    ("dest", 'dest = "127.0.0.1:99999"'),
    ("private_key", 'private_key = ""'),
    ("private_key", 'private_key = "AAAA"'),
    ("short_ids", 'short_ids = []'),
    ("short_ids", 'short_ids = ["zz"]'),
    ("server_names", 'server_names = []'),
    ("flow", 'flow = "no-such-flow"'),
    ("level", 'level = "verbose"'),
]

FAILURES = 0


def check(binary: Path, config: Path, label: str, *, accepted: bool = False) -> None:
    global FAILURES
    try:
        proc = subprocess.run(
            [str(binary), "--check", "-c", str(config)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        FAILURES += 1
        print(f"FAIL {label}: --check did not finish within 10s")
        return
    out = (proc.stdout or "") + (proc.stderr or "")
    panicked = "panicked" in out or proc.returncode == 101
    expected = 0 if accepted else 1
    ok = proc.returncode == expected and not panicked and (accepted or proc.stderr.strip())
    FAILURES += 0 if ok else 1
    if not ok:
        tail = [line for line in out.splitlines() if line.strip()][-2:]
        print(f"FAIL {label}: expected={expected} exit={proc.returncode} panicked={panicked} {' | '.join(tail)}")


def main() -> int:
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "target/release/beam"
    template = TEMPLATE.read_text(encoding="utf-8")
    out = Path(tempfile.mkdtemp(prefix="config-matrix-"))
    cases = 0

    check(binary, TEMPLATE, "example", accepted=True)
    cases += 1
    for key, (valid, invalid) in LIMITS.items():
        for accepted, values in ((True, valid), (False, invalid)):
            for value in values:
                text, replacements = re.subn(
                    rf"^{key}\s*=.*$", f"{key} = {value}", template, count=1, flags=re.M
                )
                if replacements != 1:
                    raise ValueError(f"missing config matrix setting: {key}")
                path = out / f"{key}-{value}.toml"
                path.write_text(text, encoding="utf-8")
                check(binary, path, f"{key}={value}", accepted=accepted)
                cases += 1

    # The scalar maximum is still valid with fewer sessions: exercise both
    # sides of the aggregate table budget without weakening either limit.
    for sessions, accepted in ((64, True), (65, False)):
        text = template
        for key, value in (("max_udp_destinations", 65536), ("max_xudp_sessions", sessions)):
            text, replacements = re.subn(
                rf"^{key}\s*=.*$", f"{key} = {value}", text, count=1, flags=re.M
            )
            if replacements != 1:
                raise ValueError(f"missing config matrix setting: {key}")
        path = out / f"packetaddr-budget-{sessions}.toml"
        path.write_text(text, encoding="utf-8")
        check(binary, path, f"packetaddr-budget: 65536 destinations x {sessions} sessions", accepted=accepted)
        cases += 1

    for index, (_key, line) in enumerate(TEXT_CASES):
        text = re.sub(rf"^{_key}\s*=.*$", line, template, count=1, flags=re.M)
        if line.startswith("flow"):
            text = re.sub(r"^flow\s*=.*$", line, text, count=1, flags=re.M)
        path = out / f"text-{index}.toml"
        path.write_text(text, encoding="utf-8")
        check(binary, path, line)
        cases += 1

    # One truncated file and one with an unknown key.
    (out / "truncated.toml").write_text(template[: len(template) // 3], encoding="utf-8")
    check(binary, out / "truncated.toml", "truncated")
    cases += 1
    (out / "unknown.toml").write_text(template + "\n[unknown]\nkey = 1\n", encoding="utf-8")
    check(binary, out / "unknown.toml", "unknown-key")
    cases += 1

    print(f"config-matrix: {'PASS' if FAILURES == 0 else 'FAIL'} ({cases - FAILURES}/{cases})")
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
