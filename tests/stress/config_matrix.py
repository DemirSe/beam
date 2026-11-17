#!/usr/bin/env python3
"""Config-matrix gate: `beam --check` must always answer, never panic or hang.

For each numeric limit it tries boundary values (0, 1, max, max+1, huge) and for
each text field malformed values, then requires the binary to exit 0 (accepted)
or 1 (rejected with a message). Exit 101 (panic), a signal, or a timeout is a
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

LIMITS = {
    "max_connections": ["0", "1", "2", "4294967295", "18446744073709551615"],
    "max_udp_destinations": ["0", "1", "65536", "18446744073709551615"],
    "max_preauth_per_ip": ["0", "1", "4294967295"],
    "max_xudp_sessions": ["0", "1", "4294967295", "18446744073709551615"],
    "xudp_recv_buffer_bytes": ["0", "1", "16383", "16384", "4194304", "4194305"],
    "listen_backlog": ["0", "1", "65535", "65536"],
    "shutdown_drain_ms": ["0", "1", "3000", "3001"],
    "handshake_timeout_ms": ["0", "1", "99", "100", "86400000", "86400001"],
    "idle_timeout_ms": ["0", "1", "999", "1000", "86400000", "86400001"],
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


def check(binary: Path, config: Path, label: str) -> None:
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
    ok = proc.returncode in (0, 1) and not panicked
    FAILURES += 0 if ok else 1
    if not ok:
        tail = [line for line in out.splitlines() if line.strip()][-2:]
        print(f"FAIL {label}: exit={proc.returncode} panicked={panicked} {' | '.join(tail)}")


def main() -> int:
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "target/release/beam"
    template = TEMPLATE.read_text(encoding="utf-8")
    out = Path(tempfile.mkdtemp(prefix="config-matrix-"))
    cases = 0

    for key, values in LIMITS.items():
        for value in values:
            text = re.sub(rf"^{key}\s*=.*$", f"{key} = {value}", template, count=1, flags=re.M)
            path = out / f"{key}-{value}.toml"
            path.write_text(text, encoding="utf-8")
            check(binary, path, f"{key}={value}")
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
