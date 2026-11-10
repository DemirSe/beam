#!/usr/bin/env python3
"""Five-hour local data-path soak for the beam server.

Starts one beam server, one stock Xray SOCKS client, and one loopback HTTP
target, then loops a Vision/VLESS download through the SOCKS client. Samples
the server RSS/fds/threads, runs a short concurrent churn every 5 minutes, and
runs the loopback admission/cover stress suite every 15 minutes. No TUN, no
root, no CPU pinning.

Environment:
    SOAK_SECONDS   duration, default 18000 (5 h)
    SOAK_OUT       output directory, default ~/.cache/beam/soak/<timestamp>
    XRAY_BIN       stock Xray client, default `xray` from PATH
    BEAM_BIN       server binary, default target/release/beam
    TEST_CONFIG    REALITY fixture, default config.example.toml
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAMP = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
OUT = Path(
    os.environ.get(
        "SOAK_OUT",
        str(Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
            / "beam" / "soak" / STAMP),
    )
)
BEAM = Path(os.environ.get("BEAM_BIN", ROOT / "target/release/beam"))
XRAY = os.environ.get("XRAY_BIN", "xray")
TEST_CONFIG = Path(os.environ.get("TEST_CONFIG", ROOT / "config.example.toml"))
DURATION = int(os.environ.get("SOAK_SECONDS", "18000"))
PORT = 18443
SOCKS = 11080
TARGET_PORT = 18080


def resolve_xray() -> Path:
    candidate = Path(XRAY)
    if candidate.is_file():
        return candidate
    from shutil import which

    found = which(XRAY)
    if found is None:
        raise SystemExit(f"soak: stock Xray not found: {XRAY} (set XRAY_BIN)")
    return Path(found)


def wait_port(port, timeout=20, host="127.0.0.1"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def sample(pid):
    data = {"t": round(time.time(), 3), "rss_kib": None, "fds": None, "threads": None}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                data["rss_kib"] = int(line.split()[1])
            elif line.startswith("Threads:"):
                data["threads"] = int(line.split()[1])
        data["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        data["dead"] = True
    return data


def main():
    if DURATION <= 0:
        raise SystemExit("soak: SOAK_SECONDS must be positive")
    if not BEAM.is_file():
        raise SystemExit(f"soak: beam binary not found: {BEAM} (run make build)")
    xray = resolve_xray()
    OUT.mkdir(parents=True, exist_ok=True)
    config_dir = OUT / "config"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tests/tun/config.py"),
            "--test-config",
            str(TEST_CONFIG),
            "--out-dir",
            str(config_dir),
            "--listen",
            f"127.0.0.1:{PORT}",
            "--cover",
            "whatsapp.net:443",
            "--xray",
            "--xray-client",
            "--log-level",
            "info",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    target_dir = OUT / "target"
    target_dir.mkdir(exist_ok=True)
    for name, size in (("big.bin", 64), ("small.bin", 1)):
        path = target_dir / name
        if not path.exists() or path.stat().st_size != size * 1024 * 1024:
            with path.open("wb") as handle:
                handle.write(b"\0" * (size * 1024 * 1024))

    target = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(TARGET_PORT), "--bind", "127.0.0.1",
         "--directory", str(target_dir)],
        stdout=open(OUT / "target.log", "wb"),
        stderr=subprocess.STDOUT,
    )
    client = subprocess.Popen(
        [str(xray), "run", "-c", str(config_dir / "xray-client.json")],
        stdout=open(OUT / "xray.log", "wb"),
        stderr=subprocess.STDOUT,
    )
    server = subprocess.Popen(
        [str(BEAM), "-c", str(config_dir / "beam.toml")],
        stdout=open(OUT / "beam.log", "wb"),
        stderr=subprocess.STDOUT,
    )
    procs = [target, client, server]
    try:
        if not (wait_port(PORT) and wait_port(SOCKS) and wait_port(TARGET_PORT)):
            raise RuntimeError("a soak process did not become ready")
        print("SOAK READY", flush=True)
        time.sleep(5)
        samples = []
        failures = 0
        downloads = 0
        churn = 0
        stress_runs = 0
        stress_failures = 0
        start = time.time()
        next_sample = start
        next_churn = start + 300
        next_stress = start + 900
        while time.time() - start < DURATION:
            rc = subprocess.run(
                [
                    "curl", "--silent", "--show-error", "--max-time", "120",
                    "--noproxy", "", "--socks5-hostname", f"127.0.0.1:{SOCKS}",
                    "-o", "/dev/null", "-w", "%{http_code} %{speed_download} %{time_total}",
                    f"http://127.0.0.1:{TARGET_PORT}/big.bin",
                ],
                capture_output=True,
                text=True,
            )
            downloads += 1
            if rc.returncode != 0:
                failures += 1
                with (OUT / "failures.log").open("a") as handle:
                    handle.write(
                        f"{time.time():.3f} download rc={rc.returncode} {rc.stderr.strip()}\n"
                    )
            elif not rc.stdout.startswith("200"):
                failures += 1
                with (OUT / "failures.log").open("a") as handle:
                    handle.write(f"{time.time():.3f} download code={rc.stdout}\n")
            now = time.time()
            if now >= next_sample:
                samples.append(sample(server.pid))
                next_sample = now + 30
            if now >= next_churn:
                churn += 1
                workers = [
                    subprocess.Popen(
                        [
                            "curl", "--silent", "--max-time", "30", "--noproxy", "",
                            "--socks5-hostname", f"127.0.0.1:{SOCKS}",
                            "-o", "/dev/null",
                            f"http://127.0.0.1:{TARGET_PORT}/small.bin",
                        ]
                    )
                    for _ in range(16)
                ]
                for worker in workers:
                    if worker.wait() != 0:
                        failures += 1
                next_churn = now + 300
            if now >= next_stress:
                stress_runs += 1
                stress = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "tests/stress/loopback.py"),
                        "--beam",
                        str(BEAM),
                        "--out",
                        str(OUT / f"stress-{stress_runs}"),
                    ],
                    capture_output=True,
                    text=True,
                )
                with (OUT / "stress.log").open("a") as handle:
                    handle.write(stress.stdout)
                if stress.returncode != 0:
                    stress_failures += 1
                next_stress = now + 900
            if server.poll() is not None:
                failures += 1
                break
        alive = server.poll() is None
        final = sample(server.pid)
        baseline = samples[0] if samples else {}
        summary = {
            "duration_s": round(time.time() - start, 1),
            "downloads": downloads,
            "failures": failures,
            "churn_rounds": churn,
            "stress_runs": stress_runs,
            "stress_failures": stress_failures,
            "server_alive": alive,
            "baseline": baseline,
            "final": final,
            "rss_growth_kib": (
                final["rss_kib"] - baseline["rss_kib"]
                if final.get("rss_kib") and baseline.get("rss_kib")
                else None
            ),
            "ok": bool(
                alive
                and failures == 0
                and stress_failures == 0
                and (final.get("rss_kib") or 0) > 0
            ),
        }
        (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print("SOAK DONE", json.dumps(summary), flush=True)
        return 0 if summary["ok"] else 1
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
