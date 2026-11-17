#!/usr/bin/env python3
"""Admission saturation and crash-restart: the two production restart properties."""
from __future__ import annotations
import re, signal, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vless_client import (  # noqa: E402
    Echo, free_port, reality_public_key, socks5_connect, wait_listen, write_client_config,
)

FAILURES = 0


def check(name, ok, detail):
    global FAILURES
    FAILURES += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)


def server_config(path: Path, template: Path, port: int, cover_port: int, max_connections: int) -> None:
    text = template.read_text(encoding="utf-8")
    text = re.sub(r'^listen\s*=.*$', f'listen = "127.0.0.1:{port}"', text, count=1, flags=re.M)
    text = re.sub(r'^dest\s*=.*$', f'dest = "127.0.0.1:{cover_port}"', text, count=1, flags=re.M)
    text = re.sub(r'^max_connections\s*=.*$', f"max_connections = {max_connections}", text, count=1, flags=re.M)
    path.write_text(text, encoding="utf-8")


def roundtrip(proxy, port, payload=b"probe") -> bool:
    try:
        sock = socks5_connect(proxy, "127.0.0.1", port, timeout=8.0)
        sock.settimeout(8.0)
        sock.sendall(payload)
        got = sock.recv(64)
        sock.close()
        return got == payload
    except OSError:
        return False


def main() -> int:
    beam, sing_box = Path(sys.argv[1]), Path(sys.argv[2])
    repo = Path(".").resolve()
    template = repo / "config.example.toml"
    priv = next(l.split('"')[1] for l in template.read_text().splitlines() if l.startswith("private_key"))
    pubkey = reality_public_key(priv)
    out = Path(tempfile.mkdtemp(prefix="admission-"))
    cover_port = free_port()
    cover = socket.socket(); cover.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cover.bind(("127.0.0.1", cover_port)); cover.listen(32)
    port, socks_port = free_port(), free_port()
    server_config(out / "beam.toml", template, port, cover_port, max_connections=1)
    write_client_config(out / "client.json", port, socks_port, pubkey)
    server = subprocess.Popen([str(beam), "-c", str(out / "beam.toml")],
                              stdout=(out / "beam.log").open("wb"), stderr=subprocess.STDOUT)
    client = subprocess.Popen([str(sing_box), "run", "-c", str(out / "client.json")],
                              stdout=(out / "client.log").open("wb"), stderr=subprocess.STDOUT)
    echo = Echo("tcp")
    try:
        wait_listen(port); wait_listen(socks_port, 15.0); time.sleep(0.4)
        proxy = ("127.0.0.1", socks_port)

        # A. One admitted connection works; concurrent ones beyond the limit fail
        #    without taking the server down.
        check("first_connection", roundtrip(proxy, echo.port), "admitted")
        results = []

        def attempt() -> None:
            try:
                results.append(roundtrip(proxy, echo.port))
            except Exception as error:  # the socks layer surfaces a rejected dial
                results.append(f"rejected:{type(error).__name__}")

        threads = [threading.Thread(target=attempt) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        time.sleep(1.0)
        rejected = sum(1 for value in results if value is False or str(value).startswith("rejected"))
        check(
            "limit_rejects_extras",
            len(results) == 3 and rejected >= 1 and server.poll() is None,
            f"concurrent_results={results} rejected={rejected}",
        )
        time.sleep(1.0)
        check("recovers_after_release", roundtrip(proxy, echo.port), "post-limit connection")

        # B. Hard kill, then an immediate restart on the same port must bind.
        server.send_signal(signal.SIGKILL)
        server.wait(timeout=10)
        started = time.time()
        restarted = subprocess.Popen([str(beam), "-c", str(out / "beam.toml")],
                                     stdout=(out / "beam2.log").open("wb"), stderr=subprocess.STDOUT)
        bound = False
        try:
            wait_listen(port, 10.0)
            bound = True
        except RuntimeError:
            bound = False
        elapsed = time.time() - started
        check("rebind_after_sigkill", bound, f"bound={bound} elapsed_s={elapsed:.2f}")
        check("restarted_process_alive", restarted.poll() is None, "running")
        restarted.terminate()
        try:
            restarted.wait(timeout=10)
        except subprocess.TimeoutExpired:
            restarted.kill()
    finally:
        for proc in (client, server):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        echo.close(); cover.close()
        if FAILURES:
            for name in ("beam.log", "beam2.log", "client.log"):
                path = out / name
                if path.exists():
                    print(f"--- {name} tail ---")
                    for line in path.read_text(errors="replace").splitlines()[-10:]:
                        print(f"  {line}")
    print("admission:", "PASS" if FAILURES == 0 else "FAIL")
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
