#!/usr/bin/env python3
"""Real HTTPS through the tunnel: inner TLS reaches Vision, which must switch to Direct.

All earlier campaigns sent plaintext through the relay, so the Vision detector
never saw a ServerHello. This serves a self-signed HTTPS endpoint and fetches it
through the socks proxy with curl, then compares hashes and looks for the
raw-handoff log lines that prove Direct engaged.
"""
from __future__ import annotations
import hashlib, http.server, os, socket, ssl, subprocess, sys, tempfile, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vless_client import (  # noqa: E402
    free_port, reality_public_key, wait_listen, write_client_config, write_server_config,
)

FAILURES = 0
BODY = bytes((i * 37) % 256 for i in range(2 << 20))


def check(name, ok, detail):
    global FAILURES
    FAILURES += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):  # silence
        return


def serve_tls(out: Path) -> tuple[int, ssl.SSLContext]:
    cert = out / "cert.pem"
    key = out / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def main() -> int:
    beam, sing_box = Path(sys.argv[1]), Path(sys.argv[2])
    repo = Path(".").resolve()
    template = repo / "config.example.toml"
    priv = next(l.split('"')[1] for l in template.read_text().splitlines() if l.startswith("private_key"))
    pubkey = reality_public_key(priv)
    out = Path(tempfile.mkdtemp(prefix="tlsin-"))
    ctx = serve_tls(out)
    tls_port = free_port()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", tls_port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    cover_port = free_port()
    cover = socket.socket(); cover.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cover.bind(("127.0.0.1", cover_port)); cover.listen(32)
    port, socks_port = free_port(), free_port()
    write_server_config(out / "beam.toml", port, cover_port, template)
    write_client_config(out / "client.json", port, socks_port, pubkey)
    log = (out / "beam.log").open("wb")
    server = subprocess.Popen([str(beam), "-c", str(out / "beam.toml")], stdout=log, stderr=subprocess.STDOUT)
    client = subprocess.Popen([str(sing_box), "run", "-c", str(out / "client.json")],
                              stdout=(out / "client.log").open("wb"), stderr=subprocess.STDOUT)
    try:
        wait_listen(port); wait_listen(socks_port, 15.0); time.sleep(0.4)
        # Warm the path, then fetch twice so a Direct switch cannot be a one-off.
        for attempt in (1, 2):
            dest = out / f"body-{attempt}.bin"
            result = subprocess.run(
                ["curl", "-sS", "--insecure", "--max-time", "60",
                 "--proxy", f"socks5h://127.0.0.1:{socks_port}",
                 f"https://127.0.0.1:{tls_port}/", "-o", str(dest)],
                capture_output=True, text=True,
            )
            got = dest.read_bytes() if dest.exists() else b""
            check(
                f"https_through_tunnel_{attempt}",
                result.returncode == 0 and hashlib.sha256(got).digest() == hashlib.sha256(BODY).digest(),
                f"rc={result.returncode} bytes={len(got)}/{len(BODY)} err={result.stderr.strip()[:80]}",
            )
        time.sleep(0.5)
        log.flush()
        text = (out / "beam.log").read_text(errors="replace")
        direct = text.count("switched to raw")
        check("vision_direct_engaged", direct >= 1, f"raw_switch_lines={direct}")
        check("server_alive", server.poll() is None, "running")
    finally:
        for proc in (client, server):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        httpd.shutdown()
        cover.close(); log.close()
        if FAILURES:
            for name in ("beam.log", "client.log"):
                path = out / name
                if path.exists():
                    print(f"--- {name} tail ---")
                    for line in path.read_text(errors="replace").splitlines()[-15:]:
                        print(f"  {line}")
    print("tls-in-tls:", "PASS" if FAILURES == 0 else "FAIL")
    return 0 if FAILURES == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
