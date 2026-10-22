#!/usr/bin/env python3
"""Target-side services for the full-TUN harness.

One process hosts every target in the target network namespace:

* plain HTTP on IPv4 and IPv6,
* a self-signed HTTPS origin (used to exercise Vision Direct),
* UDP echo services on IPv4 and IPv6,
* tiny DNS responders on IPv4 and IPv6,
* an optional UDP sink on 4443 so a QUIC probe can be distinguished from a
  routing failure (it intentionally does not speak HTTP/3). The harness omits
  the sink when the local HTTP/3 origin owns that address instead.

An optional regular file can be exposed at ``/large.bin`` so the benchmark can
measure HTTPS throughput through the tunnel. Per-request logging can be
disabled with ``--quiet`` to keep the target core free for the data path.

This is test-only code and is not part of the beam server.
"""

from __future__ import annotations

import argparse
import http.server
import signal
import socket
import socketserver
import ssl
import struct
import sys
import threading
from pathlib import Path

MARKER = b"beam-tun-ok\n"
DNS_TARGET = "target.test"
DNS_V4 = "10.10.2.2"
DNS_V6 = "fd00:2::2"
QUIET = False


def log(message: str) -> None:
    print(f"target: {message}", file=sys.stderr, flush=True)


def request_log(message: str) -> None:
    if not QUIET:
        log(message)


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _Server6(_Server):
    address_family = socket.AF_INET6


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "beam-tun-target/1"
    sys_version = ""
    wbufsize = 1 << 20
    large_file: Path | None = None

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        if path == "/large.bin" and self.large_file is not None:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(self.large_file.stat().st_size))
            self.send_header("Connection", "close")
            self.end_headers()
            with self.large_file.open("rb") as handle:
                while True:
                    chunk = handle.read(1 << 20)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            return
        body = MARKER
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        request_log(f"http {self.client_address[0]}: {fmt % args}")


def _serve_http(server: http.server.HTTPServer, label: str) -> None:
    log(f"{label} listening on {server.server_address}")
    try:
        server.serve_forever(poll_interval=0.2)
    except OSError as error:
        log(f"{label} stopped: {error}")


def _udp_loop(sock: socket.socket, label: str, echo: bool) -> None:
    log(f"{label} listening on {sock.getsockname()}")
    while True:
        try:
            data, peer = sock.recvfrom(65535)
        except OSError as error:
            log(f"{label} stopped: {error}")
            return
        if echo:
            try:
                sock.sendto(data, peer)
            except OSError as error:
                log(f"{label} send to {peer} failed: {error}")
        else:
            request_log(f"{label} received {len(data)} bytes from {peer}: {data[:16].hex()}")


def _dns_question(query: bytes):
    if len(query) < 12:
        return None
    qdcount = struct.unpack("!H", query[4:6])[0]
    if qdcount != 1:
        return None
    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(query):
            return None
        length = query[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or offset + length > len(query):
            return None
        labels.append(query[offset : offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 > len(query):
        return None
    qtype, qclass = struct.unpack("!HH", query[offset : offset + 4])
    offset += 4
    return ".".join(labels), qtype, qclass, query[12:offset]


def _dns_reply(query: bytes) -> bytes | None:
    parsed = _dns_question(query)
    if parsed is None:
        return None
    qid = struct.unpack("!H", query[0:2])[0]
    name, qtype, qclass, question = parsed

    flags = 0x8180  # standard response, recursion available, NOERROR
    answer = b""
    if name.lower() == DNS_TARGET and qclass == 1:
        if qtype == 1:
            answer = struct.pack("!HHIH", 0xC00C, 1, 60, 4) + socket.inet_aton(DNS_V4)
        elif qtype == 28:
            answer = struct.pack("!HHIH", 0xC00C, 28, 60, 16) + socket.inet_pton(
                socket.AF_INET6, DNS_V6
            )
    elif name.lower() != DNS_TARGET:
        flags = 0x8183  # NXDOMAIN

    ancount = 1 if answer else 0
    response = struct.pack("!HHHHHH", qid, flags, 1, ancount, 0, 0) + question + answer
    request_log(f"dns {name} type={qtype} -> {'answer' if answer else 'empty'}")
    return response


def _dns_loop(sock: socket.socket) -> None:
    log(f"dns listening on {sock.getsockname()}")
    while True:
        try:
            query, peer = sock.recvfrom(65535)
        except OSError as error:
            log(f"dns stopped: {error}")
            return
        reply = _dns_reply(query)
        if reply is not None:
            try:
                sock.sendto(reply, peer)
            except OSError as error:
                log(f"dns send to {peer} failed: {error}")


def _bind_udp(host: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    return sock


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http", default="10.10.2.2:8080")
    parser.add_argument("--http6", default="", help="optional IPv6 HTTP listen address")
    parser.add_argument("--tls", default="10.10.2.2:4443")
    parser.add_argument("--udp", default="10.10.2.2:9999")
    parser.add_argument("--udp6", default="", help="optional IPv6 UDP echo listen address")
    parser.add_argument("--dns", default="10.10.2.2:53")
    parser.add_argument("--dns6", default="", help="optional IPv6 DNS listen address")
    parser.add_argument(
        "--quic-sink",
        default="",
        help="optional UDP sink address; empty when the HTTP/3 origin owns the port",
    )
    parser.add_argument(
        "--large-file",
        default=None,
        type=Path,
        help="optional file served at /large.bin for HTTPS throughput",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress per-request logs (benchmark runs)",
    )
    parser.add_argument("--cert", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    args = parser.parse_args()

    global QUIET
    QUIET = args.quiet
    if args.large_file is not None:
        Handler.large_file = args.large_file

    servers: list[http.server.HTTPServer] = []
    threads: list[threading.Thread] = []

    def split(value: str) -> tuple[str, int]:
        host, port = value.rsplit(":", 1)
        return host.strip("[]"), int(port)

    http_host, http_port = split(args.http)
    tls_host, tls_port = split(args.tls)
    udp_host, udp_port = split(args.udp)
    dns_host, dns_port = split(args.dns)

    plain = _Server((http_host, http_port), Handler)
    servers.append(plain)
    threads.append(threading.Thread(target=_serve_http, args=(plain, "http4"), daemon=True))

    if args.http6:
        http6_host, http6_port = split(args.http6)
        plain6 = _Server6((http6_host, http6_port), Handler)
        servers.append(plain6)
        threads.append(
            threading.Thread(target=_serve_http, args=(plain6, "http6"), daemon=True)
        )

    tls = _Server((tls_host, tls_port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(args.cert), keyfile=str(args.key))
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    servers.append(tls)
    threads.append(threading.Thread(target=_serve_http, args=(tls, "https"), daemon=True))

    udp_sock = _bind_udp(udp_host, udp_port)
    threads.append(threading.Thread(target=_udp_loop, args=(udp_sock, "udp-echo", True), daemon=True))

    dns_sock = _bind_udp(dns_host, dns_port)
    threads.append(threading.Thread(target=_dns_loop, args=(dns_sock,), daemon=True))

    if args.udp6:
        udp6_host, udp6_port = split(args.udp6)
        udp6_sock = _bind_udp(udp6_host, udp6_port)
        threads.append(
            threading.Thread(
                target=_udp_loop, args=(udp6_sock, "udp-echo-v6", True), daemon=True
            )
        )

    if args.dns6:
        dns6_host, dns6_port = split(args.dns6)
        dns6_sock = _bind_udp(dns6_host, dns6_port)
        threads.append(
            threading.Thread(target=_dns_loop, args=(dns6_sock,), daemon=True)
        )

    if args.quic_sink:
        quic_host, quic_port = split(args.quic_sink)
        quic_sock = _bind_udp(quic_host, quic_port)
        threads.append(
            threading.Thread(
                target=_udp_loop, args=(quic_sock, "quic-sink", False), daemon=True
            )
        )

    for thread in threads:
        thread.start()

    log("READY")
    stop = threading.Event()

    def _stop(_signum, _frame) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    stop.wait()
    for server in servers:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
