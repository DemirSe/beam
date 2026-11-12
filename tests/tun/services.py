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

The protocol lab additionally enables: a persistent HTTP/1.1 path
(``--keepalive``), a TCP echo listener (``--tcp-echo``), a TLS 1.2-only listener
(``--tls12``), a TCP DNS responder (``--dns-tcp``), extra UDP echo ports
(``--udp-extra``) and a UDP listener that replies from a different source port
(``--udp-alt``).

An optional regular file can be exposed at ``/large.bin`` so the benchmark can
measure HTTPS throughput through the tunnel, and any response can ask for a
marker body of ``?bytes=N`` bytes. Per-request logging can be disabled with
``--quiet`` to keep the target core free for the data path.

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
MAX_BODY = 64 * 1024 * 1024
KEEPALIVE = False
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
    # The stock HTTPServer backlog of 5 turns a 64-way churn run into SYN
    # retry latency on the target, not on the server under test.
    request_queue_size = 256


class _Server6(_Server):
    address_family = socket.AF_INET6


def marker_body(size: int) -> bytes:
    repeats = (size + len(MARKER) - 1) // len(MARKER)
    return (MARKER * repeats)[:size]


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "beam-tun-target/1"
    sys_version = ""
    wbufsize = 1 << 20
    large_file: Path | None = None

    def _requested_body(self) -> bytes:
        """Body for this request: the marker, or ``?bytes=N`` of the marker.

        Raises ``ValueError`` for a malformed or out-of-range size so the
        caller can answer 400 instead of allocating an unbounded body.
        """
        _, _, query = self.path.partition("?")
        for pair in query.split("&"):
            key, _, value = pair.partition("=")
            if key != "bytes":
                continue
            try:
                size = int(value)
            except ValueError as error:
                raise ValueError(f"invalid bytes parameter: {value}") from error
            if not 1 <= size <= MAX_BODY:
                raise ValueError(f"bytes must be between 1 and {MAX_BODY}")
            return marker_body(size)
        return MARKER

    def _send_body(self, body: bytes, connection: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", connection)
        self.end_headers()
        self.wfile.write(body)

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
        persist = KEEPALIVE and path == "/keepalive"
        try:
            body = self._requested_body()
        except ValueError as error:
            message = f"bad request: {error}\n".encode()
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(message)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(message)
            return
        self._send_body(body, "keep-alive" if persist else "close")

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


def _udp_source_port_loop(sock: socket.socket, label: str) -> None:
    """Echo each datagram and append the source port the target observed.

    The idle-resume case needs the client's source port, not the target's, to
    tell whether a torn-down flow came back as a new mapping.
    """
    log(f"{label} listening on {sock.getsockname()}")
    while True:
        try:
            data, peer = sock.recvfrom(65535)
        except OSError as error:
            log(f"{label} stopped: {error}")
            return
        try:
            sock.sendto(data + struct.pack("!H", peer[1]), peer)
        except OSError as error:
            log(f"{label} send to {peer} failed: {error}")


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
        # NAME (compression pointer), TYPE, CLASS, TTL, RDLENGTH, RDATA. The
        # class field is mandatory: without it the answer is unparseable and
        # `dig` reports a malformed packet instead of the A/AAAA record.
        if qtype == 1:
            answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(DNS_V4)
        elif qtype == 28:
            answer = struct.pack("!HHHIH", 0xC00C, 28, 1, 60, 16) + socket.inet_pton(
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


def _bind_tcp(host: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    return listener


def _tcp_echo_connection(conn: socket.socket, peer, label: str) -> None:
    request_log(f"{label} connection from {peer}")
    with conn:
        while True:
            try:
                data = conn.recv(65536)
            except OSError as error:
                request_log(f"{label} connection from {peer} stopped: {error}")
                return
            if not data:
                return
            try:
                conn.sendall(data)
            except OSError as error:
                request_log(f"{label} send to {peer} failed: {error}")
                return


def _tcp_echo_loop(listener: socket.socket, label: str) -> None:
    log(f"{label} listening on {listener.getsockname()}")
    while True:
        try:
            conn, peer = listener.accept()
        except OSError as error:
            log(f"{label} stopped: {error}")
            return
        threading.Thread(
            target=_tcp_echo_connection, args=(conn, peer, label), daemon=True
        ).start()


def _recv_exact(conn: socket.socket, size: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < size:
        data = conn.recv(size - len(chunks))
        if not data:
            return None
        chunks.extend(data)
    return bytes(chunks)


def _dns_tcp_connection(conn: socket.socket, peer) -> None:
    request_log(f"dns-tcp connection from {peer}")
    with conn:
        conn.settimeout(15.0)
        while True:
            try:
                header = _recv_exact(conn, 2)
                if header is None:
                    return
                (length,) = struct.unpack("!H", header)
                if length == 0:
                    return
                query = _recv_exact(conn, length)
                if query is None:
                    return
                reply = _dns_reply(query)
                if reply is None:
                    return
                conn.sendall(struct.pack("!H", len(reply)) + reply)
            except OSError as error:
                request_log(f"dns-tcp connection from {peer} stopped: {error}")
                return


def _dns_tcp_loop(listener: socket.socket) -> None:
    log(f"dns-tcp listening on {listener.getsockname()}")
    while True:
        try:
            conn, peer = listener.accept()
        except OSError as error:
            log(f"dns-tcp stopped: {error}")
            return
        threading.Thread(target=_dns_tcp_connection, args=(conn, peer), daemon=True).start()


def _udp_alt_loop(listen: socket.socket, reply: socket.socket, label: str) -> None:
    """Echo back from a different source port than the listener.

    This is the STUN-like full-cone shape: a reply arrives from an address the
    client never sent to, which is where XUDP source-address handling shows up.
    """
    log(
        f"{label} listening on {listen.getsockname()} "
        f"(replies from {reply.getsockname()})"
    )
    while True:
        try:
            data, peer = listen.recvfrom(65535)
        except OSError as error:
            log(f"{label} stopped: {error}")
            return
        request_log(f"{label} received {len(data)} bytes from {peer}")
        try:
            reply.sendto(data, peer)
        except OSError as error:
            log(f"{label} reply to {peer} failed: {error}")


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
    parser.add_argument(
        "--tls-max-12",
        action="store_true",
        help="force the HTTPS origin to TLS 1.2 for fallback-path tests",
    )
    parser.add_argument(
        "--keepalive",
        action="store_true",
        help="serve /keepalive over a persistent HTTP/1.1 connection",
    )
    parser.add_argument(
        "--tcp-echo",
        default="",
        help="optional TCP echo listen address (protocol lab uses 9000)",
    )
    parser.add_argument(
        "--tls12",
        default="",
        help="optional TLS 1.2-only HTTPS listen address (protocol lab uses 8444)",
    )
    parser.add_argument(
        "--dns-tcp",
        default="",
        help="optional TCP DNS listen address (protocol lab uses 53)",
    )
    parser.add_argument(
        "--udp-alt",
        default="",
        help="optional UDP listen address that replies from another source port",
    )
    parser.add_argument(
        "--udp-source-port",
        default="",
        help="optional UDP listen address that echoes the observed source port",
    )
    parser.add_argument(
        "--udp-extra",
        action="append",
        default=[],
        metavar="ADDR",
        help="additional UDP echo listen address (repeatable)",
    )
    args = parser.parse_args()

    global QUIET, KEEPALIVE
    QUIET = args.quiet
    KEEPALIVE = args.keepalive
    if KEEPALIVE:
        Handler.protocol_version = "HTTP/1.1"
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
    if args.tls_max_12:
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(args.cert), keyfile=str(args.key))
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    servers.append(tls)
    threads.append(threading.Thread(target=_serve_http, args=(tls, "https"), daemon=True))

    udp_sock = _bind_udp(udp_host, udp_port)
    threads.append(threading.Thread(target=_udp_loop, args=(udp_sock, "udp-echo", True), daemon=True))

    dns_sock = _bind_udp(dns_host, dns_port)
    threads.append(threading.Thread(target=_dns_loop, args=(dns_sock,), daemon=True))

    if args.udp_source_port:
        source_host, source_port = split(args.udp_source_port)
        source_sock = _bind_udp(source_host, source_port)
        threads.append(
            threading.Thread(
                target=_udp_source_port_loop,
                args=(source_sock, "udp-source-port"),
                daemon=True,
            )
        )

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

    if args.tls12:
        tls12_host, tls12_port = split(args.tls12)
        tls12 = _Server((tls12_host, tls12_port), Handler)
        tls12_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls12_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls12_context.maximum_version = ssl.TLSVersion.TLSv1_2
        tls12_context.load_cert_chain(certfile=str(args.cert), keyfile=str(args.key))
        tls12.socket = tls12_context.wrap_socket(tls12.socket, server_side=True)
        servers.append(tls12)
        threads.append(
            threading.Thread(target=_serve_http, args=(tls12, "tls12"), daemon=True)
        )

    if args.tcp_echo:
        echo_host, echo_port = split(args.tcp_echo)
        echo_listener = _bind_tcp(echo_host, echo_port)
        threads.append(
            threading.Thread(
                target=_tcp_echo_loop, args=(echo_listener, "tcp-echo"), daemon=True
            )
        )

    if args.dns_tcp:
        dns_tcp_host, dns_tcp_port = split(args.dns_tcp)
        dns_tcp_listener = _bind_tcp(dns_tcp_host, dns_tcp_port)
        threads.append(
            threading.Thread(target=_dns_tcp_loop, args=(dns_tcp_listener,), daemon=True)
        )

    for extra in args.udp_extra:
        extra_host, extra_port = split(extra)
        extra_sock = _bind_udp(extra_host, extra_port)
        threads.append(
            threading.Thread(
                target=_udp_loop,
                args=(extra_sock, f"udp-echo-{extra_port}", True),
                daemon=True,
            )
        )

    if args.udp_alt:
        alt_host, alt_port = split(args.udp_alt)
        alt_listen = _bind_udp(alt_host, alt_port)
        # Distinct from every echo port so the reply's source is unambiguous.
        alt_reply = _bind_udp(alt_host, 9995)
        threads.append(
            threading.Thread(
                target=_udp_alt_loop,
                args=(alt_listen, alt_reply, "udp-alt"),
                daemon=True,
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
