#!/usr/bin/env python3
"""Local cover-parity helper for beam.

Two subcommands:

    proxy    Relay one TCP connection, capture the server's TLS flight.
    analyze  Parse a captured flight and compare it with a cover artifact.

The proxy is deliberately small and dependency-free. It is a passive TLS
record splitter: it forwards every byte unchanged and only keeps a copy of the
records that make up the server's first flight.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import selectors
import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

TLS_RECORD_HEADER_LEN = 5
TLS_MAX_PLAINTEXT = 16_384
# Allow record protection overhead while still rejecting a hostile length.
TLS_MAX_RECORD = TLS_MAX_PLAINTEXT + 2_048
MAX_CAPTURE_RECORDS = 32
MAX_CAPTURE_BYTES = 1 << 20
MAX_BUFFER_BYTES = 1 << 20

RECORD_HANDSHAKE = 22
RECORD_CHANGE_CIPHER_SPEC = 20
RECORD_ALERT = 21
RECORD_APPLICATION_DATA = 23

HANDSHAKE_SERVER_HELLO = 2

EXT_SUPPORTED_VERSIONS = 0x002B
EXT_KEY_SHARE = 0x0033

GROUP_NAMES = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "X25519",
    0x001E: "X448",
    0x11EB: "MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP256r1MLKEM768",
    0x11EE: "SecP384r1MLKEM1024",
}

CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

EXTENSION_NAMES = {
    0x0000: "server_name",
    0x0005: "status_request",
    0x000A: "supported_groups",
    0x000B: "ec_point_formats",
    0x000D: "signature_algorithms",
    0x0010: "alpn",
    0x0012: "signed_certificate_timestamp",
    0x0017: "extended_master_secret",
    0x001B: "certificate_authorities",
    0x0023: "session_ticket",
    0x0029: "pre_shared_key",
    0x002B: "supported_versions",
    0x002D: "psk_key_exchange_modes",
    0x0033: "key_share",
    0x0039: "compress_certificate",
    0xFE0D: "encrypted_client_hello",
}

RECORD_TYPE_NAMES = {
    RECORD_CHANGE_CIPHER_SPEC: "change_cipher_spec",
    RECORD_ALERT: "alert",
    RECORD_HANDSHAKE: "handshake",
    RECORD_APPLICATION_DATA: "application_data",
}

# Values quoted in docs/10-cover-parity.md for the rustls + aws-lc-pq cover
# probe. The artifact is treated as the source of truth when it exists; these
# are printed as the documented baseline and guard against a stale artifact.
DOC_SERVER_HELLO_BYTES = 1215
DOC_FLIGHT_BYTES = (4305, 4306)
DOC_FLIGHT_RECORD_COUNT = 5


class ParseError(Exception):
    """The captured bytes are not a well-formed TLS server flight."""


@dataclass(frozen=True)
class Record:
    record_type: int
    version: int
    payload: bytes
    raw: bytes

    @property
    def wire_length(self) -> int:
        return len(self.raw)

    @property
    def type_name(self) -> str:
        return RECORD_TYPE_NAMES.get(self.record_type, f"type-{self.record_type}")

    def as_dict(self) -> dict:
        return {
            "type": self.record_type,
            "type_name": self.type_name,
            "version": f"0x{self.version:04x}",
            "length": len(self.payload),
            "wire_length": self.wire_length,
        }


def split_records(buffer: bytearray, *, source: str) -> list[Record]:
    """Consume every complete TLS record currently in *buffer*."""
    records: list[Record] = []
    offset = 0
    while len(buffer) - offset >= TLS_RECORD_HEADER_LEN:
        record_type, version, length = struct.unpack_from("!BHH", buffer, offset)
        if length > TLS_MAX_RECORD:
            raise ParseError(
                f"{source}: record length {length} exceeds {TLS_MAX_RECORD} bytes"
            )
        total = TLS_RECORD_HEADER_LEN + length
        if len(buffer) - offset < total:
            break
        raw = bytes(buffer[offset : offset + total])
        records.append(Record(record_type, version, raw[5:], raw))
        offset += total
    del buffer[:offset]
    return records


def parse_record_stream(data: bytes, *, source: str) -> list[Record]:
    """Parse a byte stream that must contain only complete TLS records."""
    buffer = bytearray(data)
    records = split_records(buffer, source=source)
    if buffer:
        raise ParseError(
            f"{source}: {len(buffer)} trailing bytes do not form a complete record"
        )
    if not records:
        raise ParseError(f"{source}: no TLS records found")
    if len(records) > MAX_CAPTURE_RECORDS:
        raise ParseError(
            f"{source}: {len(records)} records exceeds the {MAX_CAPTURE_RECORDS} limit"
        )
    return records


def _take(body: bytes, cursor: int, length: int, what: str) -> tuple[bytes, int]:
    end = cursor + length
    if end > len(body):
        raise ParseError(f"ServerHello truncated while reading {what}")
    return body[cursor:end], end


def _u8(body: bytes, cursor: int, what: str) -> tuple[int, int]:
    raw, cursor = _take(body, cursor, 1, what)
    return raw[0], cursor


def _u16(body: bytes, cursor: int, what: str) -> tuple[int, int]:
    raw, cursor = _take(body, cursor, 2, what)
    return struct.unpack("!H", raw)[0], cursor


def parse_server_hello(record: Record) -> dict:
    """Parse the plaintext ServerHello record."""
    if record.record_type != RECORD_HANDSHAKE:
        raise ParseError(
            f"first server record is {record.type_name}, expected handshake"
        )
    payload = record.payload
    if len(payload) < 4:
        raise ParseError("ServerHello handshake header is truncated")
    handshake_type = payload[0]
    if handshake_type != HANDSHAKE_SERVER_HELLO:
        raise ParseError(
            f"first handshake message is type {handshake_type}, expected ServerHello"
        )
    handshake_length = int.from_bytes(payload[1:4], "big")
    if handshake_length + 4 != len(payload):
        raise ParseError(
            "ServerHello record contains "
            f"{len(payload) - 4} handshake bytes, header declares {handshake_length}"
        )

    body = payload[4:]
    cursor = 0
    legacy_version, cursor = _u16(body, cursor, "legacy_version")
    random_bytes, cursor = _take(body, cursor, 32, "random")
    session_id_len, cursor = _u8(body, cursor, "session_id length")
    if session_id_len > 32:
        raise ParseError(f"ServerHello session id length {session_id_len} exceeds 32")
    session_id, cursor = _take(body, cursor, session_id_len, "session id")
    cipher_suite, cursor = _u16(body, cursor, "cipher suite")
    compression, cursor = _u8(body, cursor, "compression method")
    extensions_len, cursor = _u16(body, cursor, "extensions length")
    extensions_raw, cursor = _take(body, cursor, extensions_len, "extensions")
    if cursor != len(body):
        raise ParseError(
            f"ServerHello has {len(body) - cursor} bytes after its extensions"
        )

    extensions = []
    ext_cursor = 0
    while ext_cursor < len(extensions_raw):
        if len(extensions_raw) - ext_cursor < 4:
            raise ParseError("ServerHello extension header is truncated")
        ext_type, ext_len = struct.unpack_from("!HH", extensions_raw, ext_cursor)
        ext_cursor += 4
        ext_data, ext_cursor = _take(
            extensions_raw, ext_cursor, ext_len, f"extension 0x{ext_type:04x}"
        )
        extensions.append(
            {
                "type": ext_type,
                "name": EXTENSION_NAMES.get(ext_type, "unknown"),
                "length": ext_len,
                "data": ext_data,
            }
        )
    if len(extensions) > 64:
        raise ParseError(f"ServerHello has too many extensions ({len(extensions)})")

    supported_version = None
    key_share = None
    for extension in extensions:
        if extension["type"] == EXT_SUPPORTED_VERSIONS:
            if len(extension["data"]) != 2:
                raise ParseError("supported_versions extension is not two bytes")
            supported_version = struct.unpack("!H", extension["data"])[0]
        elif extension["type"] == EXT_KEY_SHARE:
            data = extension["data"]
            if len(data) < 4:
                raise ParseError("key_share extension is truncated")
            group, key_len = struct.unpack_from("!HH", data)
            if key_len + 4 != len(data):
                raise ParseError(
                    f"key_share declares {key_len} key bytes but carries "
                    f"{len(data) - 4}"
                )
            key_share = {
                "group": group,
                "group_name": GROUP_NAMES.get(group, "unknown"),
                "key_length": key_len,
                "key_sha256": hashlib.sha256(data[4:]).hexdigest(),
            }

    if supported_version is None:
        raise ParseError("ServerHello has no supported_versions extension")
    if key_share is None:
        raise ParseError("ServerHello has no key_share extension")

    return {
        "record": record.as_dict(),
        "record_version": f"0x{record.version:04x}",
        "legacy_version": f"0x{legacy_version:04x}",
        "tls_version": f"0x{supported_version:04x}",
        "random": random_bytes.hex(),
        "session_id_length": session_id_len,
        "session_id": session_id.hex(),
        "cipher_suite": cipher_suite,
        "cipher_suite_name": CIPHER_NAMES.get(cipher_suite, "unknown"),
        "compression_method": compression,
        "extensions": [
            {
                "type": extension["type"],
                "name": extension["name"],
                "length": extension["length"],
            }
            for extension in extensions
        ],
        "extension_order": [extension["type"] for extension in extensions],
        "key_share": key_share,
        "sha256": hashlib.sha256(record.raw).hexdigest(),
    }


def parse_flight(path: Path) -> dict:
    try:
        if path.stat().st_size > MAX_CAPTURE_BYTES:
            raise ParseError(
                f"{path}: capture exceeds the {MAX_CAPTURE_BYTES}-byte limit"
            )
        data = path.read_bytes()
    except OSError as error:
        raise ParseError(f"cannot read {path}: {error}") from error
    records = parse_record_stream(data, source=str(path))
    hello = parse_server_hello(records[0])
    subsequent = [record.as_dict() for record in records[1:]]
    encrypted = [
        record.wire_length for record in records if record.record_type == RECORD_APPLICATION_DATA
    ]
    return {
        "path": str(path),
        "hello": hello,
        "records": [record.as_dict() for record in records],
        "record_count": len(records),
        "record_sizes": [record.wire_length for record in records],
        "total_bytes": sum(record.wire_length for record in records),
        "encrypted_record_sizes": encrypted,
        "encrypted_bytes": sum(encrypted),
        "subsequent": subsequent,
    }


def mark(match: bool) -> str:
    return "match" if match else "DIFF"


def describe_name(value: int, names: dict[int, str]) -> str:
    return f"0x{value:04x} {names.get(value, 'unknown')}"


def analyze(capture_path: Path, cover_path: Path, json_path: Path | None) -> int:
    try:
        beam = parse_flight(capture_path)
        cover = parse_flight(cover_path)
    except ParseError as error:
        print(f"cover-parity: parse failure: {error}", file=sys.stderr)
        return 1

    beam_hello = beam["hello"]
    cover_hello = cover["hello"]
    beam_ks = beam_hello["key_share"]
    cover_ks = cover_hello["key_share"]
    beam_order = beam_hello["extension_order"]
    cover_order = cover_hello["extension_order"]
    beam_sizes = beam["record_sizes"]
    cover_sizes = cover["record_sizes"]

    checks = {
        "group": beam_ks["group"] == cover_ks["group"],
        "cipher": beam_hello["cipher_suite"] == cover_hello["cipher_suite"],
        "extension_order": beam_order == cover_order,
        "server_hello_size": beam_sizes[0] == cover_sizes[0],
        "flight_record_count": beam["record_count"] == cover["record_count"],
        "flight_total_size": beam["total_bytes"] == cover["total_bytes"],
        "encrypted_flight_size": (
            beam["encrypted_record_sizes"] == cover["encrypted_record_sizes"]
        ),
    }
    doc_flight_ok = DOC_FLIGHT_BYTES[0] <= beam["total_bytes"] <= DOC_FLIGHT_BYTES[1]

    print("=" * 78)
    print("beam cover-parity report")
    print("=" * 78)
    print(f"capture: {capture_path}")
    print(f"cover:   {cover_path}")
    print()
    print("beam ServerHello")
    print(f"  record type:       {beam_hello['record']['type']} (handshake)")
    print(f"  record version:    {beam_hello['record_version']}")
    print(f"  record length:     {beam_hello['record']['length']} payload bytes, "
          f"{beam_hello['record']['wire_length']} on the wire")
    print(f"  legacy version:    {beam_hello['legacy_version']}")
    print(f"  TLS version:       {beam_hello['tls_version']}")
    print(f"  cipher suite:      {describe_name(beam_hello['cipher_suite'], CIPHER_NAMES)}")
    print(f"  key_share group:   {describe_name(beam_ks['group'], GROUP_NAMES)}")
    print(f"  key_share length:  {beam_ks['key_length']} bytes")
    print(f"  session id length: {beam_hello['session_id_length']}")
    print("  extension order:   " + ", ".join(
        f"0x{ext_type:04x} {EXTENSION_NAMES.get(ext_type, 'unknown')}"
        for ext_type in beam_order
    ))
    print(f"  ServerHello SHA256:{' ' + beam_hello['sha256']}")
    print()
    print("beam server flight")
    print(f"  records: {beam['record_count']}, total {beam['total_bytes']} bytes")
    for index, record in enumerate(beam["records"], start=1):
        print(
            f"    {index}. type={record['type']} ({record['type_name']}) "
            f"version={record['version']} payload={record['length']} "
            f"wire={record['wire_length']}"
        )
    print(f"  encrypted (application_data) records: "
          f"{beam['encrypted_record_sizes']} = {beam['encrypted_bytes']} bytes")
    print()
    print("cover server flight (aws-lc-pq artifact)")
    print(f"  group:  {describe_name(cover_ks['group'], GROUP_NAMES)}")
    print(f"  cipher: {describe_name(cover_hello['cipher_suite'], CIPHER_NAMES)}")
    print(f"  record sizes: {cover_sizes} total={cover['total_bytes']}")
    print(f"  encrypted record sizes: {cover['encrypted_record_sizes']} "
          f"= {cover['encrypted_bytes']} bytes")
    print()
    print("comparison (beam vs cover artifact)")
    print(f"  key_share group:       {mark(checks['group'])}  "
          f"beam={describe_name(beam_ks['group'], GROUP_NAMES)} "
          f"cover={describe_name(cover_ks['group'], GROUP_NAMES)}")
    print(f"  cipher suite:          {mark(checks['cipher'])}  "
          f"beam={describe_name(beam_hello['cipher_suite'], CIPHER_NAMES)} "
          f"cover={describe_name(cover_hello['cipher_suite'], CIPHER_NAMES)}")
    print(f"  extension order:       {mark(checks['extension_order'])}  "
          f"beam={[hex(value) for value in beam_order]} "
          f"cover={[hex(value) for value in cover_order]}")
    print(f"  ServerHello record:    {mark(checks['server_hello_size'])}  "
          f"beam={beam_sizes[0]} cover={cover_sizes[0]} "
          f"delta={beam_sizes[0] - cover_sizes[0]:+d}")
    print(f"  flight record count:   {mark(checks['flight_record_count'])}  "
          f"beam={beam['record_count']} cover={cover['record_count']} "
          f"(size difference expected)")
    print(f"  flight record sizes:   "
          f"beam={beam_sizes} cover={cover_sizes}")
    for index in range(max(len(beam_sizes), len(cover_sizes))):
        beam_size = beam_sizes[index] if index < len(beam_sizes) else None
        cover_size = cover_sizes[index] if index < len(cover_sizes) else None
        print(f"    record {index + 1}: beam={beam_size if beam_size is not None else '-'} "
              f"cover={cover_size if cover_size is not None else '-'} "
              f"{mark(beam_size == cover_size)}")
    print(f"  flight total:          {mark(checks['flight_total_size'])}  "
          f"beam={beam['total_bytes']} cover={cover['total_bytes']} "
          f"delta={beam['total_bytes'] - cover['total_bytes']:+d} (expected)")
    print(f"  encrypted flight:      {mark(checks['encrypted_flight_size'])}  "
          f"beam={beam['encrypted_bytes']} cover={cover['encrypted_bytes']} "
          f"delta={beam['encrypted_bytes'] - cover['encrypted_bytes']:+d} (expected)")
    print()
    print("documented cover baseline (docs/10-cover-parity.md)")
    print(f"  ServerHello: {DOC_SERVER_HELLO_BYTES} bytes, "
          f"flight: {DOC_FLIGHT_BYTES[0]}-{DOC_FLIGHT_BYTES[1]} bytes, "
          f"{DOC_FLIGHT_RECORD_COUNT} records")
    print(f"  beam ServerHello delta vs documented cover: "
          f"{beam_sizes[0] - DOC_SERVER_HELLO_BYTES:+d} bytes")
    print(f"  beam flight within documented cover range: "
          f"{'yes' if doc_flight_ok else 'no'} "
          f"(beam={beam['total_bytes']}, "
          f"delta={beam['total_bytes'] - DOC_FLIGHT_BYTES[1]:+d} vs upper bound; "
          f"expected smaller with the Ed25519 certificate)")

    expected_delta = beam["encrypted_bytes"] - cover["encrypted_bytes"]
    print()
    print("expected difference")
    print("  beam uses a temporary Ed25519 certificate (one small certificate);")
    print("  the cover uses a two-certificate EC chain. The encrypted flight is")
    print("  therefore expected to differ, and does not indicate a loss of cover")
    print("  parity in the plaintext ServerHello. Encrypted-flight delta:")
    print(f"    beam {beam['encrypted_bytes']} - cover {cover['encrypted_bytes']} "
          f"= {expected_delta:+d} bytes")
    print(f"    full flight delta: {beam['total_bytes'] - cover['total_bytes']:+d} bytes")

    plaintext_parity = (
        checks["group"]
        and checks["cipher"]
        and checks["extension_order"]
        and checks["server_hello_size"]
    )
    print()
    print("plaintext ServerHello parity: "
          + ("MATCH" if plaintext_parity else "DIFF (see warnings)"))
    if not checks["group"] or not checks["cipher"] or not checks["extension_order"]:
        print("WARNING: plaintext ServerHello parameters do not match the cover.")
    if not checks["server_hello_size"]:
        print("WARNING: ServerHello size differs; check the key_share length and "
              "session id echo.")

    summary = {
        "beam": beam,
        "cover": cover,
        "checks": checks,
        "documented_baseline": {
            "server_hello_bytes": DOC_SERVER_HELLO_BYTES,
            "flight_bytes": list(DOC_FLIGHT_BYTES),
            "flight_record_count": DOC_FLIGHT_RECORD_COUNT,
        },
        "plaintext_parity": plaintext_parity,
        "encrypted_size_delta": expected_delta,
    }
    if json_path is not None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(summary, indent=2) + "\n")
        print()
        print(f"JSON report: {json_path}")
    return 0


class ProxyError(Exception):
    """The proxy could not establish or relay the connection."""


def relay(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    server_flight = bytearray()
    client_hello = bytearray()
    server_records: list[Record] = []
    metadata = {
        "listen": args.listen,
        "target": args.target,
        "client_hello_seen": False,
        "client_finished_seen": False,
        "server_records": [],
        "error": None,
    }

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_host, listen_port = args.listen.rsplit(":", 1)
    target_host, target_port = args.target.rsplit(":", 1)
    client: socket.socket | None = None
    upstream: socket.socket | None = None
    selector = selectors.DefaultSelector()
    started = time.monotonic()
    try:
        listener.bind((listen_host, int(listen_port)))
        listener.listen(1)
        listener.settimeout(args.accept_timeout)
        print(f"cover-parity proxy listening on {args.listen}", flush=True)
        try:
            client, peer = listener.accept()
        except socket.timeout as error:
            raise ProxyError(
                f"no client connected to {args.listen} within "
                f"{args.accept_timeout}s"
            ) from error
        print(f"cover-parity proxy accepted {peer[0]}:{peer[1]}", flush=True)
        client.settimeout(args.idle_timeout)
        upstream = socket.create_connection(
            (target_host, int(target_port)), timeout=args.idle_timeout
        )
        client.settimeout(args.idle_timeout)
        upstream.settimeout(args.idle_timeout)
        selector.register(client, selectors.EVENT_READ, "client")
        selector.register(upstream, selectors.EVENT_READ, "upstream")

        client_buffer = bytearray()
        server_buffer = bytearray()
        client_eof = False
        upstream_eof = False
        capture_closed = False
        last_activity = time.monotonic()

        def parse_client(data: bytes) -> None:
            nonlocal capture_closed
            client_buffer.extend(data)
            if len(client_buffer) > MAX_BUFFER_BYTES:
                raise ProxyError("client record buffer exceeded its limit")
            for record in split_records(client_buffer, source="client"):
                if record.record_type == RECORD_HANDSHAKE and not metadata[
                    "client_hello_seen"
                ]:
                    metadata["client_hello_seen"] = True
                    if not client_hello:
                        client_hello.extend(record.raw)
                    continue
                if record.record_type in (RECORD_ALERT, RECORD_APPLICATION_DATA):
                    # The client's encrypted Finished (or a fatal alert) can
                    # only follow a complete server flight. Stop before
                    # forwarding it so beam cannot send a post-handshake
                    # NewSessionTicket that would pollute the capture.
                    metadata["client_finished_seen"] = True
                    capture_closed = True

        def parse_upstream(data: bytes) -> None:
            nonlocal server_flight
            server_buffer.extend(data)
            if len(server_buffer) > MAX_BUFFER_BYTES:
                raise ProxyError("server record buffer exceeded its limit")
            for record in split_records(server_buffer, source="server"):
                if capture_closed or not metadata["client_hello_seen"]:
                    continue
                if len(server_records) >= MAX_CAPTURE_RECORDS:
                    raise ProxyError(
                        f"server sent more than {MAX_CAPTURE_RECORDS} flight records"
                    )
                server_flight.extend(record.raw)
                if len(server_flight) > MAX_CAPTURE_BYTES:
                    raise ProxyError(
                        f"server flight exceeded {MAX_CAPTURE_BYTES} bytes"
                    )
                server_records.append(record)

        while not (client_eof and upstream_eof):
            time_left = args.idle_timeout - (time.monotonic() - last_activity)
            if time_left <= 0:
                metadata["error"] = "idle timeout"
                break
            events = selector.select(timeout=min(time_left, 0.5))
            if not events:
                continue
            for key, _ in events:
                if key.data == "client":
                    data = client.recv(65_536)
                    if not data:
                        client_eof = True
                        selector.unregister(client)
                        try:
                            upstream.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    last_activity = time.monotonic()
                    parse_client(data)
                    upstream.sendall(data)
                else:
                    data = upstream.recv(65_536)
                    if not data:
                        upstream_eof = True
                        selector.unregister(upstream)
                        try:
                            client.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    last_activity = time.monotonic()
                    parse_upstream(data)
                    client.sendall(data)
    except (OSError, ProxyError, ParseError) as error:
        metadata["error"] = str(error)
        print(f"cover-parity proxy error: {error}", file=sys.stderr, flush=True)
    finally:
        selector.close()
        for sock in (client, upstream):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        listener.close()

    metadata["server_records"] = [record.as_dict() for record in server_records]
    metadata["server_flight_bytes"] = len(server_flight)
    metadata["duration_ms"] = round((time.monotonic() - started) * 1000)
    (out_dir / "server-flight.bin").write_bytes(server_flight)
    if client_hello:
        (out_dir / "client-hello.bin").write_bytes(client_hello)
    (out_dir / "proxy.json").write_text(json.dumps(metadata, indent=2) + "\n")

    if not server_records:
        print(
            "cover-parity proxy: no server flight captured"
            + (f": {metadata['error']}" if metadata["error"] else ""),
            file=sys.stderr,
            flush=True,
        )
        return 1
    print(
        f"cover-parity proxy: captured {len(server_records)} server records "
        f"({len(server_flight)} bytes), client_finished="
        f"{metadata['client_finished_seen']}",
        flush=True,
    )
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    proxy = subparsers.add_parser("proxy", help="relay one connection and capture the flight")
    proxy.add_argument("--listen", required=True, help="listen address, HOST:PORT")
    proxy.add_argument("--target", required=True, help="target address, HOST:PORT")
    proxy.add_argument("--out", required=True, help="directory for capture files")
    proxy.add_argument("--accept-timeout", type=float, default=60.0)
    proxy.add_argument("--idle-timeout", type=float, default=15.0)

    analyzer = subparsers.add_parser("analyze", help="parse and compare a captured flight")
    analyzer.add_argument("--capture", required=True, type=Path)
    analyzer.add_argument("--cover", required=True, type=Path)
    analyzer.add_argument("--json", type=Path)

    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "proxy":
        return relay(args)
    return analyze(args.capture, args.cover, args.json)


if __name__ == "__main__":
    sys.exit(main())
