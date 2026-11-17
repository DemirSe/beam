#!/usr/bin/env python3
"""Liveness check for beam.

A TCP connect is not enough: the kernel completes it from the listen backlog
even when the process is stuck. This probe finishes a TLS handshake on the
listener the service uses, so it proves that the process reads, writes, and
reaches the cover.

Every 5 minutes the timer runs this file. After three failures in a row, that
is 15 minutes without a working handshake, the script restarts the service.
A success resets the counter.

The probe is unauthenticated, so beam relays it to the cover. A reset, an early
EOF, or a TLS error after the probe connected means that beam accepted the
probe and handled it, so the process is scheduling work. That is not the hung
process this restart exists for, so the case is logged as SKIP and does not
count toward a restart; restarting a live process would only drop live
sessions. It does not prove that the cover is healthy, only that beam is not
stuck.

The address and cover name come from the config that the service runs. A fixed
address would point a general install at a port that it does not use, and the
refused connection would then restart a healthy beam every 15 minutes. Without
a usable target the probe reports a failure and never restarts, because an
unproven fault must not cost live sessions.
"""
import socket
import ssl
import subprocess
import sys
import tomllib

COUNTER = "/run/beam-liveness.failures"
LIMIT = 3
# The unit this probe watches starts beam with this file, so it is the only
# source of the probe address and the cover name.
CONFIG = "/etc/beam/config.toml"

# beam bounds every cover step: 5 s for the pre-auth ClientHello read, 5 s for
# the cover dial, 5 s for the cover write, then 30 s of cover relay idle. A
# probe deadline above that sum keeps a timeout meaning "beam itself did not
# answer", which is the only failure that justifies a restart.
COVER_BOUND_SECONDS = 45
TIMEOUT = 60


def split_listen(listen: str) -> tuple[str, int]:
    """Return the probe host and port for a config `listen` value.

    A wildcard bind address is not a dialable peer, so it becomes the loopback
    address of the same family.
    """
    host, colon, port = listen.rpartition(":")
    if not colon:
        raise ValueError(f"no port in listen {listen!r}")
    port = int(port)
    if not 0 < port < 65536:
        raise ValueError(f"port out of range in listen {listen!r}")
    host = host.strip("[]")
    if host in ("", "0.0.0.0"):
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    return host, port


def probe_target() -> tuple[str, int, str] | None:
    """Return the listen address and cover name of the installed beam.

    Only the config that the service runs is authoritative: any other value
    could point the probe at a port that this host does not serve, and the
    probe would then restart a healthy beam.
    """
    try:
        with open(CONFIG, "rb") as handle:
            config = tomllib.load(handle)
        host, port = split_listen(config["server"]["listen"])
        sni = config["reality"]["server_names"][0]
        if not isinstance(sni, str) or not sni:
            raise ValueError("empty reality.server_names[0]")
        return host, port, sni
    except (OSError, KeyError, IndexError, TypeError, ValueError) as exc:
        print(
            f"liveness: FAIL no usable probe target in {CONFIG} "
            f"({type(exc).__name__}: {exc}); beam is not restarted",
            flush=True,
        )
        return None


def probe(host: str, port: int, sni: str) -> str:
    """Finish one TLS handshake through beam, which relays it to the cover."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            return tls.version() or "unknown"


def is_cover_fault(exc: BaseException) -> bool:
    """True when beam accepted the probe and then closed it.

    beam drops a probe whose cover dial, write, or relay fails, one that hits
    the cover slot limit, and one that is still open at shutdown, so these
    cases arrive as a reset, a broken pipe, or a TLS error. The error names the
    cover path, not a proven cover fault: a code path inside beam can close the
    probe too. What it does show is that the process accepted and handled the
    connection, which a stuck process cannot. A refused, timed-out, or
    otherwise unanswered connection points at beam itself; it is not listed
    here, so an unexpected error still counts as a local failure.
    """
    return isinstance(
        exc,
        (
            ssl.SSLError,
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
        ),
    )


def read_count() -> int:
    try:
        with open(COUNTER) as handle:
            return int(handle.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def write_count(value: int) -> None:
    try:
        with open(COUNTER, "w") as handle:
            handle.write(str(value))
    except OSError as exc:
        print(
            f"liveness: cannot write {COUNTER} ({exc}); the restart count is lost",
            file=sys.stderr,
            flush=True,
        )


def restart() -> tuple[bool, str]:
    """Restart beam and report only what the restart actually proved."""
    try:
        result = subprocess.run(["systemctl", "restart", "beam"], check=False)
    except OSError as exc:
        return False, f"systemctl restart could not run ({exc})"
    if result.returncode != 0:
        return False, f"systemctl restart exited {result.returncode}"
    state = subprocess.run(
        ["systemctl", "is-active", "beam"],
        capture_output=True,
        text=True,
        check=False,
    )
    active = (state.stdout or "").strip()
    if active != "active":
        return False, f"beam is {active or 'unknown'} after the restart"
    return True, "active after the restart"


def main() -> int:
    target = probe_target()
    if target is None:
        # No target means no evidence that beam is down. A restart on that
        # guess would drop live sessions, so report the broken probe instead.
        return 1
    try:
        version = probe(*target)
    except Exception as exc:  # noqa: BLE001 - any failure means "no handshake"
        if is_cover_fault(exc):
            write_count(0)
            print(
                f"liveness: SKIP cover path failed ({type(exc).__name__}); "
                "beam answered, so it is not restarted",
                flush=True,
            )
            return 0
        count = min(read_count() + 1, LIMIT)
        write_count(count)
        print(f"liveness: FAIL {count}/{LIMIT} ({type(exc).__name__})", flush=True)
        if count >= LIMIT:
            ok, detail = restart()
            if ok:
                write_count(0)
                print(f"liveness: restarted beam; {detail}", flush=True)
                return 0
            # Keep the count at LIMIT so the next run retries instead of
            # waiting for three more failures.
            print(
                f"liveness: restart FAILED ({detail}); beam is still not "
                "answering",
                flush=True,
            )
            return 1
        return 0

    write_count(0)
    print(f"liveness: OK {version}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
