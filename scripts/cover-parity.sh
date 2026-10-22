#!/usr/bin/env bash
# Local cover-parity harness.
#
# Builds beam, runs it with the test REALITY key on 127.0.0.1:18443, puts a
# recording TCP proxy on 127.0.0.1:18444, and drives the stock Xray client
# through the proxy. The proxy captures the plaintext ServerHello and the full
# server flight; the analysis step compares those bytes with the recorded
# whatsapp.net cover flight.
#
# The harness is loopback-only. The REALITY cover destination is rewritten to
# a closed local port so an authentication failure can never open an external
# cover connection. The cover destination is not part of the authenticated
# ServerHello.
#
# Usage:
#   bash scripts/cover-parity.sh
#
# Environment overrides:
#   XRAY_BIN              stock Xray binary (default /tmp/opencode/xray-server-compare/xray)
#   CLIENT_TEMPLATE       no-flow REALITY client JSON (default /tmp/opencode/tls-server-harness/client-no-flow.json)
#   TEST_CONFIG           beam test config with the test key (default /tmp/opencode/beam-test/beam.toml)
#   COVER_ARTIFACT        cover server-flight capture (default /tmp/opencode/beam-spike-tls/cover-artifacts/rustls-aws-pq-serverflight.bin)
#   BEAM_PORT             beam listen port (default 18443)
#   PROXY_PORT            recording proxy port (default 18444)
#   SOCKS_PORT            Xray SOCKS inbound port (default 11080)
#   HTTP_PORT             local HTTP target port (default 18080)
#   CARGO_PROFILE         release or debug (default release)
#   SKIP_BUILD=1          reuse an existing target/<profile>/beam
#
# Exit status: non-zero on build/start/handshake/parse failure. Cover-flight
# size differences caused by the temporary Ed25519 certificate are reported
# but do not fail the run.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

XRAY_BIN="${XRAY_BIN:-/tmp/opencode/xray-server-compare/xray}"
CLIENT_TEMPLATE="${CLIENT_TEMPLATE:-/tmp/opencode/tls-server-harness/client-no-flow.json}"
TEST_CONFIG="${TEST_CONFIG:-/tmp/opencode/beam-test/beam.toml}"
COVER_ARTIFACT="${COVER_ARTIFACT:-/tmp/opencode/beam-spike-tls/cover-artifacts/rustls-aws-pq-serverflight.bin}"

BEAM_PORT="${BEAM_PORT:-18443}"
PROXY_PORT="${PROXY_PORT:-18444}"
SOCKS_PORT="${SOCKS_PORT:-11080}"
HTTP_PORT="${HTTP_PORT:-18080}"
CARGO_PROFILE="${CARGO_PROFILE:-release}"
SKIP_BUILD="${SKIP_BUILD:-0}"

WORK_ROOT="${COVER_PARITY_DIR:-/tmp/opencode}"
mkdir -p "$WORK_ROOT"
RUN_DIR="$(mktemp -d "$WORK_ROOT/beam-cover-parity.XXXXXX")"
CAPTURE_DIR="$RUN_DIR/capture"
mkdir -p "$CAPTURE_DIR" "$RUN_DIR/http"
printf 'beam cover-parity target\n' > "$RUN_DIR/http/index.txt"

BEAM_PID=""
PROXY_PID=""
XRAY_PID=""
HTTP_PID=""

cleanup() {
  local status=$?
  set +e
  for pid in "$XRAY_PID" "$PROXY_PID" "$BEAM_PID" "$HTTP_PID"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null
    fi
  done
  wait 2>/dev/null
  trap - EXIT INT TERM
  exit "$status"
}
trap cleanup EXIT INT TERM

fail() {
  echo "cover-parity: $*" >&2
  echo "cover-parity: run directory: $RUN_DIR" >&2
  for log in build.log beam.log proxy.log xray.log http.log; do
    if [ -s "$RUN_DIR/$log" ]; then
      echo "--- $RUN_DIR/$log" >&2
      tail -n 30 "$RUN_DIR/$log" >&2 || true
    fi
  done
  exit 1
}

require_file() {
  local path=$1
  local label=$2
  [ -f "$path" ] || fail "$label not found: $path"
}

echo "cover-parity: worktree $ROOT"
echo "cover-parity: run directory $RUN_DIR"

# Use the repository's portable toolchain settings when they are present.
# shellcheck source=dev-env.sh
source "$ROOT/scripts/dev-env.sh"

command -v "$PYTHON" >/dev/null 2>&1 || fail "python3 is required"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"
[ -x "$XRAY_BIN" ] || fail "stock Xray binary is not executable: $XRAY_BIN (set XRAY_BIN)"
require_file "$CLIENT_TEMPLATE" "no-flow Xray client config"
require_file "$TEST_CONFIG" "beam test config"
require_file "$COVER_ARTIFACT" "cover server-flight artifact"

if [ "$SKIP_BUILD" != "1" ]; then
  echo "cover-parity: building beam ($CARGO_PROFILE)"
  if [ "$CARGO_PROFILE" = "release" ]; then
    (cd "$ROOT" && cargo build --release --locked -p beam) > "$RUN_DIR/build.log" 2>&1 \
      || fail "cargo build failed"
    BEAM_BIN="$ROOT/target/release/beam"
  else
    (cd "$ROOT" && cargo build --locked -p beam) > "$RUN_DIR/build.log" 2>&1 \
      || fail "cargo build failed"
    BEAM_BIN="$ROOT/target/debug/beam"
  fi
else
  if [ "$CARGO_PROFILE" = "release" ]; then
    BEAM_BIN="$ROOT/target/release/beam"
  else
    BEAM_BIN="$ROOT/target/debug/beam"
  fi
fi
[ -x "$BEAM_BIN" ] || fail "beam binary not found: $BEAM_BIN"

# The test config supplies the throwaway key, UUID, short id, and SNI. Only
# the listen address and cover destination are rewritten. The destination is a
# closed loopback port: the authenticated path never dials it, and a failed
# authentication gets an immediate local failure instead of reaching the
# internet.
sed \
  -e "s|^listen = .*|listen = \"127.0.0.1:${BEAM_PORT}\"|" \
  -e "s|^dest = .*|dest = \"127.0.0.1:9\"|" \
  -e "s|^handshake_timeout_ms = .*|handshake_timeout_ms = 15000|" \
  "$TEST_CONFIG" > "$RUN_DIR/beam.toml"

"$PYTHON" - "$CLIENT_TEMPLATE" "$RUN_DIR/client.json" "$PROXY_PORT" "$SOCKS_PORT" <<'PY'
import json
import sys

source, destination, proxy_port, socks_port = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    config = json.load(handle)
config["inbounds"][0]["port"] = int(socks_port)
config["outbounds"][0]["settings"]["vnext"][0]["port"] = int(proxy_port)
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY

echo "cover-parity: starting local HTTP target on 127.0.0.1:$HTTP_PORT"
"$PYTHON" -m http.server "$HTTP_PORT" --bind 127.0.0.1 \
  --directory "$RUN_DIR/http" > "$RUN_DIR/http.log" 2>&1 &
HTTP_PID=$!

echo "cover-parity: starting beam on 127.0.0.1:$BEAM_PORT"
"$BEAM_BIN" --config "$RUN_DIR/beam.toml" > "$RUN_DIR/beam.log" 2>&1 &
BEAM_PID=$!

beam_ready=0
for _ in $(seq 1 100); do
  if grep -q "beam listening" "$RUN_DIR/beam.log"; then
    beam_ready=1
    break
  fi
  if ! kill -0 "$BEAM_PID" 2>/dev/null; then
    wait "$BEAM_PID" 2>/dev/null || true
    BEAM_PID=""
    fail "beam exited before it started listening"
  fi
  sleep 0.1
done
[ "$beam_ready" = "1" ] || fail "beam did not start listening"

echo "cover-parity: starting recording proxy 127.0.0.1:$PROXY_PORT -> 127.0.0.1:$BEAM_PORT"
"$PYTHON" "$ROOT/scripts/cover-parity.py" proxy \
  --listen "127.0.0.1:$PROXY_PORT" \
  --target "127.0.0.1:$BEAM_PORT" \
  --out "$CAPTURE_DIR" \
  --accept-timeout 30 \
  --idle-timeout 15 > "$RUN_DIR/proxy.log" 2>&1 &
PROXY_PID=$!

proxy_ready=0
for _ in $(seq 1 100); do
  if grep -q "proxy listening" "$RUN_DIR/proxy.log"; then
    proxy_ready=1
    break
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    wait "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
    fail "recording proxy exited before it started listening"
  fi
  sleep 0.1
done
[ "$proxy_ready" = "1" ] || fail "recording proxy did not start listening"

"$XRAY_BIN" version > "$RUN_DIR/xray-version.txt" 2>&1 || true
if [ -s "$RUN_DIR/xray-version.txt" ]; then
  echo "cover-parity: client $(head -n 1 "$RUN_DIR/xray-version.txt")"
fi
echo "cover-parity: starting stock Xray client"
"$XRAY_BIN" run -c "$RUN_DIR/client.json" > "$RUN_DIR/xray.log" 2>&1 &
XRAY_PID=$!

socks_ready=0
for _ in $(seq 1 100); do
  if ! kill -0 "$XRAY_PID" 2>/dev/null; then
    wait "$XRAY_PID" 2>/dev/null || true
    XRAY_PID=""
    fail "Xray exited before the SOCKS inbound was ready"
  fi
  if "$PYTHON" - "$SOCKS_PORT" <<'PY' >/dev/null 2>&1
import socket
import sys

sock = socket.socket()
sock.settimeout(0.2)
try:
    sock.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
  then
    socks_ready=1
    break
  fi
  sleep 0.1
done
[ "$socks_ready" = "1" ] || fail "Xray SOCKS inbound did not become ready"

echo "cover-parity: requesting http://127.0.0.1:$HTTP_PORT/index.txt through Xray"
HTTP_EXIT=0
curl --silent --show-error --max-time 20 --noproxy "" \
  --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
  "http://127.0.0.1:$HTTP_PORT/index.txt" \
  > "$RUN_DIR/curl.out" 2> "$RUN_DIR/curl.err" || HTTP_EXIT=$?

# Stop the clients; the proxy then sees EOF and flushes its capture.
if [ -n "$XRAY_PID" ]; then
  kill "$XRAY_PID" 2>/dev/null || true
  wait "$XRAY_PID" 2>/dev/null || true
  XRAY_PID=""
fi
for _ in $(seq 1 100); do
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if kill -0 "$PROXY_PID" 2>/dev/null; then
  kill "$PROXY_PID" 2>/dev/null || true
fi
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""

if [ -n "$BEAM_PID" ]; then
  kill "$BEAM_PID" 2>/dev/null || true
  wait "$BEAM_PID" 2>/dev/null || true
  BEAM_PID=""
fi
if [ -n "$HTTP_PID" ]; then
  kill "$HTTP_PID" 2>/dev/null || true
  wait "$HTTP_PID" 2>/dev/null || true
  HTTP_PID=""
fi

ANALYZE_RC=0
"$PYTHON" "$ROOT/scripts/cover-parity.py" analyze \
  --capture "$CAPTURE_DIR/server-flight.bin" \
  --cover "$COVER_ARTIFACT" \
  --json "$RUN_DIR/report.json" > "$RUN_DIR/report.txt" 2> "$RUN_DIR/analyze.err" \
  || ANALYZE_RC=$?
cat "$RUN_DIR/report.txt"
if [ -s "$RUN_DIR/analyze.err" ]; then
  cat "$RUN_DIR/analyze.err" >&2
fi

if [ "$ANALYZE_RC" -ne 0 ]; then
  fail "ServerHello parse failed (see $RUN_DIR/analyze.err)"
fi

FINISHED="$("$PYTHON" - "$CAPTURE_DIR/proxy.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    metadata = json.load(handle)
print("yes" if metadata.get("client_finished_seen") else "no")
PY
)"
if [ "$FINISHED" != "yes" ]; then
  fail "client Finished was not observed; the TLS handshake did not complete"
fi

if [ "$HTTP_EXIT" -ne 0 ]; then
  echo "cover-parity: curl failed with exit $HTTP_EXIT" >&2
  cat "$RUN_DIR/curl.err" >&2 || true
  fail "the Xray client connection failed"
fi
if ! grep -q "beam cover-parity target" "$RUN_DIR/curl.out"; then
  fail "unexpected HTTP response through Xray"
fi

echo
echo "cover-parity: PASS (capture and parse succeeded; parity differences above are"
echo "  reported, not fatal)"
echo "  ServerHello and full flight captured; see $RUN_DIR/report.txt"
echo "  raw capture: $CAPTURE_DIR/server-flight.bin"
echo "  JSON report: $RUN_DIR/report.json"
echo "  logs: $RUN_DIR/{beam,proxy,xray,http}.log"
exit 0
