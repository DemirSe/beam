#!/usr/bin/env bash
# Local full-TUN interoperability harness for beam.
#
# Topology (all inside one private user + mount + network namespace):
#
#   client ns                         server ns                     target ns
#   10.10.1.2/24 -- vc | sc -- 10.10.1.1
#                                     10.10.2.1/24 -- vs | ts -- 10.10.2.2/24
#                                     fd00:2::1/64                 fd00:2::2/64
#   sing-box TUN 198.18.0.1/15 + fd00:1::1/64
#   routes 10.10.2.0/24 and fd00:2::/64 to tun0
#
# The real sing-box v1.14.3 client uses a VLESS+REALITY+Vision outbound with
# packet_encoding=xudp and utls=chrome. Probes cover TCP, UDP, DNS, QUIC and
# IPv6. Known unimplemented server paths are reported as BLOCKED with the
# exact beam log line; they do not make the run fail.
#
# The QUIC probe uses a real local HTTP/3 origin from tests/tun/h3-origin,
# built outside the beam workspace before the network namespace is entered.
#
# Usage:
#   bash tests/tun/run.sh [--release] [--control] [--no-build] [--out DIR]
#                         [--suite tun|protocols]
#   sudo TUN_ALLOW_ROOT=1 bash tests/tun/run.sh --release --no-build ...
#
# Environment:
#   SING_BOX        sing-box binary (default: sing-box from PATH)
#   XRAY_BIN        stock Xray binary (default: xray from PATH)
#   TEST_CONFIG     beam REALITY fixture (default: config.example.toml)
#   TUN_OUT         run directory (default: ~/.cache/beam/tun/<timestamp>)
#   SKIP_BUILD=1    reuse target/<profile>/beam and the H3 origin binary
#   H3_ORIGIN_BIN   use a prebuilt h3-origin binary instead of building it
#   UDP_MODE        sing-box packet_encoding: xudp, packetaddr, or legacy
#                   (default xudp; legacy renders packet_encoding "")
#   TUN_RTT_MS      round-trip delay to apply to the client/server veth with
#                   netem, split evenly across both sides (default 0)
#   TUN_LOSS_PCT    packet loss percent to apply on both veth sides (default 0)
#   TUN_MTU         sing-box TUN MTU recorded in the environment (default 1500)
#   ALLOW_TUN_BLOCKED=1
#                   accept a run whose matrix contains BLOCKED rows; without it
#                   a blocked matrix exits 2
#   TUN_ALLOW_ROOT=1
#                   as real host root, run the suite inside a private
#                   mount+network namespace instead of an unprivileged user
#                   namespace. Implies SKIP_BUILD=1: crates.io is unreachable
#                   inside the private network namespace, so binaries must be
#                   prebuilt. This is the GitHub-hosted runner path.
#
# --suite tun runs the eight functional probes. --suite protocols runs the
# real-protocol campaign (HTTP/1.1, HTTP/2, HTTP/3, UDP, DNS, TCP, mixed load,
# idle and restart) through the same sing-box -> beam path and writes a
# validated report per arm. The protocol suite also applies netem when
# TUN_RTT_MS or TUN_LOSS_PCT is non-zero and records the qdisc evidence.
#
# This is a local lab harness. It never reaches an external network in the
# measured path; only the one-time dependency/build step runs outside it.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/run.sh"
INNER="${TUN_HARNESS_INNER:-0}"

if [ "$INNER" != "1" ]; then
  if ! command -v unshare >/dev/null 2>&1; then
    echo "tun-harness: unshare is required" >&2
    exit 1
  fi
  if [ "${TUN_ALLOW_ROOT:-0}" = "1" ]; then
    [ "$(id -u)" -eq 0 ] \
      || { echo "tun-harness: TUN_ALLOW_ROOT needs root" >&2; exit 1; }
    grep -qE '^[[:space:]]*0[[:space:]]+0[[:space:]]+4294967295' /proc/self/uid_map \
      || { echo "tun-harness: TUN_ALLOW_ROOT needs real host root, not a mapped user namespace" >&2; exit 1; }
    # crates.io is unreachable inside the private netns and this guard runs
    # before the argument parser, so the root path always uses prebuilt binaries.
    export SKIP_BUILD=1
  elif ! unshare --user --map-root-user --net true 2>/dev/null; then
    echo "tun-harness: unprivileged user+network namespaces are unavailable" >&2
    exit 1
  fi

  # The H3 helper is a separate workspace. Build it before entering the
  # private network namespace, where crates.io is unreachable. A build failure
  # is reported later as a quic-udp BLOCKED row, not as a fake pass.
  H3_BUILD=1
  for argument in "$@"; do
    case "$argument" in
      --no-build|--help|-h) H3_BUILD=0 ;;
    esac
  done
  [ "${SKIP_BUILD:-0}" = "1" ] && H3_BUILD=0
  H3_BIN_OVERRIDE="${H3_ORIGIN_BIN:-}"
  H3_ORIGIN_BIN=""
  H3_BUILD_LOG=""
  H3_BUILD_ERROR=""
  if [ -n "$H3_BIN_OVERRIDE" ]; then
    H3_ORIGIN_BIN="$H3_BIN_OVERRIDE"
  elif [ "$H3_BUILD" = "1" ]; then
    H3_BUILD_LOG="$(mktemp "${TMPDIR:-/tmp}/beam-h3-origin-build.XXXXXX.log")"
    # shellcheck source=../../scripts/dev-env.sh
    source "$ROOT/scripts/dev-env.sh"
    if cargo build --locked --manifest-path "$HERE/h3-origin/Cargo.toml" \
        > "$H3_BUILD_LOG" 2>&1; then
      H3_ORIGIN_BIN="$HERE/h3-origin/target/debug/h3-origin"
    else
      H3_BUILD_ERROR="cargo build for tests/tun/h3-origin failed: $(tail -n 1 "$H3_BUILD_LOG" | tr '\t\n' '  ')"
    fi
  else
    H3_ORIGIN_BIN="$HERE/h3-origin/target/debug/h3-origin"
    if [ ! -x "$H3_ORIGIN_BIN" ]; then
      H3_BUILD_ERROR="H3 origin was not built (--no-build/SKIP_BUILD=1) and $H3_ORIGIN_BIN is missing"
    fi
  fi

  H2_CLIENT_BIN="${H2_CLIENT_BIN:-$(dirname "$H3_ORIGIN_BIN")/h2-client}"
  if [ "${TUN_ALLOW_ROOT:-0}" = "1" ]; then
    exec unshare --mount --propagation private --net --fork \
      env TUN_HARNESS_INNER=1 TUN_HARNESS_ROOT="$ROOT" TUN_HARNESS_SELF="$SELF" \
      TUN_H3_BIN="$H3_ORIGIN_BIN" TUN_H3_BUILD_ERROR="$H3_BUILD_ERROR" \
      TUN_H3_BUILD_LOG="$H3_BUILD_LOG" TUN_H2_CLIENT_BIN="$H2_CLIENT_BIN" \
      bash "$SELF" "$@"
  fi
  exec unshare --user --map-root-user --mount --net --fork \
    env TUN_HARNESS_INNER=1 TUN_HARNESS_ROOT="$ROOT" TUN_HARNESS_SELF="$SELF" \
    TUN_H3_BIN="$H3_ORIGIN_BIN" TUN_H3_BUILD_ERROR="$H3_BUILD_ERROR" \
    TUN_H3_BUILD_LOG="$H3_BUILD_LOG" TUN_H2_CLIENT_BIN="$H2_CLIENT_BIN" \
    bash "$SELF" "$@"
fi

ROOT="${TUN_HARNESS_ROOT:-$ROOT}"
SELF="${TUN_HARNESS_SELF:-$SELF}"
# shellcheck source=../../scripts/dev-env.sh
source "$ROOT/scripts/dev-env.sh"

PYTHON="${PYTHON:-python3}"
SING_BOX="${SING_BOX:-sing-box}"
XRAY_BIN="${XRAY_BIN:-xray}"
TEST_CONFIG="${TEST_CONFIG:-$ROOT/config.example.toml}"
SKIP_BUILD="${SKIP_BUILD:-0}"
UDP_MODE="${UDP_MODE:-xudp}"
PROFILE="debug"
CONTROL=0
SUITE="tun"
OUT="${TUN_OUT:-}"
TUN_RTT_MS="${TUN_RTT_MS:-0}"
TUN_LOSS_PCT="${TUN_LOSS_PCT:-0}"
TUN_MTU="${TUN_MTU:-1500}"
TUN_LOG_LEVEL="${TUN_LOG_LEVEL:-debug}"
TC="${TC:-tc}"
BEAM_ADDR="10.10.1.1:443"
CLIENT_ADDR="10.10.1.2/24"
SERVER_ADDR="10.10.1.1/24"
TARGET_ADDR="10.10.2.2/24"
SERVER_TARGET_ADDR="10.10.2.1/24"
TARGET_V6="fd00:2::2/64"
SERVER_TARGET_V6="fd00:2::1/64"
COVER="10.10.2.2:4443"
H3_ORIGIN_BIN="${H3_ORIGIN_BIN:-${TUN_H3_BIN:-$HERE/h3-origin/target/debug/h3-origin}}"
H2_CLIENT_BIN="${H2_CLIENT_BIN:-${TUN_H2_CLIENT_BIN:-$(dirname "$H3_ORIGIN_BIN")/h2-client}}"
H3_ORIGIN_ERROR="${TUN_H3_BUILD_ERROR:-}"
H3_BUILD_LOG="${TUN_H3_BUILD_LOG:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --release) PROFILE="release" ;;
    --control) CONTROL=1 ;;
    --no-build) SKIP_BUILD=1 ;;
    --out)
      shift
      [ $# -gt 0 ] || { echo "tun-harness: --out needs a directory" >&2; exit 2; }
      OUT="$1"
      ;;
    --udp-mode)
      shift
      [ $# -gt 0 ] || { echo "tun-harness: --udp-mode needs a value" >&2; exit 2; }
      UDP_MODE="$1"
      ;;
    --suite)
      shift
      [ $# -gt 0 ] || { echo "tun-harness: --suite needs a value" >&2; exit 2; }
      SUITE="$1"
      ;;
    --help|-h)
      sed -n '2,60p' "$SELF" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "tun-harness: unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

case "$UDP_MODE" in
  xudp|packetaddr|legacy) ;;
  *) echo "tun-harness: unknown UDP mode: $UDP_MODE" >&2; exit 2 ;;
esac
case "$SUITE" in
  tun|protocols) ;;
  *) echo "tun-harness: unknown suite: $SUITE" >&2; exit 2 ;;
esac
case "$TUN_RTT_MS" in
  ''|*[!0-9.]*) echo "tun-harness: TUN_RTT_MS must be numeric" >&2; exit 2 ;;
esac
case "$TUN_LOSS_PCT" in
  ''|*[!0-9.]*) echo "tun-harness: TUN_LOSS_PCT must be numeric" >&2; exit 2 ;;
esac

if [ ! -f "$TEST_CONFIG" ]; then
  echo "tun-harness: test config not found: $TEST_CONFIG" >&2
  exit 1
fi
if [ ! -x "$SING_BOX" ]; then
  resolved="$(command -v sing-box || true)"
  if [ -n "$resolved" ]; then
    SING_BOX="$resolved"
  else
    echo "tun-harness: sing-box not found (set SING_BOX)" >&2
    exit 1
  fi
fi
for command in "$PYTHON" ip curl dig tc ping; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "tun-harness: required command not found: $command" >&2
    exit 1
  fi
done
if [ "${SKIP_BUILD:-0}" != "1" ] && ! command -v cargo >/dev/null 2>&1; then
  echo "tun-harness: required command not found: cargo" >&2
  exit 1
fi
if [ "$CONTROL" = "1" ]; then
  if [ -x "$XRAY_BIN" ]; then
    :
  elif command -v "$XRAY_BIN" >/dev/null 2>&1; then
    XRAY_BIN="$(command -v "$XRAY_BIN")"
  else
    echo "tun-harness: --control requested but Xray was not found: $XRAY_BIN" >&2
    exit 1
  fi
fi
CURL_HTTP3=0
if curl --version 2>/dev/null | grep -qi 'HTTP3'; then
  CURL_HTTP3=1
fi

umask 077
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -n "$OUT" ]; then
  RUN_DIR="$OUT"
else
  RUN_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/beam/tun/$STAMP-$$"
fi
mkdir -p "$RUN_DIR/logs" "$RUN_DIR/probes" "$RUN_DIR/config"
chmod 700 "$RUN_DIR"
RUN_DIR="$(cd "$RUN_DIR" && pwd)"
LOG_DIR="$RUN_DIR/logs"
CONFIG_DIR="$RUN_DIR/config"
PROBE_DIR="$RUN_DIR/probes"
BEAM_LOG="$LOG_DIR/beam.log"
SINGBOX_LOG="$LOG_DIR/singbox.log"
TARGET_LOG="$LOG_DIR/target.log"
H3_LOG="$LOG_DIR/h3-origin.log"
XRAY_LOG="$LOG_DIR/xray.log"
BEAM_TSV="$RUN_DIR/results-beam.tsv"
XRAY_TSV="$RUN_DIR/results-xray.tsv"
PROTO_DIR="$PROBE_DIR/protocol"
PROTO_BEAM_TSV="$RUN_DIR/protocol-results-beam.tsv"
PROTO_XRAY_TSV="$RUN_DIR/protocol-results-xray.tsv"
PROTO_BEAM_REPORT="$RUN_DIR/protocol-report-beam.json"
PROTO_XRAY_REPORT="$RUN_DIR/protocol-report-xray.json"
PROTO_HARNESS_OK=1
RESTART_KILLED_MS=""
: > "$BEAM_LOG"
: > "$XRAY_LOG"
: > "$BEAM_TSV"
: > "$XRAY_TSV"
: > "$PROTO_BEAM_TSV"
: > "$PROTO_XRAY_TSV"
if [ -n "$H3_BUILD_LOG" ] && [ -f "$H3_BUILD_LOG" ]; then
  cp "$H3_BUILD_LOG" "$LOG_DIR/h3-origin-build.log" 2>/dev/null || true
fi

BEAM_PID=""
SINGBOX_PID=""
SERVICES_PID=""
H3_ORIGIN_PID=""
H3_READY=0
XRAY_PID=""
# The active server under test: the protocol suite restarts it, so the harness
# tracks whichever arm (beam or stock Xray) owns the listening process.
SERVER_PID=""
SERVER_LOG=""
SERVER_KIND=""
# Explicit server lifecycle: none -> starting -> running -> restarting ->
# starting -> running, with stopping/stopped on teardown and failed on a start
# error. SERVER_PID/SERVER_LOG/SERVER_KIND are only meaningful while starting,
# running, restarting or failed.
SERVER_STATE=none
BASELINE_RTT_MS=0
BASELINE_TARGET_RTT_MS=0
NAMESPACES=(tun-client tun-server tun-target)
# Cleanup must only remove namespaces this run created: the trap is installed
# before /run/netns is shadowed, so an early failure may still see whatever
# the host already had under those names.
CREATED_NAMESPACES=()
UNEXPECTED_FAIL=0
HARNESS_FAIL=0
TUN_BLOCKED=0
TUN_BLOCK_REASON=""

log() { printf 'tun-harness: %s\n' "$*"; }
fail_harness() {
  HARNESS_FAIL=1
  printf 'tun-harness: HARNESS FAILURE: %s\n' "$*" >&2
}

stop_pid() {
  local pid="${1:-}"
  [ -n "$pid" ] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 30); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      return 0
    fi
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  stop_pid "$SINGBOX_PID"
  server_stop
  stop_pid "$H3_ORIGIN_PID"
  stop_pid "$SERVICES_PID"
  for namespace in "${CREATED_NAMESPACES[@]}"; do
    ip netns del "$namespace" >/dev/null 2>&1
  done
  printf 'tun-harness: run directory: %s\n' "$RUN_DIR" >&2
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

has_marker() {
  local file=$1 start=$2 marker=$3
  [ -f "$file" ] || return 1
  tail -c "+$((start + 1))" "$file" 2>/dev/null | grep -qF -- "$marker"
}

marker_line() {
  local file=$1 start=$2 marker=$3
  [ -f "$file" ] || return 0
  tail -c "+$((start + 1))" "$file" 2>/dev/null \
    | grep -m1 -F -- "$marker" \
    | sed -e 's/\x1b\[[0-9;]*m//g' \
    | tr '\t\r\n' '   ' \
    | cut -c1-240 || true
}

json_field() {
  "$PYTHON" - "$1" "$2" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        value = json.load(handle).get(sys.argv[2], "")
except Exception:
    value = ""
print(value)
PY
}

record() {
  local file=$1 name=$2 status=$3 detail=$4
  detail="${detail//$'\t'/ }"
  detail="${detail//$'\n'/ }"
  printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >> "$file"
  printf '  %-18s %-8s %s\n' "$name" "$status" "$detail"
  if [ "$status" = "BLOCKED" ]; then
    TUN_BLOCKED=1
  fi
}

wait_for_log() {
  local file=$1 pattern=$2 pid=${3:-} timeout=${4:-10}
  local steps=$((timeout * 10))
  for _ in $(seq 1 "$steps"); do
    if grep -qF -- "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

wait_for_command() {
  local pid=$1 timeout=$2
  shift 2
  local steps=$((timeout * 10))
  for _ in $(seq 1 "$steps"); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

wait_for_marker_after() {
  local file=$1 mark=$2 marker=$3 pid=${4:-} timeout=${5:-15}
  local steps=$((timeout * 10))
  for _ in $(seq 1 "$steps"); do
    if has_marker "$file" "$mark" "$marker"; then
      return 0
    fi
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

# The harness must prove the requested impairment is on the wire; qdisc
# evidence is captured as JSON and validated with tight tolerances.
verify_netem() {
  local role=$1 path=$2 rc=0
  "$PYTHON" - "$role" "$path" "$TUN_RTT_MS" "$TUN_LOSS_PCT" <<'VERIFY' || rc=$?
import json
import sys

role, path, rtt, loss = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    qdisc = data[0] if isinstance(data, list) else data
    options = qdisc["options"]
except (OSError, ValueError, KeyError, IndexError) as error:
    raise SystemExit(f"could not read qdisc evidence {path}: {error}")
if rtt > 0:
    delay = options.get("delay", {}).get("delay")
    if delay is None:
        raise SystemExit(f"{role}: netem has no delay")
    want = rtt / 2
    if abs(delay * 1000 - want) > 0.5:
        raise SystemExit(
            f"{role}: netem delay {delay * 1000:.3f}ms, wanted {want:.3f}ms"
        )
if loss > 0:
    rate = options.get("loss-random", {}).get("loss")
    if rate is None:
        raise SystemExit(f"{role}: netem has no loss")
    if abs(rate * 100 - loss) > 0.05:
        raise SystemExit(f"{role}: netem loss {rate * 100:.3f}%, wanted {loss:.3f}%")
VERIFY
  [ "$rc" = "0" ] \
    || fail_harness "netem did not apply the requested impairment on the $role side"
}

apply_netem() {
  local netem_args=(limit 20000)
  local half
  if awk -v rtt="$TUN_RTT_MS" 'BEGIN { exit !(rtt > 0) }'; then
    half="$(awk -v rtt="$TUN_RTT_MS" 'BEGIN { printf "%.3f", rtt / 2 }')"
    netem_args+=(delay "${half}ms")
  fi
  if awk -v loss="$TUN_LOSS_PCT" 'BEGIN { exit !(loss > 0) }'; then
    netem_args+=(loss "${TUN_LOSS_PCT}%")
  fi
  log "applying netem on each side: ${netem_args[*]} (RTT ${TUN_RTT_MS}ms, loss ${TUN_LOSS_PCT}%)"
  ip netns exec tun-client "$TC" qdisc add dev vc root netem "${netem_args[@]}" \
    || { fail_harness "could not add netem on vc"; return 1; }
  ip netns exec tun-server "$TC" qdisc add dev sc root netem "${netem_args[@]}" \
    || { fail_harness "could not add netem on sc"; return 1; }
  ip netns exec tun-client "$TC" -j -s qdisc show dev vc \
    > "$LOG_DIR/tc-client-initial.json" \
    || { fail_harness "could not capture the client qdisc state"; return 1; }
  ip netns exec tun-server "$TC" -j -s qdisc show dev sc \
    > "$LOG_DIR/tc-server-initial.json" \
    || { fail_harness "could not capture the server qdisc state"; return 1; }
  ip netns exec tun-client "$TC" -s qdisc show > "$LOG_DIR/tc-client.txt" 2>&1
  ip netns exec tun-server "$TC" -s qdisc show > "$LOG_DIR/tc-server.txt" 2>&1
  verify_netem client "$LOG_DIR/tc-client-initial.json"
  verify_netem server "$LOG_DIR/tc-server-initial.json"
}

# Average RTT of five pings, rounded to whole milliseconds. The one-packet
# warmup resolves the neighbour entry, whose own round trip would otherwise be
# charged to the first measured packet (300 ms instead of 250 ms at a 250 ms
# RTT). A 0.3 s interval keeps the previous reply out of the netem queue: at
# the 1 s default the reported average is inflated by one RTT of queueing.
measure_baseline_rtt() {
  local target=$1 namespace=$2
  local line value
  ip netns exec "$namespace" ping -c 1 -W 1 "$target" >/dev/null 2>&1 || true
  line="$(ip netns exec "$namespace" ping -c 5 -i 0.3 -W 1 "$target" 2>/dev/null | tail -n 1 || true)"
  value="$(printf '%s' "$line" | awk -F'/' '/rtt|round-trip/ { printf "%.0f", $5 }')"
  printf '%s\n' "${value:-0}"
}

# ---------------------------------------------------------------------------
# Server lifecycle
#
# One active server owns SERVER_PID/SERVER_LOG/SERVER_KIND. Transitions are
# validated, and the restart is invoked directly from the main shell: a command
# substitution forks the state, which is how the first harness defect the lab
# found lost the new pid. The state check cannot detect a subshell by itself.
# ---------------------------------------------------------------------------

server_require() {
  local expected=$1 caller=$2
  if [ "$SERVER_STATE" != "$expected" ]; then
    fail_harness "$caller: server is $SERVER_STATE, expected $expected"
    return 1
  fi
}

# server_start beam|xray [mark]: none/stopped -> starting -> running|failed.
# A byte mark makes readiness mean "a listening line after this offset", so a
# restarted process cannot pass on the previous process's message.
server_start() {
  local kind=$1 mark=${2:-} ready=1
  case "$SERVER_STATE" in
    none|stopped) ;;
    *)
      fail_harness "server_start $kind: server is already $SERVER_STATE"
      return 1
      ;;
  esac
  SERVER_STATE=starting
  SERVER_KIND=$kind
  if [ "$kind" = "beam" ]; then
    SERVER_LOG=$BEAM_LOG
    ip netns exec tun-server "$BEAM_BIN" --config "$CONFIG_DIR/beam.toml" \
      >> "$BEAM_LOG" 2>&1 &
    BEAM_PID=$!
    SERVER_PID=$BEAM_PID
    if [ -n "$mark" ]; then
      wait_for_marker_after "$BEAM_LOG" "$mark" "beam listening" "$BEAM_PID" 15 || ready=0
    else
      wait_for_log "$BEAM_LOG" "beam listening" "$BEAM_PID" 15 || ready=0
    fi
    if [ "$ready" = "1" ]; then
      SERVER_STATE=running
      return 0
    fi
  else
    SERVER_LOG=$XRAY_LOG
    ip netns exec tun-server "$XRAY_BIN" run -c "$CONFIG_DIR/xray-server.json" \
      >> "$XRAY_LOG" 2>&1 &
    XRAY_PID=$!
    SERVER_PID=$XRAY_PID
    if wait_for_command "$XRAY_PID" 20 \
      ip netns exec tun-server "$PYTHON" -c 'import socket; socket.create_connection(("10.10.1.1", 443), 0.2).close()'; then
      SERVER_STATE=running
      return 0
    fi
  fi
  SERVER_STATE=failed
  SERVER_PID=""
  return 1
}

# Stop whichever server is current; safe in every state.
server_stop() {
  case "$SERVER_STATE" in
    none|stopped) return 0 ;;
  esac
  SERVER_STATE=stopping
  if [ "$SERVER_KIND" = "beam" ]; then
    stop_pid "$BEAM_PID"
    BEAM_PID=""
  else
    stop_pid "$XRAY_PID"
    XRAY_PID=""
  fi
  SERVER_PID=""
  SERVER_STATE=stopped
}

# Kill the running server and start a fresh process with the same config.
# running -> restarting -> starting -> running|failed; records restart evidence
# in <out> and the kill timestamp in RESTART_KILLED_MS.
server_restart() {
  local out=$1
  server_require running server_restart || return 1
  local kind=$SERVER_KIND old_pid=$SERVER_PID
  local old_start="" new_start="" new_pid="" reaped=0 mark killed
  local log=$SERVER_LOG
  if [ -z "$old_pid" ] || [ ! -r "/proc/$old_pid/stat" ]; then
    fail_harness "cannot restart the $kind server: no live pid"
    return 1
  fi
  old_start=$(awk '{print $22}' "/proc/$old_pid/stat")
  killed=$("$PYTHON" -c 'import time; print(int(time.time() * 1000))')
  SERVER_STATE=restarting
  kill -TERM "$old_pid" 2>/dev/null || true
  for _ in $(seq 1 100); do
    if ! kill -0 "$old_pid" 2>/dev/null; then
      reaped=1
      break
    fi
    if [ "$(awk '{print $3}' "/proc/$old_pid/stat" 2>/dev/null)" = "Z" ]; then
      reaped=1
      break
    fi
    sleep 0.1
  done
  if [ "$reaped" != "1" ]; then
    # SIGTERM within the window is what old_reaped reports; escalate so a
    # server that ignores TERM cannot block the harness in wait forever.
    kill -KILL "$old_pid" 2>/dev/null || true
  fi
  wait "$old_pid" 2>/dev/null || true
  mark=$(wc -c < "$log" 2>/dev/null || echo 0)
  SERVER_STATE=stopped
  SERVER_PID=""
  if ! server_start "$kind" "$mark"; then
    fail_harness "the restarted $kind process did not start"
    return 1
  fi
  new_pid=$SERVER_PID
  new_start=$(awk '{print $22}' "/proc/$new_pid/stat" 2>/dev/null || echo "")
  "$PYTHON" - "$out" "$old_pid" "$new_pid" "$old_start" "$new_start" "$reaped" "$killed" <<'RESTART'
import json
import sys

path, old_pid, new_pid, old_start, new_start, reaped, killed = sys.argv[1:8]
payload = {
    "metrics": {
        "restart-recovery": {
            "old_pid": int(old_pid),
            "new_pid": int(new_pid),
            "old_start": int(old_start) if old_start.isdigit() else 0,
            "new_start": int(new_start) if new_start.isdigit() else 0,
            "old_reaped": reaped == "1",
            "killed_at_ms": int(killed),
        }
    }
}
with open(path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(payload, sort_keys=True) + "\n")
RESTART
  RESTART_KILLED_MS="$killed"
}

# Process resources of the active server, as "rss_kib fds threads".
sample_server() {
  local rss=0 fds=0 threads=0
  if [ -n "$SERVER_PID" ] && [ -r "/proc/$SERVER_PID/status" ]; then
    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$SERVER_PID/status")
    threads=$(awk '/^Threads:/ {print $2}' "/proc/$SERVER_PID/status")
    fds=$(ls "/proc/$SERVER_PID/fd" 2>/dev/null | wc -l)
  fi
  printf '%s %s %s\n' "${rss:-0}" "${fds:-0}" "${threads:-0}"
}

print_table() {
  local file=$1 title=$2
  printf '\n== %s ==\n' "$title"
  printf '%-20s %-8s %s\n' "TEST" "RESULT" "DETAIL"
  printf '%-20s %-8s %s\n' "----" "------" "------"
  while IFS=$'\t' read -r name status detail; do
    printf '%-20s %-8s %s\n' "$name" "$status" "$detail"
  done < "$file"
}

count_status() {
  local file=$1 status=$2
  awk -F '\t' -v status="$status" '$2 == status { count++ } END { print count + 0 }' "$file"
}

blocked_file() {
  local reason=$1
  : > "$BEAM_TSV"
  for name in tcp-http-v4 tcp-http-v6 udp-echo udp-echo-v6 dns-udp dns-udp-v6 quic-udp https-direct; do
    record "$BEAM_TSV" "$name" BLOCKED "$reason"
  done
}

write_environment() {
  {
    echo "run_dir=$RUN_DIR"
    echo "beam=$BEAM_BIN"
    echo "sing-box=$SING_BOX"
    echo "profile=$PROFILE"
    echo "control=$CONTROL"
    echo "suite=$SUITE"
    echo "udp_mode=$UDP_MODE"
    echo "rtt_ms=$TUN_RTT_MS"
    echo "loss_pct=$TUN_LOSS_PCT"
    echo "tun_mtu=$TUN_MTU"
    echo "log_level=$TUN_LOG_LEVEL"
    echo "baseline_rtt_ms=$BASELINE_RTT_MS"
    echo "baseline_target_rtt_ms=$BASELINE_TARGET_RTT_MS"
    echo "client=$("$SING_BOX" version 2>/dev/null | head -n 1 || echo unknown)"
    echo "curl=$(curl --version 2>/dev/null | head -n 1 || echo unknown)"
    # sudo drops the runner's environment, so the workflow passes IMAGE_OS
    # and GIT_COMMIT explicitly; both fall back to the local values.
    echo "runner=${IMAGE_OS:-${ImageOS:-local}}"
  } > "$RUN_DIR/environment.txt"
  "$SING_BOX" version > "$RUN_DIR/singbox-version.txt" 2>&1 || true
  if [ -x "$XRAY_BIN" ]; then
    "$XRAY_BIN" version > "$RUN_DIR/xray-version.txt" 2>&1 || true
  fi
}

print_summary() {
  local beam_pass beam_blocked beam_failed
  beam_pass=$(count_status "$BEAM_TSV" PASS)
  beam_blocked=$(count_status "$BEAM_TSV" BLOCKED)
  beam_failed=$(count_status "$BEAM_TSV" FAIL)
  if [ "$SUITE" = "protocols" ]; then
    protocol_summary
    write_environment
    return
  fi
  print_table "$BEAM_TSV" "beam (server $BEAM_ADDR)"
  printf '\nsummary: %s passed, %s blocked, %s failed\n' "$beam_pass" "$beam_blocked" "$beam_failed"
  if [ "$CONTROL" = "1" ] && [ -s "$XRAY_TSV" ]; then
    local control_pass control_blocked control_failed
    control_pass=$(count_status "$XRAY_TSV" PASS)
    control_blocked=$(count_status "$XRAY_TSV" BLOCKED)
    control_failed=$(count_status "$XRAY_TSV" FAIL)
    print_table "$XRAY_TSV" "stock Xray control (same client and targets)"
    printf '\nsummary: %s passed, %s blocked, %s failed\n' "$control_pass" "$control_blocked" "$control_failed"
  fi
  write_environment
}

finish() {
  print_summary
  printf '\nrun directory: %s\n' "$RUN_DIR"
  if [ "$HARNESS_FAIL" = "1" ]; then
    exit 1
  fi
  if [ "$UNEXPECTED_FAIL" = "1" ]; then
    exit 1
  fi
  if [ "${TUN_BLOCKED:-0}" = "1" ] && [ "${ALLOW_TUN_BLOCKED:-0}" != "1" ]; then
    printf 'tun-harness: matrix contains BLOCKED rows; refusing success\n' >&2
    printf 'tun-harness: set ALLOW_TUN_BLOCKED=1 to accept a skipped matrix\n' >&2
    exit 2
  fi
  exit 0
}

record_protocol() {
  local arm=$1 file=$2 name=$3 status=$4 detail=$5
  detail="${detail//$'\t'/ }"
  detail="${detail//$'\n'/ }"
  printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >> "$file"
  printf '  %-24s %-8s %s\n' "$name" "$status" "$detail"
  if [ "$arm" = "beam" ] && [ "$status" = "BLOCKED" ]; then
    PROTO_HARNESS_OK=0
    fail_harness "beam protocol row $name is BLOCKED; every tool for the suite is pinned"
  fi
  if [ "$arm" = "beam" ] && [ "$status" = "FAIL" ]; then
    UNEXPECTED_FAIL=1
  fi
}

run_case() {
  local arm=$1 name=$2 timeout_s=$3
  shift 3
  local out="$PROTO_DIR/$arm/$name.json"
  local log="$PROTO_DIR/$arm/$name.log"
  local rc=0 status detail
  ip netns exec tun-client timeout "$timeout_s" "$PYTHON" "$HERE/protocol.py" "$name" "$@" \
    --out "$out" > "$log" 2>&1 || rc=$?
  status="$(json_field "$out" status)"
  detail="$(json_field "$out" detail)"
  if [ -z "$status" ]; then
    status="FAIL"
    detail="driver produced no result (rc=$rc): $(tail -n 2 "$log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
  elif [ "$rc" -ne 0 ] && [ "$status" != "FAIL" ]; then
    status="FAIL"
    detail="driver exited $rc after reporting $status: $detail"
  fi
  [ -n "$detail" ] || detail="no detail"
  record_protocol "$arm" "$RUN_DIR/protocol-results-$arm.tsv" "$name" "$status" "$detail"
}

write_case_failure() {
  local path=$1 name=$2 detail=$3
  "$PYTHON" - "$path" "$name" "$detail" <<'FAILURE'
import json
import sys
import time

path, name, detail = sys.argv[1:4]
now = round(time.time(), 3)
payload = {
    "name": name,
    "status": "FAIL",
    "correctness": False,
    "ok": False,
    "planned": 1,
    "completed": 0,
    "deadline_ms": 0,
    "started": now,
    "ended": now,
    "metrics": {},
    "warnings": [],
    "detail": detail,
}
with open(path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(payload, sort_keys=True) + "\n")
FAILURE
}

write_preflight_row() {
  local name=$1 status=$2 code=$3 version=$4 size=$5 detail=$6
  "$PYTHON" - "$PROTO_DIR/$name.json" "$name" "$status" "$code" "$version" "$size" "$detail" <<'PREFLIGHT'
import json
import sys
import time

path, name, status, code, version, size, detail = sys.argv[1:8]
now = round(time.time(), 3)
payload = {
    "name": name,
    "status": status,
    "correctness": status != "FAIL",
    "ok": status != "FAIL",
    "planned": 1,
    "completed": 0 if status == "FAIL" else 1,
    "deadline_ms": 20000,
    "started": now,
    "ended": now,
    "metrics": {
        "http_code": int(code) if code.isdigit() else 0,
        "http_version": version or "?",
        "bytes": int(size),
    },
    "warnings": [],
    "detail": detail,
}
with open(path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(payload, sort_keys=True) + "\n")
PREFLIGHT
}

# Direct-origin preflights: from tun-server, before beam exists. They prove the
# origins, the target namespace and the ports work; a failure is a harness
# failure, not a beam finding.
run_preflight() {
  local name=$1 url=$2 flag=${3:-} marker=$4
  local body="$PROTO_DIR/$name.body"
  local log="$LOG_DIR/$name.log"
  local rc=0 fields code version size marker_ok=0
  : > "$body"
  if [ -n "$flag" ]; then
    fields=$(ip netns exec tun-server timeout 25 curl -sS -k --noproxy '*' "$flag" \
      --max-time 15 -o "$body" -w '%{http_code} %{http_version}' "$url" 2>"$log") || rc=$?
  else
    fields=$(ip netns exec tun-server timeout 25 curl -sS -k --noproxy '*' \
      --max-time 15 -o "$body" -w '%{http_code} %{http_version}' "$url" 2>"$log") || rc=$?
  fi
  code="${fields%% *}"
  version="${fields##* }"
  size=$(wc -c < "$body" 2>/dev/null || echo 0)
  if grep -qF -- "$marker" "$body" 2>/dev/null; then
    marker_ok=1
  fi
  if [ "$rc" -eq 0 ] && [ "$code" = "200" ] && [ "$marker_ok" = "1" ]; then
    write_preflight_row "$name" PASS "$code" "$version" "$size" \
      "direct origin HTTP/$version 200, ${size} B marker, from tun-server" > /dev/null
  else
    PROTO_HARNESS_OK=0
    fail_harness "preflight $name failed: rc=$rc code=${code:-none} $(tr '\n' ' ' < "$log" | cut -c1-160)"
    write_preflight_row "$name" FAIL "${code:-0}" "$version" "$size" \
      "harness failure: the direct origin did not answer correctly: $(tr '\n' ' ' < "$log" | cut -c1-160)" > /dev/null
  fi
}

run_preflights() {
  mkdir -p "$PROTO_DIR"
  log "running direct-origin preflights from tun-server"
  run_preflight preflight-h1 "http://10.10.2.2:8080/" "" "beam-tun-ok"
  run_preflight preflight-h2 "https://10.10.2.2:8443/" "--http2" "beam-tun-h3-ok"
  run_preflight preflight-h3 "https://10.10.2.2:4443/" "--http3-only" "beam-tun-h3-ok"
  "$PYTHON" - "$PROTO_DIR" "$PROTO_DIR/preflights.json" "$PROTO_HARNESS_OK" <<'PREFLIGHTS'
import json
import sys
import time
from pathlib import Path

directory, out, ok = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3] == "1"
cases = []
for name in ("preflight-h1", "preflight-h2", "preflight-h3"):
    path = directory / f"{name}.json"
    if path.is_file():
        cases.append(json.loads(path.read_text(encoding="utf-8")))
    else:
        now = round(time.time(), 3)
        cases.append(
            {
                "name": name,
                "status": "FAIL",
                "correctness": False,
                "ok": False,
                "planned": 1,
                "completed": 0,
                "deadline_ms": 20000,
                "started": now,
                "ended": now,
                "metrics": {"http_code": 0, "http_version": "?", "bytes": 0},
                "warnings": [],
                "detail": "harness failure: the preflight produced no result",
            }
        )
payload = {"cases": cases, "complete": ok}
out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PREFLIGHTS
}

protocol_summary() {
  local arm tsv
  for arm in beam xray; do
    tsv="$RUN_DIR/protocol-results-$arm.tsv"
    [ -s "$tsv" ] || continue
    print_table "$tsv" "$arm protocol cases"
    printf '\nsummary: %s passed, %s warn, %s failed\n' \
      "$(count_status "$tsv" PASS)" "$(count_status "$tsv" WARN)" "$(count_status "$tsv" FAIL)"
  done
  if [ -f "$PROTO_BEAM_REPORT" ]; then
    "$PYTHON" - "$PROTO_BEAM_REPORT" <<'SUMMARY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
print(
    "beam protocol report: "
    f"complete={report.get('complete')} "
    f"cases={len(report.get('cases') or [])} "
    f"missing={len(report.get('missing') or [])} "
    f"duplicates={len(report.get('duplicates') or [])}"
)
SUMMARY
    if ! "$PYTHON" - "$PROTO_BEAM_REPORT" <<'COMPLETE'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
raise SystemExit(0 if report.get("complete") is True else 1)
COMPLETE
    then
      fail_harness "the beam protocol report is incomplete"
    fi
  else
    fail_harness "no beam protocol report was produced"
  fi
  if [ "$CONTROL" = "1" ] && [ ! -f "$PROTO_XRAY_REPORT" ]; then
    log "no Xray protocol report was produced (diagnostic arm only)"
  fi
}

run_protocol_suite() {
  local arm=$1
  local tsv="$RUN_DIR/protocol-results-$arm.tsv"
  local dir="$PROTO_DIR/$arm"
  mkdir -p "$dir"
  : > "$tsv"
  printf '\n-- %s protocol suite --\n' "$arm"

  local http="10.10.2.2:8080"
  local https_h2="10.10.2.2:8443"
  local https_h3="10.10.2.2:4443"
  local tls="10.10.2.2:4443"
  local tls12="10.10.2.2:8444"
  local udp="10.10.2.2:9999"
  local tcp="10.10.2.2:9000"
  local dns="10.10.2.2:53"
  local offset before after killed

  write_environment
  # Throughput cases are loss-sensitive: at 1% netem loss the 8 MiB transfers
  # took 50-85 s and the mixed cell's 16 MiB upload needs >100 s, so the harness
  # timeout must not become the correctness gate.
  run_case "$arm" h2-bulk-8m 180 --https "$https_h2"

  offset=$(wc -c < "$H3_LOG" 2>/dev/null || echo 0)
  ip netns exec tun-client timeout 90 "$H2_CLIENT_BIN" \
    --url "https://$https_h2/?bytes=65536" --streams 16 \
    --out "$dir/h2-client-raw.json" > "$dir/h2-client.log" 2>&1 || true
  run_case "$arm" h2-multiplex-16 30 --client "$dir/h2-client-raw.json" \
    --streams 16 --origin-log "$H3_LOG" --origin-offset "$offset"

  run_case "$arm" h3-bulk-8m 180 --https "$https_h3"
  offset=$(wc -c < "$H3_LOG" 2>/dev/null || echo 0)
  run_case "$arm" h3-concurrent-8 90 --https "$https_h3" \
    --origin-log "$H3_LOG" --origin-offset "$offset"
  run_case "$arm" http1-persistent-20 90 --http "$http"
  run_case "$arm" tcp-upload-8m 150 --tcp "$tcp"
  run_case "$arm" h2-cancel-64m 90 --https "$https_h2" --http "$http"
  run_case "$arm" udp-realtime-1200 90 --udp "$udp"
  run_case "$arm" udp-multidest-4 90 --udp "$udp" --ports 9996,9997,9998,9999
  run_case "$arm" udp-alt-source 30 --udp 10.10.2.2:9998
  # The server's UDP idle clock is 60 s, so a 70 s silence proves whether a
  # client recovers on its own after the flow is torn down.
  run_case "$arm" udp-idle-resume-70s 150 --udp "$udp"
  run_case "$arm" dns-udp-200 90 --dns "$dns"
  run_case "$arm" dns-tcp-fallback 90 --dns "$dns"

  before=$(sample_server)
  run_case "$arm" mixed-hol-60s 240 --https "$https_h2" --http "$http" \
    --udp "$udp" --tcp "$tcp" --dns "$dns"
  after=$(sample_server)
  "$PYTHON" - "$dir/resources.json" "$before" "$after" <<'RESOURCES'
import json
import sys

path, before, after = sys.argv[1], sys.argv[2].split(), sys.argv[3].split()
metrics = {
    "rss_before_kib": int(before[0]),
    "fds_before": int(before[1]),
    "threads_before": int(before[2]),
    "rss_after_kib": int(after[0]),
    "fds_after": int(after[1]),
    "threads_after": int(after[2]),
}
payload = {"metrics": {"mixed-hol-60s": metrics}}
with open(path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(payload, sort_keys=True) + "\n")
RESOURCES

  run_case "$arm" idle-tcp-35s 120 --tcp "$tcp"

  RESTART_KILLED_MS=""
  killed=""
  if server_restart "$dir/restart.json"; then
    killed="$RESTART_KILLED_MS"
  fi
  if [ -n "$killed" ]; then
    run_case "$arm" restart-recovery 90 --http "$http" --udp "$udp" \
      --https "$https_h2" --deadline-ms 10000 --since-ms "$killed"
  else
    write_case_failure "$dir/restart-recovery.json" restart-recovery \
      "harness failure: could not restart the $SERVER_KIND process: $(tail -n 3 "$SERVER_LOG" 2>/dev/null | tr '\n' ' ' | cut -c1-240)"
    record_protocol "$arm" "$tsv" restart-recovery FAIL \
      "harness failure: could not restart the $SERVER_KIND process"
  fi

  run_case "$arm" tls12-fallback 90 --tls "$tls12"
  run_case "$arm" datagram-size-continuity 90 --udp "$udp" --tls "$tls"

  local extras=(--extra "$PROTO_DIR/preflights.json")
  [ -f "$dir/restart.json" ] && extras+=(--extra "$dir/restart.json")
  [ -f "$dir/resources.json" ] && extras+=(--extra "$dir/resources.json")
  local complete=false
  [ "$PROTO_HARNESS_OK" = "1" ] && complete=true
  printf '{"complete": %s}\n' "$complete" > "$dir/complete.json"
  extras+=(--extra "$dir/complete.json")
  "$PYTHON" "$HERE/protocol_report.py" merge \
    --results "$dir" \
    --environment "$RUN_DIR/environment.txt" \
    --arm "$arm" \
    --commit "${GIT_COMMIT:-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)}" \
    --binary-sha256 "$(sha256sum "$BEAM_BIN" 2>/dev/null | cut -d' ' -f1)" \
    "${extras[@]}" \
    --out "$RUN_DIR/protocol-report-$arm.json" \
    --tsv "$tsv" || fail_harness "could not merge the $arm protocol report"
}

# ---------------------------------------------------------------------------
# Preflight and build
# ---------------------------------------------------------------------------

log "worktree $ROOT"
log "run directory $RUN_DIR"
log "sing-box UDP mode $UDP_MODE"
log "sing-box $("$SING_BOX" version 2>/dev/null | head -n 1 || echo unknown)"

if [ "$SKIP_BUILD" != "1" ]; then
  log "building beam ($PROFILE)"
  if [ "$PROFILE" = "release" ]; then
    (cd "$ROOT" && cargo build --locked --release -p beam) > "$LOG_DIR/build.log" 2>&1 \
      || { fail_harness "cargo build failed"; cat "$LOG_DIR/build.log" >&2; exit 1; }
  else
    (cd "$ROOT" && cargo build --locked -p beam) > "$LOG_DIR/build.log" 2>&1 \
      || { fail_harness "cargo build failed"; cat "$LOG_DIR/build.log" >&2; exit 1; }
  fi
fi
BEAM_BIN="$ROOT/target/$PROFILE/beam"
if [ ! -x "$BEAM_BIN" ]; then
  fail_harness "beam binary not found: $BEAM_BIN"
  exit 1
fi

if [ ! -c /dev/net/tun ]; then
  TUN_BLOCKED=1
  TUN_BLOCK_REASON="/dev/net/tun is unavailable on this host"
elif [ "${TUN_FORCE_BLOCK:-0}" = "1" ]; then
  TUN_BLOCKED=1
  TUN_BLOCK_REASON="TUN_FORCE_BLOCK=1 test hook forced the full-TUN case to BLOCKED"
elif ! ip netns list >/dev/null 2>&1; then
  fail_harness "ip netns is not usable after entering the private namespace"
  exit 1
fi

# ---------------------------------------------------------------------------
# Namespace topology
# ---------------------------------------------------------------------------

if [ "$TUN_BLOCKED" = "1" ]; then
  if [ "$SUITE" = "protocols" ]; then
    fail_harness "the protocol suite cannot run: $TUN_BLOCK_REASON"
    finish
  fi
  blocked_file "$TUN_BLOCK_REASON"
  finish
fi

# Shadow only the netns directory: masking all of /run hides the system bus
# socket and breaks anything that talks to systemd while the suite runs.
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns >/dev/null 2>&1 \
  || { fail_harness "could not mount tmpfs on /run/netns"; exit 1; }

for namespace in "${NAMESPACES[@]}"; do
  ip netns add "$namespace" \
    || { fail_harness "could not create network namespace $namespace"; exit 1; }
  CREATED_NAMESPACES+=("$namespace")
done

for namespace in "${NAMESPACES[@]}"; do
  ip netns exec "$namespace" ip link set lo up \
    || { fail_harness "could not bring up loopback in $namespace"; exit 1; }
done

ip link add vc type veth peer name sc \
  || { fail_harness "could not create the client/server veth pair"; exit 1; }
ip link set vc netns tun-client
ip link set sc netns tun-server
ip netns exec tun-client ip addr add "$CLIENT_ADDR" dev vc
ip netns exec tun-client ip link set vc up
ip netns exec tun-server ip addr add "$SERVER_ADDR" dev sc
ip netns exec tun-server ip link set sc up

ip link add vs type veth peer name ts \
  || { fail_harness "could not create the server/target veth pair"; exit 1; }
ip link set vs netns tun-server
ip link set ts netns tun-target
ip netns exec tun-server ip addr add "$SERVER_TARGET_ADDR" dev vs
ip netns exec tun-server ip link set vs up
ip netns exec tun-target ip addr add "$TARGET_ADDR" dev ts
ip netns exec tun-target ip link set ts up

IPV6_AVAILABLE=1
# Duplicate address detection leaves fresh addresses tentative for about a
# second, which makes an immediate bind fail with EADDRNOTAVAIL. The lab
# veths have exactly one peer each, so DAD adds no value here.
ip netns exec tun-server sysctl -qw net.ipv6.conf.vs.accept_dad=0 2>/dev/null || true
ip netns exec tun-target sysctl -qw net.ipv6.conf.ts.accept_dad=0 2>/dev/null || true
ip netns exec tun-server sysctl -qw net.ipv6.conf.vs.disable_ipv6=0 2>/dev/null || true
ip netns exec tun-target sysctl -qw net.ipv6.conf.ts.disable_ipv6=0 2>/dev/null || true
if ! ip netns exec tun-server ip -6 addr add "$SERVER_TARGET_V6" dev vs 2>"$LOG_DIR/ipv6-server.err"; then
  IPV6_AVAILABLE=0
fi
if [ "$IPV6_AVAILABLE" = "1" ] \
  && ! ip netns exec tun-target ip -6 addr add "$TARGET_V6" dev ts 2>"$LOG_DIR/ipv6-target.err"; then
  IPV6_AVAILABLE=0
fi
if [ "$IPV6_AVAILABLE" = "1" ]; then
  ip netns exec tun-server ip link set vs up
  ip netns exec tun-target ip link set ts up
  if ! ip netns exec tun-server ip -6 addr show dev vs | grep -q 'fd00:2::1'; then
    IPV6_AVAILABLE=0
  fi
  if ! ip netns exec tun-target ip -6 addr show dev ts | grep -q 'fd00:2::2'; then
    IPV6_AVAILABLE=0
  fi
fi

# Prove that the client namespace can create a TUN device before starting the
# real client. If this fails, the full-TUN case is blocked, not a harness bug.
if ! ip netns exec tun-client ip tuntap add dev tunprobe mode tun 2>"$LOG_DIR/tun-preflight.err"; then
  TUN_BLOCKED=1
  TUN_BLOCK_REASON="client namespace cannot create a TUN device: $(tr '\n' ' ' < "$LOG_DIR/tun-preflight.err")"
fi
ip netns exec tun-client ip link del tunprobe >/dev/null 2>&1 || true
if [ "$TUN_BLOCKED" = "1" ]; then
  if [ "$SUITE" = "protocols" ]; then
    fail_harness "the protocol suite cannot run: $TUN_BLOCK_REASON"
    finish
  fi
  blocked_file "$TUN_BLOCK_REASON"
  finish
fi

# ---------------------------------------------------------------------------
# Impairment and baseline evidence
# ---------------------------------------------------------------------------

if awk -v rtt="$TUN_RTT_MS" -v loss="$TUN_LOSS_PCT" \
    'BEGIN { exit !(rtt > 0 || loss > 0) }'; then
  apply_netem || finish
fi
BASELINE_RTT_MS=$(measure_baseline_rtt 10.10.1.1 tun-client)
BASELINE_TARGET_RTT_MS=$(measure_baseline_rtt 10.10.2.2 tun-server)
log "baseline RTT: client->server ${BASELINE_RTT_MS}ms, server->target ${BASELINE_TARGET_RTT_MS}ms"

# ---------------------------------------------------------------------------
# Configs
# ---------------------------------------------------------------------------

log "generating the HTTPS test certificate"
"$SING_BOX" generate tls-keypair 10.10.2.2 > "$CONFIG_DIR/tls.pem" 2> "$LOG_DIR/keygen.err" \
  || { fail_harness "sing-box could not generate a TLS test key pair"; cat "$LOG_DIR/keygen.err" >&2; exit 1; }
"$PYTHON" - "$CONFIG_DIR/tls.pem" "$CONFIG_DIR/target.key" "$CONFIG_DIR/target.crt" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
blocks = re.findall(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", text, re.S)
if len(blocks) < 2 or "PRIVATE KEY" not in blocks[0] or "CERTIFICATE" not in blocks[1]:
    raise SystemExit("unexpected tls-keypair output")
open(sys.argv[2], "w", encoding="utf-8").write(blocks[0].strip() + "\n")
open(sys.argv[3], "w", encoding="utf-8").write(blocks[1].strip() + "\n")
PY

XRAY_FLAG=()
if [ "$CONTROL" = "1" ]; then
  XRAY_FLAG=(--xray)
fi
export TUN_MTU
"$PYTHON" "$HERE/config.py" \
  --test-config "$TEST_CONFIG" \
  --out-dir "$CONFIG_DIR" \
  --listen "$BEAM_ADDR" \
  --cover "$COVER" \
  --singbox \
  --packet-encoding "$UDP_MODE" \
  "${XRAY_FLAG[@]}" \
  || { fail_harness "could not render the beam/sing-box/Xray configs"; exit 1; }

# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------

if [ -z "$H3_ORIGIN_ERROR" ] && [ ! -x "$H3_ORIGIN_BIN" ]; then
  H3_ORIGIN_ERROR="local HTTP/3 origin binary is missing: $H3_ORIGIN_BIN"
fi
if [ "$SUITE" = "protocols" ] && [ -n "$H3_ORIGIN_ERROR" ]; then
  fail_harness "the protocol suite needs the local HTTP/3+HTTP/2 origin: $H3_ORIGIN_ERROR"
  exit 1
fi
if [ "$SUITE" = "protocols" ] && [ ! -x "$H2_CLIENT_BIN" ]; then
  fail_harness "the protocol suite needs the h2-client binary: $H2_CLIENT_BIN"
  exit 1
fi
if [ -z "$H3_ORIGIN_ERROR" ]; then
  if [ "$SUITE" = "protocols" ]; then
    # Per-request ?bytes= selects the body size; an inherited env default would
    # mask a broken query parser.
    unset H3_BODY_BYTES
    log "starting local HTTP/3+HTTP/2 origin on 10.10.2.2:4443 and :8443"
    ip netns exec tun-target "$H3_ORIGIN_BIN" \
      --listen 10.10.2.2:4443 --h2-listen 10.10.2.2:8443 \
      > "$H3_LOG" 2>&1 &
    H3_ORIGIN_PID=$!
    if wait_for_log "$H3_LOG" "h3-origin: READY" "$H3_ORIGIN_PID" 15 \
      && wait_for_log "$H3_LOG" "h2-origin: READY" "$H3_ORIGIN_PID" 15; then
      H3_READY=1
    else
      fail_harness "local HTTP/3+HTTP/2 origin did not become ready"
      tail -n 40 "$H3_LOG" >&2 || true
      exit 1
    fi
  else
    log "starting local HTTP/3 origin on 10.10.2.2:4443"
    ip netns exec tun-target "$H3_ORIGIN_BIN" --listen 10.10.2.2:4443 \
      > "$H3_LOG" 2>&1 &
    H3_ORIGIN_PID=$!
    if wait_for_log "$H3_LOG" "h3-origin: READY" "$H3_ORIGIN_PID" 15; then
      H3_READY=1
    else
      fail_harness "local HTTP/3 origin did not become ready"
      tail -n 40 "$H3_LOG" >&2 || true
      exit 1
    fi
  fi
else
  log "local HTTP/3 origin unavailable: $H3_ORIGIN_ERROR"
fi

log "starting target services"
TARGET_ARGS=(
  --http 10.10.2.2:8080
  --tls 10.10.2.2:4443
  --udp 10.10.2.2:9999
  --dns 10.10.2.2:53
  --cert "$CONFIG_DIR/target.crt"
  --key "$CONFIG_DIR/target.key"
)
if [ "$IPV6_AVAILABLE" = "1" ]; then
  TARGET_ARGS+=(--http6 '[fd00:2::2]:8080' --udp6 '[fd00:2::2]:9999' --dns6 '[fd00:2::2]:53')
fi
if [ "$H3_READY" != "1" ]; then
  # Without an H3 origin the sink still proves whether a QUIC packet reached
  # the target, but it never speaks HTTP/3 and therefore never produces a pass.
  TARGET_ARGS+=(--quic-sink '10.10.2.2:4443')
fi
if [ "$SUITE" = "protocols" ]; then
  TARGET_ARGS+=(
    --keepalive
    --tcp-echo 10.10.2.2:9000
    --tls12 10.10.2.2:8444
    --dns-tcp 10.10.2.2:53
    --udp-alt 10.10.2.2:9998
    --udp-extra 10.10.2.2:9996
    --udp-extra 10.10.2.2:9997
  )
fi
ip netns exec tun-target "$PYTHON" "$HERE/services.py" \
  "${TARGET_ARGS[@]}" \
  > "$TARGET_LOG" 2>&1 &
SERVICES_PID=$!
if ! wait_for_log "$TARGET_LOG" "target: READY" "$SERVICES_PID" 15; then
  fail_harness "target services did not become ready"
  tail -n 40 "$TARGET_LOG" >&2 || true
  exit 1
fi
if [ "$SUITE" = "protocols" ]; then
  run_preflights
fi

log "starting beam on $BEAM_ADDR"
if ! server_start beam; then
  fail_harness "beam did not start listening"
  tail -n 40 "$BEAM_LOG" >&2 || true
  exit 1
fi

log "starting sing-box full-TUN client"
ip netns exec tun-client "$SING_BOX" run -c "$CONFIG_DIR/singbox.json" \
  > "$SINGBOX_LOG" 2>&1 &
SINGBOX_PID=$!
if ! wait_for_command "$SINGBOX_PID" 20 ip netns exec tun-client ip link show tun0; then
  fail_harness "sing-box did not create tun0"
  tail -n 60 "$SINGBOX_LOG" >&2 || true
  exit 1
fi
if ! ip netns exec tun-client ip link set tun0 up 2>/dev/null; then
  log "tun0 was already up"
fi

if ! ip netns exec tun-client ip route replace 10.10.2.0/24 dev tun0; then
  fail_harness "could not route 10.10.2.0/24 into tun0"
  exit 1
fi
if [ "$IPV6_AVAILABLE" = "1" ]; then
  if ! ip netns exec tun-client ip -6 route replace fd00:2::/64 dev tun0; then
    IPV6_AVAILABLE=0
  fi
fi
if ! ip netns exec tun-client ip route get 10.10.2.2 2>/dev/null | grep -q 'dev tun0'; then
  fail_harness "10.10.2.2 does not resolve to tun0"
  exit 1
fi
if [ "$IPV6_AVAILABLE" = "1" ]; then
  # sing-box adds fd00:1::1 and the route just before this check. Duplicate
  # address detection can briefly make the source address unusable and
  # `ip -6 route get` fail, so retry instead of silently disabling IPv6.
  tun6_ready=0
  for _ in $(seq 1 30); do
    if ip netns exec tun-client ip -6 addr show dev tun0 2>/dev/null | grep -q 'inet6 fd00:1::1' \
      && ip netns exec tun-client ip -6 route get fd00:2::2 2>/dev/null | grep -q 'dev tun0'; then
      tun6_ready=1
      break
    fi
    sleep 0.1
  done
  [ "$tun6_ready" = "1" ] || IPV6_AVAILABLE=0
fi

{
  echo "== client =="
  ip netns exec tun-client ip addr show
  ip netns exec tun-client ip route show
  ip netns exec tun-client ip -6 route show
  echo "== server =="
  ip netns exec tun-server ip addr show
  ip netns exec tun-server ip route show
  echo "== target =="
  ip netns exec tun-target ip addr show
  ip netns exec tun-target ip route show
} > "$RUN_DIR/network.txt" 2>&1

# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

probe_http() {
  local arm=$1 name=$2 host=$3 port=$4 use_tls=$5
  local server_log="$LOG_DIR/$arm.log"
  local start=0
  [ -f "$server_log" ] && start=$(wc -c < "$server_log")
  local out="$PROBE_DIR/$arm/$name.json"
  local tls_args=()
  [ "$use_tls" = "1" ] && tls_args=(--tls)
  if ip netns exec tun-client "$PYTHON" "$HERE/probe.py" http --host "$host" --port "$port" \
      "${tls_args[@]}" --timeout 12 --out "$out" \
      > "$PROBE_DIR/$arm/$name.log" 2>&1; then
    record "$RUN_DIR/results-$arm.tsv" "$name" PASS "$(json_field "$out" detail)"
    return
  fi
  local detail
  detail="$(json_field "$out" detail)"
  [ -n "$detail" ] || detail="probe did not produce a result"
  if [ "$arm" = "beam" ] && has_marker "$server_log" "$start" "Vision Direct mode is not supported"; then
    record "$RUN_DIR/results-$arm.tsv" "$name" BLOCKED \
      "Direct unimplemented; probe: $detail; beam: $(marker_line "$server_log" "$start" "Vision Direct mode is not supported")"
  else
    record "$RUN_DIR/results-$arm.tsv" "$name" FAIL "$detail"
    UNEXPECTED_FAIL=1
  fi
}

probe_udp() {
  local arm=$1 name=$2 host=$3 port=$4
  local server_log="$LOG_DIR/$arm.log"
  local start=0
  [ -f "$server_log" ] && start=$(wc -c < "$server_log")
  local out="$PROBE_DIR/$arm/$name.json"
  if ip netns exec tun-client "$PYTHON" "$HERE/probe.py" udp --host "$host" --port "$port" --timeout 5 \
      --out "$out" > "$PROBE_DIR/$arm/$name.log" 2>&1; then
    record "$RUN_DIR/results-$arm.tsv" "$name" PASS "$(json_field "$out" detail)"
    return
  fi
  local detail
  detail="$(json_field "$out" detail)"
  [ -n "$detail" ] || detail="probe did not produce a result"
  if [ "$arm" = "beam" ] && has_marker "$server_log" "$start" "authenticated VLESS command is not implemented yet"; then
    record "$RUN_DIR/results-$arm.tsv" "$name" BLOCKED \
      "XUDP unimplemented; probe: $detail; beam: $(marker_line "$server_log" "$start" "authenticated VLESS command is not implemented yet")"
  else
    record "$RUN_DIR/results-$arm.tsv" "$name" FAIL "$detail"
    UNEXPECTED_FAIL=1
  fi
}

probe_dns() {
  local arm=$1 name=$2 server=$3 qtype=$4 expected=$5
  local server_log="$LOG_DIR/$arm.log"
  local start=0
  [ -f "$server_log" ] && start=$(wc -c < "$server_log")
  local log="$PROBE_DIR/$arm/$name.log"
  local rc=0
  ip netns exec tun-client dig +notcp +time=3 +tries=1 "@$server" target.test "$qtype" \
    > "$log" 2>&1 || rc=$?
  local status
  status="$(grep -m1 'status:' "$log" | tr -s ' ' | sed 's/^ //' || true)"
  [ -n "$status" ] || status="$(tail -n 2 "$log" | tr '\n' ' ' || true)"
  if [ "$rc" -eq 0 ] && grep -q 'status: NOERROR' "$log" \
      && grep -qF -- "$expected" "$log"; then
    record "$RUN_DIR/results-$arm.tsv" "$name" PASS "$status; answer=$expected"
    return
  fi
  if [ "$arm" = "beam" ] && has_marker "$server_log" "$start" "authenticated VLESS command is not implemented yet"; then
    record "$RUN_DIR/results-$arm.tsv" "$name" BLOCKED \
      "XUDP unimplemented; dig: $status; beam: $(marker_line "$server_log" "$start" "authenticated VLESS command is not implemented yet")"
  else
    record "$RUN_DIR/results-$arm.tsv" "$name" FAIL "$status"
    UNEXPECTED_FAIL=1
  fi
}

probe_quic() {
  local arm=$1
  if [ "$CURL_HTTP3" != "1" ]; then
    record "$RUN_DIR/results-$arm.tsv" "quic-udp" BLOCKED \
      "the local curl has no HTTP/3 support; cannot send a QUIC Initial"
    return
  fi
  if [ "$H3_READY" != "1" ]; then
    record "$RUN_DIR/results-$arm.tsv" "quic-udp" BLOCKED \
      "local HTTP/3 origin unavailable: $H3_ORIGIN_ERROR"
    return
  fi
  local server_log="$LOG_DIR/$arm.log"
  local start=0
  [ -f "$server_log" ] && start=$(wc -c < "$server_log")
  local origin_start=0
  [ -f "$H3_LOG" ] && origin_start=$(wc -c < "$H3_LOG")
  local log="$PROBE_DIR/$arm/quic-udp.log"
  local body="$PROBE_DIR/$arm/quic-udp.body"
  : > "$body"
  local rc=0
  ip netns exec tun-client timeout 12 curl --http3-only --insecure --noproxy '*' -sS \
    --max-time 8 -o "$body" -w '%{http_code}' https://10.10.2.2:4443/ \
    > "$log" 2>&1 || rc=$?
  local code
  code="$(tr -d '\r\n' < "$log")"
  local curl_error
  curl_error="$(tr '\n' ' ' < "$log" | cut -c1-240)"
  local body_text
  body_text="$(tr '\n' ' ' < "$body" | cut -c1-120)"
  if [ "$rc" -eq 0 ] && [ "$code" = "200" ] \
      && grep -qF 'beam-tun-h3-ok' "$body"; then
    record "$RUN_DIR/results-$arm.tsv" "quic-udp" PASS "HTTP/3 200 body=$body_text"
    return
  fi
  if [ "$arm" = "beam" ] && has_marker "$server_log" "$start" "authenticated VLESS command is not implemented yet"; then
    record "$RUN_DIR/results-$arm.tsv" "quic-udp" BLOCKED \
      "XUDP unimplemented; curl: $curl_error; beam: $(marker_line "$server_log" "$start" "authenticated VLESS command is not implemented yet")"
  elif has_marker "$H3_LOG" "$origin_start" "status=200"; then
    record "$RUN_DIR/results-$arm.tsv" "quic-udp" FAIL \
      "HTTP/3 origin answered but curl failed; curl: $curl_error"
    UNEXPECTED_FAIL=1
  else
    record "$RUN_DIR/results-$arm.tsv" "quic-udp" FAIL \
      "QUIC probe failed without reaching the HTTP/3 origin; curl: $curl_error"
    UNEXPECTED_FAIL=1
  fi
}

probe_https_curl() {
  local arm=$1
  local server_log="$LOG_DIR/$arm.log"
  local start=0
  [ -f "$server_log" ] && start=$(wc -c < "$server_log")
  local log="$PROBE_DIR/$arm/https-direct.log"
  local rc=0
  ip netns exec tun-client timeout 15 curl --noproxy '*' -k -sS --max-time 12 \
    -o /dev/null -w 'http=%{http_code}' https://10.10.2.2:4443/ \
    > "$log" 2>&1 || rc=$?
  local detail
  detail="$(tr '\n' ' ' < "$log" | cut -c1-240)"
  if [ "$rc" -eq 0 ] && grep -q 'http=200' "$log"; then
    record "$RUN_DIR/results-$arm.tsv" "https-direct" PASS "$detail"
    return
  fi
  if [ "$arm" = "beam" ] && has_marker "$server_log" "$start" "Vision Direct mode is not supported"; then
    record "$RUN_DIR/results-$arm.tsv" "https-direct" BLOCKED \
      "Direct unimplemented; curl: $detail; beam: $(marker_line "$server_log" "$start" "Vision Direct mode is not supported")"
  else
    record "$RUN_DIR/results-$arm.tsv" "https-direct" FAIL "$detail"
    UNEXPECTED_FAIL=1
  fi
}

run_suite() {
  local arm=$1
  mkdir -p "$PROBE_DIR/$arm"
  : > "$RUN_DIR/results-$arm.tsv"
  printf '\n-- %s suite --\n' "$arm"

  probe_http "$arm" "tcp-http-v4" 10.10.2.2 8080 0
  if [ "$IPV6_AVAILABLE" = "1" ]; then
    probe_http "$arm" "tcp-http-v6" "fd00:2::2" 8080 0
  else
    record "$RUN_DIR/results-$arm.tsv" "tcp-http-v6" BLOCKED \
      "IPv6 is unavailable in the client or target namespace"
  fi
  probe_udp "$arm" "udp-echo" 10.10.2.2 9999
  if [ "$IPV6_AVAILABLE" = "1" ]; then
    probe_udp "$arm" "udp-echo-v6" "fd00:2::2" 9999
  else
    record "$RUN_DIR/results-$arm.tsv" "udp-echo-v6" BLOCKED \
      "IPv6 is unavailable in the client or target namespace"
  fi
  probe_dns "$arm" "dns-udp" "10.10.2.2" A 10.10.2.2
  if [ "$IPV6_AVAILABLE" = "1" ]; then
    probe_dns "$arm" "dns-udp-v6" "fd00:2::2" AAAA "fd00:2::2"
  else
    record "$RUN_DIR/results-$arm.tsv" "dns-udp-v6" BLOCKED \
      "IPv6 is unavailable in the client or target namespace"
  fi
  probe_quic "$arm"
  probe_https_curl "$arm"
}

if [ "$SUITE" = "protocols" ]; then
  run_protocol_suite beam
else
  run_suite beam
fi

if [ "$CONTROL" = "1" ]; then
  log "stopping the server under test and starting the stock Xray control"
  server_stop
  if ! server_start xray; then
    fail_harness "stock Xray control did not accept connections on $BEAM_ADDR"
    tail -n 40 "$XRAY_LOG" >&2 || true
    exit 1
  fi
  if [ "$SUITE" = "protocols" ]; then
    run_protocol_suite xray
  else
    run_suite xray
  fi
fi

finish
