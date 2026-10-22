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
#
# Environment:
#   SING_BOX        sing-box binary (default /tmp/opencode/bench/bin/sing-box)
#   XRAY_BIN        stock Xray binary (default /tmp/opencode/xray-server-compare/xray)
#   TEST_CONFIG     beam REALITY fixture (default /tmp/opencode/beam-test/beam.toml)
#   TUN_OUT         run directory (default /tmp/opencode/beam-tun/<timestamp>)
#   SKIP_BUILD=1    reuse target/<profile>/beam and the H3 origin binary
#   H3_ORIGIN_BIN   use a prebuilt h3-origin binary instead of building it
#   UDP_MODE        sing-box packet_encoding: xudp, packetaddr, or legacy
#                   (default xudp; legacy renders packet_encoding "")
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
  if ! unshare --user --map-root-user --net true 2>/dev/null; then
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
    mkdir -p /tmp/opencode
    H3_BUILD_LOG="$(mktemp /tmp/opencode/h3-origin-build.XXXXXX.log)"
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

  exec unshare --user --map-root-user --mount --net --fork \
    env TUN_HARNESS_INNER=1 TUN_HARNESS_ROOT="$ROOT" TUN_HARNESS_SELF="$SELF" \
    TUN_H3_BIN="$H3_ORIGIN_BIN" TUN_H3_BUILD_ERROR="$H3_BUILD_ERROR" \
    TUN_H3_BUILD_LOG="$H3_BUILD_LOG" \
    bash "$SELF" "$@"
fi

ROOT="${TUN_HARNESS_ROOT:-$ROOT}"
SELF="${TUN_HARNESS_SELF:-$SELF}"
# shellcheck source=../../scripts/dev-env.sh
source "$ROOT/scripts/dev-env.sh"

PYTHON="${PYTHON:-python3}"
SING_BOX="${SING_BOX:-/tmp/opencode/bench/bin/sing-box}"
XRAY_BIN="${XRAY_BIN:-/tmp/opencode/xray-server-compare/xray}"
TEST_CONFIG="${TEST_CONFIG:-/tmp/opencode/beam-test/beam.toml}"
SKIP_BUILD="${SKIP_BUILD:-0}"
UDP_MODE="${UDP_MODE:-xudp}"
PROFILE="debug"
CONTROL=0
OUT="${TUN_OUT:-}"
BEAM_ADDR="10.10.1.1:443"
CLIENT_ADDR="10.10.1.2/24"
SERVER_ADDR="10.10.1.1/24"
TARGET_ADDR="10.10.2.2/24"
SERVER_TARGET_ADDR="10.10.2.1/24"
TARGET_V6="fd00:2::2/64"
SERVER_TARGET_V6="fd00:2::1/64"
COVER="10.10.2.2:4443"
H3_ORIGIN_BIN="${H3_ORIGIN_BIN:-${TUN_H3_BIN:-$HERE/h3-origin/target/debug/h3-origin}}"
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
    --help|-h)
      sed -n '2,40p' "$SELF" | sed 's/^# \{0,1\}//'
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
for command in "$PYTHON" ip curl dig cargo; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "tun-harness: required command not found: $command" >&2
    exit 1
  fi
done
if [ "$CONTROL" = "1" ] && [ ! -x "$XRAY_BIN" ]; then
  echo "tun-harness: --control requested but Xray is not executable: $XRAY_BIN" >&2
  exit 1
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
  RUN_DIR="/tmp/opencode/beam-tun/$STAMP-$$"
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
: > "$BEAM_TSV"
: > "$XRAY_TSV"
if [ -n "$H3_BUILD_LOG" ] && [ -f "$H3_BUILD_LOG" ]; then
  cp "$H3_BUILD_LOG" "$LOG_DIR/h3-origin-build.log" 2>/dev/null || true
fi

BEAM_PID=""
SINGBOX_PID=""
SERVICES_PID=""
H3_ORIGIN_PID=""
H3_READY=0
XRAY_PID=""
NAMESPACES=(tun-client tun-server tun-target)
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
  stop_pid "$BEAM_PID"
  stop_pid "$XRAY_PID"
  stop_pid "$H3_ORIGIN_PID"
  stop_pid "$SERVICES_PID"
  for namespace in "${NAMESPACES[@]}"; do
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

print_summary() {
  local beam_pass beam_blocked beam_failed
  beam_pass=$(count_status "$BEAM_TSV" PASS)
  beam_blocked=$(count_status "$BEAM_TSV" BLOCKED)
  beam_failed=$(count_status "$BEAM_TSV" FAIL)
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
  {
    echo "run_dir=$RUN_DIR"
    echo "beam=$BEAM_BIN"
    echo "sing-box=$SING_BOX"
    echo "profile=$PROFILE"
    echo "control=$CONTROL"
    echo "udp_mode=$UDP_MODE"
  } > "$RUN_DIR/environment.txt"
  "$SING_BOX" version > "$RUN_DIR/singbox-version.txt" 2>&1 || true
  if [ -x "$XRAY_BIN" ]; then
    "$XRAY_BIN" version > "$RUN_DIR/xray-version.txt" 2>&1 || true
  fi
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
  exit 0
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
  blocked_file "$TUN_BLOCK_REASON"
  finish
fi

mount -t tmpfs tmpfs /run >/dev/null 2>&1 \
  || { fail_harness "could not mount tmpfs on /run"; exit 1; }
mkdir -p /run/netns

for namespace in "${NAMESPACES[@]}"; do
  ip netns add "$namespace" \
    || { fail_harness "could not create network namespace $namespace"; exit 1; }
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
  blocked_file "$TUN_BLOCK_REASON"
  finish
fi

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
if [ -z "$H3_ORIGIN_ERROR" ]; then
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
ip netns exec tun-target "$PYTHON" "$HERE/services.py" \
  "${TARGET_ARGS[@]}" \
  > "$TARGET_LOG" 2>&1 &
SERVICES_PID=$!
if ! wait_for_log "$TARGET_LOG" "target: READY" "$SERVICES_PID" 15; then
  fail_harness "target services did not become ready"
  tail -n 40 "$TARGET_LOG" >&2 || true
  exit 1
fi

log "starting beam on $BEAM_ADDR"
ip netns exec tun-server "$BEAM_BIN" --config "$CONFIG_DIR/beam.toml" \
  > "$BEAM_LOG" 2>&1 &
BEAM_PID=$!
if ! wait_for_log "$BEAM_LOG" "beam listening" "$BEAM_PID" 15; then
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
  elif has_marker "$H3_LOG" "$origin_start" "-> 200"; then
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

run_suite beam

if [ "$CONTROL" = "1" ]; then
  log "stopping beam and starting the stock Xray control"
  stop_pid "$BEAM_PID"
  BEAM_PID=""
  ip netns exec tun-server "$XRAY_BIN" run -c "$CONFIG_DIR/xray-server.json" \
    > "$XRAY_LOG" 2>&1 &
  XRAY_PID=$!
  if ! wait_for_command "$XRAY_PID" 20 \
      ip netns exec tun-server "$PYTHON" -c 'import socket; socket.create_connection(("10.10.1.1", 443), 0.2).close()'; then
    fail_harness "stock Xray control did not accept connections on $BEAM_ADDR"
    tail -n 40 "$XRAY_LOG" >&2 || true
    exit 1
  fi
  run_suite xray
fi

finish
