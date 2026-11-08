#!/usr/bin/env bash
# Local performance benchmark: stock Xray v26.3.27 vs beam.
#
# Topology (one private user + mount + network namespace):
#
#   client ns                         server ns                     target ns
#   10.10.1.2/24 -- vc | sc -- 10.10.1.1
#                                     10.10.2.1/24 -- vs | ts -- 10.10.2.2/24
#   sing-box TUN 198.18.0.1/15        VLESS+REALITY+Vision :443   HTTP :8080
#   routes 10.10.2.0/24 to tun0                                   HTTPS :4443
#                                                                 UDP echo :9999
#                                                                 DNS :53
#                                                                 HTTP/3 UDP :4443
#                                                                 iperf3 :5201
#
# The measured path never leaves the host. The client config, target services,
# REALITY fixture, payload and CPU masks are identical for both arms; only the
# server binary and its semantically equivalent config change.
#
# Usage:
#   bash bench/run.sh [--reps N] [--duration SEC] [--arms stock,beam]
#                     [--out DIR] [--quick] [--no-build]
#
# Defaults: 3 repetitions, 10 s per bulk scenario, both arms, release beam
# build, results under bench/results/<UTC timestamp>/.
#
# Environment:
#   SING_BOX      sing-box binary (default: sing-box from PATH)
#   XRAY_BIN      stock Xray (default: xray from PATH)
#   IPERF3        iperf3 binary (default: iperf3 from PATH)
#   IPERF3_LIB    optional LD_LIBRARY_PATH for iperf3
#   TEST_CONFIG   REALITY fixture (default: config.example.toml)
#   H3_ORIGIN_BIN prebuilt tests/tun/h3-origin binary
#   SKIP_BUILD=1  reuse target/release/beam and the H3 origin binary
#
# The script re-execs itself under `unshare --user --map-root-user --mount --net`.
# Every process is killed and every namespace is removed in the exit trap.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SELF="$HERE/run.sh"
INNER="${BENCH_INNER:-0}"
ORIGINAL_ARGS=("$@")

REPS="${BENCH_REPS:-3}"
DURATION="${BENCH_DURATION:-10}"
ARMS="${BENCH_ARMS:-stock,beam}"
OUT=""
QUICK=0
REPS_SET=0
DURATION_SET=0
SKIP_BUILD="${SKIP_BUILD:-0}"
SERVER_CPU="${BENCH_SERVER_CPU:-2}"
CLIENT_CPU="${BENCH_CLIENT_CPU:-1}"
TARGET_CPU="${BENCH_TARGET_CPU:-3}"
DRIVER_CPU="${BENCH_DRIVER_CPU:-}"
CLIENT_CPUS="${BENCH_CLIENT_CPUS:-1}"
RTT_MS="${BENCH_RTT_MS:-0}"
MAX_LOAD="${BENCH_MAX_LOAD:-0.3}"
PERF="${BENCH_PERF:-0}"
PERF_EVENTS="${BENCH_PERF_EVENTS:-task-clock,context-switches,cpu-migrations,page-faults,syscalls:sys_enter_read,syscalls:sys_enter_write,syscalls:sys_enter_recvfrom,syscalls:sys_enter_sendto,syscalls:sys_enter_splice,sched:sched_wakeup,sched:sched_switch}"
HTTPS_PARALLEL="${BENCH_HTTPS_PARALLEL:-1}"
LOG_LEVEL="${BENCH_LOG_LEVEL:-warn}"
SCENARIOS="${BENCH_SCENARIOS:-all}"
REPORT="${BENCH_REPORT:-1}"

PYTHON="${PYTHON:-python3}"
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/beam"
SING_BOX="${SING_BOX:-sing-box}"
XRAY_BIN="${XRAY_BIN:-xray}"
TEST_CONFIG="${TEST_CONFIG:-$ROOT/config.example.toml}"
IPERF3="${IPERF3:-iperf3}"
IPERF3_LIB="${IPERF3_LIB:-}"
TC="${TC:-tc}"
H3_ORIGIN_BIN="${H3_ORIGIN_BIN:-${BENCH_H3_BIN:-$HERE/../tests/tun/h3-origin/target/debug/h3-origin}}"

usage() {
  sed -n '2,45p' "$SELF" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --reps)
      shift
      [ $# -gt 0 ] || { echo "bench: --reps needs a number" >&2; exit 2; }
      REPS="$1"
      REPS_SET=1
      ;;
    --duration)
      shift
      [ $# -gt 0 ] || { echo "bench: --duration needs seconds" >&2; exit 2; }
      DURATION="$1"
      DURATION_SET=1
      ;;
    --arms)
      shift
      [ $# -gt 0 ] || { echo "bench: --arms needs a list" >&2; exit 2; }
      ARMS="$1"
      ;;
    --out)
      shift
      [ $# -gt 0 ] || { echo "bench: --out needs a directory" >&2; exit 2; }
      OUT="$1"
      ;;
    --server-cpu)
      shift
      [ $# -gt 0 ] || { echo "bench: --server-cpu needs a CPU" >&2; exit 2; }
      SERVER_CPU="$1"
      ;;
    --client-cpu)
      shift
      [ $# -gt 0 ] || { echo "bench: --client-cpu needs a CPU" >&2; exit 2; }
      CLIENT_CPU="$1"
      ;;
    --target-cpu)
      shift
      [ $# -gt 0 ] || { echo "bench: --target-cpu needs a CPU" >&2; exit 2; }
      TARGET_CPU="$1"
      ;;
    --client-cpus)
      shift
      [ $# -gt 0 ] || { echo "bench: --client-cpus needs a list" >&2; exit 2; }
      CLIENT_CPUS="$1"
      CLIENT_CPU="${CLIENT_CPUS%%,*}"
      ;;
    --driver-cpu)
      shift
      [ $# -gt 0 ] || { echo "bench: --driver-cpu needs a CPU" >&2; exit 2; }
      DRIVER_CPU="$1"
      ;;
    --max-load)
      shift
      [ $# -gt 0 ] || { echo "bench: --max-load needs a number" >&2; exit 2; }
      MAX_LOAD="$1"
      ;;
    --rtt-ms)
      shift
      [ $# -gt 0 ] || { echo "bench: --rtt-ms needs milliseconds" >&2; exit 2; }
      RTT_MS="$1"
      ;;
    --quick)
      QUICK=1
      ;;
    --no-build)
      SKIP_BUILD=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "bench: unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

if [ "$QUICK" = "1" ]; then
  [ "$REPS_SET" = "1" ] || REPS=1
  [ "$DURATION_SET" = "1" ] || DURATION=3
fi

case "$REPS" in
  ''|*[!0-9]*) echo "bench: --reps must be a positive integer" >&2; exit 2 ;;
esac
case "$DURATION" in
  ''|*[!0-9]*) echo "bench: --duration must be a positive integer" >&2; exit 2 ;;
esac
case "$RTT_MS" in
  ''|*[!0-9]*) echo "bench: --rtt-ms must be a non-negative integer" >&2; exit 2 ;;
esac
[ "$REPS" -ge 1 ] || { echo "bench: --reps must be >= 1" >&2; exit 2; }
[ "$DURATION" -ge 2 ] || { echo "bench: --duration must be >= 2" >&2; exit 2; }
case "$PERF" in 0|1) ;; *) echo "bench: BENCH_PERF must be 0 or 1" >&2; exit 2 ;; esac
case "$HTTPS_PARALLEL" in
  ''|*[!0-9]*) echo "bench: BENCH_HTTPS_PARALLEL must be a positive integer" >&2; exit 2 ;;
esac
[ "$HTTPS_PARALLEL" -ge 1 ] || { echo "bench: BENCH_HTTPS_PARALLEL must be >= 1" >&2; exit 2; }
case "$REPORT" in 0|1) ;; *) echo "bench: BENCH_REPORT must be 0 or 1" >&2; exit 2 ;; esac

# The documented vps-1c model runs the driver on the client core. A caller can
# still separate it with --driver-cpu (useful for client-bound sensitivity runs).
if [ -z "$DRIVER_CPU" ]; then
  DRIVER_CPU="$CLIENT_CPU"
fi

NPROC="$(nproc)"
for core in "$SERVER_CPU" "$CLIENT_CPU" "$TARGET_CPU" "$DRIVER_CPU"; do
  case "$core" in
    ''|*[!0-9]*) echo "bench: CPU ids must be integers" >&2; exit 2 ;;
  esac
  [ "$core" -ge 0 ] && [ "$core" -lt "$NPROC" ] \
    || { echo "bench: CPU $core is outside 0..$((NPROC - 1))" >&2; exit 2; }
done
CLIENT_CPU_LIST=()
IFS=',' read -r -a CLIENT_CPU_LIST <<< "$CLIENT_CPUS"
[ "${#CLIENT_CPU_LIST[@]}" -ge 1 ] || { echo "bench: --client-cpus is empty" >&2; exit 2; }
for core in "${CLIENT_CPU_LIST[@]}"; do
  case "$core" in
    ''|*[!0-9]*) echo "bench: client CPU ids must be integers" >&2; exit 2 ;;
  esac
  [ "$core" -ge 0 ] && [ "$core" -lt "$NPROC" ] \
    || { echo "bench: client CPU $core is outside 0..$((NPROC - 1))" >&2; exit 2; }
  [ "$core" != "$SERVER_CPU" ] && [ "$core" != "$TARGET_CPU" ] \
    || { echo "bench: client CPU $core conflicts with another role" >&2; exit 2; }
done
[ "$SERVER_CPU" != "$TARGET_CPU" ] && [ "$SERVER_CPU" != "$DRIVER_CPU" ] \
  && [ "$TARGET_CPU" != "$DRIVER_CPU" ] \
  || { echo "bench: server/target/driver CPUs must be distinct" >&2; exit 2; }
GOMAXPROCS_CLIENT="${BENCH_CLIENT_GOMAXPROCS:-${#CLIENT_CPU_LIST[@]}}"
CLIENT_MASK_SPEC="$(IFS=','; echo "${CLIENT_CPU_LIST[*]}")"

IFS=',' read -r -a ARM_LIST <<< "$ARMS"
for arm in "${ARM_LIST[@]}"; do
  case "$arm" in
    stock|beam) ;;
    *) echo "bench: unknown arm '$arm' (use stock,beam)" >&2; exit 2 ;;
  esac
done

if [ "$INNER" != "1" ]; then
  if ! command -v unshare >/dev/null 2>&1; then
    echo "bench: unshare is required" >&2
    exit 1
  fi
  if ! unshare --user --map-root-user --net true 2>/dev/null; then
    echo "bench: unprivileged user+network namespaces are unavailable" >&2
    exit 1
  fi

  BUILD_LOG="$(mktemp "${TMPDIR:-/tmp}/beam-bench-build.XXXXXX.log")"
  H3_BUILD_LOG="$(mktemp "${TMPDIR:-/tmp}/beam-bench-h3-build.XXXXXX.log")"
  # shellcheck source=../scripts/dev-env.sh
  source "$ROOT/scripts/dev-env.sh"

  if [ "$SKIP_BUILD" != "1" ]; then
    echo "bench: building beam release" >&2
    if ! (cd "$ROOT" && cargo build --locked --release -p beam) > "$BUILD_LOG" 2>&1; then
      echo "bench: cargo build failed; see $BUILD_LOG" >&2
      tail -n 20 "$BUILD_LOG" >&2 || true
      exit 1
    fi
  else
    : > "$BUILD_LOG"
  fi

  H3_BLOCKED=""
  if [ -n "${H3_ORIGIN_BIN:-}" ] && [ -x "$H3_ORIGIN_BIN" ]; then
    :
  elif [ "$SKIP_BUILD" = "1" ]; then
    H3_BLOCKED="H3 origin was not built (--no-build/SKIP_BUILD=1) and $H3_ORIGIN_BIN is missing"
  else
    echo "bench: building the local HTTP/3 origin" >&2
    if cargo build --locked --manifest-path "$HERE/../tests/tun/h3-origin/Cargo.toml" \
        > "$H3_BUILD_LOG" 2>&1; then
      H3_ORIGIN_BIN="$HERE/../tests/tun/h3-origin/target/debug/h3-origin"
    else
      H3_BLOCKED="cargo build for tests/tun/h3-origin failed: $(tail -n 1 "$H3_BUILD_LOG" | tr '\t\n' '  ')"
    fi
  fi
  if [ -z "$H3_BLOCKED" ] && [ ! -x "$H3_ORIGIN_BIN" ]; then
    H3_BLOCKED="H3 origin binary is missing: $H3_ORIGIN_BIN"
  fi

  exec unshare --user --map-root-user --mount --net --fork \
    env BENCH_INNER=1 BENCH_ROOT="$ROOT" BENCH_SELF="$SELF" \
    BENCH_H3_BIN="$H3_ORIGIN_BIN" BENCH_H3_BLOCKED="$H3_BLOCKED" \
    BENCH_BUILD_LOG="$BUILD_LOG" BENCH_H3_BUILD_LOG="$H3_BUILD_LOG" \
    BENCH_REPS="$REPS" BENCH_DURATION="$DURATION" BENCH_ARMS="$ARMS" \
    BENCH_SERVER_CPU="$SERVER_CPU" BENCH_CLIENT_CPU="$CLIENT_CPU" \
    BENCH_TARGET_CPU="$TARGET_CPU" BENCH_DRIVER_CPU="$DRIVER_CPU" BENCH_CLIENT_CPUS="$CLIENT_CPUS" BENCH_RTT_MS="$RTT_MS" BENCH_MAX_LOAD="$MAX_LOAD" \
    BENCH_PERF="$PERF" BENCH_PERF_EVENTS="$PERF_EVENTS" \
    BENCH_HTTPS_PARALLEL="$HTTPS_PARALLEL" BENCH_LOG_LEVEL="$LOG_LEVEL" \
    BENCH_SCENARIOS="$SCENARIOS" BENCH_REPORT="$REPORT" \
    SING_BOX="$SING_BOX" XRAY_BIN="$XRAY_BIN" TEST_CONFIG="$TEST_CONFIG" \
    IPERF3="$IPERF3" IPERF3_LIB="$IPERF3_LIB" TC="$TC" H3_ORIGIN_BIN="$H3_ORIGIN_BIN" \
    bash "$SELF" "${ORIGINAL_ARGS[@]}"
fi

ROOT="${BENCH_ROOT:-$ROOT}"
SELF="${BENCH_SELF:-$SELF}"
# shellcheck source=../scripts/dev-env.sh
source "$ROOT/scripts/dev-env.sh"

H3_ORIGIN_BIN="${BENCH_H3_BIN:-$H3_ORIGIN_BIN}"
H3_BLOCKED="${BENCH_H3_BLOCKED:-}"
H3_BUILD_LOG="${BENCH_H3_BUILD_LOG:-}"
BUILD_LOG="${BENCH_BUILD_LOG:-}"

BEAM_ADDR="10.10.1.1:443"
CLIENT_ADDR="10.10.1.2/24"
SERVER_ADDR="10.10.1.1/24"
TARGET_ADDR="10.10.2.2/24"
SERVER_TARGET_ADDR="10.10.2.1/24"
TARGET_V6="fd00:2::2/64"
SERVER_TARGET_V6="fd00:2::1/64"
COVER="10.10.2.2:4443"
TARGET_HOST="10.10.2.2"
IPERF3_PORT=5201
UDP_PORT=9999
DNS_PORT=53

HTTPS_MIB="${BENCH_HTTPS_MIB:-64}"
H3_REQUESTS="${BENCH_H3_REQUESTS:-20}"
DNS_COUNT="${BENCH_DNS_COUNT:-200}"
UDP_COUNT="${BENCH_UDP_COUNT:-5000}"
UDP_LATENCY_COUNT="${BENCH_UDP_LATENCY_COUNT:-200}"
if [ "$QUICK" = "1" ]; then
  HTTPS_MIB="${BENCH_HTTPS_MIB:-16}"
  H3_REQUESTS="${BENCH_H3_REQUESTS:-5}"
  DNS_COUNT="${BENCH_DNS_COUNT:-50}"
  UDP_COUNT="${BENCH_UDP_COUNT:-1000}"
  UDP_LATENCY_COUNT="${BENCH_UDP_LATENCY_COUNT:-50}"
fi

NAMESPACES=(tun-client tun-server tun-target)

log() { printf 'bench: %s\n' "$*"; }
die() {
  printf 'bench: HARNESS FAILURE: %s\n' "$*" >&2
  exit 1
}

if [ "$PERF" = "1" ] && [ "$(id -u)" -ne 0 ]; then
  die "BENCH_PERF=1 requires root; run with BENCH_INNER=1"
fi

scenario_enabled() {
  [ "$SCENARIOS" = "all" ] && return 0
  case ",$SCENARIOS," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_bin() {
  if [ -x "$1" ]; then
    printf '%s\n' "$1"
  else
    command -v "$1" 2>/dev/null
  fi
}

for command in "$PYTHON" ip curl taskset timeout sha256sum; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done
[ -f "$TEST_CONFIG" ] || die "REALITY fixture not found: $TEST_CONFIG (set TEST_CONFIG)"
SING_BOX="$(resolve_bin "$SING_BOX")" || die "sing-box not found: $SING_BOX (set SING_BOX)"
[ -c /dev/net/tun ] || die "/dev/net/tun is unavailable"
IPERF3="$(resolve_bin "$IPERF3")" || die "iperf3 not found: $IPERF3 (set IPERF3)"
if [ "$RTT_MS" != "0" ]; then
  TC="$(resolve_bin "$TC")" || die "tc not found: $TC (set TC)"
fi
export LD_LIBRARY_PATH="$IPERF3_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$IPERF3" --version >/dev/null 2>&1 || die "iperf3 cannot run (check IPERF3_LIB)"
if [[ " ${ARM_LIST[*]} " == *" stock "* ]]; then
  XRAY_BIN="$(resolve_bin "$XRAY_BIN")" || die "stock Xray not found: $XRAY_BIN (set XRAY_BIN)"
fi
if ! curl --version 2>/dev/null | grep -qi 'HTTP3'; then
  H3_BLOCKED="${H3_BLOCKED:-the local curl has no HTTP/3 support; cannot send a QUIC Initial}"
fi

umask 077
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="$STAMP-$$"
if [ -n "$OUT" ]; then
  RUN_DIR="$OUT"
else
  RUN_DIR="$ROOT/bench/results/$STAMP"
fi
mkdir -p "$RUN_DIR/logs" "$RUN_DIR/raw" "$RUN_DIR/config"
chmod 700 "$RUN_DIR"
RUN_DIR="$(cd "$RUN_DIR" && pwd)"
LOG_DIR="$RUN_DIR/logs"
CONFIG_DIR="$RUN_DIR/config"
RAW_DIR="$RUN_DIR/raw"
: > "$RUN_DIR/masks.tsv"
if [ -n "$BUILD_LOG" ] && [ -s "$BUILD_LOG" ]; then
  cp "$BUILD_LOG" "$LOG_DIR/build.log" 2>/dev/null || true
fi
if [ -n "$H3_BUILD_LOG" ] && [ -s "$H3_BUILD_LOG" ]; then
  cp "$H3_BUILD_LOG" "$LOG_DIR/h3-origin-build.log" 2>/dev/null || true
fi

SINGBOX_PID=""
SERVER_PID=""
SERVICES_PID=""
IPERF3_PID=""
H3_PID=""
H3_READY=0
IPV6_AVAILABLE=0
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOAD_BEFORE="$(awk '{print $1}' /proc/loadavg)"
YELLOW=''
if awk -v host_load="$LOAD_BEFORE" -v max_load="$MAX_LOAD" 'BEGIN { exit !(host_load > max_load) }'; then
  log "WARNING: host load $LOAD_BEFORE exceeds $MAX_LOAD; results may be noisy"
  YELLOW="host load $LOAD_BEFORE exceeds $MAX_LOAD"
fi

stop_pid() {
  local pid="${1:-}"
  [ -n "$pid" ] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 40); do
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
  stop_pid "$SERVER_PID"
  stop_pid "$H3_PID"
  stop_pid "$IPERF3_PID"
  stop_pid "$SERVICES_PID"
  for namespace in "${NAMESPACES[@]}"; do
    ip netns del "$namespace" >/dev/null 2>&1
  done
  printf 'bench: run directory: %s\n' "$RUN_DIR" >&2
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

wait_for_log() {
  local file=$1 pattern=$2 pid=${3:-} timeout=${4:-15}
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

wait_for_port() {
  local namespace=$1 host=$2 port=$3 pid=${4:-} timeout=${5:-15}
  local steps=$((timeout * 10))
  for _ in $(seq 1 "$steps"); do
    if ip netns exec "$namespace" "$PYTHON" - "$host" "$port" <<'PY' >/dev/null 2>&1
import socket
import sys

sock = socket.create_connection((sys.argv[1], int(sys.argv[2])), 0.3)
sock.close()
PY
    then
      return 0
    fi
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

mask_of() {
  local pid=$1
  taskset -pc "$pid" 2>/dev/null | sed 's/^.*: //' | tr -d ' ' || true
}

# ---------------------------------------------------------------------------
# Namespace topology
# ---------------------------------------------------------------------------

mount -t tmpfs tmpfs /run >/dev/null 2>&1 || die "could not mount tmpfs on /run"
mkdir -p /run/netns
for namespace in "${NAMESPACES[@]}"; do
  ip netns add "$namespace" || die "could not create network namespace $namespace"
  ip netns exec "$namespace" ip link set lo up || die "could not bring up lo in $namespace"
done

ip link add vc type veth peer name sc || die "could not create the client/server veth pair"
ip link set vc netns tun-client
ip link set sc netns tun-server
ip netns exec tun-client ip addr add "$CLIENT_ADDR" dev vc
ip netns exec tun-client ip link set vc txqueuelen 10000
ip netns exec tun-client ip link set vc up
ip netns exec tun-server ip addr add "$SERVER_ADDR" dev sc
ip netns exec tun-server ip link set sc txqueuelen 10000
ip netns exec tun-server ip link set sc up

ip link add vs type veth peer name ts || die "could not create the server/target veth pair"
ip link set vs netns tun-server
ip link set ts netns tun-target
ip netns exec tun-server ip addr add "$SERVER_TARGET_ADDR" dev vs
ip netns exec tun-server ip link set vs txqueuelen 10000
ip netns exec tun-server ip link set vs up
ip netns exec tun-target ip addr add "$TARGET_ADDR" dev ts
ip netns exec tun-target ip link set ts txqueuelen 10000
ip netns exec tun-target ip link set ts up

if [ "$RTT_MS" -gt 0 ]; then
  HALF_MS="$(awk -v rtt="$RTT_MS" 'BEGIN { printf "%.3f", rtt / 2 }')ms"
  log "applying netem delay $HALF_MS on each side (total RTT ${RTT_MS}ms)"
  ip netns exec tun-client "$TC" qdisc add dev vc root netem delay "$HALF_MS" limit 20000 \
    || die "could not add netem delay on vc"
  ip netns exec tun-server "$TC" qdisc add dev sc root netem delay "$HALF_MS" limit 20000 \
    || die "could not add netem delay on sc"
  ip netns exec tun-client "$TC" -s qdisc show > "$LOG_DIR/tc-client.txt" 2>&1
  ip netns exec tun-server "$TC" -s qdisc show > "$LOG_DIR/tc-server.txt" 2>&1
fi
# The lab uses one peer per veth; DAD adds no value and delays IPv6 binds.
ip netns exec tun-server sysctl -qw net.ipv6.conf.vs.accept_dad=0 2>/dev/null || true
ip netns exec tun-target sysctl -qw net.ipv6.conf.ts.accept_dad=0 2>/dev/null || true

IPV6_AVAILABLE=1
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
  if ! ip netns exec tun-target ip -6 addr show dev ts | grep -q 'fd00:2::2'; then
    IPV6_AVAILABLE=0
  fi
fi

# ---------------------------------------------------------------------------
# Configs and target services
# ---------------------------------------------------------------------------

log "generating the test certificate"
"$SING_BOX" generate tls-keypair "$TARGET_HOST" > "$CONFIG_DIR/tls.pem" 2> "$LOG_DIR/keygen.err" \
  || die "sing-box could not generate a TLS test key pair"
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
if [[ " ${ARM_LIST[*]} " == *" stock "* ]]; then
  XRAY_FLAG=(--xray)
fi
"$PYTHON" "$HERE/../tests/tun/config.py" \
  --test-config "$TEST_CONFIG" \
  --out-dir "$CONFIG_DIR" \
  --listen "$BEAM_ADDR" \
  --cover "$COVER" \
  --singbox \
  "${XRAY_FLAG[@]}" \
  --log-level "$LOG_LEVEL" \
  || die "could not render the beam/sing-box/Xray configs"

log "generating $HTTPS_MIB MiB HTTPS payload"
dd if=/dev/urandom of="$CONFIG_DIR/large.bin" bs=1M count="$HTTPS_MIB" status=none \
  || die "could not create the HTTPS payload"
HTTPS_BYTES=$((HTTPS_MIB * 1024 * 1024))
HTTPS_SHA="$(sha256sum "$CONFIG_DIR/large.bin" | awk '{print $1}')"

if [ -z "$H3_BLOCKED" ]; then
  log "starting local HTTP/3 origin on $TARGET_HOST:4443 (UDP)"
  # The origin is deliberately not pinned: pinning it to the target core
  # introduced sporadic HTTP/3 stream resets after the response was sent.
  ip netns exec tun-target "$H3_ORIGIN_BIN" --listen "$TARGET_HOST:4443" \
    > "$LOG_DIR/h3-origin.log" 2>&1 &
  H3_PID=$!
  if wait_for_log "$LOG_DIR/h3-origin.log" "h3-origin: READY" "$H3_PID" 15; then
    H3_READY=1
  else
    H3_BLOCKED="local HTTP/3 origin did not become ready: $(tail -n 2 "$LOG_DIR/h3-origin.log" | tr '\n' ' ')"
    stop_pid "$H3_PID"
    H3_PID=""
    log "$H3_BLOCKED"
  fi
else
  log "HTTP/3 origin unavailable: $H3_BLOCKED"
fi

log "starting target services"
TARGET_ARGS=(
  --http "$TARGET_HOST:8080"
  --tls "$TARGET_HOST:4443"
  --udp "$TARGET_HOST:$UDP_PORT"
  --dns "$TARGET_HOST:$DNS_PORT"
  --large-file "$CONFIG_DIR/large.bin"
  --quiet
  --cert "$CONFIG_DIR/target.crt"
  --key "$CONFIG_DIR/target.key"
)
if [ "$IPV6_AVAILABLE" = "1" ]; then
  TARGET_ARGS+=(--http6 "[fd00:2::2]:8080" --udp6 "[fd00:2::2]:$UDP_PORT" --dns6 "[fd00:2::2]:$DNS_PORT")
fi
ip netns exec tun-target taskset -c "$TARGET_CPU" "$PYTHON" "$HERE/../tests/tun/services.py" \
  "${TARGET_ARGS[@]}" > "$LOG_DIR/target.log" 2>&1 &
SERVICES_PID=$!
wait_for_log "$LOG_DIR/target.log" "target: READY" "$SERVICES_PID" 15 \
  || die "target services did not become ready"

log "starting iperf3 server on $TARGET_HOST:$IPERF3_PORT"
ip netns exec tun-target taskset -c "$TARGET_CPU" "$IPERF3" -s -p "$IPERF3_PORT" \
  > "$LOG_DIR/iperf3-server.log" 2>&1 &
IPERF3_PID=$!
wait_for_port tun-target "$TARGET_HOST" "$IPERF3_PORT" "$IPERF3_PID" 10 \
  || die "iperf3 server did not start"

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
{
  echo "run_id=$RUN_ID"
  echo "worktree=$ROOT"
  echo "reps=$REPS"
  echo "duration_s=$DURATION"
  echo "arms=$ARMS"
  echo "server_cpu=$SERVER_CPU client_cpus=$CLIENT_MASK_SPEC target_cpu=$TARGET_CPU driver_cpu=$DRIVER_CPU"
echo "rtt_ms=$RTT_MS"
  echo "singbox=$SING_BOX"
  echo "xray=$XRAY_BIN"
  echo "beam=$ROOT/target/release/beam"
  echo "iperf3=$IPERF3"
  echo "iperf3_lib=$IPERF3_LIB"
  echo "h3_origin=$H3_ORIGIN_BIN"
  echo "h3_ready=$H3_READY"
  echo "https_mib=$HTTPS_MIB"
  echo "https_sha256=$HTTPS_SHA"
  echo "host_load_before=$LOAD_BEFORE"
} > "$RUN_DIR/environment.txt"

# ---------------------------------------------------------------------------
# Arm lifecycle
# ---------------------------------------------------------------------------

SERVER_MASK=""
CLIENT_MASK=""
TARGET_MASK=""

start_arm() {
  local arm=$1 rep=$2
  local server_log="$LOG_DIR/$arm-r$rep-server.log"
  local client_log="$LOG_DIR/$arm-r$rep-client.log"
  : > "$server_log"
  : > "$client_log"

  if [ "$arm" = "beam" ]; then
    ip netns exec tun-server taskset -c "$SERVER_CPU" \
      "$ROOT/target/release/beam" --config "$CONFIG_DIR/beam.toml" > "$server_log" 2>&1 &
  else
    ip netns exec tun-server taskset -c "$SERVER_CPU" \
      env GOMAXPROCS=1 "$XRAY_BIN" run -c "$CONFIG_DIR/xray-server.json" > "$server_log" 2>&1 &
  fi
  SERVER_PID=$!
  if ! wait_for_port tun-server 10.10.1.1 443 "$SERVER_PID" 20; then
    tail -n 40 "$server_log" >&2 || true
    die "$arm did not start listening on $BEAM_ADDR"
  fi
  SERVER_MASK="$(mask_of "$SERVER_PID")"
  taskset -c "$CLIENT_MASK_SPEC" ip netns exec tun-client \
    env GOMAXPROCS="$GOMAXPROCS_CLIENT" "$SING_BOX" run -c "$CONFIG_DIR/singbox.json" \
    > "$client_log" 2>&1 &
  SINGBOX_PID=$!
  local ready=0
  for _ in $(seq 1 200); do
    if ip netns exec tun-client ip link show tun0 >/dev/null 2>&1; then
      ready=1
      break
    fi
    kill -0 "$SINGBOX_PID" 2>/dev/null || break
    sleep 0.1
  done
  if [ "$ready" != "1" ]; then
    tail -n 60 "$client_log" >&2 || true
    die "sing-box did not create tun0"
  fi
  ip netns exec tun-client ip link set tun0 up 2>/dev/null || true
  ip netns exec tun-client ip link set tun0 txqueuelen 10000 2>/dev/null || true
  ip netns exec tun-client ip route replace 10.10.2.0/24 dev tun0 \
    || die "could not route 10.10.2.0/24 into tun0"
  if [ "$IPV6_AVAILABLE" = "1" ]; then
    ip netns exec tun-client ip -6 route replace fd00:2::/64 dev tun0 2>/dev/null || IPV6_AVAILABLE=0
  fi
  if ! ip netns exec tun-client ip route get "$TARGET_HOST" 2>/dev/null | grep -q 'dev tun0'; then
    die "$TARGET_HOST does not resolve to tun0"
  fi
  CLIENT_MASK="$(mask_of "$SINGBOX_PID")"
  TARGET_MASK="$(mask_of "$SERVICES_PID")"
  printf '%s\t%s\tserver\t%s\t%s\n' "$arm" "$rep" "$SERVER_CPU" "$SERVER_MASK" >> "$RUN_DIR/masks.tsv"
  printf '%s\t%s\tclient\t%s\t%s\n' "$arm" "$rep" "$CLIENT_CPU" "$CLIENT_MASK" >> "$RUN_DIR/masks.tsv"
  printf '%s\t%s\ttarget\t%s\t%s\n' "$arm" "$rep" "$TARGET_CPU" "$TARGET_MASK" >> "$RUN_DIR/masks.tsv"
  sleep 0.5
}

stop_arm() {
  stop_pid "$SINGBOX_PID"
  SINGBOX_PID=""
  stop_pid "$SERVER_PID"
  SERVER_PID=""
  ip netns exec tun-client ip link del tun0 >/dev/null 2>&1 || true
}

# One invocation of measure.py inside the client namespace. The measurement
# process and every client tool inherit the client core mask.
measure() {
  local arm=$1 rep=$2 scenario=$3 kind=$4 out=$5
  shift 5
  if [[ "$scenario" != warmup-* ]] && ! scenario_enabled "$scenario"; then
    return 0
  fi
  local perf_pid=""
  local rc=0
  if [ "$PERF" = "1" ]; then
    perf stat -x, -e "$PERF_EVENTS" -p "$SERVER_PID" -o "$out.perf.csv" &
    perf_pid=$!
    sleep 0.5
    if ! kill -0 "$perf_pid" 2>/dev/null; then
      wait "$perf_pid" 2>/dev/null || true
      die "perf stat failed for $scenario"
    fi
  fi
  ip netns exec tun-client taskset -c "$DRIVER_CPU" \
    env LD_LIBRARY_PATH="$IPERF3_LIB" \
    "$PYTHON" "$HERE/measure.py" \
      --run-id "$RUN_ID" --arm "$arm" --rep "$rep" \
      --scenario "$scenario" --kind "$kind" \
      --out "$out" \
      --server-pid "$SERVER_PID" --client-pid "$SINGBOX_PID" \
      --target-pid "$SERVICES_PID" \
      --server-core "$SERVER_CPU" --client-core "$CLIENT_CPU" \
      --target-core "$TARGET_CPU" --driver-core "$DRIVER_CPU" \
      --client-cores "$CLIENT_MASK_SPEC" --all-cores "$NPROC" \
      --iperf3-bin "$IPERF3" \
      "$@" || rc=$?
  if [ -n "$perf_pid" ]; then
    kill -INT "$perf_pid" 2>/dev/null || true
    wait "$perf_pid" 2>/dev/null || true
  fi
  return "$rc"
}

run_warmup() {
  local arm=$1 rep=$2
  local base="$LOG_DIR/warmup-$arm-r$rep"
  local rc=0
  ip netns exec tun-client taskset -c "$DRIVER_CPU" \
    "$IPERF3" -c "$TARGET_HOST" -p "$IPERF3_PORT" -t 2 -P 1 -l 128K -4 \
    > "$base-iperf3.log" 2>&1 || rc=1
  ip netns exec tun-client taskset -c "$DRIVER_CPU" \
    curl --noproxy '*' -k -sS --http1.1 --max-time 60 \
    -o /dev/null "https://$TARGET_HOST:4443/large.bin" \
    > "$base-https.log" 2>&1 || rc=1
  if [ "$H3_READY" = "1" ]; then
    measure "$arm" "$rep" warmup-h3 h3 "$base-h3.json" --url "https://$TARGET_HOST:4443/" \
      --count 2 --max-time 10 > "$base-h3.log" 2>&1 || rc=1
  fi
  measure "$arm" "$rep" warmup-udp udp "$base-udp.json" --host "$TARGET_HOST" --port "$UDP_PORT" \
    --payload 1200 --packet-count 50 --window 8 --latency-count 10 \
    --timeout 1 > "$base-udp.log" 2>&1 || rc=1
  measure "$arm" "$rep" warmup-dns dns "$base-dns.json" --dns-server "$TARGET_HOST" \
    --dns-count 10 --timeout 1 > "$base-dns.log" 2>&1 || rc=1
  if [ "$rc" != "0" ]; then
    log "WARNING: warm-up for $arm r$rep had a failure; see $base-*.log"
  fi
  sleep 0.5
}

run_scenarios() {
  local arm=$1 rep=$2
  local raw="$RAW_DIR"
  log "measuring $arm r$rep"
  measure "$arm" "$rep" tcp-dl-1 iperf3 "$raw/$arm-tcp-dl-1-r$rep.json" \
    --direction download --flows 1 --duration "$DURATION" \
    --target-host "$TARGET_HOST" --iperf3-port "$IPERF3_PORT" \
    || die "measure.py failed for tcp-dl-1/$arm"
  measure "$arm" "$rep" tcp-dl-4 iperf3 "$raw/$arm-tcp-dl-4-r$rep.json" \
    --direction download --flows 4 --duration "$DURATION" \
    --target-host "$TARGET_HOST" --iperf3-port "$IPERF3_PORT" \
    || die "measure.py failed for tcp-dl-4/$arm"
  measure "$arm" "$rep" tcp-ul-1 iperf3 "$raw/$arm-tcp-ul-1-r$rep.json" \
    --direction upload --flows 1 --duration "$DURATION" \
    --target-host "$TARGET_HOST" --iperf3-port "$IPERF3_PORT" \
    || die "measure.py failed for tcp-ul-1/$arm"
  measure "$arm" "$rep" tcp-ul-4 iperf3 "$raw/$arm-tcp-ul-4-r$rep.json" \
    --direction upload --flows 4 --duration "$DURATION" \
    --target-host "$TARGET_HOST" --iperf3-port "$IPERF3_PORT" \
    || die "measure.py failed for tcp-ul-4/$arm"
  measure "$arm" "$rep" https-bulk https "$raw/$arm-https-bulk-r$rep.json" \
    --url "https://$TARGET_HOST:4443/large.bin" --count 3 --https-parallel "$HTTPS_PARALLEL" \
    --expected-size "$HTTPS_BYTES" --max-time 120 \
    || die "measure.py failed for https-bulk/$arm"
  measure "$arm" "$rep" udp-echo udp "$raw/$arm-udp-echo-r$rep.json" \
    --host "$TARGET_HOST" --port "$UDP_PORT" --payload 1200 \
    --packet-count "$UDP_COUNT" --window 32 --latency-count "$UDP_LATENCY_COUNT" \
    --timeout 2 || die "measure.py failed for udp-echo/$arm"
  measure "$arm" "$rep" dns-a dns "$raw/$arm-dns-a-r$rep.json" \
    --dns-server "$TARGET_HOST" --dns-count "$DNS_COUNT" --timeout 2 \
    || die "measure.py failed for dns-a/$arm"
  if [ "$H3_READY" = "1" ]; then
    measure "$arm" "$rep" h3-latency h3 "$raw/$arm-h3-latency-r$rep.json" \
      --url "https://$TARGET_HOST:4443/" --count "$H3_REQUESTS" --max-time 10 \
      || die "measure.py failed for h3-latency/$arm"
  else
    measure "$arm" "$rep" h3-latency h3 "$raw/$arm-h3-latency-r$rep.json" \
      --blocked-reason "$H3_BLOCKED" \
      || die "measure.py failed to record blocked h3-latency/$arm"
  fi
}

for rep in $(seq 1 "$REPS"); do
  if [ $((rep % 2)) -eq 1 ]; then
    ORDER=(stock beam)
  else
    ORDER=(beam stock)
  fi
  for arm in "${ORDER[@]}"; do
    if [[ ! " ${ARM_LIST[*]} " == *" $arm "* ]]; then
      continue
    fi
    start_arm "$arm" "$rep"
    run_warmup "$arm" "$rep"
    run_scenarios "$arm" "$rep"
    stop_arm
  done
done

# ---------------------------------------------------------------------------
# Manifest and report
# ---------------------------------------------------------------------------

LOAD_AFTER="$(awk '{print $1}' /proc/loadavg)"
FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ "$RTT_MS" -gt 0 ]; then
  ip netns exec tun-client "$TC" -s qdisc show > "$LOG_DIR/tc-client-final.txt" 2>&1 || true
  ip netns exec tun-server "$TC" -s qdisc show > "$LOG_DIR/tc-server-final.txt" 2>&1 || true
fi
WARNINGS=()
[ -n "$YELLOW" ] && WARNINGS+=(--warning "$YELLOW")
if awk -v host_load="$LOAD_AFTER" -v max_load="$MAX_LOAD" 'BEGIN { exit !(host_load > max_load) }'; then
  WARNINGS+=(--warning "host load after run $LOAD_AFTER exceeds $MAX_LOAD")
fi
if [ "$H3_READY" != "1" ] && [ -z "$H3_BLOCKED" ]; then
  H3_BLOCKED="HTTP/3 origin did not become ready"
fi

META_ARGS=(
  --out "$RUN_DIR/meta.json"
  --run-id "$RUN_ID"
  --started-at "$STARTED_AT"
  --finished-at "$FINISHED_AT"
  --arms "$ARMS"
  --reps "$REPS"
  --duration "$DURATION"
  --server-cpu "$SERVER_CPU"
  --client-cpu "$CLIENT_CPU"
  --client-cpus "$CLIENT_MASK_SPEC"
  --target-cpu "$TARGET_CPU"
  --driver-cpu "$DRIVER_CPU"
  --rtt-ms "$RTT_MS"
  --server-mask "$SERVER_MASK"
  --client-mask "$CLIENT_MASK"
  --target-mask "$TARGET_MASK"
  --beam-bin "$ROOT/target/release/beam"
  --singbox "$SING_BOX"
  --iperf3 "$IPERF3"
  --host-load-before "$LOAD_BEFORE"
  --host-load-after "$LOAD_AFTER"
)
[ -x "$XRAY_BIN" ] && META_ARGS+=(--stock-bin "$XRAY_BIN")
[ -x "$H3_ORIGIN_BIN" ] && META_ARGS+=(--h3-origin "$H3_ORIGIN_BIN")
META_ARGS+=(--large-file "$CONFIG_DIR/large.bin")
[ -n "$H3_BLOCKED" ] && META_ARGS+=(--h3-blocked-reason "$H3_BLOCKED")
META_ARGS+=("${WARNINGS[@]}")

"$PYTHON" "$HERE/meta.py" "${META_ARGS[@]}" || die "could not write meta.json"
if [ "$REPORT" = "1" ]; then
  "$PYTHON" "$HERE/report.py" --run "$RUN_DIR" || die "could not write the summary"
fi
printf '\nbench: run directory: %s\n' "$RUN_DIR"
