#!/bin/bash
# Server-capacity smoke test without TUN.
#
# Stock Xray client (SOCKS inbound, VLESS+REALITY+Vision outbound) talks to
# either stock Xray or beam on the same loopback target. The client, server,
# target, and driver each get a separate physical CPU. This is not the headline
# full-TUN benchmark; it removes the sing-box TUN client cap and exposes the
# server data path.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/beam"
XRAY="${XRAY_BIN:-xray}"
BEAM="${BEAM_BIN:-$ROOT/target/release/beam}"
PYTHON="${PYTHON:-python3}"
RUN_DIR="${NO_TUN_OUT:-$CACHE_ROOT/no-tun/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
TARGET="$RUN_DIR/target"
LOG="$RUN_DIR/log"
SIZE_MIB="${NO_TUN_SIZE_MIB:-256}"
REPS="${NO_TUN_REPS:-4}"
SERVER_CPU="${NO_TUN_SERVER_CPU:-2}"
CLIENT_CPU="${NO_TUN_CLIENT_CPU:-1}"
TARGET_CPU="${NO_TUN_TARGET_CPU:-0}"
DRIVER_CPU="${NO_TUN_DRIVER_CPU:-3}"
BASE_CONFIG="${TEST_CONFIG:-$ROOT/config.example.toml}"
if [ -x "$XRAY" ]; then
  :
elif command -v "$XRAY" >/dev/null 2>&1; then
  XRAY="$(command -v "$XRAY")"
else
  echo "bench: stock Xray not found: $XRAY (set XRAY_BIN)" >&2
  exit 1
fi

mkdir -p "$TARGET" "$LOG"
if [ ! -f "$TARGET/big.bin" ]; then
  dd if=/dev/zero of="$TARGET/big.bin" bs=1M count="$SIZE_MIB" status=none
fi

cleanup() {
  kill ${TARGET_PID:-} ${CLIENT_PID:-} ${SERVER_PID:-} 2>/dev/null || true
  wait ${TARGET_PID:-} ${CLIENT_PID:-} ${SERVER_PID:-} 2>/dev/null || true
}
trap cleanup EXIT

source "$ROOT/scripts/dev-env.sh"
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  cargo build --manifest-path "$ROOT/Cargo.toml" --release -p beam >"$LOG/build.log" 2>&1
fi

"$PYTHON" "$ROOT/tests/tun/config.py" \
  --test-config "$BASE_CONFIG" \
  --out-dir "$RUN_DIR/config" \
  --listen "127.0.0.1:18443" \
  --cover "whatsapp.net:443" \
  --xray --xray-client \
  --log-level warn >"$LOG/config.log" 2>&1

taskset -c "$TARGET_CPU" "$PYTHON" -m http.server 18080 --bind 127.0.0.1 \
  --directory "$TARGET" >"$LOG/target.log" 2>&1 &
TARGET_PID=$!
taskset -c "$CLIENT_CPU" "$XRAY" run -c "$RUN_DIR/config/xray-client.json" \
  >"$LOG/client.log" 2>&1 &
CLIENT_PID=$!
sleep 2

run_arm() {
  local name="$1"
  shift
  taskset -c "$SERVER_CPU" "$@" >"$LOG/$name-server.log" 2>&1 &
  SERVER_PID=$!
  sleep 2
  local out="$LOG/$name.txt"
  : >"$out"
  local i
  for i in $(seq 1 "$REPS"); do
    taskset -c "$DRIVER_CPU" curl --silent --show-error --max-time 60 --noproxy "" \
      --socks5-hostname 127.0.0.1:11080 \
      -o /dev/null \
      -w "$name rep=$i speed=%{speed_download} bytes=%{size_download} time=%{time_total}\n" \
      http://127.0.0.1:18080/big.bin >>"$out"
  done
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=
  sleep 1
  cat "$out"
}

run_arm beam "$BEAM" -c "$RUN_DIR/config/beam.toml"
run_arm stock "$XRAY" run -c "$RUN_DIR/config/xray-server.json"

"$PYTHON" - "$LOG/beam.txt" "$LOG/stock.txt" <<'PY'
import statistics
import sys

def speeds(path):
    values = []
    for line in open(path, encoding="utf-8"):
        for part in line.split():
            if part.startswith("speed="):
                values.append(float(part.split("=", 1)[1]) / 1_000_000.0)
    return values

beam = speeds(sys.argv[1])
stock = speeds(sys.argv[2])
# First sample is cold; use the remaining samples when possible.
def summary(values):
    warm = values[1:] if len(values) > 1 else values
    return statistics.median(warm), min(warm), max(warm)

if beam and stock:
    b = summary(beam)
    s = summary(stock)
    print(f"beam  median={b[0]:.1f} MB/s min={b[1]:.1f} max={b[2]:.1f}")
    print(f"stock median={s[0]:.1f} MB/s min={s[1]:.1f} max={s[2]:.1f}")
    print(f"ratio beam/stock = {b[0] / s[0]:.3f}x")
PY

echo "run directory: $RUN_DIR"
