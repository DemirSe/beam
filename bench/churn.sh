#!/bin/bash
# Short connection-churn smoke test for beam (no TUN).
#
# Starts the same stock Xray SOCKS client and loopback target as bench/no-tun.sh,
# warms up, then sends N small requests with bounded concurrency. Reports HTTP
# failures and server RSS/fd/thread growth.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/beam"
XRAY="${XRAY_BIN:-xray}"
BEAM="${BEAM_BIN:-$ROOT/target/release/beam}"
PYTHON="${PYTHON:-python3}"
RUN_DIR="${CHURN_OUT:-$CACHE_ROOT/churn/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
TARGET="$RUN_DIR/target"
LOG="$RUN_DIR/log"
REQUESTS="${CHURN_REQUESTS:-1000}"
CONCURRENCY="${CHURN_CONCURRENCY:-32}"
SERVER_CPU="${CHURN_SERVER_CPU:-2}"
CLIENT_CPU="${CHURN_CLIENT_CPU:-1}"
TARGET_CPU="${CHURN_TARGET_CPU:-0}"
DRIVER_CPU="${CHURN_DRIVER_CPU:-3}"
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
printf 'beam churn ok\n' > "$TARGET/index.txt"

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
taskset -c "$SERVER_CPU" "$BEAM" -c "$RUN_DIR/config/beam.toml" \
  >"$LOG/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

request() {
  taskset -c "$DRIVER_CPU" curl --silent --show-error --max-time 5 --noproxy "" \
    --socks5-hostname 127.0.0.1:11080 \
    -o /dev/null -w '%{http_code}\n' \
    "http://127.0.0.1:18080/index.txt"
}

for _ in $(seq 1 10); do request >/dev/null || true; done
sleep 1

sample() {
  local pid="$1"
  local rss threads fds
  rss=$(awk '/VmRSS:/ {print $2}' "/proc/$pid/status")
  threads=$(awk '/Threads:/ {print $2}' "/proc/$pid/status")
  fds=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
  printf '%s %s %s\n' "$rss" "$threads" "$fds"
}

read -r RSS_BEFORE THREADS_BEFORE FDS_BEFORE <<<"$(sample "$SERVER_PID")"
START=$(date +%s)
seq 1 "$REQUESTS" | xargs -P "$CONCURRENCY" -I{} bash -c '
  taskset -c "$0" curl --silent --show-error --max-time 5 --noproxy "" \
    --socks5-hostname 127.0.0.1:11080 -o /dev/null -w "%{http_code}\n" \
    "http://127.0.0.1:18080/index.txt"
' "$DRIVER_CPU" >"$RUN_DIR/codes.txt" || true
END=$(date +%s)
sleep 2
read -r RSS_AFTER THREADS_AFTER FDS_AFTER <<<"$(sample "$SERVER_PID")"
GOOD=$(grep -c '^200$' "$RUN_DIR/codes.txt" || true)
TOTAL=$(wc -l <"$RUN_DIR/codes.txt")

echo "churn: requests=$REQUESTS concurrency=$CONCURRENCY seconds=$((END - START))"
echo "http: good=$GOOD total=$TOTAL"
echo "server rss_kib: before=$RSS_BEFORE after=$RSS_AFTER"
echo "server threads: before=$THREADS_BEFORE after=$THREADS_AFTER"
echo "server fds: before=$FDS_BEFORE after=$FDS_AFTER"
echo "run directory: $RUN_DIR"

if [ "$GOOD" -ne "$REQUESTS" ] || [ "$FDS_AFTER" -gt $((FDS_BEFORE + 16)) ]; then
  echo "churn: FAIL"
  exit 1
fi
echo "churn: PASS"
