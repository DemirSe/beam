#!/usr/bin/env bash
# Start the external three-VM lab, run the functional matrix, and stop it.
# Results are kept outside the repository in the beam cache directory.
set -euo pipefail

LAB_DIR="${LAB_DIR:-/home/demir/pi/beam-lab}"
KEY="${KEY:-$HOME/.ssh/id_ed25519_netlen_demir}"
PROFILE="${LAB_PROFILE:-clean}"
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/beam"
OUT="${LAB_OUT:-$CACHE_ROOT/lab-results/$(date -u +%Y%m%dT%H%M%SZ)}"
KEEP_LAB="${KEEP_LAB:-0}"
SKIP_BUILD="${LAB_SKIP_BUILD:-0}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_C=(ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=8 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 demir@127.0.0.1)
SSH_S=(ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=8 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2223 demir@127.0.0.1)
NETEM_ACTIVE=0

case "$PROFILE" in
    clean|loss) ;;
    *) echo "lab-check: LAB_PROFILE must be clean or loss" >&2; exit 2 ;;
esac
[ -x "$LAB_DIR/start-lab.sh" ] || { echo "lab-check: missing $LAB_DIR/start-lab.sh" >&2; exit 2; }
[ -x "$LAB_DIR/stop-lab.sh" ] || { echo "lab-check: missing $LAB_DIR/stop-lab.sh" >&2; exit 2; }
mkdir -p "$OUT"

cleanup() {
    if [ "$NETEM_ACTIVE" -eq 1 ]; then
        "${SSH_C[@]}" 'sudo -n /usr/sbin/tc qdisc del dev lab0 root' >/dev/null 2>&1 || true
    fi
    if [ "$KEEP_LAB" != "1" ]; then
        LAB="$LAB_DIR" KEY="$KEY" "$LAB_DIR/stop-lab.sh" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "lab-check: profile=$PROFILE output=$OUT"
set +e
LAB="$LAB_DIR" KEY="$KEY" "$LAB_DIR/start-lab.sh" 2>&1 | tee "$OUT/checks-clean.txt"
rc=${PIPESTATUS[0]}
set -e
if [ "$rc" -ne 0 ]; then
    echo "lab-check: clean matrix failed (rc=$rc); output kept in $OUT" >&2
    exit "$rc"
fi

if [ "$SKIP_BUILD" != "1" ]; then
    echo "lab-check: building current source and installing it on the lab server"
    (cd "$REPO_DIR" && source scripts/dev-env.sh && cargo build --release)
    LAB_BIN="/tmp/beam-lab-check-$$.bin"
    scp -q -P 2223 -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null "$REPO_DIR/target/release/beam" \
        "demir@127.0.0.1:$LAB_BIN"
    "${SSH_S[@]}" "set -e
        sudo -n install -m 0755 '$LAB_BIN' /usr/local/bin/beam
        rm -f '$LAB_BIN'
        sudo -n systemctl restart beam
        sleep 2
        systemctl is-active beam
        sudo -n /usr/local/bin/beam --check -c /etc/beam/config.toml
        sudo -n /usr/local/bin/beam --version" 2>&1 | tee "$OUT/current-deploy.txt"

    set +e
    "${SSH_C[@]}" 'bash /home/demir/beam-lab/run-checks.sh' 2>&1 | tee "$OUT/checks-current.txt"
    rc=${PIPESTATUS[0]}
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "lab-check: current-source matrix failed (rc=$rc); output kept in $OUT" >&2
        exit "$rc"
    fi
fi

if [ "$PROFILE" = "loss" ]; then
    echo "lab-check: applying 30 ms +/- 8 ms and 0.5% loss on lab0"
    "${SSH_C[@]}" 'sudo -n /usr/sbin/tc qdisc replace dev lab0 root netem delay 30ms 8ms loss 0.5% limit 100000'
    NETEM_ACTIVE=1
    set +e
    "${SSH_C[@]}" 'bash /home/demir/beam-lab/run-checks.sh' 2>&1 | tee "$OUT/checks-loss.txt"
    rc=${PIPESTATUS[0]}
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "lab-check: impaired matrix failed (rc=$rc); output kept in $OUT" >&2
        exit "$rc"
    fi
fi

echo "lab-check: PASS; output kept in $OUT"
