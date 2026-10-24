#!/bin/bash
# Bootstrap beam on a fresh Debian 13 host. Run as root from the bundle directory.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/beam"
CONFIG="$HERE/beam.toml"
UNIT="$HERE/beam.service"
SYSCTL="$HERE/99-beam.conf"
INSTALL_BIN=/usr/local/bin/beam
INSTALL_CONFIG=/etc/beam/config.toml
INSTALL_UNIT=/etc/systemd/system/beam.service
INSTALL_SYSCTL=/etc/sysctl.d/99-beam.conf
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

# Keep a live config when only the binary/unit are being updated. The bundle
# still contains a config for a fresh install, but a host with a different
# local max_connections/log level must not be silently overwritten.
KEEP_CONFIG="${BEAM_KEEP_CONFIG:-0}"
case "$KEEP_CONFIG" in
  0|1) ;;
  *) echo "bootstrap: BEAM_KEEP_CONFIG must be 0 or 1" >&2; exit 1 ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "bootstrap: must run as root" >&2; exit 1; }
for file in "$BIN" "$UNIT" "$SYSCTL"; do
  [ -f "$file" ] || { echo "bootstrap: missing $file" >&2; exit 1; }
done
if [ "$KEEP_CONFIG" = "0" ]; then
  [ -f "$CONFIG" ] || { echo "bootstrap: missing $CONFIG" >&2; exit 1; }
else
  [ -f "$INSTALL_CONFIG" ] || {
    echo "bootstrap: BEAM_KEEP_CONFIG=1 but $INSTALL_CONFIG does not exist" >&2
    exit 1
  }
fi
[ "$(uname -m)" = "x86_64" ] || { echo "bootstrap: expected x86_64" >&2; exit 1; }

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-} ${VERSION_ID:-}" in
    "debian 13") ;;
    *) echo "bootstrap: warning: tested on Debian 13, found ${PRETTY_NAME:-unknown}" >&2 ;;
  esac
fi

# Stop any old stock/comparison listeners so 443 is free.
for unit in xray.service xray-compare.service; do
  if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
  fi
done

if ! getent group beam >/dev/null; then
  groupadd --system beam
fi
if ! id beam >/dev/null 2>&1; then
  useradd --system --gid beam --home-dir /nonexistent --shell /usr/sbin/nologin beam
fi

install -d -m 0750 -o root -g beam /etc/beam
for old in "$INSTALL_BIN" "$INSTALL_CONFIG" "$INSTALL_UNIT" "$INSTALL_SYSCTL"; do
  if [ -e "$old" ]; then
    cp -a "$old" "$old.bak-$STAMP"
  fi
done

# Validate the bundle before replacing the running binary. The old service is
# still in memory if this fails, but a broken installed binary would otherwise
# turn the next restart or reboot into an outage.
if [ "$KEEP_CONFIG" = "1" ]; then
  "$BIN" --check -c "$INSTALL_CONFIG"
else
  "$BIN" --check -c "$CONFIG"
fi

# Install beside the destination and rename, so a crash or full disk cannot
# leave a truncated binary or unit file in place.
install -m 0755 -o root -g root "$BIN" "$INSTALL_BIN.new"
mv -f "$INSTALL_BIN.new" "$INSTALL_BIN"
if [ "$KEEP_CONFIG" = "0" ]; then
  install -m 0640 -o root -g beam "$CONFIG" "$INSTALL_CONFIG.new"
  mv -f "$INSTALL_CONFIG.new" "$INSTALL_CONFIG"
fi
install -m 0644 -o root -g root "$UNIT" "$INSTALL_UNIT.new"
mv -f "$INSTALL_UNIT.new" "$INSTALL_UNIT"
install -m 0644 -o root -g root "$SYSCTL" "$INSTALL_SYSCTL.new"
mv -f "$INSTALL_SYSCTL.new" "$INSTALL_SYSCTL"
sysctl --system >/dev/null

runuser -u beam -- "$INSTALL_BIN" --check -c "$INSTALL_CONFIG"

systemctl daemon-reload
systemctl enable beam
# Always restart: an already-running process keeps the old binary, config, and
# unit properties until it is replaced.
systemctl restart beam
sleep 2
systemctl is-active --quiet beam || {
  systemctl status --no-pager -l beam || true
  journalctl -u beam -n 50 --no-pager || true
  exit 1
}

ss -ltn | grep -q ':443 ' || {
  echo "bootstrap: beam is active but not listening on 443" >&2
  systemctl status --no-pager -l beam || true
  journalctl -u beam -n 50 --no-pager || true
  exit 1
}

echo "bootstrap: beam is active on 443"
systemctl status --no-pager -l beam | sed -n '1,12p'
