#!/bin/bash
# Bootstrap beam on a fresh Debian 13 host. Run as root from the bundle directory.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/beam"
CONFIG="$HERE/beam.toml"
UNIT="$HERE/beam.service"
SYSCTL="$HERE/99-beam.conf"
CONNTRACK="$HERE/99-beam-conntrack.conf"
INSTALL_BIN=/usr/local/bin/beam
INSTALL_CONFIG=/etc/beam/config.toml
INSTALL_UNIT=/etc/systemd/system/beam.service
INSTALL_SYSCTL=/etc/sysctl.d/99-beam.conf
INSTALL_CONNTRACK=/etc/sysctl.d/99-beam-conntrack.conf
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
for old in "$INSTALL_BIN" "$INSTALL_CONFIG" "$INSTALL_UNIT" "$INSTALL_SYSCTL" "$INSTALL_CONNTRACK"; do
  if [ -e "$old" ]; then
    cp -a "$old" "$old.bak-$STAMP"
  fi
done

# Install beside the destination and validate there before replacing the
# running binary. `/tmp` may be mounted noexec, and a broken installed binary
# would turn the next restart or reboot into an outage.
install -m 0755 -o root -g root "$BIN" "$INSTALL_BIN.new"
if [ "$KEEP_CONFIG" = "1" ]; then
  CHECK_CONFIG="$INSTALL_CONFIG"
else
  CHECK_CONFIG="$CONFIG"
fi
if ! "$INSTALL_BIN.new" --check -c "$CHECK_CONFIG"; then
  rm -f "$INSTALL_BIN.new"
  echo "bootstrap: new binary failed --check; live binary unchanged" >&2
  exit 1
fi
mv -f "$INSTALL_BIN.new" "$INSTALL_BIN"
if [ "$KEEP_CONFIG" = "0" ]; then
  install -m 0640 -o root -g beam "$CONFIG" "$INSTALL_CONFIG.new"
  mv -f "$INSTALL_CONFIG.new" "$INSTALL_CONFIG"
fi
install -m 0644 -o root -g root "$UNIT" "$INSTALL_UNIT.new"
mv -f "$INSTALL_UNIT.new" "$INSTALL_UNIT"
install -m 0644 -o root -g root "$SYSCTL" "$INSTALL_SYSCTL.new"
mv -f "$INSTALL_SYSCTL.new" "$INSTALL_SYSCTL"
if [ -f "$CONNTRACK" ]; then
  install -m 0644 -o root -g root "$CONNTRACK" "$INSTALL_CONNTRACK.new"
  mv -f "$INSTALL_CONNTRACK.new" "$INSTALL_CONNTRACK"
fi
# The primary UDP buffer file is required; a typo or permission failure must
# fail the rollout rather than silently losing H3 headroom.
sysctl -p "$INSTALL_SYSCTL" >/dev/null
if [ -f "$INSTALL_CONNTRACK" ]; then
  # conntrack keys may not exist until nftables first loads the module. A
  # failure here must not abort the binary/unit rollout; the file applies at
  # the next boot as well.
  sysctl -p "$INSTALL_CONNTRACK" >/dev/null 2>&1 || \
    echo "bootstrap: warning: conntrack sysctl keys are not available yet" >&2
fi

runuser -u beam -- "$INSTALL_BIN" --check -c "$INSTALL_CONFIG"

systemctl daemon-reload
systemctl enable beam
# A previous crash-loop can leave the unit failed even after the root cause is
# fixed. Reset that state so this rollout can start normally.
systemctl reset-failed beam 2>/dev/null || true
# Always restart: an already-running process keeps the old binary, config, and
# unit properties until it is replaced.
systemctl restart beam

# Poll for beam's own listener instead of trusting a fixed sleep or any process
# that happens to hold :443. A slow start gets up to 15 s.
ready=0
for _ in $(seq 1 15); do
  if systemctl is-active --quiet beam &&
     ss -ltnp "sport = :443" 2>/dev/null | grep -q 'beam'; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" != 1 ]; then
  echo "bootstrap: beam did not become active and listening on 443" >&2
  systemctl status --no-pager -l beam || true
  journalctl -u beam -n 50 --no-pager || true
  exit 1
fi

# Keep the five most recent backups of each installed file; a long-lived host
# should not fill its disk with one binary per deploy.
for base in "$INSTALL_BIN" "$INSTALL_CONFIG" "$INSTALL_UNIT" "$INSTALL_SYSCTL" "$INSTALL_CONNTRACK"; do
  find "$(dirname "$base")" -maxdepth 1 -type f \
    -name "$(basename "$base").bak-*" -printf '%T@ %p\n' 2>/dev/null |
    sort -rn | tail -n +6 | cut -d' ' -f2- | xargs -r rm -f
done

echo "bootstrap: beam is active on 443 ($("$INSTALL_BIN" --version))"
systemctl status --no-pager -l beam | sed -n '1,12p'
