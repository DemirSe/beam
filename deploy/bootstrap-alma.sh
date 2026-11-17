#!/bin/bash
# Install the Beam host payload on AlmaLinux 10 (RHEL 10 family). Run as root
# from the directory that deploy/package.sh unpacked, or from a staged copy of
# deploy/ that has the release binary as `beam` and the config as `beam.toml`.
#
# The AlmaLinux adaptation of deploy/bootstrap.sh keeps these differences:
#   - no sshd, firewall, or IPv6 activation; those need a verified separate
#     connection and stay in the operator procedure;
#   - chrony reads /etc/chrony.conf and /etc/sysconfig/chronyd;
#   - nftables.service reads /etc/sysconfig/nftables.conf, which includes
#     /etc/nftables.conf;
#   - package management is dnf, not apt;
#   - files are relabeled with restorecon for SELinux.
#
# Config policy matches deploy/bootstrap.sh: an existing /etc/beam/config.toml
# is kept by default, BEAM_KEEP_CONFIG=0 is required to replace it, and
# BEAM_CONFIG names the file to install. A failed check restores every file,
# live sysctl value, chrony state, systemd unit state, and service that this
# script changed. It does not start a second change.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/beam"
CONFIG="${BEAM_CONFIG:-$HERE/beam.toml}"
UNIT="$HERE/beam.service"
SYSCTL="$HERE/99-beam.conf"
CONNTRACK="$HERE/99-beam-conntrack.conf"
MODULES_LOAD="$HERE/99-beam-conntrack.modules"
COREDUMP="$HERE/99-beam-coredump.conf"
JOURNALD="$HERE/journald-beam.conf"
IPV4_DROPIN="$HERE/beam-ipv4-only.conf"
RULES="$HERE/maintenance-rules.md"
MOTD="$HERE/motd"
SSHRC="$HERE/sshrc"
POSTBOOT="$HERE/post-boot-check.sh"
POSTBOOT_UNIT="$HERE/beam-post-boot-check.service"
LIVENESS="$HERE/liveness-check.py"
LIVENESS_UNIT="$HERE/beam-liveness.service"
LIVENESS_TIMER="$HERE/beam-liveness.timer"
FQ_SCRIPT="$HERE/apply-fq.sh"
FQ_UNIT="$HERE/beam-fq.service"
CHRONY="$HERE/chrony.conf"
CHRONY_OPTIONS="$HERE/chronyd-sysconfig"
NFTABLES="$HERE/nftables.conf"

INSTALL_BIN=/usr/local/bin/beam
INSTALL_CONFIG=/etc/beam/config.toml
INSTALL_UNIT=/etc/systemd/system/beam.service
INSTALL_SYSCTL=/etc/sysctl.d/99-beam.conf
INSTALL_CONNTRACK=/etc/sysctl.d/99-beam-conntrack.conf
INSTALL_MODULES_LOAD=/etc/modules-load.d/99-beam-conntrack.conf
INSTALL_COREDUMP=/etc/sysctl.d/99-beam-coredump.conf
INSTALL_JOURNALD=/etc/systemd/journald.conf.d/99-beam.conf
INSTALL_IPV4_DROPIN=/etc/systemd/system/beam.service.d/99-ipv4-only.conf
INSTALL_RULES=/etc/beam/maintenance-rules.md
INSTALL_RULES_ALIAS=/etc/host-rules.md
INSTALL_MOTD=/etc/motd
INSTALL_SSHRC=/etc/ssh/sshrc
INSTALL_POSTBOOT=/usr/local/lib/beam/post-boot-check.sh
INSTALL_POSTBOOT_UNIT=/etc/systemd/system/beam-post-boot-check.service
INSTALL_LIVENESS=/usr/local/lib/beam/liveness-check.py
INSTALL_LIVENESS_UNIT=/etc/systemd/system/beam-liveness.service
INSTALL_LIVENESS_TIMER=/etc/systemd/system/beam-liveness.timer
INSTALL_FQ_SCRIPT=/usr/local/lib/beam/apply-fq.sh
INSTALL_FQ_UNIT=/etc/systemd/system/beam-fq.service
INSTALL_CHRONY=/etc/chrony.conf
INSTALL_CHRONY_OPTIONS=/etc/sysconfig/chronyd
INSTALL_NFTABLES=/etc/nftables.conf
INSTALL_NFTABLES_INCLUDE=/etc/sysconfig/nftables.conf
NFTABLES_INCLUDE_LINE='include "/etc/nftables.conf"'
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

MANAGED=(
  "$INSTALL_BIN" "$INSTALL_CONFIG" "$INSTALL_UNIT" "$INSTALL_SYSCTL"
  "$INSTALL_CONNTRACK" "$INSTALL_MODULES_LOAD" "$INSTALL_COREDUMP"
  "$INSTALL_JOURNALD" "$INSTALL_IPV4_DROPIN" "$INSTALL_RULES" "$INSTALL_RULES_ALIAS"
  "$INSTALL_MOTD" "$INSTALL_SSHRC" "$INSTALL_POSTBOOT" "$INSTALL_POSTBOOT_UNIT"
  "$INSTALL_LIVENESS" "$INSTALL_LIVENESS_UNIT" "$INSTALL_LIVENESS_TIMER"
  "$INSTALL_FQ_SCRIPT" "$INSTALL_FQ_UNIT" "$INSTALL_CHRONY"
  "$INSTALL_CHRONY_OPTIONS" "$INSTALL_NFTABLES" "$INSTALL_NFTABLES_INCLUDE"
)
UNITS=(beam.service beam-fq.service beam-post-boot-check.service beam-liveness.timer)

declare -A INSTALLED=()
declare -A WAS_ENABLED=()
declare -A SYSCTL_ORIG=()
TOUCHED=0
SERVICE_TOUCHED=0
UNITS_ENABLED=0
BEAM_RESTARTED=0
CHRONY_TOUCHED=0
WAS_ACTIVE_BEAM="$(systemctl is-active beam 2>/dev/null || true)"
WAS_ACTIVE_FQ="$(systemctl is-active beam-fq 2>/dev/null || true)"
WAS_ACTIVE_TIMER="$(systemctl is-active beam-liveness.timer 2>/dev/null || true)"

# Keep a live config when only the binary/unit/host files are being updated.
# An existing live config defaults to preserve so a plain rollout cannot
# silently replace identity/limits. A fresh host defaults to install.
if [ -n "${BEAM_KEEP_CONFIG:-}" ]; then
  KEEP_CONFIG="$BEAM_KEEP_CONFIG"
elif [ -e "$INSTALL_CONFIG" ]; then
  KEEP_CONFIG=1
else
  KEEP_CONFIG=0
fi
case "$KEEP_CONFIG" in
  0|1) ;;
  *) echo "bootstrap-alma: BEAM_KEEP_CONFIG must be 0 or 1" >&2; exit 1 ;;
esac
echo "bootstrap-alma: KEEP_CONFIG=$KEEP_CONFIG (existing configs default to preserve; set BEAM_KEEP_CONFIG=0 explicitly to replace)" >&2
if [ "$KEEP_CONFIG" = "1" ] && [ -n "${BEAM_CONFIG:-}" ]; then
  echo "bootstrap-alma: warning: BEAM_CONFIG is ignored because the live config is kept" >&2
fi

[ "$(id -u)" -eq 0 ] || { echo "bootstrap-alma: must run as root" >&2; exit 1; }
[ "$(uname -m)" = "x86_64" ] || { echo "bootstrap-alma: expected x86_64" >&2; exit 1; }
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-} ${VERSION_ID:-}" in
    "almalinux 10"*) ;;
    *) echo "bootstrap-alma: warning: written for AlmaLinux 10, found ${PRETTY_NAME:-unknown}" >&2 ;;
  esac
fi

# The bundle holds the server config. A non-owner-only directory is a warning,
# because the manual fresh-host procedure stages it as root. A config that other
# users can read is a hard stop.
BUNDLE_MODE="$(stat -c %a "$HERE")"
case "$BUNDLE_MODE" in
  *00) ;;
  *) echo "bootstrap-alma: warning: $HERE is mode $BUNDLE_MODE; keep a secret-bearing staging directory at 0700" >&2 ;;
esac

FILES=(
  "$BIN" "$UNIT" "$SYSCTL" "$CONNTRACK" "$MODULES_LOAD" "$COREDUMP"
  "$JOURNALD" "$IPV4_DROPIN" "$RULES" "$MOTD" "$SSHRC" "$POSTBOOT" "$POSTBOOT_UNIT"
  "$LIVENESS" "$LIVENESS_UNIT" "$LIVENESS_TIMER" "$FQ_SCRIPT" "$FQ_UNIT"
  "$CHRONY" "$CHRONY_OPTIONS" "$NFTABLES"
)
if [ "$KEEP_CONFIG" = "0" ]; then
  FILES+=("$CONFIG")
fi
for file in "${FILES[@]}"; do
  [ -f "$file" ] || {
    echo "bootstrap-alma: missing $file" >&2
    echo "bootstrap-alma: stage the bundle with deploy/package.sh, or copy every file in deploy/ plus $BIN and beam.toml" >&2
    exit 1
  }
done
if [ "$KEEP_CONFIG" = "1" ]; then
  [ -f "$INSTALL_CONFIG" ] || {
    echo "bootstrap-alma: BEAM_KEEP_CONFIG=1 but $INSTALL_CONFIG does not exist" >&2
    echo "bootstrap-alma: set BEAM_KEEP_CONFIG=0 and BEAM_CONFIG=<file> for a fresh host" >&2
    exit 1
  }
else
  CONFIG_MODE="$(stat -c %a "$CONFIG")"
  case "$CONFIG_MODE" in
    *0) ;;
    *) echo "bootstrap-alma: $CONFIG is readable by other users; chmod 600 it before staging" >&2; exit 1 ;;
  esac
fi
for cmd in ip ss sysctl nft chronyc systemctl runuser; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "bootstrap-alma: missing command $cmd" >&2
    exit 1
  }
done

getent group beam >/dev/null || groupadd --system beam
id beam >/dev/null 2>&1 ||
  useradd --system --gid beam --home-dir /nonexistent --shell /sbin/nologin beam
install -d -m 0751 -o root -g beam /etc/beam
install -d -m 0755 /usr/local/lib/beam /etc/systemd/system/beam.service.d \
  /etc/systemd/journald.conf.d

backup() {
  local path
  for path in "${MANAGED[@]}"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      cp -a "$path" "$path.bak-$STAMP"
    fi
  done
}

prune_backups() {
  local path
  for path in "${MANAGED[@]}"; do
    find "$(dirname "$path")" -maxdepth 1 \( -type f -o -type l \) \
      -name "$(basename "$path").bak-*" -printf '%T@ %p\n' 2>/dev/null |
      sort -rn | tail -n +6 | cut -d' ' -f2- | xargs -r rm -f || true
  done
}

install_file() {
  local src="$1" dst="$2" mode="$3" owner="$4"
  install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$src" "$dst.new"
  mv -f "$dst.new" "$dst"
  INSTALLED["$dst"]=1
  TOUCHED=1
}

wait_ready() {
  local _
  for _ in $(seq 1 15); do
    if systemctl is-active --quiet beam &&
       ss -ltnp 'sport = :443' 2>/dev/null | grep -q beam; then
      return 0
    fi
    sleep 1
  done
  return 1
}

restore_unit_state() {
  local unit="$1" want="$2" now
  now="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  if [ "$now" = "$want" ]; then
    return 0
  fi
  case "$want" in
    enabled) systemctl enable "$unit" >/dev/null 2>&1 || return 1 ;;
    enabled-runtime) systemctl enable --runtime "$unit" >/dev/null 2>&1 || return 1 ;;
    masked) systemctl mask "$unit" >/dev/null 2>&1 || return 1 ;;
    masked-runtime) systemctl mask --runtime "$unit" >/dev/null 2>&1 || return 1 ;;
    disabled|"") systemctl disable "$unit" >/dev/null 2>&1 || return 1 ;;
    *) return 0 ;;
  esac
}

# Record each live sysctl value this script is about to change. Rollback sets
# these exact values; re-running sysctl -p would also restore values that were
# never captured. Called after the conntrack module load so its keys exist.
capture_sysctls() {
  local file raw key value
  for file in "$SYSCTL" "$CONNTRACK" "$COREDUMP"; do
    while IFS= read -r raw; do
      raw="${raw#"${raw%%[![:space:]]*}"}"
      case "$raw" in
        ""|"#"*) continue ;;
      esac
      key="${raw%%=*}"
      [ "$key" = "$raw" ] && continue
      key="${key//[[:space:]]/}"
      [ -n "$key" ] || continue
      if ! value="$(sysctl -n "$key" 2>/dev/null)"; then
        echo "bootstrap-alma: cannot read $key before applying $file" >&2
        return 1
      fi
      SYSCTL_ORIG["$key"]="$value"
    done <"$file"
  done
}

rollback() {
  trap - ERR
  set +e
  local rc=0 path unit key ok
  echo "bootstrap-alma: rolling back to backups from $STAMP" >&2
  for path in "${MANAGED[@]}"; do
    rm -f -- "$path.new"
    [ "${INSTALLED[$path]:-0}" = "1" ] || continue
    if [ -e "$path.bak-$STAMP" ] || [ -L "$path.bak-$STAMP" ]; then
      if cp -a --remove-destination "$path.bak-$STAMP" "$path"; then
        if [ ! -L "$path.bak-$STAMP" ] && ! cmp -s "$path.bak-$STAMP" "$path"; then
          echo "bootstrap-alma: restored $path differs from its backup" >&2
          rc=1
        fi
      else
        echo "bootstrap-alma: failed to restore $path from $path.bak-$STAMP" >&2
        rc=1
      fi
    elif rm -f -- "$path"; then
      :
    else
      echo "bootstrap-alma: failed to remove newly installed $path" >&2
      rc=1
    fi
  done
  for key in "${!SYSCTL_ORIG[@]}"; do
    if ! sysctl -w "$key=${SYSCTL_ORIG[$key]}" >/dev/null 2>&1; then
      echo "bootstrap-alma: failed to restore $key=${SYSCTL_ORIG[$key]}" >&2
      rc=1
    fi
  done
  if [ "$CHRONY_TOUCHED" = "1" ]; then
    if ! systemctl restart chronyd >/dev/null 2>&1; then
      echo "bootstrap-alma: failed to restart chronyd after restoring its files" >&2
      rc=1
    fi
    ok=0
    for _ in $(seq 1 10); do
      if chronyc tracking >/dev/null 2>&1; then
        ok=1
        break
      fi
      sleep 1
    done
    if [ "$ok" != "1" ]; then
      echo "bootstrap-alma: chronyd did not answer chronyc after rollback" >&2
      rc=1
    fi
  fi
  if [ "$SERVICE_TOUCHED" = "1" ]; then
    systemctl daemon-reload >/dev/null 2>&1 || rc=1
  fi
  if [ "$BEAM_RESTARTED" = "1" ]; then
    systemctl reset-failed beam >/dev/null 2>&1 || true
    if [ "$WAS_ACTIVE_BEAM" = "active" ]; then
      if ! systemctl restart beam >/dev/null 2>&1 || ! wait_ready; then
        echo "bootstrap-alma: restored beam did not become ready" >&2
        systemctl status --no-pager -l beam 2>&1 | sed -n '1,20p' >&2 || true
        journalctl -u beam -n 30 --no-pager >&2 || true
        rc=1
      fi
    elif ! systemctl stop beam >/dev/null 2>&1; then
      echo "bootstrap-alma: failed to stop beam after rollback" >&2
      rc=1
    fi
  fi
  if [ "$UNITS_ENABLED" = "1" ]; then
    for unit in "${UNITS[@]}"; do
      restore_unit_state "$unit" "${WAS_ENABLED[$unit]:-}" || {
        echo "bootstrap-alma: failed to restore the enablement of $unit" >&2
        rc=1
      }
    done
    if [ "$WAS_ACTIVE_TIMER" != "active" ]; then
      systemctl stop beam-liveness.timer >/dev/null 2>&1 || true
    fi
    if [ "$WAS_ACTIVE_FQ" != "active" ]; then
      systemctl stop beam-fq >/dev/null 2>&1 || true
    fi
  fi
  if [ "$TOUCHED" = "1" ] && [ "$rc" -eq 0 ]; then
    prune_backups
  elif [ "$rc" -ne 0 ]; then
    echo "bootstrap-alma: rollback incomplete; backups from $STAMP are retained" >&2
    echo "bootstrap-alma: inspect with 'systemctl --failed --no-pager' and restore a file with 'cp -a <path>.bak-$STAMP <path>'" >&2
  fi
  return "$rc"
}

on_error() {
  echo "bootstrap-alma: rollout failed" >&2
  if ! rollback; then
    echo "bootstrap-alma: rollback incomplete; restore manually from the .bak-$STAMP files" >&2
  fi
  exit 1
}

fail_rollback() {
  echo "bootstrap-alma: $*" >&2
  if ! rollback; then
    echo "bootstrap-alma: rollback incomplete; restore manually from the .bak-$STAMP files" >&2
  fi
  exit 1
}

fail_preflight() {
  rm -f -- "$INSTALL_BIN.new" "$INSTALL_CONFIG.new"
  echo "bootstrap-alma: $*" >&2
  echo "bootstrap-alma: live files and the running service are unchanged" >&2
  exit 1
}

# Validate the exact binary and config before they replace anything live. The
# service user must be able to run the staged binary and read the exact config
# that is about to become live. A fresh-install config is staged root:beam 0640
# so the unprivileged service user can validate it.
install -m 0755 -o root -g root "$BIN" "$INSTALL_BIN.new"
if [ "$KEEP_CONFIG" = "0" ]; then
  install -m 0640 -o root -g beam "$CONFIG" "$INSTALL_CONFIG.new"
  CHECK_CONFIG="$INSTALL_CONFIG.new"
else
  CHECK_CONFIG="$INSTALL_CONFIG"
fi
if ! bash -c 'ulimit -n 65536 2>/dev/null || true; exec "$0" --check -c "$1"' \
    "$INSTALL_BIN.new" "$CHECK_CONFIG"; then
  fail_preflight "the staged binary failed --check with $CHECK_CONFIG"
fi
if ! runuser -u beam -- bash -c 'ulimit -n 65536 2>/dev/null || true; exec "$0" --check -c "$1"' \
    "$INSTALL_BIN.new" "$CHECK_CONFIG"; then
  fail_preflight "the beam user cannot validate $CHECK_CONFIG with the staged binary"
fi

trap on_error ERR
echo "bootstrap-alma: backups use suffix .bak-$STAMP" >&2
WAS_ENABLED[beam.service]="$(systemctl is-enabled beam.service 2>/dev/null || true)"
WAS_ENABLED[beam-fq.service]="$(systemctl is-enabled beam-fq.service 2>/dev/null || true)"
WAS_ENABLED[beam-post-boot-check.service]="$(systemctl is-enabled beam-post-boot-check.service 2>/dev/null || true)"
WAS_ENABLED[beam-liveness.timer]="$(systemctl is-enabled beam-liveness.timer 2>/dev/null || true)"
backup

# Host tuning. conntrack keys need the module, so load it before sysctl runs.
# BBR and fq must also be loaded before their sysctl keys are set, or the first
# sysctl -p fails on an unknown congestion controller.
install_file "$MODULES_LOAD" "$INSTALL_MODULES_LOAD" 0644 root:root
modprobe nf_conntrack 2>/dev/null || true
modprobe sch_fq 2>/dev/null || true
modprobe tcp_bbr 2>/dev/null || true
capture_sysctls || fail_rollback "cannot record the current sysctl values"
install_file "$SYSCTL" "$INSTALL_SYSCTL" 0644 root:root
install_file "$CONNTRACK" "$INSTALL_CONNTRACK" 0644 root:root
install_file "$COREDUMP" "$INSTALL_COREDUMP" 0644 root:root
install_file "$JOURNALD" "$INSTALL_JOURNALD" 0644 root:root
sysctl -p "$INSTALL_SYSCTL" >/dev/null
sysctl -p "$INSTALL_CONNTRACK" >/dev/null

# Time. chronyd reads /etc/chrony.conf and /etc/sysconfig/chronyd on Alma.
install_file "$CHRONY" "$INSTALL_CHRONY" 0644 root:root
install_file "$CHRONY_OPTIONS" "$INSTALL_CHRONY_OPTIONS" 0644 root:root
CHRONY_TOUCHED=1
systemctl restart chronyd
ok=0
for _ in $(seq 1 10); do
  if chronyc tracking >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 1
done
[ "$ok" = "1" ] || fail_rollback "chronyc tracking failed after restarting chronyd"

# Firewall files only. Activation stays a separate verified step: firewalld
# must be stopped first, because a second manager would flush this table. Keep
# any other include lines that the host already has in the sysconfig file.
install_file "$NFTABLES" "$INSTALL_NFTABLES" 0644 root:root
if [ -f "$INSTALL_NFTABLES_INCLUDE" ] &&
   grep -Fqx "$NFTABLES_INCLUDE_LINE" "$INSTALL_NFTABLES_INCLUDE"; then
  :
elif [ -f "$INSTALL_NFTABLES_INCLUDE" ]; then
  printf '%s\n' "$NFTABLES_INCLUDE_LINE" >>"$INSTALL_NFTABLES_INCLUDE"
  INSTALLED["$INSTALL_NFTABLES_INCLUDE"]=1
  TOUCHED=1
else
  printf '%s\n' \
    '# Loaded by nftables.service on AlmaLinux. Rules live in /etc/nftables.conf.' \
    "$NFTABLES_INCLUDE_LINE" |
    install -m 0644 -o root -g root /dev/stdin "$INSTALL_NFTABLES_INCLUDE"
  INSTALLED["$INSTALL_NFTABLES_INCLUDE"]=1
  TOUCHED=1
fi
nft -c -f "$INSTALL_NFTABLES" >/dev/null || fail_rollback "$INSTALL_NFTABLES failed validation"

# Swap the validated binary and config into place.
SERVICE_TOUCHED=1
mv -f "$INSTALL_BIN.new" "$INSTALL_BIN"
INSTALLED["$INSTALL_BIN"]=1
TOUCHED=1
if [ "$KEEP_CONFIG" = "0" ]; then
  mv -f "$INSTALL_CONFIG.new" "$INSTALL_CONFIG"
  INSTALLED["$INSTALL_CONFIG"]=1
fi
install_file "$UNIT" "$INSTALL_UNIT" 0644 root:root
install_file "$IPV4_DROPIN" "$INSTALL_IPV4_DROPIN" 0644 root:root
install_file "$RULES" "$INSTALL_RULES" 0644 root:root
ln -sfn "$INSTALL_RULES" "$INSTALL_RULES_ALIAS"
INSTALLED["$INSTALL_RULES_ALIAS"]=1
install_file "$MOTD" "$INSTALL_MOTD" 0644 root:root
install_file "$SSHRC" "$INSTALL_SSHRC" 0755 root:root
install_file "$POSTBOOT" "$INSTALL_POSTBOOT" 0755 root:root
install_file "$POSTBOOT_UNIT" "$INSTALL_POSTBOOT_UNIT" 0644 root:root
install_file "$LIVENESS" "$INSTALL_LIVENESS" 0755 root:root
install_file "$LIVENESS_UNIT" "$INSTALL_LIVENESS_UNIT" 0644 root:root
install_file "$LIVENESS_TIMER" "$INSTALL_LIVENESS_TIMER" 0644 root:root
install_file "$FQ_SCRIPT" "$INSTALL_FQ_SCRIPT" 0755 root:root
install_file "$FQ_UNIT" "$INSTALL_FQ_UNIT" 0644 root:root

# SELinux labels follow the policy defaults for these paths.
restorecon -R /etc/beam /usr/local/lib/beam /etc/systemd/system/beam.service \
  /etc/systemd/system/beam.service.d /etc/systemd/system/beam-liveness.service \
  /etc/systemd/system/beam-liveness.timer /etc/systemd/system/beam-fq.service \
  /etc/systemd/system/beam-post-boot-check.service /usr/local/bin/beam \
  /etc/sysctl.d/99-beam.conf /etc/sysctl.d/99-beam-conntrack.conf \
  /etc/sysctl.d/99-beam-coredump.conf /etc/modules-load.d/99-beam-conntrack.conf \
  /etc/systemd/journald.conf.d/99-beam.conf /etc/nftables.conf /etc/sysconfig/nftables.conf /etc/chrony.conf \
  /etc/sysconfig/chronyd /etc/ssh/sshrc /etc/motd

systemctl daemon-reload
UNITS_ENABLED=1
systemctl enable beam-fq.service beam-post-boot-check.service beam.service
systemctl enable --now beam-liveness.timer
systemctl reset-failed beam 2>/dev/null || true
BEAM_RESTARTED=1
systemctl restart beam
systemctl start beam-fq.service

if ! wait_ready; then
  echo "bootstrap-alma: beam did not become active and listening on 443" >&2
  systemctl status --no-pager -l beam 2>&1 | sed -n '1,20p' >&2 || true
  journalctl -u beam -n 50 --no-pager >&2 || true
  fail_rollback "readiness probe failed"
fi

VERSION="$("$INSTALL_BIN" --version)"
trap - ERR
prune_backups
echo "bootstrap-alma: beam $VERSION is listening on 443"
echo "bootstrap-alma: replaced files have .bak-$STAMP copies; the previous five backup sets are kept"
