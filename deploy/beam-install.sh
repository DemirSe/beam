#!/bin/bash
# General systemd Linux install, update, and uninstall path for beam.
#
# The input is a release from scripts/release-artifact.sh: either the gzip
# tar, or that tar extracted. A release holds these root members:
#
#   beam                server binary, installed as /usr/local/bin/beam
#   beam.service        systemd unit, installed as
#                       /etc/systemd/system/beam.service
#   beam-install.sh     this installer
#   config.example.toml template, installed as /etc/beam/config.example.toml
#   liveness-check.py   liveness probe, installed as
#                       /usr/local/lib/beam/liveness-check.py
#   beam-liveness.service, beam-liveness.timer
#                       probe units, installed under /etc/systemd/system and
#                       enabled as a timer. All three liveness members are
#                       optional, but a release carries all or none: an older
#                       archive without them installs no liveness check.
#   SHA256SUMS          manifest that pins beam
#
# With BEAM_ARTIFACT set, the archive is checked against its pin
# (<artifact>.sha256 or BEAM_SHA256), then the extracted members against
# SHA256SUMS. Without it, the release next to this script is used, and beam
# must match SHA256SUMS. Verify the download with
# `sha256sum -c <name>.tar.gz.sha256` before extraction. A release member that
# is missing is ignored, except beam and SHA256SUMS: those are required, so the
# inner binary pin is checked in both forms. No member may be a symlink.
#
# The unit comes from the release, else from BEAM_UNIT, else from
# beam.service next to this script. The example config is a reference only and
# never becomes the live config. This path installs the binary, the unit, the
# example, the account, the config, and the liveness probe when the release
# carries it. It never changes SSH, the firewall, sysctls, IPv6, or the clock;
# host-level policy stays with the operator (see docs/DEPLOY.md).
#
# The liveness timer restarts beam after three failed probes, so this script
# stops it around a rollout and a planned stop must stop it first; see
# docs/DEPLOY.md.
#
# Usage:
#   sudo env BEAM_ARTIFACT=<tar.gz> BEAM_CONFIG=<toml> bash beam-install.sh install
#   sudo env BEAM_ARTIFACT=<tar.gz> bash beam-install.sh update
#   sudo bash beam-install.sh uninstall
#   bash beam-install.sh help
set -euo pipefail

PROG=beam-install
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_BIN=/usr/local/bin/beam
INSTALL_UNIT=/etc/systemd/system/beam.service
INSTALL_CONFIG_DIR=/etc/beam
INSTALL_CONFIG=/etc/beam/config.toml
INSTALL_EXAMPLE=/etc/beam/config.example.toml
INSTALL_LIVENESS=/usr/local/lib/beam/liveness-check.py
INSTALL_LIVENESS_UNIT=/etc/systemd/system/beam-liveness.service
INSTALL_LIVENESS_TIMER=/etc/systemd/system/beam-liveness.timer
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
# The probe, its unit, and its timer are installed together or not at all.
LIVENESS_MEMBERS=(liveness-check.py beam-liveness.service beam-liveness.timer)

BIN=""
UNIT=""
EXAMPLE_CONFIG=""
LIVENESS_SCRIPT=""
LIVENESS_UNIT=""
LIVENESS_TIMER=""
WORK=""
KEEP_CONFIG=""
CHECK_CONFIG=""
CONFIG_SRC=""
MANAGED=()
declare -A INSTALLED=()
WAS_ACTIVE=""
WAS_ENABLED=""
UNIT_TOUCHED=0
SERVICE_TOUCHED=0
ENABLE_CHANGED=0
TIMER_TOUCHED=0
WAS_TIMER_ENABLED=""
WAS_TIMER_ACTIVE=""

say() { echo "$PROG: $*" >&2; }
die() { say "$*"; exit 1; }

usage() {
  cat <<'EOF'
usage: beam-install.sh install|update|uninstall|help

  install    install the binary, unit, liveness probe, service account, and
             config
  update     replace the binary, unit, liveness probe, and example, keep the
             live config
  uninstall  remove the binary and unit, keep the config unless BEAM_PURGE=1
  help       print this text

Environment:
  BEAM_ARTIFACT      release tar.gz (install, update). Default: read the
                     extracted release next to this script
  BEAM_CONFIG        config to install when the live config is not kept
  BEAM_KEEP_CONFIG   1 keeps /etc/beam/config.toml, 0 replaces it from
                     BEAM_CONFIG. Default: keep an existing config.
  BEAM_SHA256        expected archive SHA-256, overrides <artifact>.sha256.
                     Needs BEAM_ARTIFACT
  BEAM_UNIT          unit file to install when the release has no beam.service.
                     Default: beam.service next to this script
  BEAM_PURGE         uninstall: 1 also removes the config, the example, the
                     .bak-* copies of the binary, unit, config, and example,
                     and the beam account

The release is a tar.gz from scripts/release-artifact.sh with `beam` and
`SHA256SUMS` at the root and, usually, `beam.service`, `config.example.toml`,
and the liveness set `liveness-check.py`, `beam-liveness.service`, and
`beam-liveness.timer`. Liveness is installed and its timer enabled only when
the release carries all three. An existing config is kept unless
BEAM_KEEP_CONFIG=0 is set explicitly. The example config is installed for
reference; it is never the live config.
EOF
}

cleanup() {
  if [ -n "$WORK" ]; then rm -rf -- "$WORK"; fi
}
trap cleanup EXIT

require_root() {
  [ "$(id -u)" -eq 0 ] || die "must run as root"
}

require_commands() {
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing command $cmd"
  done
}

# ---- artifact ----------------------------------------------------------

# Check the staged binary against the release manifest.
verify_beam_sum() {
  local expected actual
  expected="$(awk '$2 == "beam" || $2 == "./beam" { print $1; exit }' "$WORK/SHA256SUMS")"
  [ -n "$expected" ] || die "SHA256SUMS has no beam entry"
  expected="$(printf '%s' "$expected" | tr 'A-F' 'a-f')"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] ||
    die "SHA256SUMS beam entry is not a SHA-256, got '$expected'"
  actual="$(sha256sum -- "$WORK/beam" | cut -d ' ' -f 1)"
  [ "$actual" = "$expected" ] ||
    die "beam SHA-256 mismatch: expected $expected, got $actual"
}

pick_unit() { # release directory
  if [ -f "$1/beam.service" ] && [ ! -L "$1/beam.service" ]; then
    UNIT="$1/beam.service"
  elif [ -n "${BEAM_UNIT:-}" ]; then
    UNIT="$BEAM_UNIT"
  elif [ -f "$HERE/beam.service" ] && [ ! -L "$HERE/beam.service" ]; then
    UNIT="$HERE/beam.service"
  else
    die "no beam.service: add it to the release, place it next to $0, or set BEAM_UNIT"
  fi
  [ -f "$UNIT" ] && [ ! -L "$UNIT" ] ||
    die "unit is not a regular file: $UNIT"
}

# A release carries the probe, its unit, and its timer together or not at all.
# An older archive without them installs no liveness check; a partial set is
# ambiguous, so it fails before any live file changes.
pick_liveness() { # release directory
  local dir="$1" member found=0
  LIVENESS_SCRIPT="" LIVENESS_UNIT="" LIVENESS_TIMER=""
  for member in "${LIVENESS_MEMBERS[@]}"; do
    if [ -e "$dir/$member" ] || [ -L "$dir/$member" ]; then
      found=$((found + 1))
    fi
  done
  [ "$found" -gt 0 ] || return 0
  [ "$found" -eq ${#LIVENESS_MEMBERS[@]} ] ||
    die "release has only part of the liveness set (${LIVENESS_MEMBERS[*]}); include all three or none"
  for member in "${LIVENESS_MEMBERS[@]}"; do
    [ -f "$dir/$member" ] && [ ! -L "$dir/$member" ] ||
      die "liveness member $member is not a regular file"
  done
  LIVENESS_SCRIPT="$dir/liveness-check.py"
  LIVENESS_UNIT="$dir/beam-liveness.service"
  LIVENESS_TIMER="$dir/beam-liveness.timer"
}

stage_archive() {
  local expected="${BEAM_SHA256:-}" actual sidecar listing member
  [ -f "$BEAM_ARTIFACT" ] || die "artifact not found: $BEAM_ARTIFACT"
  [ -r "$BEAM_ARTIFACT" ] || die "artifact is not readable: $BEAM_ARTIFACT"

  if [ -z "$expected" ]; then
    sidecar="$BEAM_ARTIFACT.sha256"
    [ -f "$sidecar" ] || die "no checksum: set BEAM_SHA256 or provide $sidecar"
    read -r expected _ <"$sidecar" || true
  fi
  expected="$(printf '%s' "$expected" | tr 'A-F' 'a-f')"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] ||
    die "expected SHA-256 must be 64 hex characters, got '$expected'"
  actual="$(sha256sum -- "$BEAM_ARTIFACT" | cut -d ' ' -f 1)"
  [ "$actual" = "$expected" ] ||
    die "artifact SHA-256 mismatch: expected $expected, got $actual"

  listing="$(tar -tzf "$BEAM_ARTIFACT")" ||
    die "cannot read artifact $BEAM_ARTIFACT"
  # The outer pin covers the archive; the inner manifest covers the binary
  # this run installs, so both are required.
  for member in beam SHA256SUMS; do
    grep -qx "$member" <<<"$listing" ||
      die "artifact $BEAM_ARTIFACT has no $member at the root"
  done
  WORK="$(mktemp -d /tmp/beam-install.XXXXXXXX)"
  chmod 0700 "$WORK"
  local members=(beam SHA256SUMS)
  for member in beam.service config.example.toml "${LIVENESS_MEMBERS[@]}"; do
    if grep -qx "$member" <<<"$listing"; then members+=("$member"); fi
  done
  tar -xzf "$BEAM_ARTIFACT" -C "$WORK" "${members[@]}" ||
    die "cannot extract beam from $BEAM_ARTIFACT"
  # A symlink member would make install follow it out of the staging
  # directory, so a signed archive could copy any root-readable file into
  # /etc/beam. The extracted-release path rejects the same case.
  for member in "${members[@]}"; do
    if [ -L "$WORK/$member" ]; then
      die "artifact member $member is a symlink"
    fi
  done
  BIN="$WORK/beam"
  [ -f "$BIN" ] || die "artifact member beam is not a regular file"
  verify_beam_sum
  pick_unit "$WORK"
  pick_liveness "$WORK"
  if [ -f "$WORK/config.example.toml" ]; then
    EXAMPLE_CONFIG="$WORK/config.example.toml"
  fi
}

# Download-and-use path: the release was extracted and this script is run in
# place, so the bundle sits next to it.
stage_bundle() {
  local member
  [ -f "$HERE/beam" ] ||
    die "BEAM_ARTIFACT is not set and no beam sits next to $0; extract a release here or set BEAM_ARTIFACT"
  [ -f "$HERE/SHA256SUMS" ] ||
    die "no SHA256SUMS next to $0; cannot verify beam"
  WORK="$(mktemp -d /tmp/beam-install.XXXXXXXX)"
  chmod 0700 "$WORK"
  # Copy into a private directory first, so a swapped source cannot change the
  # bytes between the hash check and the install.
  for member in beam SHA256SUMS beam.service config.example.toml \
    "${LIVENESS_MEMBERS[@]}"; do
    [ -e "$HERE/$member" ] || continue
    [ -L "$HERE/$member" ] && die "release member $member is a symlink"
    cp -- "$HERE/$member" "$WORK/$member"
  done
  [ -f "$WORK/beam" ] || die "release has no beam binary"
  verify_beam_sum
  BIN="$WORK/beam"
  pick_unit "$WORK"
  pick_liveness "$WORK"
  if [ -f "$WORK/config.example.toml" ]; then
    EXAMPLE_CONFIG="$WORK/config.example.toml"
  fi
}

stage_artifact() {
  if [ -n "${BEAM_ARTIFACT:-}" ]; then
    stage_archive
  else
    [ -z "${BEAM_SHA256:-}" ] ||
      die "BEAM_SHA256 pins the archive; set BEAM_ARTIFACT to use it"
    stage_bundle
  fi
}

# ---- config policy -----------------------------------------------------

# An existing live config is kept by default. Replacing it needs an explicit
# BEAM_KEEP_CONFIG=0, so a plain update cannot swap the identity or limits.
resolve_config() {
  local mode="${BEAM_KEEP_CONFIG:-}" src="${BEAM_CONFIG:-}"
  case "$mode" in
    0|1|"") ;;
    *) die "BEAM_KEEP_CONFIG must be 0 or 1" ;;
  esac
  if [ "$VERB" = update ]; then
    [ -f "$INSTALL_BIN" ] ||
      die "update needs an installed $INSTALL_BIN; run install for a fresh host"
    [ -f "$INSTALL_CONFIG" ] ||
      die "update needs the live $INSTALL_CONFIG; run install for a fresh host"
  fi
  if [ -z "$mode" ]; then
    if [ -e "$INSTALL_CONFIG" ]; then mode=1; else mode=0; fi
  fi
  KEEP_CONFIG="$mode"
  if [ "$KEEP_CONFIG" = 1 ]; then
    [ -f "$INSTALL_CONFIG" ] ||
      die "BEAM_KEEP_CONFIG=1 but $INSTALL_CONFIG does not exist; set BEAM_CONFIG for a fresh host"
    [ -z "$src" ] || say "ignoring BEAM_CONFIG because the live config is kept"
    case "$(stat -c %a "$INSTALL_CONFIG")" in
      *0) ;;
      *) say "warning: the kept $INSTALL_CONFIG is readable by other users; chmod 640 it" ;;
    esac
    CHECK_CONFIG="$INSTALL_CONFIG"
    return 0
  fi
  [ -n "$src" ] ||
    die "BEAM_CONFIG is not set and $INSTALL_CONFIG is not kept; write a config from config.example.toml and set BEAM_CONFIG"
  [ -f "$src" ] || die "config not found: $src"
  [ -r "$src" ] || die "config is not readable: $src"
  case "$(stat -c %a "$src")" in
    *0) ;;
    *) die "$src is readable by other users; chmod 600 it before installing" ;;
  esac
  CONFIG_SRC="$src"
  CHECK_CONFIG="$INSTALL_CONFIG.new"
  MANAGED+=("$INSTALL_CONFIG")
}

# ---- rollback ----------------------------------------------------------

backup() {
  local path
  for path in "${MANAGED[@]}"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      cp -a -- "$path" "$path.bak-$STAMP"
    fi
  done
}

prune_backups() {
  local path
  # Order by the UTC stamp in the name: cp -a keeps the mtime of the content,
  # so a newer backup can hold an older timestamp than an older one.
  for path in "${MANAGED[@]}"; do
    find "$(dirname "$path")" -maxdepth 1 -type f \
      -name "$(basename "$path").bak-*" -print 2>/dev/null |
      sort -r | tail -n +6 | xargs -r rm -f || true
  done
}

wait_ready() {
  local _
  for _ in 1 2 3 4 5; do
    systemctl is-active --quiet beam.service || return 1
    [ "$(systemctl show beam.service -p NRestarts --value 2>/dev/null || echo 0)" = 0 ] ||
      return 1
    sleep 1
  done
  return 0
}

rollback() {
  trap - ERR
  set +e
  local rc=0 path
  say "rolling back to backups from $STAMP"
  for path in "${MANAGED[@]}"; do
    rm -f -- "$path.new"
    [ "${INSTALLED[$path]:-0}" = 1 ] || continue
    if [ -e "$path.bak-$STAMP" ] || [ -L "$path.bak-$STAMP" ]; then
      cp -a --remove-destination "$path.bak-$STAMP" "$path" || {
        say "failed to restore $path from $path.bak-$STAMP"
        rc=1
      }
    else
      rm -f -- "$path" || {
        say "failed to remove newly installed $path"
        rc=1
      }
    fi
  done
  if [ "$UNIT_TOUCHED" = 1 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || rc=1
  fi
  if [ "$ENABLE_CHANGED" = 1 ]; then
    case "$WAS_ENABLED" in
      enabled|enabled-runtime) ;;
      *) systemctl disable beam.service >/dev/null 2>&1 || rc=1 ;;
    esac
  fi
  if [ "$SERVICE_TOUCHED" = 1 ]; then
    systemctl reset-failed beam.service >/dev/null 2>&1 || true
    if [ "$WAS_ACTIVE" = active ]; then
      if ! systemctl restart beam.service >/dev/null 2>&1 || ! wait_ready; then
        say "restored beam did not become ready"
        systemctl status --no-pager -l beam.service 2>&1 | sed -n '1,20p' >&2 || true
        journalctl -u beam.service -n 30 --no-pager >&2 || true
        rc=1
      fi
    else
      systemctl stop beam.service >/dev/null 2>&1 || rc=1
    fi
  fi
  # The service is back, so the timer may start again. A timer that did not
  # exist before stays disabled, and one that was running runs again.
  if [ "$TIMER_TOUCHED" = 1 ]; then
    systemctl stop beam-liveness.timer >/dev/null 2>&1 || true
    systemctl stop beam-liveness.service >/dev/null 2>&1 || true
    case "$WAS_TIMER_ENABLED" in
      enabled|enabled-runtime) ;;
      *) systemctl disable beam-liveness.timer >/dev/null 2>&1 || rc=1 ;;
    esac
    if [ "$WAS_TIMER_ACTIVE" = active ]; then
      systemctl start beam-liveness.timer >/dev/null 2>&1 || {
        say "failed to restore beam-liveness.timer"
        rc=1
      }
    fi
  fi
  [ "$rc" -eq 0 ] || say "rollback incomplete; restore the .bak-$STAMP files by hand"
  return "$rc"
}

on_error() {
  set +e
  say "rollout failed"
  rollback
  exit 1
}

fail_rollback() {
  say "$*"
  systemctl status --no-pager -l beam.service 2>&1 | sed -n '1,20p' >&2 || true
  journalctl -u beam.service -n 30 --no-pager >&2 || true
  on_error
}

fail_preflight() {
  local path
  for path in "${MANAGED[@]}"; do rm -f -- "$path.new"; done
  die "$*; live files and the running service are unchanged"
}

place() { # source, destination, mode, owner
  install -m "$3" -o "${4%%:*}" -g "${4##*:}" -- "$1" "$2.new"
  mv -f -- "$2.new" "$2"
  INSTALLED["$2"]=1
}

promote() { # take the validated staged file as the live file
  mv -f -- "$1" "$2"
  INSTALLED["$2"]=1
}

run_check() {
  bash -c 'ulimit -n 65536 2>/dev/null || true; exec "$0" --check -c "$1"' "$1" "$2"
}

# ---- install and update ------------------------------------------------

install_or_update() {
  require_root
  require_commands systemctl sha256sum getent groupadd useradd runuser install
  if [ -n "${BEAM_ARTIFACT:-}" ]; then require_commands tar; fi
  MANAGED=("$INSTALL_BIN" "$INSTALL_UNIT")
  stage_artifact
  if [ -n "$EXAMPLE_CONFIG" ]; then MANAGED+=("$INSTALL_EXAMPLE"); fi
  if [ -n "$LIVENESS_SCRIPT" ]; then
    MANAGED+=("$INSTALL_LIVENESS" "$INSTALL_LIVENESS_UNIT" "$INSTALL_LIVENESS_TIMER")
  fi
  resolve_config
  WAS_ACTIVE="$(systemctl is-active beam.service 2>/dev/null || true)"
  WAS_ENABLED="$(systemctl is-enabled beam.service 2>/dev/null || true)"
  WAS_TIMER_ACTIVE="$(systemctl is-active beam-liveness.timer 2>/dev/null || true)"
  WAS_TIMER_ENABLED="$(systemctl is-enabled beam-liveness.timer 2>/dev/null || true)"

  getent group beam >/dev/null || groupadd --system beam
  id beam >/dev/null 2>&1 ||
    useradd --system --gid beam --home-dir /nonexistent --shell /sbin/nologin beam
  install -d -m 0755 -o root -g root "$(dirname "$INSTALL_BIN")"
  install -d -m 0751 -o root -g beam "$INSTALL_CONFIG_DIR"
  install -d -m 0755 -o root -g root "$(dirname "$INSTALL_UNIT")"
  if [ -n "$LIVENESS_SCRIPT" ]; then
    install -d -m 0755 -o root -g root "$(dirname "$INSTALL_LIVENESS")"
  fi

  # Validate the exact binary and config before any live file changes. The
  # service user must be able to validate the config it will run with.
  install -m 0755 -o root -g root -- "$BIN" "$INSTALL_BIN.new"
  if [ "$KEEP_CONFIG" = 0 ]; then
    install -m 0640 -o root -g beam -- "$CONFIG_SRC" "$INSTALL_CONFIG.new"
  fi
  if [ -n "$EXAMPLE_CONFIG" ]; then
    install -m 0640 -o root -g beam -- "$EXAMPLE_CONFIG" "$INSTALL_EXAMPLE.new"
  fi
  run_check "$INSTALL_BIN.new" "$CHECK_CONFIG" ||
    fail_preflight "the staged binary failed --check with $CHECK_CONFIG"
  runuser -u beam -- bash -c 'ulimit -n 65536 2>/dev/null || true; exec "$0" --check -c "$1"' \
    "$INSTALL_BIN.new" "$CHECK_CONFIG" ||
    fail_preflight "the beam user cannot validate $CHECK_CONFIG with the staged binary"

  trap on_error ERR
  say "backups use the suffix .bak-$STAMP"
  backup
  # A probe must not restart beam while this rollout changes its files. The
  # timer resumes after the readiness check proves the new binary.
  if [ "$WAS_TIMER_ACTIVE" = active ]; then
    TIMER_TOUCHED=1
    systemctl stop beam-liveness.timer >/dev/null 2>&1 || true
    systemctl stop beam-liveness.service >/dev/null 2>&1 || true
  fi
  promote "$INSTALL_BIN.new" "$INSTALL_BIN"
  place "$UNIT" "$INSTALL_UNIT" 0644 root:root
  UNIT_TOUCHED=1
  if [ -n "$LIVENESS_SCRIPT" ]; then
    place "$LIVENESS_SCRIPT" "$INSTALL_LIVENESS" 0755 root:root
    place "$LIVENESS_UNIT" "$INSTALL_LIVENESS_UNIT" 0644 root:root
    place "$LIVENESS_TIMER" "$INSTALL_LIVENESS_TIMER" 0644 root:root
  fi
  if [ "$KEEP_CONFIG" = 0 ]; then
    promote "$INSTALL_CONFIG.new" "$INSTALL_CONFIG"
  fi
  if [ -n "$EXAMPLE_CONFIG" ]; then
    promote "$INSTALL_EXAMPLE.new" "$INSTALL_EXAMPLE"
    say "installed the reference config as $INSTALL_EXAMPLE"
  fi

  if command -v restorecon >/dev/null 2>&1; then
    local -a relabel=("$INSTALL_BIN" "$INSTALL_UNIT" "$INSTALL_CONFIG_DIR")
    if [ -n "$LIVENESS_SCRIPT" ]; then
      relabel+=("$INSTALL_LIVENESS" "$INSTALL_LIVENESS_UNIT" "$INSTALL_LIVENESS_TIMER")
    fi
    restorecon -R "${relabel[@]}" >/dev/null 2>&1 ||
      say "warning: restorecon failed; check the SELinux labels"
  fi

  systemctl daemon-reload
  case "$WAS_ENABLED" in
    enabled|enabled-runtime) ;;
    *)
      systemctl enable beam.service >/dev/null
      ENABLE_CHANGED=1
      ;;
  esac
  SERVICE_TOUCHED=1
  systemctl reset-failed beam.service >/dev/null 2>&1 || true
  systemctl restart beam.service
  wait_ready ||
    fail_rollback "beam.service did not stay active with NRestarts=0 after restart"

  # Enable and start only after the service is proven healthy, so the first
  # probe reaches the new process and a failing rollout never enables a timer
  # that would restart the service underneath the rollback. The probe uses
  # stdlib `tomllib` (Python 3.11+); skip enabling it on older Python instead
  # of leaving a broken timer running.
  if [ -n "$LIVENESS_SCRIPT" ]; then
    if command -v python3 >/dev/null 2>&1 &&
      python3 -c 'import tomllib' >/dev/null 2>&1; then
      TIMER_TOUCHED=1
      systemctl enable --now beam-liveness.timer ||
        fail_rollback "beam-liveness.timer did not start"
    else
      say "warning: python3 3.11+ (tomllib) is required for beam-liveness.timer; skipping timer enable"
    fi
  elif [ "$WAS_TIMER_ACTIVE" = active ]; then
    systemctl start beam-liveness.timer >/dev/null 2>&1 ||
      say "warning: could not restart beam-liveness.timer"
  fi

  trap - ERR
  prune_backups
  say "installed $("$INSTALL_BIN" --version 2>/dev/null || echo beam) as $INSTALL_BIN"
  if [ "$KEEP_CONFIG" = 1 ]; then
    say "kept the live config $INSTALL_CONFIG"
  else
    say "installed the config as $INSTALL_CONFIG"
  fi
  say "beam.service is $(systemctl is-active beam.service 2>/dev/null || echo unknown)"
  if [ -n "$LIVENESS_SCRIPT" ]; then
    say "beam-liveness.timer is $(systemctl is-active beam-liveness.timer 2>/dev/null || echo unknown)"
  fi
}

# ---- uninstall ---------------------------------------------------------

uninstall() {
  local purge="${BEAM_PURGE:-0}"
  require_commands systemctl
  case "$purge" in
    0|1) ;;
    *) die "BEAM_PURGE must be 0 or 1" ;;
  esac
  # The timer restarts beam after three failed probes, so it goes first; a
  # planned stop must stop the timer before beam for the same reason.
  if [ -e "$INSTALL_LIVENESS_TIMER" ] ||
    systemctl is-active --quiet beam-liveness.timer 2>/dev/null; then
    if ! systemctl disable --now beam-liveness.timer; then
      say "warning: could not stop and disable beam-liveness.timer; continuing with removal"
    fi
  fi
  systemctl stop beam-liveness.service >/dev/null 2>&1 || true
  if [ -e "$INSTALL_UNIT" ] || systemctl is-active --quiet beam.service; then
    if ! systemctl disable --now beam.service; then
      say "warning: could not stop and disable beam.service; continuing with removal"
    fi
  fi
  rm -f -- "$INSTALL_UNIT" "$INSTALL_LIVENESS_UNIT" "$INSTALL_LIVENESS_TIMER" \
    "$INSTALL_LIVENESS"
  rmdir --ignore-fail-on-non-empty "$(dirname "$INSTALL_LIVENESS")" 2>/dev/null || true
  systemctl daemon-reload || say "warning: systemctl daemon-reload failed"
  systemctl reset-failed beam.service >/dev/null 2>&1 || true
  systemctl reset-failed beam-liveness.service >/dev/null 2>&1 || true
  rm -f -- "$INSTALL_BIN"
  if [ "$purge" = 1 ]; then
    rm -f -- "$INSTALL_BIN".bak-* "$INSTALL_UNIT".bak-* \
      "$INSTALL_LIVENESS".bak-* "$INSTALL_LIVENESS_UNIT".bak-* \
      "$INSTALL_LIVENESS_TIMER".bak-* \
      "$INSTALL_CONFIG" "$INSTALL_CONFIG".bak-* \
      "$INSTALL_EXAMPLE" "$INSTALL_EXAMPLE".bak-*
    rmdir --ignore-fail-on-non-empty "$INSTALL_CONFIG_DIR" 2>/dev/null || true
    userdel beam >/dev/null 2>&1 || true
    groupdel beam >/dev/null 2>&1 || true
    say "removed $INSTALL_BIN, the beam and liveness units, $INSTALL_CONFIG, $INSTALL_EXAMPLE, their backups, and the beam account"
  else
    say "removed $INSTALL_BIN and the beam and liveness units; kept $INSTALL_CONFIG, $INSTALL_EXAMPLE, and their .bak-* copies"
    say "set BEAM_PURGE=1 to remove the config, its backups, the binary and unit backups, and the beam account"
  fi
}

VERB="${1:-}"
case "$VERB" in
  install|update)
    install_or_update
    ;;
  uninstall)
    require_root
    uninstall
    ;;
  help|-h|--help)
    usage
    ;;
  "")
    usage
    exit 2
    ;;
  *)
    usage
    die "unknown command '$VERB'"
    ;;
esac
