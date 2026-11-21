#!/bin/bash
# Local harness for deploy/beam-install.sh. The script is copied with every
# absolute /etc and /usr/local path rewritten into a temp root, install owner
# flags stripped, and systemctl, account, runuser, and sleep replaced by stubs.
# Bundles use the release layout: beam, beam.service, beam-install.sh,
# config.example.toml, liveness-check.py, beam-liveness.service,
# beam-liveness.timer, and SHA256SUMS. Both input forms are covered, the
# archive and the extracted release that an operator downloads and runs.
# No host file, unit, account, firewall, or sysctl is touched.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
T="$(mktemp -d /tmp/beam-install-harness.XXXXXXXX)"
trap 'rm -rf -- "$T"' EXIT
STUBS="$T/stubs"
mkdir -p "$STUBS"
PASS=0
FAIL=0

check() { # description, 0 for pass
  if [ "$2" = "0" ]; then
    echo "PASS: $1"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $1"
    FAIL=$((FAIL + 1))
  fi
}

# ---- stubs -------------------------------------------------------------
cat >"$STUBS/systemctl" <<'EOF'
#!/bin/sh
echo "systemctl $*" >>"$SYSTEMCTL_LOG"
case "${2:-}" in --quiet|--now) unit="${3:-}" ;; *) unit="${2:-}" ;; esac
case "${1:-}" in
  is-active)
    if [ "$unit" = beam.service ] && [ -e "$STATE/active-broken" ]; then
      rm -f "$STATE/active-broken"
      exit 3
    fi
    if [ -e "$STATE/active.$unit" ]; then
      [ "${2:-}" = "--quiet" ] || echo active
      exit 0
    fi
    [ "${2:-}" = "--quiet" ] || echo inactive
    exit 3
    ;;
  is-enabled)
    [ -e "$STATE/enabled.$unit" ] && { echo enabled; exit 0; }
    echo disabled
    exit 1
    ;;
  show) echo 0 ;;
  enable)
    if [ "$unit" = beam-liveness.timer ] && [ -e "$STATE/fail-timer-enable" ]; then
      exit 1
    fi
    : >"$STATE/enabled.$unit"
    [ "${2:-}" = "--now" ] && : >"$STATE/active.$unit"
    exit 0
    ;;
  disable)
    rm -f "$STATE/enabled.$unit"
    [ "${2:-}" = "--now" ] && rm -f "$STATE/active.$unit"
    exit 0
    ;;
  restart|start)
    : >"$STATE/active.$unit"
    if [ "$unit" = beam.service ] && [ -e "$STATE/fail-active-after-restart" ]; then
      rm -f "$STATE/fail-active-after-restart"
      : >"$STATE/active-broken"
    fi
    exit 0
    ;;
  stop) rm -f "$STATE/active.$unit"; exit 0 ;;
esac
exit 0
EOF
cat >"$STUBS/id" <<'EOF'
#!/bin/sh
case "${1:-}" in -u) echo 0 ;; esac
exit 0
EOF
printf '#!/bin/sh\nexit 0\n' >"$STUBS/getent"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/groupadd"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/useradd"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/groupdel"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/userdel"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/restorecon"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/sleep"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/journalctl"
cat >"$STUBS/runuser" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--" ]; then
    shift
    exec "$@"
  fi
  shift
done
exit 1
EOF
chmod 0755 "$STUBS"/*

# ---- helpers -----------------------------------------------------------
setup_case() { # name -> sets CASE ROOT STATE LOGS ART
  CASE="$T/$1"
  ROOT="$CASE/root"
  STATE="$CASE/state"
  LOGS="$CASE/logs"
  ART="$CASE/art"
  mkdir -p "$ROOT/etc/systemd/system" "$ROOT/usr/local/bin" "$STATE" "$LOGS" "$ART"
  # Rewrite absolute paths and strip chown flags; the real script is unchanged
  # in logic otherwise.
  sed -e "s#/etc/#$ROOT/etc/#g" -e "s#/usr/local/#$ROOT/usr/local/#g" \
    -e 's/ -o [^ ]* -g [^ ]*//g' \
    "$REPO/deploy/beam-install.sh" >"$CASE/beam-install.sh"
  chmod 0755 "$CASE/beam-install.sh"
  # A deploy directory carries the unit and the liveness set next to the
  # installer. The probe unit names the installed script path, so that absolute
  # path is rewritten into the temp root too.
  cp "$REPO/deploy/beam.service" "$CASE/beam.service"
  sed -e "s#/usr/local/#$ROOT/usr/local/#g" \
    "$REPO/deploy/liveness-check.py" >"$CASE/liveness-check.py"
  sed -e "s#/usr/local/#$ROOT/usr/local/#g" \
    "$REPO/deploy/beam-liveness.service" >"$CASE/beam-liveness.service"
  cp "$REPO/deploy/beam-liveness.timer" "$CASE/beam-liveness.timer"
  chmod 0755 "$CASE/liveness-check.py"
}

make_artifact() { # name [check-exit] -> prints archive path
  local dir="$ART/$1" member members=(beam SHA256SUMS)
  write_bundle "$dir" "${2:-0}"
  for member in beam.service beam-install.sh config.example.toml \
    liveness-check.py beam-liveness.service beam-liveness.timer; do
    [ -e "$dir/$member" ] && members+=("$member")
  done
  pack_bundle "$dir" "${members[@]}"
}

write_bundle() { # dir [check-exit] -> release members, no archive
  local dir="$1" check_rc="${2:-0}"
  mkdir -p "$dir"
  cat >"$dir/beam" <<EOF
#!/bin/sh
case "\${1:-}" in
  --check) exit $check_rc ;;
  --version) echo "beam 0.1.0-test" ;;
esac
exit 0
EOF
  chmod 0755 "$dir/beam"
  if [ -f "$CASE/beam.service" ]; then cp "$CASE/beam.service" "$dir/beam.service"; fi
  if [ -f "$CASE/beam-install.sh" ]; then cp "$CASE/beam-install.sh" "$dir/beam-install.sh"; fi
  for member in liveness-check.py beam-liveness.service beam-liveness.timer; do
    [ -f "$CASE/$member" ] && cp "$CASE/$member" "$dir/$member"
  done
  cp "$REPO/config.example.toml" "$dir/config.example.toml"
  ( cd "$dir" && sha256sum beam >SHA256SUMS )
}

pack_bundle() { # dir, members... -> prints archive path
  local dir="$1"
  shift
  tar -C "$dir" -czf "$dir/release.tar.gz" "$@"
  ( cd "$dir" && sha256sum release.tar.gz >release.tar.gz.sha256 )
  printf '%s\n' "$dir/release.tar.gz"
}

# An extracted release, as an operator gets after downloading and unpacking.
extract_release() { # archive, dir -> prints dir
  mkdir -p "$2"
  tar -xzf "$1" -C "$2"
  printf '%s\n' "$2"
}

seed_live() {
  printf 'OLD-BIN\n' >"$ROOT/usr/local/bin/beam"
  chmod 0755 "$ROOT/usr/local/bin/beam"
  printf 'OLD-UNIT\n' >"$ROOT/etc/systemd/system/beam.service"
  mkdir -p "$ROOT/etc/beam"
  printf 'LIVE-CONFIG\n' >"$ROOT/etc/beam/config.toml"
  chmod 0640 "$ROOT/etc/beam/config.toml"
  : >"$STATE/active.beam.service"
  : >"$STATE/enabled.beam.service"
}

# A host that already runs the liveness timer.
seed_liveness() {
  mkdir -p "$ROOT/usr/local/lib/beam"
  printf 'OLD-PROBE\n' >"$ROOT/usr/local/lib/beam/liveness-check.py"
  printf 'OLD-LIVENESS-UNIT\n' >"$ROOT/etc/systemd/system/beam-liveness.service"
  printf 'OLD-LIVENESS-TIMER\n' >"$ROOT/etc/systemd/system/beam-liveness.timer"
  : >"$STATE/enabled.beam-liveness.timer"
  : >"$STATE/active.beam-liveness.timer"
}

run_at() { # script, args...
  local script="$1"
  shift
  : >"$LOGS/systemctl"
  SYSTEMCTL_LOG="$LOGS/systemctl" STATE="$STATE" PATH="$STUBS:$PATH" \
    BEAM_ARTIFACT="${BEAM_ARTIFACT:-}" BEAM_CONFIG="${BEAM_CONFIG:-}" \
    BEAM_KEEP_CONFIG="${BEAM_KEEP_CONFIG:-}" BEAM_SHA256="${BEAM_SHA256:-}" \
    BEAM_UNIT="${BEAM_UNIT:-}" BEAM_PURGE="${BEAM_PURGE:-}" \
    bash "$script" "$@" >"$LOGS/out" 2>"$LOGS/err"
}

run_script() { run_at "$CASE/beam-install.sh" "$@"; }

# ---- case 1: usage -----------------------------------------------------
setup_case usage
run_script help
rc=$?
check "help: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "help: prints usage" "$(grep -q '^usage: beam-install.sh' "$LOGS/out" && echo 0 || echo 1)"
run_script
rc=$?
check "no args: exit 2" "$([ "$rc" = 2 ] && echo 0 || echo 1)"
run_script bogus
rc=$?
check "unknown verb: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "unknown verb: names it" "$(grep -q "unknown command 'bogus'" "$LOGS/err" && echo 0 || echo 1)"

# ---- case 2: artifact guards ------------------------------------------
setup_case guards
run_script install
rc=$?
check "no artifact: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "no artifact: names BEAM_ARTIFACT" "$(grep -q 'BEAM_ARTIFACT is not set' "$LOGS/err" && echo 0 || echo 1)"

printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
GOOD="$(make_artifact good)"
printf '1111111111111111111111111111111111111111111111111111111111111111\n' \
  >"$GOOD.sha256"
BEAM_ARTIFACT="$GOOD" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "digest mismatch: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "digest mismatch: names both hashes" "$(grep -q 'SHA-256 mismatch' "$LOGS/err" && echo 0 || echo 1)"
check "digest mismatch: nothing installed" \
  "$([ ! -e "$ROOT/usr/local/bin/beam" ] && [ ! -e "$ROOT/etc/systemd/system/beam.service" ] && echo 0 || echo 1)"

cp "$GOOD" "$CASE/no-sum.tar.gz"
BEAM_ARTIFACT="$CASE/no-sum.tar.gz" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "no checksum: fails closed" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "no checksum: names the sidecar" "$(grep -q 'no checksum' "$LOGS/err" && echo 0 || echo 1)"

cp "$GOOD" "$CASE/pinned.tar.gz"
BEAM_ARTIFACT="$CASE/pinned.tar.gz" BEAM_CONFIG="$CASE/config.toml" \
  BEAM_SHA256="$(sha256sum "$CASE/pinned.tar.gz" | cut -d ' ' -f1)" run_script install
rc=$?
check "BEAM_SHA256 pin: install accepted" "$([ "$rc" = 0 ] && echo 0 || echo 1)"

# ---- case 3: artifact contents ----------------------------------------
setup_case no_unit
rm -f "$CASE/beam.service"
ARTIFACT="$(make_artifact no_unit)"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "no unit available: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "no unit available: names BEAM_UNIT" \
  "$(grep -q 'set BEAM_UNIT' "$LOGS/err" && echo 0 || echo 1)"

setup_case unit_override
rm -f "$CASE/beam.service"
ARTIFACT="$(make_artifact unit_override)"
cp "$REPO/deploy/beam.service" "$CASE/alt.service"
printf '# alternate unit\n' >>"$CASE/alt.service"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config.toml" \
  BEAM_UNIT="$CASE/alt.service" run_script install
rc=$?
check "BEAM_UNIT: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "BEAM_UNIT: alternate unit installed" \
  "$(cmp -s "$CASE/alt.service" "$ROOT/etc/systemd/system/beam.service" && echo 0 || echo 1)"

setup_case unit_in_archive
write_bundle "$ART/unit_in_archive"
printf '# unit from the archive\n' >>"$ART/unit_in_archive/beam.service"
ARTIFACT="$(pack_bundle "$ART/unit_in_archive" beam beam.service beam-install.sh config.example.toml SHA256SUMS)"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "archive unit: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "archive unit: unit from the archive wins" \
  "$(cmp -s "$ART/unit_in_archive/beam.service" "$ROOT/etc/systemd/system/beam.service" && echo 0 || echo 1)"

setup_case symlink
mkdir -p "$CASE/symlink"
ln -s /bin/true "$CASE/symlink/beam"
printf '%064d  beam\n' 0 >"$CASE/symlink/SHA256SUMS"
tar -C "$CASE/symlink" -czf "$CASE/symlink.tar.gz" beam SHA256SUMS
sha256sum "$CASE/symlink.tar.gz" >"$CASE/symlink.tar.gz.sha256"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_ARTIFACT="$CASE/symlink.tar.gz" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "symlink member: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "symlink member: names the member" \
  "$(grep -q 'artifact member beam is a symlink' "$LOGS/err" && echo 0 || echo 1)"

setup_case archive_no_sums
write_bundle "$ART/v1"
rm -f "$ART/v1/SHA256SUMS"
ARTIFACT="$(pack_bundle "$ART/v1" beam beam.service beam-install.sh config.example.toml)"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "archive without SHA256SUMS: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "archive without SHA256SUMS: names it" \
  "$(grep -q 'has no SHA256SUMS at the root' "$LOGS/err" && echo 0 || echo 1)"
check "archive without SHA256SUMS: nothing installed" \
  "$([ ! -e "$ROOT/usr/local/bin/beam" ] && [ ! -e "$ROOT/etc/systemd/system/beam.service" ] && echo 0 || echo 1)"

# A symlink member would let an archive copy any root-readable file into the
# installed example config, which the beam user group can read.
setup_case archive_symlink_example
write_bundle "$ART/v1"
rm -f "$ART/v1/config.example.toml"
printf 'STAGING-SECRET\n' >"$CASE/secret"
ln -s "$CASE/secret" "$ART/v1/config.example.toml"
ARTIFACT="$(pack_bundle "$ART/v1" beam beam.service beam-install.sh config.example.toml SHA256SUMS)"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "archive symlink example: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "archive symlink example: names the member" \
  "$(grep -q 'artifact member config.example.toml is a symlink' "$LOGS/err" && echo 0 || echo 1)"
check "archive symlink example: nothing installed" \
  "$([ ! -e "$ROOT/usr/local/bin/beam" ] && [ ! -e "$ROOT/etc/beam" ] && echo 0 || echo 1)"

# A release that names only part of the liveness set is ambiguous: the
# installer must refuse it before any live file changes.
setup_case liveness_partial
rm -f "$CASE/beam-liveness.timer"
ARTIFACT="$(make_artifact liveness_partial)"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "partial liveness set: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "partial liveness set: names the set" \
  "$(grep -q 'only part of the liveness set' "$LOGS/err" && echo 0 || echo 1)"
check "partial liveness set: nothing installed" \
  "$([ ! -e "$ROOT/usr/local/bin/beam" ] && [ ! -e "$ROOT/etc/systemd/system/beam-liveness.timer" ] && echo 0 || echo 1)"

# The probe runs as root, so a symlink member must not be followed.
setup_case liveness_symlink
write_bundle "$ART/v1"
rm -f "$ART/v1/liveness-check.py"
ln -s /bin/true "$ART/v1/liveness-check.py"
ARTIFACT="$(pack_bundle "$ART/v1" beam beam.service beam-install.sh config.example.toml \
  liveness-check.py beam-liveness.service beam-liveness.timer SHA256SUMS)"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "liveness symlink member: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "liveness symlink member: names the member" \
  "$(grep -q 'artifact member liveness-check.py is a symlink' "$LOGS/err" && echo 0 || echo 1)"
check "liveness symlink member: nothing installed" \
  "$([ ! -e "$ROOT/usr/local/lib/beam/liveness-check.py" ] && echo 0 || echo 1)"

# ---- case 4: fresh install --------------------------------------------
setup_case fresh
ARTIFACT="$(make_artifact fresh)"
printf 'CONFIG-A\n' >"$CASE/config-a.toml"
chmod 0600 "$CASE/config-a.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config-a.toml" run_script install
rc=$?
check "fresh: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "fresh: binary installed" \
  "$(cmp -s "$ART/fresh/beam" "$ROOT/usr/local/bin/beam" && echo 0 || echo 1)"
check "fresh: unit installed from the deploy directory" \
  "$(cmp -s "$REPO/deploy/beam.service" "$ROOT/etc/systemd/system/beam.service" && echo 0 || echo 1)"
check "fresh: config installed" \
  "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "CONFIG-A" ] && echo 0 || echo 1)"
check "fresh: config mode 0640" \
  "$([ "$(stat -c %a "$ROOT/etc/beam/config.toml")" = 640 ] && echo 0 || echo 1)"
check "fresh: config dir mode 0751" \
  "$([ "$(stat -c %a "$ROOT/etc/beam")" = 751 ] && echo 0 || echo 1)"
check "fresh: reference example installed" \
  "$(cmp -s "$REPO/config.example.toml" "$ROOT/etc/beam/config.example.toml" && echo 0 || echo 1)"
check "fresh: liveness probe installed" \
  "$(cmp -s "$CASE/liveness-check.py" "$ROOT/usr/local/lib/beam/liveness-check.py" && echo 0 || echo 1)"
check "fresh: liveness probe mode 0755" \
  "$([ "$(stat -c %a "$ROOT/usr/local/lib/beam/liveness-check.py")" = 755 ] && echo 0 || echo 1)"
check "fresh: liveness unit installed" \
  "$(cmp -s "$CASE/beam-liveness.service" "$ROOT/etc/systemd/system/beam-liveness.service" && echo 0 || echo 1)"
check "fresh: liveness timer installed" \
  "$(cmp -s "$CASE/beam-liveness.timer" "$ROOT/etc/systemd/system/beam-liveness.timer" && echo 0 || echo 1)"
check "fresh: liveness units mode 0644" \
  "$([ "$(stat -c %a "$ROOT/etc/systemd/system/beam-liveness.service")" = 644 ] && [ "$(stat -c %a "$ROOT/etc/systemd/system/beam-liveness.timer")" = 644 ] && echo 0 || echo 1)"
check "fresh: probe unit points at the installed probe" \
  "$(grep -q "^ExecStart=$ROOT/usr/local/lib/beam/liveness-check.py$" "$ROOT/etc/systemd/system/beam-liveness.service" && echo 0 || echo 1)"
check "fresh: timer enabled and started" \
  "$(grep -q '^systemctl enable --now beam-liveness.timer$' "$LOGS/systemctl" && echo 0 || echo 1)"
check "fresh: timer started after the service restart" \
  "$(awk '/^systemctl restart beam.service$/{r=NR} /^systemctl enable --now beam-liveness.timer$/{e=NR} END{exit !(r && e && r < e)}' "$LOGS/systemctl" && echo 0 || echo 1)"
check "fresh: example is not the live config" \
  "$(! cmp -s "$ROOT/etc/beam/config.toml" "$ROOT/etc/beam/config.example.toml" && echo 0 || echo 1)"
check "fresh: daemon-reload before restart" \
  "$(grep -q '^systemctl daemon-reload$' "$LOGS/systemctl" && echo 0 || echo 1)"
check "fresh: service enabled" "$(grep -q '^systemctl enable beam.service$' "$LOGS/systemctl" && echo 0 || echo 1)"
check "fresh: service restarted" "$(grep -q '^systemctl restart beam.service$' "$LOGS/systemctl" && echo 0 || echo 1)"
# A previous unit may have hit its start limit; the installer must clear that
# before it starts the new one.
check "fresh: reset-failed before restart" \
  "$(awk '/^systemctl reset-failed beam.service$/{r=NR} /^systemctl restart beam.service$/{s=NR} END{exit !(r && s && r < s)}' "$LOGS/systemctl" && echo 0 || echo 1)"
check "fresh: no .new left" "$([ -z "$(find "$ROOT" -name '*.new')" ] && echo 0 || echo 1)"
check "fresh: no unit drop-in created" "$([ ! -e "$ROOT/etc/systemd/system/beam.service.d" ] && echo 0 || echo 1)"
check "fresh: no sysctl file created" "$([ ! -e "$ROOT/etc/sysctl.d" ] && echo 0 || echo 1)"

setup_case no_liveness
rm -f "$CASE/liveness-check.py" "$CASE/beam-liveness.service" "$CASE/beam-liveness.timer"
ARTIFACT="$(make_artifact no_liveness)"
printf 'CONFIG-A\n' >"$CASE/config-a.toml"
chmod 0600 "$CASE/config-a.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config-a.toml" run_script install
rc=$?
check "no liveness in the release: install still works" \
  "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "no liveness in the release: no probe installed" \
  "$([ ! -e "$ROOT/usr/local/lib/beam/liveness-check.py" ] && echo 0 || echo 1)"
check "no liveness in the release: timer not touched" \
  "$(! grep -Eq '^systemctl (enable|disable|start|stop) .*beam-liveness' "$LOGS/systemctl" && echo 0 || echo 1)"

setup_case no_config
ARTIFACT="$(make_artifact no_config)"
BEAM_ARTIFACT="$ARTIFACT" run_script install
rc=$?
check "no config: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "no config: names BEAM_CONFIG" "$(grep -q 'BEAM_CONFIG is not set' "$LOGS/err" && echo 0 || echo 1)"

setup_case public_config
ARTIFACT="$(make_artifact public_config)"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0644 "$CASE/config.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "public config: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "public config: asks for chmod 600" "$(grep -q 'chmod 600' "$LOGS/err" && echo 0 || echo 1)"

# A timer that cannot start is a rollout failure: the recovery path the release
# promises is part of the install, and rollback must not leave it half enabled.
setup_case timer_fail
ARTIFACT="$(make_artifact timer_fail)"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
: >"$STATE/fail-timer-enable"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "timer start failure: exit nonzero" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "timer start failure: names the timer" \
  "$(grep -q 'beam-liveness.timer did not start' "$LOGS/err" && echo 0 || echo 1)"
check "timer start failure: rollback reported" \
  "$(grep -q 'rolling back' "$LOGS/err" && echo 0 || echo 1)"
check "timer start failure: timer not left enabled" \
  "$([ ! -e "$STATE/enabled.beam-liveness.timer" ] && [ ! -e "$STATE/active.beam-liveness.timer" ] && echo 0 || echo 1)"
check "timer start failure: newly installed probe removed" \
  "$([ ! -e "$ROOT/usr/local/lib/beam/liveness-check.py" ] && echo 0 || echo 1)"
check "timer start failure: no .new left" "$([ -z "$(find "$ROOT" -name '*.new')" ] && echo 0 || echo 1)"

# ---- case 5: update keeps the config ----------------------------------
setup_case update_missing
ARTIFACT="$(make_artifact update_missing)"
BEAM_ARTIFACT="$ARTIFACT" run_script update
rc=$?
check "update without install: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "update without install: names install" \
  "$(grep -q 'run install for a fresh host' "$LOGS/err" && echo 0 || echo 1)"

setup_case update
ART1="$(make_artifact v1)"
printf 'CONFIG-A\n' >"$CASE/config-a.toml"
chmod 0600 "$CASE/config-a.toml"
BEAM_ARTIFACT="$ART1" BEAM_CONFIG="$CASE/config-a.toml" run_script install
rc=$?
check "update setup: install ok" "$([ "$rc" = 0 ] && echo 0 || echo 1)"

printf '# v2 probe\n' >>"$CASE/liveness-check.py"
ART2="$(make_artifact v2)"
printf 'CONFIG-B\n' >"$CASE/config-b.toml"
chmod 0600 "$CASE/config-b.toml"
BEAM_ARTIFACT="$ART2" BEAM_CONFIG="$CASE/config-b.toml" run_script update
rc=$?
check "update: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "update: binary replaced" \
  "$(cmp -s "$ART/v2/beam" "$ROOT/usr/local/bin/beam" && echo 0 || echo 1)"
check "update: live config kept" \
  "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "CONFIG-A" ] && echo 0 || echo 1)"
check "update: says BEAM_CONFIG is ignored" \
  "$(grep -q 'ignoring BEAM_CONFIG' "$LOGS/err" && echo 0 || echo 1)"
check "update: previous binary backed up" \
  "$(ls "$ROOT/usr/local/bin/beam".bak-* >/dev/null 2>&1 && echo 0 || echo 1)"
check "update: not enabled twice" \
  "$([ "$(grep -c '^systemctl enable beam.service$' "$LOGS/systemctl")" = 0 ] && echo 0 || echo 1)"
check "update: liveness timer stopped before the service restart" \
  "$(awk '/^systemctl stop beam-liveness.timer$/{s=NR} /^systemctl restart beam.service$/{r=NR} END{exit !(s && r && s < r)}' "$LOGS/systemctl" && echo 0 || echo 1)"
check "update: liveness timer restarted after the service restart" \
  "$(awk '/^systemctl restart beam.service$/{r=NR} /^systemctl enable --now beam-liveness.timer$/{e=NR} END{exit !(r && e && r < e)}' "$LOGS/systemctl" && echo 0 || echo 1)"
check "update: liveness probe backed up" \
  "$(ls "$ROOT/usr/local/lib/beam/liveness-check.py".bak-* >/dev/null 2>&1 && echo 0 || echo 1)"
check "update: liveness probe replaced from the release" \
  "$(cmp -s "$ART/v2/liveness-check.py" "$ROOT/usr/local/lib/beam/liveness-check.py" && echo 0 || echo 1)"

BEAM_ARTIFACT="$ART2" BEAM_CONFIG="$CASE/config-b.toml" BEAM_KEEP_CONFIG=0 run_script update
rc=$?
check "update replace config: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "update replace config: config replaced" \
  "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "CONFIG-B" ] && echo 0 || echo 1)"
check "update replace config: config mode 0640" \
  "$([ "$(stat -c %a "$ROOT/etc/beam/config.toml")" = 640 ] && echo 0 || echo 1)"

BEAM_ARTIFACT="$ART2" BEAM_KEEP_CONFIG=2 run_script update
rc=$?
check "invalid keep: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "invalid keep: names the variable" \
  "$(grep -q 'BEAM_KEEP_CONFIG must be 0 or 1' "$LOGS/err" && echo 0 || echo 1)"

setup_case keep_config_public
seed_live
chmod 0644 "$ROOT/etc/beam/config.toml"
ARTIFACT="$(make_artifact keep_config_public)"
BEAM_ARTIFACT="$ARTIFACT" run_script update
rc=$?
check "public live config: update succeeds" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "public live config: warns about the mode" \
  "$(grep -q 'readable by other users' "$LOGS/err" && echo 0 || echo 1)"
check "public live config: live config kept" \
  "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "LIVE-CONFIG" ] && echo 0 || echo 1)"

# ---- case 6: a failed --check leaves live state alone -----------------
setup_case checkfail
seed_live
ARTIFACT="$(make_artifact checkfail 1)"
printf 'CONFIG-NEW\n' >"$CASE/config-new.toml"
chmod 0600 "$CASE/config-new.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config-new.toml" BEAM_KEEP_CONFIG=0 \
  run_script update
rc=$?
check "check fail: exit nonzero" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "check fail: names the config" "$(grep -q 'failed --check' "$LOGS/err" && echo 0 || echo 1)"
check "check fail: live binary kept" \
  "$([ "$(cat "$ROOT/usr/local/bin/beam")" = "OLD-BIN" ] && echo 0 || echo 1)"
check "check fail: live unit kept" \
  "$([ "$(cat "$ROOT/etc/systemd/system/beam.service")" = "OLD-UNIT" ] && echo 0 || echo 1)"
check "check fail: live config kept" \
  "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "LIVE-CONFIG" ] && echo 0 || echo 1)"
check "check fail: service not restarted" \
  "$(! grep -q '^systemctl restart beam.service$' "$LOGS/systemctl" && echo 0 || echo 1)"
check "check fail: stage message" \
  "$(grep -q 'live files and the running service are unchanged' "$LOGS/err" && echo 0 || echo 1)"

# ---- case 7: readiness failure rolls back -----------------------------
setup_case readiness
seed_live
ARTIFACT="$(make_artifact readiness)"
: >"$STATE/fail-active-after-restart"
BEAM_ARTIFACT="$ARTIFACT" run_script update
rc=$?
check "readiness: exit nonzero" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "readiness: diagnostic printed" \
  "$(grep -q 'did not stay active with NRestarts=0' "$LOGS/err" && echo 0 || echo 1)"
check "readiness: rollback reported" "$(grep -q 'rolling back' "$LOGS/err" && echo 0 || echo 1)"
check "readiness: binary restored" \
  "$([ "$(cat "$ROOT/usr/local/bin/beam")" = "OLD-BIN" ] && echo 0 || echo 1)"
check "readiness: unit restored" \
  "$([ "$(cat "$ROOT/etc/systemd/system/beam.service")" = "OLD-UNIT" ] && echo 0 || echo 1)"
check "readiness: live config kept" \
  "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "LIVE-CONFIG" ] && echo 0 || echo 1)"
check "readiness: restarted on rollout and rollback" \
  "$([ "$(grep -c '^systemctl restart beam.service$' "$LOGS/systemctl")" -ge 2 ] && echo 0 || echo 1)"
check "readiness: no .new left" "$([ -z "$(find "$ROOT" -name '*.new')" ] && echo 0 || echo 1)"
# The liveness set was new in this rollout, so a rollback must remove it and
# must not leave an enabled timer behind that could restart the old binary.
check "readiness: newly installed liveness probe removed" \
  "$([ ! -e "$ROOT/usr/local/lib/beam/liveness-check.py" ] && echo 0 || echo 1)"
check "readiness: newly installed liveness units removed" \
  "$([ ! -e "$ROOT/etc/systemd/system/beam-liveness.service" ] && [ ! -e "$ROOT/etc/systemd/system/beam-liveness.timer" ] && echo 0 || echo 1)"
check "readiness: timer never enabled" \
  "$([ ! -e "$STATE/enabled.beam-liveness.timer" ] && [ ! -e "$STATE/active.beam-liveness.timer" ] && echo 0 || echo 1)"

# The same failure on a host that already runs the probe: the old liveness set
# and its running timer must come back, not the new one and not a stopped one.
setup_case rollback_liveness
seed_live
seed_liveness
ARTIFACT="$(make_artifact rollback_liveness)"
: >"$STATE/fail-active-after-restart"
BEAM_ARTIFACT="$ARTIFACT" run_script update
rc=$?
check "rollback liveness: exit nonzero" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "rollback liveness: old probe restored" \
  "$([ "$(cat "$ROOT/usr/local/lib/beam/liveness-check.py")" = "OLD-PROBE" ] && echo 0 || echo 1)"
check "rollback liveness: old units restored" \
  "$([ "$(cat "$ROOT/etc/systemd/system/beam-liveness.service")" = "OLD-LIVENESS-UNIT" ] && [ "$(cat "$ROOT/etc/systemd/system/beam-liveness.timer")" = "OLD-LIVENESS-TIMER" ] && echo 0 || echo 1)"
check "rollback liveness: timer still enabled" \
  "$([ -e "$STATE/enabled.beam-liveness.timer" ] && echo 0 || echo 1)"
check "rollback liveness: timer running again" \
  "$([ -e "$STATE/active.beam-liveness.timer" ] && echo 0 || echo 1)"
check "rollback liveness: timer stopped before the rollout restart" \
  "$(awk '/^systemctl stop beam-liveness.timer$/{if(!s)s=NR} /^systemctl restart beam.service$/{if(!r)r=NR} END{exit !(s && r && s < r)}' "$LOGS/systemctl" && echo 0 || echo 1)"
check "rollback liveness: timer restarted after the rollback restart" \
  "$(awk '/^systemctl restart beam.service$/{r=NR} /^systemctl start beam-liveness.timer$/{s=NR} END{exit !(r && s && r < s)}' "$LOGS/systemctl" && echo 0 || echo 1)"
check "rollback liveness: no .new left" "$([ -z "$(find "$ROOT" -name '*.new')" ] && echo 0 || echo 1)"

# Five backups are kept per managed file, newest stamp first. cp -a keeps the
# mtime of the content, so a newer backup can look older than an older one.
setup_case prune
seed_live
for s in 20200101T000000Z 20200102T000000Z 20200103T000000Z 20200104T000000Z 20200105T000000Z; do
  printf 'OLD\n' >"$ROOT/usr/local/bin/beam.bak-$s"
done
touch -d '2000-01-01 00:00:00Z' "$ROOT/usr/local/bin/beam"
ARTIFACT="$(make_artifact prune)"
BEAM_ARTIFACT="$ARTIFACT" run_script install
rc=$?
check "prune: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "prune: five backups kept" \
  "$([ "$(ls "$ROOT/usr/local/bin"/beam.bak-* | wc -l)" = 5 ] && echo 0 || echo 1)"
check "prune: drops the oldest stamp" \
  "$([ ! -e "$ROOT/usr/local/bin/beam.bak-20200101T000000Z" ] && echo 0 || echo 1)"
check "prune: keeps the backup of the replaced binary" \
  "$([ -n "$(grep -l 'OLD-BIN' "$ROOT/usr/local/bin"/beam.bak-* 2>/dev/null)" ] && echo 0 || echo 1)"

# ---- case 8: uninstall and purge --------------------------------------
setup_case uninstall
seed_live
seed_liveness
printf 'BIN-BAK\n' >"$ROOT/usr/local/bin/beam.bak-20260101T000000Z"
run_script uninstall
rc=$?
check "uninstall: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "uninstall: binary backups kept" \
  "$([ -f "$ROOT/usr/local/bin/beam.bak-20260101T000000Z" ] && echo 0 || echo 1)"
check "uninstall: binary removed" "$([ ! -e "$ROOT/usr/local/bin/beam" ] && echo 0 || echo 1)"
check "uninstall: unit removed" \
  "$([ ! -e "$ROOT/etc/systemd/system/beam.service" ] && echo 0 || echo 1)"
check "uninstall: liveness probe removed" \
  "$([ ! -e "$ROOT/usr/local/lib/beam/liveness-check.py" ] && echo 0 || echo 1)"
check "uninstall: liveness units removed" \
  "$([ ! -e "$ROOT/etc/systemd/system/beam-liveness.service" ] && [ ! -e "$ROOT/etc/systemd/system/beam-liveness.timer" ] && echo 0 || echo 1)"
check "uninstall: config kept" \
  "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "LIVE-CONFIG" ] && echo 0 || echo 1)"
check "uninstall: timer stopped and disabled before the service" \
  "$(awk '/^systemctl disable --now beam-liveness.timer$/{t=NR} /^systemctl disable --now beam.service$/{s=NR} END{exit !(t && s && t < s)}' "$LOGS/systemctl" && echo 0 || echo 1)"
check "uninstall: liveness service stopped" \
  "$(grep -q '^systemctl stop beam-liveness.service$' "$LOGS/systemctl" && echo 0 || echo 1)"
check "uninstall: service stopped and disabled" \
  "$(grep -q '^systemctl disable --now beam.service$' "$LOGS/systemctl" && echo 0 || echo 1)"
check "uninstall: daemon-reload" "$(grep -q '^systemctl daemon-reload$' "$LOGS/systemctl" && echo 0 || echo 1)"

setup_case purge
seed_live
seed_liveness
printf 'CONFIG-BAK\n' >"$ROOT/etc/beam/config.toml.bak-20260101T000000Z"
printf 'EXAMPLE-BAK\n' >"$ROOT/etc/beam/config.example.toml"
printf 'EXAMPLE-BAK\n' >"$ROOT/etc/beam/config.example.toml.bak-20260101T000000Z"
printf 'BIN-BAK\n' >"$ROOT/usr/local/bin/beam.bak-20260101T000000Z"
printf 'UNIT-BAK\n' >"$ROOT/etc/systemd/system/beam.service.bak-20260101T000000Z"
printf 'PROBE-BAK\n' >"$ROOT/usr/local/lib/beam/liveness-check.py.bak-20260101T000000Z"
printf 'LIVENESS-BAK\n' >"$ROOT/etc/systemd/system/beam-liveness.service.bak-20260101T000000Z"
printf 'TIMER-BAK\n' >"$ROOT/etc/systemd/system/beam-liveness.timer.bak-20260101T000000Z"
BEAM_PURGE=1 run_script uninstall
rc=$?
check "purge: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "purge: config removed" "$([ ! -e "$ROOT/etc/beam/config.toml" ] && echo 0 || echo 1)"
check "purge: config backups removed" \
  "$([ -z "$(find "$ROOT/etc" -name 'config.toml.bak-*' 2>/dev/null)" ] && echo 0 || echo 1)"
check "purge: example removed" \
  "$([ ! -e "$ROOT/etc/beam/config.example.toml" ] && echo 0 || echo 1)"
check "purge: example backups removed" \
  "$([ -z "$(find "$ROOT/etc" -name 'config.example.toml*' 2>/dev/null)" ] && echo 0 || echo 1)"
check "purge: names the account removal" \
  "$(grep -q 'beam account' "$LOGS/err" && echo 0 || echo 1)"
check "purge: binary backups removed" \
  "$([ -z "$(find "$ROOT/usr/local/bin" -name 'beam.bak-*' 2>/dev/null)" ] && echo 0 || echo 1)"
check "purge: unit backups removed" \
  "$([ -z "$(find "$ROOT/etc/systemd/system" -name 'beam.service.bak-*' 2>/dev/null)" ] && echo 0 || echo 1)"
check "purge: liveness probe backups removed" \
  "$([ -z "$(find "$ROOT/usr/local/lib/beam" -name 'liveness-check.py.bak-*' 2>/dev/null)" ] && echo 0 || echo 1)"
check "purge: liveness unit backups removed" \
  "$([ -z "$(find "$ROOT/etc/systemd/system" -name 'beam-liveness.*.bak-*' 2>/dev/null)" ] && echo 0 || echo 1)"

setup_case purge_invalid
BEAM_PURGE=2 run_script uninstall
rc=$?
check "invalid purge: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"

# ---- case 9: downloaded release, then update and uninstall ------------
setup_case download
printf 'CONFIG-A\n' >"$CASE/config-a.toml"
chmod 0600 "$CASE/config-a.toml"
printf 'CONFIG-B\n' >"$CASE/config-b.toml"
chmod 0600 "$CASE/config-b.toml"
write_bundle "$ART/v1"
ART1="$(pack_bundle "$ART/v1" beam beam.service beam-install.sh config.example.toml \
  liveness-check.py beam-liveness.service beam-liveness.timer SHA256SUMS)"
check "download: archive pin verifies" \
  "$( ( cd "$ART/v1" && sha256sum -c release.tar.gz.sha256 >/dev/null 2>&1 ) && echo 0 || echo 1)"
REL1="$(extract_release "$ART1" "$CASE/release1")"
BEAM_CONFIG="$CASE/config-a.toml" run_at "$REL1/beam-install.sh" install
rc=$?
check "download: install from the extracted release" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "download: binary installed" \
  "$(cmp -s "$REL1/beam" "$ROOT/usr/local/bin/beam" && echo 0 || echo 1)"
check "download: unit installed" \
  "$(cmp -s "$REL1/beam.service" "$ROOT/etc/systemd/system/beam.service" && echo 0 || echo 1)"
check "download: live config installed" \
  "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "CONFIG-A" ] && echo 0 || echo 1)"
check "download: reference example installed" \
  "$(cmp -s "$REL1/config.example.toml" "$ROOT/etc/beam/config.example.toml" && echo 0 || echo 1)"
check "download: liveness probe installed" \
  "$(cmp -s "$REL1/liveness-check.py" "$ROOT/usr/local/lib/beam/liveness-check.py" && echo 0 || echo 1)"
check "download: liveness timer enabled and running" \
  "$([ -e "$STATE/enabled.beam-liveness.timer" ] && [ -e "$STATE/active.beam-liveness.timer" ] && echo 0 || echo 1)"

write_bundle "$ART/v2"
printf '# v2\n' >>"$ART/v2/beam"
( cd "$ART/v2" && sha256sum beam >SHA256SUMS )
ART2="$(pack_bundle "$ART/v2" beam beam.service beam-install.sh config.example.toml \
  liveness-check.py beam-liveness.service beam-liveness.timer SHA256SUMS)"
REL2="$(extract_release "$ART2" "$CASE/release2")"
BEAM_CONFIG="$CASE/config-b.toml" run_at "$REL2/beam-install.sh" update
rc=$?
check "download update: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "download update: binary replaced" \
  "$(cmp -s "$REL2/beam" "$ROOT/usr/local/bin/beam" && echo 0 || echo 1)"
check "download update: live config kept" \
  "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "CONFIG-A" ] && echo 0 || echo 1)"
check "download update: says BEAM_CONFIG is ignored" \
  "$(grep -q 'ignoring BEAM_CONFIG' "$LOGS/err" && echo 0 || echo 1)"

run_at "$REL2/beam-install.sh" uninstall
rc=$?
check "download uninstall: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "download uninstall: binary removed" \
  "$([ ! -e "$ROOT/usr/local/bin/beam" ] && echo 0 || echo 1)"
check "download uninstall: unit removed" \
  "$([ ! -e "$ROOT/etc/systemd/system/beam.service" ] && echo 0 || echo 1)"
check "download uninstall: liveness set removed" \
  "$([ ! -e "$ROOT/usr/local/lib/beam/liveness-check.py" ] && [ ! -e "$ROOT/etc/systemd/system/beam-liveness.timer" ] && echo 0 || echo 1)"
check "download uninstall: timer disabled and stopped" \
  "$([ ! -e "$STATE/enabled.beam-liveness.timer" ] && [ ! -e "$STATE/active.beam-liveness.timer" ] && echo 0 || echo 1)"
check "download uninstall: live config kept" \
  "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "CONFIG-A" ] && echo 0 || echo 1)"
check "download uninstall: reference example kept" \
  "$([ -f "$ROOT/etc/beam/config.example.toml" ] && echo 0 || echo 1)"

# ---- case 10: extracted-release guards -------------------------------
setup_case bundle_missing_beam
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "bundle without beam: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "bundle without beam: names BEAM_ARTIFACT" \
  "$(grep -q 'BEAM_ARTIFACT is not set' "$LOGS/err" && echo 0 || echo 1)"

setup_case bundle_no_sums
write_bundle "$ART/v1"
rm -f "$ART/v1/SHA256SUMS"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_CONFIG="$CASE/config.toml" run_at "$ART/v1/beam-install.sh" install
rc=$?
check "bundle without SHA256SUMS: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "bundle without SHA256SUMS: names it" \
  "$(grep -q 'no SHA256SUMS next to' "$LOGS/err" && echo 0 || echo 1)"

setup_case bundle_tampered
write_bundle "$ART/v1"
printf '# tampered\n' >>"$ART/v1/beam"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_CONFIG="$CASE/config.toml" run_at "$ART/v1/beam-install.sh" install
rc=$?
check "bundle tampered: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "bundle tampered: names the mismatch" \
  "$(grep -q 'beam SHA-256 mismatch' "$LOGS/err" && echo 0 || echo 1)"
check "bundle tampered: nothing installed" \
  "$([ ! -e "$ROOT/usr/local/bin/beam" ] && [ ! -e "$ROOT/etc/systemd/system/beam.service" ] && echo 0 || echo 1)"

setup_case archive_tampered
write_bundle "$ART/v1"
printf '# tampered\n' >>"$ART/v1/beam"
ARTIFACT="$(pack_bundle "$ART/v1" beam beam.service beam-install.sh config.example.toml SHA256SUMS)"
printf 'CONFIG\n' >"$CASE/config.toml"
chmod 0600 "$CASE/config.toml"
BEAM_ARTIFACT="$ARTIFACT" BEAM_CONFIG="$CASE/config.toml" run_script install
rc=$?
check "archive tampered: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "archive tampered: manifest check runs" \
  "$(grep -q 'beam SHA-256 mismatch' "$LOGS/err" && echo 0 || echo 1)"
check "archive tampered: nothing installed" \
  "$([ ! -e "$ROOT/usr/local/bin/beam" ] && [ ! -e "$ROOT/etc/systemd/system/beam.service" ] && echo 0 || echo 1)"

setup_case bundle_pin_without_archive
write_bundle "$ART/v1"
BEAM_SHA256="$(printf '0%.0s' $(seq 64))" run_at "$ART/v1/beam-install.sh" install
rc=$?
check "bundle with BEAM_SHA256: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "bundle with BEAM_SHA256: needs BEAM_ARTIFACT" \
  "$(grep -q 'BEAM_SHA256 pins the archive' "$LOGS/err" && echo 0 || echo 1)"

# ---- case 11: host-wide state is out of scope --------------------------
SCOPE="$REPO/deploy/beam-install.sh"
check "scope: no ssh, firewall, sysctl, or ipv6 command" \
  "$(! grep -Eq '^[[:space:]]*(nft|iptables|ip6tables|ufw|firewall-cmd|sysctl|sshd|ip)[[:space:]]' "$SCOPE" && echo 0 || echo 1)"
check "scope: declares the excluded host state" \
  "$(grep -q 'never changes SSH, the firewall, sysctls, IPv6' "$SCOPE" && echo 0 || echo 1)"

echo "----"
echo "passed=$PASS failed=$FAIL"
echo "logs=$T"
[ "$FAIL" = 0 ]
