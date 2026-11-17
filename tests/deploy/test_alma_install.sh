#!/bin/bash
# Local harness for deploy/bootstrap-alma.sh. Runs the real script with:
#   - every absolute /etc and /usr/local path rewritten into a temp root
#   - install -o/-g stripped (owner checks are already known from bootstrap.sh)
#   - system commands replaced by logging stubs
# No host file, service, sysctl, or firewall is touched.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
T=$(mktemp -d /tmp/alma-harness.XXXXXXXX)
trap 'rm -rf -- "$T"' EXIT
STUBS="$T/stubs"
mkdir -p "$STUBS"
PASS=0
FAIL=0

check() { # description, condition already evaluated
  if [ "$2" = "0" ]; then echo "PASS: $1"; PASS=$((PASS + 1));
  else echo "FAIL: $1"; FAIL=$((FAIL + 1)); fi
}
eq() { [ "$1" = "$2" ]; }

# ---- stubs -------------------------------------------------------------
cat >"$STUBS/id" <<'EOF'
#!/bin/sh
case "${1:-}" in -u) echo 0 ;; *) exit 0 ;; esac
EOF
printf '#!/bin/sh\nexit 0\n' >"$STUBS/getent"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/groupadd"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/useradd"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/modprobe"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/chronyc"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/restorecon"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/sleep"
cat >"$STUBS/runuser" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--" ]; then shift; exec "$@"; fi
  shift
done
exit 1
EOF
cat >"$STUBS/systemctl" <<'EOF'
#!/bin/sh
echo "systemctl $*" >>"$SYSTEMCTL_LOG"
case "${1:-}" in
  is-active) [ "${2:-}" = "--quiet" ] && exit 0
    case "${2:-}" in
      beam-liveness.timer|beam-fq) echo inactive ;;
      *) echo active ;;
    esac
    exit 0 ;;
  is-enabled) [ -e "$STATE/enabled-${2:-}" ] && { echo enabled; exit 0; }; echo disabled; exit 0 ;;
  enable) shift; for unit in "$@"; do [ "$unit" = "--now" ] && continue; : >"$STATE/enabled-$unit"; done; exit 0 ;;
  disable) shift; for unit in "$@"; do rm -f "$STATE/enabled-$unit"; done; exit 0 ;;
  status) echo "stub status output"; exit 0 ;;
esac
exit 0
EOF
cat >"$STUBS/ss" <<'EOF'
#!/bin/sh
n=$(cat "$SS_COUNT" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" >"$SS_COUNT"
if [ "$n" -gt "${SS_EMPTY_CALLS:-0}" ]; then
  echo 'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("beam",pid=1,fd=3))'
fi
exit 0
EOF
cat >"$STUBS/sysctl" <<'EOF'
#!/bin/sh
echo "sysctl $*" >>"$SYSCTL_LOG"
case "${1:-}" in
  -n) echo "orig:${2:-}" ;;
esac
exit 0
EOF
cat >"$STUBS/nft" <<'EOF'
#!/bin/sh
echo "nft $*" >>"$NFT_LOG"
[ -e "$NFT_FAIL" ] && exit 1
exit 0
EOF
chmod 0755 "$STUBS"/*

# ---- helpers -----------------------------------------------------------
setup_case() { # name -> sets ROOT BUNDLE LOGS
  CASE="$T/$1"
  ROOT="$CASE/root"
  BUNDLE="$CASE/bundle"
  LOGS="$CASE/logs"
  STATE="$CASE/state"
  mkdir -p "$ROOT/etc/beam" "$ROOT/etc/sysctl.d" "$ROOT/etc/modules-load.d" \
    "$ROOT/etc/systemd/system/beam.service.d" "$ROOT/etc/sysconfig" \
    "$ROOT/etc/ssh" "$ROOT/usr/local/bin" "$ROOT/usr/local/lib/beam" \
    "$BUNDLE" "$LOGS" "$STATE"
  chmod 0700 "$BUNDLE"
  for f in beam.service 99-beam.conf 99-beam-conntrack.conf \
    99-beam-conntrack.modules 99-beam-coredump.conf journald-beam.conf beam-ipv4-only.conf \
    maintenance-rules.md motd sshrc post-boot-check.sh \
    beam-post-boot-check.service liveness-check.py beam-liveness.service \
    beam-liveness.timer apply-fq.sh beam-fq.service nftables.conf; do
    cp "$REPO/deploy/$f" "$BUNDLE/$f"
  done
  cp "$REPO/deploy/chrony-beam.conf" "$BUNDLE/chrony.conf"
  printf 'OPTIONS="-4"\n' >"$BUNDLE/chronyd-sysconfig"
  printf '#!/bin/sh\n[ "${1:-}" = --version ] && echo 0.1.0-test\nexit 0\n' >"$BUNDLE/beam"
  chmod 0755 "$BUNDLE/beam"
  printf 'BUNDLE-CONFIG\n' >"$BUNDLE/beam.toml"
  chmod 0600 "$BUNDLE/beam.toml"
  # Rewrite absolute paths and strip chown flags; the real script is unchanged
  # in logic otherwise.
  sed -e "s#/etc/#$ROOT/etc/#g" -e "s#/usr/local/#$ROOT/usr/local/#g" \
    -e 's/ -o [^ ]* -g [^ ]*//g' \
    "$REPO/deploy/bootstrap-alma.sh" >"$BUNDLE/bootstrap-alma.sh"
  chmod 0755 "$BUNDLE/bootstrap-alma.sh"
}

seed_live() {
  printf 'OLD-MOTD\n' >"$ROOT/etc/motd"
  printf 'OLD-SYSCTL\n' >"$ROOT/etc/sysctl.d/99-beam.conf"
  printf 'OLD-UNIT\n' >"$ROOT/etc/systemd/system/beam.service"
  printf 'OLD-BIN\n' >"$ROOT/usr/local/bin/beam"
  chmod 0755 "$ROOT/usr/local/bin/beam"
  printf 'OLD-CHRONY\n' >"$ROOT/etc/chrony.conf"
  printf 'OLD-SYSCONFIG\ninclude "/etc/vendor.nft"\n' >"$ROOT/etc/sysconfig/nftables.conf"
  printf 'OLD-RULES-TARGET\n' >"$ROOT/etc/old-rules.md"
  ln -s "$ROOT/etc/old-rules.md" "$ROOT/etc/host-rules.md"
  : >"$LOGS/systemctl"
  : >"$LOGS/sysctl"
  : >"$LOGS/nft"
}

run_script() {
  : >"$LOGS/ss-count"
  SYSTEMCTL_LOG="$LOGS/systemctl" SYSCTL_LOG="$LOGS/sysctl" \
    NFT_LOG="$LOGS/nft" NFT_FAIL="${NFT_FAIL:-/nonexistent}" \
    SS_COUNT="$LOGS/ss-count" SS_EMPTY_CALLS="${SS_EMPTY_CALLS:-0}" \
    STATE="$STATE" PATH="$STUBS:$PATH" \
    bash "$BUNDLE/bootstrap-alma.sh" >"$LOGS/out" 2>"$LOGS/err"
}

# ---- case 1: fresh install --------------------------------------------
setup_case fresh
seed_live
rm -f "$ROOT/etc/beam/config.toml" "$ROOT/etc/host-rules.md" "$ROOT/etc/old-rules.md"
run_script
rc=$?
check "fresh: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "fresh: config installed" "$(cmp -s "$BUNDLE/beam.toml" "$ROOT/etc/beam/config.toml" && echo 0 || echo 1)"
check "fresh: config mode 0640" "$([ "$(stat -c %a "$ROOT/etc/beam/config.toml")" = 640 ] && echo 0 || echo 1)"
check "fresh: motd replaced" "$(cmp -s "$BUNDLE/motd" "$ROOT/etc/motd" && echo 0 || echo 1)"
check "fresh: alias points at rules" "$([ "$(readlink "$ROOT/etc/host-rules.md")" = "$ROOT/etc/beam/maintenance-rules.md" ] && echo 0 || echo 1)"
check "fresh: binary replaced" "$(cmp -s "$BUNDLE/beam" "$ROOT/usr/local/bin/beam" && echo 0 || echo 1)"
check "fresh: sysconfig keeps vendor include" "$(grep -qxF 'include "/etc/vendor.nft"' "$ROOT/etc/sysconfig/nftables.conf" && echo 0 || echo 1)"
check "fresh: sysconfig gains beam include" "$(grep -qxF "include \"$ROOT/etc/nftables.conf\"" "$ROOT/etc/sysconfig/nftables.conf" && echo 0 || echo 1)"
check "fresh: beam restarted" "$(grep -q '^systemctl restart beam$' "$LOGS/systemctl" && echo 0 || echo 1)"
check "fresh: beam-fq enabled" "$(grep -q 'systemctl enable beam-fq.service' "$LOGS/systemctl" && echo 0 || echo 1)"
check "fresh: liveness timer enabled+started" "$(grep -q 'systemctl enable --now beam-liveness.timer' "$LOGS/systemctl" && echo 0 || echo 1)"
check "fresh: sysctl applied" "$(grep -q 'sysctl -p .*99-beam.conf$' "$LOGS/sysctl" && echo 0 || echo 1)"
check "fresh: nft validated" "$(grep -q 'nft -c -f' "$LOGS/nft" && echo 0 || echo 1)"
check "fresh: backup kept" "$(ls "$ROOT/etc/motd".bak-* >/dev/null 2>&1 && echo 0 || echo 1)"
check "fresh: no .new left" "$([ -z "$(find "$ROOT" -name '*.new')" ] && echo 0 || echo 1)"

# ---- case 2: existing config kept by default, replaced with 0 ----------
printf 'DIFFERENT-CONFIG\n' >"$BUNDLE/beam.toml"
run_script
rc=$?
check "update: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "update: live config kept" "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "BUNDLE-CONFIG" ] && echo 0 || echo 1)"
check "update: sysconfig include not duplicated" "$([ "$(grep -cF "include \"$ROOT/etc/nftables.conf\"" "$ROOT/etc/sysconfig/nftables.conf")" = 1 ] && echo 0 || echo 1)"
check "update: alias is one symlink" "$([ -L "$ROOT/etc/host-rules.md" ] && [ "$(readlink "$ROOT/etc/host-rules.md")" = "$ROOT/etc/beam/maintenance-rules.md" ] && echo 0 || echo 1)"
export BEAM_KEEP_CONFIG=0
run_script
rc=$?
unset BEAM_KEEP_CONFIG
check "replace: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "replace: config replaced" "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "DIFFERENT-CONFIG" ] && echo 0 || echo 1)"
export BEAM_KEEP_CONFIG=2
run_script
rc=$?
unset BEAM_KEEP_CONFIG
check "invalid KEEP: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "invalid KEEP: names the variable" "$(grep -q 'BEAM_KEEP_CONFIG must be 0 or 1' "$LOGS/err" && echo 0 || echo 1)"

# ---- case 3: rollback after an nft validation failure ------------------
setup_case nftfail
seed_live
: >"$LOGS/fail"
export NFT_FAIL="$LOGS/fail"
run_script
rc=$?
unset NFT_FAIL
check "nftfail: exit nonzero" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "nftfail: motd restored" "$([ "$(cat "$ROOT/etc/motd")" = "OLD-MOTD" ] && echo 0 || echo 1)"
check "nftfail: unit restored" "$([ "$(cat "$ROOT/etc/systemd/system/beam.service")" = "OLD-UNIT" ] && echo 0 || echo 1)"
check "nftfail: binary restored" "$([ "$(cat "$ROOT/usr/local/bin/beam")" = "OLD-BIN" ] && echo 0 || echo 1)"
check "nftfail: chrony restored" "$([ "$(cat "$ROOT/etc/chrony.conf")" = "OLD-CHRONY" ] && echo 0 || echo 1)"
check "nftfail: sysctl file restored" "$([ "$(cat "$ROOT/etc/sysctl.d/99-beam.conf")" = "OLD-SYSCTL" ] && echo 0 || echo 1)"
check "nftfail: nftables include restored" "$(cmp -s "$ROOT/etc/sysconfig/nftables.conf" "$ROOT/etc/sysconfig/nftables.conf.bak-"* && grep -qxF 'include "/etc/vendor.nft"' "$ROOT/etc/sysconfig/nftables.conf" && [ "$(wc -l <"$ROOT/etc/sysconfig/nftables.conf")" = 2 ] && echo 0 || echo 1)"
check "nftfail: alias restored" "$([ "$(readlink "$ROOT/etc/host-rules.md")" = "$ROOT/etc/old-rules.md" ] && echo 0 || echo 1)"
check "nftfail: live config not installed" "$([ ! -e "$ROOT/etc/beam/config.toml" ] && echo 0 || echo 1)"
check "nftfail: rules not installed" "$([ ! -e "$ROOT/etc/beam/maintenance-rules.md" ] && echo 0 || echo 1)"
check "nftfail: chronyd restarted twice" "$([ "$(grep -c '^systemctl restart chronyd$' "$LOGS/systemctl")" = 2 ] && echo 0 || echo 1)"
check "nftfail: sysctl values written back" "$(grep -q 'sysctl -w net.core.rmem_max=orig:net.core.rmem_max' "$LOGS/sysctl" && echo 0 || echo 1)"
check "nftfail: no .new left" "$([ -z "$(find "$ROOT" -name '*.new')" ] && echo 0 || echo 1)"
check "nftfail: rollback reported complete" "$(! grep -q 'rollback incomplete' "$LOGS/err" && echo 0 || echo 1)"

# ---- case 4: readiness failure, rollback restarts the old service ------
setup_case readiness
seed_live
printf 'LIVE-CONFIG\n' >"$ROOT/etc/beam/config.toml"
export SS_EMPTY_CALLS=15
run_script
rc=$?
unset SS_EMPTY_CALLS
check "readiness: exit nonzero" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "readiness: diagnostic printed" "$(grep -q 'did not become active and listening on 443' "$LOGS/err" && echo 0 || echo 1)"
check "readiness: beam restarted on rollout and rollback" "$([ "$(grep -c '^systemctl restart beam$' "$LOGS/systemctl")" -ge 2 ] && echo 0 || echo 1)"
check "readiness: daemon-reload on rollback" "$(grep -q '^systemctl daemon-reload$' "$LOGS/systemctl" && echo 0 || echo 1)"
check "readiness: binary restored" "$([ "$(cat "$ROOT/usr/local/bin/beam")" = "OLD-BIN" ] && echo 0 || echo 1)"
check "readiness: live config kept" "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "LIVE-CONFIG" ] && echo 0 || echo 1)"
check "readiness: alias restored" "$([ "$(readlink "$ROOT/etc/host-rules.md")" = "$ROOT/etc/old-rules.md" ] && echo 0 || echo 1)"
check "readiness: enablement restored" "$(grep -q '^systemctl disable beam.service$' "$LOGS/systemctl" && echo 0 || echo 1)"
check "readiness: rollback reported complete" "$(! grep -q 'rollback incomplete' "$LOGS/err" && echo 0 || echo 1)"

# ---- case 5: KEEP=1 with no config in the bundle -----------------------
setup_case keep_nobundle
seed_live
printf 'LIVE-CONFIG\n' >"$ROOT/etc/beam/config.toml"
rm -f "$BUNDLE/beam.toml"
run_script
rc=$?
check "keep-nobundle: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "keep-nobundle: live config kept" "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "LIVE-CONFIG" ] && echo 0 || echo 1)"

# ---- case 6: KEEP=1 with no live config fails and names the fix ---------
setup_case keep_nolive
seed_live
rm -f "$ROOT/etc/beam/config.toml" "$BUNDLE/beam.toml"
export BEAM_KEEP_CONFIG=1
run_script
rc=$?
unset BEAM_KEEP_CONFIG
check "keep-nolive: fails" "$([ "$rc" != 0 ] && echo 0 || echo 1)"
check "keep-nolive: names BEAM_KEEP_CONFIG=1" "$(grep -q 'BEAM_KEEP_CONFIG=1 but' "$LOGS/err" && echo 0 || echo 1)"
check "keep-nolive: names the config path" "$(grep -q "$ROOT/etc/beam/config.toml" "$LOGS/err" && echo 0 || echo 1)"
check "keep-nolive: no config written" "$([ ! -e "$ROOT/etc/beam/config.toml" ] && echo 0 || echo 1)"

# ---- case 7: explicit BEAM_CONFIG --------------------------------------
setup_case explicit_config
seed_live
printf 'EXPLICIT-CONFIG\n' >"$CASE/explicit.toml"
chmod 0600 "$CASE/explicit.toml"
export BEAM_CONFIG="$CASE/explicit.toml"
run_script
rc=$?
unset BEAM_CONFIG
check "explicit: exit 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
check "explicit: installed from BEAM_CONFIG" "$([ "$(cat "$ROOT/etc/beam/config.toml")" = "EXPLICIT-CONFIG" ] && echo 0 || echo 1)"

echo "----"
echo "passed=$PASS failed=$FAIL"
echo "logs=$T"
[ "$FAIL" = 0 ]
