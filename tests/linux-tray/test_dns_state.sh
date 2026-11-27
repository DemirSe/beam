#!/usr/bin/env bash
# Isolated state test for clients/linux-tray/helper.c.
# Needs only a C compiler: no root, no /etc writes, no TUN, no network.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/beam-dns-test.XXXXXXXX")"
trap 'rm -rf -- "$TMP"' EXIT

DNS_DIR="$TMP/etc/systemd/resolved.conf.d"
BIN_DIR="$TMP/bin"
mkdir -p "$DNS_DIR" "$BIN_DIR"

INSTALL="$HERE/../../clients/linux-tray/install.sh"

# The boot reset must run for both saved drop-ins, for a leftover
# 99-beam.conf, and for the ownership marker of a crash between the marker and
# live-file writes. Without the last two conditions, a power loss can leave DNS
# pointed at the dead tunnel or leave a stale marker behind.
for cond in 10-controld.conf.beam-off 99-beam.conf.beam-prev 99-beam.conf \
            99-beam.conf.beam-own 99-beam.conf.beam-reload; do
  grep -qxF "ConditionPathExists=|/etc/systemd/resolved.conf.d/$cond" \
    "$INSTALL" || {
    echo "install.sh: missing boot-reset condition for $cond" >&2
    exit 1
  }
 done

# The reset must finish before a client start can write a new drop-in.
grep -qxF 'Before=beam-client.service' "$INSTALL" || {
  echo "install.sh: boot reset is not ordered before beam-client.service" >&2
  exit 1
}

# The installer must prove the active unit stopped before it replaces live
# files: the inactivity check has to sit between `systemctl stop` and the first
# live write, and an unstopped unit must abort with a named error.
stop_line=$(grep -n '^systemctl stop beam-client' "$INSTALL" | cut -d: -f1 || true)
guard_line=$(grep -n 'cannot stop beam-client' "$INSTALL" | cut -d: -f1 || true)
config_line=$(grep -n '^install -m 0600 "$NORMALIZED_CONFIG" /etc/beam/config.json' \
  "$INSTALL" | cut -d: -f1 || true)
[ -n "$stop_line" ] && [ -n "$guard_line" ] && [ -n "$config_line" ] || {
  echo "install.sh: missing stop guard or live config install" >&2
  exit 1
}
[ "$stop_line" -lt "$guard_line" ] && [ "$guard_line" -lt "$config_line" ] || {
  echo "install.sh: stop guard is not between stop and the live config write" >&2
  exit 1
}
awk -v first="$stop_line" -v last="$guard_line" \
  'NR > first && NR < last && /systemctl is-active --quiet beam-client/ {found=1}
   END {exit found ? 0 : 1}' "$INSTALL" || {
  echo "install.sh: the stop guard does not check whether the unit is inactive" >&2
  exit 1
}

# A unit that will not stop aborts before the BBR files are written, so a
# failed stop leaves no sysctl or module file modified.
bbr_line=$(grep -n 'install -m 0644 "$HERE/99-beam-client-bbr.conf"' "$INSTALL" \
  | cut -d: -f1 | head -1 || true)
[ -n "$bbr_line" ] && [ "$guard_line" -lt "$bbr_line" ] || {
  echo "install.sh: BBR files are written before the stop guard" >&2
  exit 1
}

# The DNS switch needs the real resolver and its drop-in directory. Both
# checks must run before the service is stopped or any live file is replaced.
resolved_line=$(grep -n 'systemctl is-active --quiet systemd-resolved' "$INSTALL" \
  | cut -d: -f1 || true)
dir_line=$(grep -n 'for dir in /etc/systemd/resolved.conf.d /etc/sysctl.d' "$INSTALL" \
  | cut -d: -f1 || true)
[ -n "$resolved_line" ] && [ -n "$dir_line" ] || {
  echo "install.sh: missing systemd-resolved or drop-in directory check" >&2
  exit 1
}
[ "$resolved_line" -lt "$stop_line" ] && [ "$dir_line" -lt "$stop_line" ] || {
  echo "install.sh: resolver preconditions are checked after the service stop" >&2
  exit 1
}
grep -q 'systemd-resolved is not active; the DNS switch needs it' "$INSTALL" || {
  echo "install.sh: the resolver check has no named error" >&2
  exit 1
}

# An unresolved INSTALL_USER leaves the tray unable to call the helper. The
# check must run before any directory creation, backup, or service change.
user_line=$(grep -n 'id -nu -- "$INSTALL_USER"' "$INSTALL" | cut -d: -f1 || true)
[ -n "$user_line" ] && [ "$user_line" -lt "$dir_line" ] || {
  echo "install.sh: INSTALL_USER is not resolved before side effects" >&2
  exit 1
}
grep -qF 'does not resolve to a user' "$INSTALL" || {
  echo "install.sh: unresolved INSTALL_USER has no named error" >&2
  exit 1
}
# A numeric uid resolves but never matches the helper's name comparison, and
# "0" must not bypass the root guard after normalization.
grep -qF 'INSTALL_USER must be the desktop user, not root' "$INSTALL" || {
  echo "install.sh: normalized INSTALL_USER is not re-checked for root" >&2
  exit 1
}

# Unit ordering: the client reloads systemd-resolved and moves the ctrld
# drop-in, so it must follow both units. The boot reset must run first.
unit_body() {
  sed -n "/^cat > \/etc\/systemd\/system\/$1 <<'EOF'$/,/^EOF$/p" "$INSTALL"
}
client_unit=$(unit_body beam-client.service)
reset_unit=$(unit_body beam-dns-reset.service)
[ -n "$client_unit" ] && [ -n "$reset_unit" ] || {
  echo "install.sh: missing beam-client or beam-dns-reset unit text" >&2
  exit 1
}
client_after=$(printf '%s\n' "$client_unit" | sed -n 's/^After=//p')
for unit in systemd-resolved.service ctrld.service; do
  printf '%s\n' "$client_after" | tr ' ' '\n' | grep -qxF "$unit" || {
    echo "install.sh: beam-client is not ordered after $unit" >&2
    exit 1
  }
done
printf '%s\n' "$reset_unit" | grep -qxF 'Before=beam-client.service' || {
  echo "install.sh: boot reset is not ordered before beam-client.service" >&2
  exit 1
}
reset_after=$(printf '%s\n' "$reset_unit" | sed -n 's/^After=//p')
printf '%s\n' "$reset_after" | tr ' ' '\n' | grep -qxF 'systemd-resolved.service' || {
  echo "install.sh: boot reset is not ordered after systemd-resolved.service" >&2
  exit 1
}
printf '%s\n' "$reset_after" | tr ' ' '\n' | grep -qxF 'ctrld.service' || {
  echo "install.sh: boot reset is not ordered after ctrld.service" >&2
  exit 1
}
if printf '%s\n' "$reset_unit" | grep -qxF 'Wants=ctrld.service'; then
  echo "install.sh: boot reset starts ctrld" >&2
  exit 1
fi

# The installer must parse inherited enablement, restore only enabled states
# on rollback, leave the unit disabled after a successful install, and stop on
# a masked unit before it can write a unit file through a /dev/null symlink.
state_body=$(sed -n '/^unit_enable_state() {/,/^}/p' "$INSTALL")
restore_body=$(sed -n '/^restore_unit_enablement() {/,/^}/p' "$INSTALL")
[ -n "$state_body" ] && [ -n "$restore_body" ] || {
  echo "install.sh: missing enablement parser or restore helper" >&2
  exit 1
}
check_enable_state() {
  local fake="$1" want_rc="$2" want_out="$3" want_err="$4" rc
  (
    systemctl() { printf '%s\n' "$FAKE_STATE"; }
    eval "$state_body"
    unit_enable_state beam-client
  ) >"$TMP/state.out" 2>"$TMP/state.err" && rc=0 || rc=$?
  [ "$rc" -eq "$want_rc" ] || {
    echo "install.sh: state '$fake' returned $rc, expected $want_rc" >&2
    exit 1
  }
  [ "$(cat "$TMP/state.out")" = "$want_out" ] || {
    echo "install.sh: state '$fake' parsed as '$(cat "$TMP/state.out")'" >&2
    exit 1
  }
  if [ -n "$want_err" ]; then
    grep -qF "$want_err" "$TMP/state.err" || {
      echo "install.sh: state '$fake' has no clear error" >&2
      cat "$TMP/state.err" >&2
      exit 1
    }
  fi
}
FAKE_STATE=enabled
check_enable_state enabled 0 enabled ''
FAKE_STATE=enabled-runtime
check_enable_state enabled-runtime 0 enabled-runtime ''
FAKE_STATE=static
check_enable_state static 0 static ''
FAKE_STATE=disabled
check_enable_state disabled 0 disabled ''
FAKE_STATE=masked
check_enable_state masked 1 '' 'is masked'
FAKE_STATE=masked-runtime
check_enable_state masked-runtime 1 '' 'unmask'

check_restore_state() {
  local state="$1" want="$2" rc
  : > "$TMP/enable.log"
  (
    systemctl() { printf '%s %s\n' "$1" "$2" >> "$TMP/enable.log"; }
    eval "$restore_body"
    restore_unit_enablement beam-client.service "$state"
  ) >/dev/null 2>&1 && rc=0 || rc=$?
  [ "$rc" -eq 0 ] || {
    echo "install.sh: rollback failed for '$state'" >&2
    exit 1
  }
  grep -qxF "$want" "$TMP/enable.log" || {
    echo "install.sh: rollback of '$state' did not run '$want'" >&2
    cat "$TMP/enable.log" >&2
    exit 1
  }
  case "$state" in
    enabled*)
      if grep -q '^disable ' "$TMP/enable.log"; then
        echo "install.sh: rollback disabled an enabled unit" >&2
        exit 1
      fi
      ;;
    *)
      if grep -q '^enable ' "$TMP/enable.log"; then
        echo "install.sh: rollback tried to enable '$state'" >&2
        exit 1
      fi
      ;;
  esac
}
check_restore_state enabled 'enable beam-client.service'
check_restore_state enabled-runtime 'enable beam-client.service'
check_restore_state static 'disable beam-client.service'
check_restore_state disabled 'disable beam-client.service'

state_line=$(grep -n '^DNS_RESET_STATE=\$(unit_enable_state' "$INSTALL" | cut -d: -f1 || true)
[ -n "$state_line" ] && [ "$state_line" -lt "$stop_line" ] || {
  echo "install.sh: enablement is not parsed before the stop" >&2
  exit 1
}
if grep -qF 'systemctl is-enabled --quiet' "$INSTALL"; then
  echo "install.sh: enablement still uses --quiet" >&2
  exit 1
fi
disable_line=$(grep -n '^if ! systemctl disable beam-client.service' "$INSTALL" | cut -d: -f1 || true)
commit_line=$(grep -n '^INSTALL_COMMITTED=1' "$INSTALL" | cut -d: -f1 || true)
[ -n "$disable_line" ] && [ -n "$commit_line" ] && [ "$disable_line" -lt "$commit_line" ] || {
  echo "install.sh: successful install does not disable beam-client" >&2
  exit 1
}

# A fresh install must name the pinned core files it needs, not fail later in
# the staging copy.
core_list=$(sed -n 's/^for core_file in \(.*\); do$/\1/p' "$INSTALL")
for core in sing-box libcronet.so LICENSE; do
  printf '%s\n' "$core_list" | tr ' ' '\n' | grep -qxF "$core" || {
    echo "install.sh: prerequisite loop does not name $core" >&2
    exit 1
  }
  grep -qF '"$CORE_DIR/$core_file"' "$INSTALL" || {
    echo "install.sh: no readable check for \$CORE_DIR/$core_file" >&2
    exit 1
  }
done

# A user-owned core directory or a symlinked directory can publish secret
# bytes. Exercise the installer's validator in a subshell with injected stat
# output, then check that the call sits before the staging copies.
validator=$(sed -n '/^validate_core_dir() {/,/^}/p' "$INSTALL")
[ -n "$validator" ] || {
  echo "install.sh: missing validate_core_dir" >&2
  exit 1
}
check_core_dir() {
  local want="$1" core_uid="$2" dir_mode="$3"
  shift 3
  local rc
  (
    stat() {
      local fmt path
      [ "${1:-}" = -c ] && shift
      fmt="$1"
      shift
      [ "${1:-}" = -- ] && shift
      path="$1"
      case "$path" in
        */LICENSE) printf '%s\n' "$core_uid" ;;
        *) [ "$fmt" = '%A' ] && printf '%s\n' "$dir_mode" || printf '%s\n' "$core_uid" ;;
      esac
    }
    eval "$validator"
    validate_core_dir "$CORE_TEST_DIR"
  ) >"$TMP/core.out" 2>&1 && rc=0 || rc=$?
  if [ "$rc" -ne "$want" ]; then
    echo "install.sh: core validator returned $rc, expected $want" >&2
    cat "$TMP/core.out" >&2
    exit 1
  fi
  if [ $# -gt 0 ]; then
    grep -qF "$1" "$TMP/core.out" || {
      echo "install.sh: core validator missed: $1" >&2
      cat "$TMP/core.out" >&2
      exit 1
    }
  fi
}

mkdir -p "$TMP/core-dir"
printf 'license\n' > "$TMP/core-dir/LICENSE"
CORE_TEST_DIR="$TMP/core-dir"
check_core_dir 0 0 '-rwxr-xr-x'
check_core_dir 1 1000 '-rwxr-xr-x' 'must be owned by root'
check_core_dir 1 0 '-rwxrwxr-x' 'group or world writable'
check_core_dir 1 0 '-rwxr-xrwx' 'group or world writable'
ln -s "$TMP/core-dir" "$TMP/core-link"
CORE_TEST_DIR="$TMP/core-link"
check_core_dir 1 0 '-rwxr-xr-x' 'must not be a symlink'
CORE_TEST_DIR="$TMP/core-dir"
ln -s "$TMP/core-dir/LICENSE" "$TMP/core-dir/LICENSE.link"
mv -f "$TMP/core-dir/LICENSE.link" "$TMP/core-dir/LICENSE.symlink"
rm -f "$TMP/core-dir/LICENSE"
ln -s LICENSE.symlink "$TMP/core-dir/LICENSE"
check_core_dir 1 0 '-rwxr-xr-x' 'not a symlink'

stage_line=$(grep -n '^STAGE_DIR=\$(mktemp' "$INSTALL" | cut -d: -f1 || true)
validate_line=$(grep -n '^validate_core_dir "\$CORE_DIR"' "$INSTALL" | cut -d: -f1 || true)
[ -n "$stage_line" ] && [ -n "$validate_line" ] || {
  echo "install.sh: missing core validation call or staging" >&2
  exit 1
}
[ "$validate_line" -lt "$stage_line" ] || {
  echo "install.sh: core validation runs after staging" >&2
  exit 1
}

# Repeated installs must not retain old generated profiles. Run the
# installer's own backup and prune functions against a temporary directory.
bak_dir="$TMP/config-bak"
mkdir -p "$bak_dir"
keep=$(sed -n 's/^CONFIG_BAK_KEEP=//p' "$INSTALL" | head -1 || true)
[ "$keep" = 3 ] || {
  echo "install.sh: no bounded config backup retention" >&2
  exit 1
}
backup_body=$(sed -n '/^backup_config() {/,/^}/p' "$INSTALL")
prune_body=$(sed -n '/^prune_config_backups() {/,/^}/p' "$INSTALL" |
  sed "s|/etc/beam|$bak_dir|g")
[ -n "$backup_body" ] && [ -n "$prune_body" ] || {
  echo "install.sh: missing backup_config or prune_config_backups" >&2
  exit 1
}
printf '%s\n' "$prune_body" | grep -qF 'LC_ALL=C sort' || {
  echo "install.sh: backup pruning does not use LC_ALL=C sort" >&2
  exit 1
}
cleanup_body=$(sed -n '/^cleanup() {/,/^}/p' "$INSTALL")
if printf '%s\n' "$cleanup_body" | grep -qF 'prune_config_backups'; then
  echo "install.sh: cleanup prunes before the install is committed" >&2
  exit 1
fi
prune_call=$(grep -n '^prune_config_backups$' "$INSTALL" | cut -d: -f1 || true)
[ -n "$prune_call" ] && [ "$prune_call" -gt "$commit_line" ] || {
  echo "install.sh: backups are pruned before the install is committed" >&2
  exit 1
}
CONFIG_BAK_KEEP="$keep"
eval "$backup_body"
eval "$prune_body"
printf 'live profile\n' > "$bak_dir/config.json"
chmod 0644 "$bak_dir/config.json"
backup_config "$bak_dir"
newest=$(find "$bak_dir" -maxdepth 1 -type f \
  -name 'config.json.bak-????????T???????????????Z' -printf '%f\n' |
  LC_ALL=C sort | tail -1)
[ -n "$newest" ] || {
  echo "install.sh: backup_config made no timestamped copy" >&2
  exit 1
}
[ "$(stat -c %a "$bak_dir/$newest")" = 600 ] || {
  echo "install.sh: backup copy is not mode 0600" >&2
  exit 1
}
printf 'operator file\n' > "$bak_dir/config.json.bak-pre-upgrade"
printf 'operator note\n' > "$bak_dir/config.json.bak-notes"
chmod 0644 "$bak_dir/config.json.bak-pre-upgrade" "$bak_dir/config.json.bak-notes"
for n in 01 02 03 04 05; do
  printf 'profile %s\n' "$n" > "$bak_dir/config.json.bak-202601${n}T000000000000000Z"
  chmod 0600 "$bak_dir/config.json.bak-202601${n}T000000000000000Z"
done
prune_config_backups
count=$(find "$bak_dir" -maxdepth 1 -type f \
  -name 'config.json.bak-????????T???????????????Z' | wc -l)
[ "$count" -eq "$keep" ] || {
  echo "install.sh: kept $count generated backups, expected $keep" >&2
  exit 1
}
[ -f "$bak_dir/config.json.bak-20260105T000000000000000Z" ] || {
  echo "install.sh: pruned the newest generated copy" >&2
  exit 1
}
[ -f "$bak_dir/config.json.bak-pre-upgrade" ] || {
  echo "install.sh: pruned an operator backup" >&2
  exit 1
}
[ -f "$bak_dir/config.json.bak-notes" ] || {
  echo "install.sh: pruned a non-timestamped file" >&2
  exit 1
}

# reload_resolved() execs this absolute path. The marker makes a reload fail.
cat > "$BIN_DIR/systemctl" <<EOF
#!/bin/sh
[ -e "$DNS_DIR/reload.fail" ] && exit 1
exit 0
EOF
chmod 0755 "$BIN_DIR/systemctl"

CC="${CC:-cc}"
"$CC" -std=c11 -O1 -Wall -Wextra -Werror \
  -DDNS_DIR="\"$DNS_DIR\"" \
  -DLOCK_PATH="\"$TMP/beam-helper.lock\"" \
  -DSYSTEMCTL="\"$BIN_DIR/systemctl\"" \
  -DTUN_IFACE='"lo"' \
  -DALLOWED_USER="\"$TMP/allowed-user\"" \
  -Dsyslog=beam_test_syslog \
  -Dgeteuid=beam_test_geteuid \
  -DUNLINK=beam_test_unlink \
  -DRENAME=beam_test_rename \
  -o "$TMP/test-dns-state" "$HERE/test_dns_state.c"

"$TMP/test-dns-state"
