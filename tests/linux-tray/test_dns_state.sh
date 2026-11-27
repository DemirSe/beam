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
user_line=$(grep -n 'id -u -- "$INSTALL_USER"' "$INSTALL" | cut -d: -f1 || true)
[ -n "$user_line" ] && [ "$user_line" -lt "$dir_line" ] || {
  echo "install.sh: INSTALL_USER is not resolved before side effects" >&2
  exit 1
}
grep -qF 'does not resolve to a user' "$INSTALL" || {
  echo "install.sh: unresolved INSTALL_USER has no named error" >&2
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

# The installer must record inherited enablement, restore it on rollback, and
# leave the unit disabled after a successful install. The wants symlink is not
# a managed path, so systemctl handles it.
enabled_line=$(grep -n 'systemctl is-enabled --quiet beam-client' "$INSTALL" | cut -d: -f1 || true)
[ -n "$enabled_line" ] && [ "$enabled_line" -lt "$stop_line" ] || {
  echo "install.sh: beam-client enablement is not recorded before the stop" >&2
  exit 1
}
disable_line=$(grep -n '^if ! systemctl disable beam-client.service' "$INSTALL" | cut -d: -f1 || true)
commit_line=$(grep -n '^INSTALL_COMMITTED=1' "$INSTALL" | cut -d: -f1 || true)
[ -n "$disable_line" ] && [ -n "$commit_line" ] && [ "$disable_line" -lt "$commit_line" ] || {
  echo "install.sh: successful install does not disable beam-client" >&2
  exit 1
}
rollback_body=$(sed -n '/^rollback_live() {/,/^}/p' "$INSTALL")
printf '%s\n' "$rollback_body" | grep -qF 'systemctl enable beam-client.service' || {
  echo "install.sh: rollback does not restore beam-client enablement" >&2
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

# A user-owned core directory with a symlinked LICENSE can publish secret
# bytes. Both ownership checks must run before the staging copies.
stage_line=$(grep -n '^STAGE_DIR=\$(mktemp' "$INSTALL" | cut -d: -f1 || true)
core_owner_line=$(grep -n 'CORE_DIR must be owned by root' "$INSTALL" | cut -d: -f1 || true)
license_line=$(grep -n 'LICENSE must be a root-owned regular file' "$INSTALL" | cut -d: -f1 || true)
[ -n "$stage_line" ] && [ -n "$core_owner_line" ] && [ -n "$license_line" ] || {
  echo "install.sh: missing CORE_DIR or LICENSE ownership check" >&2
  exit 1
}
[ "$core_owner_line" -lt "$stage_line" ] && [ "$license_line" -lt "$stage_line" ] || {
  echo "install.sh: core ownership checks run after staging" >&2
  exit 1
}
grep -qF '[ -L "$CORE_DIR/LICENSE" ]' "$INSTALL" || {
  echo "install.sh: LICENSE symlinks are not rejected" >&2
  exit 1
}
grep -qF 'stat -Lc %u "$CORE_DIR"' "$INSTALL" || {
  echo "install.sh: CORE_DIR owner is not checked" >&2
  exit 1
}

# Repeated installs must not retain old profiles. Run the installer's own
# prune function against a temporary directory.
bak_dir="$TMP/config-bak"
mkdir -p "$bak_dir"
keep=$(sed -n 's/^CONFIG_BAK_KEEP=//p' "$INSTALL" | head -1 || true)
[ "$keep" = 3 ] || {
  echo "install.sh: no bounded config backup retention" >&2
  exit 1
}
prune_body=$(sed -n '/^prune_config_backups() {/,/^}/p' "$INSTALL" |
  sed "s|/etc/beam|$bak_dir|g")
[ -n "$prune_body" ] || {
  echo "install.sh: missing prune_config_backups" >&2
  exit 1
}
CONFIG_BAK_KEEP="$keep"
eval "$prune_body"
for n in 01 02 03 04 05; do
  printf 'profile %s\n' "$n" > "$bak_dir/config.json.bak-202601${n}T000000000Z"
  chmod 0600 "$bak_dir/config.json.bak-202601${n}T000000000Z"
done
prune_config_backups
count=$(find "$bak_dir" -maxdepth 1 -type f -name 'config.json.bak-*' | wc -l)
[ "$count" -eq "$keep" ] || {
  echo "install.sh: kept $count config backups, expected $keep" >&2
  exit 1
}
[ -f "$bak_dir/config.json.bak-20260105T000000000Z" ] || {
  echo "install.sh: pruned the newest pre-replace copy" >&2
  exit 1
}
[ "$(stat -c %a "$bak_dir/config.json.bak-20260105T000000000Z")" = 600 ] || {
  echo "install.sh: pruned copy changed mode" >&2
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
