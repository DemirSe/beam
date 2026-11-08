#!/bin/bash
# Bootstrap beam on a fresh Debian 13 host. Run as root from the bundle directory.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/beam"
CONFIG="$HERE/beam.toml"
UNIT="$HERE/beam.service"
SYSCTL="$HERE/99-beam.conf"
CONNTRACK="$HERE/99-beam-conntrack.conf"
MODULES_LOAD="$HERE/99-beam-conntrack.modules"
IPV4_DROPIN="$HERE/beam-ipv4-only.conf"
IPV6_SYSCTL="$HERE/99-beam-ipv6-disable.conf"
SSHD_DROPIN="$HERE/sshd-61-ipv4-only.conf"
INSTALL_BIN=/usr/local/bin/beam
INSTALL_CONFIG=/etc/beam/config.toml
INSTALL_UNIT=/etc/systemd/system/beam.service
INSTALL_SYSCTL=/etc/sysctl.d/99-beam.conf
INSTALL_CONNTRACK=/etc/sysctl.d/99-beam-conntrack.conf
INSTALL_MODULES_LOAD=/etc/modules-load.d/99-beam-conntrack.conf
INSTALL_IPV4_DROPIN=/etc/systemd/system/beam.service.d/99-ipv4-only.conf
INSTALL_IPV6_SYSCTL=/etc/sysctl.d/99-beam-ipv6-disable.conf
INSTALL_SSHD_DROPIN=/etc/ssh/sshd_config.d/61-ipv4-only.conf
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
IPV6_APPLIED=0
SSHD_RELOADED=0
ORIGINAL_IPV6_ALL=
ORIGINAL_IPV6_DEFAULT=
ORIGINAL_IPV6_LO=
ORIGINAL_IPV6_ADDRS=
ORIGINAL_IPV6_DEFAULT_ROUTES=
ORIGINAL_SSHD_FAMILY=
ORIGINAL_SSH_IPV6_LISTENER=0

# Keep a live config when only the binary/unit are being updated. An existing
# live config defaults to preserve so a plain documented rollout cannot
# silently replace identity/limits. A fresh host defaults to install; replacing
# an existing config requires an explicit BEAM_KEEP_CONFIG=0.
if [ -n "${BEAM_KEEP_CONFIG:-}" ]; then
  KEEP_CONFIG="$BEAM_KEEP_CONFIG"
elif [ -e "$INSTALL_CONFIG" ]; then
  KEEP_CONFIG=1
else
  KEEP_CONFIG=0
fi
case "$KEEP_CONFIG" in
  0|1) ;;
  *) echo "bootstrap: BEAM_KEEP_CONFIG must be 0 or 1" >&2; exit 1 ;;
esac
echo "bootstrap: KEEP_CONFIG=$KEEP_CONFIG (existing configs default to preserve; set BEAM_KEEP_CONFIG=0 explicitly to replace)" >&2

[ "$(id -u)" -eq 0 ] || { echo "bootstrap: must run as root" >&2; exit 1; }
for file in "$BIN" "$UNIT" "$SYSCTL" "$CONNTRACK" "$MODULES_LOAD" \
    "$IPV4_DROPIN" "$IPV6_SYSCTL" "$SSHD_DROPIN"; do
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

[ -x /usr/sbin/sshd ] || { echo "bootstrap: missing /usr/sbin/sshd" >&2; exit 1; }
systemctl cat ssh.service >/dev/null 2>&1 || {
  echo "bootstrap: ssh.service is not available" >&2
  exit 1
}
grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)' \
  /etc/ssh/sshd_config || {
  echo "bootstrap: /etc/ssh/sshd_config does not include sshd_config.d/*.conf" >&2
  exit 1
}
for cmd in ip ss sysctl; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "bootstrap: missing command $cmd" >&2
    exit 1
  }
done
/usr/sbin/sshd -t >/dev/null 2>&1 || {
  echo "bootstrap: existing sshd configuration is invalid" >&2
  exit 1
}
[ -n "$(ss -H -4 -ltnp "sport = :22" 2>/dev/null || true)" ] || {
  echo "bootstrap: no IPv4 SSH listener on port 22; refusing IPv4-only SSH policy" >&2
  exit 1
}
# Capture the complete pre-change host policy. Rollback must restore these
# exact values, not a hardcoded enabled/disabled assumption, and every query
# must fail closed: a broken `ip`/`ss`/`sshd` must abort the rollout instead of
# being read as "no addresses/routes/listeners".
for key in all default lo; do
  value="$(sysctl -n "net.ipv6.conf.$key.disable_ipv6")" || {
    echo "bootstrap: cannot read net.ipv6.conf.$key.disable_ipv6" >&2
    exit 1
  }
  case "$value" in
    0|1) ;;
    *) echo "bootstrap: net.ipv6.conf.$key.disable_ipv6=$value (expected 0 or 1)" >&2; exit 1 ;;
  esac
  printf -v "ORIGINAL_IPV6_${key^^}" '%s' "$value"
done
ORIGINAL_IPV6_ADDRS="$(ip -6 -o addr show | awk '{print $2, $4}' | sort)" || {
  echo "bootstrap: cannot query IPv6 addresses" >&2
  exit 1
}
ORIGINAL_IPV6_DEFAULT_ROUTES="$(ip -6 -o route show default | sort)" || {
  echo "bootstrap: cannot query IPv6 default routes" >&2
  exit 1
}
ORIGINAL_SSHD_FAMILY="$(/usr/sbin/sshd -T 2>/dev/null | sed -n 's/^addressfamily //p')" || {
  echo "bootstrap: cannot query the sshd address family" >&2
  exit 1
}
case "$ORIGINAL_SSHD_FAMILY" in
  any|inet|inet6) ;;
  *) echo "bootstrap: unexpected sshd addressfamily '$ORIGINAL_SSHD_FAMILY'" >&2; exit 1 ;;
esac
ssh_ipv6_listeners="$(ss -H -6 -ltnp "sport = :22")" || {
  echo "bootstrap: cannot query IPv6 SSH listeners" >&2
  exit 1
}
[ -z "$ssh_ipv6_listeners" ] || ORIGINAL_SSH_IPV6_LISTENER=1

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
WAS_ENABLED="$(systemctl is-enabled beam 2>/dev/null || true)"
for old in "$INSTALL_BIN" "$INSTALL_CONFIG" "$INSTALL_UNIT" "$INSTALL_SYSCTL" "$INSTALL_CONNTRACK" "$INSTALL_MODULES_LOAD" "$INSTALL_IPV4_DROPIN" "$INSTALL_IPV6_SYSCTL" "$INSTALL_SSHD_DROPIN"; do
  if [ -e "$old" ] || [ -L "$old" ]; then
    cp -a "$old" "$old.bak-$STAMP"
  fi
done

# A failed rollout must not leave new files on disk with a stopped service.
# Only restart when a live file or the unit was actually replaced; a rejected
# preflight or sysctl must not bounce an otherwise healthy service.
DIRTY=0
declare -A INSTALLED=()
wait_ready() {
  local _
  for _ in $(seq 1 15); do
    if systemctl is-active --quiet beam &&
       ss -ltnp "sport = :443" 2>/dev/null | grep -q 'beam'; then
      return 0
    fi
    sleep 1
  done
  return 1
}
# A validated config and a successful HUP do not prove sshd survived the
# re-exec: a failed bind would leave the host unreachable. Poll briefly for a
# live IPv4 listener and fail closed on a query error.
wait_ipv4_ssh() {
  local listeners
  for _ in $(seq 1 10); do
    if ! listeners="$(ss -H -4 -ltnp "sport = :22" 2>/dev/null)"; then
      echo "bootstrap: cannot query IPv4 SSH listeners" >&2
      return 1
    fi
    [ -n "$listeners" ] && return 0
    sleep 1
  done
  echo "bootstrap: IPv4 SSH listener is missing" >&2
  return 1
}
prune_backups() {
  for base in "$INSTALL_BIN" "$INSTALL_CONFIG" "$INSTALL_UNIT" "$INSTALL_SYSCTL" "$INSTALL_CONNTRACK" "$INSTALL_MODULES_LOAD" "$INSTALL_IPV4_DROPIN" "$INSTALL_IPV6_SYSCTL" "$INSTALL_SSHD_DROPIN"; do
    find "$(dirname "$base")" -maxdepth 1 -type f \
      -name "$(basename "$base").bak-*" -printf '%T@ %p\n' 2>/dev/null |
      sort -rn | tail -n +6 | cut -d' ' -f2- | xargs -r rm -f || true
  done
}

# Bring IPv6 back after a rollback. Reconfigure every networkd-managed link
# so the kernel re-runs its IPv6 setup (addresses and default route) without a
# reboot; restart networkd when networkctl cannot enumerate links.
reconfigure_ipv6_interfaces() {
  local iface found=0
  if command -v networkctl >/dev/null 2>&1; then
    for iface in $(networkctl list --no-legend 2>/dev/null | awk '{print $2}'); do
      [ "$iface" = "lo" ] && continue
      found=1
      networkctl reconfigure "$iface" >/dev/null 2>&1 || return 1
    done
    [ "$found" = "1" ] && return 0
  fi
  systemctl restart systemd-networkd >/dev/null 2>&1
}

# Require the live IPv6 sysctls, addresses, and default routes to match the
# captured pre-change state exactly. Any failed query is a rollback failure; it
# must never read as an empty match.
verify_original_ipv6_network() {
  local key value name addrs routes rc=0
  for key in all default lo; do
    if ! value="$(sysctl -n "net.ipv6.conf.$key.disable_ipv6" 2>/dev/null)"; then
      echo "bootstrap: cannot read net.ipv6.conf.$key.disable_ipv6 during rollback verification" >&2
      return 1
    fi
    name="ORIGINAL_IPV6_${key^^}"
    if [ "$value" != "${!name}" ]; then
      echo "bootstrap: net.ipv6.conf.$key.disable_ipv6=$value after rollback (expected ${!name})" >&2
      rc=1
    fi
  done
  if ! addrs="$(ip -6 -o addr show 2>/dev/null | awk '{print $2, $4}' | sort)"; then
    echo "bootstrap: cannot query IPv6 addresses during rollback verification" >&2
    return 1
  fi
  if [ "$addrs" != "$ORIGINAL_IPV6_ADDRS" ]; then
    echo "bootstrap: IPv6 address set differs from the captured original state" >&2
    rc=1
  fi
  if ! routes="$(ip -6 -o route show default 2>/dev/null | sort)"; then
    echo "bootstrap: cannot query IPv6 default routes during rollback verification" >&2
    return 1
  fi
  if [ "$routes" != "$ORIGINAL_IPV6_DEFAULT_ROUTES" ]; then
    echo "bootstrap: IPv6 default route differs from the captured original state" >&2
    rc=1
  fi
  return "$rc"
}

# Require the restored sshd family and IPv6 listener state to match the
# captured originals. Called only after ssh has been reloaded with the restored
# config and IPv6 has been restored, so an originally-enabled host can bind its
# IPv6 listener again.
verify_original_ssh() {
  local family listeners listener=0 rc=0
  if ! family="$(/usr/sbin/sshd -T 2>/dev/null | sed -n 's/^addressfamily //p')"; then
    echo "bootstrap: cannot query the sshd address family during rollback verification" >&2
    return 1
  fi
  if [ "$family" != "$ORIGINAL_SSHD_FAMILY" ]; then
    echo "bootstrap: sshd addressfamily=$family after rollback (expected $ORIGINAL_SSHD_FAMILY)" >&2
    rc=1
  fi
  if ! listeners="$(ss -H -6 -ltnp "sport = :22" 2>/dev/null)"; then
    echo "bootstrap: cannot query IPv6 SSH listeners during rollback verification" >&2
    return 1
  fi
  [ -z "$listeners" ] || listener=1
  if [ "$listener" != "$ORIGINAL_SSH_IPV6_LISTENER" ]; then
    echo "bootstrap: IPv6 SSH listener state is $listener after rollback (expected $ORIGINAL_SSH_IPV6_LISTENER)" >&2
    rc=1
  fi
  return "$rc"
}

verify_original_ipv6() {
  local rc=0
  verify_original_ipv6_network || rc=1
  verify_original_ssh || rc=1
  return "$rc"
}

# Recover SSH after a rollback. A reload that failed, or a daemon that died
# during re-exec/binding, cannot be reloaded; start it when inactive. Then poll
# until the original listener state is back, failing closed on query errors.
restore_ssh_service() {
  local listeners ok=0
  if systemctl is-active --quiet ssh; then
    if ! /usr/sbin/sshd -t >/dev/null 2>&1; then
      echo "bootstrap: restored sshd config is invalid" >&2
      return 1
    fi
    systemctl reload ssh >/dev/null 2>&1 || {
      echo "bootstrap: failed to reload ssh after restoring its config" >&2
      return 1
    }
  else
    # A stopped unit has lost RuntimeDirectory=sshd, so a standalone sshd -t
    # fails. Start the unit: it recreates the directory and runs its own
    # ExecStartPre sshd -t before accepting the config.
    systemctl start ssh >/dev/null 2>&1 || {
      echo "bootstrap: failed to start ssh after rollback" >&2
      return 1
    }
  fi
  for _ in $(seq 1 10); do
    if ! listeners="$(ss -H -4 -ltnp "sport = :22" 2>/dev/null)"; then
      echo "bootstrap: cannot query IPv4 SSH listeners after rollback" >&2
      return 1
    fi
    if [ -n "$listeners" ] &&
       systemctl is-active --quiet ssh &&
       verify_original_ssh >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 1
  done
  if [ "$ok" != "1" ]; then
    echo "bootstrap: SSH is not restored to its original state" >&2
    return 1
  fi
}

rollback() {
  trap - ERR
  set +e
  local rc=0 base key name ipv6_ok=0
  echo "bootstrap: rolling back to backups from $STAMP" >&2
  rm -f "$INSTALL_BIN.new" "$INSTALL_CONFIG.new" "$INSTALL_UNIT.new" \
    "$INSTALL_SYSCTL.new" "$INSTALL_CONNTRACK.new" "$INSTALL_MODULES_LOAD.new" \
    "$INSTALL_IPV4_DROPIN.new" "$INSTALL_IPV6_SYSCTL.new" "$INSTALL_SSHD_DROPIN.new" \
    || rc=1
  for base in "$INSTALL_BIN" "$INSTALL_CONFIG" "$INSTALL_UNIT" "$INSTALL_SYSCTL" "$INSTALL_CONNTRACK" "$INSTALL_MODULES_LOAD" "$INSTALL_IPV4_DROPIN" "$INSTALL_IPV6_SYSCTL" "$INSTALL_SSHD_DROPIN"; do
    if [ -e "$base.bak-$STAMP" ] || [ -L "$base.bak-$STAMP" ]; then
      if cp -a --remove-destination "$base.bak-$STAMP" "$base"; then
        cmp -s "$base.bak-$STAMP" "$base" || rc=1
      else
        echo "bootstrap: failed to restore $base" >&2
        rc=1
      fi
    elif [ "${INSTALLED[$base]:-0}" = "1" ]; then
      rm -f "$base" || rc=1
    fi
  done
  if [ "$IPV6_APPLIED" = "1" ]; then
    if [ ! -e "$INSTALL_IPV6_SYSCTL.bak-$STAMP" ]; then
      rm -f "$INSTALL_IPV6_SYSCTL" || rc=1
    fi
    for key in all default lo; do
      name="ORIGINAL_IPV6_${key^^}"
      sysctl -w "net.ipv6.conf.$key.disable_ipv6=${!name}" >/dev/null 2>&1 || {
        echo "bootstrap: failed to restore net.ipv6.conf.$key.disable_ipv6=${!name}" >&2
        rc=1
      }
    done
    # Only a host that was IPv6-enabled needs its links reconfigured. A host
    # that started IPv6-disabled keeps the restored disabled policy.
    if [ "$ORIGINAL_IPV6_ALL" = "0" ]; then
      reconfigure_ipv6_interfaces || {
        echo "bootstrap: failed to reconfigure interfaces after restoring IPv6" >&2
        rc=1
      }
    fi
    for _ in $(seq 1 10); do
      if verify_original_ipv6_network >/dev/null 2>&1; then
        ipv6_ok=1
        break
      fi
      sleep 1
    done
    if [ "$ipv6_ok" != "1" ]; then
      verify_original_ipv6_network || true
      rc=1
    fi
  fi
  # Recover ssh only after IPv6 is back: an originally-enabled host must be
  # able to bind [::]:22 again when the restored config is AddressFamily any.
  # An inactive daemon is started, not reloaded.
  if [ "$SSHD_RELOADED" = "1" ]; then
    restore_ssh_service || rc=1
  fi
  if [ "$IPV6_APPLIED" = "1" ] || [ "$SSHD_RELOADED" = "1" ]; then
    verify_original_ipv6 || rc=1
  fi
  if [ -z "$(ss -H -4 -ltnp "sport = :22" 2>/dev/null || true)" ]; then
    echo "bootstrap: IPv4 SSH listener is missing after rollback" >&2
    rc=1
  fi
  if ! sysctl -p "$INSTALL_SYSCTL" >/dev/null 2>&1; then
    echo "bootstrap: failed to restore sysctl settings" >&2
    rc=1
  fi
  if [ -f "$INSTALL_CONNTRACK" ]; then
    sysctl -p "$INSTALL_CONNTRACK" >/dev/null 2>&1 || rc=1
  fi
  if [ "$DIRTY" = "1" ]; then
    systemctl daemon-reload >/dev/null 2>&1 || rc=1
    systemctl reset-failed beam >/dev/null 2>&1 || true
    systemctl restart beam >/dev/null 2>&1 || rc=1
    wait_ready || rc=1
    if [ "$WAS_ENABLED" != "enabled" ]; then
      case "$WAS_ENABLED" in
        enabled-runtime)
          systemctl disable beam >/dev/null 2>&1 || rc=1
          systemctl enable --runtime beam >/dev/null 2>&1 || rc=1
          ;;
        masked) systemctl mask beam >/dev/null 2>&1 || rc=1 ;;
        masked-runtime) systemctl mask --runtime beam >/dev/null 2>&1 || rc=1 ;;
        *) systemctl disable beam >/dev/null 2>&1 || rc=1 ;;
      esac
    fi
  fi
  if [ "$rc" -eq 0 ]; then
    prune_backups
  else
    echo "bootstrap: rollback incomplete; retaining backups from $STAMP" >&2
  fi
  return "$rc"
}
trap 'echo "bootstrap: rollout failed; restoring previous files" >&2; if ! rollback; then echo "bootstrap: rollback incomplete" >&2; fi; exit 1' ERR
fail_rollback() {
  echo "bootstrap: $*" >&2
  if ! rollback; then
    echo "bootstrap: rollback incomplete" >&2
  fi
  exit 1
}

# Install beside the destination and validate there before replacing the
# running binary. `/tmp` may be mounted noexec, and a broken installed binary
# would turn the next restart or reboot into an outage. A fresh-install config
# is staged root:beam 0640 so the unprivileged service user can read exactly
# the file that is about to become live.
install -m 0755 -o root -g root "$BIN" "$INSTALL_BIN.new"
if [ "$KEEP_CONFIG" = "1" ]; then
  CHECK_CONFIG="$INSTALL_CONFIG"
else
  install -m 0640 -o root -g beam "$CONFIG" "$INSTALL_CONFIG.new"
  CHECK_CONFIG="$INSTALL_CONFIG.new"
fi
if ! bash -c 'ulimit -n 65536 2>/dev/null || true; exec "$0" --check -c "$1"' \
    "$INSTALL_BIN.new" "$CHECK_CONFIG"; then
  rm -f "$INSTALL_BIN.new" "$INSTALL_CONFIG.new"
  echo "bootstrap: new binary failed --check; live binary unchanged" >&2
  exit 1
fi
if ! runuser -u beam -- bash -c 'ulimit -n 65536 2>/dev/null || true; exec "$0" --check -c "$1"' \
    "$INSTALL_BIN.new" "$CHECK_CONFIG"; then
  rm -f "$INSTALL_BIN.new" "$INSTALL_CONFIG.new"
  echo "bootstrap: new binary failed the beam-user check; live binary unchanged" >&2
  exit 1
fi

# Apply required sysctls only after both binary/config preflights pass. BBR/fq
# and UDP buffer limits are part of the running configuration, not optional
# tuning, but a rejected binary must not mutate the live kernel.
sysctl -p "$SYSCTL" >/dev/null
# net.core.default_qdisc only affects newly created interfaces. Existing
# cloud NICs keep their old qdisc until reboot, so apply fq to the default
# route now. Keep this best-effort: a missing tc/ip must not fail a rollout.
apply_live_qdisc() {
  local tc ip iface
  tc="$(command -v tc 2>/dev/null || command -v /usr/sbin/tc 2>/dev/null || true)"
  ip="$(command -v ip 2>/dev/null || command -v /usr/sbin/ip 2>/dev/null || true)"
  if [ -z "$tc" ] || [ -z "$ip" ]; then
    echo "bootstrap: warning: tc/ip unavailable; fq not applied live" >&2
    return 0
  fi
  iface="$("$ip" -o route show default 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' 2>/dev/null || true)"
  [ -n "$iface" ] || return 0
  "$tc" qdisc replace dev "$iface" root fq 2>/dev/null || \
    echo "bootstrap: warning: could not apply fq to $iface" >&2
}
apply_live_qdisc
# systemd-sysctl.service is ordered after systemd-modules-load.service. Install
# the module-load request before applying the sysctls so a fresh boot has the
# net.netfilter keys available without relying on nftables' module autoload.
install -d -m 0755 /etc/modules-load.d
install -m 0644 -o root -g root "$MODULES_LOAD" "$INSTALL_MODULES_LOAD.new"
mv -f "$INSTALL_MODULES_LOAD.new" "$INSTALL_MODULES_LOAD"
INSTALLED["$INSTALL_MODULES_LOAD"]=1
DIRTY=1
if command -v modprobe >/dev/null 2>&1; then
  modprobe nf_conntrack 2>/dev/null || true
fi
if ! sysctl -p "$CONNTRACK" >/dev/null 2>&1; then
  echo "bootstrap: warning: conntrack sysctl keys are not available yet" >&2
fi

mv -f "$INSTALL_BIN.new" "$INSTALL_BIN"
INSTALLED["$INSTALL_BIN"]=1
if [ "$KEEP_CONFIG" = "0" ]; then
  mv -f "$INSTALL_CONFIG.new" "$INSTALL_CONFIG"
  INSTALLED["$INSTALL_CONFIG"]=1
fi
install -m 0644 -o root -g root "$UNIT" "$INSTALL_UNIT.new"
mv -f "$INSTALL_UNIT.new" "$INSTALL_UNIT"
INSTALLED["$INSTALL_UNIT"]=1
install -d -m 0755 /etc/systemd/system/beam.service.d
install -m 0644 -o root -g root "$IPV4_DROPIN" "$INSTALL_IPV4_DROPIN.new"
mv -f "$INSTALL_IPV4_DROPIN.new" "$INSTALL_IPV4_DROPIN"
INSTALLED["$INSTALL_IPV4_DROPIN"]=1
DIRTY=1
install -m 0644 -o root -g root "$SYSCTL" "$INSTALL_SYSCTL.new"
mv -f "$INSTALL_SYSCTL.new" "$INSTALL_SYSCTL"
INSTALLED["$INSTALL_SYSCTL"]=1
if [ -f "$CONNTRACK" ]; then
  install -m 0644 -o root -g root "$CONNTRACK" "$INSTALL_CONNTRACK.new"
  mv -f "$INSTALL_CONNTRACK.new" "$INSTALL_CONNTRACK"
  INSTALLED["$INSTALL_CONNTRACK"]=1
fi

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
if ! wait_ready; then
  echo "bootstrap: beam did not become active and listening on 443" >&2
  systemctl status --no-pager -l beam || true
  journalctl -u beam -n 50 --no-pager || true
  if ! rollback; then
    echo "bootstrap: rollback incomplete" >&2
  fi
  exit 1
fi
# The SSH family policy is applied only after beam is confirmed healthy.
# A failure here restores the SSH config and any sysctl changes before exit.
install -d -m 0755 /etc/ssh/sshd_config.d
install -m 0644 -o root -g root "$SSHD_DROPIN" "$INSTALL_SSHD_DROPIN.new"
mv -f "$INSTALL_SSHD_DROPIN.new" "$INSTALL_SSHD_DROPIN"
INSTALLED["$INSTALL_SSHD_DROPIN"]=1
if ! /usr/sbin/sshd -t >/dev/null 2>&1; then
  fail_rollback "new sshd config failed validation"
fi
# Mark the reload as potentially effective before attempting it: a reload that
# returns failure may still have re-exec'd sshd, so rollback must recover SSH.
SSHD_RELOADED=1
if ! systemctl reload ssh >/dev/null 2>&1; then
  fail_rollback "ssh reload failed"
fi
sleep 1
if ! ssh_ipv6_listeners="$(ss -H -6 -ltnp "sport = :22" 2>/dev/null)"; then
  fail_rollback "cannot query IPv6 SSH listeners after reload"
fi
[ -z "$ssh_ipv6_listeners" ] || fail_rollback "IPv6 SSH listener remains after reload"
if ! sshd_family="$(/usr/sbin/sshd -T 2>/dev/null | sed -n 's/^addressfamily //p')"; then
  fail_rollback "cannot query sshd address family after reload"
fi
[ "$sshd_family" = "inet" ] || fail_rollback "sshd does not report addressfamily inet"
if ! systemctl is-active --quiet ssh; then
  fail_rollback "ssh is not active after reload"
fi
if ! wait_ipv4_ssh; then
  fail_rollback "IPv4 SSH listener is missing after reload"
fi

# Persist and apply host-wide IPv6 disable last. IPV6_APPLIED is set before
# sysctl -p so a partial apply is reverted by rollback rather than left live.
install -d -m 0755 /etc/sysctl.d
install -m 0644 -o root -g root "$IPV6_SYSCTL" "$INSTALL_IPV6_SYSCTL.new"
mv -f "$INSTALL_IPV6_SYSCTL.new" "$INSTALL_IPV6_SYSCTL"
INSTALLED["$INSTALL_IPV6_SYSCTL"]=1
IPV6_APPLIED=1
if ! sysctl -p "$INSTALL_IPV6_SYSCTL" >/dev/null; then
  fail_rollback "host IPv6 sysctl apply failed"
fi
for key in all default lo; do
  if ! value="$(sysctl -n "net.ipv6.conf.$key.disable_ipv6" 2>/dev/null)"; then
    fail_rollback "cannot read net.ipv6.conf.$key.disable_ipv6 after host-wide disable"
  fi
  [ "$value" = "1" ] || fail_rollback "net.ipv6.conf.$key.disable_ipv6=$value (expected 1)"
done
if ! ipv6_addrs="$(ip -6 addr show 2>/dev/null)"; then
  fail_rollback "cannot query IPv6 addresses after host-wide disable"
fi
[ -z "$ipv6_addrs" ] || fail_rollback "IPv6 addresses remain after host-wide disable"
if ! ipv6_routes="$(ip -6 route show table all 2>/dev/null)"; then
  fail_rollback "cannot query IPv6 routes after host-wide disable"
fi
[ -z "$ipv6_routes" ] || fail_rollback "IPv6 routes remain after host-wide disable"
if ! ipv6_listeners="$(ss -H -6 -lntup 2>/dev/null)"; then
  fail_rollback "cannot query IPv6 listeners after host-wide disable"
fi
[ -z "$ipv6_listeners" ] || fail_rollback "IPv6 listeners remain after host-wide disable"
if ! sshd_family="$(/usr/sbin/sshd -T 2>/dev/null | sed -n 's/^addressfamily //p')"; then
  fail_rollback "cannot query sshd address family after host-wide disable"
fi
[ "$sshd_family" = "inet" ] || fail_rollback "sshd reports an IPv6 address family after host-wide disable"
if ! systemctl is-active --quiet beam; then
  fail_rollback "beam is not active after host-wide disable"
fi
beam_listener="$(ss -H -ltnp "sport = :443" 2>/dev/null || true)"
case "$beam_listener" in
  *beam*) ;;
  *) fail_rollback ":443 is not owned by beam after host-wide disable" ;;
esac
if ! systemctl is-active --quiet ssh; then
  fail_rollback "ssh is not active after host-wide disable"
fi
if ! wait_ipv4_ssh; then
  fail_rollback "IPv4 SSH listener is missing after host-wide disable"
fi

trap - ERR
prune_backups

echo "bootstrap: beam is active on 443 ($("$INSTALL_BIN" --version))"
systemctl status --no-pager -l beam | sed -n '1,12p'
