#!/bin/sh
# Read-only post-boot health check. The output goes to the journal, and the
# last line is either "post-boot: PASS" or "post-boot: FAIL".
#
# This script changes nothing. It exists so that the first thing an operator or
# an agent sees after a reboot is a clear verdict instead of a guess.
set -u
fail=0
SSH_PORT="${SSH_PORT:-22}"
say() { printf 'post-boot: %s\n' "$*"; }

# Each entry lists the unit names that satisfy the role, Debian first. AlmaLinux
# names these units chronyd and sshd.
for role in "beam" "chrony chronyd" "fail2ban" "nftables" "ssh sshd"; do
  name=${role%% *}
  state=missing
  for unit in $role; do
    state=$(systemctl is-active "$unit" 2>/dev/null || true)
    name=$unit
    [ "$state" = "active" ] && break
  done
  if [ "$state" = "active" ]; then
    say "ok unit $name"
  else
    say "FAIL unit $name=$state"
    fail=1
  fi
done

listen=$(ss -H -4 -lnt 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -u | tr '\n' ' ')
for port in "$SSH_PORT" 443; do
  case " $listen " in
    *" $port "*) say "ok port $port" ;;
    *) say "FAIL port $port missing, open: $listen"; fail=1 ;;
  esac
done

v6=$(ss -H -6 -lntup 2>/dev/null | wc -l)
if [ "$v6" -eq 0 ]; then say "ok ipv6 listeners 0"; else say "FAIL ipv6 listeners $v6"; fail=1; fi

offset=$(chronyc tracking 2>/dev/null | awk '/System time/{print $4}')
case "$offset" in
  ''|*[!0-9.]*) say "FAIL clock offset unreadable"; fail=1 ;;
  *) awk -v o="$offset" 'BEGIN{exit !(o < 1.0)}' \
       && say "ok clock offset ${offset}s" \
       || { say "FAIL clock offset ${offset}s"; fail=1; } ;;
esac

pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || true)
if [ "$pattern" = "|/bin/false" ]; then say "ok coredumps disabled"; else say "FAIL core_pattern=$pattern"; fail=1; fi

used=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
if [ "${used:-100}" -lt 90 ]; then say "ok disk ${used}%"; else say "FAIL disk ${used}%"; fail=1; fi

if /usr/local/bin/beam --check -c /etc/beam/config.toml >/dev/null 2>&1; then
  say "ok config valid"
else
  say "FAIL config invalid"
  fail=1
fi

# A stopped watchdog is silent: the service stays healthy and every line above
# still passes. Check the timer, then check that it actually fired.
if [ "$(systemctl is-enabled beam-liveness.timer 2>/dev/null || true)" = "enabled" ] &&
   [ "$(systemctl is-active beam-liveness.timer 2>/dev/null || true)" = "active" ]; then
  say "ok watchdog enabled and active"
else
  say "FAIL watchdog enabled=$(systemctl is-enabled beam-liveness.timer 2>/dev/null || echo missing) active=$(systemctl is-active beam-liveness.timer 2>/dev/null || echo missing)"
  fail=1
fi

# At boot the first liveness run is five minutes away, so a missing trigger is
# only a failure after that window has passed.
up=$(cut -d. -f1 /proc/uptime)
last=$(systemctl show beam-liveness.timer -p LastTriggerUSec --value 2>/dev/null || true)
case "$last" in
  ''|n/a)
    if [ "$up" -lt 600 ]; then say "ok watchdog pending first run"
    else say "FAIL watchdog never fired in ${up}s of uptime"; fail=1; fi ;;
  *)
    last_s=$(date -d "$last" +%s 2>/dev/null || echo 0)
    age=$(( $(date +%s) - last_s ))
    if [ "$age" -gt 600 ]; then say "FAIL watchdog last fired ${age}s ago"; fail=1
    else say "ok watchdog last fired ${age}s ago"; fi ;;
esac

[ "$fail" -eq 0 ] && say "PASS" || say "FAIL"
exit 0
