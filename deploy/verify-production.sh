#!/usr/bin/env bash
# Read-only production verification with explicit assertions.
# No config contents or secrets are printed.
set -euo pipefail

: "${SSH_KEY:?set SSH_KEY to the private key path}"
: "${SERVER:?set SERVER to user@host}"
SSH=(ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$SERVER")

remote() { "${SSH[@]}" "$@"; }

echo "=== beam production verification ==="
remote 'set -u
fail=0
active=$(systemctl is-active beam 2>/dev/null || true)
enabled=$(systemctl is-enabled beam 2>/dev/null || true)
nrestarts=$(systemctl show beam -p NRestarts --value 2>/dev/null || true)
echo "active=$active enabled=$enabled nrestarts=$nrestarts"
[ "$active" = "active" ] || { echo "FAIL: beam is not active" >&2; fail=1; }
if systemctl is-failed --quiet beam; then echo "FAIL: beam unit is failed" >&2; fail=1; fi
[ "$nrestarts" = "0" ] || { echo "FAIL: NRestarts=$nrestarts (expected 0)" >&2; fail=1; }
[ "$enabled" = "enabled" ] || { echo "WARN: beam is not enabled ($enabled)" >&2; }

/usr/local/bin/beam --version
sha256sum /usr/local/bin/beam
sudo -n sha256sum /etc/beam/config.toml
mode=$(sudo -n stat -c "%a %U:%G" /etc/beam/config.toml)
echo "config_mode=$mode"
[ "$mode" = "640 root:beam" ] || { echo "FAIL: config mode/owner is $mode (expected 640 root:beam)" >&2; fail=1; }

cc=$(/usr/sbin/sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
qdisc=$(/usr/sbin/sysctl -n net.core.default_qdisc 2>/dev/null || true)
ct_max=$(/usr/sbin/sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || true)
ct_count=$(/usr/sbin/sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null || true)
udp_timeout=$(/usr/sbin/sysctl -n net.netfilter.nf_conntrack_udp_timeout 2>/dev/null || true)
udp_stream_timeout=$(/usr/sbin/sysctl -n net.netfilter.nf_conntrack_udp_timeout_stream 2>/dev/null || true)
printf "congestion=%s qdisc=%s conntrack=%s/%s udp_timeout=%s udp_stream_timeout=%s\n" \
  "$cc" "$qdisc" "$ct_count" "$ct_max" "$udp_timeout" "$udp_stream_timeout"
[ "$cc" = "bbr" ] || { echo "FAIL: congestion control is $cc (expected bbr)" >&2; fail=1; }
[ "$qdisc" = "fq" ] || { echo "FAIL: default qdisc is $qdisc (expected fq)" >&2; fail=1; }
[ "$ct_max" = "65536" ] || { echo "FAIL: conntrack max is $ct_max (expected 65536)" >&2; fail=1; }
[ "$udp_timeout" = "600" ] || { echo "FAIL: UDP conntrack timeout is $udp_timeout (expected 600)" >&2; fail=1; }
[ "$udp_stream_timeout" = "600" ] || { echo "FAIL: UDP stream timeout is $udp_stream_timeout (expected 600)" >&2; fail=1; }
if [ -n "$ct_count" ] && [ -n "$ct_max" ] && [ "$ct_max" -gt 0 ]; then
  if [ "$ct_count" -ge $((ct_max * 9 / 10)) ]; then
    echo "FAIL: conntrack is above 90% ($ct_count/$ct_max)" >&2
    fail=1
  fi
fi

iface=$(ip -o route show default | awk "{for(i=1;i<=NF;i++) if (\$i==\"dev\") {print \$(i+1); exit}}")
echo "iface=$iface"
qdisc_out=$(/usr/sbin/tc qdisc show dev "$iface" 2>/dev/null | sed -n "1p" || true)
echo "qdisc_out=$qdisc_out"
printf "%s\n" "$qdisc_out" | grep -q "fq" || { echo "FAIL: live qdisc is not fq" >&2; fail=1; }

listener=$(sudo -n ss -ltnp "sport = :443" 2>/dev/null || true)
printf "%s\n" "$listener" | sed -n "1,3p"
printf "%s\n" "$listener" | grep -q "beam" || { echo "FAIL: :443 is not owned by beam" >&2; fail=1; }

exit "$fail"
'

binary_sha=$(remote 'sha256sum /usr/local/bin/beam' | awk '{print $1}')
config_sha=$(remote 'sudo -n sha256sum /etc/beam/config.toml' | awk '{print $1}')
if [ -n "${EXPECTED_BINARY_SHA:-}" ] && [ "$binary_sha" != "$EXPECTED_BINARY_SHA" ]; then
    echo "verify: binary SHA mismatch: expected $EXPECTED_BINARY_SHA, got $binary_sha" >&2
    exit 1
fi
if [ -n "${EXPECTED_CONFIG_SHA:-}" ] && [ "$config_sha" != "$EXPECTED_CONFIG_SHA" ]; then
    echo "verify: config SHA mismatch: expected $EXPECTED_CONFIG_SHA, got $config_sha" >&2
    exit 1
fi

if [ "${CHECK_H2:-0}" = "1" ]; then
    iface="${TUN_IFACE:-sbtun0}"
    if ! ip link show "$iface" >/dev/null 2>&1; then
        echo "verify: CHECK_H2=1 but tunnel interface $iface is missing" >&2
        exit 1
    fi
    for attempt in 1 2 3; do
        code=$(curl -4 --interface "$iface" -sS --max-time 12 -o /dev/null \
            -w '%{http_code}' https://example.com || true)
        echo "h2 attempt=$attempt http=$code"
        [ "$code" = "200" ] || { echo "verify: tunneled H2 check failed" >&2; exit 1; }
        sleep 1
    done
fi
echo "verify: PASS"
