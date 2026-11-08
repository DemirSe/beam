#!/usr/bin/env bash
# Read-only production verification with explicit assertions.
# No config contents or secrets are printed.
set -euo pipefail

: "${SSH_KEY:?set SSH_KEY to the private key path}"
: "${SERVER:?set SERVER to user@host}"
SSH=(ssh -4 -i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes \
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
case "${ct_count:-}" in
  ""|*[!0-9]*) echo "FAIL: conntrack count is not numeric ($ct_count)" >&2; fail=1 ;;
esac
case "${ct_max:-}" in
  ""|*[!0-9]*) echo "FAIL: conntrack max is not numeric ($ct_max)" >&2; fail=1 ;;
esac
if [ "${fail:-0}" -eq 0 ] && [ "$ct_count" -ge $((ct_max * 9 / 10)) ]; then
  echo "FAIL: conntrack is above 90% ($ct_count/$ct_max)" >&2
  fail=1
fi

iface=$(ip -o route show default | awk "{for(i=1;i<=NF;i++) if (\$i==\"dev\") {print \$(i+1); exit}}")
echo "iface=$iface"
qdisc_out=$(/usr/sbin/tc qdisc show dev "$iface" 2>/dev/null | sed -n "1p" || true)
echo "qdisc_out=$qdisc_out"
qkind=$(printf "%s\n" "$qdisc_out" | awk "NR == 1 {print \$2}")
[ "$qkind" = "fq" ] || { echo "FAIL: live qdisc is not fq (got $qkind)" >&2; fail=1; }

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

if [ "${EXPECT_IPV4_ONLY:-0}" = "1" ]; then
    families=$(remote 'systemctl show beam -p RestrictAddressFamilies --value' | tr -d '\r')
    echo "restrict_address_families=$families"
    if [ "$families" != "AF_INET AF_UNIX" ]; then
        echo "verify: RestrictAddressFamilies is '$families' (expected 'AF_INET AF_UNIX')" >&2
        exit 1
    fi
fi

if [ "${EXPECT_HOST_IPV6_DISABLED:-0}" = "1" ]; then
    if ! host_all_raw=$(remote 'sudo -n /usr/sbin/sysctl -n net.ipv6.conf.all.disable_ipv6'); then
        echo "verify: failed to read net.ipv6.conf.all.disable_ipv6 on the host" >&2
        exit 1
    fi
    if ! host_default_raw=$(remote 'sudo -n /usr/sbin/sysctl -n net.ipv6.conf.default.disable_ipv6'); then
        echo "verify: failed to read net.ipv6.conf.default.disable_ipv6 on the host" >&2
        exit 1
    fi
    if ! host_lo_raw=$(remote 'sudo -n /usr/sbin/sysctl -n net.ipv6.conf.lo.disable_ipv6'); then
        echo "verify: failed to read net.ipv6.conf.lo.disable_ipv6 on the host" >&2
        exit 1
    fi
    if ! host_addrs=$(remote 'ip -6 addr show'); then
        echo "verify: failed to query IPv6 addresses on the host" >&2
        exit 1
    fi
    if ! host_routes=$(remote 'ip -6 route show table all'); then
        echo "verify: failed to query IPv6 routes on the host" >&2
        exit 1
    fi
    if ! host_listeners=$(remote 'sudo -n ss -H -6 -lntup'); then
        echo "verify: failed to query IPv6 listeners on the host" >&2
        exit 1
    fi
    if ! host_sshd_family_raw=$(remote 'set -u
out=$(sudo -n /usr/sbin/sshd -T 2>&1)
rc=$?
if [ "$rc" -ne 0 ]; then
    printf "%s\n" "sshd -T failed: $out" >&2
    exit "$rc"
fi
printf "%s\n" "$out" | sed -n "s/^addressfamily //p"'); then
        echo "verify: failed to query the sshd address family on the host" >&2
        exit 1
    fi
    host_all=$(printf '%s' "$host_all_raw" | tr -d '\r[:space:]')
    host_default=$(printf '%s' "$host_default_raw" | tr -d '\r[:space:]')
    host_lo=$(printf '%s' "$host_lo_raw" | tr -d '\r[:space:]')
    host_addr_count=$(printf '%s' "$host_addrs" | awk 'NF {n++} END {print n+0}')
    host_route_count=$(printf '%s' "$host_routes" | awk 'NF {n++} END {print n+0}')
    host_listener_count=$(printf '%s' "$host_listeners" | awk 'NF {n++} END {print n+0}')
    host_sshd_family=$(printf '%s' "$host_sshd_family_raw" | tr -d '\r[:space:]')
    printf 'host_ipv6 all=%s default=%s lo=%s inet6_addr_count=%s ipv6_route_count=%s ipv6_listener_count=%s sshd_family=%s\n' \
        "$host_all" "$host_default" "$host_lo" "$host_addr_count" \
        "$host_route_count" "$host_listener_count" "$host_sshd_family"
    host_fail=0
    [ "$host_all" = "1" ] || { echo "verify: net.ipv6.conf.all.disable_ipv6=$host_all (expected 1)" >&2; host_fail=1; }
    [ "$host_default" = "1" ] || { echo "verify: net.ipv6.conf.default.disable_ipv6=$host_default (expected 1)" >&2; host_fail=1; }
    [ "$host_lo" = "1" ] || { echo "verify: net.ipv6.conf.lo.disable_ipv6=$host_lo (expected 1)" >&2; host_fail=1; }
    [ "$host_addr_count" = "0" ] || { echo "verify: IPv6 address count is $host_addr_count (expected 0)" >&2; host_fail=1; }
    [ "$host_route_count" = "0" ] || { echo "verify: IPv6 route count is $host_route_count (expected 0)" >&2; host_fail=1; }
    [ "$host_listener_count" = "0" ] || { echo "verify: IPv6 listener count is $host_listener_count (expected 0)" >&2; host_fail=1; }
    [ "$host_sshd_family" = "inet" ] || { echo "verify: sshd address family is '$host_sshd_family' (expected inet)" >&2; host_fail=1; }
    [ "$host_fail" -eq 0 ] || exit 1
fi

if [ "${CHECK_H2:-0}" = "1" ]; then
    iface="${TUN_IFACE:-sbtun0}"
    if ! ip link show "$iface" >/dev/null 2>&1; then
        echo "verify: CHECK_H2=1 but tunnel interface $iface is missing" >&2
        exit 1
    fi

    # Validate the destination before sending traffic: a malformed value would
    # otherwise surface as a misleading "not tunnelled" failure.
    dst="${CHECK_H2_DST:-1.1.1.1:443}"
    case "$dst" in
        *:*) ;;
        *) echo "verify: CHECK_H2_DST must be host:port, got '$dst'" >&2; exit 1 ;;
    esac
    dst_addr="${dst%:*}"
    dst_port="${dst##*:}"
    case "$dst_port" in
        ''|*[!0-9]*) echo "verify: CHECK_H2_DST must end in a numeric port, got '$dst'" >&2; exit 1 ;;
    esac
    # Accept a bracketed IPv6 literal; bash /dev/tcp and ss both take it bare.
    dst_addr="${dst_addr#\[}"
    dst_addr="${dst_addr%\]}"
    hold="${CHECK_H2_HOLD:-8}"
    case "$hold" in
        ''|*[!0-9]*) echo "verify: CHECK_H2_HOLD must be a whole number of seconds" >&2; exit 1 ;;
    esac
    [ "$hold" -ge 4 ] || { echo "verify: CHECK_H2_HOLD must be at least 4 seconds" >&2; exit 1; }
    # Sample at half the hold, so every accepted hold leaves the socket up.
    delay=$(( hold / 2 ))

    # Derive the address family from the validated destination. This makes the
    # application probe use the same family as the beam-owned socket check.
    case "$dst_addr" in
        *:*) family=6 ;;
        *) family=4 ;;
    esac
    if [ -n "${CHECK_H2_FAMILY:-}" ]; then
        case "$CHECK_H2_FAMILY" in
            4|6) family="$CHECK_H2_FAMILY" ;;
            *) echo "verify: CHECK_H2_FAMILY must be 4 or 6" >&2; exit 1 ;;
        esac
    fi
    case "$dst_addr" in
        *:*) url="https://[$dst_addr]:$dst_port/cdn-cgi/trace" ;;
        *)   url="https://$dst_addr:$dst_port/cdn-cgi/trace" ;;
    esac

    # The shipped Linux profile sets auto_redirect, so locally generated TCP is
    # redirected into the client and never enters the tun device. Pinning a
    # probe to the device tests a path the product does not use; probe the path
    # traffic actually takes instead. Require negotiated HTTP/2, not just a
    # successful TCP connect, and record the family and remote address.
    for attempt in 1 2 3; do
        if ! out=$(curl -"$family" --http2 -sS --max-time 12 -o /dev/null \
            -w '%{http_code} %{http_version} %{remote_ip}' "$url" 2>&1); then
            echo "verify: curl failed for $url: $out" >&2
            exit 1
        fi
        set -- $out
        code=${1:-}
        version=${2:-}
        remote_ip=${3:-}
        echo "h2 family=$family attempt=$attempt http=$code version=$version remote=$remote_ip"
        if [ "$code" != "200" ] || [ "$version" != "2" ]; then
            echo "verify: HTTP/2 through the client path failed for $url" >&2
            exit 1
        fi
        sleep 1
    done

    # A direct uplink also answers those requests, so prove the traffic left
    # through beam: hold one client connection open and require a new
    # established socket owned by beam for the same destination on the server.
    tunnel_sockets() {
        local n
        if ! n=$(remote "set -u
            out=\$(sudo -n ss -tnpH state established \"dst ${dst_addr}:${dst_port}\" 2>&1)
            rc=\$?
            if [ \"\$rc\" -ne 0 ]; then
                printf '%s\n' \"ss query failed: \$out\" >&2
                exit \"\$rc\"
            fi
            count=\$(printf '%s\n' \"\$out\" | grep -c beam)
            grc=\$?
            if [ \"\$grc\" -gt 1 ]; then
                printf '%s\n' \"grep failed\" >&2
                exit \"\$grc\"
            fi
            printf '%s\n' \"\${count:-0}\""); then
            return 1
        fi
        n=$(printf '%s' "$n" | tr -d '[:space:]')
        case "$n" in
            ''|*[!0-9]*) return 1 ;;
        esac
        printf '%s' "$n"
    }
    if ! before=$(tunnel_sockets); then
        echo "verify: failed to query beam-owned sockets before probe" >&2
        exit 1
    fi
    ( exec 3<>"/dev/tcp/${dst_addr}/${dst_port}" 2>/dev/null; sleep "$hold"; exec 3<&- 3>&- ) &
    holder=$!
    sleep "$delay"
    if ! during=$(tunnel_sockets); then
        echo "verify: failed to query beam-owned sockets during probe" >&2
        kill "$holder" 2>/dev/null || true
        exit 1
    fi
    wait "$holder" 2>/dev/null || true
    sleep 1
    if ! after=$(tunnel_sockets); then
        echo "verify: failed to query beam-owned sockets after probe" >&2
        exit 1
    fi
    echo "tunnel sockets dst=$dst beam-owned: before=$before during=$during after=$after"
    if [ "$during" -le "$before" ]; then
        echo "verify: client traffic is not tunnelled (no beam-owned socket to $dst appeared)" >&2
        echo "verify: last client journal lines:" >&2
        journalctl -u beam-client -n 20 --no-pager 2>/dev/null >&2 || true
        exit 1
    fi
    if [ "${after:-0}" -gt "${before:-0}" ]; then
        echo "verify: note: beam-owned sockets to $dst did not return to baseline" >&2
    fi
fi
echo "verify: PASS"
