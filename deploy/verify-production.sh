#!/usr/bin/env bash
# Read-only production verification. No config contents or secrets are printed.
set -euo pipefail

: "${SSH_KEY:?set SSH_KEY to the private key path}"
: "${SERVER:?set SERVER to user@host}"
SSH=(ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$SERVER")

remote() { "${SSH[@]}" "$@"; }

echo "=== beam production verification ==="
remote 'set -e
date -u
systemctl is-active beam
systemctl show beam -p NRestarts -p MainPID
/usr/local/bin/beam --version
sha256sum /usr/local/bin/beam
sudo -n sha256sum /etc/beam/config.toml
sudo -n stat -c "%a %U:%G %y" /etc/beam/config.toml
/usr/sbin/sysctl -n net.ipv4.tcp_congestion_control net.core.default_qdisc net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_udp_timeout net.netfilter.nf_conntrack_udp_timeout_stream
iface=$(ip -o route show default | awk "{for(i=1;i<=NF;i++) if (\$i==\"dev\") {print \$(i+1); exit}}")
echo "iface=$iface"
/usr/sbin/tc qdisc show dev "$iface" | sed -n "1p"
ss -ltn "sport = :443" | sed -n "1,3p"
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
    for attempt in 1 2 3; do
        curl -4 -sS --max-time 12 -o /dev/null \
            -w "h2 attempt=$attempt http=%{http_code} time=%{time_total}\n" \
            https://example.com
    done
fi
echo "verify: PASS"
