#!/bin/sh
# Clamp TCP MSS on the IPv4 default route to 1400 bytes.
#
# Some CDN paths (measured: Meta/Instagram 57.144.0.0/16 and Vercel
# 76.76.21.0/24) have a 1460-byte path MTU but advertise a 1500-byte MSS and
# return no ICMP fragmentation-needed message. A 1500-byte segment is silently
# dropped, so TLS handshakes and video segments stall.
#
# Advertising MSS 1400 in the SYN packet makes the peer send at most 1400
# payload bytes, which with TCP/IP options stays below the 1460-byte path MTU.
# Doing this on the default route is global: there is no per-destination or
# per-service list to maintain. Normal 1500-byte paths still work; the only
# cost is a slightly smaller segment on outbound TCP.
set -eu

ip_cmd=${IP:-/sbin/ip}
default=$("$ip_cmd" route show default | awk '/^default/ {print; exit}')
[ -n "$default" ] || {
  echo "beam-mtu: no IPv4 default route" >&2
  exit 1
}

gateway=$(printf '%s\n' "$default" | awk '{for (i = 1; i <= NF; i++) if ($i == "via") {print $(i + 1); exit}}')
interface=$(printf '%s\n' "$default" | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
proto=$(printf '%s\n' "$default" | awk '{for (i = 1; i <= NF; i++) if ($i == "proto") {print $(i + 1); exit}}')
[ -n "$gateway" ] && [ -n "$interface" ] || {
  echo "beam-mtu: could not parse default route: $default" >&2
  exit 1
}

# Remove the old per-prefix clamps if an earlier deployment left them.
"$ip_cmd" route del 57.144.0.0/16 2>/dev/null || true
"$ip_cmd" route del 76.76.21.0/24 2>/dev/null || true

if [ -n "$proto" ]; then
  "$ip_cmd" route replace default via "$gateway" dev "$interface" proto "$proto" advmss 1400
else
  "$ip_cmd" route replace default via "$gateway" dev "$interface" advmss 1400
fi
