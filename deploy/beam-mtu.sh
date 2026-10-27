#!/bin/sh
# Clamp TCP MSS for CDN paths whose path MTU is 1460 bytes.
#
# The production VPS has a 1460-byte path MTU to Meta's 57.144.0.0/16
# (Instagram CDN) and Vercel's 76.76.21.0/24. Both networks advertise a
# 1460-byte MSS, so a 1500-byte segment is silently dropped and large TLS
# handshakes or video segments stall. The kernel never receives an ICMP
# fragmentation-needed message, so PMTU probing cannot recover quickly.
#
# `advmss 1400` leaves 20 bytes below the observed 1460-byte path MTU and
# affects only those two prefixes; normal 1500-byte paths keep their MSS.
set -eu

ip_cmd=${IP:-/sbin/ip}
default=$("$ip_cmd" route show default | awk '/^default/ {print $3, $5; exit}')
[ -n "$default" ] || {
  echo "beam-mtu: no IPv4 default route" >&2
  exit 1
}
# shellcheck disable=SC2086
set -- $default
gateway=$1
interface=$2
[ -n "$gateway" ] && [ -n "$interface" ] || {
  echo "beam-mtu: could not parse default route: $default" >&2
  exit 1
}

"$ip_cmd" route replace 57.144.0.0/16 via "$gateway" dev "$interface" advmss 1400
"$ip_cmd" route replace 76.76.21.0/24 via "$gateway" dev "$interface" advmss 1400
