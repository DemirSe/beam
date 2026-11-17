#!/bin/sh
# Apply the fq qdisc to the interface that carries the default route.
#
# net.core.default_qdisc only affects interfaces that the kernel creates after
# the sysctl applies. A cloud NIC usually exists before that point, so it keeps
# its old qdisc until something replaces it. This script runs at boot from
# beam-fq.service. It is idempotent and harmless when fq is already active.
set -eu

iface="$(ip -o route show default 2>/dev/null |
  awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
[ -n "${iface:-}" ] || exit 0

tc qdisc replace dev "$iface" root fq 2>/dev/null || {
  echo "apply-fq: could not apply fq to $iface" >&2
  exit 0
}
