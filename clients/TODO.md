# Client backlog

No client/TUN work is planned for now. This file records client-side items that
affect the tunnel but are not server defects.

## Rootless Android cannot enable BBR while preserving REALITY/TCP cover

Status: open, not planned for now.

A rootless Android client can keep the REALITY/TCP cover (`TCP/443` with the
`whatsapp.net` TLS ClientHello) or change congestion control, but not both on
this device class.

Device/lab evidence (2026-11-06):

- Samsung SM-S721B, Android 17 / SDK 37, kernel `6.1.162-android14-11`.
- `tcp_available_congestion_control` and `tcp_allowed_congestion_control` are
  both `reno cubic`; `tcp_congestion_control=cubic`; no `tcp_bbr` module.
- Root is absent (`ro.debuggable=0`, locked bootloader); `shell` cannot modify
  the sysctls or qdisc.
- Buffer tuning is already generous: `tcp_rmem` max 16 MiB, `tcp_wmem` max
  8 MiB, `rmem_max` 32 MiB, `wmem_max` 16 MiB.
- Stock SFA/sing-box is active; its VPN TUN is MTU 1500. sing-box exposes no
  TCP congestion-control field for standard VLESS/TCP outbounds.
- Lab, 20 Mbps UDP upload, client CUBIC, `30 ms ±8 ms`, 0.5% loss:
  `xudp` **61.5%**, `packetaddr` **51.2%**, `legacy` **73.1%** loss.
  The same client with BBR produced **0–0.74%** loss.
- Hysteria2/TUIC or other QUIC/UDP transports use userspace congestion control,
  but the WAN packet is UDP, not the visible `whatsapp.net` TCP/REALITY
  stream. They therefore violate the current cover requirement.
- A custom client on the same kernel TCP can add queueing/pacing or per-socket
  options, but cannot replace missing kernel BBR; it is mitigation only.
- Cover-preserving paths are: root/custom-kernel BBR, or an external BBR Linux
  gateway/router that terminates REALITY/TCP while the phone stays rootless.

Next probe when client work resumes: evaluate an external BBR Linux gateway as
the rootless cover-preserving path (TUN/MTU, 20 Mbps UDP upload, loss matrix,
latency, throughput, and whether the WAN side still shows `whatsapp.net`
TCP/443). If that fails, quantify custom-client pacing/queue only; a QUIC
transport is a separate product decision because it changes the visible
transport.
