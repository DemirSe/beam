# Production runbook
Live single-user `beam` deployment, 2026-10-22. This file has no UUIDs, short
IDs, private keys, or client links. Public server addresses are included.
Secrets stay in `~/.config/beam/` locally and `/etc/beam/config.toml` on the
host. Replace `<server>` and define:
```bash
export HOST="<server>"
export SERVER=demir@$HOST
export SSH_KEY=~/.ssh/id_ed25519_netlen_demir
bssh() { ssh -i "$SSH_KEY" "$SERVER" "$@"; }
```
Related: `deploy/README.md`, `docs/10-cover-parity.md`,
`docs/13-vision-direct-design.md`, `docs/14-tun-harness.md`,
`docs/17-resource-hardening.md`, `bench/README.md`.

## 1. What is deployed

| Item | State |
|---|---|
| Host | Debian 13.7, x86_64, 1 vCPU, 1 GiB RAM, 1 GiB swap; kernel 6.12.113 active |
| Service | `beam.service`, active and enabled, `User=beam`, `0.0.0.0:443`; cover `whatsapp.net:443`; limits 1024 connections / 10 s handshake; systemd exposure 1.7 OK |
| Binary | `/usr/local/bin/beam`, root:root 0755 |
| Config | `/etc/beam/config.toml`, root:beam 0640, contains secrets |
| Unit / backups | `/etc/systemd/system/beam.service` 0644; `*.bak-<UTC stamp>` beside each installed file |
| Hardening | Deployed 2026-10-30 02:26 UTC: binary `e0843cc3…` (daily lifecycle/TLS/ops hardening; 1024 global sessions, 128 KiB receive buffer); previous `cf8425fe…` at 01:10 UTC; config backup `20261030T011011Z` |
| Earlier hardening | 2026-10-29 18:20 UTC binary `9e26cb55…`; 2026-10-24 binary `f33f07fe…`; 2026-10-22/23 binaries preserved in backups |
| Conntrack | `/etc/sysctl.d/99-beam-conntrack.conf`: max 65536, established 3600 s, TIME_WAIT 30 s |
| Local client | sing-box, `/etc/sing-box/config.json` 0600, active but disabled at boot |
| Client identity | `~/.config/beam/client-identity.json`, `client-link.txt` 0600 |
| Tunnel egress | IPv4 `158.94.216.102`, IPv6 `2a01:f900:11:168::1` |
| Host firewall | `nftables` enabled; default-deny input; 22/443, established, ICMP/ICMPv6, loopback; LLMNR dropped |
| SSH | key-only `demir`; root and `debian` disabled; X11 off; `MaxAuthTries 3`; `LoginGraceTime 30` |
| Resolver | systemd-resolved DNS-over-TLS + DNSSEC; LLMNR/mDNS off |
| UDP tuning | `/etc/sysctl.d/99-beam.conf` sets `rmem_max=wmem_max=4 MiB` |
| Network tuning | `/etc/sysctl.d/99-beam-net.conf` sets `tcp_congestion_control=bbr` and `default_qdisc=fq`; `beam-qdisc.service` reapplies `fq` to `eth0` at boot; beam sets `TCP_MAXSEG 1400` on its target sockets for 1460-byte PMTU paths |

Old stock Xray is absent; only TCP/443 and SSH 22 are exposed. The unit sets
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`,
`RestrictNamespaces`, `SystemCallFilter=@system-service`,
`MemoryDenyWriteExecute`, `LimitCORE=0`, `LimitNOFILE=65536`, and only
`CAP_NET_BIND_SERVICE`. The Tokio blocking pool is capped at 160 threads.

## 2. Daily checks
```bash
bssh 'systemctl status --no-pager -l beam; systemctl is-failed beam; systemctl show beam -p NRestarts --value'
bssh 'sudo -n ss -ltnp; sudo -n journalctl -u beam --since "24 hours ago" -p warning --no-pager'
bssh 'pid=$(systemctl show beam -p MainPID --value); ps -o pid,rss,vsz,nlwp,etime,comm -p "$pid"; printf "fds="; sudo -n ls "/proc/$pid/fd" | wc -l'
bssh 'cat /sys/fs/cgroup/system.slice/beam.service/memory.current; cat /sys/fs/cgroup/system.slice/beam.service/memory.peak'
bssh 'df -h /; df -i /; free -m; swapon --show; uptime; du -sh /usr/local/bin/beam.bak-* 2>/dev/null | tail -3'
bssh 'sudo -n journalctl --disk-usage; ls /tmp/beam-deploy* 2>/dev/null || true'
```
Expect `active (running)` and `enabled`; `ss` should show `beam` on
`0.0.0.0:443` and `sshd` on 22, with no unexpected listeners. A healthy
`warn`-level process is normally quiet. The only documented benign warning is
`authenticated VLESS command is not implemented yet; closing command=Rvs` for
the unsupported reverse command; treat anything else as actionable. A
`runtime pressure counters increased` warning means traffic was rejected or a
queue dropped something; inspect its deltas before changing limits.
`ps` reports RSS/VSZ in KiB and `nlwp` as threads. Local churn baseline: RSS
7.7 to 8.3 MiB, 2 threads, 10 fds; live idle RSS was about 17 MiB at the last
audit. The same pass covers disk, inodes, swap, load, and restart count.
From the laptop, with the TUN client running, verify egress:
```bash
curl -4 -sS https://ipv4.icanhazip.com
curl -6 -sS https://ipv6.icanhazip.com
```
Expect `158.94.216.102` and `2a01:f900:11:168::1`. An ISP address means the
tunnel is down; run `sudo systemctl start sing-box` (disabled at boot) and retry.

## 3. Client rotation
Rotate after an identity change, on a new laptop, or when egress is not the VPS.
`update-client.py` backs up `/etc/sing-box/config.json`, writes the REALITY
fields from `~/.config/beam/client-identity.json`, sets every TUN inbound to
`stack: system` with MTU 1500, restarts sing-box, restores the backup on
failure, and enables the service at boot. The kernel stack is stable for large
HTTP/3 bodies; gVisor stalls them. MTU 1500 matches the server egress path,
while 1400 loses Google and YouTube H3. The outer TCP connection segments for
smaller mobile/hotspot paths:
```bash
cd /home/demir/pi/beam
sudo python3 deploy/update-client.py
```
Alternatively, import `~/.config/beam/client-link.txt` into Hiddify; set Hiddify's
TUN stack to `system` manually. The link contains credentials, so never paste it
into chat, tickets, or git. For the local `Xray Tray (sing-box)`, install the
passwordless unit rule and autostart:
```bash
sudo install -m 0644 deploy/50-sing-box-tray.rules \
  /etc/polkit-1/rules.d/50-sing-box-tray.rules
install -D -m 0644 deploy/sing-box-tray-autostart.desktop \
  ~/.config/autostart/sing-box-tray.desktop
```
The rule only allows `demir` to manage `sing-box.service`; the tray can then
start/stop/restart without a password prompt. Verify:
```bash
systemctl status --no-pager sing-box
curl -4 -sS https://ipv4.icanhazip.com; curl -6 -sS https://ipv6.icanhazip.com
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com; curl -sS -o /dev/null -w '%{http_code}\n' http://example.com
dig +short example.com; dig +short AAAA example.com
curl --http3-only -sS -o /dev/null -w '%{http_code}\n' https://cloudflare-quic.com/
```
The HTTP checks must print `200`; DNS must return addresses. HTTP/3 needs a
curl built with HTTP/3 (`curl --version | grep -i HTTP3`). This covers HTTPS,
HTTP, DNS, HTTP/3, IPv6, and Vision Direct; UDP echo is lab-only.
Check that unauthenticated TLS still reaches the real cover. The laptop may not
have the `openssl` CLI, so use curl's verbose certificate output:
```bash
curl --interface wlp0s20f3 --resolve "whatsapp.net:443:$HOST" \
  -sS -v -o /dev/null https://whatsapp.net/ 2>&1 \
  | grep -E 'subject:|issuer:|SSL connection'
```
Expect a public certificate for `*.whatsapp.net` issued by a public CA, not a
beam certificate; this proves cover forwarding. Drop `--interface` on a host
without the TUN, or use the active Wi-Fi interface if the TUN intercepts the
server IP.
Run the local full-TUN matrix after client or server changes:
```bash
source scripts/dev-env.sh
for mode in xudp packetaddr legacy; do bash tests/tun/run.sh --udp-mode "$mode"; done
```
Each arm must report 8/8 PASS; `BLOCKED` is not a pass. If `/dev/net/tun` is
unavailable all rows are BLOCKED and the harness exits 0. This is a local lab,
not the VPS.

## 4. Server update and deploy
From the repo root, preflight a clean tree:
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
Package and upload:
```bash
BUNDLE=$(bash deploy/package.sh | sed -n 's/^bundle=//p')
test -f "$BUNDLE"
scp -i "$SSH_KEY" "$BUNDLE" "$SERVER:/tmp/beam-deploy.tar.gz"
bssh 'chmod 600 /tmp/beam-deploy.tar.gz'
```
Deploy and load the new binary:
```bash
bssh 'rm -rf /tmp/beam-deploy && mkdir -p /tmp/beam-deploy && tar -xzf /tmp/beam-deploy.tar.gz -C /tmp/beam-deploy && sudo -n bash /tmp/beam-deploy/bootstrap.sh'
bssh 'rm -rf /tmp/beam-deploy /tmp/beam-deploy.tar.gz'
```
`bootstrap.sh` stops/disables the old Xray units, creates `beam`, backs up and
installs binary/config/unit, installs the UDP sysctl drop-in, validates the
config, restarts the service (so an active process picks up the new binary and
unit), and checks 443.

If the local `~/.config/beam/beam.toml` differs from the live config (for
example local `max_connections=64`/`log=warn` versus live 1024/`info`), update
only the binary and unit and preserve `/etc/beam/config.toml`:
```bash
bssh 'rm -rf /tmp/beam-deploy && mkdir -p /tmp/beam-deploy && tar -xzf /tmp/beam-deploy.tar.gz -C /tmp/beam-deploy && sudo -n env BEAM_KEEP_CONFIG=1 bash /tmp/beam-deploy/bootstrap.sh'
bssh 'rm -rf /tmp/beam-deploy /tmp/beam-deploy.tar.gz'
```
`BEAM_KEEP_CONFIG=1` skips the config install but still requires the live file,
validates it with the new binary (including derived runtime limits), installs
the unit, restarts, and polls beam's own 443 listener for up to 15 s. The
bundle's `beam.toml` is ignored in that mode. Uploads are chmod 600 before
extraction; remove the extracted directory and tarball after success.
`deploy/package.sh` runs `beam --check` on the local secrets before creating a
bundle; `bootstrap.sh` prunes each file's backups to the five newest.
Health checks:
```bash
bssh 'systemctl is-active beam; systemctl is-enabled beam; systemctl show beam -p NRestarts --value'
bssh 'sudo -n ss -ltnp "sport = :443"; sudo -n journalctl -u beam -n 50 --no-pager'
bssh 'sudo -n runuser -u beam -- /usr/local/bin/beam --check -c /etc/beam/config.toml'
sha256sum target/release/beam; bssh 'sha256sum /usr/local/bin/beam'
```
The two hashes must match. Then run the client checks in section 3.
Rollback uses the timestamped backups:
```bash
bssh 'ls -1t /usr/local/bin/beam.bak-* /etc/beam/config.toml.bak-* /etc/systemd/system/beam.service.bak-* /etc/sysctl.d/99-beam.conf.bak-* /etc/sysctl.d/99-beam-conntrack.conf.bak-*'
STAMP="<stamp>"
bssh 'sudo -n systemctl stop beam'
bssh "sudo -n install -m 0755 -o root -g root /usr/local/bin/beam.bak-$STAMP /usr/local/bin/beam"
bssh "sudo -n install -m 0640 -o root -g beam /etc/beam/config.toml.bak-$STAMP /etc/beam/config.toml"
bssh "sudo -n install -m 0644 -o root -g root /etc/systemd/system/beam.service.bak-$STAMP /etc/systemd/system/beam.service"
bssh "sudo -n install -m 0644 -o root -g root /etc/sysctl.d/99-beam.conf.bak-$STAMP /etc/sysctl.d/99-beam.conf"
bssh "sudo -n install -m 0644 -o root -g root /etc/sysctl.d/99-beam-conntrack.conf.bak-$STAMP /etc/sysctl.d/99-beam-conntrack.conf"
bssh 'sudo -n runuser -u beam -- /usr/local/bin/beam --check -c /etc/beam/config.toml; sudo -n sysctl --system >/dev/null; sudo -n systemctl daemon-reload && sudo -n systemctl reset-failed beam || true; sudo -n systemctl start beam'
```
Rollback is not atomic; stop first, install all four, then start. There is no
automatic stock Xray fallback, so keep a known-good bundle or snapshot before cutover.

## 5. Identity rotation
The identity is the X25519 keypair, short ID, UUID, and SNI/cover. The private
key exists only in `~/.config/beam/beam.toml` and `/etc/beam/config.toml`; there
is no escrow, so after a wipe the old key is unrecoverable. If both copies are
lost, generate a new identity and rotate every client.
The repo ships no key generator. The verified local tool is the stock Xray
compatibility binary; otherwise use a trusted X25519 generator with raw-base64url encoding:
```bash
umask 077
/tmp/opencode/xray-server-compare/xray x25519 > ~/.config/beam/new-identity.txt
chmod 600 ~/.config/beam/new-identity.txt
python3 -c 'import secrets; print(secrets.token_hex(8))' > ~/.config/beam/new-short-id.txt
python3 -c 'import uuid; print(uuid.uuid4())' > ~/.config/beam/new-user-id.txt
```
Copy the values into `~/.config/beam/beam.toml` and
`~/.config/beam/client-identity.json`, then package, deploy, and rotate the client.
Replace key, short ID, and UUID together; old clients fail immediately. Keep the
old files until verified, then destroy them. Never commit or paste these values.

## 6. Emergency procedures
Stop, start, disable, or re-enable the service:
```bash
bssh 'sudo -n systemctl stop beam'
bssh 'sudo -n systemctl start beam'
bssh 'sudo -n systemctl disable beam'
bssh 'sudo -n systemctl enable beam'
```
Keep provider console access before changing SSH or firewall state; the web/serial
console is the out-of-band path. The host `nftables` rules are in
`/etc/nftables.conf`; the provider firewall is a second layer. If a host rule
mistake locks you out, use the provider console and run `nft flush ruleset`.
Restore from a provider snapshot through the provider console (snapshot ->
restore). After boot:
```bash
bssh 'systemctl status --no-pager -l beam; sudo -n ss -ltnp "sport = :443"'
```
A snapshot predating an identity rotation requires a client rotation; snapshots
contain `/etc/beam/config.toml` and are secret. If 443 is occupied, stop the old listener:
```bash
bssh 'sudo -n ss -ltnp "sport = :443"'
bssh 'sudo -n systemctl stop xray.service xray-compare.service 2>/dev/null || true'
```
For a crash loop, read the unit and validate the config:
```bash
bssh 'sudo -n systemctl status --no-pager -l beam; sudo -n journalctl -u beam -n 100 --no-pager'
bssh 'sudo -n runuser -u beam -- /usr/local/bin/beam --check -c /etc/beam/config.toml'
```
If the disk is full, check and vacuum the journal:
```bash
bssh 'df -h /; sudo -n journalctl --disk-usage'
bssh 'sudo -n journalctl --vacuum-time=7d'
```
If the cover is down, unauthenticated probes fail while authenticated connections
still work. Confirm with section 3; change `dest` only with a deploy and matching
client SNI. For rollback, use section 4.

## 7. Monitoring thresholds
Operational defaults for the 1 vCPU / 1 GiB host, not measured release gates;
tune after a 24-hour soak.

| Signal | Normal | Warn | Page / action |
|---|---|---|---|
| RSS | < 20 MiB idle | > 128 MiB or monotonic growth | > 256 MiB; restart, lower limits |
| fds | ~10 idle | > 256 | > 512; check leaks, lower limits |
| Threads | 2 idle | > 128 | > 160; lower `max_connections` |
| Swap | 0 used | any sustained use | > 128 MiB; restart, lower limits |
| Disk | < 70% | > 80% | > 90%; vacuum journal, clean bundles |
| Load | < 1 | > 2 | > 4; investigate before changing limits |
| Restarts | 0 | > 3/day | crash loop; read journal and config check |
| 443 listener | present | missing briefly during restart | missing otherwise; page |
| Egress | the two VPS addresses | ISP address | tunnel down; start sing-box |

The live `max_connections` is 1024 and the pre-auth ClientHello deadline is
5 s. Admission is split: up to 256 connections may hold a pre-auth slot, and
the 1024 authenticated permits are acquired only after REALITY succeeds. An
unauthenticated flood therefore drops new probes instead of blocking the accept
loop. Each Vision Direct relay can hold up to two blocking splice tasks and
512 KiB pipes; a process-wide splice semaphore covers about 60 pairs and turns
excess directions into the bounded async copy path, so the pool cannot queue a
handoff forever. The XUDP reply queue is 512 frames and session sockets request
a 128 KiB receive buffer (`xudp_recv_buffer_bytes`), live overridable. XUDP
sessions expire after at most **60 s** of idleness (the TCP relay idle timeout
remains 300 s), under the **process-wide 1024-session cap**; the **32
cover-relay cap** is separate. Check

```bash
bssh 'systemctl show beam -p MemoryHigh -p MemoryMax -p MemorySwapMax'
bssh 'cat /sys/fs/cgroup/system.slice/beam.service/memory.current; cat /sys/fs/cgroup/system.slice/beam.service/memory.peak'
bssh 'nstat -az | grep -E "UdpRcvbufErrors|UdpSndbufErrors"'
```

Change a limit, validate, and restart:
```bash
ssh -t -i "$SSH_KEY" "$SERVER" 'sudoedit /etc/beam/config.toml'
bssh 'sudo -n runuser -u beam -- /usr/local/bin/beam --check -c /etc/beam/config.toml'
bssh 'sudo -n systemctl restart beam'
```
Edit only `[limits]`; keep the file root:beam 0640. The example's 1024 default matches the live value.

`SIGTERM` closes the listener, drains for at most 2 s, then bounds blocking
splices with a 3 s runtime shutdown. `SIGHUP` is logged and ignored; use
`systemctl restart` to reload. The unit has no `ExecReload`. Expect a restart
to reset active streams, not to hang for the 90 s systemd default. `beam --version` includes the build
commit; startup logs `version` and `beam --check` validates both scalar limits
and the derived XUDP/TLS configuration before systemd starts the service.

### Connection admission and relay capacity

`max_connections=1024` is an admission cap, not a promise of 1024 concurrent
bulk relays. The listener backlog is configurable through
`limits.listen_backlog` (**default 1024**, range 1–65535); the old Tokio/mio
default was **128**, the live SYN backlog is **128**, and historical load tests
recorded **102** accept-queue overflows/drops. The listener now sets
`SO_REUSEADDR` so a restart during `TIME_WAIT` does not fail to bind.
Unauthenticated admission is bounded to **256** process-wide and
`limits.max_preauth_per_ip` (**default 128**) per source address; one scanner
can therefore no longer consume every pre-auth slot. Unauthenticated cover
relays are capped at **32** process-wide and **8** per source. Each Vision
Direct connection can pin up to **two** `spawn_blocking` splice tasks. The
160-thread pool is split into a 120-task splice budget plus reserve for cover
relays and dials; above the budget, a direction uses the async copy path
instead of queueing indefinitely. A local 512×1 MB load completed, but with a
49.7 s median latency; a 1024×1 MB load produced 937 timeouts and 927 partial
bodies, with 162 threads. Do not raise the blocking pool blindly on the 1 GiB
host; lower `max_connections` or move the relay to an epoll/io_uring design if
bulk concurrency matters. The current normal load is tens of connections, where
the pool is not saturated. XUDP sessions are capped by
`limits.max_xudp_sessions` (**default 256**, process-wide; live 1024) in
addition to the per-stream limit, and expire after 60 s of idleness. Graceful shutdown drains
for `limits.shutdown_drain_ms` (**default 2000**, max 3000). Admission counters
(`preauth_rejected`, `cover_limited`, `connection_limited`, `accept_errors`)
are logged every 60 seconds when they change.

### Network tuning during the 2026-10-23 hotspot test

`tcp_congestion_control=bbr` and `fq` were measured on the live hotspot path
with a 5 MB download repeated five times per mode. Cubic median was
**2.76 MB/s** (2.37–4.63); BBR median was **5.75 MB/s** (5.39–6.65) with a
smaller spread. CPU remained idle outside the transfer and the qdisc reported
zero drops. Run `sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc`
and `/sbin/tc qdisc show dev eth0` after a reboot; expect `bbr` and `fq`.

### Target-socket MSS clamp; MTU probing stays disabled

`net.ipv4.tcp_mtu_probing` remains **0**. On a lossy mobile path it is not a
free win: after `tcp_retries1` (3 here) RTO retries the kernel enables probing
and caps the MSS at `tcp_base_mss` (**1024** on this host), while repeated RTOs
can halve `search_low` down to `tcp_mtu_probe_floor` (48). SACK/DSACK can also
suppress the recovery probe. The live outer MSS is 1348–1448, so a false
positive costs roughly 24–29% payload per segment before recovery.

On 2026-10-27 a real PMTU black hole was measured on Meta/Instagram
`57.144.0.0/16` and Vercel `76.76.21.0/24`: both have a **1460-byte path MTU**
but advertise a 1500-byte MSS and return no ICMP fragmentation message. A TLS
ClientHello went out and no ServerHello came back; small HTTP responses still
worked. `tcp_mtu_probing` cannot fix the receive direction because the peer
keeps using our advertised MSS.

beam now sets **`TCP_MAXSEG 1400` before connecting every target and cover
socket**. Linux uses that value for both the SYN MSS and the local send limit;
production showed an effective `mss:1388 advmss:1388`, which fits below the
1460-byte path MTU. There is no host route, nftables rule, or per-prefix list.
See `docs/23-target-mss-2026-10-27.md`.

Check after a reconnect:

```bash
curl -4 -sS -o /dev/null -w '%{http_code}\n' https://artificialanalysis.ai/
ss -tin | grep -A1 '76.76.21.21:443'
```

The host's own TCP traffic is deliberately not clamped; only beam's target
sockets are.

## 8. Known risks and gaps
- Host `nftables` is default-deny with 22/443, established, ICMP/ICMPv6 and
  loopback allowed. The provider firewall was not independently verified.
- SSH is key-only `demir` with passwordless sudo; root and `debian` are
  disabled. The SSH key and provider account are the perimeter.
- Kernel `6.12.113+deb13-cloud-amd64` is active after the 2026-10-22 reboot;
  `needrestart` reports no pending kernel. Verify 443 and a fresh SSH connection
  after any future kernel update.
- `update-client.py` enables `sing-box` at boot and the tray autostart is
  installed; until the local sudo step is run, the service remains disabled and
  a reboot needs a manual/tray start.
- Cover parity is incomplete: beam emits `key_share, supported_versions` versus the
  cover's `supported_versions, key_share`, and the encrypted flight is 3 records /
  416 B versus 5 / 3085 B (temporary Ed25519 certificate). See `docs/10-cover-parity.md`.
- A real PMTU black hole exists on the VPS's path to Meta/Instagram
  `57.144.0.0/16` and Vercel `76.76.21.0/24`; both have a 1460-byte path MTU.
  beam clamps its own target sockets to `TCP_MAXSEG 1400` before connect and
  advertises an effective MSS of 1388. No host route or per-prefix rule is
  used. UDP/QUIC and unrelated host TCP traffic are not covered. See
  `docs/23-target-mss-2026-10-27.md`.
- Large HTTP/3 bodies through the production TUN can still show completion
  outliers. The original 20–45 s stalls were consistent with the 1400 MTU
  failure. At 1500 the 2026-10-24 TT Mobil hotspot run passed 1.33 MiB H3 and
  64 MiB TCP, but Google H3 showed 1–4/10 ~10.5 s completion outliers while
  HTTP/2 stayed stable. TUN
  and server drop counters stayed at zero, so this is H3-over-TCP/QUIC PTO,
  not an MTU drop. Hiddify users must select `system` and MTU 1500 manually.
- **HTTP/3 needs TUN MTU >=1480 for IPv4 and 1500 for IPv6 on this client
  stack.** The local 2026-10-23 matrix passes the IPv4 H3 probe at
  1480/1492/1500 and fails at 1280/1300/1400/1450 with beam and with stock
  Xray, across all UDP encodings and both `system` and `gvisor` TUN stacks.
  TCP, 1200-byte UDP, DNS, and HTTPS are unaffected at 1400. The production
  client is now **MTU 1500**; 1400 remains the fallback that loses H3. The
  2026-10-24 mobile hotspot run used outer MSS 1388 with no TUN drops. See
  `docs/14-tun-harness.md`.
- A 5-minute post-hardening soak and the read-only audit are complete. A
  low-rate four-hour live observation ran on 2026-10-24 across several
  deployments (about 2.5 hours on the final binary); its fd/restart sampler
  columns were malformed. A clean final-binary 24-hour soak and the privileged
  quiet syscall/wakeup gates remain open.
- No per-IP connection cap; the 1024-connection global cap, 256 pre-auth slots
  with a 5 s ClientHello deadline, 30 s cover timeout and provider firewall are
  the current mitigation.
- HTTPS upload acceleration needs Vision Direct before the body (e.g.
  `Expect: 100-continue`). Fully framed uploads stay async at ~1.34-1.37 s/GiB
  versus ~0.11 s/GiB with early Direct; this is a performance gap, not correctness.
- `bootstrap.sh` now restarts `beam`; verify 443 and a fresh SSH connection after
  every deploy.
- Single user, one inbound, no hot reload or stats; config changes need a restart, and there is no stock Xray fallback.

## 9. AI agent autonomy
Without approval: read-only checks (`systemctl status`, `journalctl`, `ss`, `ps`,
`df`, `free`, `curl`, `dig`, certificate checks via `curl -v`), local
builds/tests/benchmarks, packaging, docs, and commits on feature branches.
Server read-only checks are allowed.

Local sudo is required for client rotation (`sudo python3 deploy/update-client.py`),
starting/stopping `sing-box`, and editing `/etc/sing-box/config.json`. The sandbox
sets `no_new_privs`, so a human must run these local privileged commands.

Server sudo is already available to the agent as `demir` through `sudo -n`. Deploy,
restart, rollback, journal vacuum, and limit edits are allowed. Identity rotation,
snapshot restore, provider firewall changes, host wipe, and disabling SSH need
explicit approval. Never commit secrets, paste keys/UUIDs/links, or push/merge.
