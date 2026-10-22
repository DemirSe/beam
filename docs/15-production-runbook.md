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
`docs/13-vision-direct-design.md`, `docs/14-tun-harness.md`, `bench/README.md`.

## 1. What is deployed

| Item | State |
|---|---|
| Host | Debian 13.6, x86_64, 1 vCPU, 1 GiB RAM, 1 GiB swap |
| Service | `beam.service`, active and enabled, `User=beam`, `0.0.0.0:443`; cover `whatsapp.net:443` |
| Binary | `/usr/local/bin/beam`, root:root 0755 |
| Config | `/etc/beam/config.toml`, root:beam 0640, contains secrets |
| Unit / backups | `/etc/systemd/system/beam.service` 0644; `*.bak-<UTC stamp>` beside each installed file |
| Local client | sing-box, `/etc/sing-box/config.json` 0600, active but disabled at boot |
| Client identity | `~/.config/beam/client-identity.json`, `client-link.txt` 0600 |
| Tunnel egress | IPv4 `158.94.216.102`, IPv6 `2a01:f900:11:168::1` |
| Firewall | No host `nftables`/`ufw`; provider firewall is the only firewall (allowlist not verified here) |

Old stock Xray is absent; only TCP/443 and SSH 22 are exposed. The unit sets
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `LimitNOFILE=65536`, and only `CAP_NET_BIND_SERVICE`.

## 2. Daily checks
```bash
bssh 'systemctl status --no-pager -l beam'
bssh 'sudo -n ss -ltnp; sudo -n journalctl -u beam --since "24 hours ago" -p warning --no-pager'
bssh 'pid=$(systemctl show beam -p MainPID --value); ps -o pid,rss,vsz,nlwp,etime,comm -p "$pid"; printf "fds="; sudo -n ls "/proc/$pid/fd" | wc -l'
bssh 'df -h /; df -i /; free -m; swapon --show; uptime; systemctl show beam -p NRestarts --value'
bssh 'sudo -n journalctl --disk-usage'
```
Expect `active (running)` and `enabled`; `ss` should show `beam` on
`0.0.0.0:443` and `sshd` on 22, with no unexpected listeners. A healthy
`warn`-level process is normally quiet. The only documented benign warning is
`authenticated VLESS command is not implemented yet; closing command=Rvs` for
the unsupported reverse command; treat anything else as actionable.
`ps` reports RSS/VSZ in KiB and `nlwp` as threads. Local churn baseline: RSS
7.7 to 8.3 MiB, 2 threads, 10 fds; live idle RSS was about 840 KiB. The same
pass covers disk, inodes, swap, load, and restart count.
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
fields from `~/.config/beam/client-identity.json`, restarts sing-box, and
restores the backup on failure:
```bash
cd /home/demir/pi/beam
sudo python3 deploy/update-client.py
```
Alternatively, import `~/.config/beam/client-link.txt` into Hiddify; it contains
credentials, so never paste it into chat, tickets, or git. Verify:
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
```
Deploy and load the new binary:
```bash
bssh 'rm -rf /tmp/beam-deploy && mkdir -p /tmp/beam-deploy && tar -xzf /tmp/beam-deploy.tar.gz -C /tmp/beam-deploy && sudo -n bash /tmp/beam-deploy/bootstrap.sh'
bssh 'sudo -n systemctl restart beam'
```
`bootstrap.sh` stops/disables the old Xray units, creates `beam`, backs up and
installs binary/config/unit, validates the config, starts the service, and checks
443. `enable --now` does not restart an active process; the explicit restart
above is required.
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
bssh 'ls -1t /usr/local/bin/beam.bak-* /etc/beam/config.toml.bak-* /etc/systemd/system/beam.service.bak-*'
STAMP="<stamp>"
bssh 'sudo -n systemctl stop beam'
bssh "sudo -n install -m 0755 -o root -g root /usr/local/bin/beam.bak-$STAMP /usr/local/bin/beam"
bssh "sudo -n install -m 0640 -o root -g beam /etc/beam/config.toml.bak-$STAMP /etc/beam/config.toml"
bssh "sudo -n install -m 0644 -o root -g root /etc/systemd/system/beam.service.bak-$STAMP /etc/systemd/system/beam.service"
bssh 'sudo -n systemctl daemon-reload && sudo -n systemctl start beam'
```
Rollback is not atomic; stop first, install all three, then start. There is no
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
console is the out-of-band path. The provider firewall is the only firewall;
`nftables`/`ufw` are absent, so do not assume host rules.
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
| Threads | 2 idle | > 16 | > 64; lower `max_connections` |
| Swap | 0 used | any sustained use | > 128 MiB; restart, lower limits |
| Disk | < 70% | > 80% | > 90%; vacuum journal, clean bundles |
| Load | < 1 | > 2 | > 4; investigate before changing limits |
| Restarts | 0 | > 3/day | crash loop; read journal and config check |
| 443 listener | present | missing briefly during restart | missing otherwise; page |
| Egress | the two VPS addresses | ISP address | tunnel down; start sing-box |

The live `max_connections` is 256. Each Vision Direct relay can hold a blocking
task and a 512 KiB splice pipe. On 1 vCPU, Tokio's blocking pool can grow to 512
threads, but more threads are not more capacity; 256 worst-case connections can
pressure 1 GiB before the fd limit. Lower to 128 when RSS exceeds 256 MiB,
threads exceed 64, swap is used, or p95 latency rises; lower to 64 if pressure
persists. `max_udp_destinations` also consumes one socket/fd per destination.
Change a limit, validate, and restart:
```bash
ssh -t -i "$SSH_KEY" "$SERVER" 'sudoedit /etc/beam/config.toml'
bssh 'sudo -n runuser -u beam -- /usr/local/bin/beam --check -c /etc/beam/config.toml'
bssh 'sudo -n systemctl restart beam'
```
Edit only `[limits]`; keep the file root:beam 0640. The example's 1024 default is not the live value.

## 8. Known risks and gaps
- No host firewall: only the provider firewall protects 22/443; a provider mistake exposes the host.
- Root SSH key login and passwordless sudo for `demir` are the access model; the SSH key and provider account are the perimeter.
- `sing-box` is active but disabled at boot; after a reboot there is no tunnel until
  a manual/tray start. Enabling at boot changes host routing and needs a test.
- Cover parity is incomplete: beam emits `key_share, supported_versions` versus the
  cover's `supported_versions, key_share`, and the encrypted flight is 3 records /
  416 B versus 5 / 3085 B (temporary Ed25519 certificate). See `docs/10-cover-parity.md`.
- Only a 5-minute production soak has run; a separate read-only audit is in
  progress. A 24-hour soak and privileged syscall/wakeup gates remain open.
- HTTPS upload acceleration needs Vision Direct before the body (e.g.
  `Expect: 100-continue`). Fully framed uploads stay async at ~1.34-1.37 s/GiB
  versus ~0.11 s/GiB with early Direct; this is a performance gap, not correctness.
- `bootstrap.sh` does not restart an active service; the explicit restart in section 4 is mandatory.
- Single user, one inbound, no hot reload or stats; config changes need a restart, and there is no stock Xray fallback.

## 9. AI agent autonomy
Without approval: read-only checks (`systemctl status`, `journalctl`, `ss`, `ps`,
`df`, `free`, `curl`, `dig`, `openssl s_client`), local builds/tests/benchmarks,
packaging, docs, and commits on feature branches. Server read-only checks are allowed.

Local sudo is required for client rotation (`sudo python3 deploy/update-client.py`),
starting/stopping `sing-box`, and editing `/etc/sing-box/config.json`. The sandbox
sets `no_new_privs`, so a human must run these local privileged commands.

Server sudo is already available to the agent as `demir` through `sudo -n`. Deploy,
restart, rollback, journal vacuum, and limit edits are allowed. Identity rotation,
snapshot restore, provider firewall changes, host wipe, and disabling SSH need
explicit approval. Never commit secrets, paste keys/UUIDs/links, or push/merge.
