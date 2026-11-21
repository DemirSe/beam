# Deployment guide

This guide covers installing, updating, and operating `beam` on a Linux host
with systemd.

The repository ships a distribution-agnostic service installer
([`deploy/beam-install.sh`](../deploy/beam-install.sh)), the systemd unit
([`deploy/beam.service`](../deploy/beam.service)), and an optional liveness
probe/timer. Host-level policy (SSH, firewall, sysctls, NTP, IPv6, journald) is
not managed by the installer and stays with the operator; recommended settings
are listed below.

## Install from a release archive

Download the release archive (`beam-<version>-<commit>-<target>.tar.gz`) and
its `.sha256` pin into one directory, or build one from a clean checkout with
`bash scripts/release-artifact.sh`.

1. Verify the archive and extract it (replace the example filename with your
   downloaded archive):

   ```bash
   ARCHIVE="beam-0.1.0-0123456789ab-x86_64-unknown-linux-gnu.tar.gz"
   sha256sum -c "$ARCHIVE.sha256"
   tar -xzf "$ARCHIVE"
   ```

2. Generate an identity and prepare your configuration:

   ```bash
   cp config.example.toml config.toml
   (umask 077; ./beam generate --host your.server.example --sni example.com > identity.txt)
   chmod 600 config.toml identity.txt
   ```

   Edit `config.toml` to replace `user.id`, `reality.private_key`,
   `reality.short_ids`, `reality.server_names`, and `reality.dest`. Validate
   it before installing:

   ```bash
   ./beam --check -c config.toml
   ```

3. Install the service, unprivileged `beam` account, unit, and liveness timer:

   ```bash
   sudo env BEAM_ARTIFACT="$ARCHIVE" BEAM_CONFIG=config.toml \
     bash beam-install.sh install
   ```

   `beam-install.sh` verifies both the outer archive SHA-256 and the inner
   `SHA256SUMS` binary hash, validates the staged binary as the `beam` user
   before replacing live files, creates `/etc/beam/config.toml` as
   `root:beam 0640`, runs `restorecon` when SELinux tools are present, enables
   and starts `beam.service` (and `beam-liveness.timer` when Python 3.11+ is
   available), and rolls back if the new binary fails readiness.

4. Remove any temporary secret-bearing files (`config.toml`, `identity.txt`)
   from the staging directory once the service is running.

## Update an existing host

By default `beam-install.sh` preserves `/etc/beam/config.toml` and stops
`beam-liveness.timer` while swapping files:

```bash
ARCHIVE="beam-0.1.0-0123456789ab-x86_64-unknown-linux-gnu.tar.gz"
sha256sum -c "$ARCHIVE.sha256"
tar -xzf "$ARCHIVE" beam-install.sh
sudo env BEAM_ARTIFACT="$ARCHIVE" bash beam-install.sh update
```

Set `BEAM_KEEP_CONFIG=0` and `BEAM_CONFIG=<path>` explicitly only when you
intend to replace the live configuration. Up to five timestamped `.bak-<stamp>`
backups are kept beside each managed file (`/usr/local/bin/beam`,
`/etc/systemd/system/beam.service`, `/etc/beam/config.toml`, and the liveness
files).

## Uninstall

```bash
sudo bash deploy/beam-install.sh uninstall
```

Pass `BEAM_PURGE=1` to also remove `/etc/beam/config.toml`, `.bak-*` backups,
and the `beam` system user/group.

## Self-recovery and liveness

- **`beam.service`** runs with `Restart=always`, `RestartSec=3s`,
  `RestartSteps=4`, `RestartMaxDelaySec=60s` (requires systemd 254+), and
  `StartLimitIntervalSec=300` / `StartLimitBurst=10`. On systemd 254+, crashes
  recover automatically with exponential backoff without hitting the start
  limit. On older systemd versions, `RestartSteps=` and `RestartMaxDelaySec=`
  are ignored, so a persistent crash loop retries every 3 seconds and can hit
  `StartLimitBurst=10` (requiring `systemctl reset-failed beam` after fixing
  the cause).
- **`beam-liveness.timer`** runs `/usr/local/lib/beam/liveness-check.py` every
  5 minutes (requires Python 3.11+ for stdlib `tomllib`; `beam-install.sh`
  skips enabling the timer with a warning on older Python). It reads
  `[server].listen` and `reality.server_names[0]` from `/etc/beam/config.toml`,
  completes a TLS handshake through `beam`, and restarts `beam.service` after
  three consecutive unresponsive probes (15 minutes). Cover-side resets/TLS
  errors are logged as `SKIP` so a cover outage never drops live sessions.
- If you stop `beam.service` intentionally for maintenance, stop
  `beam-liveness.timer` first so it does not restart the service after 15
  minutes.

## Recommended host settings

These settings are distribution-agnostic recommendations, not repo-maintained
scripts. Adapt file paths and service names to your Linux distribution and keep
provider console access open before changing SSH or firewall rules.

### Network and conntrack tuning

Apply via `/etc/sysctl.d/99-beam.conf` (load `tcp_bbr`, `sch_fq`, and
`nf_conntrack` if built as modules):

```ini
# Leave headroom for XUDP SO_RCVBUF requests (128 KiB * 2 per socket) and H3 bursts.
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304

# Recommended congestion control and pacing qdisc.
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Match beam's 1024 listen backlog with burst headroom.
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192

# Bound conntrack for churn while keeping UDP entries alive past idle timeouts.
net.netfilter.nf_conntrack_max = 65536
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_udp_timeout = 600
net.netfilter.nf_conntrack_udp_timeout_stream = 600
```

Note that `net.core.default_qdisc = fq` applies only to interfaces created
after the sysctl runs. On an existing NIC, apply `fq` live (or via your network
manager / boot hook):

```bash
tc qdisc replace dev <iface> root fq
```

Keep `net.ipv4.tcp_mtu_probing = 0` unless a measured PMTU failure justifies
changing it (see [README.md](../README.md#tls-stack-cover-and-mtu)).

### Firewall

Use a default-drop inbound policy and allow only:

- Loopback (`lo`) and `established,related` traffic
- ICMP / ICMPv6 as needed
- Your SSH port (verify it matches `sshd` before enabling the firewall)
- `beam`'s listening TCP port (default `443`)

Ensure only one firewall manager (`nftables`, `firewalld`, or `ufw`) is active
so rules are not flushed by a second daemon.

### Time synchronization

REALITY rejects handshakes whose timestamp differs from the server clock by
more than 300 seconds. Keep an NTP daemon (`chrony` or `systemd-timesyncd`)
enabled and synchronized. Prefer non-smearing UTC sources if you configure
explicit NTP servers.

### Optional IPv4-only service drop-in

If your host runs IPv4-only, you can narrow `beam.service`'s socket families
with a systemd drop-in at `/etc/systemd/system/beam.service.d/99-ipv4-only.conf`:

```ini
[Service]
# Reset the base unit's RestrictAddressFamilies= list before narrowing it.
RestrictAddressFamilies=
RestrictAddressFamilies=AF_INET AF_UNIX
```

Then run `systemctl daemon-reload && systemctl restart beam`.

### SSH, logging, and crash dumps

- Use key-only SSH (`PermitRootLogin no`, `PasswordAuthentication no`) and an
  optional brute-force jail (e.g. `fail2ban`).
- Cap persistent systemd journals (e.g. `Storage=persistent` and
  `SystemMaxUse=256M` in `/etc/systemd/journald.conf.d/`) so logs survive
  reboots without filling the root filesystem.
- `beam.service` sets `LimitCORE=0` to prevent core dumps of process memory.

## Health checks and rollback

Routine checks on the server:

```bash
systemctl status --no-pager -l beam
systemctl show beam -p NRestarts --value
sudo ss -ltnp 'sport = :443'
sudo journalctl -u beam --since "24 hours ago" -p warning --no-pager
```

Expect `active (running)`, `NRestarts=0`, `:443` owned by `beam`, and a quiet
warn-level journal. `runtime pressure counters increased` is actionable;
inspect its deltas.

To roll back to a previous release:

```bash
sudo env BEAM_ARTIFACT=<previous.tar.gz> bash beam-install.sh update
```

## Troubleshooting

| Symptom | First check |
|---|---|
| `beam` will not start | `sudo runuser -u beam -- /usr/local/bin/beam --check -c /etc/beam/config.toml`, then `journalctl -u beam -n 100`. |
| Auth fails for a valid client | Check server clock drift (`chronyc tracking` or `timedatectl`); REALITY rejects >300 s skew. |
| Repeated restarts, then stopped | `journalctl -u beam -n 100`; after fixing the cause, `systemctl reset-failed beam && systemctl start beam`. |
| Stopped service comes back after 15 min | Stop `beam-liveness.timer` before a planned stop of `beam.service`. |
| Disk filling | `journalctl --disk-usage` then `journalctl --vacuum-size=256M`. |
| Config rejected after an upgrade | `diff -u /etc/beam/config.example.toml /etc/beam/config.toml`, then update with `BEAM_KEEP_CONFIG=0`. |

## Client setup

The optional Linux/Windows tray clients and mobile profile notes are in
[`CLIENT.md`](CLIENT.md).
