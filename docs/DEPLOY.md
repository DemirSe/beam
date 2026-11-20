# Operator deploy runbook

This is the operator runbook for one Linux host. It covers service install,
host policy, client setup, and recovery.

The numbers in this runbook come from measurements on one host and one network
path. They are historical evidence, not a guarantee for your host. Measure your
own path before you set thresholds or expect the same results. The full lab
record is in [`STRESS-FINDINGS.md`](STRESS-FINDINGS.md).

Host details in the steps below are examples. Confirm distribution versions,
package names, ports, and unit names on your own host.

## Before you deploy

Read the host choices, the required preparation, and the minimum posture in
the [`Deploy`](../README.md#deploy) section of the README first. That section
decides whether you change this host at all. The rest of this runbook is the
mechanics, and the order of operations is [below](#order-of-operations).

### What each script changes, and what it leaves to you

Each script has a fixed boundary. Read it before you assume a step is done.

- `bootstrap.sh` installs and applies the SSH IPv4-only files and the host
  IPv6 sysctl on Debian. It does this after beam becomes ready.
- `bootstrap.sh` does not install nftables rules or start nftables. The
  operator owns the firewall on Debian.
- `bootstrap.sh` does not install chrony files, the `-4` clock option, or
  fail2ban. The operator owns those items on Debian.
- `bootstrap.sh` does not install the journald drop-in. The operator owns that
  file on Debian.
- `bootstrap.sh` warns on distributions other than Debian 13. It refuses
  non-x86_64 hosts, missing sshd, a missing Include, an invalid sshd
  configuration, no IPv4 SSH listener, or missing commands.
- `bootstrap-alma.sh` does not change SSH or host IPv6. The operator owns both
  changes on AlmaLinux.
- `bootstrap-alma.sh` installs nftables files and validates the rules. It does
  not start nftables or stop firewalld. The operator owns activation.
- `bootstrap-alma.sh` installs chrony files, chronyd options, and the journald
  drop-in. It does not install the chrony or fail2ban packages. It warns on
  distributions other than AlmaLinux 10 and refuses non-x86_64 hosts.
- `beam-install.sh` installs the binary, unit, example config, account, config,
  and optional liveness set. It never changes SSH, nftables, sysctls, IPv6, or
  the clock. It has no distribution check.

### Order of operations

1. Choose the host and confirm console access. If you stop here, the host
   stays unchanged.
2. Take the snapshot and prepare the account, sudo, and required tools. If you
   stop here, the host still runs its original service.
3. Prepare and check the config, then pin the release artifact by hash. If you
   stop here, the live files stay as they are.
4. Stage the bundle with the steps in [Stage the archive on the
   host](#stage-the-archive-on-the-host). If you stop here, remove the
   secret-bearing stage as that section describes.
5. Run the bootstrap path for the host distribution. If you stop here, beam is
   ready or restored by rollback. The Debian bootstrap applies SSH and IPv6
   policy. The operator applies AlmaLinux policy in step 6.
6. Verify production and install the remaining host policy from the sections
   below. If you stop here, the checks confirm the applied policy.
7. Remove the secret-bearing stage and watch the journal. If you stop here,
   keep the snapshot until the next check.

## Operations

Set `SSH_KEY` and `SERVER` in the shell before using the examples below.
`SSH_PORT` defaults to 22 when it is unset. The verifier uses it for both the
connection and the expected sshd port. For a
first-time host, install AlmaLinux 10 or Debian 13 with key-only access for
your own account and passwordless sudo; test the `deploy/` nftables/SSH/resolver
files before enabling them, keeping the provider console available. The
examples use a placeholder account name; substitute your own. Use
`deploy/bootstrap-alma.sh` on AlmaLinux and `deploy/bootstrap.sh` on Debian.
The local client
rotation helper is `deploy/update-client.py` (TUN `system`, MTU 1500); it
preserves whether the client service is enabled at boot. The
tray polkit/autostart files are in `deploy/`. Never commit or paste secrets.

### Host hardening extras

Three host files are not part of `bootstrap.sh`, because they install or
configure packages that the rollout does not manage.

- **Firewall counters.** `deploy/nftables.conf` counts each rule. Run
  `nft list table inet filter` to see new connections per port and the bytes
  that the host drops. The counters cost no measurable throughput.
- **fq at boot.** `net.core.default_qdisc` applies only to interfaces that the
  kernel creates after the sysctl. A cloud NIC exists earlier, so
  `deploy/beam-fq.service` runs `deploy/apply-fq.sh` at boot and replaces the
  qdisc on the default-route interface. The script is idempotent.
- **Time sources.** `chrony`, configured by `deploy/chrony-beam.conf`, uses five
  explicit servers from four institutions in three countries:
  `time.ume.tubitak.gov.tr`, `samur.ulak.net.tr`,
  `ntp.ripe.net`, `ptbtime1.ptb.de`, and
  `ntp.time.nl`. There is no pool entry, so the server set never rotates to an
  unknown host. `minsources 3` stops a single bad clock from moving the host.
  The clock matters because REALITY rejects a handshake whose timestamp is more
  than 300 seconds away from the server clock. Measure with `chronyc -n
  sources` and `chronyc sourcestats`. Install `deploy/chrony-beam.conf` as
  `/etc/chrony/chrony.conf` on Debian or `/etc/chrony.conf` on AlmaLinux. The
  `-4` option keeps chrony on IPv4, because it otherwise opens a control
  socket on `[::1]:323` and the verifier requires zero IPv6 listeners: install
  `deploy/default-chrony` as `/etc/default/chrony` on Debian, or write
  `/etc/sysconfig/chronyd` with `OPTIONS="-4"` on AlmaLinux.
- **Leap smear.** Google, Amazon, and Meta smear leap seconds. None of the five
  servers above belongs to those operators, so the set agrees with UTC through
  a leap second.
- **Self recovery.** `beam.service` runs with `Restart=always` and bounded
  systemd start limits, so a crash recovers without an unlimited loop. A manual
  stop still stays stopped. `deploy/beam-liveness.timer` runs a full TLS
  handshake on port 443 every five minutes and restarts the service after
  three failures in a row, which covers a hung process that systemd cannot
  see.
- **SSH port.** `deploy/sshd-62-port.conf` moves sshd to port
  `${SSH_PORT:-22}`. Set that variable in the shell before using these
  commands. `bootstrap.sh` reads the live port from `sshd -T` instead of
  assuming 22. Update any SSH client that still uses the default.
- **SSH brute-force jail.** Install `fail2ban`, copy `deploy/zz-beam-sshd.local`
  to `/etc/fail2ban/jail.d/`, then run `systemctl enable --now fail2ban`. Keep
  the `zz-` prefix so that the file loads after the distribution defaults.
  Confirm with `fail2ban-client get sshd bantime` and
  `fail2ban-client status sshd`. Confirm the package name and jail path on your
  host.

Operating system updates are manual by owner decision. The host has no
automatic update service and restarts only when the owner runs them.

### Host maintenance rules

`deploy/maintenance-rules.md` is installed as
`/etc/beam/maintenance-rules.md`, with the alias `/etc/host-rules.md`.
The login banner and the `/etc/ssh/sshrc` line use the alias, so the
notice names no service and no host role. The banner is three lines and
the `/etc/ssh/sshrc` line goes to stderr only, so standard output stays
clean. `/etc/beam` is mode 0751 `root:beam`: logins can traverse it to read
the alias but cannot list the directory. The config stays mode 0640. The rules
file holds no secret; never copy `/etc/beam/config.toml` or other secret files.
Add a rule to that file when a decision changes.

### Daily checks

```bash
ssh -i "$SSH_KEY" "$SERVER" \
  'systemctl status --no-pager -l beam; systemctl is-failed beam; systemctl show beam -p NRestarts --value'
ssh -i "$SSH_KEY" "$SERVER" \
  'sudo -n ss -ltnp; sudo -n journalctl -u beam --since "24 hours ago" -p warning --no-pager'
ssh -i "$SSH_KEY" "$SERVER" \
  'pid=$(systemctl show beam -p MainPID --value); ps -o pid,rss,vsz,nlwp,etime,comm -p "$pid"; printf "fds="; sudo -n ls "/proc/$pid/fd" | wc -l'
ssh -i "$SSH_KEY" "$SERVER" \
  'cat /sys/fs/cgroup/system.slice/beam.service/memory.current; cat /sys/fs/cgroup/system.slice/beam.service/memory.peak'
ssh -i "$SSH_KEY" "$SERVER" \
  'cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max'
```

Expect active/running, enabled, `NRestarts=0`, no unexpected listeners, and a
quiet warn-level journal. `runtime pressure counters increased` is actionable;
inspect its deltas. A healthy idle process is roughly 2 threads and 10 fds;
RSS is normally under 20 MiB but can retain an allocator plateau after a large
burst (measured on one host, 2026-11). Warn at RSS >128 MiB or monotonic
growth, fds >256, threads >128, or sustained swap. Confirm these thresholds on
your host.

### Deploy

A host that needs only the beam service can use the release archive and
`beam-install.sh`. That path installs the binary, the unit, the account, and
the config, and it leaves every host policy decision alone. The fresh and
update paths below also install the nftables, SSH, sysctl, and post-boot
files, and they install the full host policy set.

Both paths build a bundle with `deploy/package.sh`, copy it to a private
staging directory on the host, and unpack it there. A new host needs the
bundle that contains `beam.toml`; an update uses the bundle without it.

#### Stage the archive on the host

`deploy/package.sh` prints `bundle=<path>`. Assign that path to `BUNDLE` in
this shell, then run these commands:

```bash
source scripts/dev-env.sh
: "${BUNDLE:?set BUNDLE to the bundle path printed by deploy/package.sh}"
test -f "$BUNDLE"
STAGE=$(ssh -4 -p "${SSH_PORT:-22}" -i "$SSH_KEY" "$SERVER" 'mktemp -d /tmp/beam-deploy.XXXXXXXX')
test -n "$STAGE"
test "$(ssh -4 -p "${SSH_PORT:-22}" -i "$SSH_KEY" "$SERVER" "stat -c %a '$STAGE'")" = 700
trap 'ssh -4 -p "${SSH_PORT:-22}" -i "$SSH_KEY" "$SERVER" "rm -rf -- \"$STAGE\""' EXIT
scp -4 -p "${SSH_PORT:-22}" -i "$SSH_KEY" "$BUNDLE" "$SERVER:$STAGE/beam-deploy.tar.gz"
ssh -4 -p "${SSH_PORT:-22}" -i "$SSH_KEY" "$SERVER" "chmod 600 '$STAGE/beam-deploy.tar.gz'"
ssh -4 -p "${SSH_PORT:-22}" -i "$SSH_KEY" "$SERVER" "tar -xzf '$STAGE/beam-deploy.tar.gz' -C '$STAGE'"
```

`mktemp -d` creates an atomically named, mode-0700 staging directory; do not
use a predictable `/tmp/beam-deploy` directory. The guard stops an empty or
missing `BUNDLE` before `scp` can copy the wrong file. The installer reads the
unpacked files from `$STAGE` and stops at the first missing file and names it.
Remove the secret-bearing stage in every outcome, including a failed rollout,
after preserving local logs and the timestamped recovery backups. The trap
removes it when the shell exits; the fresh and update steps below also remove
it explicitly.

#### Fresh host

1. Install AlmaLinux 10 or Debian 13. Give your own account a key-only login
   and passwordless sudo, and keep the provider console open. Install `chrony`,
   `nftables`, and `fail2ban` (`fail2ban` comes from EPEL on AlmaLinux), and
   enable the time daemon and the jail; the post-boot check names each unit
   that is not active.
2. Run `make build`. Copy `config.example.toml`, replace every value with your
   own X25519 key, short ID, UUID, cover name, and cover destination
   (`reality.dest`), then run
   `target/release/beam --check -c <your-config>`. Keep the file mode 0600.
3. Build the bundle with your config:
   `BEAM_CONFIG=<your-config> bash deploy/package.sh`. It prints
   `bundle=<path>`; use that path as `BUNDLE` and stage it as in
   [Stage the archive on the host](#stage-the-archive-on-the-host).
4. Install from `$STAGE` over SSH:
   `ssh -4 -p "${SSH_PORT:-22}" -i "$SSH_KEY" "$SERVER" "sudo -n env BEAM_KEEP_CONFIG=0 bash '$STAGE/bootstrap-alma.sh'"`
   on AlmaLinux, or the same command with `bootstrap.sh` on Debian. The
   AlmaLinux script does not change SSH, the firewall, or host IPv6.
5. Verify with `deploy/verify-production.sh`. On AlmaLinux, install the
   firewall and host IPv6 files, and `deploy/sshd-60-hardening.conf` as
   `/etc/ssh/sshd_config.d/00-beam-hardening.conf`, over that verified
   connection and with the console open. Replace the `AllowUsers` account name
   first. Before you enable nftables, confirm that the SSH `dport` in
   `deploy/nftables.conf` matches your `${SSH_PORT:-22}` and the `Port` in
   `deploy/sshd-62-port.conf`. The shipped rule allows 22 only, so a host on a
   different port is locked out the moment nftables starts.
6. Remove the secret-bearing stage and clear the exit trap:

   ```bash
   ssh -4 -p "${SSH_PORT:-22}" -i "$SSH_KEY" "$SERVER" "rm -rf -- '$STAGE'"
   trap - EXIT
   ```

#### Update an existing host

The update bundle omits the config, because the installer keeps the live
`/etc/beam/config.toml`:

```bash
source scripts/dev-env.sh
BUNDLE=$(BEAM_KEEP_CONFIG=1 bash deploy/package.sh | sed -n 's/^bundle=//p')
```

Stage it with [Stage the archive on the host](#stage-the-archive-on-the-host),
then install from `$STAGE` and remove it:

```bash
ssh -4 -p "${SSH_PORT:-22}" -i "$SSH_KEY" "$SERVER" \
  "sudo -n env BEAM_KEEP_CONFIG=1 bash '$STAGE/bootstrap.sh'"
ssh -4 -p "${SSH_PORT:-22}" -i "$SSH_KEY" "$SERVER" "rm -rf -- '$STAGE'"
```

`bootstrap.sh` is the Debian path. On AlmaLinux, use the same commands with
`bootstrap-alma.sh`. Both installers preserve an existing
`/etc/beam/config.toml` by default and keep `.bak-<stamp>` copies of replaced
files; they do not activate the firewall. For host policy, `bootstrap.sh`
installs and applies the SSH and host IPv6 files on Debian.
`bootstrap-alma.sh` only writes nftables files and leaves activation to the
operator. Set `BEAM_KEEP_CONFIG=0` explicitly to replace the live config. A plain
`sudo bash ...` cannot inherit an exported `BEAM_KEEP_CONFIG`, so use `env`
for both modes. Do not use `BEAM_KEEP_CONFIG=1` for a host without
`/etc/beam/config.toml`: the installer stops with an error.

`package.sh` validates local secrets and bundles both installers, their service
and host files, and the Alma chrony inputs. With `BEAM_KEEP_CONFIG=1` the
archive contains no `beam.toml`. Bootstrap
applies and validates sysctls, validates the new binary as the unprivileged
service user, installs the beam drop-in, backs up replaced files, rolls back on
a failed restart/readiness probe, prunes each backup set to five, and polls
beam's own 443 listener. After beam is ready it installs the SSH
`AddressFamily inet` drop-in and applies the host IPv6 sysctl; a failure in
either step restores the previous SSH/sysctl state before exit. Verify the
deployed state without printing config contents:

```bash
SSH_KEY="$SSH_KEY" SERVER="$SERVER" EXPECT_IPV4_ONLY=1 \
  EXPECT_HOST_IPV6_DISABLED=1 deploy/verify-production.sh
SSH_KEY="$SSH_KEY" SERVER="$SERVER" EXPECT_IPV4_ONLY=1 \
  EXPECT_HOST_IPV6_DISABLED=1 CHECK_H2=1 \
  TUN_IFACE=sbtun0 CHECK_H2_DST=1.1.1.1:443 CHECK_H2_FAMILY=4 \
  deploy/verify-production.sh
```

`EXPECT_IPV4_ONLY=1` checks that systemd reports
`RestrictAddressFamilies=AF_INET AF_UNIX` and fails if `AF_INET6` remains.
`EXPECT_HOST_IPV6_DISABLED=1` requires `all/default/lo.disable_ipv6=1`, zero
IPv6 addresses, routes, and listeners, and `sshd` reporting
`addressfamily inet`.
`CHECK_H2=1` requires the named local tunnel and fails if it is missing. It
verifies the path real traffic takes: three sequential HTTPS requests to
`https://<CHECK_H2_DST>/cdn-cgi/trace`, each requiring HTTP 200 and negotiated
HTTP/2, then a held client connection that must produce a new established
socket owned by beam on the server for the same destination. The example
profile uses `CHECK_H2_DST=1.1.1.1:443` and `CHECK_H2_FAMILY=4`; IPv6 probes
remain available for lab use only via `CHECK_H2_FAMILY=6`. The correlated
beam-owned socket observation during the held connection is the discriminator;
HTTPS alone can also succeed through the host's direct uplink. Override the
hold length with `CHECK_H2_HOLD` (default 8 seconds); it must be at least 4
seconds. The Linux profile sets
`auto_redirect`, so never pin probes to the tunnel device: traffic bound to it
is not proxied. Set `EXPECTED_BINARY_SHA` and `EXPECTED_CONFIG_SHA` to make the
script fail on a hash mismatch.

Production uses the production-only drop-in
`deploy/beam-ipv4-only.conf`; copy it to the host and install it as
`/etc/systemd/system/beam.service.d/99-ipv4-only.conf`:

```bash
sudo install -d -m 0755 /etc/systemd/system/beam.service.d
sudo install -m 0644 deploy/beam-ipv4-only.conf \
  /etc/systemd/system/beam.service.d/99-ipv4-only.conf
sudo systemctl daemon-reload
sudo systemctl restart beam
```

The empty `RestrictAddressFamilies=` assignment is required: systemd appends
repeated family assignments, so without the reset the base unit's `AF_INET6`
remains. To roll back, remove the drop-in, reload, reset the failed state, and
restart:

```bash
sudo rm -f /etc/systemd/system/beam.service.d/99-ipv4-only.conf
sudo systemctl daemon-reload
sudo systemctl reset-failed beam
sudo systemctl restart beam
```

This narrows only the beam service's socket families. Host IPv6 and SSH are
controlled by separate files: `deploy/99-beam-ipv6-disable.conf` (installed as
`/etc/sysctl.d/99-beam-ipv6-disable.conf`) and
`deploy/sshd-61-ipv4-only.conf` (installed as
`/etc/ssh/sshd_config.d/61-ipv4-only.conf`). The fresh-host bootstrap installs
the beam drop-in before restart, then the SSH and IPv6 files after beam is
ready. To roll back host-wide policy, remove the SSH
and IPv6 files, re-enable IPv6, reconfigure the IPv4-default interface, and
reload ssh while retaining provider console access:

```bash
sudo rm -f /etc/ssh/sshd_config.d/61-ipv4-only.conf
sudo rm -f /etc/sysctl.d/99-beam-ipv6-disable.conf
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 \
  net.ipv6.conf.default.disable_ipv6=0 net.ipv6.conf.lo.disable_ipv6=0
iface=$(ip -o -4 route show default | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -n "$iface" ]; then
  if command -v nmcli >/dev/null 2>&1; then
    sudo nmcli device reapply "$iface" || sudo systemctl restart NetworkManager
  else
    sudo networkctl reconfigure "$iface" || sudo systemctl restart systemd-networkd
  fi
fi
sudo sshd -t
sudo systemctl reload sshd 2>/dev/null || sudo systemctl reload ssh
```

AlmaLinux names the SSH unit `sshd` and owns the NIC through NetworkManager;
Debian uses `ssh` and `systemd-networkd`. Confirm the unit and NIC manager on
your host.

Then verify end to end on IPv4:

```bash
curl -4 -sS -o /dev/null -w '%{http_code}\n' https://example.com/
# Expected failure: the default profile rejects public UDP/443.
if curl --http3-only -sS -o /dev/null --max-time 5 https://cloudflare-quic.com/; then
  echo 'unexpected H3 success' >&2
  exit 1
fi
dig +short example.com
```

For cover verification, request `https://whatsapp.net` through the server and
confirm the public `*.whatsapp.net` certificate. Run the local TUN matrix in
all three UDP modes after client or server changes.

### Rollback and emergency

Backups are timestamped beside each installed file:

```text
/usr/local/bin/beam.bak-<stamp>
/etc/beam/config.toml.bak-<stamp>
/etc/beam/config.example.toml.bak-<stamp>
/etc/systemd/system/beam.service.bak-<stamp>
/etc/systemd/system/beam.service.d/99-ipv4-only.conf.bak-<stamp>
/etc/sysctl.d/99-beam.conf.bak-<stamp>
/etc/sysctl.d/99-beam-conntrack.conf.bak-<stamp>
/etc/sysctl.d/99-beam-ipv6-disable.conf.bak-<stamp>
/etc/modules-load.d/99-beam-conntrack.conf.bak-<stamp>
/etc/ssh/sshd_config.d/61-ipv4-only.conf.bak-<stamp>
```

Stop beam, install all required backups, validate config, run `sysctl
--system`, daemon-reload/reset-failed, and start. `beam-install.sh` keeps the
five newest `.bak-<stamp>` copies per managed file. Rollback is not atomic and
there is no automatic stock-Xray fallback. Keep provider console access before
changing SSH or firewall state. For a crash loop, read the unit and journal
and run `beam --check` as the `beam` user. For a full disk, inspect and vacuum
the journal.

## Client setup

The Linux tray client, its DNS on/off switch, the ctrld recovery paths, and the
mobile profile are in [`CLIENT.md`](CLIENT.md). This runbook covers the server
only.

## When it breaks

| Symptom | First check |
|---|---|
| Locked out after enabling nftables | The SSH `dport` in `/etc/nftables.conf` must match `Port` in `sshd-62-port.conf`. Use the provider console. |
| beam will not start | `runuser -u beam -- /usr/local/bin/beam --check -c /etc/beam/config.toml`, then `journalctl -u beam -n 100`. |
| Repeated restarts, then stopped | `journalctl -u beam -n 100`; after a fix, `systemctl reset-failed beam` then `systemctl start beam`. |
| New release misbehaves | Reinstall the previous artifact: `sudo env BEAM_ARTIFACT=<old.tar.gz> bash beam-install.sh update`. |
| Disk filling | `journalctl --disk-usage` then `journalctl --vacuum-size=256M`. |
| Config rejected after an upgrade | `diff -u config.example.toml /etc/beam/config.toml`, then reinstall with `BEAM_KEEP_CONFIG=0`. |
| Host rebooted, service down | `systemctl is-enabled beam beam-liveness.timer beam-fq.service`; `journalctl -u beam-post-boot-check -b`. |

Removing beam: `sudo bash deploy/beam-install.sh uninstall`. Add `BEAM_PURGE=1`
to remove the account and the config as well.
