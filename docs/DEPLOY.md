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
`SSH_PORT` defaults to 22 when it is unset. For a
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
  that the host drops. The counters cost no measurable throughput: 245 Mbit/s
  without them and 271 Mbit/s with them, three runs each on the same path
  (measured on one host, 2026-11).
- **fq at boot.** `net.core.default_qdisc` applies only to interfaces that the
  kernel creates after the sysctl. A cloud NIC exists earlier, so
  `deploy/beam-fq.service` runs `deploy/apply-fq.sh` at boot and replaces the
  qdisc on the default-route interface. The script is idempotent.
- **Time sources.** `chrony`, configured by `deploy/chrony-beam.conf`, uses five
  explicit servers from four institutions in three countries:
  `time.ume.tubitak.gov.tr` (stratum 1, 26 microseconds standard deviation,
  measured on one host, 2026-11),
  `samur.ulak.net.tr` (ULAKBIM), `ntp.ripe.net`, `ptbtime1.ptb.de`, and
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
   own X25519 key, short ID, UUID, and cover name, then run
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
   first.
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

## Linux tray and DNS switch

`clients/linux-tray` is a minimal GTK/AppIndicator tray plus a small setuid
root helper. It has one action: Connect/Disconnect. There is no settings window
and no autostart entry.

- Disconnected: systemd-resolved uses the existing local ctrld resolver at
  `127.0.0.1:5300`, which forwards to NextDNS
  (`https://dns.nextdns.io/<PROFILE_ID>`). If ctrld is not installed, the helper
  restores the host's own `99-beam.conf` when it saved one. Other resolved
  drop-ins are never touched. Confirm the resolver address and port on your
  host.
- Connected: `beam-client.service` starts and its `ExecStartPost` calls the
  helper's `dns-on`. The helper waits for `sbtun0`, moves the ctrld resolved
  drop-in aside, writes `99-beam.conf` with `DNS=1.1.1.1`, and reloads
  systemd-resolved. The intended path is that this query leaves through the TUN
  and reaches the profile's NextDNS DoH resolver; the isolated test does not
  prove that live path. Without ctrld, the helper's own file starts with an
  empty `DNS=`, because repeated `DNS=` assignments append.
- Ownership is recorded in `99-beam.conf.beam-own`, which stores the exact
  bytes the helper wrote. Content alone never proves ownership. Before the
  first write, a host `99-beam.conf` is saved as `99-beam.conf.beam-prev`,
  with or without ctrld, and restored on disconnect. A host file whose content
  happens to equal a helper output is saved and restored too. The helper logs
  one warning, because it cannot tell that file from a marker-less leftover of
  an older helper version. Do not delete that file on a content guess. The
  recovery section below gives a safe procedure.
- The helper deletes a live `99-beam.conf` only when its bytes equal the
  marker. Bytes that differ from the marker stay, even when they equal some
  other helper output, so an edit wins over the cleanup. When a saved host file
  exists, the helper removes the marker first and then renames the host file
  back. This order is required: a marker that outlived the restore would match
  a byte-identical host file, and the next restore would delete host data. If
  the marker delete fails, both files stay and the run exits nonzero. If the
  rename fails, the helper writes the marker back and exits nonzero, so a
  later attempt retries the rename. A power loss between the two steps leaves
  the saved host file, the live helper file, and no marker. That state is
  reported and never deleted; use the recovery table below.
- A `99-beam.conf` with no marker is host data and stays. This includes a file
  left by a helper version that predates the marker. After a power loss such a
  file can point DNS at `1.1.1.1` through a tunnel that is down. The boot
  reset runs for that file but does not delete it. Use the recovery steps
  below.
- While connected, an edit to `99-beam.conf` is never overwritten. With a
  saved host file, `dns-off` keeps both files, writes one warning to the system
  log, and exits nonzero, so `ExecStopPost` reports the failure. A later
  `dns-on` refuses the same way. Without a saved host file, the edited file is
  host data: `dns-off` leaves it, clears the marker, and exits zero, and a
  later `dns-on` refuses rather than overwrite the edit. The operator must
  reconcile the files.
- The Linux profile sets `auto_redirect: true` on the TUN. With only
  `auto_route`, TCP through the TUN timed out (observed on one host, 2026-11);
  the nftables redirect path fixes TCP and is required on this host. Requires
  nftables and a root client service.
  The profile has no IPv6 TUN address and uses `dns.strategy: ipv4_only`; with
  `auto_redirect`, sing-box rejects IPv6 at the host, so IPv6 (including local
  loopback) is intentionally unavailable while connected.
- The Linux profile also rejects UDP/443 before sniffing with
  `action: reject`, `method: default`, and `no_drop: true`. sing-box emits ICMP
  port unreachable immediately, so browsers and curl fall back to HTTP/2
  without waiting for the XUDP/TCP retransmission timeout. H3 is intentionally
  unavailable on this stock-client profile; the TCP/REALITY cover is unchanged.
- `restore-dns` (also used by the boot reset) restores the saved ctrld and host
  files and removes only a live file whose bytes equal the marker. It is safe
  to run by hand while connected: it does not stop the service, and the later
  `ExecStopPost` `dns-off` finds nothing to restore and exits 0. Each component
  is restored even when the other conflicts. An unresolved conflict keeps its
  files and keeps returning nonzero on later attempts.
- `ExecStopPost` calls `dns-off` and restores the saved ctrld drop-in or the
  saved `99-beam.conf`. `Restart=no` avoids a restart cycle where the TUN
  comes back without the matching DNS state.
- `beam-dns-reset.service` is enabled at boot and is ordered before
  `beam-client.service`. It runs when any of these files exists: the saved
  ctrld drop-in, the saved host drop-in, a `99-beam.conf`, or the ownership
  marker. The condition only starts the unit. The helper still decides what it
  can delete. On a host with its own `99-beam.conf`, the unit runs, leaves that
  file, and exits 0. A marker with no live file covers a crash between the two
  writes. The marker-less leftover above is a documented limit, not a
  recovery.
- `beam-client.service` is ordered after `systemd-resolved.service` and
  `ctrld.service`. `dns-on` reloads the resolver and moves the ctrld drop-in
  aside. Ordering after ctrld stops a late ctrld start from re-creating that
  drop-in in the middle of `dns-on`.
- Limits: the helper manages only systemd-resolved global drop-ins. The
  isolated state test proves the drop-in file handling, not the resolver
  behavior. These paths can bypass or override the helper's file, and they
  are not tested:
  - per-link DNS from NetworkManager, systemd-networkd, or DHCP. resolved
    applies it to one link, and it can win over the global `DNS=` for a
    matching name;
  - a drop-in whose file name sorts after `99-beam.conf`;
  - a resolver stub, container resolver, or application that ignores the
    systemd-resolved configuration, such as a browser with its own DoH, a
    static `/etc/resolv.conf`, or an application-level cache that keeps old
    answers;
  - IPv6 RDNSS on a link that the TUN does not own;
  - whether a resolver answers behind a restored ctrld drop-in. The helper
    cannot detect a ctrld removal while connected. See [Removing or upgrading
    ctrld](#removing-or-upgrading-ctrld);
  - the live effect of the empty `DNS=` reset on a host without ctrld, and the
    claim that DNS queries traverse the TUN to NextDNS.

Check `resolvectl status` and `resolvectl query <name>` while connected.
Compare the reported link, server, and routing domain before you rely on the
tunnel for DNS.

### DNS recovery after a failed switch

`dns-off`, `restore-dns`, and the boot reset log to the journal as
`beam-helper`. A nonzero exit means that the helper kept at least one file. Do
not delete a kept file. Identify it first.

```bash
sudo systemctl stop beam-client          # if the unit is still up
sudo journalctl -e -t beam-helper        # names the kept files
sudo ls -l /etc/systemd/resolved.conf.d/
resolvectl status
```

| State | Safe action |
|---|---|
| `99-beam.conf.beam-prev` and `99-beam.conf` differ | The host file was edited while connected. Copy the live file aside if you need it. Move `99-beam.conf.beam-prev` back, then reload. |
| Both files and no marker | An interrupted restore, or a leftover from an older helper. The helper cannot prove which bytes are host data, so it keeps both. Copy both aside, decide which one DNS should use, move that one to `99-beam.conf`, and reload. |
| `99-beam.conf` with no marker | Host data, or a leftover from an older helper. Move it out of the directory instead of deleting it: `sudo mv 99-beam.conf 99-beam.conf.leftover-$(date -u +%Y%m%d)`. Then reload. |
| Marker and a live file with different bytes | The file was edited after a failed write. The marker no longer matches, so the helper keeps the file. Decide which bytes are correct. Move the other file out, then reload. |
| `10-controld.conf.beam-off` and a live `10-controld.conf` | ctrld was reinstalled or upgraded while connected. Keep the live ctrld file. Move the stale saved copy out, then reload. |
| Restored `10-controld.conf`, then DNS fails | ctrld was removed while connected. The restored file points at `127.0.0.1:5300` with no listener. Move that file out, reload, then connect again: `dns-on` takes the no-ctrld path. |
| A marker or saved file remains after a clean restore | A delete or rename failed. Check ownership and permissions. Run `sudo /usr/local/libexec/beam-helper restore-dns` again. |

Finish with `sudo systemctl reload systemd-resolved` and `resolvectl query
<name>`. Only remove a file after you know what wrote it.

### Removing or upgrading ctrld

ctrld is the resolver in the disconnected state. The helper only moves its
drop-in aside, and it restores that drop-in on disconnect. Do the steps in this
order:

1. Disconnect the tray and wait for `beam-client` to become inactive.
2. Stop the ctrld service.
3. Remove or upgrade ctrld.
4. Move a stale `10-controld.conf.beam-off` out of
   `/etc/systemd/resolved.conf.d/`. Keep the live `10-controld.conf` if ctrld
   is still installed.
5. Reload systemd-resolved and query one name.

A removal or upgrade while connected can leave two ctrld files: the new live
`10-controld.conf` and the saved copy. The helper then reports a conflict on
every attempt and keeps both. Resolve it with the table above. The helper never
deletes a ctrld file that it did not save.

**A removal while connected is not detectable.** `dns-on` moves the ctrld
drop-in aside before the removal. The package then leaves no trace that the
helper can read: the saved copy is byte-identical to a host where ctrld is
still installed. The helper restores the saved copy and names the limit in the
journal:

```
restored /etc/systemd/resolved.conf.d/10-controld.conf without verifying a resolver behind it; if ctrld was removed while connected, DNS stays pointed at a dead address until an operator moves the file out
```

The helper does not start or query the daemon. The unit name, the installation
form, a container, or an on-demand start can differ from what the helper would
check, and a local socket test does not prove that the resolver answers
correctly. A wrong guess could delete the host's own configuration, so the
helper keeps the file and reports the unverified state. Global DNS then points
at `127.0.0.1:5300` with no listener until an operator moves the restored file
out and reloads. The next `dns-on` writes the no-ctrld drop-in that clears the
inherited list before it sets `DNS=1.1.1.1`. That no-ctrld path is tested as a
file operation, not against a live resolver.

Build and install:

```bash
cd clients/linux-tray
./build.sh
sudo env CONFIG_SRC=/path/to/config.json ./install.sh
/usr/local/bin/beam-tray
```

A fresh install needs these inputs. The installer stops with a named error
before it stages, stops, or replaces anything when one is missing:

| Input | Requirement |
|---|---|
| `CONFIG_SRC` | Path to the client profile (sing-box JSON). Required when `/etc/beam/config.json` does not exist; a reinstall reuses that file when `CONFIG_SRC` is unset. It is the client profile, not the server `beam.toml`. |
| `python3` | Normalizes the QUIC policy and validates the normalized profile. |
| `CORE_DIR` | Directory that holds the pinned core. Default `/tmp/beam-core`; it is not a download cache. |
| `$CORE_DIR/sing-box` | Executable core. SHA-256 `1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a`. |
| `$CORE_DIR/libcronet.so` | Shared library next to the core. SHA-256 `23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294`. |
| `$CORE_DIR/LICENSE` | Copied to `/usr/local/lib/beam/LICENSE`; not hash-pinned. |
| `INSTALL_USER` | Desktop user that may run the tray. Taken from `SUDO_USER` when the installer runs under `sudo`; set it explicitly otherwise. |
| `beam-tray`, `beam-helper` | Built in `clients/linux-tray` by `./build.sh`. |
| `systemd-resolved` | Active before the install. The DNS switch writes its drop-ins and reloads this unit. The installer stops with a named error when the unit is not active, because a missing resolver would surface only as a failed `ExecStartPost`. |
| `/etc/systemd/resolved.conf.d`, `/etc/sysctl.d` | Created with mode 0755 when missing. The installer stops with a named error when it cannot create one. |

The two hashes are pinned inside `install.sh` for the core the client has been
checked with. A different core needs a deliberate update of both pins and a new
`sing-box check` run; the installer never downloads or chooses a core. The
sanitized profile structure is in `clients/linux-tray/config.example.json`.

On kernels that expose `tcp_bbr`, the installer enables BBR and the `fq`
default qdisc through `/etc/sysctl.d/99-beam-client-bbr.conf`. This is
sender-side tuning: it improves TCP uploads on lossy/high-RTT paths, while
downloads still follow the remote server's congestion control. The setting is
applied immediately; `default_qdisc` affects interfaces created afterwards,
and BBR falls back to internal per-socket pacing on an existing non-fq qdisc.
The installer warns and continues if the kernel has no BBR. No buffer or
`tcp_notsent_lowat` changes are installed. Remove
`/etc/sysctl.d/99-beam-client-bbr.conf` and `/etc/modules-load.d/beam-bbr.conf`
to revert. The BBR files are written only after the stop guard passes. A unit
that will not stop therefore aborts the install before any BBR file changes. A
failed install still does not re-apply the previous live sysctl values; the
files are restored by the rollback.

The installer copies the core into a private staging directory under
`/usr/local/lib`, verifies the staged copies by SHA-256, normalizes the config,
and runs `sing-box check` with the staged binary before it stops the service or
touches the live core/config. Before that point it also checks that
`systemd-resolved` is active and that its drop-in directory exists, because the
installed unit cannot work without them. If `beam-client` is active, it stops
the unit and requires systemd to report it inactive *before* it replaces any
live file. If the unit does not stop, the installer exits nonzero and leaves
the live core, config, and BBR files unchanged; the staged copies and the
backup are removed. A nonzero `systemctl stop` result while the unit is
inactive is only a warning, because `ExecStopPost` can return nonzero for a DNS
conflict that needs an operator.

If replacement of the live files fails, the managed config, core, helper, tray,
and unit files are restored from the pre-install snapshot; an active service is
started again with the restored configuration. If restoration itself fails, the
installer exits nonzero and keeps the snapshot under
`/usr/local/lib/.beam-backup.*` for recovery. A normal install leaves the
service installed but neither enabled nor started.

DNS changes use `systemctl reload systemd-resolved`, so rapid tray toggles do not
restart the resolver or hit its start limit. The tray also applies a three
second cooldown after each helper action.
The helper only accepts fixed commands, checks that its real user matches
`/etc/beam/allowed-user`, clears its environment, redirects stdio, closes
inherited descriptors, and executes
absolute `systemctl` paths. The TUN profile excludes the VLESS server from the
TUN route, and uses `auto_redirect: true` for TCP.

The helper is local, unsigned, and setuid root; treat the repository and
installer as trusted input. SELinux relabeling is attempted on Fedora, but the
service/helper still need a real TUN/DNS smoke test. Run
`bash tests/linux-tray/test_dns_state.sh` after changing the helper; it tests
the ctrld and no-ctrld paths, same-content host files, every marker/crash state,
the edit conflicts, a failed delete that keeps the marker, a failed marker
delete or restore rename next to a byte-identical host file, and a manual
`restore-dns` followed by `dns-off` in a temporary directory without root. It
also checks the installer's resolver and directory preconditions, the stop
guard before the BBR files, and the unit ordering. It does not test the live
resolver.

## Mobile profile

The canonical Android profile is a mode-0600 file under `$HOME/.config/beam/`,
for example `$HOME/.config/beam/android.json`. It contains the live UUID, the
REALITY keys, and the DoH path (`https://dns.nextdns.io/<PROFILE_ID>`). Do not
commit it.

Each profile pins two resolver addresses instead of resolving the name at run
time: a nearby address (`203.0.113.10`) and an anycast fallback
(`198.51.100.20`). These are documentation addresses. Replace them with current
addresses from the provider and update every client profile together. A
documentation IPv6 address such as `2001:db8::1` must never be configured,
because the mobile profile is IPv4-only.

The repository root holds no live profile. If a device needs a copy in the
repository, place it as `mobile-singbox.json` and confirm that Git ignores it.
The file is ignored by `.gitignore`, but the check is manual.

The profile sets `dns.strategy` to `ipv4_only`, carries no IPv6 TUN address,
omits the IPv6 DoH bootstrap entries, and rejects IPv6 with the first route rule
`{"ip_version": 6, "action": "reject"}`. It uses `stack: system`, MTU 1500,
`auto_route` on, and no generic mux. Like the Linux profile, it rejects UDP/443
before sniffing with `method: default` and `no_drop: true`. H3 fails fast and
the client falls back to HTTP/2; H3 is intentionally unavailable in this
profile. The TCP/REALITY path is unchanged.

The Windows profile is `$HOME/.config/beam/windows.json`. The installer is
`$HOME/.config/beam/beam-install-windows.ps1`.
