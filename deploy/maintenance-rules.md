# Beam host maintenance rules

This file is the operating contract for the production host. Read it before you
change anything. It is short on purpose.

## Before any change

1. Run `deploy/verify-production.sh` from the repository and keep the result.
2. If the change touches the service, the firewall, the SSH configuration, the
   time sources, or the kernel, run the verifier again after the change.
3. If a check fails, revert first. Do not stack a second change on a failed
   check.

## Updates

4. Updates are manual. The host has no automatic update service
   (`dnf-automatic` is not installed) and no automatic restart. Do not add
   either one.
5. After a kernel or package update, run the verifier again. A new kernel can
   change the TCP defaults that BBR, fq, and the conntrack limits depend on.
6. After each update, run `dnf clean all`. The package cache has no automatic
   cap.

## Platform

The host runs AlmaLinux 10, not Debian. These names differ from older notes:

- SSH is `sshd.service`, not `ssh.service`. Apply a change with
  `sudo sshd -t && sudo systemctl reload sshd`.
- Time is `chronyd.service`, configured by `/etc/chrony.conf` and
  `/etc/sysconfig/chronyd`. The sysconfig file carries `OPTIONS="-F 2 -4"` so the
  daemon keeps every socket on IPv4.
- Packages come from dnf. `fail2ban` and its SELinux policy come from EPEL.
- SELinux is enforcing. Never set it permissive to work around a denial. Read
  the denial and fix the label or the policy.
- The firewall is nftables from `/etc/nftables.conf`; `nftables.service` loads
  it through `/etc/sysconfig/nftables.conf`. `firewalld` is masked and stays
  masked, because two managers flush each other's tables.
- sshd reads drop-ins in name order and keeps the first value it reads. The
  beam policy is `/etc/ssh/sshd_config.d/00-beam-hardening.conf`, ahead of the
  installer's `01-permitrootlogin.conf` and `50-redhat.conf`.
- The SSH host keys are the restored production keys. The ED25519 fingerprint
  is `<SSH_HOST_KEY_FINGERPRINT>`.
- DNS is `systemd-resolved` on `127.0.0.53` with DNS-over-TLS; NetworkManager
  hands DNS to it and does not write `/etc/resolv.conf`. After a network or
  resolver change, run `sudo nmcli device reapply <iface>`, or restart
  NetworkManager from the provider console.
- `/etc/host-rules.md` is a symlink to this file. `/etc/beam` is mode 0751
  `root:beam`: other users can traverse it but cannot list it. The config
  itself stays mode 0640, so other users cannot read it.
- On the production host, the named DoT servers in
  `/etc/systemd/resolved.conf.d/99-beam.conf` are the only resolvers.
  The active NetworkManager connection must not supply per-link DNS servers.

## Invariants that must not change

7. IPv6 stays disabled on the host, and the verifier must report zero IPv6
   addresses, routes, and listeners.
8. SSH stays on the configured port (`${SSH_PORT:-22}` by default) with key
   authentication only, no root login, and no password login.
9. The input firewall keeps the default `drop` policy. Only the SSH port
   (`${SSH_PORT:-22}` by default) and port 443 answer.
10. `/etc/beam/config.toml` stays mode 640 owned by `root:beam`. Never copy its
    contents to a log, a chat, a report, or the repository.

## Time

11. REALITY rejects a handshake whose timestamp is more than 300 seconds from
    the server clock. When authentication fails without an obvious cause, check
    `chronyc tracking` first.
12. Keep at least three time sources agreeing. `minsources 3` enforces this. If
    a source stops answering for a long time, replace it with another explicit
    server. Do not add a pool.
13. None of the time sources may smear leap seconds. Google, Amazon, and Meta
    do. Do not add them.

## Cover target

14. The REALITY cover target is `whatsapp.net`. Once a month, check that the
    certificate the host serves for that name matches the real certificate of
    the site. A mismatch means the cover path no longer works, even if the
    tunnel still does.
15. Do not change the cover target without a decision from the owner. A new
    target changes the client profile as well.

## Checks when you connect

Run these checks when you connect to the host. A calendar is not needed, and no
check is mandatory on a fixed date. Each check takes a few seconds.

16. After every reboot, read `journalctl -u beam-post-boot-check | grep
    post-boot`. The last line is `post-boot: PASS` or `post-boot: FAIL`. Treat a
    FAIL as urgent.
17. Compare the hashes of these files with the recorded values:
    `/etc/beam/config.toml`, `/etc/nftables.conf`, `/etc/ssh/sshd_config.d/*`,
    `/etc/chrony.conf`, `/etc/systemd/system/beam.service`, and
    `/etc/ssh/sshrc`. A difference the owner did not make is drift.
18. Read `steal` in `/proc/stat` and the drop column in
    `/proc/net/softnet_stat`. Both are zero at handover. A rise in `steal`
    means the hypervisor gives less CPU. A rise in drops means the receive
    queue overflows.
19. Run `journalctl -k -p err --no-pager` and look for XFS, LVM, or I/O
    errors. A filesystem that remounts read-only leaves the service running but
    unable to write.
20. Re-measure the two settings that stay at their defaults because no evidence
    supported a change: `tcp_slow_start_after_idle` and
    `net.core.netdev_max_backlog`. Use the same method as the first
    measurement. Do this once a year, not on every visit.

## Self recovery

21. The unit runs with `Restart=always`. The restart delay grows from 3 s to
    60 s in four steps, then holds at one attempt per minute. A crash recovers
    without an operator, and a persistent failure retries slowly instead of in
    a hot loop. The backoff keys need systemd 254 or later; AlmaLinux 10 has
    257. The start limit of 10 starts in 300 seconds counts every start, manual
    or automatic. The backoff keeps an automatic crash loop below that window,
    so the limit mainly catches repeated manual restarts. Clear that state with
    `sudo systemctl reset-failed beam`. A manual stop stays stopped until the
    timer is stopped too; rule 23 covers that case.
22. `beam-liveness.timer` checks the listener and the cover name from
    `/etc/beam/config.toml` every five minutes with a full TLS handshake. After
    three failures in a row, that is 15 minutes, it restarts
    the service. The counter resets on success. A failure that comes from the
    cover side is logged as `SKIP` and resets the counter instead: beam
    answered, so only the cover path is down and a restart would drop live
    sessions. A config the probe cannot read is logged as `FAIL no usable
    probe target` and never restarts beam. A restart that fails is logged as
    `restart FAILED`, fails the unit, and is retried by the next run.
23. If you stop the service on purpose, stop the timer too. Otherwise the timer
    restarts the service after 15 minutes.

## Diagnostics

24. Crash dumps are discarded on purpose. Use the journals.
25. `journalctl -u beam`, `chronyc tracking`, `fail2ban-client status sshd`, and
    `nft list table inet filter` answer most questions.
26. `fail2ban` bans an address for one hour, and the time does not increase.
    A ladder would land on a shared carrier-grade NAT address and lock the
    owner out. `dbpurgeage` is 30 days, so the failure history outlives a ban.
27. SSH limits unfinished handshakes with `MaxStartups 10:30:30`. Do not raise
    it without a measurement.
28. `/etc/systemd/journald.conf.d/99-beam.conf` sets `Storage=persistent` and
    caps the journal at 256M with `SystemMaxUse=256M`. The journal now survives
    a reboot, so use it to inspect events before the last restart.

## Where the details live

- `README.md` in the repository: deployment, verification, and every invariant
  in full.
- `docs/TODO.md` in the repository: what is still open.
- `deploy/` in the repository: the exact files installed on this host.
