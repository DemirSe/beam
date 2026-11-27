# Client setup

Any standard Xray or sing-box client that speaks VLESS with `xtls-rprx-vision`
works against beam. That is the supported path, and the TUN interop workflow
proves it end to end against pinned sing-box and Xray.

The tray clients in `clients/` are our own convenience wrapper around a stock
sing-box core. They are optional, and the sections below that describe them do
not apply if you already use a standard client.

The server runbook is in [`DEPLOY.md`](DEPLOY.md).

## Linux tray and DNS switch

This section documents the sing-box tray install. That install writes its own
`/etc/systemd/system/beam-client.service` with `/usr/local/lib/beam/sing-box`
and a `sbtun0` interface. Do not combine it with the native `beam-client` unit
([`deploy/beam-client.service`](../deploy/beam-client.service)), which is
installed to the same `/etc/systemd/system/beam-client.service` path, runs
`/usr/local/bin/beam-client` on `beamtun0`, and uses per-link DNS instead of
`99-beam.conf`. See
[`clients/linux-tray/README.md`](../clients/linux-tray/README.md) for the
install-path comparison.

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

The native Android client (`crates/beam-android` + `clients/android`, `:vpn`
process isolation, Keystore storage, and `VpnService` wiring) is documented in
[`clients/android/README.md`](../clients/android/README.md).

The Windows profile is `$HOME/.config/beam/windows.json`. The installer is
`$HOME/.config/beam/beam-install-windows.ps1`.

## beam-client diagnostics

`beam-client --check` prints the validated TUN and server policy, then one DNS
summary line: upstream kind and target, the detected or configured
`local_upstream`, `cache_size`, `ipv4_only`, and the configured suffix counts.
The DoH target shows the host and port only. The client omits the path because
it can contain a provider profile ID or token.

The client publishes `/run/beam-client/status` as `key=value` lines for
`beam-tray`: `state`, `ifname`, `ts`, `pid`, `rtt_ms`, `reason`, `generation`,
`bypass_ok`, `dial_failures`, and, when non-zero, `drops`. DNS outcome counters
stay internal/API-level and are not published in the status file. The tray ignores keys
it does not know, so this list can grow without breaking an older tray. A
`reason` of `dial_failures` means authenticated upstream dials keep failing, so
a bare TCP connect to the server no longer reports the link as connected. The
client reports this state while a new dial failure is no more than 20 s old, and
only after three consecutive failures. A gap of more than 30 s between failures
starts a new failure count.

The tray turns these keys into a degraded warning. `health.rs` emits
`state=connected`, `state=reconnecting` (with `reason=dial_failures` while
fresh authenticated dial failures degrade the link), or
`state=waiting_network`; it never emits `state=degraded`. The tray shows green
`Beam: connected` (with RTT when reported) only for `state=connected` with
`bypass_ok != 0`. It shows a degraded warning for `state=connected` with
`bypass_ok=0` (`Beam: degraded (bypass missing)`), for `state=reconnecting`
with `reason=dial_failures` (`Beam: degraded (dial failures)`, combined with
the bypass text when both apply), and plain `Beam: reconnecting...` or
`Beam: waiting for network...` otherwise. The `dial_failures` count is a
lifetime counter, so the tray matches on `reason`, not on the count. The tray
returns to green `Beam: connected` automatically once the status file reports
healthy again.

The `drops` value holds `key:value` pairs. The keys are `tun_tx_full`,
`ip_parse`, `frag`, `route`, `tcp_limit`, `tcp_rx_ovf`, `udp_mux_q`,
`udp_sess_q`, `udp_pending`, `udp_payload`, and `udp_sess_tbl`. `tcp_limit`
counts new TCP flows that the client resets when it reaches
`max_tcp_connections`. These resets are not `route` drops. `tcp_rx_ovf` counts
TCP packets dropped because the stack RX queue was full, and `udp_mux_q`
counts UDP frames dropped by a full XUDP mux queue (outbound or inbound).
