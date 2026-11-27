# Linux tray client

`clients/linux-tray/` builds a GTK tray and a root helper. The tray calls the helper for `up` and `down`. The helper handles DNS.

## Build

Dependencies: a C11 compiler (`CC` or `gcc`), AppIndicator 3, GTK 3, GObject 2,
and GLib 2. Python 3 is needed at install time for `config-policy.py`.

From this directory, run `./build.sh`.
The output is `beam-tray` and `beam-helper` in this directory.

## Install

`./install.sh` needs root. Run it with sudo from the desktop user, or set
`INSTALL_USER`. The user name must resolve on the host and must not have uid 0.
The installer checks these inputs before it changes live files:

- `CONFIG_SRC`: client profile. Default: `/etc/beam/config.json`.
- `CORE_DIR`: pinned core directory. Default: `/tmp/beam-core`.
  It must hold `sing-box`, `libcronet.so`, and `LICENSE`.
  It must not be a symlink. Root must own it.
  Group and other users must not be able to write to it.
  `LICENSE` must be a root-owned regular file, not a symlink.
  Two SHA-256 hashes are checked. The script does not download the core.
- An active `systemd-resolved` unit and `systemctl`.

The script runs `config-policy.py` and checks the config with `sing-box check`.
It stages files under `/usr/local/lib` and backs up managed paths.
It stops `beam-client` before it installs new files.
It keeps one mode-0600 timestamped copy before it installs the profile. After
the install succeeds, it keeps the three newest generated copies. It does not
prune other backup files. It leaves the service stopped and disabled. It disables an inherited unit so
the new unit cannot start at boot. Failed installs restore the backups. They
restore only `enabled` and `enabled-runtime` state. The installer refuses a
masked unit before it writes any unit file.

## Native `beam-client` or this install: choose one

Two install paths exist in this repository. They are not compatible on one
host, because both write the same unit name. Do not mix them.

| | Native (recommended) | This tray install (sing-box) |
|---|---|---|
| Unit | `deploy/beam-client.service` | `/etc/systemd/system/beam-client.service` written by `install.sh` |
| Program | `/usr/local/bin/beam-client` | `/usr/local/lib/beam/sing-box` |
| TUN interface | `beamtun0` | `sbtun0` |
| DNS switch | per-link `resolvectl dns` and `resolvectl domain` on the TUN | global `99-beam.conf` drop-in written by `beam-helper` |
| DNS cleanup | kernel drops the link while the unit stops | `beam-helper dns-off`, `restore-dns`, `beam-dns-reset.service` |

`install.sh` replaces `/etc/systemd/system/beam-client.service`. A host that
still runs the native unit therefore loses that unit definition. Its per-link
DNS settings stay behind, while the new start path writes a global drop-in.

Switch in this order:

1. Stop the running unit.
2. Remove the unit file of the old install and remove its DNS state.
3. Install the other path.
4. Reload systemd, then start the unit.

`beam-helper` and its `99-beam.conf` handling belong to the sing-box path only.
The native unit does not call the helper and does not write `99-beam.conf`.
The native unit uses per-link DNS on `beamtun0` when the built-in DNS
interceptor is enabled.

See [`docs/CLIENT.md`](../../docs/CLIENT.md#linux-tray-and-dns-switch) for the
sing-box DNS behaviour and recovery steps.

## DNS switch

`dns-on` runs from `ExecStartPost` of `beam-client.service`. It moves the ctrld drop-in aside and saves a host `99-beam.conf`.
It writes a `99-beam.conf` drop-in with `DNS=1.1.1.1` and `Domains=~.`, then reloads systemd-resolved.
`dns-off` runs from `ExecStopPost`. It restores the saved files and reloads the resolver.
`beam-dns-reset.service` runs `restore-dns` at boot.
The reset unit orders after ctrld but does not start it.

## Recover from a bad DNS state

Run `/usr/local/libexec/beam-helper restore-dns` by hand.
The helper marks the live files that it writes.
It keeps an unmarked file and reports it for manual inspection.
If `dns-on`, `dns-off`, or `ctrld-off` logs `could not reload systemd-resolved`,
the helper writes `99-beam.conf.beam-reload`. The boot reset retries the reload
for that file. A later successful switch clears the trigger. To fix it now,
run `sudo systemctl reload systemd-resolved`, then run
`sudo /usr/local/libexec/beam-helper restore-dns` to clear the trigger.
