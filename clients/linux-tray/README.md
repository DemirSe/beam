# Linux tray client

`clients/linux-tray/` builds a GTK tray and a root helper. The tray calls the helper for `up` and `down`. The helper handles DNS.

## Build

Dependencies: a C11 compiler (`CC` or `gcc`), AppIndicator 3, GTK 3, GObject 2,
and GLib 2. Python 3 is needed at install time for `config-policy.py`.

From this directory, run `./build.sh`.
The output is `beam-tray` and `beam-helper` in this directory.

## Install

`./install.sh` needs root. Run it with sudo from the desktop user, or set
`INSTALL_USER`. It checks these inputs before it changes live files:

- `CONFIG_SRC`: client profile. Default: `/etc/beam/config.json`.
- `CORE_DIR`: pinned core directory. Default: `/tmp/beam-core`.
  It must hold `sing-box`, `libcronet.so`, and `LICENSE`.
  Two SHA-256 hashes are checked. The script does not download the core.
- An active `systemd-resolved` unit and `systemctl`.

The script runs `config-policy.py` and checks the config with `sing-box check`.
It stages files under `/usr/local/lib` and backs up managed paths.
It stops `beam-client` before it installs new files.
It leaves the service stopped and disabled. Failed installs restore the backups.

## DNS switch

`dns-on` runs from `ExecStartPost` of `beam-client.service`. It moves the ctrld drop-in aside and saves a host `99-beam.conf`.
It writes a `99-beam.conf` drop-in with `DNS=1.1.1.1` and `Domains=~.`, then reloads systemd-resolved.
`dns-off` runs from `ExecStopPost`. It restores the saved files and reloads the resolver.
`beam-dns-reset.service` runs `restore-dns` at boot.

## Recover from a bad DNS state

Run `/usr/local/libexec/beam-helper restore-dns` by hand.
The helper marks the live files that it writes.
It keeps an unmarked file and reports it for manual inspection.
