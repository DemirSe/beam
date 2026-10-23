# Deployment

This directory contains the local deployment tooling for `beam`. Secrets are
kept outside the repository in `~/.config/beam/` with mode `0600`.

## One-time setup (owner)

1. Reinstall the VPS with Debian 13 and add this SSH public key for `demir`:

   ```bash
   cat ~/.ssh/id_ed25519_netlen_demir.pub
   ```

2. Enable passwordless sudo for `demir` on the new VPS, matching the old
   deployment. The agent uses `sudo -n` over SSH.

3. Update the local full-TUN client. The client config is root-only, so the
   agent cannot do this from its sandbox:

   ```bash
   sudo python3 deploy/update-client.py
   ```

   The script now writes the REALITY identity, sets every TUN inbound to
   `stack: system` with MTU 1400 (the gVisor stack stalls large HTTP/3 bodies),
   restarts `sing-box`, and enables it at boot. If you import the link into
   Hiddify instead, set its TUN stack to `system` manually.

   Install the tray's passwordless unit rule and autostart:

   ```bash
   sudo install -m 0644 deploy/50-sing-box-tray.rules \
     /etc/polkit-1/rules.d/50-sing-box-tray.rules
   install -D -m 0644 deploy/sing-box-tray-autostart.desktop \
     ~/.config/autostart/sing-box-tray.desktop
   ```

   The rule only allows `demir` to manage `sing-box.service`; the tray can then
   start/stop/restart without a password prompt. The autostart launches the
   existing `Xray Tray (sing-box)` at login.

4. If the VPS IP changed, update `~/.config/beam/client-identity.json`
   (`server`), regenerate `client-outbound.json`/`client-link.txt`, and re-run
   `update-client.py`. The server config binds `0.0.0.0:443`, so it does not
   need the IP.

After these steps, the agent can package, deploy, and test without further
approval.

## Agent flow

```bash
bash deploy/package.sh
scp -i ~/.ssh/id_ed25519_netlen_demir \
  /tmp/opencode/beam-deploy-*/beam-deploy.tar.gz \
  demir@<server>:/tmp/
ssh -i ~/.ssh/id_ed25519_netlen_demir demir@<server> \
  'mkdir -p /tmp/beam-deploy && tar -xzf /tmp/beam-deploy.tar.gz -C /tmp/beam-deploy && sudo bash /tmp/beam-deploy/bootstrap.sh'
```

`bootstrap.sh` stops/disables `xray.service` and `xray-compare.service`, creates
the `beam` user, installs the binary/config/unit, installs the UDP sysctl
drop-in, validates the config as `beam`, restarts the service (so an active
process picks up the new binary/unit), and checks that 443 is listening. Old
binary, config, unit, and sysctl files are backed up with a timestamp suffix.
The unit also sets `MemoryHigh=512M`, `MemoryMax=768M`, and
`MemorySwapMax=512M`; the code caps unauthenticated cover relays at 32 and
process-wide XUDP sessions at 256. See `docs/17-resource-hardening.md`.

## Identity

The new identity was generated locally. The REALITY public key and client
fields are in `~/.config/beam/client-identity.json`; the private key is in
`~/.config/beam/beam.toml` (`0600`). Do not commit either file. The old client
credentials no longer work after this rotation; update the client as above.

## Host hardening

The live host was hardened on 2026-10-22. Reproduce on a fresh Debian 13 host
after `demir` key access and passwordless sudo work, and keep the provider
console available:

```bash
# SSH: key-only demir, no root/debian access.
sudo install -m 0644 deploy/sshd-60-hardening.conf /etc/ssh/sshd_config.d/60-hardening.conf
sudo sshd -t && sudo systemctl reload ssh
sudo rm -f /root/.ssh/authorized_keys /home/debian/.ssh/authorized_keys
sudo usermod -L -s /usr/sbin/nologin debian
sudo rm -f /etc/sudoers.d/90-cloud-init-users

# Host firewall: validate before enabling.
sudo apt-get install -y nftables
sudo install -m 0644 deploy/nftables.conf /etc/nftables.conf
sudo nft -c -f /etc/nftables.conf && sudo systemctl enable --now nftables

# Encrypted resolver; verify DNS and cover forwarding.
sudo install -d -m 0755 /etc/systemd/resolved.conf.d
sudo install -m 0644 deploy/resolved-99-beam.conf /etc/systemd/resolved.conf.d/99-beam.conf
sudo systemctl restart systemd-resolved
resolvectl query example.com
```

`bootstrap.sh` installs `99-beam.conf` under `/etc/sysctl.d/` and runs
`sysctl --system`. The SSH/firewall/resolver files are intentionally not
installed by `bootstrap.sh`: a mistake there can lock out the host.

## Rollback

- Binary: `/usr/local/bin/beam.bak-<stamp>`
- Config: `/etc/beam/config.toml.bak-<stamp>`
- Unit: `/etc/systemd/system/beam.service.bak-<stamp>`
- To go back to stock Xray, keep the stock binary/config on the host before
  removing it, or reinstall it deliberately. `bootstrap.sh` disables the old
  services so they cannot race for 443.

## Verification

```bash
systemctl status --no-pager -l beam
ss -ltnp | grep ':443 '
journalctl -u beam -n 50 --no-pager
```

Then run the local client matrix (TCP, UDP, DNS, QUIC, HTTPS Direct, IPv6) and
a fresh SSH/443 check. The live host has a 5-minute post-hardening soak, the
6.12.113 kernel reboot, and a light 24-hour background soak; large-H3 client-TUN
validation and privileged quiet acceptance remain open.
