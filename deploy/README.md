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
   agent cannot do this from its sandbox. Choose one:

   ```bash
   sudo python3 deploy/update-client.py
   ```

   or import the link in `~/.config/beam/client-link.txt` into Hiddify.

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
the `beam` user, installs the binary/config/unit, validates the config as
`beam`, starts the service, and checks that 443 is listening. Old binary,
config, and unit are backed up with a timestamp suffix.

## Identity

The new identity was generated locally. The REALITY public key and client
fields are in `~/.config/beam/client-identity.json`; the private key is in
`~/.config/beam/beam.toml` (`0600`). Do not commit either file. The old client
credentials no longer work after this rotation; update the client as above.

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
the 24-hour soak/churn acceptance run before treating the cutover as final.
