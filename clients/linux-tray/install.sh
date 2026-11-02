#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
CORE_DIR="${CORE_DIR:-/tmp/beam-core}"
CONFIG_SRC="${CONFIG_SRC:-}"
INSTALL_USER="${INSTALL_USER:-${SUDO_USER:-}}"
if [ -z "$INSTALL_USER" ] || [ "$INSTALL_USER" = root ]; then
    echo "run via sudo from the desktop user, or set INSTALL_USER=<name>" >&2
    exit 1
fi

if [ -z "$CONFIG_SRC" ]; then
    if [ -f /etc/beam/config.json ]; then
        CONFIG_SRC=/etc/beam/config.json
    else
        echo "set CONFIG_SRC to the client profile; refusing to guess /tmp" >&2
        exit 1
    fi
fi
[ -r "$CONFIG_SRC" ] || { echo "missing or unreadable $CONFIG_SRC" >&2; exit 1; }
[ -f "$HERE/config-policy.py" ] || { echo "missing $HERE/config-policy.py" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required to normalize the client policy" >&2; exit 1; }

[ -x "$CORE_DIR/sing-box" ] || { echo "missing $CORE_DIR/sing-box" >&2; exit 1; }
[ -x "$HERE/beam-tray" ] || { echo "build first: $HERE/build.sh" >&2; exit 1; }
[ -x "$HERE/beam-helper" ] || { echo "build first: $HERE/build.sh" >&2; exit 1; }

CORE_SING_SHA=1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a
CORE_LIB_SHA=23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294
actual_sing=$(sha256sum "$CORE_DIR/sing-box" | awk '{print $1}')
actual_lib=$(sha256sum "$CORE_DIR/libcronet.so" | awk '{print $1}')
[ "$actual_sing" = "$CORE_SING_SHA" ] || { echo "core sing-box hash mismatch" >&2; exit 1; }
[ "$actual_lib" = "$CORE_LIB_SHA" ] || { echo "core libcronet hash mismatch" >&2; exit 1; }

install -d -m 0755 /usr/local/lib/beam /usr/local/libexec /etc/beam
install -m 0755 "$CORE_DIR/sing-box" /usr/local/lib/beam/sing-box
install -m 0644 "$CORE_DIR/libcronet.so" /usr/local/lib/beam/libcronet.so
install -m 0644 "$CORE_DIR/LICENSE" /usr/local/lib/beam/LICENSE

NORMALIZED_CONFIG=$(mktemp)
trap 'rm -f "$NORMALIZED_CONFIG"' EXIT
chmod 0600 "$NORMALIZED_CONFIG"
python3 "$HERE/config-policy.py" "$CONFIG_SRC" "$NORMALIZED_CONFIG"
/usr/local/lib/beam/sing-box check -c "$NORMALIZED_CONFIG"

systemctl stop beam-client 2>/dev/null || true
if [ -f /etc/beam/config.json ]; then
    cp -a /etc/beam/config.json "/etc/beam/config.json.bak-$(date -u +%Y%m%dT%H%M%S%NZ)"
fi
install -m 0600 "$NORMALIZED_CONFIG" /etc/beam/config.json
printf '%s\n' "$INSTALL_USER" > /etc/beam/allowed-user
chmod 0644 /etc/beam/allowed-user

install -m 0755 "$HERE/beam-helper" /usr/local/libexec/beam-helper
chown root:root /usr/local/libexec/beam-helper
chmod 4755 /usr/local/libexec/beam-helper
install -m 0755 "$HERE/beam-tray" /usr/local/bin/beam-tray

cat > /etc/systemd/system/beam-client.service <<'EOF'
[Unit]
Description=beam client (sing-box VLESS/REALITY TUN)
After=network-online.target nss-lookup.target
Wants=network-online.target
# The tray may toggle quickly; do not make a transient stop/start permanent.
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/lib/beam/sing-box run -c /etc/beam/config.json
ExecStartPost=/usr/local/libexec/beam-helper dns-on
ExecStopPost=/usr/local/libexec/beam-helper dns-off
Restart=no
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/beam-client.service

cat > /etc/systemd/system/beam-dns-reset.service <<'EOF'
[Unit]
Description=Restore ctrld DNS after a beam client reboot
After=systemd-resolved.service ctrld.service
Wants=ctrld.service
ConditionPathExists=/etc/systemd/resolved.conf.d/99-beam.conf

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/beam-helper restore-dns

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/beam-dns-reset.service
systemctl daemon-reload
systemctl enable beam-dns-reset.service

if command -v restorecon >/dev/null 2>&1; then
    restorecon -RFv /usr/local/lib/beam /usr/local/libexec /usr/local/bin/beam-tray         /etc/beam /etc/systemd/system/beam-client.service         /etc/systemd/system/beam-dns-reset.service         /usr/share/applications/beam-tray.desktop >/dev/null 2>&1 || true
    chcon -t bin_t /usr/local/lib/beam/sing-box /usr/local/libexec/beam-helper         /usr/local/bin/beam-tray 2>/dev/null || true
    chcon -t lib_t /usr/local/lib/beam/libcronet.so 2>/dev/null || true
fi

install -d -m 0755 /usr/share/applications
cat > /usr/share/applications/beam-tray.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=Beam Tray
GenericName=Beam tunnel control
Comment=Connect or disconnect the beam TUN tunnel
Exec=/usr/local/bin/beam-tray
Icon=network-vpn
Terminal=false
Categories=Network;
StartupNotify=false
EOF
chmod 0644 /usr/share/applications/beam-tray.desktop
update-desktop-database /usr/share/applications >/dev/null 2>&1 || true

echo "installed; service is not enabled or started"
echo "launch: /usr/local/bin/beam-tray"
