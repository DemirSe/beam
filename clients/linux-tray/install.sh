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
[ -r "$HERE/99-beam-client-bbr.conf" ] || { echo "missing $HERE/99-beam-client-bbr.conf" >&2; exit 1; }

CORE_SING_SHA=1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a
CORE_LIB_SHA=23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294

install -d -m 0755 /usr/local/lib /usr/local/libexec /etc/beam
STAGE_DIR=
NORMALIZED_CONFIG=
BACKUP_DIR=
BACKUP_READY=0
INSTALL_COMMITTED=0
SERVICE_WAS_ACTIVE=0
DNS_RESET_ENABLED=0
MANAGED_PATHS=(
    /etc/beam/config.json
    /etc/beam/allowed-user
    /usr/local/lib/beam/sing-box
    /usr/local/lib/beam/libcronet.so
    /usr/local/lib/beam/LICENSE
    /usr/local/libexec/beam-helper
    /usr/local/bin/beam-tray
    /etc/systemd/system/beam-client.service
    /etc/systemd/system/beam-dns-reset.service
    /etc/systemd/system/multi-user.target.wants/beam-dns-reset.service
    /etc/sysctl.d/99-beam-client-bbr.conf
    /etc/modules-load.d/beam-bbr.conf
    /usr/share/applications/beam-tray.desktop
)

backup_live() {
    local src dest
    for src in "${MANAGED_PATHS[@]}"; do
        if [ -e "$src" ] || [ -L "$src" ]; then
            dest="$BACKUP_DIR$src"
            install -d -m 0755 "$(dirname "$dest")"
            cp -a "$src" "$dest"
        fi
    done
}

rollback_live() {
    local path failed=0
    for path in "${MANAGED_PATHS[@]}"; do
        if [ -e "$BACKUP_DIR$path" ] || [ -L "$BACKUP_DIR$path" ]; then
            if ! cp -a "$BACKUP_DIR$path" "$path"; then
                echo "installer: could not restore $path" >&2
                failed=1
            fi
        elif ! rm -f "$path"; then
            echo "installer: could not remove $path" >&2
            failed=1
        fi
    done
    systemctl daemon-reload 2>/dev/null || true
    if [ "$DNS_RESET_ENABLED" = "1" ]; then
        if ! systemctl enable beam-dns-reset.service >/dev/null 2>&1; then
            echo "installer: could not restore beam-dns-reset enablement" >&2
            failed=1
        fi
    else
        systemctl disable beam-dns-reset.service >/dev/null 2>&1 || true
    fi
    if [ "$failed" = "0" ] && [ "$SERVICE_WAS_ACTIVE" = "1" ]; then
        if ! systemctl start beam-client 2>/dev/null; then
            echo "installer: could not restart beam-client after rollback" >&2
            failed=1
        fi
    fi
    return "$failed"
}

cleanup() {
    local status=$? keep_backup=0
    if [ "$BACKUP_READY" = "1" ] && [ "$INSTALL_COMMITTED" = "0" ]; then
        if ! rollback_live; then
            keep_backup=1
            status=1
            printf 'installer: rollback incomplete; backup kept at %s\n' "$BACKUP_DIR" >&2
        fi
    fi
    if [ -n "$STAGE_DIR" ]; then
        rm -rf "$STAGE_DIR"
    fi
    if [ -n "$NORMALIZED_CONFIG" ]; then
        rm -f "$NORMALIZED_CONFIG"
    fi
    if [ "$keep_backup" = "0" ] && [ -n "$BACKUP_DIR" ]; then
        rm -rf "$BACKUP_DIR"
    fi
    return "$status"
}
trap cleanup EXIT

STAGE_DIR=$(mktemp -d /usr/local/lib/.beam-stage.XXXXXX)
NORMALIZED_CONFIG=$(mktemp)
chmod 0600 "$NORMALIZED_CONFIG"

# Copy into a private staging directory, then hash and validate the copies.
# The live core and config are touched only after every check passes.
install -m 0755 "$CORE_DIR/sing-box" "$STAGE_DIR/sing-box"
install -m 0644 "$CORE_DIR/libcronet.so" "$STAGE_DIR/libcronet.so"
install -m 0644 "$CORE_DIR/LICENSE" "$STAGE_DIR/LICENSE"

actual_sing=$(sha256sum "$STAGE_DIR/sing-box" | awk '{print $1}')
actual_lib=$(sha256sum "$STAGE_DIR/libcronet.so" | awk '{print $1}')
[ "$actual_sing" = "$CORE_SING_SHA" ] || { echo "core sing-box hash mismatch" >&2; exit 1; }
[ "$actual_lib" = "$CORE_LIB_SHA" ] || { echo "core libcronet hash mismatch" >&2; exit 1; }

python3 "$HERE/config-policy.py" "$CONFIG_SRC" "$NORMALIZED_CONFIG"
"$STAGE_DIR/sing-box" check -c "$NORMALIZED_CONFIG"

BACKUP_DIR=$(mktemp -d /usr/local/lib/.beam-backup.XXXXXX)
backup_live
BACKUP_READY=1
if systemctl is-enabled --quiet beam-dns-reset.service 2>/dev/null; then
    DNS_RESET_ENABLED=1
fi

# BBR is sender-side: it helps TCP uploads on lossy/high-RTT links, not
# downloads. Enable it only when this kernel actually exposes the algorithm.
# Keep the install usable on old kernels without BBR.
if command -v modprobe >/dev/null 2>&1; then
    modprobe tcp_bbr 2>/dev/null || true
fi
if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    install -m 0644 "$HERE/99-beam-client-bbr.conf" /etc/sysctl.d/99-beam-client-bbr.conf
    sysctl -p /etc/sysctl.d/99-beam-client-bbr.conf >/dev/null 2>&1 || true
    if [ "$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null)" = bbr ]; then
        echo "enabled: bbr congestion control and fq default qdisc"
    else
        echo "warning: BBR is available but did not become the live default" >&2
    fi
    if command -v modinfo >/dev/null 2>&1 && modinfo tcp_bbr >/dev/null 2>&1; then
        install -d -m 0755 /etc/modules-load.d
        {
            printf 'tcp_bbr\n'
            if modinfo sch_fq >/dev/null 2>&1; then
                printf 'sch_fq\n'
            fi
        } > /etc/modules-load.d/beam-bbr.conf
        chmod 0644 /etc/modules-load.d/beam-bbr.conf
    fi
else
    rm -f /etc/sysctl.d/99-beam-client-bbr.conf
    echo "warning: kernel does not expose tcp_bbr; BBR/fq not enabled" >&2
fi

if systemctl is-active --quiet beam-client 2>/dev/null; then
    SERVICE_WAS_ACTIVE=1
fi

systemctl stop beam-client 2>/dev/null || true
if [ -f /etc/beam/config.json ]; then
    cp -a /etc/beam/config.json "/etc/beam/config.json.bak-$(date -u +%Y%m%dT%H%M%S%NZ)"
fi
install -m 0600 "$NORMALIZED_CONFIG" /etc/beam/config.json
printf '%s\n' "$INSTALL_USER" > /etc/beam/allowed-user
chmod 0644 /etc/beam/allowed-user

install -d -m 0755 /usr/local/lib/beam
mv -f "$STAGE_DIR/sing-box" /usr/local/lib/beam/sing-box
mv -f "$STAGE_DIR/libcronet.so" /usr/local/lib/beam/libcronet.so
mv -f "$STAGE_DIR/LICENSE" /usr/local/lib/beam/LICENSE
rm -rf "$STAGE_DIR"
STAGE_DIR=

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
ConditionPathExists=/etc/systemd/resolved.conf.d/10-controld.conf.beam-off

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
INSTALL_COMMITTED=1
update-desktop-database /usr/share/applications >/dev/null 2>&1 || true

echo "installed; service is not enabled or started"
echo "launch: /usr/local/bin/beam-tray"
