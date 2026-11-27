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

# The helper compares allowed-user with the invoking name, so a typo or a
# numeric uid would install cleanly and leave the tray unable to call it.
# Keep the raw input for errors and reject any account with uid 0.
resolve_install_user() {
    local raw="$1" name uid
    name=$(id -nu -- "$raw" 2>/dev/null) || {
        echo "INSTALL_USER=$raw does not resolve to a user" >&2
        return 1
    }
    if [ -z "$name" ]; then
        echo "INSTALL_USER=$raw does not resolve to a user" >&2
        return 1
    fi
    if [ "$name" = root ]; then
        echo "INSTALL_USER must be the desktop user, not root" >&2
        return 1
    fi
    uid=$(id -u -- "$name" 2>/dev/null) || {
        echo "INSTALL_USER=$raw does not resolve to a uid" >&2
        return 1
    }
    if [ "$uid" = 0 ]; then
        echo "INSTALL_USER=$raw resolves to uid 0; use the desktop user" >&2
        return 1
    fi
    printf '%s\n' "$name"
}

if [ -z "$INSTALL_USER" ] || [ "$INSTALL_USER" = root ]; then
    echo "run via sudo from the desktop user, or set INSTALL_USER=<name>" >&2
    exit 1
fi
INSTALL_USER=$(resolve_install_user "$INSTALL_USER") || exit 1

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

STAGE_DIR=
NORMALIZED_CONFIG=
BACKUP_DIR=
BACKUP_READY=0
INSTALL_COMMITTED=0
SERVICE_WAS_ACTIVE=0
DNS_RESET_STATE=
CLIENT_STATE=
CONFIG_BAK_KEEP=3

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

# An untrusted core tree can hold genuine pinned binaries plus a LICENSE
# symlink to a secret. Resolve no symlink and accept only a root-owned,
# non-writable directory and a root-owned regular LICENSE. Every ancestor
# must also be safe: a writable parent can replace the directory after it is
# checked.
validate_core_dir() {
    local dir="$1" owner perms part prefix
    local IFS=/

    check_component() {
        local path="$1"
        if [ -L "$path" ]; then
            echo "CORE_DIR must not be a symlink: $path" >&2
            return 1
        fi
        if [ ! -d "$path" ]; then
            echo "CORE_DIR is not a directory: $path" >&2
            return 1
        fi
        owner=$(stat -c %u -- "$path") || return 1
        if [ "$owner" != 0 ]; then
            echo "CORE_DIR must be owned by root: $path" >&2
            return 1
        fi
        perms=$(stat -c %A -- "$path") || return 1
        case "${perms:5:1}${perms:8:1}" in
            *w*)
                echo "CORE_DIR must not be group or world writable: $path" >&2
                return 1
                ;;
        esac
    }

    # A trailing slash makes -L follow the link instead of naming it.
    while [ "$dir" != / ] && [ "${dir%/}" != "$dir" ]; do
        dir=${dir%/}
    done
    [ -n "$dir" ] || {
        echo "CORE_DIR must not be empty" >&2
        return 1
    }
    case "$dir" in
        /*) ;;
        *) dir="$PWD/$dir" ;;
    esac

    prefix=/
    check_component "$prefix" || return 1
    for part in $dir; do
        [ -n "$part" ] && [ "$part" != . ] || continue
        if [ "$part" = .. ]; then
            prefix=${prefix%/*}
            [ -n "$prefix" ] || prefix=/
            continue
        fi
        if [ "$prefix" = / ]; then
            prefix="/$part"
        else
            prefix="$prefix/$part"
        fi
        check_component "$prefix" || return 1
    done

    if [ -L "$dir/LICENSE" ] || [ ! -f "$dir/LICENSE" ]; then
        echo "LICENSE must be a root-owned regular file, not a symlink: $dir/LICENSE" >&2
        return 1
    fi
    owner=$(stat -c %u -- "$dir/LICENSE") || return 1
    if [ "$owner" != 0 ]; then
        echo "LICENSE must be a root-owned regular file, not a symlink: $dir/LICENSE" >&2
        return 1
    fi
}

# The pinned sing-box core is not downloaded: a fresh install must point
# CORE_DIR at the pinned release pair. A mismatch stops before any live file.
for core_file in sing-box libcronet.so LICENSE; do
    [ -r "$CORE_DIR/$core_file" ] || {
        echo "missing $CORE_DIR/$core_file; set CORE_DIR to the pinned core directory" >&2
        exit 1
    }
done
[ -x "$CORE_DIR/sing-box" ] || { echo "missing $CORE_DIR/sing-box" >&2; exit 1; }
validate_core_dir "$CORE_DIR"

# Freeze the validated copies before another check can replace the source.
install -d -m 0755 /usr/local/lib
STAGE_DIR=$(mktemp -d /usr/local/lib/.beam-stage.XXXXXX)
install -m 0755 "$CORE_DIR/sing-box" "$STAGE_DIR/sing-box"
install -m 0644 "$CORE_DIR/libcronet.so" "$STAGE_DIR/libcronet.so"
install -m 0644 "$CORE_DIR/LICENSE" "$STAGE_DIR/LICENSE"

[ -x "$HERE/beam-tray" ] || { echo "build first: $HERE/build.sh" >&2; exit 1; }
[ -x "$HERE/beam-helper" ] || { echo "build first: $HERE/build.sh" >&2; exit 1; }
[ -r "$HERE/99-beam-client-bbr.conf" ] || { echo "missing $HERE/99-beam-client-bbr.conf" >&2; exit 1; }

CORE_SING_SHA=1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a
CORE_LIB_SHA=23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294

# The helper edits systemd-resolved drop-ins and reloads that unit, so the
# resolver and its drop-in directory must exist before any live file changes.
# A missing resolver would otherwise surface only as a failed ExecStartPost.
command -v systemctl >/dev/null 2>&1 || {
    echo "systemctl is required: the tray controls beam-client through systemd" >&2
    exit 1
}
if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo "systemd-resolved is not active; the DNS switch needs it. Start and enable systemd-resolved, or install without the helper dns-on/dns-off lines and beam-dns-reset.service" >&2
    exit 1
fi
for dir in /etc/systemd/resolved.conf.d /etc/sysctl.d; do
    if [ ! -d "$dir" ]; then
        install -d -m 0755 "$dir" || {
            echo "could not create $dir; the installed files need it" >&2
            exit 1
        }
    fi
done

install -d -m 0755 /usr/local/lib /usr/local/libexec /etc/beam
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

backup_config() {
    local dir="$1" dest
    [ -f "$dir/config.json" ] || return 0
    dest="$dir/config.json.bak-$(date -u +%Y%m%dT%H%M%S%NZ)"
    install -m 0600 "$dir/config.json" "$dest"
}

# Timestamp suffixes sort in time order. Keep the newest copies, including
# the one made by this install. Match only generated suffixes so operator
# files such as config.json.bak-pre-upgrade stay untouched.
prune_config_backups() {
    local old name
    old=$(find /etc/beam -maxdepth 1 -type f \
        -name 'config.json.bak-????????T???????????????Z' \
        -printf '%f\n' | LC_ALL=C sort | head -n -"$CONFIG_BAK_KEEP")
    if [ -n "$old" ]; then
        while IFS= read -r name; do
            rm -f "/etc/beam/$name"
        done <<< "$old"
    fi
}

# systemctl returns 0 for static, generated and enabled-runtime units. Only
# enabled and enabled-runtime are enablement we can restore on rollback.
# A masked unit must stop the install before its unit file is written.
unit_enable_state() {
    local unit="$1" state
    state=$(systemctl is-enabled "$unit" 2>/dev/null) || true
    case "$state" in
        masked|masked-runtime)
            echo "installer: $unit is masked; unmask it before installing" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$state"
}

restore_unit_enablement() {
    local unit="$1" state="$2"
    case "$state" in
        enabled)
            if ! systemctl enable "$unit" >/dev/null 2>&1; then
                echo "installer: could not restore $unit enablement" >&2
                return 1
            fi
            ;;
        enabled-runtime)
            if ! systemctl enable --runtime "$unit" >/dev/null 2>&1; then
                echo "installer: could not restore $unit runtime enablement" >&2
                return 1
            fi
            ;;
        *)
            systemctl disable "$unit" >/dev/null 2>&1 || true
            ;;
    esac
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
    # Restore the inherited wants symlink; MANAGED_PATHS does not hold it.
    if ! restore_unit_enablement beam-client.service "$CLIENT_STATE"; then
        failed=1
    fi
    if ! restore_unit_enablement beam-dns-reset.service "$DNS_RESET_STATE"; then
        failed=1
    fi
    if [ "$failed" = "0" ] && [ "$SERVICE_WAS_ACTIVE" = "1" ]; then
        if ! systemctl start beam-client 2>/dev/null; then
            echo "installer: could not restart beam-client after rollback" >&2
            failed=1
        fi
    fi
    return "$failed"
}

NORMALIZED_CONFIG=$(mktemp)
chmod 0600 "$NORMALIZED_CONFIG"

# Hash and validate the staged copies. The live core and config are touched
# only after every check passes.
actual_sing=$(sha256sum "$STAGE_DIR/sing-box" | awk '{print $1}')
actual_lib=$(sha256sum "$STAGE_DIR/libcronet.so" | awk '{print $1}')
[ "$actual_sing" = "$CORE_SING_SHA" ] || { echo "core sing-box hash mismatch" >&2; exit 1; }
[ "$actual_lib" = "$CORE_LIB_SHA" ] || { echo "core libcronet hash mismatch" >&2; exit 1; }

python3 "$HERE/config-policy.py" "$CONFIG_SRC" "$NORMALIZED_CONFIG"
"$STAGE_DIR/sing-box" check -c "$NORMALIZED_CONFIG"

# Read enablement before taking a backup: a state-read failure must abort
# before the EXIT trap can roll back with empty states.
DNS_RESET_STATE=$(unit_enable_state beam-dns-reset.service) || exit 1
CLIENT_STATE=$(unit_enable_state beam-client) || exit 1

BACKUP_DIR=$(mktemp -d /usr/local/lib/.beam-backup.XXXXXX)
backup_live
BACKUP_READY=1

if systemctl is-active --quiet beam-client 2>/dev/null; then
    SERVICE_WAS_ACTIVE=1
fi

# Replacing the live core or config while the old process keeps running would
# pair the new files with the old TUN and DNS state. Stop first and prove that
# systemd reports the unit inactive. A stop command that returns nonzero while
# the unit is inactive is only a warning: ExecStopPost can fail on a DNS
# conflict that needs an operator.
stop_rc=0
systemctl stop beam-client 2>/dev/null || stop_rc=$?
if systemctl is-active --quiet beam-client 2>/dev/null; then
    echo "cannot stop beam-client; live files and config were not replaced" >&2
    BACKUP_READY=0
    exit 1
fi
if [ "$stop_rc" -ne 0 ]; then
    echo "warning: systemctl stop beam-client returned $stop_rc; the unit is inactive, check the DNS state" >&2
fi

# BBR is sender-side: it helps TCP uploads on lossy/high-RTT links, not
# downloads. Enable it only when this kernel actually exposes the algorithm.
# Keep the install usable on old kernels without BBR. This runs after the stop
# guard: a unit that will not stop aborts the install before it changes any
# BBR file, so no sysctl or module file is left modified.
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

backup_config /etc/beam
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
# dns-on reloads systemd-resolved and moves the ctrld drop-in aside. Ordering
# after both units stops dns-on from running before the resolver exists, and
# stops a late ctrld start from re-creating the drop-in during dns-on. A unit
# named only in After= that is absent is ignored.
After=network-online.target nss-lookup.target systemd-resolved.service ctrld.service
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
Description=Restore DNS after a beam client reboot
# Order after ctrld without starting it: the file restore and reload do not
# need a running ctrld, and a boot-time start can re-create its drop-in.
After=systemd-resolved.service ctrld.service
# Restore the previous DNS state before a client start can write a new one.
Before=beam-client.service
# Run for a saved ctrld or host drop-in, for a leftover beam 99-beam.conf
# from a power loss on a host that had neither ctrld nor a saved file, and for
# the ownership marker of a crash between the marker and live-file writes,
# or the trigger left by a dns-off reload failure.
ConditionPathExists=|/etc/systemd/resolved.conf.d/10-controld.conf.beam-off
ConditionPathExists=|/etc/systemd/resolved.conf.d/99-beam.conf.beam-prev
ConditionPathExists=|/etc/systemd/resolved.conf.d/99-beam.conf
ConditionPathExists=|/etc/systemd/resolved.conf.d/99-beam.conf.beam-own
ConditionPathExists=|/etc/systemd/resolved.conf.d/99-beam.conf.beam-reload

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/beam-helper restore-dns

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/beam-dns-reset.service
systemctl daemon-reload
systemctl enable beam-dns-reset.service
# An inherited wants symlink would start this unit at boot with a DNS change.
if ! systemctl disable beam-client.service >/dev/null 2>&1; then
    echo "installer: could not disable beam-client" >&2
    exit 1
fi

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
prune_config_backups
update-desktop-database /usr/share/applications >/dev/null 2>&1 || true

echo "installed; service is not enabled or started"
echo "launch: /usr/local/bin/beam-tray"
