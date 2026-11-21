#!/bin/bash
# Build and package the Windows tray client release asset for one commit.
#
# Runs alongside scripts/release-artifact.sh in .github/workflows/release.yml.
# Output, in BEAM_RELEASE_OUT (default target/release-artifact):
#   beam-windows-tray-<version>-<commit>-<target>.zip         archive
#   beam-windows-tray-<version>-<commit>-<target>.zip.sha256  archive pin
#
# Archive members:
#   beam-tray.exe        Windows tray binary
#   install.ps1          PowerShell 5.1+ installer/uninstaller
#   install.cmd          Double-click install wrapper
#   uninstall.cmd        Double-click uninstall wrapper
#   config.example.json  sing-box 1.15+ Windows TUN placeholder profile
#   README.md            Windows client usage and install notes
#   SHA256SUMS           beam-tray.exe pin only
#
# Environment (optional):
#   BEAM_WINDOWS_TRAY_BIN  package this prebuilt beam-tray.exe and skip build.sh;
#                          needs BEAM_RELEASE_COMMIT
#   BEAM_RELEASE_VERSION   override the workspace version
#   BEAM_RELEASE_COMMIT    override the commit stamp
#   BEAM_WINDOWS_TARGET    override the target triple (default x86_64-pc-windows-gnu)
#   BEAM_RELEASE_OUT       output directory
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WIN_DIR="$ROOT/clients/windows-tray"
OUT="${BEAM_RELEASE_OUT:-$ROOT/target/release-artifact}"

die() { echo "release-windows-tray: $*" >&2; exit 1; }

workspace_version() {
  awk '/^\[workspace\.package\]/{found=1; next} /^\[/{found=0}
       found && $1=="version"{gsub(/"/, "", $3); print $3; exit}' "$ROOT/Cargo.toml"
}

VERSION="${BEAM_RELEASE_VERSION:-$(workspace_version)}"
[ -n "$VERSION" ] || die "no version in Cargo.toml [workspace.package]"

if [ -n "${BEAM_RELEASE_COMMIT:-}" ]; then
  COMMIT="$BEAM_RELEASE_COMMIT"
else
  [ -z "${BEAM_WINDOWS_TRAY_BIN:-}" ] ||
    die "BEAM_WINDOWS_TRAY_BIN needs BEAM_RELEASE_COMMIT; the commit is not guessed"
  COMMIT="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null)" ||
    die "not a git checkout; set BEAM_RELEASE_COMMIT"
fi

TARGET="${BEAM_WINDOWS_TARGET:-x86_64-pc-windows-gnu}"

[[ "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]*$ ]] ||
  die "invalid version '$VERSION'"
[[ "$COMMIT" =~ ^[0-9a-f]{7,40}$ ]] ||
  die "invalid commit '$COMMIT'"
[[ "$TARGET" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
  die "invalid target '$TARGET'"

NAME="beam-windows-tray-$VERSION-$COMMIT-$TARGET"
ARCHIVE="$OUT/$NAME.zip"
mkdir -p "$OUT"
if [ -e "$ARCHIVE" ] || [ -e "$ARCHIVE.sha256" ]; then
  die "refusing to replace $ARCHIVE"
fi

if [ -n "${BEAM_WINDOWS_TRAY_BIN:-}" ]; then
  BIN="$BEAM_WINDOWS_TRAY_BIN"
else
  [ -z "$(git -C "$ROOT" status --porcelain)" ] ||
    die "working tree is dirty; commit the release source first"
  bash "$WIN_DIR/build.sh" >&2
  BIN="$WIN_DIR/beam-tray.exe"
fi
[ -f "$BIN" ] || die "missing binary $BIN"

for name in install.ps1 install.cmd uninstall.cmd config.example.json README.md; do
  [ -f "$WIN_DIR/$name" ] || die "missing clients/windows-tray/$name"
done

STAGE="$(mktemp -d "$OUT/.win-stage.XXXXXX")"
DONE=0
trap 'rc=$?; rm -rf -- "$STAGE"; [ "$DONE" = 1 ] || rm -f -- "$ARCHIVE" "$ARCHIVE.sha256"; exit $rc' EXIT

install -m 0755 "$BIN" "$STAGE/beam-tray.exe"
install -m 0644 "$WIN_DIR/install.ps1" "$STAGE/install.ps1"
install -m 0644 "$WIN_DIR/install.cmd" "$STAGE/install.cmd"
install -m 0644 "$WIN_DIR/uninstall.cmd" "$STAGE/uninstall.cmd"
install -m 0644 "$WIN_DIR/config.example.json" "$STAGE/config.example.json"
install -m 0644 "$WIN_DIR/README.md" "$STAGE/README.md"

BIN_SHA="$(sha256sum "$STAGE/beam-tray.exe" | awk '{print $1}')"
printf '%s  %s\n' "$BIN_SHA" beam-tray.exe > "$STAGE/SHA256SUMS"
chmod 0644 "$STAGE/SHA256SUMS"

MTIME="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 1700000000)}"

python3 - "$STAGE" "$ARCHIVE" "$MTIME" <<'PY'
import datetime, sys, zipfile
from pathlib import Path

stage = Path(sys.argv[1])
archive = Path(sys.argv[2])
mtime = int(sys.argv[3])
# ZIP format minimum timestamp is 1980-01-01 00:00:00.
dt = datetime.datetime.fromtimestamp(max(mtime, 315532800), tz=datetime.timezone.utc)
date_time = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

members = [
    "README.md",
    "SHA256SUMS",
    "beam-tray.exe",
    "config.example.json",
    "install.cmd",
    "install.ps1",
    "uninstall.cmd",
]

with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for name in members:
        src = stage / name
        info = zipfile.ZipInfo(filename=name, date_time=date_time)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (0o755 if name == "beam-tray.exe" else 0o644) << 16
        zf.writestr(info, src.read_bytes())
PY

ARCHIVE_SHA="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
printf '%s  %s\n' "$ARCHIVE_SHA" "$NAME.zip" > "$ARCHIVE.sha256"
DONE=1

echo "win_version=$VERSION"
echo "win_commit=$COMMIT"
echo "win_target=$TARGET"
echo "win_artifact=$ARCHIVE"
echo "win_artifact_sha256=$ARCHIVE_SHA"
echo "win_binary_sha256=$BIN_SHA"
