#!/bin/bash
# Package the native Windows client release asset for one commit.
#
# Runs in .github/workflows/windows-build.yml and .github/workflows/release.yml.
# Output, in BEAM_RELEASE_OUT (default target/release-artifact):
#   beam-windows-client-<version>-<commit>-<target>.zip         archive
#   beam-windows-client-<version>-<commit>-<target>.zip.sha256  archive pin
#
# Archive members (deterministic sorted order):
#   README.md                   Windows client usage and install notes
#   SHA256SUMS                  pins beam-client.exe, beam-tray.exe, wintun.dll
#   beam-client.exe             Native Rust Windows client & service binary
#   beam-tray.exe               Unelevated Win32 system tray binary
#   config.client.example.toml  Client TOML placeholder configuration
#   install.cmd                 Double-click install wrapper
#   install.ps1                 PowerShell 5.1+ installer/uninstaller
#   uninstall.cmd               Double-click uninstall wrapper
#   wintun.dll                  WHQL-signed WireGuard WinTun 0.14.1 (amd64)
#
# Environment (required):
#   BEAM_WINDOWS_CLIENT_BIN     path to prebuilt beam-client.exe
#   BEAM_WINDOWS_TRAY_BIN       path to prebuilt beam-tray.exe
#   BEAM_WINDOWS_WINTUN_DLL     path to verified wintun.dll (0.14.1 amd64)
#   BEAM_RELEASE_COMMIT         commit stamp for the prebuilt binaries
#
# Environment (optional):
#   BEAM_RELEASE_VERSION        override the workspace version
#   BEAM_WINDOWS_TARGET         override the target triple (default x86_64-pc-windows-msvc)
#   BEAM_RELEASE_OUT            output directory
#   BEAM_WINDOWS_SKIP_WINTUN_PIN  set to 1 only for stub contract tests
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WIN_DIR="$ROOT/clients/windows-tray"
OUT="${BEAM_RELEASE_OUT:-$ROOT/target/release-artifact}"

WINTUN_AMD64_SHA256="e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"

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
  die "BEAM_RELEASE_COMMIT is required for prebuilt Windows binaries; the commit is not guessed"
fi

TARGET="${BEAM_WINDOWS_TARGET:-x86_64-pc-windows-msvc}"

[[ "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]*$ ]] ||
  die "invalid version '$VERSION'"
[[ "$COMMIT" =~ ^[0-9a-f]{7,40}$ ]] ||
  die "invalid commit '$COMMIT'"
[[ "$TARGET" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
  die "invalid target '$TARGET'"

[ -n "${BEAM_WINDOWS_CLIENT_BIN:-}" ] || die "BEAM_WINDOWS_CLIENT_BIN is required"
[ -n "${BEAM_WINDOWS_TRAY_BIN:-}" ] || die "BEAM_WINDOWS_TRAY_BIN is required"
[ -n "${BEAM_WINDOWS_WINTUN_DLL:-}" ] || die "BEAM_WINDOWS_WINTUN_DLL is required"

[ -f "$BEAM_WINDOWS_CLIENT_BIN" ] || die "missing client binary $BEAM_WINDOWS_CLIENT_BIN"
[ -f "$BEAM_WINDOWS_TRAY_BIN" ] || die "missing tray binary $BEAM_WINDOWS_TRAY_BIN"
[ -f "$BEAM_WINDOWS_WINTUN_DLL" ] || die "missing wintun.dll $BEAM_WINDOWS_WINTUN_DLL"

sha256_file() {
  # GNU coreutils sha256sum prefixes a leading '\' when the path contains '\' (Windows).
  sha256sum "$1" | awk '{sub(/^\\/, "", $1); print $1}'
}

WINTUN_SHA="$(sha256_file "$BEAM_WINDOWS_WINTUN_DLL")"
if [ "${BEAM_WINDOWS_SKIP_WINTUN_PIN:-0}" != "1" ]; then
  [ "$WINTUN_SHA" = "$WINTUN_AMD64_SHA256" ] ||
    die "wintun.dll SHA-256 mismatch: got $WINTUN_SHA, expected $WINTUN_AMD64_SHA256"
fi

NAME="beam-windows-client-$VERSION-$COMMIT-$TARGET"
ARCHIVE="$OUT/$NAME.zip"
mkdir -p "$OUT"
if [ -e "$ARCHIVE" ] || [ -e "$ARCHIVE.sha256" ]; then
  die "refusing to replace $ARCHIVE"
fi

for name in install.ps1 install.cmd uninstall.cmd README.md; do
  [ -f "$WIN_DIR/$name" ] || die "missing clients/windows-tray/$name"
done
[ -f "$ROOT/config.client.example.toml" ] || die "missing config.client.example.toml"

STAGE="$(mktemp -d "$OUT/.win-stage.XXXXXX")"
DONE=0
trap 'rc=$?; rm -rf -- "$STAGE"; [ "$DONE" = 1 ] || rm -f -- "$ARCHIVE" "$ARCHIVE.sha256"; exit $rc' EXIT

install -m 0755 "$BEAM_WINDOWS_CLIENT_BIN" "$STAGE/beam-client.exe"
install -m 0755 "$BEAM_WINDOWS_TRAY_BIN" "$STAGE/beam-tray.exe"
install -m 0755 "$BEAM_WINDOWS_WINTUN_DLL" "$STAGE/wintun.dll"
install -m 0644 "$ROOT/config.client.example.toml" "$STAGE/config.client.example.toml"
install -m 0644 "$WIN_DIR/install.ps1" "$STAGE/install.ps1"
install -m 0644 "$WIN_DIR/install.cmd" "$STAGE/install.cmd"
install -m 0644 "$WIN_DIR/uninstall.cmd" "$STAGE/uninstall.cmd"
install -m 0644 "$WIN_DIR/README.md" "$STAGE/README.md"

CLIENT_SHA="$(sha256_file "$STAGE/beam-client.exe")"
TRAY_SHA="$(sha256_file "$STAGE/beam-tray.exe")"
WINTUN_SHA="$(sha256_file "$STAGE/wintun.dll")"
{
  printf '%s  %s\n' "$CLIENT_SHA" beam-client.exe
  printf '%s  %s\n' "$TRAY_SHA" beam-tray.exe
  printf '%s  %s\n' "$WINTUN_SHA" wintun.dll
} > "$STAGE/SHA256SUMS"
chmod 0644 "$STAGE/SHA256SUMS"

MTIME="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 1700000000)}"

PYTHON_BIN=""
for cand in "${PYTHON:-}" python3 python; do
  [ -n "$cand" ] || continue
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import sys" >/dev/null 2>&1; then
    PYTHON_BIN="$cand"
    break
  fi
done
[ -n "$PYTHON_BIN" ] || die "python3 or python is required to package the archive"

"$PYTHON_BIN" - "$STAGE" "$ARCHIVE" "$MTIME" <<'PY'
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
    "beam-client.exe",
    "beam-tray.exe",
    "config.client.example.toml",
    "install.cmd",
    "install.ps1",
    "uninstall.cmd",
    "wintun.dll",
]
executables = {"beam-client.exe", "beam-tray.exe", "wintun.dll"}

with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for name in members:
        src = stage / name
        info = zipfile.ZipInfo(filename=name, date_time=date_time)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (0o755 if name in executables else 0o644) << 16
        zf.writestr(info, src.read_bytes())
PY

ARCHIVE_SHA="$(sha256_file "$ARCHIVE")"
printf '%s  %s\n' "$ARCHIVE_SHA" "$NAME.zip" > "$ARCHIVE.sha256"
DONE=1

echo "win_version=$VERSION"
echo "win_commit=$COMMIT"
echo "win_target=$TARGET"
echo "win_artifact=$ARCHIVE"
echo "win_artifact_sha256=$ARCHIVE_SHA"
echo "win_client_sha256=$CLIENT_SHA"
echo "win_tray_sha256=$TRAY_SHA"
echo "win_wintun_sha256=$WINTUN_SHA"
