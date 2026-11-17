#!/bin/bash
# Build and package the release artifact for one commit.
#
# The release workflow runs this from `prod`, or from a `v*` tag that names the
# `prod` tip. `main` is the development line and is not a release source; `prod`
# is the single permanent release line and points only at the commit the
# production host runs.
#
# Output, in BEAM_RELEASE_OUT (default target/release-artifact):
#   beam-<version>-<commit>-<target>.tar.gz         archive
#   beam-<version>-<commit>-<target>.tar.gz.sha256  archive pin
#
# Archive members:
#   beam                 server binary, 0755
#   beam.service         systemd unit, 0644
#   beam-install.sh      install, update, uninstall path, 0755
#   config.example.toml  example config with placeholders, 0600
#   liveness-check.py    liveness probe run by the timer, 0755
#   beam-liveness.service liveness probe unit, 0644
#   beam-liveness.timer  five-minute liveness timer, 0644
#   SHA256SUMS           binary pin only
#
# SHA256SUMS holds the binary line only, so an operator who edits the example
# config still verifies with `sha256sum -c SHA256SUMS`. The archive pin covers
# every member and verifies with `sha256sum -c <name>.tar.gz.sha256` next to the
# archive. The installer reads the unit from the archive, so an extracted
# directory installs with `bash beam-install.sh install`.
#
# Environment (optional; the release workflow sets none of them):
#   BEAM_RELEASE_BIN      package this binary and skip the build; needs
#                         BEAM_RELEASE_COMMIT, because the commit is never
#                         guessed for a prebuilt binary
#   BEAM_RELEASE_VERSION  override the workspace version
#   BEAM_RELEASE_COMMIT   override the commit stamp
#   BEAM_RELEASE_TARGET   override the target triple
#   BEAM_RELEASE_OUT      output directory
#
# The version, commit, and target become the archive name and, downstream, the
# release tag and asset names. Each is checked against a strict character set
# before it reaches a path.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="${BEAM_RELEASE_OUT:-$ROOT/target/release-artifact}"

die() { echo "release: $*" >&2; exit 1; }

workspace_version() { # print the [workspace.package] version
  awk '/^\[workspace\.package\]/{found=1; next} /^\[/{found=0}
       found && $1=="version"{gsub(/"/, "", $3); print $3; exit}' "$ROOT/Cargo.toml"
}

VERSION="${BEAM_RELEASE_VERSION:-$(workspace_version)}"
[ -n "$VERSION" ] || die "no version in Cargo.toml [workspace.package]"

if [ -n "${BEAM_RELEASE_COMMIT:-}" ]; then
  COMMIT="$BEAM_RELEASE_COMMIT"
else
  # A prebuilt binary must name its own commit: stamping it with HEAD would
  # claim a source it may not come from.
  [ -z "${BEAM_RELEASE_BIN:-}" ] ||
    die "BEAM_RELEASE_BIN needs BEAM_RELEASE_COMMIT; the commit is not guessed"
  COMMIT="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null)" ||
    die "not a git checkout; set BEAM_RELEASE_COMMIT"
fi

TARGET="${BEAM_RELEASE_TARGET:-$(rustc -vV 2>/dev/null | awk '/^host: /{print $2}')}"
[ -n "$TARGET" ] || die "no rustc host triple; set BEAM_RELEASE_TARGET"

# No path separator, space, or newline can enter the archive name below.
[[ "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]*$ ]] ||
  die "invalid version '$VERSION'"
[[ "$COMMIT" =~ ^[0-9a-f]{7,40}$ ]] ||
  die "invalid commit '$COMMIT'"
[[ "$TARGET" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
  die "invalid target '$TARGET'"

NAME="beam-$VERSION-$COMMIT-$TARGET"
ARCHIVE="$OUT/$NAME.tar.gz"
mkdir -p "$OUT"
if [ -e "$ARCHIVE" ] || [ -e "$ARCHIVE.sha256" ]; then
  die "refusing to replace $ARCHIVE"
fi

if [ -n "${BEAM_RELEASE_BIN:-}" ]; then
  BIN="$BEAM_RELEASE_BIN"
else
  # One commit must back both the version stamp and the SHA-256 pin.
  [ -z "$(git -C "$ROOT" status --porcelain)" ] ||
    die "working tree is dirty; commit the release source first"
  # The stamp must come from git HEAD; an inherited override could label the
  # binary with another commit.
  unset BEAM_BUILD_GIT_HASH
  source "$ROOT/scripts/dev-env.sh"
  cargo build --locked --release --bin beam --manifest-path "$ROOT/Cargo.toml"
  BIN="$ROOT/target/release/beam"
fi
[ -f "$BIN" ] || die "missing binary $BIN"

VERSION_OUT="$("$BIN" --version)" || die "$BIN --version failed"
case "$VERSION_OUT" in
  "beam $VERSION "*) ;;
  *) die "binary reports '$VERSION_OUT', expected 'beam $VERSION ...'" ;;
esac
case "$VERSION_OUT" in
  *"($COMMIT)") ;;
  *) die "binary commit stamp does not match $COMMIT: '$VERSION_OUT'" ;;
esac
"$BIN" --check -c "$ROOT/config.example.toml" >/dev/null ||
  die "beam --check failed on config.example.toml"

STAGE="$(mktemp -d "$OUT/.stage.XXXXXX")"
# A failed run leaves neither staging files nor a partial archive that would
# make the next run stop at "refusing to replace".
DONE=0
trap 'rc=$?; rm -rf -- "$STAGE"; [ "$DONE" = 1 ] || rm -f -- "$ARCHIVE" "$ARCHIVE.sha256"; exit $rc' EXIT
install -m 0755 "$BIN" "$STAGE/beam"
install -m 0644 "$ROOT/deploy/beam.service" "$STAGE/beam.service"
install -m 0755 "$ROOT/deploy/beam-install.sh" "$STAGE/beam-install.sh"
# 0600 in the archive: the operator edits this file into a secret-bearing one,
# and the installer refuses a config that other users can read.
install -m 0600 "$ROOT/config.example.toml" "$STAGE/config.example.toml"
# The probe and its unit and timer travel with the archive, so one download
# carries the deployed liveness state and not only the server unit.
for name in liveness-check.py beam-liveness.service beam-liveness.timer; do
  [ -f "$ROOT/deploy/$name" ] || die "missing deploy/$name"
done
install -m 0755 "$ROOT/deploy/liveness-check.py" "$STAGE/liveness-check.py"
install -m 0644 "$ROOT/deploy/beam-liveness.service" "$STAGE/beam-liveness.service"
install -m 0644 "$ROOT/deploy/beam-liveness.timer" "$STAGE/beam-liveness.timer"
BIN_SHA="$(sha256sum "$STAGE/beam" | awk '{print $1}')"
printf '%s  %s\n' "$BIN_SHA" beam > "$STAGE/SHA256SUMS"
# Artifact modes are part of the contract, so they must not follow the
# caller's umask. build under `umask 077` still produces a verifiable bundle.
chmod 0644 "$STAGE/SHA256SUMS"

# Fixed ownership and timestamp keep the archive metadata off the hash input
# that varies between runners.
MTIME="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}"
tar -C "$STAGE" --sort=name --owner=0 --group=0 --numeric-owner \
  --mtime="@$MTIME" -czf "$ARCHIVE" \
  beam beam.service beam-install.sh config.example.toml \
  liveness-check.py beam-liveness.service beam-liveness.timer SHA256SUMS
ARCHIVE_SHA="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
printf '%s  %s\n' "$ARCHIVE_SHA" "$NAME.tar.gz" > "$ARCHIVE.sha256"
DONE=1

echo "version=$VERSION"
echo "commit=$COMMIT"
echo "target=$TARGET"
echo "artifact=$ARCHIVE"
echo "artifact_sha256=$ARCHIVE_SHA"
echo "binary_sha256=$BIN_SHA"
