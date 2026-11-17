#!/bin/bash
# Build a root-readable deployment bundle from a local config file.
#
# One bundle serves both installers:
#   deploy/bootstrap.sh        Debian 13
#   deploy/bootstrap-alma.sh   AlmaLinux 10
#
# Environment:
#   BEAM_CONFIG       Config file to bundle. BEAM_SECRETS is an older alias.
#                     Default: $HOME/.config/beam/beam.toml.
#   BEAM_KEEP_CONFIG  1 builds an update bundle with no config, because the
#                     installer keeps the live /etc/beam/config.toml. 0 or
#                     unset requires and validates a config.
#   BEAM_BUNDLE_OUT   New directory under /tmp for the bundle. An existing path
#                     is refused, never replaced.
#
# The binary is built from a clean tree at HEAD and its `--version` stamp must
# name that commit; a staged, unstaged, or untracked change stops the build.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CONFIG="${BEAM_CONFIG:-${BEAM_SECRETS:-$HOME/.config/beam/beam.toml}}"
# Staging runs after `cd "$OUT"`, so a relative BEAM_CONFIG must resolve first.
CONFIG="$(realpath -m -- "$CONFIG")"
KEEP_CONFIG="${BEAM_KEEP_CONFIG:-}"
case "$KEEP_CONFIG" in
  0|1|"") ;;
  *) echo "package: BEAM_KEEP_CONFIG must be 0 or 1" >&2; exit 1 ;;
esac

# Every file an installer copies. Manual host-hardening extras are not here.
TEXT_FILES=(
  beam.service 99-beam.conf 99-beam-conntrack.conf 99-beam-conntrack.modules
  99-beam-coredump.conf 99-beam-ipv6-disable.conf journald-beam.conf beam-ipv4-only.conf
  sshd-60-hardening.conf sshd-61-ipv4-only.conf sshd-62-port.conf maintenance-rules.md motd
  beam-post-boot-check.service beam-liveness.service beam-liveness.timer
  beam-fq.service nftables.conf
)
EXEC_FILES=(
  bootstrap.sh bootstrap-alma.sh post-boot-check.sh liveness-check.py
  apply-fq.sh sshrc
)
for name in "${TEXT_FILES[@]}" "${EXEC_FILES[@]}" chrony-beam.conf; do
  [ -f "$HERE/$name" ] || { echo "package: missing deploy/$name" >&2; exit 1; }
done

BUNDLE_CONFIG=0
if [ "$KEEP_CONFIG" = "1" ]; then
  echo "package: BEAM_KEEP_CONFIG=1, no config in the bundle; the live config is kept" >&2
  [ -z "${BEAM_CONFIG:-}${BEAM_SECRETS:-}" ] ||
    echo "package: ignoring BEAM_CONFIG/BEAM_SECRETS because BEAM_KEEP_CONFIG=1" >&2
else
  if [ ! -f "$CONFIG" ]; then
    echo "package: missing config file $CONFIG" >&2
    echo "package: set BEAM_CONFIG=<file> for a new host, or BEAM_KEEP_CONFIG=1 for an update without a config" >&2
    exit 1
  fi
  [ -r "$CONFIG" ] || { echo "package: cannot read $CONFIG" >&2; exit 1; }
  case "$(stat -c %a "$CONFIG")" in
    *0) ;;
    *) echo "package: $CONFIG is readable by other users; chmod 600 it before building a bundle" >&2; exit 1 ;;
  esac
  BUNDLE_CONFIG=1
fi

# Bind the bundle to one commit before creating any secret-bearing directory.
COMMIT="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null)" || {
  echo "package: not a git checkout; a production bundle must name its commit" >&2
  exit 1
}
# One porcelain read covers staged, unstaged, and untracked state. Ignored
# local files, such as target/ or ~/.config/beam/beam.toml, stay out of it.
DIRTY="$(git -C "$ROOT" status --porcelain --untracked-files=normal)" || {
  echo "package: cannot read git status in $ROOT" >&2
  exit 1
}
if [ -n "$DIRTY" ]; then
  echo "package: refusing a dirty tree; the binary must match $COMMIT" >&2
  echo "package: commit these changes, or keep the file out of the tree or in .gitignore:" >&2
  printf '%s\n' "$DIRTY" >&2
  exit 1
fi
VERSION="$(awk '/^\[workspace\.package\]/{found=1; next} /^\[/{found=0}
  found && $1=="version"{gsub(/"/, "", $3); print $3; exit}' "$ROOT/Cargo.toml")"
[ -n "$VERSION" ] || { echo "package: no version in Cargo.toml [workspace.package]" >&2; exit 1; }
# An inherited stamp would label the binary with another commit; the release
# script drops it for the same reason.
if [ -n "${BEAM_BUILD_GIT_HASH:-}" ]; then
  echo "package: ignoring BEAM_BUILD_GIT_HASH=$BEAM_BUILD_GIT_HASH; the stamp comes from HEAD" >&2
  unset BEAM_BUILD_GIT_HASH
fi

# Build and validate before creating any secret-bearing directory.
source "$ROOT/scripts/dev-env.sh"
cargo build --locked --manifest-path "$ROOT/Cargo.toml" --release -p beam
BIN="$ROOT/target/release/beam"
VERSION_OUT="$("$BIN" --version)" || { echo "package: $BIN --version failed" >&2; exit 1; }
EXPECTED="beam $VERSION ($COMMIT)"
if [ "$VERSION_OUT" != "$EXPECTED" ]; then
  echo "package: $BIN reports '$VERSION_OUT', expected '$EXPECTED'" >&2
  echo "package: rerun after 'cargo clean -p beam' so the build script stamps HEAD" >&2
  exit 1
fi
BIN_SHA="$(sha256sum "$BIN" | awk '{print $1}')"
if [ "$BUNDLE_CONFIG" = "1" ]; then
  if ! bash -c 'ulimit -n 65536 2>/dev/null || true; exec "$0" --check -c "$1"' \
      "$BIN" "$CONFIG"; then
    echo "package: $CONFIG failed beam --check" >&2
    exit 1
  fi
fi

if [ -n "${BEAM_BUNDLE_OUT:-}" ]; then
  OUT="$(realpath -m -- "$BEAM_BUNDLE_OUT")"
  case "$OUT" in
    /tmp/?*) ;;
    *) echo "package: refusing an output path outside /tmp: '$OUT'" >&2; exit 1 ;;
  esac
  if [ -e "$OUT" ] || [ -L "$OUT" ]; then
    echo "package: refusing to replace existing $OUT; remove it yourself or choose a new path" >&2
    exit 1
  fi
  mkdir -m 0700 -- "$OUT" || {
    echo "package: cannot create $OUT; use a new path whose parent directory exists" >&2
    exit 1
  }
else
  OUT="$(mktemp -d /tmp/beam-deploy.XXXXXXXX)"
fi
trap 'rm -rf -- "$OUT"' ERR INT TERM

(
  cd "$OUT"
  install -m 0755 "$BIN" beam
  for name in "${TEXT_FILES[@]}"; do install -m 0644 "$HERE/$name" "$name"; done
  for name in "${EXEC_FILES[@]}"; do install -m 0755 "$HERE/$name" "$name"; done
  # bootstrap-alma.sh reads the AlmaLinux names for the time source.
  install -m 0644 "$HERE/chrony-beam.conf" chrony.conf
  printf '%s\n' \
    '# Generated by deploy/package.sh for AlmaLinux.' \
    '# chronyd.service reads OPTIONS from this file. -4 keeps every chrony' \
    '# socket on IPv4; the verifier requires zero IPv6 listeners.' \
    'OPTIONS="-4"' > chronyd-sysconfig
  chmod 0644 chronyd-sysconfig
  if [ "$BUNDLE_CONFIG" = "1" ]; then install -m 0600 "$CONFIG" beam.toml; fi
)

ARCHIVE=(beam chrony.conf chronyd-sysconfig "${TEXT_FILES[@]}" "${EXEC_FILES[@]}")
if [ "$BUNDLE_CONFIG" = "1" ]; then ARCHIVE+=(beam.toml); fi
tar -C "$OUT" -czf "$OUT/beam-deploy.tar.gz" "${ARCHIVE[@]}"
chmod 0600 "$OUT/beam-deploy.tar.gz"
sha256sum "$OUT/beam-deploy.tar.gz" > "$OUT/beam-deploy.tar.gz.sha256"
trap - ERR INT TERM
echo "version=$VERSION"
echo "commit=$COMMIT"
echo "binary_sha256=$BIN_SHA"
echo "bundle=$OUT/beam-deploy.tar.gz"
echo "sha256=$(cat "$OUT/beam-deploy.tar.gz.sha256")"
