#!/bin/bash
# Cross-compiles libbeam_android.so for aarch64-linux-android and builds the APK.
#
#   ./scripts/android-build.sh --debug [--install]
#   ./scripts/android-build.sh --release [--install]
#
# Copies the .so (stripped only for --release) to
# clients/android/app/src/main/jniLibs/arm64-v8a/, runs the Gradle build, and
# optionally `adb install -r` the newest APK.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="debug"
INSTALL=0

for arg in "$@"; do
    case "$arg" in
        --debug) MODE="debug" ;;
        --release) MODE="release" ;;
        --install) INSTALL=1 ;;
        *) echo "usage: $0 [--debug|--release] [--install]" >&2; exit 2 ;;
    esac
done

: "${ANDROID_NDK_HOME:=${ANDROID_HOME:-$HOME/Android/Sdk}/ndk/27.2.12479018}"
if [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "error: NDK not found at $ANDROID_NDK_HOME" >&2
    echo "run ./scripts/android-setup-local.sh first" >&2
    exit 1
fi

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
export CC_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android31-clang"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384"

info() { echo "[android-build] $*"; }

# 1. Rust cdylib ---------------------------------------------------------------
if [ "$MODE" = "release" ]; then
    info "cargo build --release -p beam-android --target aarch64-linux-android"
    (cd "$REPO_ROOT" && cargo build --release -p beam-android --target aarch64-linux-android)
    SO="$REPO_ROOT/target/aarch64-linux-android/release/libbeam_android.so"
else
    info "cargo build -p beam-android --target aarch64-linux-android"
    (cd "$REPO_ROOT" && cargo build -p beam-android --target aarch64-linux-android)
    SO="$REPO_ROOT/target/aarch64-linux-android/debug/libbeam_android.so"
fi

[ -f "$SO" ] || { echo "error: $SO not produced" >&2; exit 1; }

# 2. Strip + stage into jniLibs ------------------------------------------------
# Debug builds stay unstripped so the symbols are usable in a debugger.
if [ "$MODE" = "release" ]; then
    "$TOOLCHAIN/bin/llvm-strip" "$SO" 2>/dev/null || true
fi
JNIDIR="$REPO_ROOT/clients/android/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$JNIDIR"
cp "$SO" "$JNIDIR/libbeam_android.so"
info "staged $(du -h "$JNIDIR/libbeam_android.so" | cut -f1) -> $JNIDIR"

# 3. Gradle --------------------------------------------------------------------
GRADLE_TASK="assembleDebug"
[ "$MODE" = "release" ] && GRADLE_TASK="assembleRelease"
info "./gradlew $GRADLE_TASK"
(cd "$REPO_ROOT/clients/android" && ./gradlew "$GRADLE_TASK")

APK="$(ls -t "$REPO_ROOT/clients/android/app/build/outputs/apk/$MODE"/*.apk 2>/dev/null | head -1)"
info "APK: ${APK:-<none found>}"

# 4. Optional install ----------------------------------------------------------
if [ "$INSTALL" = 1 ]; then
    [ -n "$APK" ] || { echo "error: no APK to install" >&2; exit 1; }
    if [[ "$APK" == *unsigned*.apk ]]; then
        echo "error: $APK is unsigned and cannot be installed via adb." >&2
        echo "set BEAM_KEYSTORE_PATH/PASSWORD/ALIAS or pass -Pbeam.signReleaseWithDebug=true (or use --debug)." >&2
        exit 1
    fi
    adb install -r "$APK"
fi
