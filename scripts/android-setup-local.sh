#!/bin/bash
# Installs the local Android build prerequisites:
#   - Rust aarch64-linux-android target
#   - Android NDK r27c + SDK 35 (cmdline-tools)
#   - JDK 17
# Idempotent: safe to re-run. Exits non-zero on failure.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NDK_VERSION="${NDK_VERSION:-r27c}"
NDK_NUM="27.2.12479018"
ANDROID_HOME_DEFAULT="$HOME/Android/Sdk"
ANDROID_HOME="${ANDROID_HOME:-$ANDROID_HOME_DEFAULT}"
SDK_PACKAGES="platform-tools;platforms;android-35;build-tools;35.0.0"

info() { echo "[android-setup] $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# 1. Rust target ---------------------------------------------------------------
if rustup target list --installed 2>/dev/null | grep -q aarch64-linux-android; then
    info "rust target aarch64-linux-android already installed"
else
    info "installing rust target aarch64-linux-android..."
    rustup target add aarch64-linux-android
fi

# 2. Java 17 -------------------------------------------------------------------
if have java; then
    info "java: $(java -version 2>&1 | head -1)"
else
    info "JDK 17 not found."
    if have apt-get; then
        info "install with: sudo apt-get install -y openjdk-17-jdk"
        sudo apt-get install -y openjdk-17-jdk
    elif have brew; then
        info "install with: brew install openjdk@17"
    else
        info "install a JDK 17 and re-run this script"
        exit 1
    fi
fi

# 3. Android SDK + NDK ---------------------------------------------------------
export ANDROID_HOME
export ANDROID_SDK_ROOT="$ANDROID_HOME"
mkdir -p "$ANDROID_HOME/cmdline-tools"

if [ ! -x "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
    info "downloading Android command-line tools..."
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    curl -sSL -o "$TMP/tools.zip" \
        "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
    unzip -q "$TMP/tools.zip" -d "$TMP"
    rm -rf "$ANDROID_HOME/cmdline-tools/latest"
    mkdir -p "$ANDROID_HOME/cmdline-tools/latest"
    mv "$TMP/cmdline-tools/"* "$ANDROID_HOME/cmdline-tools/latest/"
    rm -rf "$TMP"
    trap - EXIT
else
    info "cmdline-tools present"
fi

SDKM="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
yes | "$SDKM" --licenses >/dev/null 2>&1 || true
info "installing SDK packages: $SDK_PACKAGES + ndk;$NDK_NUM"
"$SDKM" "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;$NDK_NUM"

NDK_HOME="$ANDROID_HOME/ndk/$NDK_NUM"
if [ -d "$NDK_HOME" ]; then
    info "NDK ready at $NDK_HOME"
else
    info "ERROR: NDK directory missing after install: $NDK_HOME"
    exit 1
fi

# 4. Persist env for shells ----------------------------------------------------
ENV_LINE="export ANDROID_HOME=\"$ANDROID_HOME\" ANDROID_SDK_ROOT=\"$ANDROID_HOME\" ANDROID_NDK_HOME=\"$NDK_HOME\" NDK_HOME=\"$NDK_HOME\""
if ! grep -q "ANDROID_NDK_HOME" ~/.bashrc 2>/dev/null; then
    echo "$ENV_LINE" >> ~/.bashrc
    info "appended Android env to ~/.bashrc"
fi

info "done. NDK=$NDK_HOME  SDK=$ANDROID_HOME"
info "next: ./scripts/android-build.sh --debug"
