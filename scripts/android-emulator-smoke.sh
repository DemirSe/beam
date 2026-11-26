#!/usr/bin/env bash
set -euo pipefail

# Runs instrumentation tests on the debug APK, then installs and smoke-tests
# the R8-minified release APK on the booted Android emulator.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_DIR="$(cd "$SCRIPT_DIR/../clients/android" && pwd)"

cd "$ANDROID_DIR"

if ! ./gradlew -Pbeam.includeX86_64=true connectedDebugAndroidTest; then
    echo "=== instrumentation results ==="
    find app/build/outputs/androidTest-results -name '*.xml' -print -exec cat {} +
    exit 1
fi

RELEASE_APK="app/build/outputs/apk/release/app-release.apk"
if [ ! -f "$RELEASE_APK" ]; then
    echo "error: expected R8 release APK at $RELEASE_APK"
    exit 1
fi

echo "=== smoke-testing R8 release APK ($RELEASE_APK) ==="
adb uninstall com.beam.android || true
adb logcat -b crash -c || true
adb install -r "$RELEASE_APK"
adb shell am start -W -n com.beam.android/.ui.MainActivity
sleep 8

if ! adb shell pidof com.beam.android; then
    echo "error: release com.beam.android died after launch"
    adb logcat -d -t 200
    exit 1
fi

if adb shell logcat -b crash -d | grep -q "com.beam.android"; then
    echo "error: crash detected in release APK"
    adb shell logcat -b crash -d
    exit 1
fi

adb shell dumpsys meminfo com.beam.android | head -n 25
echo "=== R8 release APK smoke test PASSED ==="
