#!/usr/bin/env bash
set -euo pipefail

# Runs instrumentation tests on both the debug APK and the R8-minified release
# APK (proving JNI, Keystore, and ProGuard keep rules end to end), then launches
# the release APK and checks for crashes and memory footprint.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_DIR="$(cd "$SCRIPT_DIR/../clients/android" && pwd)"

cd "$ANDROID_DIR"

echo "=== running debug instrumentation tests ==="
if ! ./gradlew -Pbeam.includeX86_64=true connectedDebugAndroidTest; then
    echo "=== debug instrumentation results ==="
    find app/build/outputs/androidTest-results -name '*.xml' -print -exec cat {} +
    exit 1
fi

RELEASE_APK="app/build/outputs/apk/release/app-release.apk"
if [ ! -f "$RELEASE_APK" ]; then
    echo "error: expected R8 release APK at $RELEASE_APK"
    exit 1
fi

echo "=== running R8 release instrumentation tests (JNI + Keystore + R8) ==="
adb uninstall com.beam.android || true
adb uninstall com.beam.android.test || true
if ! ./gradlew -Pbeam.includeX86_64=true -Pbeam.signReleaseWithDebug=true -Pbeam.testBuildType=release connectedReleaseAndroidTest; then
    echo "=== release instrumentation results ==="
    find app/build/outputs/androidTest-results -name '*.xml' -print -exec cat {} +
    exit 1
fi

echo "=== smoke-testing R8 release APK launch ($RELEASE_APK) ==="
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
echo "=== R8 release APK instrumentation + launch smoke test PASSED ==="
