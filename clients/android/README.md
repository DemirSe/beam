# Beam Android client

Native Android client for `beam`. The Rust tunnel runs in the isolated `:vpn`
process. The UI is Kotlin with XML layouts and Material 3.

Closing the UI does not stop the tunnel. The `:vpn` process keeps the engine and
the foreground notification. The UI binds to it only while it is visible.

## What is in this module

| Path | Purpose |
|---|---|
| `app/src/main/java/com/beam/android/ui/` | Dashboard, Profiles, Settings, QR scanner |
| `app/src/main/java/com/beam/android/tile/` | Quick Settings tile |
| `app/src/main/java/com/beam/android/vpn/` | `VpnService`, network monitor, notification |
| `app/src/main/java/com/beam/android/storage/` | Keystore-encrypted profile store, settings store |
| `app/src/main/aidl/com/beam/android/ipc/` | AIDL contract between the UI and `:vpn` |
| `app/src/main/res/` | Layouts, drawables, themes, strings |

## Requirements

- JDK 17.
- Android SDK 35 and build tools 35.
- Android NDK r27c.
- Rust target `aarch64-linux-android`.
- A device with Android 12 or later on arm64-v8a.

## Set up the toolchain

Run the setup script one time. It adds the Rust target and checks the SDK, the
NDK and the JDK:

```bash
./scripts/android-setup-local.sh
```

To build by hand, export the same paths:

```bash
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.2.12479018"
```

## Build and install

```bash
./scripts/android-build.sh --debug --install
```

The script does four steps:

1. It cross-compiles `libbeam_android.so` for arm64.
2. It copies the library to `app/src/main/jniLibs/arm64-v8a/`.
3. It builds the APK with Gradle.
4. With `--install`, it runs `adb install -r` on the connected device.

To use Gradle only, put the native library in `app/src/main/jniLibs/arm64-v8a/`
first:

```bash
cd clients/android
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## First run

1. Open **Profiles**.
2. Tap the add button and paste a `vless://` link, or tap the QR button and scan
   the QR code.
3. Tap the profile. The check mark shows the active profile.
4. Open **Dashboard** and tap **Connect**.
5. Accept the Android VPN dialog.

The list shows only the profile name and `server:port`. The app does not show or
log the UUID, the SNI or the private key.

## Battery, Doze and Samsung One UI

The app holds no WakeLock and runs no background timer. The dashboard polls
telemetry every 2 seconds only while it is visible and connected.

Android can still pause a background app. Do these steps on the device:

1. Open **Settings**, then **System**, then the **Always-on VPN** row in the app.
2. Enable **Always-on VPN** for beam.
3. Enable **Block connections without VPN**. This is the kill-switch.
4. Open the **Unrestricted battery** row in the app and allow unrestricted use.

Samsung One UI adds a second limit:

1. Open **Settings**, then **Battery**, then **Background usage limits**.
2. Open **Never sleeping apps**.
3. Add beam.

Check the state with:

```bash
adb shell dumpsys deviceidle whitelist | grep com.beam.android
```

## Quick Settings tile and restart

- Add the **beam** tile from the Quick Settings edit screen.
- Tap the tile to connect or disconnect with the active profile.
- The tile opens the app when no profile is active or VPN consent is missing.
- Enable **Start on boot** in Settings to reconnect after a reboot. Note:
  Android 12+ background foreground-service restrictions can block
  `BOOT_COMPLETED` starts on some OEMs, so enabling Android's **Always-on VPN**
  (with kill-switch) is the guaranteed reboot path.

## Test and profile

```bash
cd clients/android
./gradlew testDebugUnitTest lintDebug
```

```bash
# Memory of the tunnel process, target 20 to 30 MiB typical
adb shell dumpsys meminfo com.beam.android:vpn

# Zero idle wakeups during Doze
adb shell dumpsys batterystats --reset
adb shell dumpsys deviceidle force-idle
adb shell dumpsys batterystats | grep -A 20 "com.beam.android"

# Service state changes only
adb logcat -s BeamVpnService
```

## Known limits

- Only the `arm64-v8a` ABI is built.
- The TUN interface uses `198.19.0.1/30` and the TUN DNS server is
  `198.19.0.2`. A bypass CIDR that covers `198.19.0.0/30` is ignored, so the DNS
  server can never be bypassed. Android 12 (API 31-32) has no route exclusion;
  the app adds the complementary routes instead.
- Split tunneling covers this app and the bypass CIDRs. Per-app proxy is not
  included.
- The native library parses `vless://` links. The UI falls back to a plain URI
  parser when the library is not loaded, so profile import still works. The
  fallback accepts only REALITY links with a public key and an SNI.
