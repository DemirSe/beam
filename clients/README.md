# Clients

The tray clients are optional. The server does not need them, and any standard
Xray or sing-box client works without them. They are our own wrapper around a
stock sing-box core, so they add no protocol code to `beam`.

- [Linux tray](linux-tray/README.md): GTK tray and a fixed-command root helper.
- [Windows tray](windows-tray/README.md): Windows tray launcher for sing-box.
- [Android](android/README.md): native Rust (`beam-android`) + Kotlin Android `VpnService` client. Build and device steps are in the module README.
- [Android client plan](../docs/ANDROID-PLAN.md): design and phased delivery of the Android client.
