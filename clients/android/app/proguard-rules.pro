# Keep the JNI bridge: called by Rust via JNI, stripped by R8 otherwise.
-keep class com.beam.android.vpn.BeamNativeBridge {
    *;
}
-keep class com.beam.android.vpn.NativeStateListener {
    *;
}

# Rust calls VpnService.protect(int) via JNI by name and signature.
-keepclassmembers class * extends android.net.VpnService {
    public boolean protect(int);
}

# Keep cross-process AIDL interfaces, Stubs, and Proxies intact under R8 full mode.
-keep class com.beam.android.ipc.** {
    *;
}

# Preserve stack trace line numbers with R8 mapping.txt deobfuscation.
-keepattributes SourceFile,LineNumberTable
