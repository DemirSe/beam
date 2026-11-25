# Keep the JNI bridge: called by Rust via JNI, stripped by R8 otherwise.
-keep class com.beam.android.vpn.BeamNativeBridge {
    *;
}
-keep class com.beam.android.vpn.NativeStateListener {
    *;
}
