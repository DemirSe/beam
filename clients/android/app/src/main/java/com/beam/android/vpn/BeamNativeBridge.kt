package com.beam.android.vpn

/** Connection states shared with the Rust engine (must match engine ordinals). */
object VpnState {
    const val DISCONNECTED = 0
    const val CONNECTING = 1
    const val CONNECTED = 2
    const val DEGRADED = 3
    const val DISCONNECTING = 4
}

/** JNI callback for engine state pushes. */
interface NativeStateListener {
    fun onNativeStateChanged(state: Int, detail: String)
}

/** Thin JNI bridge to libbeam_android.so. All FD unsafe lives in Rust/beam-sys. */
object BeamNativeBridge {
    init {
        System.loadLibrary("beam_android")
    }

    @JvmStatic external fun nativeStart(
        tunFd: Int,
        configJson: String,
        vpnService: Any,
        listener: NativeStateListener?,
    ): Long

    @JvmStatic external fun nativeStop(handle: Long)

    @JvmStatic external fun nativeNotifyNetworkChange(handle: Long)

    @JvmStatic external fun nativePollTelemetry(handle: Long): String?

    @JvmStatic external fun nativeParseVlessLink(uri: String): String?
}
