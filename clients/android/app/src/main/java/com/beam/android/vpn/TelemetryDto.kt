package com.beam.android.vpn

import org.json.JSONObject

/** Lock-free telemetry snapshot polled on demand (Dashboard polls only while STARTED). */
data class TelemetryDto(
    val activeTcpFlows: Long = 0,
    val activeUdpSessions: Long = 0,
    val bytesTx: Long? = null,
    val bytesRx: Long? = null,
    val lastRttMs: Long? = null,
    val dialFailures: Long = 0,
    val drops: Long = 0,
    val state: Int = VpnState.DISCONNECTED,
) {
    companion object {
        fun fromJson(json: String): TelemetryDto {
            if (json.isBlank()) return TelemetryDto()
            return try {
                val o = JSONObject(json)
                TelemetryDto(
                    activeTcpFlows = o.optLong("active_tcp_flows"),
                    activeUdpSessions = o.optLong("active_udp_sessions"),
                    bytesTx = o.optLongOrNull("bytes_tx"),
                    bytesRx = o.optLongOrNull("bytes_rx"),
                    lastRttMs = o.optLongOrNull("last_rtt_ms"),
                    dialFailures = o.optLong("dial_failures"),
                    drops = o.optLong("drops"),
                    state = o.optInt("state", VpnState.DISCONNECTED),
                )
            } catch (_: Exception) {
                TelemetryDto()
            }
        }

        /** Null when the engine has no value yet, so the UI shows "—". */
        private fun JSONObject.optLongOrNull(key: String): Long? =
            if (has(key) && !isNull(key)) optLong(key) else null
    }
}
