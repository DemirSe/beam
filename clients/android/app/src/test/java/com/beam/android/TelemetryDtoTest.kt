package com.beam.android

import com.beam.android.vpn.TelemetryDto
import com.beam.android.vpn.VpnState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TelemetryDtoTest {

    @Test
    fun `parses full live telemetry payload`() {
        val json = """
            {
              "active_tcp_flows": 7,
              "active_udp_sessions": 2,
              "bytes_tx": 1048576,
              "bytes_rx": 8388608,
              "last_rtt_ms": 42,
              "dial_failures": 1,
              "drops": 3,
              "state": 2
            }
        """.trimIndent()
        val dto = TelemetryDto.fromJson(json)
        assertEquals(7L, dto.activeTcpFlows)
        assertEquals(2L, dto.activeUdpSessions)
        assertEquals(1048576L, dto.bytesTx)
        assertEquals(8388608L, dto.bytesRx)
        assertEquals(42L, dto.lastRttMs)
        assertEquals(1L, dto.dialFailures)
        assertEquals(3L, dto.drops)
        assertEquals(VpnState.CONNECTED, dto.state)
    }

    @Test
    fun `preserves null optional fields`() {
        val json = """
            {
              "active_tcp_flows": 0,
              "active_udp_sessions": 0,
              "bytes_tx": null,
              "bytes_rx": null,
              "last_rtt_ms": null,
              "dial_failures": 0,
              "drops": 0,
              "state": 0
            }
        """.trimIndent()
        val dto = TelemetryDto.fromJson(json)
        assertNull(dto.bytesTx)
        assertNull(dto.bytesRx)
        assertNull(dto.lastRttMs)
        assertEquals(VpnState.DISCONNECTED, dto.state)
    }

    @Test
    fun `falls back cleanly on blank or malformed json`() {
        assertEquals(TelemetryDto(), TelemetryDto.fromJson(""))
        assertEquals(TelemetryDto(), TelemetryDto.fromJson("   "))
        assertEquals(TelemetryDto(), TelemetryDto.fromJson("{not-json"))
    }
}
