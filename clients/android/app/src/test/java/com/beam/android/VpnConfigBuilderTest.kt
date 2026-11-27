package com.beam.android.vpn

import com.beam.android.storage.AppSettings
import com.beam.android.storage.SettingsValidator
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnConfigBuilderTest {

    @Test
    fun `build emits Rust AndroidEngineConfig schema`() {
        val json = VpnConfigBuilder.buildConfigJson(
            vlessUri = "vless://uuid@example.com:443?security=reality#t",
            dohUrl = "https://cloudflare-dns.com/dns-query",
            ipv4Only = true,
            rejectQuic = true,
            bypassCidrs = listOf("10.0.0.0/8"),
            serverIp = "203.0.113.10",
        )
        val o = JSONObject(json)
        assertEquals("vless://uuid@example.com:443?security=reality#t", o.getString("vless_uri"))
        assertEquals(1500, o.getInt("mtu"))
        assertEquals("beam0", o.getString("tun_name"))
        assertEquals("198.19.0.1", o.getString("tun_ipv4"))
        assertEquals("198.19.0.2", o.getString("tun_dns_ipv4"))
        assertEquals("https://cloudflare-dns.com/dns-query", o.getString("doh_url"))
        assertTrue(o.getBoolean("ipv4_only"))
        assertTrue(o.getBoolean("reject_ipv6"))
        assertTrue(o.getBoolean("reject_quic"))
        val cidrs: JSONArray = o.getJSONArray("bypass_cidrs")
        assertEquals(1, cidrs.length())
        assertEquals("10.0.0.0/8", cidrs.getString(0))
        assertEquals("203.0.113.10", o.getString("server_ip"))
        assertEquals("info", o.getString("log_level"))
    }

    @Test
    fun `unresolved server host omits server_ip`() {
        val o = JSONObject(
            VpnConfigBuilder.buildConfigJson(
                vlessUri = "vless://x",
                dohUrl = "https://dns.nextdns.io",
                ipv4Only = true,
                rejectQuic = false,
                bypassCidrs = emptyList(),
            ),
        )
        assertFalse(o.has("server_ip"))
    }

    @Test
    fun `ipv4Only false leaves ipv6 path open`() {
        val o = JSONObject(
            VpnConfigBuilder.buildConfigJson(
                "vless://x", "https://dns.nextdns.io", false, false, emptyList(),
            ),
        )
        assertEquals(false, o.getBoolean("ipv4_only"))
        assertEquals(false, o.getBoolean("reject_ipv6"))
    }

    @Test
    fun `invalid stored doh url falls back to the default`() {
        assertEquals(
            AppSettings.DEFAULT_DOH_URL to true,
            VpnConfigBuilder.sanitizeDohUrl("http://not-https.example/dns-query"),
        )
        assertEquals(
            AppSettings.DEFAULT_DOH_URL to true,
            VpnConfigBuilder.sanitizeDohUrl("sentinel.invalid"),
        )
    }

    @Test
    fun `blank doh url stays blank so dns interception stays off`() {
        assertEquals("" to false, VpnConfigBuilder.sanitizeDohUrl(""))
        assertEquals("" to false, VpnConfigBuilder.sanitizeDohUrl("   "))
        assertEquals(
            AppSettings.DOH_NEXTDNS to false,
            VpnConfigBuilder.sanitizeDohUrl("  ${AppSettings.DOH_NEXTDNS}  "),
        )
    }

    @Test
    fun `sanitize drops invalid tun overlapping and default routes`() {
        val input = listOf(
            "10.0.0.0/8",
            " 192.168.0.0/16 ",
            "not-a-cidr",
            "10.0.0.0/33",
            "198.19.0.2/32",
            "0.0.0.0/0",
            "::/0",
            "::/00",
            "fd00:be:a::/0",
            "",
        )
        assertEquals(
            listOf("10.0.0.0/8", "192.168.0.0/16"),
            VpnConfigBuilder.sanitizeBypassCidrs(input),
        )
    }

    @Test
    fun `sanitize caps bypass entries at the engine limit`() {
        val many = List(SettingsValidator.MAX_BYPASS_CIDRS + 5) { "10.0.0.0/8" }
        assertEquals(
            SettingsValidator.MAX_BYPASS_CIDRS,
            VpnConfigBuilder.sanitizeBypassCidrs(many).size,
        )
    }

    @Test
    fun `ipv6 bypass needs api 33 where exclude route exists`() {
        val input = listOf("10.0.0.0/8", "fd00::/8")
        assertEquals(
            listOf("10.0.0.0/8"),
            VpnConfigBuilder.sanitizeBypassCidrs(input, allowIpv6 = false),
        )
        assertEquals(input, VpnConfigBuilder.sanitizeBypassCidrs(input))
    }

    @Test
    fun `recommended tcp cap scales with device ram`() {
        val gib = 1024L * 1024 * 1024
        assertEquals(128, VpnConfigBuilder.recommendedMaxTcpConnections(0L))
        assertEquals(128, VpnConfigBuilder.recommendedMaxTcpConnections(4L * gib))
        assertEquals(256, VpnConfigBuilder.recommendedMaxTcpConnections(6L * gib))
        assertEquals(256, VpnConfigBuilder.recommendedMaxTcpConnections(8L * gib))

        val json = VpnConfigBuilder.buildConfigJson(
            vlessUri = "vless://example",
            dohUrl = AppSettings.DEFAULT_DOH_URL,
            ipv4Only = true,
            rejectQuic = true,
            bypassCidrs = emptyList(),
            maxTcpConnections = 256,
        )
        assertEquals(256, org.json.JSONObject(json).getInt("max_tcp_connections"))
    }
}

class TelemetryDtoTest {

    @Test
    fun `fromJson parses engine snapshot`() {
        val dto = TelemetryDto.fromJson(
            """{"active_tcp_flows":3,"active_udp_sessions":5,"bytes_tx":100,"bytes_rx":200,"last_rtt_ms":42,"dial_failures":1,"drops":2,"state":2}""",
        )
        assertEquals(3, dto.activeTcpFlows)
        assertEquals(5, dto.activeUdpSessions)
        assertEquals(100L, dto.bytesTx)
        assertEquals(200L, dto.bytesRx)
        assertEquals(42L, dto.lastRttMs)
        assertEquals(1, dto.dialFailures)
        assertEquals(2, dto.drops)
        assertEquals(VpnState.CONNECTED, dto.state)
    }

    @Test
    fun `fromJson tolerates blank, garbage and null counters`() {
        assertEquals(TelemetryDto(), TelemetryDto.fromJson(""))
        assertEquals(TelemetryDto(), TelemetryDto.fromJson("not json"))
        assertNull(TelemetryDto.fromJson("{}").lastRttMs)
        val idle = TelemetryDto.fromJson(
            """{"bytes_tx":null,"bytes_rx":null,"last_rtt_ms":null,"state":0}""",
        )
        assertNull(idle.bytesTx)
        assertNull(idle.bytesRx)
        assertNull(idle.lastRttMs)
    }

    @Test
    fun `state ordinals match contract`() {
        assertEquals(0, VpnState.DISCONNECTED)
        assertEquals(1, VpnState.CONNECTING)
        assertEquals(2, VpnState.CONNECTED)
        assertEquals(3, VpnState.DEGRADED)
        assertEquals(4, VpnState.DISCONNECTING)
    }
}
