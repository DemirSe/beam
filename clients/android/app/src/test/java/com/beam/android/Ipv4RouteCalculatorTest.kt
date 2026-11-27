package com.beam.android.vpn

import com.beam.android.storage.AppSettings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Ipv4RouteCalculatorTest {

    @Test
    fun `no excludes routes everything`() {
        assertEquals(listOf("0.0.0.0" to 0), Ipv4RouteCalculator.subtractCidrs(emptyList()))
    }

    @Test
    fun `invalid and ipv6 entries are ignored`() {
        val invalid = listOf(
            "10.0.0.0",
            "10.0.0.0/33",
            "010.0.0.0/8",
            "999.1.1.1/8",
            "fd00::/8",
            "+1.2.3.4/8",
            "1.2.3.4/+8",
        )
        assertEquals(
            Ipv4RouteCalculator.subtractCidrs(emptyList()),
            Ipv4RouteCalculator.subtractCidrs(invalid),
        )
    }

    @Test
    fun `a single rfc1918 block is removed from the full space`() {
        assertEquals(
            listOf(
                "0.0.0.0" to 5,
                "8.0.0.0" to 7,
                "11.0.0.0" to 8,
                "12.0.0.0" to 6,
                "16.0.0.0" to 4,
                "32.0.0.0" to 3,
                "64.0.0.0" to 2,
                "128.0.0.0" to 1,
            ),
            Ipv4RouteCalculator.subtractCidrs(listOf("10.0.0.0/8")),
        )
    }

    @Test
    fun `adjacent halves merge into one prefix`() {
        assertEquals(
            Ipv4RouteCalculator.subtractCidrs(listOf("10.0.0.0/8")),
            Ipv4RouteCalculator.subtractCidrs(listOf("10.0.0.0/9", "10.128.0.0/9")),
        )
    }

    @Test
    fun `half space is subtracted exactly`() {
        assertEquals(
            listOf("128.0.0.0" to 1),
            Ipv4RouteCalculator.subtractCidrs(listOf("0.0.0.0/1")),
        )
    }

    @Test
    fun `cidrs that cover the tun subnet are dropped`() {
        // 198.19.0.0/30 must stay routed or TUN DNS breaks, so an excluding
        // supernet is ignored and the full space is returned.
        assertEquals(
            listOf("0.0.0.0" to 0),
            Ipv4RouteCalculator.subtractCidrs(listOf("0.0.0.0/0")),
        )
        assertEquals(
            Ipv4RouteCalculator.subtractCidrs(emptyList()),
            Ipv4RouteCalculator.subtractCidrs(listOf("198.18.0.0/15")),
        )
    }

    @Test
    fun `tun overlap detection`() {
        assertTrue(Ipv4RouteCalculator.overlapsTunSubnet("198.19.0.0/30"))
        assertTrue(Ipv4RouteCalculator.overlapsTunSubnet("198.19.0.2/32"))
        assertTrue(Ipv4RouteCalculator.overlapsTunSubnet("0.0.0.0/0"))
        assertFalse(Ipv4RouteCalculator.overlapsTunSubnet("198.19.0.4/30"))
        assertFalse(Ipv4RouteCalculator.overlapsTunSubnet("172.16.0.0/12"))
        assertFalse(Ipv4RouteCalculator.overlapsTunSubnet("not-a-cidr"))
    }

    @Test
    fun `tun subnet overlap and subtraction cover the edges`() {
        assertTrue(Ipv4RouteCalculator.overlapsTunSubnet(VpnConfigBuilder.TUN_NETWORK_CIDR))
        assertTrue(Ipv4RouteCalculator.overlapsTunSubnet("128.0.0.0/1"))
        assertTrue(Ipv4RouteCalculator.overlapsTunSubnet("198.19.0.2/32"))
        assertFalse(Ipv4RouteCalculator.overlapsTunSubnet("192.168.0.0/16"))

        // Every overlapping prefix is ignored, so the TUN DNS stays routed.
        assertEquals(
            listOf("0.0.0.0" to 0),
            Ipv4RouteCalculator.subtractCidrs(
                listOf("198.19.0.0/30", "128.0.0.0/1", "198.19.0.2/32"),
            ),
        )

        // A LAN prefix that does not overlap is subtracted from the tunnel routes.
        val ranges = Ipv4RouteCalculator.subtractCidrs(listOf("192.168.0.0/16")).map(::rangeOf)
        val lan = ipToLong("192.168.0.0")..ipToLong("192.168.255.255")
        assertFalse(ranges.any { it.first <= lan.last && lan.first <= it.last })
        assertEquals((1L shl 32) - 65536, ranges.sumOf { it.last - it.first + 1 })
    }

    @Test
    fun `default bypass complement is disjoint, sorted and complete`() {
        val ranges = Ipv4RouteCalculator.subtractCidrs(AppSettings.DEFAULT_BYPASS_CIDRS)
            .map(::rangeOf)

        ranges.zipWithNext().forEach { (a, b) -> assertTrue(a.last < b.first) }

        val excluded = (1L shl 24) + (1L shl 20) + (1L shl 16)
        assertEquals((1L shl 32) - excluded, ranges.sumOf { it.last - it.first + 1 })

        listOf("10.1.2.3", "172.20.0.1", "192.168.1.1").forEach { ip ->
            val value = ipToLong(ip)
            assertFalse(ranges.any { value in it })
        }
        // TUN DNS stays inside a tunnel route.
        assertTrue(ranges.any { ipToLong("198.19.0.2") in it })
    }

    @Test
    fun `strict cidr validation matches the engine parser`() {
        assertTrue(Ipv4RouteCalculator.isValidCidr("10.0.0.0/8"))
        assertTrue(Ipv4RouteCalculator.isValidCidr("0.0.0.0/0"))
        assertTrue(Ipv4RouteCalculator.isValidCidr("198.19.0.2/32"))
        assertTrue(Ipv4RouteCalculator.isValidCidr("  10.0.0.0/8  "))

        assertFalse(Ipv4RouteCalculator.isValidCidr("10.0.0.0"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("010.0.0.0/8"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("10.0.0.0/33"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("10.0.0.0/-1"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("256.0.0.0/8"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("10.0.0/8"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("10.0.0.0/8/8"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("10.0.0.0/"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("example.com/8"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("+1.2.3.4/8"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("1.+2.3.4/8"))
        assertFalse(Ipv4RouteCalculator.isValidCidr("1.2.3.4/+8"))
    }

    @Test
    fun `ipv6 cidrs need the opt-in and a valid literal`() {
        assertFalse(Ipv4RouteCalculator.isValidCidr("fd00::/8"))
        assertTrue(Ipv4RouteCalculator.isValidCidr("fd00::/8", allowIpv6 = true))
        assertTrue(Ipv4RouteCalculator.isValidCidr("::/0", allowIpv6 = true))
        assertTrue(Ipv4RouteCalculator.isValidCidr("2001:db8::/32", allowIpv6 = true))
        assertTrue(Ipv4RouteCalculator.isValidCidr("::ffff:1.2.3.4/128", allowIpv6 = true))
        assertTrue(
            Ipv4RouteCalculator.isValidCidr("2001:db8:0:0:0:0:0:1/128", allowIpv6 = true),
        )

        assertFalse(Ipv4RouteCalculator.isValidCidr("fd00::/129", allowIpv6 = true))
        assertFalse(Ipv4RouteCalculator.isValidCidr("fd00::zz/8", allowIpv6 = true))
        assertFalse(Ipv4RouteCalculator.isValidCidr("1::2::3/64", allowIpv6 = true))
        assertFalse(Ipv4RouteCalculator.isValidCidr(":::", allowIpv6 = true))
        assertFalse(Ipv4RouteCalculator.isValidCidr("1:2:3:4:5:6:7/64", allowIpv6 = true))
        assertFalse(
            Ipv4RouteCalculator.isValidCidr("::1:2:3:4:5:6:7:8/64", allowIpv6 = true),
        )
        assertFalse(Ipv4RouteCalculator.isValidCidr("fe80::1%wlan0/64", allowIpv6 = true))
        assertFalse(Ipv4RouteCalculator.isValidCidr("1:2:3:4:5:6:7:8:/64", allowIpv6 = true))
    }

    private fun rangeOf(route: Pair<String, Int>): LongRange {
        val start = ipToLong(route.first)
        return start..(start + (1L shl (32 - route.second)) - 1)
    }

    private fun ipToLong(ip: String): Long =
        ip.split('.').fold(0L) { acc, part -> (acc shl 8) or part.toLong() }
}
