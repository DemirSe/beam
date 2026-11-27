package com.beam.android.vpn

/**
 * IPv4 prefix arithmetic for the `VpnService` route table.
 *
 * API 31-32 has no `excludeRoute`, so the bypass CIDRs must be turned into the
 * complement of `0.0.0.0/0`: the routes that still go through the tunnel.
 * Pure Kotlin on purpose so it runs in plain JVM unit tests.
 */
object Ipv4RouteCalculator {

    private const val ADDRESS_SPACE = 1L shl 32
    private const val HEX_DIGITS = "0123456789abcdefABCDEF"

    /**
     * Strict `address/prefix` check that matches the Rust `IpNet::parse_cidr`
     * used by the engine: dotted quads without leading zeros, no hostnames, no
     * zone ids. IPv6 input is accepted only when [allowIpv6] is set.
     */
    fun isValidCidr(cidr: String, allowIpv6: Boolean = false): Boolean {
        val text = cidr.trim()
        val slash = text.lastIndexOf('/')
        if (slash <= 0 || slash == text.length - 1) return false
        val prefixText = text.substring(slash + 1)
        if (prefixText.any { it !in '0'..'9' }) return false
        val prefix = prefixText.toIntOrNull() ?: return false
        val address = text.substring(0, slash)
        if (!address.contains(':')) return prefix in 0..32 && parseIpv4(address) != null
        return allowIpv6 && prefix in 0..128 && isIpv6Literal(address)
    }

    /** Strict RFC 4291 literal: hex groups, at most one `::`, optional IPv4 tail. */
    private fun isIpv6Literal(text: String): Boolean {
        if (text.isEmpty() || text.contains('%')) return false
        var body = text
        val tail = text.substringAfterLast(':')
        if (tail.contains('.')) {
            if (parseIpv4(tail) == null) return false
            // A trailing IPv4 address occupies the last two groups.
            body = text.removeSuffix(tail) + "0:0"
        }
        if (body.startsWith(':') && !body.startsWith("::")) return false
        if (body.endsWith(':') && !body.endsWith("::")) return false
        val gap = body.indexOf("::")
        if (gap >= 0 && body.indexOf("::", gap + 1) >= 0) return false
        val groups = body.split(':').filter { it.isNotEmpty() }
        if (groups.any { g -> g.length > 4 || g.any { it !in HEX_DIGITS } }) return false
        return if (gap >= 0) groups.size <= 7 else groups.size == 8
    }

    /** Routes that cover `0.0.0.0/0` except [excludes]. */
    fun subtractCidrs(excludes: List<String>): List<Pair<String, Int>> {
        val ranges = mutableListOf<LongRange>()
        for (cidr in excludes) {
            if (overlapsTunSubnet(cidr)) continue
            val (start, end) = parseCidr(cidr) ?: continue
            ranges += start..end
        }
        ranges.sortBy { it.first }

        val out = mutableListOf<Pair<String, Int>>()
        var cursor = 0L
        for (range in ranges) {
            if (range.first > cursor) out += toCidrs(cursor, range.first - 1)
            cursor = maxOf(cursor, range.last + 1)
        }
        if (cursor < ADDRESS_SPACE) out += toCidrs(cursor, ADDRESS_SPACE - 1)
        return out
    }

    /**
     * True when [cidr] is a valid IPv4 prefix that overlaps the TUN `/30`.
     * Such a prefix would bypass the TUN DNS server, so it is dropped.
     */
    fun overlapsTunSubnet(cidr: String): Boolean {
        val (start, end) = parseCidr(cidr) ?: return false
        val (tunStart, tunEnd) = parseCidr(VpnConfigBuilder.TUN_NETWORK_CIDR) ?: return false
        return start <= tunEnd && tunStart <= end
    }

    /** Smallest prefix list that covers exactly `from..to`. */
    private fun toCidrs(from: Long, to: Long): List<Pair<String, Int>> {
        val out = mutableListOf<Pair<String, Int>>()
        var start = from
        while (start <= to) {
            val alignment = java.lang.Long.numberOfTrailingZeros(start).coerceAtMost(32)
            var block = 1L shl alignment
            while (start + block - 1 > to) block = block shr 1
            out += (formatIpv4(start) to (32 - java.lang.Long.numberOfTrailingZeros(block)))
            start += block
        }
        return out
    }

    /** Strict dotted-quad CIDR parser: no DNS lookup, no octal or IPv6 input. */
    private fun parseCidr(cidr: String): Pair<Long, Long>? {
        val slash = cidr.lastIndexOf('/')
        if (slash <= 0) return null
        val address = parseIpv4(cidr.substring(0, slash).trim()) ?: return null
        val prefixText = cidr.substring(slash + 1).trim()
        if (prefixText.isEmpty() || prefixText.any { it !in '0'..'9' }) return null
        val prefix = prefixText.toIntOrNull() ?: return null
        if (prefix !in 0..32) return null
        val mask = if (prefix == 0) 0L else (0xFFFF_FFFFL shl (32 - prefix)) and 0xFFFF_FFFFL
        val start = address and mask
        val end = (start or mask.inv()) and 0xFFFF_FFFFL
        return start to end
    }
    private fun parseIpv4(text: String): Long? {
        val parts = text.split('.')
        if (parts.size != 4) return null
        var value = 0L
        for (part in parts) {
            if (part.isEmpty() || part.length > 3) return null
            if (part.length > 1 && part[0] == '0') return null
            if (part.any { it !in '0'..'9' }) return null
            val octet = part.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            value = (value shl 8) or octet.toLong()
        }
        return value
    }

    private fun formatIpv4(value: Long): String =
        "${value shr 24 and 0xFF}.${value shr 16 and 0xFF}.${value shr 8 and 0xFF}.${value and 0xFF}"
}
