package com.beam.android.storage

/**
 * Pure-Kotlin config validators aligned with Rust `DnsUpstream::parse`
 * (`crates/beam-tun/src/dns.rs`) and `AndroidEngineConfig::validate`
 * (`crates/beam-android/src/config.rs`).
 *
 * Pure string parsing (no `InetAddress.getByName`) so callers on the UI thread
 * never trigger DNS lookups or StrictMode violations.
 */
object SettingsValidator {

    /** Mirrors `MAX_BYPASS_CIDRS` in `crates/beam-android/src/config.rs`. */
    const val MAX_BYPASS_CIDRS = 256
    private const val MAX_DOH_HOST_BYTES = 255
    private const val MAX_DOH_PATH_BYTES = 512

    /**
     * Trims and normalizes an `https://` DoH URL to match `DnsUpstream::parse`.
     * Returns the normalized URL (lowercase scheme) or `null` if invalid.
     */
    fun normalizeAndValidateDohUrl(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        if (trimmed.any { it.code < 0x20 || it.code == 0x7F || it == ' ' }) return null
        if (!trimmed.startsWith("https://", ignoreCase = true)) return null
        val rest = trimmed.substring("https://".length)
        if (rest.isEmpty()) return null

        val slashIdx = rest.indexOf('/')
        val authority = if (slashIdx >= 0) rest.substring(0, slashIdx) else rest
        val path = if (slashIdx >= 0) rest.substring(slashIdx) else "/dns-query"
        if (authority.isEmpty() || authority.contains('@')) return null
        if (!path.startsWith('/') || path.toByteArray(Charsets.UTF_8).size > MAX_DOH_PATH_BYTES) {
            return null
        }

        val parsed = splitHostPort(authority) ?: return null
        val (host, port, bracketed) = parsed
        if (host.isEmpty() || host.toByteArray(Charsets.UTF_8).size > MAX_DOH_HOST_BYTES) {
            return null
        }
        if (port != null && port !in 1..65535) return null
        // Mirrors Rust `split_host_port`: bracketed authorities must be IPv6 literals.
        if (bracketed) {
            if (!isIpv6Literal(host)) return null
        } else {
            if (!isValidDohHost(host)) return null
        }

        return "https://$rest"
    }

    /** Returns true when [host] is a strict literal IPv4 or IPv6 address (no DNS lookup). */
    fun isIpLiteral(host: String): Boolean {
        val trimmed = host.trim()
        if (trimmed.isEmpty()) return false
        if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
            return isIpv6Literal(trimmed.substring(1, trimmed.length - 1))
        }
        return if (trimmed.contains(':')) isIpv6Literal(trimmed) else isIpv4Literal(trimmed)
    }

    private fun isIpv4Literal(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            if (part.isEmpty() || part.length > 3) return false
            // Rust `Ipv4Addr::from_str` rejects leading zeros (e.g. "01").
            if (part.length > 1 && part[0] == '0') return false
            part.all(Char::isDigit) && (part.toIntOrNull() in 0..255)
        }
    }

    /** Strict RFC 4291 / Rust `Ipv6Addr::from_str` syntax check (pure Kotlin). */
    private fun isIpv6Literal(raw: String): Boolean {
        if (raw.isEmpty() || raw.contains('%')) return false
        val doubleColon = raw.indexOf("::")
        if (doubleColon >= 0 && raw.indexOf("::", doubleColon + 2) >= 0) return false

        val halves = if (doubleColon >= 0) {
            listOf(raw.substring(0, doubleColon), raw.substring(doubleColon + 2))
        } else {
            listOf(raw)
        }

        var groupCount = 0
        for ((halfIdx, half) in halves.withIndex()) {
            if (half.isEmpty()) continue
            val parts = half.split(':')
            for ((partIdx, part) in parts.withIndex()) {
                val isLastOverall = (halfIdx == halves.lastIndex) && (partIdx == parts.lastIndex)
                if (part.contains('.')) {
                    if (!isLastOverall || !isIpv4Literal(part)) return false
                    groupCount += 2
                } else {
                    if (part.isEmpty() || part.length > 4) return false
                    if (!part.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return false
                    groupCount += 1
                }
            }
        }
        return if (doubleColon >= 0) groupCount < 8 else groupCount == 8
    }

    private data class AuthorityParts(val host: String, val port: Int?, val bracketed: Boolean)

    private fun splitHostPort(authority: String): AuthorityParts? {
        if (authority.startsWith('[')) {
            val close = authority.indexOf(']')
            if (close < 0) return null
            val host = authority.substring(1, close)
            val tail = authority.substring(close + 1)
            if (tail.isEmpty()) return AuthorityParts(host, null, bracketed = true)
            if (!tail.startsWith(':')) return null
            val port = tail.substring(1).toIntOrNull() ?: return null
            return AuthorityParts(host, port, bracketed = true)
        }
        val colon = authority.indexOf(':')
        if (colon < 0) return AuthorityParts(authority, null, bracketed = false)
        // Multiple colons without brackets is not a valid host:port authority.
        if (authority.indexOf(':', colon + 1) >= 0) return null
        val host = authority.substring(0, colon)
        val port = authority.substring(colon + 1).toIntOrNull() ?: return null
        return AuthorityParts(host, port, bracketed = false)
    }

    private fun isValidDohHost(host: String): Boolean {
        if (isIpv4Literal(host)) return true
        if (host.startsWith('.') || host.endsWith('.') || host.contains("..")) return false
        val labels = host.split('.')
        return labels.all { label ->
            label.isNotEmpty() &&
                label.length <= 63 &&
                !label.startsWith('-') &&
                !label.endsWith('-') &&
                label.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }
        }
    }
}
