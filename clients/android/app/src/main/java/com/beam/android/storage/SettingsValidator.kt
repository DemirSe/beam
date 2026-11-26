package com.beam.android.storage

import java.net.InetAddress

/**
 * Pure-Kotlin config validators aligned with Rust `DnsUpstream::parse`
 * (`crates/beam-tun/src/dns.rs`) and `AndroidEngineConfig::validate`
 * (`crates/beam-android/src/config.rs`).
 */
object SettingsValidator {

    /** Mirrors `MAX_BYPASS_CIDRS` in `crates/beam-android/src/config.rs`. */
    const val MAX_BYPASS_CIDRS = 256
    private const val MAX_DOH_HOST_LEN = 255
    private const val MAX_DOH_PATH_LEN = 512

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
        if (!path.startsWith('/') || path.length > MAX_DOH_PATH_LEN) return null

        val (host, port) = splitHostPort(authority) ?: return null
        if (host.isEmpty() || host.length > MAX_DOH_HOST_LEN) return null
        if (port != null && port !in 1..65535) return null
        if (!isValidDohHost(host)) return null

        return "https://$rest"
    }

    /** Returns true when [host] is a literal IPv4 or IPv6 address (no DNS lookup needed). */
    fun isIpLiteral(host: String): Boolean {
        val clean = host.trim().removePrefix("[").removeSuffix("]")
        if (clean.isEmpty()) return false
        if (clean.contains(':')) {
            // IPv6 literal: hex digits, colons, optional embedded IPv4 dots.
            if (!clean.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) {
                return false
            }
            return runCatching { InetAddress.getByName(clean) }.isSuccess
        }
        val parts = clean.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit) &&
                (part.toIntOrNull() in 0..255)
        }
    }

    private fun splitHostPort(authority: String): Pair<String, Int?>? {
        if (authority.startsWith('[')) {
            val close = authority.indexOf(']')
            if (close < 0) return null
            val host = authority.substring(1, close)
            val tail = authority.substring(close + 1)
            if (tail.isEmpty()) return host to null
            if (!tail.startsWith(':')) return null
            val port = tail.substring(1).toIntOrNull() ?: return null
            return host to port
        }
        val colon = authority.indexOf(':')
        if (colon < 0) return authority to null
        // Multiple colons without brackets is not a valid host:port authority.
        if (authority.indexOf(':', colon + 1) >= 0) return null
        val host = authority.substring(0, colon)
        val port = authority.substring(colon + 1).toIntOrNull() ?: return null
        return host to port
    }

    private fun isValidDohHost(host: String): Boolean {
        if (isIpLiteral(host)) return true
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
