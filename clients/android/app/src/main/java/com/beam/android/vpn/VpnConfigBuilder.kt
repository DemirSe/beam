package com.beam.android.vpn

import com.beam.android.storage.AppSettings
import com.beam.android.storage.SettingsValidator
import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds the JSON config consumed by the Rust AndroidEngineConfig.
 * Schema: vless_uri, mtu, tun_name, tun_ipv4, tun_dns_ipv4, doh_url,
 * ipv4_only, reject_ipv6, reject_quic, bypass_cidrs, server_ip, log_level.
 */
object VpnConfigBuilder {
    const val MTU = 1500
    // 198.19.0.0/30 is outside the RFC 1918 bypass defaults, so the TUN DNS
    // server can never be reached through a bypass route.
    const val TUN_IPV4 = "198.19.0.1"
    const val TUN_DNS_IPV4 = "198.19.0.2"
    const val TUN_PREFIX = 30
    const val TUN_NETWORK_CIDR = "198.19.0.0/30"

    /**
     * Returns the DoH URL to hand to the engine and whether it was replaced by
     * the default. A blank URL stays blank on purpose: the engine then runs
     * without the DNS interceptor.
     */
    fun sanitizeDohUrl(raw: String): Pair<String, Boolean> {
        if (raw.isBlank()) return "" to false
        val normalized = SettingsValidator.normalizeAndValidateDohUrl(raw)
            ?: return AppSettings.DEFAULT_DOH_URL to true
        return normalized to false
    }

    /**
     * Drops entries the engine config or route table would reject: blanks,
     * malformed CIDRs, `/0` (it would capture all traffic) and prefixes that
     * overlap the TUN subnet, which would bypass the TUN DNS server.
     *
     * IPv6 prefixes are kept only when [allowIpv6] is set: API 31-32 routes the
     * IPv4 complement and cannot honour them.
     */
    fun sanitizeBypassCidrs(
        cidrs: List<String>,
        allowIpv6: Boolean = true,
    ): List<String> = cidrs
        .map { it.trim() }
        .filter {
            it.isNotEmpty() &&
                it.substringAfterLast('/').toIntOrNull() != 0 &&
                Ipv4RouteCalculator.isValidCidr(it, allowIpv6 = allowIpv6) &&
                !Ipv4RouteCalculator.overlapsTunSubnet(it)
        }
        .take(SettingsValidator.MAX_BYPASS_CIDRS)

    fun buildConfigJson(
        vlessUri: String,
        dohUrl: String,
        ipv4Only: Boolean,
        rejectQuic: Boolean,
        bypassCidrs: List<String>,
        serverIp: String? = null,
        logLevel: String = "info",
    ): String {
        val json = JSONObject()
            .put("vless_uri", vlessUri)
            .put("mtu", MTU)
            .put("tun_name", "beam0")
            .put("tun_ipv4", TUN_IPV4)
            .put("tun_dns_ipv4", TUN_DNS_IPV4)
            .put("doh_url", dohUrl)
            .put("ipv4_only", ipv4Only)
            .put("reject_ipv6", ipv4Only)
            .put("reject_quic", rejectQuic)
            .put("bypass_cidrs", JSONArray(bypassCidrs))
            .put("log_level", logLevel)
        // Pre-resolved before the TUN exists; omitted when resolution failed.
        if (serverIp != null) json.put("server_ip", serverIp)
        return json.toString()
    }
}
