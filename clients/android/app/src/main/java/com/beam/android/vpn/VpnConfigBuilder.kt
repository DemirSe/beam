package com.beam.android.vpn

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
