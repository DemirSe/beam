package com.beam.android.storage

data class VlessProfile(
    val id: String,
    val name: String,
    val uri: String,
    val serverHost: String,
    val serverPort: Int,
    val createdAtMs: Long,
)

data class AppSettings(
    val dohUrl: String = DEFAULT_DOH_URL,
    val ipv4Only: Boolean = true,
    val rejectQuic: Boolean = true,
    val bypassCidrs: List<String> = DEFAULT_BYPASS_CIDRS,
    val startOnBoot: Boolean = false,
) {
    companion object {
        const val DOH_CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
        const val DOH_NEXTDNS = "https://dns.nextdns.io"
        const val DEFAULT_DOH_URL = DOH_CLOUDFLARE
        val DEFAULT_BYPASS_CIDRS: List<String> = listOf(
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        )
    }
}
