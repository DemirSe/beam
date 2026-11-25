package com.beam.android.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AppSettingsTest {

    @Test
    fun `mobile defaults lock down leaks`() {
        val s = AppSettings()
        assertEquals(AppSettings.DEFAULT_DOH_URL, s.dohUrl)
        assertEquals(AppSettings.DOH_CLOUDFLARE, s.dohUrl)
        assertTrue(s.ipv4Only)
        assertTrue(s.rejectQuic)
    }

    @Test
    fun `default bypass covers RFC1918`() {
        assertEquals(
            listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
            AppSettings.DEFAULT_BYPASS_CIDRS,
        )
    }

    @Test
    fun `doh presets are https`() {
        assertTrue(AppSettings.DOH_CLOUDFLARE.startsWith("https://"))
        assertTrue(AppSettings.DOH_NEXTDNS.startsWith("https://"))
    }
}
