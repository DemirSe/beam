package com.beam.android.storage

import org.json.JSONException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class SettingsStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun `valid settings file is parsed in place`() {
        val file = tmp.newFile("settings.json")
        file.writeText(
            """{"doh_url":"https://dns.nextdns.io","ipv4_only":false,"start_on_boot":true}""",
        )

        val settings = SettingsStore.loadFile(file)

        assertEquals(AppSettings.DOH_NEXTDNS, settings.dohUrl)
        assertFalse(settings.ipv4Only)
        assertTrue(settings.startOnBoot)
        assertTrue(file.exists())
    }

    @Test
    fun `corrupt settings file is quarantined and reported`() {
        val file = tmp.newFile("settings.json")
        file.writeText("{not json")

        var thrown = false
        try {
            SettingsStore.loadFile(file)
        } catch (_: JSONException) {
            thrown = true
        }

        assertTrue(thrown)
        assertFalse(file.exists())
        val quarantined = tmp.root.listFiles()
            .orEmpty()
            .filter { it.name.startsWith("settings.json.corrupt-") }
        assertEquals(1, quarantined.size)
        assertEquals("{not json", quarantined[0].readText())
    }
}
