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

    @Test
    fun `empty settings file is quarantined and reported`() {
        val file = tmp.newFile("settings.json")
        var thrown = false
        try {
            SettingsStore.loadFile(file)
        } catch (_: JSONException) {
            thrown = true
        }

        assertTrue(thrown)
        assertFalse(file.exists())
        assertEquals(1, quarantinedSnapshots().size)
    }

    @Test
    fun `quarantine keeps only the newest snapshots`() {
        // Real snapshot names use epoch millis, so the pruning order is numeric.
        val now = System.currentTimeMillis()
        val stamps = listOf(now - 4_000, now - 3_000, now - 2_000, now - 1_000)
        for (stamp in stamps) {
            tmp.newFile("settings.json.corrupt-$stamp").writeText("old$stamp")
        }
        val file = tmp.newFile("settings.json")
        file.writeText("{not json")

        try {
            SettingsStore.loadFile(file)
        } catch (_: JSONException) {
            // Expected: the caller sees the corruption, the file is quarantined.
        }

        val names = quarantinedSnapshots().map { it.name }.toSet()
        assertEquals(3, names.size)
        // Newest first, so the two oldest snapshots are deleted.
        assertTrue(names.contains("settings.json.corrupt-${now - 1_000}"))
        assertTrue(names.contains("settings.json.corrupt-${now - 2_000}"))
        assertFalse(names.contains("settings.json.corrupt-${now - 3_000}"))
        assertFalse(names.contains("settings.json.corrupt-${now - 4_000}"))
    }

    private fun quarantinedSnapshots(): List<java.io.File> = tmp.root.listFiles()
        .orEmpty()
        .filter { it.name.startsWith("settings.json.corrupt-") }
}
