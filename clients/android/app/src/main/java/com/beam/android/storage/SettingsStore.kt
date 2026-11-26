package com.beam.android.storage

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import org.json.JSONArray
import org.json.JSONObject

/**
 * Atomic JSON settings file in `filesDir`.
 *
 * NOT SharedPreferences: SharedPreferences is NOT multi-process safe across
 * the UI and `:vpn` processes. Every load and save holds `settings.lock` and
 * reads fresh bytes from disk.
 */
class SettingsStore(context: Context) {

    private val dir: File = context.filesDir
    private val file = File(dir, "settings.json")
    private val lockFile = File(dir, "settings.lock")

    @Synchronized
    fun load(): AppSettings = withFileLock(lockFile) {
        if (!file.exists()) return@withFileLock AppSettings()
        try {
            val o = JSONObject(file.readText(Charsets.UTF_8))
            AppSettings(
                dohUrl = o.optString("doh_url", AppSettings.DEFAULT_DOH_URL),
                ipv4Only = o.optBoolean("ipv4_only", true),
                rejectQuic = o.optBoolean("reject_quic", true),
                bypassCidrs = o.optJSONArray("bypass_cidrs")?.let { arr ->
                    List(arr.length()) { i -> arr.optString(i) }.filter { it.isNotBlank() }
                } ?: AppSettings.DEFAULT_BYPASS_CIDRS,
                startOnBoot = o.optBoolean("start_on_boot", false),
                treatAsUnmetered = o.optBoolean("treat_as_unmetered", false),
            )
        } catch (_: Exception) {
            AppSettings()
        }
    }

    @Synchronized
    fun save(settings: AppSettings) = withFileLock(lockFile) {
        val json = JSONObject()
            .put("doh_url", settings.dohUrl)
            .put("ipv4_only", settings.ipv4Only)
            .put("reject_quic", settings.rejectQuic)
            .put("bypass_cidrs", JSONArray(settings.bypassCidrs))
            .put("start_on_boot", settings.startOnBoot)
            .put("treat_as_unmetered", settings.treatAsUnmetered)
            .toString()
        val tmp = File(dir, "settings.json.tmp")
        val bytes = json.toByteArray(Charsets.UTF_8)
        FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.flush()
            out.fd.sync()
        }
        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw IllegalStateException("atomic settings write failed")
        }
    }
}
