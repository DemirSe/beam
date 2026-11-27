package com.beam.android.storage

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/**
 * Atomic JSON settings file in `filesDir`.
 *
 * NOT SharedPreferences: SharedPreferences is NOT multi-process safe across
 * the UI and `:vpn` processes. Every load and save holds `settings.lock` and
 * reads fresh bytes from disk.
 */
class SettingsStore(context: Context) {

    companion object {
        private const val TAG = "SettingsStore"
        private const val MAX_QUARANTINE_FILES = 3

        /**
         * Reads [file]. A corrupt file is quarantined before [JSONException]
         * reaches the caller, so one bad write cannot poison every later load.
         *
         * Caller must hold `settings.lock`. Keep free of `android.util.Log` so
         * JVM unit tests can exercise this path without Android framework mocks.
         */
        internal fun loadFile(file: File): AppSettings = try {
            parse(JSONObject(file.readText(Charsets.UTF_8)))
        } catch (e: JSONException) {
            quarantineCorrupt(file)
            throw e
        }

        private fun parse(o: JSONObject) = AppSettings(
            dohUrl = o.optString("doh_url", AppSettings.DEFAULT_DOH_URL),
            ipv4Only = o.optBoolean("ipv4_only", true),
            rejectQuic = o.optBoolean("reject_quic", true),
            bypassCidrs = o.optJSONArray("bypass_cidrs")?.let { arr ->
                List(arr.length()) { i -> arr.optString(i) }.filter { it.isNotBlank() }
            } ?: AppSettings.DEFAULT_BYPASS_CIDRS,
            startOnBoot = o.optBoolean("start_on_boot", false),
            treatAsUnmetered = o.optBoolean("treat_as_unmetered", false),
        )

        /** Keeps the most recent corrupt snapshots for diagnostics; deletes on rename failure. */
        private fun quarantineCorrupt(file: File) {
            val parent = file.parentFile
            val prefix = "${file.name}.corrupt-"
            val target = File(parent, "$prefix${System.currentTimeMillis()}")
            if (!file.renameTo(target)) file.delete()
            val snapshots = parent?.listFiles { f -> f.name.startsWith(prefix) } ?: return
            if (snapshots.size > MAX_QUARANTINE_FILES) {
                snapshots.sortedByDescending { it.name }
                    .drop(MAX_QUARANTINE_FILES)
                    .forEach { it.delete() }
            }
        }
    }

    private val dir: File = context.filesDir
    private val file = File(dir, "settings.json")
    private val lockFile = File(dir, "settings.lock")

    /**
     * Returns null only when the load failed for a transient reason. The file
     * is kept, so a later load can still succeed and the UI must not overwrite
     * it with defaults.
     */
    @Synchronized
    fun loadOrNull(): AppSettings? = withFileLock(lockFile) {
        if (!file.exists()) return@withFileLock AppSettings()
        try {
            loadFile(file)
        } catch (e: JSONException) {
            Log.w(TAG, "quarantined corrupt settings.json", e)
            AppSettings()
        } catch (e: Exception) {
            // Transient I/O: keep the file so a later load can still succeed.
            Log.w(TAG, "settings.json load failed", e)
            null
        }
    }

    @Synchronized
    fun load(): AppSettings = loadOrNull() ?: AppSettings()

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
