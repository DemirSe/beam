package com.beam.android.storage

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import java.io.File
import java.io.FileOutputStream
import javax.crypto.AEADBadTagException
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/**
 * Keystore AES-256-GCM encrypted profile store (key alias `beam_profiles_v1`).
 *
 * Multi-process safe: UI and `:vpn` are separate processes, so every public
 * call holds one file lock across the whole read-modify-write, reads fresh
 * bytes from disk, and writes atomic temp-file + rename. Never caches.
 */
class EncryptedProfileStore(context: Context) {

    private val dir: File = context.filesDir
    private val dataFile = File(dir, "profiles.enc")
    private val lockFile = File(dir, "profiles.lock")

    @Synchronized
    fun listProfiles(): List<VlessProfile> = withFileLock(lockFile) { readAll() }

    @Synchronized
    fun listProfilesWithActiveId(): Pair<List<VlessProfile>, String?> = withFileLock(lockFile) {
        parseProfilesWithActiveId(readPayload())
    }

    @Synchronized
    fun getProfile(id: String): VlessProfile? =
        withFileLock(lockFile) { readAll().find { it.id == id } }

    @Synchronized
    fun saveProfile(profile: VlessProfile) = withFileLock(lockFile) {
        val payload = readPayload()
        val all = readAll(payload).filterNot { it.id == profile.id } + profile
        writeAll(all, activeIdOf(payload))
    }

    @Synchronized
    fun saveProfileAndActivateIfNone(profile: VlessProfile) = withFileLock(lockFile) {
        val payload = readPayload()
        val all = readAll(payload).filterNot { it.id == profile.id } + profile
        val active = resolveActiveIdAfterSave(activeIdOf(payload), profile.id)
        writeAll(all, active)
    }

    @Synchronized
    fun deleteProfile(id: String) = withFileLock(lockFile) {
        val payload = readPayload()
        val all = readAll(payload).filterNot { it.id == id }
        // If the deleted profile was active (or none was set), fall back to
        // the first remaining profile so :vpn always has a valid target.
        val active = activeIdOf(payload).takeIf { it != id && all.any { p -> p.id == it } }
            ?: all.firstOrNull()?.id
        writeAll(all, active)
    }

    @Synchronized
    fun getActiveProfileId(): String? =
        withFileLock(lockFile) { activeIdOf(readPayload()) }

    @Synchronized
    fun setActiveProfileId(id: String?) = withFileLock(lockFile) {
        val payload = readPayload()
        if (activeIdOf(payload) == id) return@withFileLock
        writeAll(readAll(payload), id)
    }

    /**
     * Persists [id] as the active profile if it still exists in the store,
     * skipping re-encryption when [id] is already active.
     */
    @Synchronized
    fun setActiveProfileIdIfExists(id: String): Boolean = withFileLock(lockFile) {
        val payload = readPayload()
        val all = readAll(payload)
        if (all.none { it.id == id }) return@withFileLock false
        if (activeIdOf(payload) != id) {
            writeAll(all, id)
        }
        true
    }

    @Synchronized
    fun getActiveProfile(): VlessProfile? = withFileLock(lockFile) {
        val payload = readPayload()
        val activeId = activeIdOf(payload) ?: return@withFileLock null
        readAll(payload).find { it.id == activeId }
    }

    private fun readAll(payload: JSONObject? = readPayload()): List<VlessProfile> =
        parseProfiles(payload)

    private fun writeAll(profiles: List<VlessProfile>, activeId: String?) {
        val arr = JSONArray()
        for (p in profiles) {
            arr.put(
                JSONObject()
                    .put("id", p.id)
                    .put("name", p.name)
                    .put("uri", p.uri)
                    .put("server_host", p.serverHost)
                    .put("server_port", p.serverPort)
                    .put("created_at_ms", p.createdAtMs),
            )
        }
        val payload = JSONObject()
            .put("profiles", arr)
            .put("active_id", activeId)
            .toString()
        val tmp = File(dir, "profiles.enc.tmp")
        val encrypted = ProfileCrypto.encrypt(payload.toByteArray(Charsets.UTF_8))
        FileOutputStream(tmp).use { out ->
            out.write(encrypted)
            out.flush()
            out.fd.sync()
        }
        if (!tmp.renameTo(dataFile)) {
            tmp.delete()
            throw IllegalStateException("atomic profile write failed")
        }
    }

    private fun readPayload(): JSONObject? {
        if (!dataFile.exists()) return null
        val bytes: ByteArray = dataFile.readBytes()
        if (bytes.isEmpty()) return null
        return try {
            JSONObject(String(ProfileCrypto.decrypt(bytes), Charsets.UTF_8))
        } catch (e: Exception) {
            // Only quarantine on permanent ciphertext/key/JSON corruption.
            // Transient Keystore/TEE hiccups must rethrow without wiping profiles.enc.
            if (isPermanentCorruption(e)) {
                quarantineCorruptStore()
                null
            } else {
                throw e
            }
        }
    }

    /**
     * Parks an unreadable blob (corrupt file or a regenerated Keystore key) so
     * the next save writes a fresh one instead of failing forever.
     */
    private fun quarantineCorruptStore() {
        val target = File(dir, "profiles.enc.corrupt-${System.currentTimeMillis()}")
        val moved = runCatching { dataFile.renameTo(target) }.getOrDefault(false)
        if (!moved) runCatching { dataFile.delete() }
    }

    internal companion object {
        fun isPermanentCorruption(e: Throwable): Boolean =
            e is AEADBadTagException ||
                e is KeyPermanentlyInvalidatedException ||
                e is IllegalArgumentException ||
                e is JSONException

        fun activeIdOf(payload: JSONObject?): String? =
            payload?.optString("active_id")?.ifBlank { null }

        fun parseProfilesWithActiveId(payload: JSONObject?): Pair<List<VlessProfile>, String?> =
            parseProfiles(payload) to activeIdOf(payload)

        fun resolveActiveIdAfterSave(currentActiveId: String?, savedProfileId: String): String =
            currentActiveId?.ifBlank { null } ?: savedProfileId

        fun parseProfiles(payload: JSONObject?): List<VlessProfile> {
            if (payload == null) return emptyList()
            val out = mutableListOf<VlessProfile>()
            val arr = payload.optJSONArray("profiles") ?: JSONArray()
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val id = o.optString("id")
                val uri = o.optString("uri")
                if (id.isBlank() || uri.isBlank()) continue
                out += VlessProfile(
                    id = id,
                    name = o.optString("name"),
                    uri = uri,
                    serverHost = o.optString("server_host"),
                    serverPort = o.optInt("server_port", 443),
                    createdAtMs = o.optLong("created_at_ms"),
                )
            }
            return out
        }
    }
}
