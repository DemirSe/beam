package com.beam.android.storage

import java.io.IOException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.ProviderException
import javax.crypto.BadPaddingException
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptedProfileStoreLogicTest {

    @Test
    fun `transient Keystore errors are not classified as permanent corruption`() {
        assertFalse(EncryptedProfileStore.isPermanentCorruption(KeyStoreException("TEE busy")))
        assertFalse(EncryptedProfileStore.isPermanentCorruption(ProviderException("KeyMint transient")))
        assertFalse(EncryptedProfileStore.isPermanentCorruption(IOException("disk busy")))
        // InvalidKeyException also covers permanent invalidation, which is
        // matched by type before this fallback.
        assertFalse(EncryptedProfileStore.isPermanentCorruption(InvalidKeyException("key busy")))
    }

    @Test
    fun `corrupt ciphertext and JSON errors are classified as permanent corruption`() {
        // BadPaddingException also covers its AEADBadTagException subclass.
        assertTrue(EncryptedProfileStore.isPermanentCorruption(BadPaddingException("bad tag")))
        assertTrue(EncryptedProfileStore.isPermanentCorruption(IllegalArgumentException("ciphertext too short")))
        assertTrue(EncryptedProfileStore.isPermanentCorruption(JSONException("malformed json")))
    }

    @Test
    fun `parseProfiles skips malformed entries with blank id or uri`() {
        val arr = JSONArray()
            .put(JSONObject().put("id", "").put("uri", "vless://valid"))
            .put(JSONObject().put("id", "p1").put("uri", "   "))
            .put(
                JSONObject()
                    .put("id", "p2")
                    .put("name", "Good")
                    .put("uri", "vless://uuid@1.2.3.4:443")
                    .put("server_host", "1.2.3.4")
                    .put("server_port", 443)
                    .put("created_at_ms", 123L),
            )
        val payload = JSONObject().put("profiles", arr)
        val parsed = EncryptedProfileStore.parseProfiles(payload)
        assertEquals(1, parsed.size)
        assertEquals("p2", parsed[0].id)
        assertEquals("Good", parsed[0].name)
    }

    @Test
    fun `parseProfilesWithActiveId returns profiles and active id in one pass`() {
        val arr = JSONArray().put(
            JSONObject()
                .put("id", "p1")
                .put("name", "One")
                .put("uri", "vless://uuid@1.2.3.4:443")
                .put("server_host", "1.2.3.4")
                .put("server_port", 443)
                .put("created_at_ms", 10L),
        )
        val payload = JSONObject().put("profiles", arr).put("active_id", "p1")
        val (profiles, activeId) = EncryptedProfileStore.parseProfilesWithActiveId(payload)
        assertEquals(1, profiles.size)
        assertEquals("p1", activeId)
    }

    @Test
    fun `resolveActiveIdAfterSave activates saved profile only when none is active`() {
        val ids = setOf("existing", "p1", "p2")
        assertEquals("p1", EncryptedProfileStore.resolveActiveIdAfterSave(null, "p1", ids))
        assertEquals("p1", EncryptedProfileStore.resolveActiveIdAfterSave("   ", "p1", ids))
        assertEquals(
            "existing",
            EncryptedProfileStore.resolveActiveIdAfterSave("existing", "p2", ids),
        )
    }

    @Test
    fun `resolveActiveIdAfterSave replaces a dangling active id`() {
        // The stored active id pointed at a profile that is already gone; the
        // freshly saved profile must become active instead of leaving a hole.
        assertEquals(
            "p2",
            EncryptedProfileStore.resolveActiveIdAfterSave("deleted", "p2", setOf("p2")),
        )
    }
}
