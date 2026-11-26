package com.beam.android.storage

import java.io.IOException
import java.security.KeyStoreException
import java.security.ProviderException
import javax.crypto.AEADBadTagException
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
    }

    @Test
    fun `corrupt ciphertext and JSON errors are classified as permanent corruption`() {
        assertTrue(EncryptedProfileStore.isPermanentCorruption(AEADBadTagException("bad tag")))
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
}
