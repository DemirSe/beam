package com.beam.android

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.beam.android.storage.AppSettings
import com.beam.android.storage.EncryptedProfileStore
import com.beam.android.storage.SettingsStore
import com.beam.android.storage.VlessProfile
import com.beam.android.vpn.BeamNativeBridge
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Emulator smoke test: proves libbeam_android.so loads through JNI and the
 * stores work against the real Android Keystore. Runs only on a device
 * (`connectedDebugAndroidTest`).
 */
@RunWith(AndroidJUnit4::class)
class NativeBridgeSmokeTest {

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun nativeParseVlessLinkAcceptsRealityLink() {
        val json = BeamNativeBridge.nativeParseVlessLink(VALID_LINK)
        assertNotNull("nativeParseVlessLink returned null", json)
        val parsed = JSONObject(json!!)
        assertTrue("parse failed: $json", parsed.optBoolean("ok"))
        assertEquals("203.0.113.10", parsed.optString("server"))
        assertEquals(443, parsed.optInt("port"))
        assertEquals("whatsapp.net", parsed.optString("sni"))
        // The bridge must never echo the UUID or the link itself.
        assertFalse(json.contains(UUID))
        assertFalse(json.contains("WlpaWlpa"))
    }

    @Test
    fun nativeParseVlessLinkRejectsInvalidLink() {
        val json = BeamNativeBridge.nativeParseVlessLink("vless://$UUID@:443")
        assertNotNull("nativeParseVlessLink returned null", json)
        assertFalse(JSONObject(json!!).optBoolean("ok"))
        assertFalse(json.contains(UUID))
    }

    @Test
    fun encryptedProfileStoreRoundTripsThroughKeystore() {
        val store = EncryptedProfileStore(context)
        val profile = VlessProfile(
            id = "smoke-$UUID",
            name = "smoke",
            uri = VALID_LINK,
            serverHost = "203.0.113.10",
            serverPort = 443,
            createdAtMs = 1_700_000_000_000,
        )
        try {
            store.saveProfile(profile)
            store.setActiveProfileId(profile.id)
            assertEquals(profile, store.getProfile(profile.id))
            assertEquals(profile.id, store.getActiveProfileId())
            assertEquals(profile, store.getActiveProfile())
        } finally {
            store.deleteProfile(profile.id)
        }
        assertFalse(store.listProfiles().any { it.id == profile.id })
    }

    @Test
    fun settingsStoreRoundTrips() {
        val store = SettingsStore(context)
        val previous = store.load()
        val changed = previous.copy(
            dohUrl = AppSettings.DOH_NEXTDNS,
            ipv4Only = false,
            rejectQuic = false,
            bypassCidrs = listOf("10.0.0.0/8", "192.168.0.0/16"),
            startOnBoot = true,
        )
        try {
            store.save(changed)
            assertEquals(changed, store.load())
        } finally {
            store.save(previous)
        }
    }

    private companion object {
        private const val UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
        private const val VALID_LINK =
            "vless://$UUID@203.0.113.10:443?encryption=none&security=reality" +
                "&sni=whatsapp.net&fp=chrome" +
                "&pbk=WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo" +
                "&sid=0123456789abcdef&type=tcp&flow=xtls-rprx-vision#beam"
    }
}
