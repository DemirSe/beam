package com.beam.android.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.UserManager
import android.util.Log
import com.beam.android.storage.EncryptedProfileStore
import com.beam.android.storage.SettingsStore

/**
 * Starts the tunnel after boot when the user enabled start-on-boot.
 * `USER_UNLOCKED` covers devices that boot straight into a locked state.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_USER_UNLOCKED -> Unit
            else -> return
        }
        // Storage is credential-protected; retry on USER_UNLOCKED instead.
        if (context.getSystemService(UserManager::class.java)?.isUserUnlocked == false) return
        val settings = runCatching { SettingsStore(context).load() }.getOrNull() ?: return
        if (!settings.startOnBoot) return
        val hasProfile = runCatching {
            EncryptedProfileStore(context).getActiveProfileId() != null
        }.getOrDefault(false)
        if (!hasProfile) return
        val start = Intent(context, BeamVpnService::class.java)
            .setAction(BeamVpnService.ACTION_START)
        // An already connected service returns early in connect().
        runCatching { context.startForegroundService(start) }
            .onFailure { Log.w(TAG, "startForegroundService failed", it) }
    }

    private companion object {
        const val TAG = "BootReceiver"
    }
}
