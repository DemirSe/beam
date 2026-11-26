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
 * Because this receiver is not `directBootAware`, `ACTION_BOOT_COMPLETED`
 * is delivered only after the user unlocks credential-protected storage.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (context.getSystemService(UserManager::class.java)?.isUserUnlocked == false) return
        val appContext = context.applicationContext
        val pendingResult = goAsync()
        Thread {
            try {
                val settings = runCatching { SettingsStore(appContext).load() }.getOrNull() ?: return@Thread
                if (!settings.startOnBoot) return@Thread
                val hasProfile = runCatching {
                    EncryptedProfileStore(appContext).getActiveProfileId() != null
                }.getOrDefault(false)
                if (!hasProfile) return@Thread
                val start = Intent(appContext, BeamVpnService::class.java)
                    .setAction(BeamVpnService.ACTION_START)
                // An already connected service returns early in connect().
                runCatching { appContext.startForegroundService(start) }
                    .onFailure { Log.w(TAG, "startForegroundService failed", it) }
            } finally {
                pendingResult.finish()
            }
        }.start()
    }

    private companion object {
        const val TAG = "BootReceiver"
    }
}
