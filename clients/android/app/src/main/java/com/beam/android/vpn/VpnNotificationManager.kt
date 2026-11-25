package com.beam.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.beam.android.R
import com.beam.android.ui.MainActivity

/**
 * Foreground-service notification. Updated ONLY on state transitions —
 * never periodic — to keep zero idle wakeups (battery design).
 */
class VpnNotificationManager(private val context: Context) {

    companion object {
        const val CHANNEL_ID = "beam_vpn"
        const val NOTIFICATION_ID = 1
    }

    private val manager: NotificationManager =
        context.getSystemService(NotificationManager::class.java)

    init {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Beam VPN",
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)
    }

    fun build(state: Int, detail: String): Notification {
        val label = context.getString(context.applicationInfo.labelRes)
        val (title, text) = when (state) {
            VpnState.CONNECTED -> label to "Connected"
            VpnState.CONNECTING -> label to "Connecting…"
            VpnState.DEGRADED -> label to "Unstable connection"
            VpnState.DISCONNECTING -> label to "Disconnecting…"
            else -> label to detail.ifBlank { "Disconnected" }
        }
        // Tap re-opens the dashboard.
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pending = PendingIntent.getActivity(
            context, 0, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(pending)
            .setOngoing(state != VpnState.DISCONNECTED)
            .setOnlyAlertOnce(true)
            .build()
    }

    fun notify(state: Int, detail: String) {
        manager.notify(NOTIFICATION_ID, build(state, detail))
    }

    fun cancel() {
        manager.cancel(NOTIFICATION_ID)
    }
}
