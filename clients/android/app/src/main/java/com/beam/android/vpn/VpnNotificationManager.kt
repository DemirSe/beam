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
        val label = context.getString(R.string.app_name)
        val text = when (state) {
            VpnState.CONNECTED -> context.getString(R.string.status_connected)
            VpnState.CONNECTING -> context.getString(R.string.status_connecting)
            VpnState.DEGRADED -> context.getString(R.string.status_degraded)
            VpnState.DISCONNECTING -> context.getString(R.string.status_disconnecting)
            else -> detail.ifBlank { context.getString(R.string.status_disconnected) }
        }
        // Tap re-opens the dashboard.
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pending = PendingIntent.getActivity(
            context, 0, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle(label)
            .setContentText(text)
            .setContentIntent(pending)
            .setOngoing(state != VpnState.DISCONNECTED)
            .setOnlyAlertOnce(true)

        if (state == VpnState.CONNECTED || state == VpnState.DEGRADED || state == VpnState.CONNECTING) {
            val stopIntent = Intent(context, BeamVpnService::class.java).apply {
                action = BeamVpnService.ACTION_STOP
            }
            val stopPending = PendingIntent.getService(
                context, 1, stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            builder.addAction(
                0,
                context.getString(R.string.action_disconnect),
                stopPending,
            )
        }
        return builder.build()
    }

    fun notify(state: Int, detail: String) {
        manager.notify(NOTIFICATION_ID, build(state, detail))
    }

    fun cancel() {
        manager.cancel(NOTIFICATION_ID)
    }
}
