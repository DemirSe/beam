package com.beam.android.tile

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.beam.android.R
import com.beam.android.ipc.IBeamStateCallback
import com.beam.android.ipc.IBeamVpnService
import com.beam.android.storage.EncryptedProfileStore
import com.beam.android.ui.MainActivity
import com.beam.android.vpn.BeamVpnService
import com.beam.android.vpn.VpnState
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Quick Settings tile. It binds to the service only while the panel is open,
 * mirrors the pushed state, and opens the UI when a profile or consent is
 * missing.
 *
 * Binder calls and Keystore reads happen on [worker]; every `qsTile` touch
 * stays on [mainHandler].
 */
class BeamTileService : TileService() {

    private var service: IBeamVpnService? = null
    private var isBound = false
    private val mainHandler = Handler(Looper.getMainLooper())

    /** One thread, so tile actions keep their click order. */
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()

    /** Last state known to the UI; only [updateTile] writes it. */
    private var lastState: Int = VpnState.DISCONNECTED

    private val stateCallback = object : IBeamStateCallback.Stub() {
        override fun onStateChanged(state: Int, detail: String?) {
            // Pushed from the :vpn binder thread; Tile updates are main-only.
            mainHandler.post { updateTile(state, hasProfile = true) }
        }
    }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val bound = binder?.let { IBeamVpnService.Stub.asInterface(it) } ?: return
            service = bound
            worker.execute {
                runCatching { bound.registerCallback(stateCallback) }
                refreshTile(bound)
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            service = null
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        if (!isBound) {
            isBound = bindService(
                Intent(this, BeamVpnService::class.java),
                serviceConnection,
                Context.BIND_AUTO_CREATE,
            )
        }
        val bound = service
        worker.execute { refreshTile(bound) }
    }

    override fun onStopListening() {
        if (isBound) {
            runCatching { service?.unregisterCallback(stateCallback) }
            runCatching { unbindService(serviceConnection) }
            isBound = false
        }
        service = null
        super.onStopListening()
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    override fun onClick() {
        val bound = service
        val connected = isActive(lastState)
        val previous = lastState
        // Optimistic: the panel must react before the binder round trip ends.
        updateTile(if (connected) VpnState.DISCONNECTING else VpnState.CONNECTING, hasProfile = true)

        worker.execute {
            val profileId = activeProfileId()
            val consent = runCatching { VpnService.prepare(this) }.getOrNull()
            if (profileId == null || bound == null || consent != null) {
                mainHandler.post {
                    updateTile(previous, hasProfile = profileId != null)
                    openApp()
                }
                return@execute
            }
            if (connected) {
                runCatching { bound.disconnect() }
            } else {
                runCatching { bound.connect(profileId) }
            }
        }
    }

    /** Reads the service state and the profile store; worker thread only. */
    private fun refreshTile(bound: IBeamVpnService?) {
        val state = bound?.let { runCatching { it.getState() }.getOrNull() }
            ?: VpnState.DISCONNECTED
        val hasProfile = activeProfileId() != null
        mainHandler.post { updateTile(state, hasProfile) }
    }

    private fun activeProfileId(): String? = runCatching {
        EncryptedProfileStore(this).getActiveProfileId()
    }.getOrNull()

    private fun isActive(state: Int): Boolean = state == VpnState.CONNECTED ||
        state == VpnState.DEGRADED ||
        state == VpnState.CONNECTING

    private fun updateTile(state: Int, hasProfile: Boolean) {
        lastState = state
        val tile = qsTile ?: return
        tile.state = when {
            isActive(state) -> Tile.STATE_ACTIVE
            !hasProfile -> Tile.STATE_INACTIVE
            service == null && isBound -> Tile.STATE_UNAVAILABLE
            else -> Tile.STATE_INACTIVE
        }
        tile.label = getString(R.string.tile_label)
        tile.stateDescription =
            getString(if (hasProfile) statusLabel(state) else R.string.tile_no_profile)
        tile.icon = Icon.createWithResource(this, R.drawable.ic_tile)
        tile.updateTile()
    }

    private fun statusLabel(state: Int): Int = when (state) {
        VpnState.CONNECTING -> R.string.status_connecting
        VpnState.CONNECTED -> R.string.status_connected
        VpnState.DEGRADED -> R.string.status_degraded
        VpnState.DISCONNECTING -> R.string.status_disconnecting
        else -> R.string.status_disconnected
    }

    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                ),
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
