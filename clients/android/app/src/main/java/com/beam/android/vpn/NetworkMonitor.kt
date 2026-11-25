package com.beam.android.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.Looper

/**
 * Debounced (300 ms) default-network callback. On switch: updates
 * setUnderlyingNetworks() and pokes the Rust engine (network_reset++).
 * On loss: clears the underlying network so the engine cannot keep a dead one.
 * No polling, no timers while idle.
 */
class NetworkMonitor(
    private val connectivityManager: ConnectivityManager,
    private val onNetworkSwitch: (Network) -> Unit,
    private val onNetworkLost: () -> Unit,
) : ConnectivityManager.NetworkCallback() {

    companion object {
        const val DEBOUNCE_MS = 300L
    }

    private val handler = Handler(Looper.getMainLooper())
    private var pending: Runnable? = null
    private var pendingLoss: Runnable? = null

    fun start() {
        connectivityManager.registerDefaultNetworkCallback(this)
    }

    fun stop() {
        pending?.let(handler::removeCallbacks)
        pending = null
        pendingLoss?.let(handler::removeCallbacks)
        pendingLoss = null
        try {
            connectivityManager.unregisterNetworkCallback(this)
        } catch (_: Exception) {
            // Already unregistered.
        }
    }

    override fun onAvailable(network: Network) {
        debounce(network)
    }

    override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
        debounce(network)
    }

    override fun onLost(network: Network) {
        // A queued switch to the lost network must not apply afterwards.
        pending?.let(handler::removeCallbacks)
        pending = null
        // A queued loss must not survive stop() and poke a torn-down engine.
        pendingLoss?.let(handler::removeCallbacks)
        val r = Runnable {
            pendingLoss = null
            onNetworkLost()
        }
        pendingLoss = r
        handler.post(r)
    }

    private fun debounce(network: Network) {
        pending?.let(handler::removeCallbacks)
        val r = Runnable { onNetworkSwitch(network) }
        pending = r
        handler.postDelayed(r, DEBOUNCE_MS)
    }
}
