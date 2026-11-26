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
    @Volatile private var stopped: Boolean = false
    @Volatile private var lastNetworkHandle: Long? = null
    @Volatile private var lastValidated: Boolean = false

    fun start() {
        stopped = false
        connectivityManager.registerDefaultNetworkCallback(this)
    }

    fun stop() {
        stopped = true
        pending?.let(handler::removeCallbacks)
        pending = null
        pendingLoss?.let(handler::removeCallbacks)
        pendingLoss = null
        lastNetworkHandle = null
        lastValidated = false
        try {
            connectivityManager.unregisterNetworkCallback(this)
        } catch (_: Exception) {
            // Already unregistered.
        }
    }

    override fun onAvailable(network: Network) {
        if (stopped) return
        val handle = network.networkHandle
        val previous = lastNetworkHandle
        if (previous == handle) {
            // Network came back before loss debounce fired; cancel the loss.
            pendingLoss?.let(handler::removeCallbacks)
            pendingLoss = null
            return
        }
        lastNetworkHandle = handle
        lastValidated = false
        debounce(network)
    }

    override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
        if (stopped) return
        val handle = network.networkHandle
        val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        val sameNetwork = (lastNetworkHandle == handle)
        if (sameNetwork) {
            // Signal/bandwidth fluctuations on the same network must not RST flows.
            // Only re-arm if the network just became validated (e.g. captive portal).
            if (!validated || lastValidated) return
            lastValidated = true
            debounce(network)
            return
        }
        lastNetworkHandle = handle
        lastValidated = validated
        debounce(network)
    }

    override fun onLost(network: Network) {
        if (stopped) return
        if (lastNetworkHandle != null && lastNetworkHandle != network.networkHandle) return
        // A queued switch to the lost network must not apply afterwards.
        pending?.let(handler::removeCallbacks)
        pending = null
        // Debounce loss so a rapid Wi-Fi <-> 5G handoff doesn't reset twice.
        pendingLoss?.let(handler::removeCallbacks)
        val r = Runnable {
            pendingLoss = null
            if (stopped) return@Runnable
            lastNetworkHandle = null
            lastValidated = false
            onNetworkLost()
        }
        pendingLoss = r
        handler.postDelayed(r, DEBOUNCE_MS)
    }

    private fun debounce(network: Network) {
        if (stopped) return
        pendingLoss?.let(handler::removeCallbacks)
        pendingLoss = null
        pending?.let(handler::removeCallbacks)
        val r = Runnable {
            pending = null
            if (stopped) return@Runnable
            onNetworkSwitch(network)
        }
        pending = r
        handler.postDelayed(r, DEBOUNCE_MS)
    }
}
