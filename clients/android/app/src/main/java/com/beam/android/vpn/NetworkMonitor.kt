package com.beam.android.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.Looper
import android.util.Log

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
    private val onInitialNetwork: (Network) -> Unit = {},
) : ConnectivityManager.NetworkCallback() {

    companion object {
        const val DEBOUNCE_MS = 300L
        private const val TAG = "NetworkMonitor"
    }

    private val handler = Handler(Looper.getMainLooper())
    private val callbackLock = Any()
    private var pending: Runnable? = null
    private var pendingLoss: Runnable? = null
    @Volatile private var stopped: Boolean = false
    @Volatile private var registered: Boolean = false
    @Volatile private var lastNetworkHandle: Long? = null
    @Volatile private var lastValidated: Boolean = false

    fun start() {
        stopped = false
        // Seed baseline from the already-active default network so the immediate
        // onAvailable()/onCapabilitiesChanged() delivered by registerDefaultNetworkCallback()
        // does not fire a spurious network_reset ~300 ms after every VPN connect.
        val active = runCatching { connectivityManager.activeNetwork }.getOrNull()
        val caps = if (active != null) {
            runCatching { connectivityManager.getNetworkCapabilities(active) }.getOrNull()
        } else {
            null
        }
        // Defensive guard: addDisallowedApplication(packageName) normally keeps the
        // physical network as our default, but if self-exclude fails or an OEM/work
        // profile surfaces a VPN network, never seed or hand it to the engine.
        if (active != null && !isVpnNetwork(caps)) {
            lastNetworkHandle = active.networkHandle
            lastValidated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
            onInitialNetwork(active)
        }
        runCatching { connectivityManager.registerDefaultNetworkCallback(this) }
            .onSuccess { registered = true }
            .onFailure { Log.w(TAG, "registerDefaultNetworkCallback failed", it) }
    }

    fun markStopped() {
        synchronized(callbackLock) {
            stopped = true
            pending?.let(handler::removeCallbacks)
            pending = null
            pendingLoss?.let(handler::removeCallbacks)
            pendingLoss = null
            lastNetworkHandle = null
            lastValidated = false
        }
    }

    fun unregister() {
        if (!registered) return
        registered = false
        try {
            connectivityManager.unregisterNetworkCallback(this)
        } catch (_: Exception) {
            // Already unregistered.
        }
    }

    fun stop() {
        markStopped()
        unregister()
    }

    override fun onAvailable(network: Network) {
        // Never let the VPN's own network become the underlying network.
        val caps = runCatching { connectivityManager.getNetworkCapabilities(network) }.getOrNull()
        if (isVpnNetwork(caps)) return
        synchronized(callbackLock) {
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
            debounceLocked(network)
        }
    }

    override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
        if (isVpnNetwork(caps)) return
        val handle = network.networkHandle
        val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        val needsDefaultCheck = synchronized(callbackLock) {
            if (stopped) return
            val sameNetwork = (lastNetworkHandle == handle)
            if (sameNetwork) {
                // Track validation loss so subsequent captive-portal revalidation triggers a reset.
                if (!validated) {
                    lastValidated = false
                    return
                }
                // Signal/bandwidth fluctuations on an already-validated network must not RST flows.
                if (lastValidated) return
                lastValidated = true
                debounceLocked(network)
                return
            }
            if (lastNetworkHandle == null) {
                lastNetworkHandle = handle
                lastValidated = validated
                debounceLocked(network)
                return
            }
            true
        }
        if (!needsDefaultCheck) return
        // Read activeNetwork outside callbackLock so a system_server IPC never blocks markStopped().
        val currentDefault = runCatching {
            connectivityManager.activeNetwork?.networkHandle
        }.getOrNull()
        if (currentDefault != null && currentDefault != handle) return
        synchronized(callbackLock) {
            if (stopped) return
            if (lastNetworkHandle == handle) return
            lastNetworkHandle = handle
            lastValidated = validated
            debounceLocked(network)
        }
    }

    override fun onLost(network: Network) {
        synchronized(callbackLock) {
            if (stopped) return
            if (lastNetworkHandle != network.networkHandle) return
            // A queued switch to the lost network must not apply afterwards.
            pending?.let(handler::removeCallbacks)
            pending = null
            // Debounce loss so a rapid Wi-Fi <-> 5G handoff doesn't reset twice.
            pendingLoss?.let(handler::removeCallbacks)
            val r = Runnable {
                synchronized(callbackLock) {
                    pendingLoss = null
                    if (stopped) return@Runnable
                    lastNetworkHandle = null
                    lastValidated = false
                }
                onNetworkLost()
            }
            pendingLoss = r
            handler.postDelayed(r, DEBOUNCE_MS)
        }
    }

    private fun isVpnNetwork(caps: NetworkCapabilities?): Boolean =
        caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

    private fun debounceLocked(network: Network) {
        if (stopped) return
        pendingLoss?.let(handler::removeCallbacks)
        pendingLoss = null
        pending?.let(handler::removeCallbacks)
        val r = Runnable {
            synchronized(callbackLock) {
                pending = null
                if (stopped) return@Runnable
            }
            onNetworkSwitch(network)
        }
        pending = r
        handler.postDelayed(r, DEBOUNCE_MS)
    }
}
