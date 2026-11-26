package com.beam.android.vpn

import android.content.Intent
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.RemoteCallbackList
import android.util.Log
import com.beam.android.R
import com.beam.android.ipc.IBeamStateCallback
import com.beam.android.ipc.IBeamVpnService
import com.beam.android.storage.EncryptedProfileStore
import com.beam.android.storage.SettingsStore
import com.beam.android.storage.SettingsValidator
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Always-on capable VPN service running in the isolated `:vpn` process.
 * Zero WakeLocks, zero idle timers; notification updates only on transitions.
 */
class BeamVpnService : VpnService() {

    companion object {
        private const val TAG = "BeamVpnService"
        const val ACTION_START = "com.beam.android.action.START"
        const val ACTION_STOP = "com.beam.android.action.STOP"
        const val EXTRA_PROFILE_ID = "profile_id"
        private const val EXTRA_KEEP_ALIVE_ONLY = "keep_alive_only"

        /** DNS must never hold up the foreground service start. */
        private const val RESOLVE_TIMEOUT_MS = 5_000L

        /** Backoff delays between hostname re-resolution retries on network switch. */
        private val NETWORK_SWITCH_RESOLVE_BACKOFF_MS = longArrayOf(1_500L, 3_000L)
    }

    private data class ActiveEngine(val handle: Long, val generation: Long)

    private data class StateSnapshot(val state: Int, val detail: String)

    private class DnsResolutionException(message: String) : IllegalStateException(message)

    @Volatile private var stateSnapshot: StateSnapshot = StateSnapshot(VpnState.DISCONNECTED, "")
    private val state: Int get() = stateSnapshot.state
    private val stateDetail: String get() = stateSnapshot.detail
    /** Guarded by [callbackLock]; tracks the last state/detail pushed to notification/callbacks. */
    private var lastPublishedState: Int = VpnState.DISCONNECTED
    private var lastPublishedDetail: String = ""
    /** Guarded by [callbackLock]; prevents broadcasting after [onDestroy] calls `callbacks.kill()`. */
    private var destroyed: Boolean = false
    @Volatile private var activeProfileId: String? = null
    @Volatile private var pendingProfileId: String? = null
    @Volatile private var activeServerHost: String? = null
    @Volatile private var activeIpv4Only: Boolean = true
    @Volatile private var activeEngine: ActiveEngine? = null

    private var tun: ParcelFileDescriptor? = null
    private var monitor: NetworkMonitor? = null
    private lateinit var notifications: VpnNotificationManager
    private val callbacks = RemoteCallbackList<IBeamStateCallback>()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    /** Bounded non-cancellable pool so rapid profile switches do not serialize 2 s shutdowns. */
    private val cleanupThreadCounter = AtomicInteger(1)
    private val cleanupExecutor: ExecutorService = Executors.newFixedThreadPool(2) { runnable ->
        Thread(runnable, "beam-cleanup-${cleanupThreadCounter.getAndIncrement()}").apply {
            isDaemon = true
        }
    }

    /** Serialises state transitions and establish()/detach() against teardown(). */
    private val stateLock = Any()

    /** Serialises [publishCurrentState] and `RemoteCallbackList` lifecycle across IO/binder/JNI threads. */
    private val callbackLock = Any()

    /** Bumped by every connect()/disconnect()/onRevoke()/onDestroy(); stale attempts abort. */
    private val connectGeneration = AtomicLong(0L)
    /** Monotonic counter ordering concurrent network-switch re-resolutions. */
    private val networkSwitchGeneration = AtomicLong(0L)
    private var connectJob: Job? = null
    private var networkSwitchJob: Job? = null

    private val binder = object : IBeamVpnService.Stub() {
        override fun connect(profileId: String) {
            this@BeamVpnService.connect(profileId)
        }

        override fun disconnect() {
            this@BeamVpnService.disconnect()
        }

        override fun getState(): Int {
            // Lightweight JNI state refresh without serializing telemetry JSON.
            if (this@BeamVpnService.activeEngine != null) this@BeamVpnService.refreshNativeState()
            return this@BeamVpnService.state
        }

        override fun getStateDetail(): String = this@BeamVpnService.stateDetail

        override fun getActiveProfileId(): String? = this@BeamVpnService.activeProfileId

        override fun getTelemetryJson(): String = this@BeamVpnService.pollTelemetry()

        override fun registerCallback(cb: IBeamStateCallback) {
            callbacks.register(cb)
        }

        override fun unregisterCallback(cb: IBeamStateCallback) {
            callbacks.unregister(cb)
        }
    }

    override fun onCreate() {
        super.onCreate()
        notifications = VpnNotificationManager(this)
    }

    /**
     * Always-on VPN binds with [SERVICE_INTERFACE] and needs the framework
     * binder; only the app binds to our own AIDL interface. Returning our
     * binder for the framework intent silently breaks Always-on VPN.
     */
    override fun onBind(intent: Intent?): IBinder? =
        if (intent?.action == SERVICE_INTERFACE) super.onBind(intent) else binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                // Capture stopGen on main immediately, then run teardown off main
                // so nativeStop() (up to 2 s) never stalls the service main thread
                // and a stale stop cannot tear down a newer connect().
                val stopGen = connectGeneration.incrementAndGet()
                serviceScope.launch { disconnect(expectedGen = stopGen) }
            }
            // ACTION_START, null action, or SERVICE_INTERFACE (Always-on VPN): connect.
            else -> {
                if (intent?.getBooleanExtra(EXTRA_KEEP_ALIVE_ONLY, false) == true) {
                    return START_NOT_STICKY
                }
                // startForegroundService() callers are killed when the foreground
                // notification is late, so post it before the profile lookup.
                if (state == VpnState.DISCONNECTED || state == VpnState.DISCONNECTING) {
                    startForeground(
                        VpnNotificationManager.NOTIFICATION_ID,
                        notifications.build(VpnState.CONNECTING, ""),
                    )
                }
                val startGen = connectGeneration.get()
                serviceScope.launch {
                    if (startGen != connectGeneration.get()) {
                        stopSelfIfIdle(startGen, startId)
                        return@launch
                    }
                    val id = intent?.getStringExtra(EXTRA_PROFILE_ID)
                        ?: runCatching {
                            EncryptedProfileStore(this@BeamVpnService).getActiveProfileId()
                        }.getOrNull()
                    if (startGen != connectGeneration.get()) {
                        stopSelfIfIdle(startGen, startId)
                        return@launch
                    }
                    if (id != null) {
                        connect(id)
                    } else {
                        // Nothing to connect to: stop instead of idling in foreground.
                        val released = synchronized(stateLock) {
                            if (startGen != connectGeneration.get()) return@launch
                            detachResources()
                        }
                        releaseResources(released)
                        val stateChanged = synchronized(stateLock) {
                            if (startGen != connectGeneration.get()) return@launch
                            updateStateLocked(VpnState.DISCONNECTED, "")
                        }
                        if (stateChanged) publishCurrentState()
                        synchronized(stateLock) {
                            if (startGen == connectGeneration.get()) {
                                stopSelfResult(startId)
                            }
                        }
                    }
                }
            }
        }
        // Never resurrect the service without an explicit start intent.
        return START_NOT_STICKY
    }

    /**
     * Starts a connect attempt. Never blocks the caller: everything slow
     * (Keystore, DNS, establish, JNI) runs on [serviceScope] so a quick
     * disconnect() can cancel it.
     */
    private fun connect(profileId: String) {
        val myGen: Long
        val previous: ReleasedResources
        synchronized(stateLock) {
            if ((state == VpnState.CONNECTING || state == VpnState.CONNECTED) &&
                (activeProfileId == profileId || pendingProfileId == profileId)
            ) {
                return
            }
            myGen = connectGeneration.incrementAndGet()
            connectJob?.cancel()
            connectJob = null
            // A new profile detaches the old engine before the new one starts.
            previous = detachResources(keepForeground = true)
            // Track pending attempt separately so getActiveProfileId() only
            // publishes a profile once the tunnel is actually established.
            pendingProfileId = profileId
            updateStateLocked(VpnState.CONNECTING, "")
        }
        // Claim a started-service reference BEFORE startForeground() so API 34+
        // never sees startForeground() on a bound-only stopped service, and
        // unbinding MainActivity / TileService never tears down an active tunnel.
        // EXTRA_KEEP_ALIVE_ONLY prevents onStartCommand from re-entering connect().
        runCatching {
            startService(
                Intent(this, BeamVpnService::class.java)
                    .setAction(ACTION_START)
                    .putExtra(EXTRA_PROFILE_ID, profileId)
                    .putExtra(EXTRA_KEEP_ALIVE_ONLY, true),
            )
        }
        // Android 12+ kills the service if the foreground notification is late,
        // so it goes up before any DNS or Keystore work (outside stateLock).
        val promoted = runCatching {
            startForeground(
                VpnNotificationManager.NOTIFICATION_ID,
                notifications.build(VpnState.CONNECTING, ""),
            )
        }
        // Always release any detached previous engine/TUN on the dedicated
        // cleanup executor so cancelling connectJob or serviceScope can never
        // leak an old Rust runtime or TUN descriptor.
        scheduleRelease(previous)
        if (promoted.isFailure) {
            Log.e(TAG, "startForeground failed", promoted.exceptionOrNull())
            val failedChanged = synchronized(stateLock) {
                if (connectGeneration.get() == myGen) {
                    pendingProfileId = null
                    updateStateLocked(
                        VpnState.DISCONNECTED,
                        getString(R.string.vpn_error_generic),
                    )
                } else {
                    false
                }
            }
            if (failedChanged) publishCurrentState()
            synchronized(stateLock) {
                if (connectGeneration.get() == myGen) {
                    stopSelf()
                }
            }
            return
        }
        publishCurrentState()
        synchronized(stateLock) {
            if (connectGeneration.get() == myGen) {
                connectJob = serviceScope.launch { runConnect(profileId, myGen) }
            }
        }
    }

    private suspend fun runConnect(profileId: String, myGen: Long) {
        try {
            val store = EncryptedProfileStore(this)
            val profile = store.getProfile(profileId)
                ?: throw IllegalArgumentException("unknown profile")
            val settings = SettingsStore(this).load()

            // Resolve before establish(): once the TUN is up, a platform lookup
            // could stall behind the new route. The 5 s deadline is best effort
            // because InetAddress.getAllByName is blocking, but failing here on
            // timeout/error avoids falling through to unbounded Rust getaddrinfo.
            val serverIp = if (SettingsValidator.isIpLiteral(profile.serverHost)) {
                profile.serverHost.trim().removePrefix("[").removeSuffix("]")
            } else {
                withTimeoutOrNull(RESOLVE_TIMEOUT_MS) {
                    resolveServerHost(profile.serverHost, settings.ipv4Only)
                } ?: throw DnsResolutionException("server host could not be resolved")
            }
            if (connectGeneration.get() != myGen) return
            // Re-check that the profile was not deleted while resolving DNS.
            if (store.getProfile(profileId) == null) {
                throw IllegalArgumentException("unknown profile")
            }

            // A bypass CIDR that covers the TUN /30 would bypass the TUN DNS.
            val bypass = settings.bypassCidrs.filterNot(Ipv4RouteCalculator::overlapsTunSubnet)
            val configJson = VpnConfigBuilder.buildConfigJson(
                vlessUri = profile.uri,
                dohUrl = settings.dohUrl,
                ipv4Only = settings.ipv4Only,
                rejectQuic = settings.rejectQuic,
                bypassCidrs = bypass,
                serverIp = serverIp,
            )

            // Narrow stateLock: hold it only for establish(), release before nativeStart()
            // so onDestroy()/disconnect() on the main thread can never ANR behind JNI startup.
            val pfd = synchronized(stateLock) {
                if (connectGeneration.get() != myGen) return
                buildTunBuilder(bypass, settings.treatAsUnmetered).establish()
                    ?: throw IllegalStateException("establish() returned null")
            }
            // Re-check after blocking establish(): a concurrent disconnect/onRevoke/onDestroy
            // bumps connectGeneration before taking stateLock, so abort before starting Rust.
            if (connectGeneration.get() != myGen) {
                runCatching { pfd.close() }
                return
            }
            val fd = pfd.detachFd()
            val handle = try {
                BeamNativeBridge.nativeStart(
                    fd, configJson, this,
                    object : NativeStateListener {
                        override fun onNativeStateChanged(s: Int, detail: String) {
                            // Ignore callbacks from a torn-down or superseded engine so
                            // teardown(keepForeground = true) never cancels the FGS notification.
                            var shouldDisconnect = false
                            val changed = synchronized(stateLock) {
                                if (myGen != connectGeneration.get()) return@synchronized false
                                val active = activeEngine
                                // Defer the synchronous CONNECTED push from inside nativeStart()
                                // until activeEngine and activeProfileId are published below.
                                if (active == null || myGen != active.generation) {
                                    return@synchronized false
                                }
                                if (s == VpnState.DISCONNECTED) {
                                    shouldDisconnect = true
                                    return@synchronized false
                                }
                                // Reserve stateDetail for user-facing errors, not raw state labels.
                                updateStateLocked(
                                    s,
                                    if (s == VpnState.DEGRADED) "degraded" else "",
                                )
                            }
                            if (shouldDisconnect) {
                                // Unexpected engine exit (e.g. fatal TUN error): tear down FGS cleanly.
                                serviceScope.launch { disconnect(expectedGen = myGen) }
                                return
                            }
                            if (changed) publishCurrentState()
                        }
                    },
                )
            } catch (e: LinkageError) {
                // nativeStart was never entered, so Rust never took the fd:
                // closing it here is the only owner, exactly once. For any
                // post-entry throw, Rust's LinuxTun::from_detached_fd already
                // adopted and closed the fd on error.
                runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
                throw e
            }

            var staleRelease: ReleasedResources? = null
            synchronized(stateLock) {
                if (connectGeneration.get() != myGen) {
                    staleRelease = ReleasedResources(
                        handle = handle,
                        tun = pfd,
                        stopForeground = false,
                        generation = myGen,
                    )
                } else {
                    tun = pfd
                    activeEngine = ActiveEngine(handle, myGen)
                    activeProfileId = profileId
                    activeServerHost = profile.serverHost
                    activeIpv4Only = settings.ipv4Only
                    pendingProfileId = null
                }
            }
            if (staleRelease != null) {
                scheduleRelease(staleRelease!!)
                return
            }

            // Now that activeEngine and activeProfileId are published, query the
            // live state so CONNECTED reaches the UI with valid handle/profile.
            val liveState = BeamNativeBridge.nativeRefreshState(handle)
            if (liveState == VpnState.DISCONNECTED) {
                disconnect(expectedGen = myGen)
                return
            }
            // Re-check generation and active handle under stateLock so a concurrent
            // onDestroy()/disconnect() cannot have CONNECTED re-posted after teardown.
            var liveChanged = false
            val stillOwner = synchronized(stateLock) {
                if (connectGeneration.get() == myGen && activeEngine?.handle == handle) {
                    liveChanged = updateStateLocked(
                        liveState,
                        if (liveState == VpnState.DEGRADED) "degraded" else "",
                    )
                    true
                } else {
                    false
                }
            }
            if (!stillOwner) return
            if (liveChanged) publishCurrentState()

            val cm = getSystemService(ConnectivityManager::class.java)
            val newMonitor = NetworkMonitor(
                cm,
                onInitialNetwork = { network ->
                    runCatching { setUnderlyingNetworks(arrayOf(network)) }
                        .onFailure { Log.w(TAG, "initial setUnderlyingNetworks failed", it) }
                },
                onNetworkSwitch = { network ->
                    if (connectGeneration.get() == myGen) {
                        synchronized(stateLock) {
                            if (connectGeneration.get() == myGen) {
                                val switchGen = networkSwitchGeneration.incrementAndGet()
                                networkSwitchJob?.cancel()
                                networkSwitchJob = serviceScope.launch {
                                    handleNetworkSwitch(network, myGen, switchGen)
                                }
                            }
                        }
                    }
                },
                onNetworkLost = {
                    if (connectGeneration.get() == myGen) {
                        synchronized(stateLock) {
                            if (connectGeneration.get() == myGen) {
                                networkSwitchGeneration.incrementAndGet()
                                networkSwitchJob?.cancel()
                                networkSwitchJob = null
                            }
                        }
                        if (connectGeneration.get() == myGen) {
                            runCatching { setUnderlyingNetworks(null) }
                                .onFailure { Log.w(TAG, "setUnderlyingNetworks(null) failed", it) }
                            notifyNativeNetworkChange(serverIp = null)
                        }
                    }
                },
            ).also { it.start() }

            val keepMonitor = synchronized(stateLock) {
                if (connectGeneration.get() == myGen) {
                    monitor = newMonitor
                    true
                } else {
                    false
                }
            }
            if (!keepMonitor) {
                newMonitor.stop()
                return
            }

            // Only persist active profile if this attempt still owns the tunnel and
            // the profile was not deleted during connect. Transient Keystore/I/O
            // errors here are advisory and must not tear down a healthy tunnel.
            if (connectGeneration.get() != myGen) return
            val stillPresent = runCatching { store.setActiveProfileIdIfExists(profile.id) }
                .onFailure { Log.w(TAG, "failed to persist active profile id", it) }
                .getOrDefault(true)
            if (!stillPresent) {
                disconnect(expectedGen = myGen)
                return
            }
        } catch (c: CancellationException) {
            // A cancelling connect()/disconnect() owns the cleanup of whatever
            // was already established.
            throw c
        } catch (t: Throwable) {
            // Stale attempt: a newer connect() or disconnect() already owns the lifecycle.
            if (connectGeneration.get() != myGen) return
            // Throwable, not Exception: a missing or stale libbeam_android.so
            // surfaces as LinkageError/ExceptionInInitializerError.
            Log.e(TAG, "connect failed", t)
            val released = synchronized(stateLock) {
                if (connectGeneration.get() != myGen) return
                detachResources()
            }
            releaseResources(released)
            val errChanged = synchronized(stateLock) {
                if (connectGeneration.get() != myGen) return
                updateStateLocked(VpnState.DISCONNECTED, userFacingError(t))
            }
            if (errChanged) publishCurrentState()
            synchronized(stateLock) {
                if (connectGeneration.get() == myGen) {
                    stopSelf()
                }
            }
        }
    }

    private fun userFacingError(t: Throwable): String = when {
        t is IllegalArgumentException && t.message?.contains("profile", ignoreCase = true) == true ->
            getString(R.string.vpn_error_profile)
        t is DnsResolutionException ->
            getString(R.string.vpn_error_dns)
        t is IllegalStateException && t.message?.contains("establish()", ignoreCase = true) == true ->
            getString(R.string.vpn_error_consent)
        t is LinkageError || t is IllegalStateException ->
            getString(R.string.vpn_error_native)
        else -> getString(R.string.vpn_error_generic)
    }

    /** Builds the TUN parameters; the caller holds [stateLock] for establish(). */
    private fun buildTunBuilder(bypass: List<String>, treatAsUnmetered: Boolean): Builder {
        val builder = Builder()
            .setMtu(VpnConfigBuilder.MTU)
            .addAddress(VpnConfigBuilder.TUN_IPV4, VpnConfigBuilder.TUN_PREFIX)
            // Capture IPv6 so reject_ipv6=true prevents clear IPv6 leaks.
            .addAddress("fd00:be:a::1", 126)
            .addRoute("::", 0)
            .addDnsServer(VpnConfigBuilder.TUN_DNS_IPV4)
            .setBlocking(false)
        if (treatAsUnmetered) {
            builder.setMetered(false)
        }
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "self-exclude failed", e)
        }
        if (Build.VERSION.SDK_INT >= 33) {
            builder.addRoute("0.0.0.0", 0)
            for (cidr in bypass) {
                // IpPrefix takes an InetAddress and a prefix length, not a CIDR
                // string. isValidCidr keeps hostnames out of getByName.
                val text = cidr.trim()
                if (!Ipv4RouteCalculator.isValidCidr(text, allowIpv6 = true)) {
                    Log.w(TAG, "ignoring invalid bypass CIDR: $cidr")
                    continue
                }
                try {
                    builder.excludeRoute(
                        IpPrefix(
                            InetAddress.getByName(text.substringBefore('/')),
                            text.substringAfter('/').toInt(),
                        ),
                    )
                } catch (e: IllegalArgumentException) {
                    Log.w(TAG, "ignoring invalid bypass CIDR: $cidr")
                }
            }
        } else {
            // API 31-32 has no excludeRoute(): route the complement instead.
            // It always covers 198.19.0.0/30 because overlapping CIDRs were
            // filtered out, and IPv6 bypass is not supported on this path.
            for ((addr, prefix) in Ipv4RouteCalculator.subtractCidrs(bypass)) {
                builder.addRoute(addr, prefix)
            }
        }
        return builder
    }

    /** Resolves the profile host on the default network. */
    private suspend fun resolveServerHost(host: String, ipv4Only: Boolean): String? =
        withContext(Dispatchers.IO) {
            val addresses = runCatching { InetAddress.getAllByName(host) }.getOrNull()
            pickResolvedAddress(addresses, ipv4Only)
        }

    /** Resolves the profile host directly over a specific underlying [Network]. */
    private suspend fun resolveServerHostOnNetwork(
        network: Network,
        host: String,
        ipv4Only: Boolean,
    ): String? = withContext(Dispatchers.IO) {
        val addresses = runCatching { network.getAllByName(host) }.getOrNull()
        pickResolvedAddress(addresses, ipv4Only)
    }

    private fun pickResolvedAddress(addresses: Array<InetAddress>?, ipv4Only: Boolean): String? {
        if (addresses.isNullOrEmpty()) return null
        val preferred = if (ipv4Only) addresses.firstOrNull { it is Inet4Address } else null
        return (preferred ?: addresses.first()).hostAddress
    }

    private suspend fun handleNetworkSwitch(
        network: Network,
        expectedGen: Long,
        expectedSwitchGen: Long,
    ) {
        if (connectGeneration.get() != expectedGen || networkSwitchGeneration.get() != expectedSwitchGen) {
            return
        }
        runCatching { setUnderlyingNetworks(arrayOf(network)) }
            .onFailure { Log.w(TAG, "setUnderlyingNetworks failed", it) }
        val host = activeServerHost
        if (host == null || SettingsValidator.isIpLiteral(host)) {
            notifyNativeNetworkChange(null)
            return
        }
        val firstIp = withTimeoutOrNull(RESOLVE_TIMEOUT_MS) {
            resolveServerHostOnNetwork(network, host, activeIpv4Only)
        }
        if (connectGeneration.get() != expectedGen || networkSwitchGeneration.get() != expectedSwitchGen) {
            return
        }
        if (firstIp != null) {
            notifyNativeNetworkChange(firstIp)
            return
        }
        // Reset stale flows from the previous network immediately instead of
        // waiting through the full retry budget, then update server_ip once DNS recovers.
        notifyNativeNetworkChange(null)
        for (backoffMs in NETWORK_SWITCH_RESOLVE_BACKOFF_MS) {
            delay(backoffMs)
            if (connectGeneration.get() != expectedGen ||
                networkSwitchGeneration.get() != expectedSwitchGen
            ) {
                return
            }
            val retriedIp = withTimeoutOrNull(RESOLVE_TIMEOUT_MS) {
                resolveServerHostOnNetwork(network, host, activeIpv4Only)
            }
            if (connectGeneration.get() != expectedGen ||
                networkSwitchGeneration.get() != expectedSwitchGen
            ) {
                return
            }
            if (retriedIp != null) {
                notifyNativeNetworkChange(retriedIp)
                return
            }
        }
    }

    private data class ReleasedResources(
        val handle: Long,
        val tun: ParcelFileDescriptor?,
        val stopForeground: Boolean,
        val generation: Long,
    )

    private fun stopSelfIfIdle(expectedGen: Long, startId: Int) {
        synchronized(stateLock) {
            if (connectGeneration.get() != expectedGen && state == VpnState.DISCONNECTED) {
                stopSelfResult(startId)
            }
        }
    }

    private fun disconnect(expectedGen: Long? = null) {
        val myGen = if (expectedGen != null) {
            if (connectGeneration.get() != expectedGen) return
            expectedGen
        } else {
            // Bump first: an in-flight connect() must not establish behind our back.
            connectGeneration.incrementAndGet()
        }
        val released: ReleasedResources
        val disconnectingChanged: Boolean
        synchronized(stateLock) {
            if (connectGeneration.get() != myGen) return
            connectJob?.cancel()
            connectJob = null
            disconnectingChanged = if (state != VpnState.DISCONNECTED) {
                updateStateLocked(VpnState.DISCONNECTING, "")
            } else {
                false
            }
            released = detachResources()
        }
        if (disconnectingChanged) publishCurrentState()
        // Release native engine (up to 2 s shutdown) and TUN off the caller's
        // binder thread so UI/tile toggles never stall behind nativeStop().
        if (released.handle == 0L && released.tun == null && !released.stopForeground) {
            finalizeDisconnect(myGen)
        } else {
            scheduleRelease(released) { finalizeDisconnect(myGen) }
        }
    }

    private fun finalizeDisconnect(myGen: Long) {
        val changed = synchronized(stateLock) {
            if (connectGeneration.get() == myGen) {
                if (state != VpnState.DISCONNECTED) {
                    updateStateLocked(VpnState.DISCONNECTED, "")
                } else {
                    false
                }
            } else {
                false
            }
        }
        if (changed) publishCurrentState()
        synchronized(stateLock) {
            if (connectGeneration.get() == myGen) {
                stopSelf()
            }
        }
    }

    override fun onRevoke() {
        val stopGen = connectGeneration.incrementAndGet()
        serviceScope.launch { disconnect(expectedGen = stopGen) }
    }

    override fun onDestroy() {
        connectGeneration.incrementAndGet()
        serviceScope.cancel()
        val released = synchronized(stateLock) {
            connectJob?.cancel()
            connectJob = null
            detachResources()
        }
        // Never run nativeStop() (up to 2 s) synchronously on the main thread.
        scheduleRelease(released)
        // Graceful shutdown (not shutdownNow) so queued engine releases finish
        // nativeStop() + tun.close() off the main thread.
        cleanupExecutor.shutdown()
        synchronized(callbackLock) {
            destroyed = true
            callbacks.kill()
        }
        super.onDestroy()
    }

    private fun scheduleRelease(
        released: ReleasedResources,
        onDone: (() -> Unit)? = null,
    ) {
        if (released.handle == 0L && released.tun == null && !released.stopForeground) {
            onDone?.invoke()
            return
        }
        val task = Runnable {
            try {
                releaseResources(released)
            } finally {
                onDone?.invoke()
            }
        }
        if (cleanupExecutor.isShutdown) {
            Thread(task, "beam-cleanup-fallback").apply {
                isDaemon = true
            }.start()
            return
        }
        runCatching { cleanupExecutor.execute(task) }
            .onFailure {
                Thread(task, "beam-cleanup-fallback").apply {
                    isDaemon = true
                }.start()
            }
    }

    /**
     * Detaches the TUN and engine handle under [stateLock] without blocking on
     * native shutdown so main-thread lifecycle calls cannot ANR behind the lock.
     */
    private fun detachResources(keepForeground: Boolean = false): ReleasedResources {
        networkSwitchGeneration.incrementAndGet()
        networkSwitchJob?.cancel()
        networkSwitchJob = null
        monitor?.stop()
        monitor = null
        pendingProfileId = null
        activeProfileId = null
        activeServerHost = null
        val h = activeEngine?.handle ?: 0L
        activeEngine = null
        val pfd = tun
        tun = null
        return ReleasedResources(
            handle = h,
            tun = pfd,
            stopForeground = !keepForeground,
            generation = connectGeneration.get(),
        )
    }

    private fun releaseResources(released: ReleasedResources) {
        if (released.handle != 0L) {
            try {
                BeamNativeBridge.nativeStop(released.handle)
            } catch (t: Throwable) {
                Log.w(TAG, "nativeStop failed", t)
            }
        }
        try {
            released.tun?.close()
        } catch (_: Throwable) {
        }
        // Only remove the foreground notification if no newer connect() superseded this teardown.
        if (released.stopForeground && connectGeneration.get() == released.generation) {
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        }
    }

    private fun refreshNativeState() {
        val active = activeEngine ?: return
        try {
            val reported = BeamNativeBridge.nativeRefreshState(active.handle)
            applyReportedState(reported, active.generation)
        } catch (t: Throwable) {
            Log.w(TAG, "nativeRefreshState failed", t)
        }
    }

    private fun pollTelemetry(): String {
        val active = activeEngine ?: return "{}"
        return try {
            // nativePollTelemetry() already runs refresh_state() in Rust and
            // invokes NativeStateListener on transitions, avoiding a second JSON parse here.
            BeamNativeBridge.nativePollTelemetry(active.handle) ?: "{}"
        } catch (t: Throwable) {
            Log.w(TAG, "telemetry poll failed", t)
            "{}"
        }
    }

    private fun applyReportedState(reported: Int, gen: Long) {
        var changed = false
        val shouldDisconnect = synchronized(stateLock) {
            val active = activeEngine ?: return
            if (gen != connectGeneration.get() || gen != active.generation) return
            if (reported == VpnState.DISCONNECTED) {
                true
            } else {
                if (reported != state) {
                    // Telemetry owns the state, not the detail: never forward a stale one.
                    changed = updateStateLocked(
                        reported,
                        if (reported == VpnState.DEGRADED) "degraded" else "",
                    )
                }
                false
            }
        }
        if (changed) publishCurrentState()
        if (shouldDisconnect) {
            serviceScope.launch { disconnect(expectedGen = gen) }
        }
    }

    private fun notifyNativeNetworkChange(serverIp: String? = null) {
        val active = activeEngine ?: return
        try {
            BeamNativeBridge.nativeNotifyNetworkChangeWithServerIp(active.handle, serverIp)
        } catch (t: Throwable) {
            Log.w(TAG, "nativeNotifyNetworkChange failed", t)
        }
    }

    /** Updates [stateSnapshot] while holding [stateLock]; call [publishCurrentState] outside. */
    private fun updateStateLocked(s: Int, detail: String): Boolean {
        val prev = stateSnapshot
        val changed = (s != prev.state) || (detail != prev.detail)
        if (changed) stateSnapshot = StateSnapshot(s, detail)
        return changed
    }

    /**
     * Publishes the latest [stateSnapshot] to the notification (on state
     * transitions only) and AIDL callbacks (on state or detail changes) under
     * [callbackLock], never while holding [stateLock]. Reading a single
     * immutable volatile snapshot inside [callbackLock] avoids torn pairs and
     * preserves transition order when threads release [stateLock] concurrently.
     */
    private fun publishCurrentState() {
        synchronized(callbackLock) {
            if (destroyed) return
            val snap = stateSnapshot
            val s = snap.state
            val detail = snap.detail
            val stateChanged = (s != lastPublishedState)
            if (!stateChanged && detail == lastPublishedDetail) return
            lastPublishedState = s
            lastPublishedDetail = detail
            // Notification ONLY on state transitions.
            if (stateChanged) {
                if (s == VpnState.DISCONNECTED) {
                    notifications.cancel()
                } else {
                    notifications.notify(s, detail)
                }
            }
            val n = callbacks.beginBroadcast()
            try {
                for (i in 0 until n) {
                    try {
                        callbacks.getBroadcastItem(i).onStateChanged(s, detail)
                    } catch (_: Exception) {
                    }
                }
            } finally {
                callbacks.finishBroadcast()
            }
        }
    }
}
