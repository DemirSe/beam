package com.beam.android.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.RemoteCallbackList
import android.os.SystemClock
import android.util.Log
import androidx.core.content.ContextCompat
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
        private val NETWORK_SWITCH_RESOLVE_BACKOFF_MS = longArrayOf(1_500L, 3_000L, 6_000L)

        /** Backoff delays for restarting an engine that exited without a user disconnect. */
        private val ENGINE_RETRY_BACKOFF_MS = longArrayOf(2_000L, 5_000L)

        /** A tunnel that stayed up this long earns a fresh engine retry budget. */
        private const val ENGINE_RETRY_RESET_AFTER_MS = 30_000L

        /** Doze freezes monotonic clocks; a longer gap means the flows are stale. */
        private const val DOZE_RECOVERY_MIN_SLEEP_MS = 120_000L
    }

    private data class ActiveEngine(val handle: Long, val generation: Long)

    private data class StateSnapshot(val state: Int, val detail: String)

    private class DnsResolutionException(message: String) : IllegalStateException(message)

    @Volatile private var stateSnapshot: StateSnapshot = StateSnapshot(VpnState.DISCONNECTED, "")
    private val state: Int get() = stateSnapshot.state
    private val stateDetail: String get() = stateSnapshot.detail
    /** Guarded by [callbackLock]; tracks the last state/detail pushed to callbacks. */
    private var lastPublishedState: Int = VpnState.DISCONNECTED
    private var lastPublishedDetail: String = ""
    /** Guarded by [callbackLock]; tracks the last state posted to NotificationManager. */
    private var lastNotifiedState: Int = VpnState.DISCONNECTED
    /** Set under [callbackLock]; volatile so [stateLock] holders can also read it. */
    @Volatile private var destroyed: Boolean = false
    @Volatile private var activeProfileId: String? = null
    @Volatile private var pendingProfileId: String? = null
    @Volatile private var activeServerHost: String? = null
    /** Resolved address the engine currently dials, compared on network switch. */
    @Volatile private var activeServerIp: String? = null
    @Volatile private var activeIpv4Only: Boolean = true
    @Volatile private var activeEngine: ActiveEngine? = null
    /** Grows while the device sleeps; a long gap means the engine's flows are stale. */
    @Volatile private var lastSleepOffsetMs: Long = currentSleepOffset()

    private var tun: ParcelFileDescriptor? = null
    private var monitor: NetworkMonitor? = null
    /** Guarded by [stateLock]; the doze-exit receiver while the tunnel is up. */
    private var idleReceiver: BroadcastReceiver? = null
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

    /** Serialises state transitions and detach() against teardown(). */
    private val stateLock = Any()

    /** Serialises the blocking establish() calls; never held with [stateLock]. */
    private val establishLock = Any()

    /** Serialises [publishCurrentState] and `RemoteCallbackList` lifecycle across IO/binder/JNI threads. */
    private val callbackLock = Any()

    /** Bumped by every connect()/disconnect()/onRevoke()/onDestroy(); stale attempts abort. */
    private val connectGeneration = AtomicLong(0L)
    /** Guarded by [stateLock]; bounded restart budget for an engine that exits on its own. */
    private var engineRetryCount = 0
    /** Guarded by [stateLock]; [SystemClock.elapsedRealtime] when the engine became active. */
    private var connectedSinceMs = 0L
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
                // Capture stopGen on main immediately. disconnect() itself never
                // blocks: it detaches state under stateLock and hands nativeStop()
                // (up to 2 s) plus the TUN close to cleanupExecutor, and a stale
                // stop still cannot tear down a newer connect().
                val stopGen = connectGeneration.incrementAndGet()
                disconnect(expectedGen = stopGen)
            }
            // ACTION_START, null action, or SERVICE_INTERFACE (Always-on VPN): connect.
            else -> {
                if (intent?.getBooleanExtra(EXTRA_KEEP_ALIVE_ONLY, false) == true) {
                    return START_NOT_STICKY
                }
                // startForegroundService() callers are killed when the foreground
                // notification is late, so post it before the profile lookup.
                if (state == VpnState.DISCONNECTED || state == VpnState.DISCONNECTING) {
                    // Serialised with releaseResources() under callbackLock so a
                    // concurrent teardown cannot remove the notification we just posted.
                    val promoted = synchronized(callbackLock) {
                        runCatching {
                            startForeground(
                                VpnNotificationManager.NOTIFICATION_ID,
                                notifications.build(VpnState.CONNECTING, ""),
                            )
                        }.onSuccess { lastNotifiedState = VpnState.CONNECTING }
                    }
                    if (promoted.isFailure) {
                        Log.e(TAG, "startForeground failed", promoted.exceptionOrNull())
                        val failedChanged = synchronized(stateLock) {
                            updateStateLocked(
                                VpnState.DISCONNECTED,
                                getString(R.string.vpn_error_generic),
                            )
                        }
                        if (failedChanged) publishCurrentState()
                        stopSelfResult(startId)
                        return START_NOT_STICKY
                    }
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
     *
     * Must stay non-suspending: the immediate-exit retry path invokes [connect]
     * from inside [connectJob] and relies on synchronous self-cancellation
     * completing through the new [connectJob] assignment.
     */
    private fun connect(profileId: String, retryGen: Long? = null) {
        val myGen: Long
        val previous: ReleasedResources
        synchronized(stateLock) {
            if (retryGen != null) {
                // Bounded engine restart: only disconnect(), onRevoke(), onDestroy()
                // or a newer connect() can have bumped the generation since.
                if (connectGeneration.get() != retryGen) return
            } else {
                if ((state == VpnState.CONNECTING || state == VpnState.CONNECTED) &&
                    (activeProfileId == profileId || pendingProfileId == profileId)
                ) {
                    return
                }
                // A user or external connect starts with a full restart budget.
                engineRetryCount = 0
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
        // Use startForegroundService() rather than startService(): on Android 12+,
        // startService() throws in the background even when an FGS exemption
        // applies (such as an active tunnel restarting itself or a TileService
        // start). If no exemption applies, startForegroundService() throws
        // ForegroundServiceStartNotAllowedException and abortConnect() cleans up.
        val keepAlive = runCatching {
            ContextCompat.startForegroundService(
                this,
                Intent(this, BeamVpnService::class.java)
                    .setAction(ACTION_START)
                    .putExtra(EXTRA_PROFILE_ID, profileId)
                    .putExtra(EXTRA_KEEP_ALIVE_ONLY, true),
            )
        }
        if (keepAlive.isFailure) {
            Log.e(TAG, "startForegroundService failed", keepAlive.exceptionOrNull())
            abortConnect(myGen, previous)
            return
        }
        // Android 12+ kills the service if the foreground notification is late,
        // so it goes up before any DNS or Keystore work (outside stateLock) and
        // under callbackLock so a concurrent teardown cannot stop it first.
        val promoted = synchronized(callbackLock) {
            runCatching {
                startForeground(
                    VpnNotificationManager.NOTIFICATION_ID,
                    notifications.build(VpnState.CONNECTING, ""),
                )
            }.onSuccess { lastNotifiedState = VpnState.CONNECTING }
        }
        if (promoted.isFailure) {
            Log.e(TAG, "startForeground failed", promoted.exceptionOrNull())
            abortConnect(myGen, previous)
            return
        }
        // Always release any detached previous engine/TUN on the dedicated
        // cleanup executor so cancelling connectJob or serviceScope can never
        // leak an old Rust runtime or TUN descriptor.
        scheduleRelease(previous)
        publishCurrentState()
        synchronized(stateLock) {
            if (connectGeneration.get() == myGen) {
                connectJob = serviceScope.launch { runConnect(profileId, myGen) }
            }
        }
    }

    /**
     * Aborts a connect attempt that could not claim the foreground service.
     * Releases whatever the attempt already detached, clears the pending
     * profile, and stops the service while this attempt still owns it.
     */
    private fun abortConnect(myGen: Long, previous: ReleasedResources) {
        // previous was detached with keepForeground = true; demote the foreground
        // service too (still gated on myGen under callbackLock) so a failed
        // promotion cannot leave a stale notification behind while bound.
        scheduleRelease(previous.copy(stopForeground = true))
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
            // A profile deleted mid-resolve is caught by setActiveProfileIdIfExists
            // post-establish, avoiding a redundant Keystore decrypt on the connect path.

            // A bypass CIDR that covers the TUN /30 would bypass the TUN DNS.
            val rawBypass = settings.bypassCidrs
            val bypass = VpnConfigBuilder.sanitizeBypassCidrs(
                rawBypass,
                allowIpv6 = Build.VERSION.SDK_INT >= 33,
            )
            if (bypass.size != rawBypass.size) {
                Log.w(TAG, "dropped ${rawBypass.size - bypass.size} unsupported bypass CIDRs")
            }
            val (dohUrl, dohFellBack) = VpnConfigBuilder.sanitizeDohUrl(settings.dohUrl)
            if (dohFellBack) Log.w(TAG, "invalid stored DoH URL; using the default")
            val configJson = VpnConfigBuilder.buildConfigJson(
                vlessUri = profile.uri,
                dohUrl = dohUrl,
                ipv4Only = settings.ipv4Only,
                rejectQuic = settings.rejectQuic,
                bypassCidrs = bypass,
                serverIp = serverIp,
            )

            // Narrow establishLock: hold it only for establish(), release before
            // nativeStart() so onDestroy()/disconnect() on the main thread can never
            // ANR behind JNI startup while two attempts stay serialised.
            val pfd = synchronized(establishLock) {
                if (connectGeneration.get() != myGen) return
                buildTunBuilder(bypass, settings.treatAsUnmetered).establish()
                    ?: throw IllegalStateException("establish() returned null")
            }
            // Re-check after blocking establish(): a concurrent disconnect/onRevoke/onDestroy
            // bumps connectGeneration, so abort before starting Rust.
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
                                updateStateLocked(s, "")
                            }
                            if (shouldDisconnect) {
                                // Unexpected engine exit (e.g. fatal TUN error).
                                serviceScope.launch { handleUnexpectedEngineExit(myGen) }
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
                    activeServerIp = serverIp
                    activeIpv4Only = settings.ipv4Only
                    connectedSinceMs = SystemClock.elapsedRealtime()
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
                // An engine that exits immediately is a failure, not a user stop:
                // go through the bounded restart instead of a silent teardown.
                handleUnexpectedEngineExit(myGen)
                return
            }
            // Re-check generation and active handle under stateLock so a concurrent
            // onDestroy()/disconnect() cannot have CONNECTED re-posted after teardown.
            var liveChanged = false
            val stillOwner = synchronized(stateLock) {
                if (connectGeneration.get() == myGen && activeEngine?.handle == handle) {
                    liveChanged = updateStateLocked(liveState, "")
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
                    // A superseded attempt must not reseat the underlying network
                    // after a newer connect() or disconnect() took over.
                    if (connectGeneration.get() == myGen) {
                        runCatching { setUnderlyingNetworks(arrayOf(network)) }
                            .onFailure { Log.w(TAG, "initial setUnderlyingNetworks failed", it) }
                    }
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
                                val lostGen = networkSwitchGeneration.incrementAndGet()
                                networkSwitchJob?.cancel()
                                // Off the network callback thread: setUnderlyingNetworks()
                                // and the JNI call must never stall the framework callback.
                                networkSwitchJob = serviceScope.launch {
                                    if (connectGeneration.get() == myGen &&
                                        networkSwitchGeneration.get() == lostGen
                                    ) {
                                        runCatching { setUnderlyingNetworks(null) }
                                            .onFailure {
                                                Log.w(TAG, "setUnderlyingNetworks(null) failed", it)
                                            }
                                        notifyNativeNetworkChange(serverIp = null)
                                    }
                                }
                            }
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
            registerIdleExitReceiver(myGen)

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

    /** Builds the TUN parameters; the caller holds [establishLock] for establish(). */
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

    /**
     * Doze freezes every flow without telling the engine. On leaving idle mode
     * after a long sleep, or when the tunnel is already degraded, reset the
     * engine's flows once. A fresh instance per connect keeps an old release
     * from unregistering the newer registration.
     */
    private fun newIdleExitReceiver(): BroadcastReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED) return
            val power = getSystemService(PowerManager::class.java) ?: return
            if (power.isDeviceIdleMode) return
            val nowOffset = currentSleepOffset()
            val sleepDelta = nowOffset - lastSleepOffsetMs
            lastSleepOffsetMs = nowOffset
            if (sleepDelta < DOZE_RECOVERY_MIN_SLEEP_MS && state != VpnState.DEGRADED) return
            // Native call with its own locks: never run it on the main thread.
            serviceScope.launch { notifyNativeNetworkChange(null) }
        }
    }

    private fun registerIdleExitReceiver(expectedGen: Long) {
        val receiver = newIdleExitReceiver()
        lastSleepOffsetMs = currentSleepOffset()
        val registered = runCatching {
            ContextCompat.registerReceiver(
                this,
                receiver,
                IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED),
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
        }.onFailure { Log.w(TAG, "idle receiver registration failed", it) }
            .isSuccess
        if (!registered) return
        val keep = synchronized(stateLock) {
            if (connectGeneration.get() == expectedGen && activeEngine != null && idleReceiver == null) {
                idleReceiver = receiver
                true
            } else {
                false
            }
        }
        // A teardown or newer connect that raced this registration already owns the cleanup.
        if (!keep) runCatching { unregisterReceiver(receiver) }
    }

    /** Grows while the device sleeps: [SystemClock.elapsedRealtime] keeps counting in Doze. */
    private fun currentSleepOffset(): Long =
        SystemClock.elapsedRealtime() - SystemClock.uptimeMillis()

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
        // Reset stale TCP flows from the old network now instead of leaving them
        // stalled until DNS resolves; server_ip is refreshed below when it changed.
        notifyNativeNetworkChange(null)
        val host = activeServerHost
        if (host == null || SettingsValidator.isIpLiteral(host)) return
        val firstIp = withTimeoutOrNull(RESOLVE_TIMEOUT_MS) {
            resolveServerHostOnNetwork(network, host, activeIpv4Only)
        }
        if (connectGeneration.get() != expectedGen || networkSwitchGeneration.get() != expectedSwitchGen) {
            return
        }
        if (firstIp != null) {
            applyResolvedServerIp(firstIp)
            return
        }
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
                applyResolvedServerIp(retriedIp)
                return
            }
        }
    }

    /** Pokes the engine with a new server address only when it actually changed. */
    private fun applyResolvedServerIp(serverIp: String) {
        if (serverIp == activeServerIp) return
        notifyNativeNetworkChange(serverIp)
        activeServerIp = serverIp
    }

    private data class ReleasedResources(
        val handle: Long,
        val tun: ParcelFileDescriptor?,
        val monitor: NetworkMonitor? = null,
        val idleReceiver: BroadcastReceiver? = null,
        val stopForeground: Boolean,
        val generation: Long,
    )

    /** Bounded engine restart after the native engine exited on its own. */
    private data class EngineRetry(
        val profileId: String,
        val attempt: Int,
        val backoffMs: Long,
        val released: ReleasedResources,
    )

    private fun stopSelfIfIdle(expectedGen: Long, startId: Int) {
        synchronized(stateLock) {
            if (connectGeneration.get() != expectedGen && state == VpnState.DISCONNECTED) {
                stopSelfResult(startId)
            }
        }
    }

    private fun disconnect(expectedGen: Long? = null, detail: String = "") {
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
        if (released.handle == 0L && released.tun == null && released.monitor == null &&
            released.idleReceiver == null && !released.stopForeground
        ) {
            finalizeDisconnect(myGen, detail)
        } else {
            scheduleRelease(released) { finalizeDisconnect(myGen, detail) }
        }
    }

    private fun finalizeDisconnect(myGen: Long, detail: String = "") {
        val changed = synchronized(stateLock) {
            if (connectGeneration.get() == myGen) {
                if (state != VpnState.DISCONNECTED) {
                    updateStateLocked(VpnState.DISCONNECTED, detail)
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
        // Same non-blocking teardown as ACTION_STOP: state is cleared under
        // stateLock and nativeStop() runs on cleanupExecutor.
        disconnect(expectedGen = stopGen)
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
        if (released.handle == 0L && released.tun == null && released.monitor == null &&
            released.idleReceiver == null && !released.stopForeground
        ) {
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
        val oldMonitor = monitor
        monitor = null
        oldMonitor?.markStopped()
        val oldIdleReceiver = idleReceiver
        idleReceiver = null
        pendingProfileId = null
        activeProfileId = null
        activeServerHost = null
        activeServerIp = null
        connectedSinceMs = 0L
        val h = activeEngine?.handle ?: 0L
        activeEngine = null
        val pfd = tun
        tun = null
        return ReleasedResources(
            handle = h,
            tun = pfd,
            monitor = oldMonitor,
            idleReceiver = oldIdleReceiver,
            stopForeground = !keepForeground,
            generation = connectGeneration.get(),
        )
    }

    private fun releaseResources(released: ReleasedResources) {
        released.monitor?.unregister()
        released.idleReceiver?.let { receiver ->
            runCatching { unregisterReceiver(receiver) }
        }
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
        // Only remove the foreground notification if no newer connect() superseded
        // this teardown; callbackLock orders this against startForeground().
        if (released.stopForeground) {
            synchronized(callbackLock) {
                if (connectGeneration.get() == released.generation) {
                    runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
                        .onSuccess { lastNotifiedState = VpnState.DISCONNECTED }
                }
            }
        }
    }

    /**
     * The native engine exited without a user disconnect. Restart it a bounded
     * number of times with a short backoff while the foreground service stays
     * up, then fall back to a full teardown.
     */
    private suspend fun handleUnexpectedEngineExit(myGen: Long) {
        val retry = synchronized(stateLock) {
            if (connectGeneration.get() != myGen || destroyed) return
            val profileId = activeProfileId ?: return
            // A tunnel that stayed up long enough earns a fresh retry budget.
            if (connectedSinceMs != 0L &&
                SystemClock.elapsedRealtime() - connectedSinceMs >= ENGINE_RETRY_RESET_AFTER_MS
            ) {
                engineRetryCount = 0
            }
            if (engineRetryCount >= ENGINE_RETRY_BACKOFF_MS.size) {
                null
            } else {
                val backoffMs = ENGINE_RETRY_BACKOFF_MS[engineRetryCount]
                engineRetryCount += 1
                val attempt = engineRetryCount
                // Release the dead engine and TUN, but keep the notification up.
                val released = detachResources(keepForeground = true)
                updateStateLocked(VpnState.CONNECTING, "")
                EngineRetry(profileId, attempt, backoffMs, released)
            }
        } ?: run {
            // Restart budget exhausted: surface why the tunnel is gone.
            disconnect(expectedGen = myGen, detail = getString(R.string.vpn_error_native))
            return
        }
        Log.i(TAG, "engine exited; retry ${retry.attempt} in ${retry.backoffMs} ms")
        publishCurrentState()
        scheduleRelease(retry.released)
        delay(retry.backoffMs)
        // connect() re-checks myGen under stateLock, so a user disconnect(),
        // onRevoke(), onDestroy() or a newer connect() cancels this retry.
        connect(retry.profileId, retryGen = myGen)
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
                    changed = updateStateLocked(reported, "")
                }
                false
            }
        }
        if (changed) publishCurrentState()
        if (shouldDisconnect) {
            serviceScope.launch { handleUnexpectedEngineExit(gen) }
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
            // Notification ONLY on state transitions not already posted (e.g. by startForeground).
            if (s != lastNotifiedState) {
                lastNotifiedState = s
                if (s == VpnState.DISCONNECTED) {
                    notifications.cancel()
                } else {
                    notifications.notify(s, detail)
                }
            }
        }
    }
}
