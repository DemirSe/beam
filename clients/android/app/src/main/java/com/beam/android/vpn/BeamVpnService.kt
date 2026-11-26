package com.beam.android.vpn

import android.content.Intent
import android.net.ConnectivityManager
import android.net.IpPrefix
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
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject

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

        /** DNS must never hold up the foreground service start. */
        private const val RESOLVE_TIMEOUT_MS = 5_000L
    }

    @Volatile private var state: Int = VpnState.DISCONNECTED
    @Volatile private var stateDetail: String = ""
    @Volatile private var activeProfileId: String? = null
    @Volatile private var pendingProfileId: String? = null
    @Volatile private var engineHandle: Long = 0L
    @Volatile private var engineGeneration: Long = 0L

    private var tun: ParcelFileDescriptor? = null
    private var monitor: NetworkMonitor? = null
    private lateinit var notifications: VpnNotificationManager
    private val callbacks = RemoteCallbackList<IBeamStateCallback>()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Serialises establish()/nativeStart() against teardown(). */
    private val stateLock = Any()

    /** Serialises setState() + RemoteCallbackList.beginBroadcast() across IO/binder/JNI threads. */
    private val callbackLock = Any()

    /** Bumped by every connect()/disconnect()/onRevoke()/onDestroy(); stale attempts abort. */
    private val connectGeneration = AtomicLong(0L)
    private var connectJob: Job? = null

    private val binder = object : IBeamVpnService.Stub() {
        override fun connect(profileId: String) {
            this@BeamVpnService.connect(profileId)
        }

        override fun disconnect() {
            this@BeamVpnService.disconnect()
        }

        override fun getState(): Int {
            // Poll so binder callers see the state the engine derived last.
            if (this@BeamVpnService.engineHandle != 0L) this@BeamVpnService.pollTelemetry()
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
            ACTION_STOP -> disconnect()
            // ACTION_START, null action, or SERVICE_INTERFACE (Always-on VPN): connect.
            else -> {
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
                        if (state == VpnState.DISCONNECTED) stopSelf()
                        return@launch
                    }
                    val id = intent?.getStringExtra(EXTRA_PROFILE_ID)
                        ?: EncryptedProfileStore(this@BeamVpnService).getActiveProfileId()
                    if (startGen != connectGeneration.get()) {
                        if (state == VpnState.DISCONNECTED) stopSelf()
                        return@launch
                    }
                    if (id != null) {
                        connect(id)
                    } else {
                        // Nothing to connect to: stop instead of idling in foreground.
                        synchronized(stateLock) { teardown() }
                        setState(VpnState.DISCONNECTED, "")
                        stopSelf()
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
        if ((state == VpnState.CONNECTING || state == VpnState.CONNECTED) &&
            (activeProfileId == profileId || pendingProfileId == profileId)
        ) {
            return
        }
        val myGen = connectGeneration.incrementAndGet()
        connectJob?.cancel()
        connectJob = null

        // Android 12+ kills the service if the foreground notification is late,
        // so it goes up before any DNS or Keystore work.
        startForeground(
            VpnNotificationManager.NOTIFICATION_ID,
            notifications.build(VpnState.CONNECTING, ""),
        )
        synchronized(stateLock) {
            // a disconnect() that landed in between owns the cleanup.
            if (connectGeneration.get() != myGen) {
                teardown()
                setState(VpnState.DISCONNECTED, "")
                return
            }
            // A new profile drops the old engine before the new one starts.
            teardown(keepForeground = true)
            // Track pending attempt separately so getActiveProfileId() only
            // publishes a profile once the tunnel is actually established.
            pendingProfileId = profileId
            setState(VpnState.CONNECTING, "")
            connectJob = serviceScope.launch { runConnect(profileId, myGen) }
        }
    }

    private suspend fun runConnect(profileId: String, myGen: Long) {
        try {
            val store = EncryptedProfileStore(this)
            val profile = store.getProfile(profileId)
                ?: throw IllegalArgumentException("unknown profile")
            val settings = SettingsStore(this).load()

            // Resolve before establish(): once the TUN is up, the lookup would
            // be captured by our own tunnel. The 5 s deadline is best effort
            // because a blocking lookup is not interruptible; on timeout the
            // engine resolves the host itself, exactly like a failed lookup.
            val serverIp = withTimeoutOrNull(RESOLVE_TIMEOUT_MS) {
                resolveServerHost(profile.serverHost, settings.ipv4Only)
            }
            if (connectGeneration.get() != myGen) return

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

            synchronized(stateLock) {
                // disconnect() or a newer connect() may have won while we
                // resolved: this attempt owns nothing, so never start the engine.
                if (connectGeneration.get() != myGen) return
                val pfd = buildTunBuilder(bypass).establish()
                    ?: throw IllegalStateException("establish() returned null")
                val fd = pfd.detachFd()
                val handle = try {
                    BeamNativeBridge.nativeStart(
                        fd, configJson, this,
                        object : NativeStateListener {
                            override fun onNativeStateChanged(s: Int, detail: String) {
                                setState(s, detail)
                            }
                        },
                    )
                } catch (e: LinkageError) {
                    // nativeStart was never entered, so Rust never took the fd:
                    // closing it here is the only owner, exactly once.
                    runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
                    throw e
                }
                tun = pfd
                engineHandle = handle
                engineGeneration = myGen
                activeProfileId = profileId
                pendingProfileId = null
                val cm = getSystemService(ConnectivityManager::class.java)
                monitor = NetworkMonitor(
                    cm,
                    onNetworkSwitch = { network ->
                        runCatching { setUnderlyingNetworks(arrayOf(network)) }
                            .onFailure { Log.w(TAG, "setUnderlyingNetworks failed", it) }
                        notifyNativeNetworkChange()
                    },
                    onNetworkLost = {
                        runCatching { setUnderlyingNetworks(null) }
                            .onFailure { Log.w(TAG, "setUnderlyingNetworks(null) failed", it) }
                        notifyNativeNetworkChange()
                    },
                ).also { it.start() }
            }
            store.setActiveProfileId(profile.id)
            // The engine reports CONNECTED/DEGRADED from live telemetry.
        } catch (c: CancellationException) {
            // A cancelling connect()/disconnect() owns the cleanup of whatever
            // was already established.
            throw c
        } catch (t: Throwable) {
            // Throwable, not Exception: a missing or stale libbeam_android.so
            // surfaces as LinkageError/ExceptionInInitializerError.
            Log.e(TAG, "connect failed", t)
            synchronized(stateLock) { teardown() }
            setState(VpnState.DISCONNECTED, userFacingError(t))
            stopSelf()
        }
    }

    private fun userFacingError(t: Throwable): String = when {
        t is IllegalArgumentException && t.message?.contains("profile", ignoreCase = true) == true ->
            getString(R.string.vpn_error_profile)
        t is IllegalStateException && t.message?.contains("establish()", ignoreCase = true) == true ->
            getString(R.string.vpn_error_consent)
        t is LinkageError || t is IllegalStateException ->
            getString(R.string.vpn_error_native)
        else -> getString(R.string.vpn_error_generic)
    }

    /** Builds the TUN parameters; the caller holds [stateLock] for establish(). */
    private fun buildTunBuilder(bypass: List<String>): Builder {
        val builder = Builder()
            .setMtu(VpnConfigBuilder.MTU)
            .addAddress(VpnConfigBuilder.TUN_IPV4, VpnConfigBuilder.TUN_PREFIX)
            // Capture IPv6 so reject_ipv6=true prevents clear IPv6 leaks.
            .addAddress("fd00:be:a::1", 126)
            .addRoute("::", 0)
            .addDnsServer(VpnConfigBuilder.TUN_DNS_IPV4)
            .setMetered(false)
            .setBlocking(false)
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

    /** Resolves the profile host; null lets the engine resolve it. */
    private suspend fun resolveServerHost(host: String, ipv4Only: Boolean): String? =
        withContext(Dispatchers.IO) {
            val addresses = runCatching { InetAddress.getAllByName(host) }.getOrNull()
            if (addresses.isNullOrEmpty()) {
                Log.w(TAG, "server host not resolved locally; engine will retry")
                return@withContext null
            }
            val preferred = if (ipv4Only) addresses.firstOrNull { it is Inet4Address } else null
            (preferred ?: addresses.first()).hostAddress
        }

    private fun disconnect() {
        // Bump first: an in-flight connect() must not establish behind our back.
        connectGeneration.incrementAndGet()
        connectJob?.cancel()
        connectJob = null
        synchronized(stateLock) {
            if (state != VpnState.DISCONNECTED) setState(VpnState.DISCONNECTING, "")
            teardown()
            if (state != VpnState.DISCONNECTED) setState(VpnState.DISCONNECTED, "")
        }
        stopSelf()
    }

    override fun onRevoke() {
        connectGeneration.incrementAndGet()
        disconnect()
    }

    override fun onDestroy() {
        connectGeneration.incrementAndGet()
        connectJob?.cancel()
        connectJob = null
        serviceScope.cancel()
        synchronized(stateLock) { teardown() }
        callbacks.kill()
        super.onDestroy()
    }

    /**
     * Releases the TUN and the engine. The caller holds [stateLock] so it
     * cannot interleave with establish()/nativeStart().
     */
    private fun teardown(keepForeground: Boolean = false) {
        monitor?.stop()
        monitor = null
        pendingProfileId = null
        val h = engineHandle
        engineHandle = 0L
        engineGeneration = 0L
        if (h != 0L) {
            try {
                BeamNativeBridge.nativeStop(h)
            } catch (t: Throwable) {
                Log.w(TAG, "nativeStop failed", t)
            }
        }
        try {
            tun?.close()
        } catch (_: Throwable) {
        }
        tun = null
        if (!keepForeground) stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun pollTelemetry(): String {
        val h = engineHandle
        val gen = engineGeneration
        if (h == 0L || gen == 0L) return "{}"
        return try {
            val json = BeamNativeBridge.nativePollTelemetry(h) ?: return "{}"
            applyNativeState(json, gen)
            json
        } catch (t: Throwable) {
            Log.w(TAG, "telemetry poll failed", t)
            "{}"
        }
    }

    /** The engine re-derives CONNECTED/DEGRADED on every poll. */
    private fun applyNativeState(json: String, gen: Long) {
        if (gen != connectGeneration.get()) return
        val reported = runCatching { JSONObject(json) }.getOrNull()
            ?.takeIf { it.has("state") }
            ?.optInt("state")
            ?: return
        if (reported == state) return
        // Telemetry owns the state, not the detail: never forward a stale one.
        setState(reported, if (reported == VpnState.DEGRADED) "degraded" else "")
    }

    private fun notifyNativeNetworkChange() {
        val h = engineHandle
        if (h == 0L) return
        try {
            BeamNativeBridge.nativeNotifyNetworkChange(h)
        } catch (t: Throwable) {
            Log.w(TAG, "nativeNotifyNetworkChange failed", t)
        }
    }

    private fun setState(s: Int, detail: String) {
        synchronized(callbackLock) {
            val changed = (s != state)
            state = s
            stateDetail = detail
            // Notification ONLY on transitions.
            if (changed) {
                if (s == VpnState.DISCONNECTED) {
                    notifications.cancel()
                } else {
                    notifications.notify(s, detail)
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
}
