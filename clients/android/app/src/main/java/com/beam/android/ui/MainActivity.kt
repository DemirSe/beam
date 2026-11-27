package com.beam.android.ui

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.core.view.updatePadding
import androidx.fragment.app.Fragment
import androidx.fragment.app.commitNow
import androidx.lifecycle.lifecycleScope
import com.beam.android.R
import com.beam.android.databinding.ActivityMainBinding
import com.beam.android.ipc.IBeamStateCallback
import com.beam.android.ipc.IBeamVpnService
import com.beam.android.storage.EncryptedProfileStore
import com.beam.android.vpn.BeamVpnService
import com.beam.android.vpn.VpnState
import com.google.android.material.snackbar.Snackbar
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Current tunnel state, pushed by the `:vpn` process. */
data class BeamStatus(val state: Int = VpnState.DISCONNECTED, val detail: String? = null)

/**
 * UI shell: bottom navigation plus the AIDL binding to `BeamVpnService`.
 *
 * The binding exists only between [onStart] and [onStop]. Closing the UI
 * therefore leaves the isolated `:vpn` process and its tunnel untouched.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val _status = MutableStateFlow(BeamStatus())
    val status: StateFlow<BeamStatus> = _status.asStateFlow()

    @Volatile
    var beam: IBeamVpnService? = null
        private set

    private var boundBinder: IBinder? = null
    private var isBound = false
    private var pendingProfileId: String? = null

    // Serialises state pushes from the service against snapshot reads and local
    // banner updates so an older read cannot overwrite a newer callback.
    private val statusLock = Any()
    private val callbackSeq = AtomicLong(0L)

    private val binderDeathRecipient = IBinder.DeathRecipient {
        runOnUiThread { handleBinderDied() }
    }

    private val stateCallback = object : IBeamStateCallback.Stub() {
        override fun onStateChanged(state: Int, detail: String?) {
            synchronized(statusLock) {
                callbackSeq.incrementAndGet()
                _status.value = BeamStatus(state, detail?.takeIf { it.isNotBlank() })
            }
        }
    }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val service = binder?.let { IBeamVpnService.Stub.asInterface(it) } ?: return
            unlinkBinderDeath()
            boundBinder = binder
            runCatching { binder.linkToDeath(binderDeathRecipient, 0) }
            beam = service
            runCatching { service.registerCallback(stateCallback) }
            val seqBefore = callbackSeq.get()
            lifecycleScope.launch {
                // Binder reads are I/O: the service polls the engine for state.
                val snapshot = withContext(Dispatchers.IO) {
                    runCatching { service.getState() to service.getStateDetail() }.getOrNull()
                } ?: return@launch
                // A callback that landed during the read is newer than the snapshot.
                synchronized(statusLock) {
                    if (callbackSeq.get() != seqBefore || beam !== service) return@launch
                    _status.value = BeamStatus(snapshot.first, snapshot.second?.takeIf { it.isNotBlank() })
                }
            }
            val pending = pendingProfileId
            if (pending != null) {
                pendingProfileId = null
                startVpn(pending)
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            // Ignore a stale disconnect from a previous dead binding after rebind succeeded.
            if (boundBinder?.isBinderAlive == true) return
            unlinkBinderDeath()
            synchronized(statusLock) {
                beam = null
                callbackSeq.incrementAndGet()
                _status.value = BeamStatus(VpnState.DISCONNECTED)
            }
        }

        override fun onBindingDied(name: ComponentName?) {
            handleBinderDied()
        }
    }

    private val vpnConsentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val profileId = pendingProfileId
        pendingProfileId = null
        if (result.resultCode != RESULT_OK) {
            synchronized(statusLock) {
                callbackSeq.incrementAndGet()
                _status.value = BeamStatus(VpnState.DISCONNECTED, getString(R.string.vpn_consent_denied))
            }
        } else if (profileId != null) {
            requestConnect(profileId)
        }
    }

    // A denied notification permission hides the foreground notification only;
    // the tunnel itself keeps running.
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        pendingProfileId = savedInstanceState?.getString(STATE_PENDING_PROFILE_ID)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        ViewCompat.setOnApplyWindowInsetsListener(binding.mainRoot) { _, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
            )
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            val imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime())
            // Edge-to-edge: the window no longer resizes behind the keyboard, so
            // hide the bar and lift the content over the IME by hand.
            binding.bottomNav.isVisible = !imeVisible
            binding.fragmentContainer.updatePadding(
                left = bars.left,
                top = bars.top,
                right = bars.right,
                bottom = if (imeVisible) maxOf(ime.bottom, bars.bottom) else 0,
            )
            binding.bottomNav.updatePadding(left = bars.left, right = bars.right, bottom = bars.bottom)
            WindowInsetsCompat.CONSUMED
        }
        binding.bottomNav.setOnItemSelectedListener { item ->
            if (supportFragmentManager.isStateSaved) {
                false
            } else {
                showTab(item.itemId)
                true
            }
        }
        if (supportFragmentManager.fragments.isEmpty()) {
            val restored = binding.bottomNav.selectedItemId
            showTab(if (TAB_TAGS.containsKey(restored)) restored else R.id.nav_dashboard)
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        pendingProfileId?.let { outState.putString(STATE_PENDING_PROFILE_ID, it) }
    }

    override fun onStart() {
        super.onStart()
        ensureBound()
    }

    override fun onStop() {
        unlinkBinderDeath()
        if (isBound) {
            runCatching { beam?.unregisterCallback(stateCallback) }
            runCatching { unbindService(serviceConnection) }
            isBound = false
        }
        beam = null
        super.onStop()
    }

    private fun unlinkBinderDeath() {
        val prev = boundBinder
        boundBinder = null
        if (prev != null) {
            runCatching { prev.unlinkToDeath(binderDeathRecipient, 0) }
        }
    }

    private fun handleBinderDied() {
        unlinkBinderDeath()
        synchronized(statusLock) {
            beam = null
            callbackSeq.incrementAndGet()
            _status.value = BeamStatus(VpnState.DISCONNECTED)
        }
        if (isBound) {
            runCatching { unbindService(serviceConnection) }
            isBound = false
        }
        if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)) {
            ensureBound()
        }
    }

    /** Connect with [profileId], after the Android VPN consent dialog when needed. */
    fun requestConnect(profileId: String) {
        clearErrorDetail()
        if (beam == null) {
            pendingProfileId = profileId
            ensureBound()
            return
        }
        startVpn(profileId)
    }

    fun requestDisconnect() {
        val service = beam ?: return
        lifecycleScope.launch {
            withContext(Dispatchers.IO) { runCatching { service.disconnect() } }
        }
    }

    fun isTunnelActive(): Boolean {
        val s = status.value.state
        return s == VpnState.CONNECTED || s == VpnState.DEGRADED || s == VpnState.CONNECTING
    }

    /** Drop a stale failure message so the next attempt starts from a clean banner. */
    fun clearErrorDetail() {
        synchronized(statusLock) {
            val current = _status.value
            if (current.state == VpnState.DISCONNECTED && current.detail != null) {
                _status.value = BeamStatus(VpnState.DISCONNECTED)
            }
        }
    }

    fun showReconnectHint() {
        if (!isTunnelActive() || isFinishing || isDestroyed ||
            !lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED) ||
            !binding.fragmentContainer.isAttachedToWindow
        ) {
            return
        }
        val snackbar = Snackbar.make(
            binding.fragmentContainer,
            R.string.reconnect_to_apply,
            Snackbar.LENGTH_LONG,
        )
        if (binding.bottomNav.isVisible) {
            snackbar.setAnchorView(binding.bottomNav)
        }
        snackbar.setAction(R.string.action_reconnect) {
            lifecycleScope.launch {
                val activeId = withContext(Dispatchers.IO) {
                    runCatching { beam?.disconnect() }
                    runCatching { EncryptedProfileStore(this@MainActivity).getActiveProfileId() }.getOrNull()
                } ?: return@launch
                requestConnect(activeId)
            }
        }.show()
    }

    fun openProfiles() {
        if (supportFragmentManager.isStateSaved) return
        binding.bottomNav.selectedItemId = R.id.nav_profiles
    }

    private fun startVpn(profileId: String) {
        lifecycleScope.launch {
            val consent = withContext(Dispatchers.IO) {
                runCatching { VpnService.prepare(this@MainActivity) }.getOrNull()
            }
            if (!lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED) ||
                supportFragmentManager.isStateSaved
            ) {
                pendingProfileId = profileId
                return@launch
            }
            if (consent != null) {
                pendingProfileId = profileId
                vpnConsentLauncher.launch(consent)
                return@launch
            }
            val service = beam
            if (service == null) {
                pendingProfileId = profileId
                ensureBound()
                return@launch
            }
            // Ask for notifications only when the tunnel is about to start, so the
            // permission dialog never stacks on top of the VPN consent dialog.
            requestNotificationPermission()
            val connected = withContext(Dispatchers.IO) {
                runCatching { service.connect(profileId) }.isSuccess
            }
            if (!connected) {
                synchronized(statusLock) {
                    callbackSeq.incrementAndGet()
                    _status.value = BeamStatus(_status.value.state, getString(R.string.connect_failed))
                }
            }
        }
    }

    private fun ensureBound() {
        if (isBound) return
        isBound = bindService(
            Intent(this, BeamVpnService::class.java),
            serviceConnection,
            Context.BIND_AUTO_CREATE,
        )
        if (!isBound) {
            pendingProfileId = null
            synchronized(statusLock) {
                callbackSeq.incrementAndGet()
                _status.value = BeamStatus(_status.value.state, getString(R.string.connect_failed))
            }
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun showTab(itemId: Int) {
        val tag = TAB_TAGS[itemId] ?: return
        // commitNow throws once the activity state is saved.
        if (supportFragmentManager.isStateSaved) return
        val manager = supportFragmentManager
        manager.commitNow {
            setReorderingAllowed(true)
            for (fragment in manager.fragments) hide(fragment)
            val existing = manager.findFragmentByTag(tag)
            if (existing == null) {
                add(R.id.fragment_container, newFragment(itemId), tag)
            } else {
                show(existing)
            }
        }
    }

    private fun newFragment(itemId: Int): Fragment = when (itemId) {
        R.id.nav_profiles -> ProfilesFragment()
        R.id.nav_settings -> SettingsFragment()
        else -> DashboardFragment()
    }

    private companion object {
        const val STATE_PENDING_PROFILE_ID = "pending_profile_id"
        const val TAG_DASHBOARD = "dashboard"
        const val TAG_PROFILES = "profiles"
        const val TAG_SETTINGS = "settings"

        val TAB_TAGS = mapOf(
            R.id.nav_dashboard to TAG_DASHBOARD,
            R.id.nav_profiles to TAG_PROFILES,
            R.id.nav_settings to TAG_SETTINGS,
        )
    }
}
