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
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
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

    private var isBound = false
    private var pendingProfileId: String? = null

    private val stateCallback = object : IBeamStateCallback.Stub() {
        override fun onStateChanged(state: Int, detail: String?) {
            _status.value = BeamStatus(state, detail?.takeIf { it.isNotBlank() })
        }
    }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val service = binder?.let { IBeamVpnService.Stub.asInterface(it) } ?: return
            beam = service
            runCatching { service.registerCallback(stateCallback) }
            lifecycleScope.launch {
                // Binder reads are I/O: the service polls the engine for state.
                val snapshot = withContext(Dispatchers.IO) {
                    runCatching { service.getState() to service.getStateDetail() }.getOrNull()
                } ?: return@launch
                _status.value = BeamStatus(snapshot.first, snapshot.second?.takeIf { it.isNotBlank() })
            }
            val pending = pendingProfileId
            if (pending != null) {
                pendingProfileId = null
                startVpn(pending)
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            beam = null
        }
    }

    private val vpnConsentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val profileId = pendingProfileId
        pendingProfileId = null
        if (result.resultCode != RESULT_OK) {
            showMessage(R.string.vpn_consent_denied)
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
            binding.fragmentContainer.updatePadding(left = bars.left, top = bars.top, right = bars.right)
            binding.bottomNav.updatePadding(left = bars.left, right = bars.right, bottom = bars.bottom)
            WindowInsetsCompat.CONSUMED
        }
        binding.bottomNav.setOnItemSelectedListener { item ->
            showTab(item.itemId)
            true
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
        if (isBound) {
            runCatching { beam?.unregisterCallback(stateCallback) }
            runCatching { unbindService(serviceConnection) }
            isBound = false
        }
        beam = null
        super.onStop()
    }

    /** Connect with [profileId], after the Android VPN consent dialog when needed. */
    fun requestConnect(profileId: String) {
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

    fun showReconnectHint() {
        if (!isTunnelActive()) return
        Snackbar.make(binding.fragmentContainer, R.string.reconnect_to_apply, Snackbar.LENGTH_LONG)
            .setAnchorView(binding.bottomNav)
            .setAction(R.string.action_reconnect) {
                lifecycleScope.launch {
                    val activeId = withContext(Dispatchers.IO) {
                        runCatching { beam?.disconnect() }
                        runCatching { EncryptedProfileStore(this@MainActivity).getActiveProfileId() }.getOrNull()
                    } ?: return@launch
                    requestConnect(activeId)
                }
            }
            .show()
    }

    fun openProfiles() {
        binding.bottomNav.selectedItemId = R.id.nav_profiles
    }

    private fun startVpn(profileId: String) {
        requestNotificationPermission()
        val consent = runCatching { VpnService.prepare(this) }.getOrNull()
        if (consent != null) {
            pendingProfileId = profileId
            vpnConsentLauncher.launch(consent)
            return
        }
        val service = beam
        if (service == null) {
            pendingProfileId = profileId
            ensureBound()
            return
        }
        lifecycleScope.launch {
            val connected = withContext(Dispatchers.IO) {
                runCatching { service.connect(profileId) }.isSuccess
            }
            if (!connected) showMessage(R.string.connect_failed)
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
            showMessage(R.string.connect_failed)
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
        val manager = supportFragmentManager
        manager.commitNow {
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

    private fun showMessage(resId: Int) {
        Toast.makeText(this, resId, Toast.LENGTH_SHORT).show()
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
