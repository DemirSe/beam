package com.beam.android.ui

import android.content.res.ColorStateList
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.core.graphics.ColorUtils
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.beam.android.R
import com.beam.android.databinding.FragmentDashboardBinding
import com.beam.android.storage.EncryptedProfileStore
import com.beam.android.vpn.TelemetryDto
import com.beam.android.vpn.VpnState
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Status, active profile and connect button.
 *
 * Battery rule: telemetry is polled at [POLL_INTERVAL_MS] only while the view
 * is STARTED and only while connected or degraded. Zero polling elsewhere.
 */
class DashboardFragment : Fragment() {

    private var _binding: FragmentDashboardBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        _binding = FragmentDashboardBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.connectButton.setOnClickListener { toggleVpn() }
        binding.addProfileButton.setOnClickListener {
            (requireActivity() as MainActivity).openProfiles()
        }
        observeStatus()
    }

    override fun onResume() {
        super.onResume()
        renderActiveProfile()
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }

    private fun observeStatus() {
        val main = requireActivity() as MainActivity
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    main.status.collectLatest { renderStatus(it) }
                }
                launch {
                    main.status
                        .map { it.state }
                        .distinctUntilChanged()
                        .collectLatest { state ->
                            if (state == VpnState.CONNECTED || state == VpnState.DEGRADED) {
                                while (true) {
                                    refreshTelemetry()
                                    delay(POLL_INTERVAL_MS)
                                }
                            } else {
                                renderTelemetry(null)
                            }
                        }
                }
            }
        }
    }

    private fun toggleVpn() {
        val main = requireActivity() as MainActivity
        val state = main.status.value.state
        if (state == VpnState.CONNECTED || state == VpnState.DEGRADED ||
            state == VpnState.CONNECTING
        ) {
            main.requestDisconnect()
            return
        }
        val context = requireContext()
        viewLifecycleOwner.lifecycleScope.launch {
            val profile = withContext(Dispatchers.IO) {
                runCatching { EncryptedProfileStore(context).getActiveProfile() }.getOrNull()
            }
            if (profile == null) {
                main.openProfiles()
            } else {
                main.requestConnect(profile.id)
            }
        }
    }

    private suspend fun refreshTelemetry() {
        val main = requireActivity() as MainActivity
        val service = main.beam ?: return
        val json = withContext(Dispatchers.IO) {
            runCatching { service.getTelemetryJson() }.getOrNull()
        } ?: return
        renderTelemetry(TelemetryDto.fromJson(json))
    }

    private fun renderTelemetry(telemetry: TelemetryDto?) {
        val binding = _binding ?: return
        val dash = getString(R.string.telemetry_none)
        binding.rttValue.text = telemetry?.lastRttMs
            ?.let { String.format(Locale.US, "%d ms", it) } ?: dash
        binding.flowsValue.text = telemetry
            ?.let { "${it.activeTcpFlows} / ${it.activeUdpSessions}" } ?: dash
        binding.txValue.text = telemetry?.bytesTx?.let(::formatBytes) ?: dash
        binding.rxValue.text = telemetry?.bytesRx?.let(::formatBytes) ?: dash
        binding.dialFailuresValue.text = telemetry?.dialFailures?.toString() ?: dash
        binding.dropsValue.text = telemetry?.drops?.toString() ?: dash
        binding.telemetryHint.isVisible = telemetry == null
    }

    private fun renderStatus(status: BeamStatus) {
        val binding = _binding ?: return
        val accent = ContextCompat.getColor(requireContext(), statusColor(status.state))
        binding.statusBadge.text = getString(statusLabel(status.state))
        binding.statusBadge.setTextColor(accent)
        binding.statusBadge.backgroundTintList =
            ColorStateList.valueOf(ColorUtils.setAlphaComponent(accent, BADGE_ALPHA))

        val detail = status.detail?.takeIf { it.isNotBlank() }
        binding.statusDetail.isVisible = detail != null
        if (detail != null) {
            binding.statusDetail.text = detail
            binding.statusDetail.setTextColor(accent)
            binding.statusDetail.backgroundTintList =
                ColorStateList.valueOf(ColorUtils.setAlphaComponent(accent, BANNER_ALPHA))
        }

        val connected = status.state == VpnState.CONNECTED || status.state == VpnState.DEGRADED
        // Stays enabled while CONNECTING as "Cancel" so a hanging dial can abort.
        binding.connectButton.isEnabled = connected || status.state == VpnState.DISCONNECTED ||
            status.state == VpnState.CONNECTING
        binding.connectButton.text = getString(
            when (status.state) {
                VpnState.CONNECTED, VpnState.DEGRADED -> R.string.action_disconnect
                VpnState.CONNECTING -> R.string.action_cancel
                VpnState.DISCONNECTING -> R.string.action_disconnecting
                else -> R.string.action_connect
            },
        )
    }

    private fun renderActiveProfile() {
        val context = requireContext()
        viewLifecycleOwner.lifecycleScope.launch {
            val profile = withContext(Dispatchers.IO) {
                runCatching { EncryptedProfileStore(context).getActiveProfile() }.getOrNull()
            }
            val binding = _binding ?: return@launch
            binding.activeProfileName.text =
                profile?.name ?: getString(R.string.dashboard_no_profile)
            binding.activeProfileServer.isVisible = profile != null
            if (profile != null) {
                binding.activeProfileServer.text = getString(
                    R.string.profiles_server_format, profile.serverHost, profile.serverPort,
                )
            }
            binding.addProfileButton.isVisible = profile == null
        }
    }

    private fun statusLabel(state: Int): Int = when (state) {
        VpnState.CONNECTING -> R.string.status_connecting
        VpnState.CONNECTED -> R.string.status_connected
        VpnState.DEGRADED -> R.string.status_degraded
        VpnState.DISCONNECTING -> R.string.status_disconnecting
        else -> R.string.status_disconnected
    }

    private fun statusColor(state: Int): Int = when (state) {
        VpnState.CONNECTING, VpnState.DISCONNECTING -> R.color.status_connecting
        VpnState.CONNECTED -> R.color.status_connected
        VpnState.DEGRADED -> R.color.status_degraded
        else -> R.color.status_disconnected
    }

    private fun formatBytes(bytes: Long?): String {
        if (bytes == null) return getString(R.string.telemetry_none)
        if (bytes < 1024L) return "${bytes} B"
        val kib = bytes / 1024.0
        if (kib < 1024.0) return String.format(Locale.US, "%.1f KiB", kib)
        val mib = kib / 1024.0
        if (mib < 1024.0) return String.format(Locale.US, "%.1f MiB", mib)
        return String.format(Locale.US, "%.1f GiB", mib / 1024.0)
    }

    private companion object {
        const val POLL_INTERVAL_MS = 2_000L
        const val BADGE_ALPHA = 0x26
        const val BANNER_ALPHA = 0x1A
    }
}
