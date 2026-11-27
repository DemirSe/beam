package com.beam.android.ui

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.beam.android.R
import com.beam.android.databinding.FragmentSettingsBinding
import com.beam.android.storage.AppSettings
import com.beam.android.storage.SettingsStore
import com.beam.android.storage.SettingsValidator
import com.beam.android.vpn.Ipv4RouteCalculator
import com.beam.android.vpn.VpnConfigBuilder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** DoH presets, leak switches, bypass routes and the two system shortcuts. */
class SettingsFragment : Fragment() {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!

    private lateinit var store: SettingsStore

    /** True once the stored values are in the views; Save stays off until then. */
    private var settingsLoaded = false
    private var saving = false

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        _binding = FragmentSettingsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        store = SettingsStore(requireContext())
        binding.buttonSave.isEnabled = false
        // A restored view already holds the stored values plus the user's edits;
        // binding again would discard them, so only re-enable Save.
        if (savedInstanceState?.getBoolean(KEY_SETTINGS_LOADED, false) == true) {
            settingsLoaded = true
            binding.buttonSave.isEnabled = !saving
        } else {
            viewLifecycleOwner.lifecycleScope.launch {
                val settings = withContext(Dispatchers.IO) {
                    try {
                        store.loadOrNull()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        null
                    }
                }
                if (_binding == null) return@launch
                if (settings == null) {
                    // Never overwrite a file we could not read with defaults.
                    toast(R.string.settings_load_failed)
                } else {
                    settingsLoaded = true
                    bind(settings)
                    binding.buttonSave.isEnabled = true
                }
            }
        }

        binding.dohGroup.setOnCheckedChangeListener { _, _ -> updateDohCustomVisibility() }
        binding.buttonBypassReset.setOnClickListener {
            binding.inputBypass.setText(AppSettings.DEFAULT_BYPASS_CIDRS.joinToString("\n"))
            binding.bypassLayout.error = null
        }
        binding.buttonSave.setOnClickListener { save() }
        binding.alwaysOnRow.setOnClickListener {
            openSystemSettings(Settings.ACTION_VPN_SETTINGS)
        }
        binding.batteryRow.setOnClickListener {
            openSystemSettings(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
        }
    }

    override fun onViewStateRestored(savedInstanceState: Bundle?) {
        super.onViewStateRestored(savedInstanceState)
        if (_binding != null && savedInstanceState?.getBoolean(KEY_SETTINGS_LOADED, false) == true) {
            updateDohCustomVisibility()
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_SETTINGS_LOADED, settingsLoaded)
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }

    private fun bind(settings: AppSettings) {
        when (settings.dohUrl) {
            AppSettings.DOH_CLOUDFLARE -> binding.radioDohCloudflare.isChecked = true
            AppSettings.DOH_NEXTDNS -> binding.radioDohNextDns.isChecked = true
            else -> {
                binding.radioDohCustom.isChecked = true
                binding.inputDohCustom.setText(settings.dohUrl)
            }
        }
        binding.switchIpv4Only.isChecked = settings.ipv4Only
        binding.switchQuic.isChecked = settings.rejectQuic
        binding.switchUnmetered.isChecked = settings.treatAsUnmetered
        binding.switchStartOnBoot.isChecked = settings.startOnBoot
        binding.inputBypass.setText(settings.bypassCidrs.joinToString("\n"))
        updateDohCustomVisibility()
    }

    private fun updateDohCustomVisibility() {
        binding.dohCustomLayout.isVisible = binding.radioDohCustom.isChecked
    }

    private fun save() {
        val rawDohUrl = when {
            binding.radioDohNextDns.isChecked -> AppSettings.DOH_NEXTDNS
            binding.radioDohCustom.isChecked ->
                binding.inputDohCustom.text?.toString()?.trim().orEmpty()
            else -> AppSettings.DOH_CLOUDFLARE
        }
        val dohUrl = SettingsValidator.normalizeAndValidateDohUrl(rawDohUrl)
        if (dohUrl == null) {
            binding.dohCustomLayout.error = getString(R.string.settings_doh_invalid)
            return
        }
        binding.dohCustomLayout.error = null

        val cidrs = binding.inputBypass.text?.toString().orEmpty()
            .lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toList()
        if (cidrs.size > SettingsValidator.MAX_BYPASS_CIDRS) {
            binding.bypassLayout.error =
                getString(R.string.settings_bypass_too_many, SettingsValidator.MAX_BYPASS_CIDRS)
            return
        }
        val allowIpv6 = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        val invalid = cidrs.firstOrNull { !Ipv4RouteCalculator.isValidCidr(it, allowIpv6) }
        if (invalid != null) {
            // A valid IPv6 CIDR cannot be honoured on API 31-32: that path only
            // routes the IPv4 complement, so say so instead of silently ignoring it.
            val ipv6Unsupported =
                !allowIpv6 && Ipv4RouteCalculator.isValidCidr(invalid, allowIpv6 = true)
            binding.bypassLayout.error = getString(
                if (ipv6Unsupported) {
                    R.string.settings_bypass_ipv6_unsupported
                } else {
                    R.string.settings_bypass_invalid
                },
                invalid,
            )
            return
        }
        val defaultRoute = cidrs.firstOrNull {
            it.substringAfter('/', missingDelimiterValue = "").toIntOrNull() == 0
        }
        if (defaultRoute != null) {
            binding.bypassLayout.error = getString(R.string.settings_bypass_default_route, defaultRoute)
            return
        }
        // A prefix that covers the TUN /30 would bypass the TUN DNS server.
        val tunOverlap = cidrs.firstOrNull { Ipv4RouteCalculator.overlapsTunSubnet(it) }
        if (tunOverlap != null) {
            binding.bypassLayout.error = getString(
                R.string.settings_bypass_tun_overlap,
                tunOverlap,
                VpnConfigBuilder.TUN_NETWORK_CIDR,
            )
            return
        }
        val normalizedCidrs = cidrs.map { cidr ->
            val host = cidr.substringBefore('/')
            val prefix = cidr.substringAfter('/').toInt()
            "$host/$prefix"
        }
        binding.bypassLayout.error = null

        val settings = AppSettings(
            dohUrl = dohUrl,
            ipv4Only = binding.switchIpv4Only.isChecked,
            rejectQuic = binding.switchQuic.isChecked,
            bypassCidrs = normalizedCidrs,
            startOnBoot = binding.switchStartOnBoot.isChecked,
            treatAsUnmetered = binding.switchUnmetered.isChecked,
        )
        if (saving) return
        saving = true
        binding.buttonSave.isEnabled = false
        viewLifecycleOwner.lifecycleScope.launch {
            val saved = try {
                // NonCancellable: a torn-down fragment must not cut a rename short.
                withContext(Dispatchers.IO + NonCancellable) {
                    runCatching { store.save(settings) }.isSuccess
                }
            } finally {
                saving = false
                if (_binding != null) binding.buttonSave.isEnabled = true
            }
            if (saved) {
                val main = activity as? MainActivity
                if (main?.isTunnelActive() == true) {
                    main.showReconnectHint()
                } else {
                    toast(R.string.settings_saved)
                }
            } else {
                toast(R.string.settings_save_failed)
            }
        }
    }

    private fun openSystemSettings(action: String) {
        if (runCatching { startActivity(Intent(action)) }.isSuccess) return
        val fallback = Intent(
            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            android.net.Uri.fromParts("package", requireContext().packageName, null),
        )
        if (runCatching { startActivity(fallback) }.isFailure) {
            toast(R.string.settings_open_failed)
        }
    }

    private fun toast(resId: Int) {
        context?.let { Toast.makeText(it, resId, Toast.LENGTH_SHORT).show() }
    }

    private companion object {
        const val KEY_SETTINGS_LOADED = "settings_loaded"
    }
}
