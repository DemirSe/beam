package com.beam.android.ui

import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.beam.android.R
import com.beam.android.databinding.FragmentProfilesBinding
import com.beam.android.storage.EncryptedProfileStore
import com.beam.android.storage.VlessProfile
import com.beam.android.vpn.BeamNativeBridge
import com.beam.android.vpn.BeamVpnService
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Saved profiles. The list shows only the profile name and `host:port`; the
 * raw `vless://` URI (UUID, SNI, keys) never reaches the UI or Logcat.
 */
class ProfilesFragment : Fragment() {

    private var _binding: FragmentProfilesBinding? = null
    private val binding get() = _binding!!

    private lateinit var store: EncryptedProfileStore
    private lateinit var adapter: ProfilesAdapter
    private var activeDialog: AlertDialog? = null
    private var reloadJob: Job? = null
    private var activeProfileId: String? = null

    private enum class SaveOutcome { SAVED, INVALID_LINK, STORAGE_ERROR }

    private val scanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode != Activity.RESULT_OK) return@registerForActivityResult
        val scanned = result.data?.getStringExtra(QrScannerActivity.EXTRA_RESULT)
        if (scanned != null) {
            saveProfile(scanned) { outcome ->
                when (outcome) {
                    SaveOutcome.SAVED -> Unit
                    SaveOutcome.INVALID_LINK -> toast(R.string.profiles_add_invalid)
                    SaveOutcome.STORAGE_ERROR -> toast(R.string.profiles_save_failed)
                }
            }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        _binding = FragmentProfilesBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        store = EncryptedProfileStore(requireContext())
        adapter = ProfilesAdapter(
            onSelect = { profile -> selectProfile(profile) },
            onRename = { profile -> showRenameDialog(profile) },
            onDelete = { profile -> confirmDelete(profile) },
        )
        binding.profilesList.layoutManager = LinearLayoutManager(requireContext())
        binding.profilesList.adapter = adapter
        binding.fabAdd.setOnClickListener { showAddDialog() }
        binding.fabScanQr.setOnClickListener {
            scanLauncher.launch(Intent(requireContext(), QrScannerActivity::class.java))
        }
    }

    override fun onResume() {
        super.onResume()
        if (!isHidden) reload()
    }

    override fun onHiddenChanged(hidden: Boolean) {
        super.onHiddenChanged(hidden)
        if (!hidden && _binding != null) reload()
    }

    override fun onDestroyView() {
        activeDialog?.dismiss()
        activeDialog = null
        reloadJob?.cancel()
        reloadJob = null
        _binding = null
        super.onDestroyView()
    }

    private fun reload() {
        reloadJob?.cancel()
        reloadJob = viewLifecycleOwner.lifecycleScope.launch {
            val (profiles, activeId) = withContext(Dispatchers.IO) {
                try {
                    store.listProfilesWithActiveId()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    emptyList<VlessProfile>() to null
                }
            }
            val binding = _binding ?: return@launch
            activeProfileId = activeId
            adapter.submit(profiles, activeId)
            binding.profilesEmpty.isVisible = profiles.isEmpty()
            binding.profilesList.isVisible = profiles.isNotEmpty()
        }
    }

    private fun selectProfile(profile: VlessProfile) {
        // Tapping the profile that is already active changes nothing.
        if (profile.id == activeProfileId) return
        val main = activity as? MainActivity
        viewLifecycleOwner.lifecycleScope.launch {
            val saved = withContext(Dispatchers.IO) {
                try {
                    store.setActiveProfileIdIfExists(profile.id)
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    null
                }
            }
            when (saved) {
                true -> {
                    main?.clearErrorDetail()
                    reload()
                    main?.showReconnectHint()
                }
                // Removed between the list load and the tap: just refresh.
                false -> reload()
                null -> toast(R.string.profiles_save_failed)
            }
        }
    }

    private fun showRenameDialog(profile: VlessProfile) {
        val content = layoutInflater.inflate(R.layout.dialog_add_profile, null)
        val input = content.findViewById<TextInputEditText>(R.id.dialogLinkInput)
        val layout = content.findViewById<TextInputLayout>(R.id.dialogLinkLayout)
        layout.hint = getString(R.string.profiles_rename_hint)
        input.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
        input.isSingleLine = true
        input.setText(profile.name)
        input.setSelection(profile.name.length)
        input.doAfterTextChanged { layout.error = null }

        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.profiles_rename_title)
            .setView(content)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_save, null)
            .create()
        dialog.setOnShowListener {
            val positiveButton = dialog.getButton(DialogInterface.BUTTON_POSITIVE)
            positiveButton.setOnClickListener {
                val newName = input.text?.toString()?.trim()?.take(MAX_NAME_LENGTH).orEmpty()
                if (newName.isEmpty()) {
                    layout.error = getString(R.string.profiles_rename_invalid)
                    return@setOnClickListener
                }
                positiveButton.isEnabled = false
                viewLifecycleOwner.lifecycleScope.launch {
                    val saved = withContext(Dispatchers.IO) {
                        runCatching { store.saveProfile(profile.copy(name = newName)) }.isSuccess
                    }
                    if (saved) {
                        dialog.dismiss()
                        reload()
                        toast(R.string.profiles_renamed)
                    } else {
                        positiveButton.isEnabled = true
                        toast(R.string.profiles_save_failed)
                    }
                }
            }
        }
        activeDialog?.dismiss()
        activeDialog = dialog
        dialog.setOnDismissListener { if (activeDialog === dialog) activeDialog = null }
        dialog.show()
    }

    private fun confirmDelete(profile: VlessProfile) {
        val main = activity as? MainActivity
        val appContext = requireContext().applicationContext
        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.profiles_delete_title)
            .setMessage(getString(R.string.profiles_delete_message, profile.name))
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_delete) { _, _ ->
                // Read the binder on the main thread; only the store and binder
                // calls go to IO.
                val beam = main?.beam
                viewLifecycleOwner.lifecycleScope.launch {
                    withContext(Dispatchers.IO) {
                        if (beam != null) {
                            val connectedId = runCatching { beam.getActiveProfileId() }.getOrNull()
                            if (connectedId == profile.id) {
                                runCatching { beam.disconnect() }
                            }
                        } else {
                            // An unbound UI leaves the profile as the :vpn target, so
                            // deleting it must stop the tunnel that it still describes.
                            val previousActiveId = runCatching { store.getActiveProfileId() }.getOrNull()
                            if (previousActiveId == profile.id) {
                                runCatching {
                                    appContext.startService(
                                        Intent(appContext, BeamVpnService::class.java)
                                            .setAction(BeamVpnService.ACTION_STOP),
                                    )
                                }
                            }
                        }
                        runCatching { store.deleteProfile(profile.id) }
                    }
                    main?.clearErrorDetail()
                    if (_binding != null) reload()
                }
            }
            .create()
        activeDialog?.dismiss()
        activeDialog = dialog
        dialog.setOnDismissListener { if (activeDialog === dialog) activeDialog = null }
        dialog.show()
    }

    private fun showAddDialog() {
        val content = layoutInflater.inflate(R.layout.dialog_add_profile, null)
        val input = content.findViewById<TextInputEditText>(R.id.dialogLinkInput)
        val layout = content.findViewById<TextInputLayout>(R.id.dialogLinkLayout)
        input.doAfterTextChanged { layout.error = null }

        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.profiles_add_title)
            .setView(content)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_save, null)
            .create()
        dialog.setOnShowListener {
            val positiveButton = dialog.getButton(DialogInterface.BUTTON_POSITIVE)
            positiveButton.setOnClickListener {
                positiveButton.isEnabled = false
                saveProfile(input.text?.toString().orEmpty()) { outcome ->
                    when (outcome) {
                        SaveOutcome.SAVED -> dialog.dismiss()
                        SaveOutcome.INVALID_LINK -> {
                            positiveButton.isEnabled = true
                            layout.error = getString(R.string.profiles_add_invalid)
                        }
                        SaveOutcome.STORAGE_ERROR -> {
                            positiveButton.isEnabled = true
                            layout.error = getString(R.string.profiles_save_failed)
                        }
                    }
                }
            }
        }
        activeDialog?.dismiss()
        activeDialog = dialog
        dialog.setOnDismissListener { if (activeDialog === dialog) activeDialog = null }
        dialog.show()
        // A clipboard read can block on the system service, so never do it on the UI thread.
        val appContext = requireContext().applicationContext
        viewLifecycleOwner.lifecycleScope.launch {
            val link = withContext(Dispatchers.IO) { clipVlessLink(appContext) }
            if (link != null && dialog.isShowing && input.text.isNullOrEmpty()) {
                input.setText(link)
            }
        }
    }

    /** Stores [raw]; [onResult] reports the outcome and nothing is saved when invalid. */
    private fun saveProfile(raw: String, onResult: (SaveOutcome) -> Unit = {}) {
        val uri = raw.trim()
        if (uri.length > MAX_LINK_LENGTH || uri.toByteArray(Charsets.UTF_8).size > MAX_LINK_LENGTH) {
            onResult(SaveOutcome.INVALID_LINK)
            return
        }
        viewLifecycleOwner.lifecycleScope.launch {
            val link = withContext(Dispatchers.IO) { parseLink(uri) }
            if (link == null) {
                onResult(SaveOutcome.INVALID_LINK)
                return@launch
            }
            val profile = VlessProfile(
                id = UUID.randomUUID().toString(),
                name = link.name.take(MAX_NAME_LENGTH),
                uri = uri,
                serverHost = link.host,
                serverPort = link.port,
                createdAtMs = System.currentTimeMillis(),
            )
            val saved = withContext(Dispatchers.IO) {
                runCatching { store.saveProfileAndActivateIfNone(profile) }.isSuccess
            }
            if (!saved) {
                onResult(SaveOutcome.STORAGE_ERROR)
                return@launch
            }
            if (_binding != null) reload()
            toast(R.string.profiles_saved)
            onResult(SaveOutcome.SAVED)
        }
    }

    private fun parseLink(uri: String): LinkInfo? = when (val native = parseWithNative(uri)) {
        is NativeParse.Ok -> native.info
        NativeParse.Rejected -> null
        NativeParse.Unavailable -> parseWithUri(uri)
    }

    /** Native parser from beam-core; falls back only when libbeam_android.so is unavailable. */
    private fun parseWithNative(uri: String): NativeParse {
        val raw = try {
            BeamNativeBridge.nativeParseVlessLink(uri)
        } catch (_: Throwable) {
            return NativeParse.Unavailable
        }
        if (raw == null) return NativeParse.Unavailable
        val json = runCatching { JSONObject(raw) }.getOrNull() ?: return NativeParse.Unavailable
        if (!json.optBoolean("ok")) return NativeParse.Rejected
        val host = json.optString("server").trim()
        if (host.isEmpty()) return NativeParse.Rejected
        val port = json.optInt("port", DEFAULT_PORT).takeIf { it in 1..65535 } ?: DEFAULT_PORT
        val name = json.optString("name").trim().takeIf { it.isNotEmpty() && it != "null" } ?: host
        return NativeParse.Ok(LinkInfo(name, host, port))
    }

    /** Safe fallback so the UI still works when the native library is missing. */
    private fun parseWithUri(uri: String): LinkInfo? = runCatching {
        if (!uri.startsWith("vless://", ignoreCase = true)) return@runCatching null
        val parsed = android.net.Uri.parse(uri)
        // Same strictness as the beam-core parser: REALITY with key and SNI.
        if (!parsed.getQueryParameter("security").equals("reality", ignoreCase = true)) {
            return@runCatching null
        }
        if (parsed.getQueryParameter("pbk").isNullOrBlank()) return@runCatching null
        if (parsed.getQueryParameter("sni").isNullOrBlank()) return@runCatching null
        val host = parsed.host?.takeIf { it.isNotBlank() } ?: return@runCatching null
        val port = parsed.port.takeIf { it in 1..65535 } ?: DEFAULT_PORT
        val fragment = parsed.fragment?.takeIf { it.isNotBlank() && it != "null" }
        LinkInfo(fragment?.let { android.net.Uri.decode(it) } ?: host, host, port)
    }.getOrNull()

    private fun clipVlessLink(context: Context): String? {
        val manager = context.getSystemService(ClipboardManager::class.java) ?: return null
        val clip = manager.primaryClip ?: return null
        if (clip.itemCount == 0) return null
        val text = clip.getItemAt(0).coerceToText(context).toString().trim()
        return text.takeIf { it.startsWith("vless://", ignoreCase = true) && it.length <= MAX_LINK_LENGTH }
    }

    private fun toast(resId: Int) {
        context?.let { Toast.makeText(it, resId, Toast.LENGTH_SHORT).show() }
    }

    private data class LinkInfo(val name: String, val host: String, val port: Int)

    /** Distinguishes a rejected link from a missing native library. */
    private sealed interface NativeParse {
        data class Ok(val info: LinkInfo) : NativeParse
        object Rejected : NativeParse
        object Unavailable : NativeParse
    }

    private companion object {
        const val MAX_LINK_LENGTH = 2048
        const val MAX_NAME_LENGTH = 64
        const val DEFAULT_PORT = 443
    }
}
