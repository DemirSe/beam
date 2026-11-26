package com.beam.android.ui

import android.app.Activity
import android.content.ClipboardManager
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
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import java.util.UUID
import kotlinx.coroutines.Dispatchers
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

    private val scanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode != Activity.RESULT_OK) return@registerForActivityResult
        val scanned = result.data?.getStringExtra(QrScannerActivity.EXTRA_RESULT)
        if (scanned != null) {
            saveProfile(scanned) { ok -> if (!ok) toast(R.string.profiles_add_invalid) }
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
        reload()
    }

    override fun onHiddenChanged(hidden: Boolean) {
        super.onHiddenChanged(hidden)
        if (!hidden && _binding != null) reload()
    }

    override fun onDestroyView() {
        activeDialog?.dismiss()
        activeDialog = null
        _binding = null
        super.onDestroyView()
    }

    private fun reload() {
        viewLifecycleOwner.lifecycleScope.launch {
            val (profiles, activeId) = withContext(Dispatchers.IO) {
                runCatching { store.listProfiles() }.getOrDefault(emptyList()) to
                    runCatching { store.getActiveProfileId() }.getOrNull()
            }
            val binding = _binding ?: return@launch
            adapter.submit(profiles, activeId)
            binding.profilesEmpty.isVisible = profiles.isEmpty()
            binding.profilesList.isVisible = profiles.isNotEmpty()
        }
    }

    private fun selectProfile(profile: VlessProfile) {
        val main = activity as? MainActivity
        viewLifecycleOwner.lifecycleScope.launch {
            val saved = withContext(Dispatchers.IO) {
                runCatching { store.setActiveProfileId(profile.id) }.isSuccess
            }
            if (saved) {
                reload()
                main?.showReconnectHint()
            } else {
                toast(R.string.profiles_save_failed)
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
            dialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                val newName = input.text?.toString()?.trim()?.take(MAX_NAME_LENGTH).orEmpty()
                if (newName.isEmpty()) {
                    layout.error = getString(R.string.profiles_rename_invalid)
                    return@setOnClickListener
                }
                viewLifecycleOwner.lifecycleScope.launch {
                    val saved = withContext(Dispatchers.IO) {
                        runCatching { store.saveProfile(profile.copy(name = newName)) }.isSuccess
                    }
                    if (saved) {
                        dialog.dismiss()
                        reload()
                        toast(R.string.profiles_renamed)
                    } else {
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
        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.profiles_delete_title)
            .setMessage(getString(R.string.profiles_delete_message, profile.name))
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_delete) { _, _ ->
                viewLifecycleOwner.lifecycleScope.launch {
                    withContext(Dispatchers.IO) {
                        val connectedId = runCatching { main?.beam?.getActiveProfileId() }.getOrNull()
                        if (main?.isTunnelActive() == true && connectedId == profile.id) {
                            runCatching { main.beam?.disconnect() }
                        }
                        runCatching { store.deleteProfile(profile.id) }
                    }
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
        clipVlessLink()?.let { input.setText(it) }
        input.doAfterTextChanged { layout.error = null }

        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.profiles_add_title)
            .setView(content)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_save, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                saveProfile(input.text?.toString().orEmpty()) { saved ->
                    if (saved) {
                        dialog.dismiss()
                    } else {
                        layout.error = getString(R.string.profiles_add_invalid)
                    }
                }
            }
        }
        activeDialog?.dismiss()
        activeDialog = dialog
        dialog.setOnDismissListener { if (activeDialog === dialog) activeDialog = null }
        dialog.show()
    }

    /** Validates and stores [raw]; [onSaved] gets false and nothing is saved when invalid. */
    private fun saveProfile(raw: String, onSaved: (Boolean) -> Unit = {}) {
        val uri = raw.trim().take(MAX_LINK_LENGTH)
        val link = parseLink(uri)
        if (link == null) {
            onSaved(false)
            return
        }
        val profile = VlessProfile(
            id = UUID.randomUUID().toString(),
            name = link.name.take(MAX_NAME_LENGTH),
            uri = uri,
            serverHost = link.host,
            serverPort = link.port,
            createdAtMs = System.currentTimeMillis(),
        )
        viewLifecycleOwner.lifecycleScope.launch {
            val saved = withContext(Dispatchers.IO) {
                runCatching {
                    store.saveProfile(profile)
                    if (store.getActiveProfileId() == null) store.setActiveProfileId(profile.id)
                }.isSuccess
            }
            if (!saved) {
                toast(R.string.profiles_save_failed)
                onSaved(false)
                return@launch
            }
            if (_binding != null) reload()
            toast(R.string.profiles_saved)
            onSaved(true)
        }
    }

    private fun parseLink(uri: String): LinkInfo? = parseWithNative(uri) ?: parseWithUri(uri)

    /** Native parser from beam-core; unavailable until libbeam_android.so is loaded. */
    private fun parseWithNative(uri: String): LinkInfo? = runCatching {
        val json = JSONObject(BeamNativeBridge.nativeParseVlessLink(uri) ?: return@runCatching null)
        if (!json.optBoolean("ok")) return@runCatching null
        val host = json.optString("server").trim()
        if (host.isEmpty()) return@runCatching null
        val port = json.optInt("port", DEFAULT_PORT).takeIf { it in 1..65535 } ?: DEFAULT_PORT
        val name = json.optString("name").trim().takeIf { it.isNotEmpty() && it != "null" } ?: host
        LinkInfo(name, host, port)
    }.getOrNull()

    /** Safe fallback so the UI still works when the native library is missing. */
    private fun parseWithUri(uri: String): LinkInfo? {
        if (!uri.startsWith("vless://", ignoreCase = true)) return null
        val parsed = runCatching { android.net.Uri.parse(uri) }.getOrNull() ?: return null
        // Same strictness as the beam-core parser: REALITY with key and SNI.
        if (!parsed.getQueryParameter("security").equals("reality", ignoreCase = true)) return null
        if (parsed.getQueryParameter("pbk").isNullOrBlank()) return null
        if (parsed.getQueryParameter("sni").isNullOrBlank()) return null
        val host = parsed.host?.takeIf { it.isNotBlank() } ?: return null
        val port = parsed.port.takeIf { it in 1..65535 } ?: DEFAULT_PORT
        val fragment = parsed.fragment?.takeIf { it.isNotBlank() && it != "null" }
        return LinkInfo(fragment?.let { android.net.Uri.decode(it) } ?: host, host, port)
    }

    private fun clipVlessLink(): String? {
        val manager = requireContext().getSystemService(ClipboardManager::class.java) ?: return null
        val clip = manager.primaryClip ?: return null
        if (clip.itemCount == 0) return null
        val text = clip.getItemAt(0).coerceToText(requireContext()).toString().trim()
        return text.takeIf { it.startsWith("vless://", ignoreCase = true) && it.length <= MAX_LINK_LENGTH }
    }

    private fun toast(resId: Int) {
        context?.let { Toast.makeText(it, resId, Toast.LENGTH_SHORT).show() }
    }

    private data class LinkInfo(val name: String, val host: String, val port: Int)

    private companion object {
        const val MAX_LINK_LENGTH = 2048
        const val MAX_NAME_LENGTH = 64
        const val DEFAULT_PORT = 443
    }
}
