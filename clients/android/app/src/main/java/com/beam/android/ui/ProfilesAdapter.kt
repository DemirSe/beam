package com.beam.android.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.view.isVisible
import androidx.recyclerview.widget.RecyclerView
import com.beam.android.R
import com.beam.android.databinding.ItemProfileBinding
import com.beam.android.storage.VlessProfile

/** Profile list: name and `host:port` only. The URI stays out of the UI. */
class ProfilesAdapter(
    private val onSelect: (VlessProfile) -> Unit,
    private val onRename: (VlessProfile) -> Unit,
    private val onDelete: (VlessProfile) -> Unit,
) : RecyclerView.Adapter<ProfilesAdapter.Holder>() {

    private var items: List<VlessProfile> = emptyList()
    private var activeId: String? = null

    fun submit(profiles: List<VlessProfile>, active: String?) {
        items = profiles
        activeId = active
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(ItemProfileBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val profile = items[position]
        val binding = holder.binding
        binding.profileName.text = profile.name
        binding.profileServer.text = holder.itemView.context.getString(
            R.string.profiles_server_format,
            profile.serverHost,
            profile.serverPort,
        )
        binding.profileActiveIcon.isVisible = profile.id == activeId
        binding.root.setOnClickListener { onSelect(profile) }
        binding.root.setOnLongClickListener {
            onRename(profile)
            true
        }
        binding.profileDelete.setOnClickListener { onDelete(profile) }
    }

    override fun getItemCount(): Int = items.size

    class Holder(val binding: ItemProfileBinding) : RecyclerView.ViewHolder(binding.root)
}
