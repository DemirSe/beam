package com.beam.android.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.view.isVisible
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.beam.android.R
import com.beam.android.databinding.ItemProfileBinding
import com.beam.android.storage.VlessProfile

/** Profile list: name and `host:port` only. The URI stays out of the UI. */
class ProfilesAdapter(
    private val onSelect: (VlessProfile) -> Unit,
    private val onRename: (VlessProfile) -> Unit,
    private val onDelete: (VlessProfile) -> Unit,
) : ListAdapter<ProfilesAdapter.ProfileItem, ProfilesAdapter.Holder>(DIFF) {

    data class ProfileItem(val profile: VlessProfile, val isActive: Boolean)

    fun submit(profiles: List<VlessProfile>, active: String?) {
        submitList(profiles.map { ProfileItem(it, it.id == active) })
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(ItemProfileBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val item = getItem(position)
        val profile = item.profile
        val binding = holder.binding
        binding.profileName.text = profile.name
        binding.profileServer.text = holder.itemView.context.getString(
            R.string.profiles_server_format,
            profile.serverHost,
            profile.serverPort,
        )
        binding.profileActiveIcon.isVisible = item.isActive
        binding.root.setOnClickListener { onSelect(profile) }
        binding.root.setOnLongClickListener {
            onRename(profile)
            true
        }
        binding.profileDelete.setOnClickListener { onDelete(profile) }
        binding.profileDelete.contentDescription = holder.itemView.context.getString(
            R.string.profiles_delete_content_description,
            profile.name,
        )
    }

    class Holder(val binding: ItemProfileBinding) : RecyclerView.ViewHolder(binding.root)

    private companion object {
        val DIFF = object : DiffUtil.ItemCallback<ProfileItem>() {
            override fun areItemsTheSame(oldItem: ProfileItem, newItem: ProfileItem): Boolean =
                oldItem.profile.id == newItem.profile.id

            override fun areContentsTheSame(oldItem: ProfileItem, newItem: ProfileItem): Boolean =
                oldItem == newItem
        }
    }
}
