//
//  Fortress Crypt — 6-layer cascade encryption system
//  Copyright (C) 2025 Steve Watts, The Lion's Kingdom IT Solutions, LLC
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published
//  by the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
//  For commercial licensing without the AGPL's copyleft obligations,
//  contact the Maintainer (see README).
//

package com.fortress.crypt.service

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.fortress.crypt.viewmodel.VaultItem
import org.json.JSONArray
import org.json.JSONObject

/**
 * Encrypted vault metadata persistence using AndroidX EncryptedSharedPreferences.
 * Vault item list and settings are stored encrypted at rest with AES-256-SIV.
 */
object VaultPersistence {

    private const val PREFS_FILE = "fortress_vault_prefs"
    private const val KEY_ITEMS = "vault_items"
    private const val KEY_SECURITY_LEVEL = "security_level"

    private fun getPrefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        PREFS_FILE,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveItems(context: Context, items: List<VaultItem>) {
        val array = JSONArray()
        items.forEach { item ->
            array.put(JSONObject().apply {
                put("id", item.id)
                put("name", item.name)
                put("originalFileName", item.originalFileName)
                put("encryptedFileName", item.encryptedFileName)
                put("fileSize", item.fileSize)
                put("dateAdded", item.dateAdded)
                put("category", item.category)
                put("isFavorite", item.isFavorite)
            })
        }
        getPrefs(context).edit().putString(KEY_ITEMS, array.toString()).apply()
    }

    fun loadItems(context: Context): List<VaultItem> {
        val json = getPrefs(context).getString(KEY_ITEMS, null) ?: return emptyList()
        val array = JSONArray(json)
        return (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            VaultItem(
                id = obj.getString("id"),
                name = obj.getString("name"),
                originalFileName = obj.getString("originalFileName"),
                encryptedFileName = obj.getString("encryptedFileName"),
                fileSize = obj.getLong("fileSize"),
                dateAdded = obj.getLong("dateAdded"),
                category = obj.optString("category", "other"),
                isFavorite = obj.optBoolean("isFavorite", false)
            )
        }
    }

    fun saveSecurityLevel(context: Context, level: String) {
        getPrefs(context).edit().putString(KEY_SECURITY_LEVEL, level).apply()
    }

    fun loadSecurityLevel(context: Context): String {
        return getPrefs(context).getString(KEY_SECURITY_LEVEL, "PARANOID") ?: "PARANOID"
    }
}
