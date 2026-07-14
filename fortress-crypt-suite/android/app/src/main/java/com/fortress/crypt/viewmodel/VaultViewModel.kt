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

package com.fortress.crypt.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.fortress.crypt.crypto.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.util.UUID

// ── Data Models ─────────────────────────────────────────────────

data class VaultItem(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val originalFileName: String,
    val encryptedFileName: String,
    val fileSize: Long,
    val dateAdded: Long = System.currentTimeMillis(),
    val category: String = "other",
    val isFavorite: Boolean = false
)

sealed class VaultState {
    object Locked : VaultState()
    object Unlocking : VaultState()
    object Unlocked : VaultState()
    data class Error(val message: String) : VaultState()
}

sealed class OperationState {
    object Idle : OperationState()
    object DerivingKeys : OperationState()
    data class Encrypting(val progress: Double, val status: String) : OperationState()
    data class Decrypting(val progress: Double, val status: String) : OperationState()
    data class Complete(val success: Boolean, val message: String) : OperationState()
}

// ── ViewModel ───────────────────────────────────────────────────

class VaultViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow<VaultState>(VaultState.Locked)
    val state = _state.asStateFlow()

    private val _items = MutableStateFlow<List<VaultItem>>(emptyList())
    val items = _items.asStateFlow()

    private val _operationState = MutableStateFlow<OperationState>(OperationState.Idle)
    val operationState = _operationState.asStateFlow()

    private val _securityLevel = MutableStateFlow(SecurityLevel.PARANOID)
    val securityLevel = _securityLevel.asStateFlow()

    private var masterPassword: String? = null

    private val vaultDir: File
        get() = File(getApplication<Application>().filesDir, "fortress_vault").also { it.mkdirs() }

    fun unlock(password: String) {
        _state.value = VaultState.Unlocking
        masterPassword = password
        viewModelScope.launch(Dispatchers.IO) {
            try {
                delay(300)
                val context = getApplication<Application>()
                val loadedItems = com.fortress.crypt.service.VaultPersistence.loadItems(context)
                val savedLevel = com.fortress.crypt.service.VaultPersistence.loadSecurityLevel(context)
                withContext(Dispatchers.Main) {
                    _items.value = loadedItems
                    _securityLevel.value = SecurityLevel.entries.find { it.name == savedLevel } ?: SecurityLevel.PARANOID
                    _state.value = VaultState.Unlocked
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    _state.value = VaultState.Error(e.message ?: "Unknown error")
                }
            }
        }
    }

    fun lock() {
        // Save before locking
        viewModelScope.launch(Dispatchers.IO) {
            val context = getApplication<Application>()
            com.fortress.crypt.service.VaultPersistence.saveItems(context, _items.value)
            com.fortress.crypt.service.VaultPersistence.saveSecurityLevel(context, _securityLevel.value.name)
        }
        masterPassword = null
        _items.value = emptyList()
        _state.value = VaultState.Locked
    }

    private fun saveVault() {
        viewModelScope.launch(Dispatchers.IO) {
            val context = getApplication<Application>()
            com.fortress.crypt.service.VaultPersistence.saveItems(context, _items.value)
        }
    }

    fun setSecurityLevel(level: SecurityLevel) {
        _securityLevel.value = level
    }

    fun encryptFile(
        uri: Uri, trapCodes: List<String> = emptyList(),
        duressPassword: String? = null, duressData: ByteArray? = null
    ) {
        val password = masterPassword ?: return
        val context = getApplication<Application>()

        _operationState.value = OperationState.DerivingKeys

        viewModelScope.launch(Dispatchers.IO) {
            try {
                // Copy URI content to temp file
                val fileName = uri.lastPathSegment ?: "file"
                val tempInput = File(context.cacheDir, "input_${System.currentTimeMillis()}")
                context.contentResolver.openInputStream(uri)?.use { inp ->
                    tempInput.outputStream().use { out -> inp.copyTo(out) }
                }

                val outputFile = File(vaultDir, "${UUID.randomUUID()}.fortress")

                val result = FortressAPI.encryptFile(
                    inputFile = tempInput, outputFile = outputFile, password = password,
                    level = _securityLevel.value,
                    trapCodes = trapCodes.ifEmpty { null },
                    duressPassword = duressPassword, duressData = duressData,
                    progress = { progress, status ->
                        _operationState.value = OperationState.Encrypting(progress, status)
                    }
                )

                tempInput.delete()

                val item = VaultItem(
                    name = fileName.substringBeforeLast("."),
                    originalFileName = fileName,
                    encryptedFileName = outputFile.name,
                    fileSize = result["inputSize"] as Long,
                    category = categorize(fileName)
                )

                withContext(Dispatchers.Main) {
                    _items.value = _items.value + item
                    _operationState.value = OperationState.Complete(true, "Encrypted successfully")
                    saveVault()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    _operationState.value = OperationState.Complete(false, e.message ?: "Encryption failed")
                }
            }
        }
    }

    fun decryptFile(item: VaultItem, outputUri: Uri, trapCodes: List<String> = emptyList()) {
        val password = masterPassword ?: return
        val context = getApplication<Application>()

        _operationState.value = OperationState.DerivingKeys

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val inputFile = File(vaultDir, item.encryptedFileName)
                val tempOutput = File(context.cacheDir, "output_${System.currentTimeMillis()}")

                FortressAPI.decryptFile(
                    inputFile = inputFile, outputFile = tempOutput, password = password,
                    trapCodes = trapCodes.ifEmpty { null },
                    progress = { progress, status ->
                        _operationState.value = OperationState.Decrypting(progress, status)
                    }
                )

                // Copy to output URI
                context.contentResolver.openOutputStream(outputUri)?.use { out ->
                    tempOutput.inputStream().use { inp -> inp.copyTo(out) }
                }
                tempOutput.delete()

                withContext(Dispatchers.Main) {
                    _operationState.value = OperationState.Complete(true, "Decrypted successfully")
                }
            } catch (e: FortressException.TrapTriggered) {
                withContext(Dispatchers.Main) {
                    _operationState.value = OperationState.Complete(false, "TRAP TRIGGERED: ${e.message}")
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    _operationState.value = OperationState.Complete(false, e.message ?: "Decryption failed")
                }
            }
        }
    }

    fun deleteItem(item: VaultItem) {
        File(vaultDir, item.encryptedFileName).delete()
        _items.value = _items.value.filter { it.id != item.id }
        saveVault()
    }

    fun clearOperationState() {
        _operationState.value = OperationState.Idle
    }

    private fun categorize(filename: String): String = when (filename.substringAfterLast(".").lowercase()) {
        "pdf", "doc", "docx", "txt" -> "document"
        "jpg", "jpeg", "png", "heic" -> "image"
        "mp4", "mov", "avi" -> "video"
        "mp3", "aac", "wav" -> "audio"
        "zip", "tar", "gz" -> "archive"
        else -> "other"
    }
}

fun Long.formatFileSize(): String {
    var size = toDouble()
    for (unit in listOf("B", "KB", "MB", "GB", "TB")) {
        if (size < 1024) return "%.1f %s".format(size, unit)
        size /= 1024
    }
    return "%.1f PB".format(size)
}
