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

package com.fortress.crypt.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.fortress.crypt.crypto.SecurityLevel
import com.fortress.crypt.ui.theme.FortressCyan
import com.fortress.crypt.ui.theme.FortressCyanDark
import com.fortress.crypt.viewmodel.*

// ═══════════════════════════════════════════════════════════════
//  LOCK SCREEN
// ═══════════════════════════════════════════════════════════════

@Composable
fun LockScreen(onUnlock: (String) -> Unit) {
    var password by remember { mutableStateOf("") }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0A0C10)),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(horizontal = 48.dp)
        ) {
            // Shield icon
            Icon(
                Icons.Filled.Shield,
                contentDescription = null,
                modifier = Modifier.size(72.dp),
                tint = FortressCyan
            )

            Spacer(Modifier.height(24.dp))

            Text(
                "FORTRESS",
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = Color.White,
                letterSpacing = 6.sp
            )
            Text(
                "CRYPT",
                fontSize = 12.sp,
                fontWeight = FontWeight.Light,
                color = Color.Gray,
                letterSpacing = 8.sp
            )

            Spacer(Modifier.height(48.dp))

            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Master Password") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = FortressCyan,
                    cursorColor = FortressCyan,
                ),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(20.dp))

            Button(
                onClick = { if (password.isNotEmpty()) onUnlock(password) },
                modifier = Modifier.fillMaxWidth().height(52.dp),
                colors = ButtonDefaults.buttonColors(containerColor = FortressCyan),
                shape = RoundedCornerShape(12.dp),
                enabled = password.isNotEmpty()
            ) {
                Icon(Icons.Filled.LockOpen, contentDescription = null, tint = Color.Black)
                Spacer(Modifier.width(8.dp))
                Text("Unlock Vault", color = Color.Black, fontWeight = FontWeight.SemiBold)
            }

            Spacer(Modifier.height(64.dp))

            Text(
                "6-Layer Cascade Encryption",
                fontSize = 10.sp,
                color = Color.Gray.copy(alpha = 0.4f)
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  MAIN VAULT SCREEN (with bottom nav)
// ═══════════════════════════════════════════════════════════════

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultMainScreen(viewModel: VaultViewModel) {
    var selectedTab by remember { mutableIntStateOf(0) }
    val operationState by viewModel.operationState.collectAsState()
    val items by viewModel.items.collectAsState()

    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let { viewModel.encryptFile(it) }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            when (selectedTab) { 0 -> "Vault"; 1 -> "Messages"; else -> "Settings" },
                            fontWeight = FontWeight.Bold
                        )
                    },
                    actions = {
                        if (selectedTab == 0) {
                            IconButton(onClick = { filePicker.launch(arrayOf("*/*")) }) {
                                Icon(Icons.Filled.Add, "Import file")
                            }
                        }
                        IconButton(onClick = { viewModel.lock() }) {
                            Icon(Icons.Filled.Lock, "Lock", tint = FortressCyan.copy(alpha = 0.7f))
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = Color(0xFF0A0C10)
                    )
                )
            },
            bottomBar = {
                NavigationBar(containerColor = Color(0xFF12151C)) {
                    NavigationBarItem(
                        selected = selectedTab == 0,
                        onClick = { selectedTab = 0 },
                        icon = { Icon(Icons.Filled.Shield, "Vault") },
                        label = { Text("Vault") },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = FortressCyan,
                            indicatorColor = FortressCyan.copy(alpha = 0.15f)
                        )
                    )
                    NavigationBarItem(
                        selected = selectedTab == 1,
                        onClick = { selectedTab = 1 },
                        icon = { Icon(Icons.Filled.Email, "Messages") },
                        label = { Text("Messages") },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = FortressCyan,
                            indicatorColor = FortressCyan.copy(alpha = 0.15f)
                        )
                    )
                    NavigationBarItem(
                        selected = selectedTab == 2,
                        onClick = { selectedTab = 2 },
                        icon = { Icon(Icons.Filled.Settings, "Settings") },
                        label = { Text("Settings") },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = FortressCyan,
                            indicatorColor = FortressCyan.copy(alpha = 0.15f)
                        )
                    )
                }
            },
            containerColor = Color(0xFF0A0C10)
        ) { padding ->
            Box(modifier = Modifier.padding(padding)) {
                when (selectedTab) {
                    0 -> VaultFilesScreen(items, viewModel)
                    1 -> MessagesScreen()
                    2 -> SettingsScreen(viewModel)
                }
            }
        }

        // Operation overlay
        AnimatedVisibility(
            visible = operationState !is OperationState.Idle && operationState !is OperationState.Complete,
            enter = fadeIn(), exit = fadeOut()
        ) {
            OperationOverlay(operationState)
        }
    }

    // Show completion snackbar
    val opState = operationState
    if (opState is OperationState.Complete) {
        LaunchedEffect(opState) {
            delay(3000)
            viewModel.clearOperationState()
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  VAULT FILES LIST
// ═══════════════════════════════════════════════════════════════

@Composable
fun VaultFilesScreen(items: List<VaultItem>, viewModel: VaultViewModel) {
    if (items.isEmpty()) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Outlined.Shield, null,
                    modifier = Modifier.size(64.dp),
                    tint = Color.Gray.copy(alpha = 0.3f)
                )
                Spacer(Modifier.height(16.dp))
                Text("No encrypted files", color = Color.Gray)
                Text("Tap + to import and encrypt", fontSize = 13.sp, color = Color.Gray.copy(alpha = 0.5f))
            }
        }
    } else {
        LazyColumn(
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(items, key = { it.id }) { item ->
                VaultItemCard(item, onDelete = { viewModel.deleteItem(item) })
            }
        }
    }
}

@Composable
fun VaultItemCard(item: VaultItem, onDelete: () -> Unit) {
    val iconColor = when (item.category) {
        "document" -> Color(0xFF3B82F6)
        "image" -> Color(0xFF10B981)
        "video" -> Color(0xFF8B5CF6)
        "audio" -> Color(0xFFF59E0B)
        "archive" -> Color.Gray
        else -> Color.Gray
    }
    val icon = when (item.category) {
        "document" -> Icons.Filled.Description
        "image" -> Icons.Filled.Image
        "video" -> Icons.Filled.VideoFile
        "audio" -> Icons.Filled.AudioFile
        "archive" -> Icons.Filled.FolderZip
        else -> Icons.Filled.InsertDriveFile
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF12151C)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(iconColor.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, null, tint = iconColor, modifier = Modifier.size(24.dp))
            }

            Spacer(Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(item.name, fontWeight = FontWeight.Medium, maxLines = 1)
                Text(
                    item.fileSize.formatFileSize(),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Icon(
                Icons.Filled.Lock, null,
                tint = FortressCyan.copy(alpha = 0.4f),
                modifier = Modifier.size(16.dp)
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  MESSAGES SCREEN
// ═══════════════════════════════════════════════════════════════

@Composable
fun MessagesScreen() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Outlined.Email, null, Modifier.size(64.dp), tint = Color.Gray.copy(alpha = 0.3f))
            Spacer(Modifier.height(16.dp))
            Text("No encrypted messages", color = Color.Gray)
            Text("Compose encrypted messages to share", fontSize = 13.sp, color = Color.Gray.copy(alpha = 0.5f))
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  SETTINGS SCREEN
// ═══════════════════════════════════════════════════════════════

@Composable
fun SettingsScreen(viewModel: VaultViewModel) {
    val level by viewModel.securityLevel.collectAsState()

    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            Text("Security", fontSize = 13.sp, color = FortressCyan, fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(vertical = 8.dp))
        }

        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF12151C)), shape = RoundedCornerShape(12.dp)) {
                Column(Modifier.padding(16.dp)) {
                    Text("Default Security Level", fontWeight = FontWeight.Medium)
                    Spacer(Modifier.height(12.dp))
                    SecurityLevel.entries.forEach { sl ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            RadioButton(
                                selected = level == sl,
                                onClick = { viewModel.setSecurityLevel(sl) },
                                colors = RadioButtonDefaults.colors(selectedColor = FortressCyan)
                            )
                            Text(sl.displayName, fontSize = 14.sp)
                        }
                    }
                }
            }
        }

        item {
            Text("About", fontSize = 13.sp, color = FortressCyan, fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(vertical = 8.dp))
        }

        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF12151C)), shape = RoundedCornerShape(12.dp)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    InfoRow("Version", "2.0.0")
                    InfoRow("Cipher Layers", "6 (double cascade)")
                    InfoRow("KDF Chain", "Argon2id -> scrypt -> HKDF")
                    InfoRow("Post-Quantum", "ML-KEM-1024")
                }
            }
        }

        item {
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = { viewModel.lock() },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF991B1B)),
                shape = RoundedCornerShape(12.dp)
            ) {
                Icon(Icons.Filled.Lock, null)
                Spacer(Modifier.width(8.dp))
                Text("Lock Vault")
            }
        }
    }
}

@Composable
fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(label, color = Color.Gray, fontSize = 14.sp, modifier = Modifier.weight(1f))
        Text(value, fontSize = 14.sp)
    }
}

// ═══════════════════════════════════════════════════════════════
//  OPERATION OVERLAY
// ═══════════════════════════════════════════════════════════════

@Composable
fun OperationOverlay(state: OperationState) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.75f)),
        contentAlignment = Alignment.Center
    ) {
        Card(
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1D26))
        ) {
            Column(
                modifier = Modifier.padding(40.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                val icon = when (state) {
                    is OperationState.Encrypting -> Icons.Filled.Lock
                    is OperationState.Decrypting -> Icons.Filled.LockOpen
                    else -> Icons.Filled.Key
                }
                Icon(icon, null, Modifier.size(48.dp), tint = FortressCyan)

                Spacer(Modifier.height(20.dp))

                when (state) {
                    is OperationState.Encrypting -> {
                        LinearProgressIndicator(
                            progress = { state.progress.toFloat() },
                            modifier = Modifier.width(200.dp),
                            color = FortressCyan,
                            trackColor = Color(0xFF2A3040)
                        )
                        Spacer(Modifier.height(12.dp))
                        Text("${(state.progress * 100).toInt()}%",
                            fontFamily = FontFamily.Monospace, fontSize = 20.sp)
                        Text(state.status, fontSize = 13.sp, color = Color.Gray)
                    }
                    is OperationState.Decrypting -> {
                        LinearProgressIndicator(
                            progress = { state.progress.toFloat() },
                            modifier = Modifier.width(200.dp),
                            color = FortressCyan,
                            trackColor = Color(0xFF2A3040)
                        )
                        Spacer(Modifier.height(12.dp))
                        Text("${(state.progress * 100).toInt()}%",
                            fontFamily = FontFamily.Monospace, fontSize = 20.sp)
                        Text(state.status, fontSize = 13.sp, color = Color.Gray)
                    }
                    is OperationState.DerivingKeys -> {
                        CircularProgressIndicator(color = FortressCyan, modifier = Modifier.size(32.dp))
                        Spacer(Modifier.height(12.dp))
                        Text("Deriving keys...", fontSize = 13.sp, color = Color.Gray)
                    }
                    else -> {}
                }
            }
        }
    }
}
