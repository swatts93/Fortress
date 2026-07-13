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

package com.fortress.crypt

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.viewmodel.compose.viewModel
import com.fortress.crypt.ui.screens.LockScreen
import com.fortress.crypt.ui.screens.VaultMainScreen
import com.fortress.crypt.ui.theme.FortressTheme
import com.fortress.crypt.viewmodel.VaultState
import com.fortress.crypt.viewmodel.VaultViewModel
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Register Bouncy Castle as security provider
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        enableEdgeToEdge()

        setContent {
            FortressTheme {
                val viewModel: VaultViewModel = viewModel()
                val state by viewModel.state.collectAsState()

                when (state) {
                    is VaultState.Locked, is VaultState.Error -> {
                        LockScreen(onUnlock = { viewModel.unlock(it) })
                    }
                    is VaultState.Unlocking -> {
                        LockScreen(onUnlock = {}) // show loading state
                    }
                    is VaultState.Unlocked -> {
                        VaultMainScreen(viewModel)
                    }
                }
            }
        }
    }
}
