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

package com.fortress.crypt.ui.theme

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val FortressCyan = Color(0xFF00D4FF)
val FortressCyanDark = Color(0xFF0077A8)
val FortressBlack = Color(0xFF0A0C10)
val FortressSurface = Color(0xFF12151C)
val FortressSurfaceVariant = Color(0xFF1E2330)
val FortressRed = Color(0xFFEF4444)
val FortressAmber = Color(0xFFF59E0B)

private val FortressDarkScheme = darkColorScheme(
    primary = FortressCyan,
    onPrimary = Color.Black,
    secondary = FortressCyanDark,
    background = FortressBlack,
    surface = FortressSurface,
    surfaceVariant = FortressSurfaceVariant,
    error = FortressRed,
    onBackground = Color(0xFFE8EAF0),
    onSurface = Color(0xFFE8EAF0),
    onSurfaceVariant = Color(0xFF6B7280),
    outline = Color(0xFF2A3040),
)

@Composable
fun FortressTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = FortressDarkScheme,
        typography = Typography(),
        content = content
    )
}
