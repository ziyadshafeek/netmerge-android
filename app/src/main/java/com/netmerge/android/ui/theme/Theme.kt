package com.netmerge.android.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColors = darkColorScheme(
    primary = Color(0xFF4ADE80),
    onPrimary = Color(0xFF0B1F14),
    secondary = Color(0xFF22D3EE),
    background = Color(0xFF0A0F0C),
    surface = Color(0xFF131A15),
    surfaceVariant = Color(0xFF1C2620),
    onBackground = Color(0xFFE8F0EA),
    onSurface = Color(0xFFE8F0EA),
    onSurfaceVariant = Color(0xFF9DB3A4),
    error = Color(0xFFF87171),
)

@Composable
fun NetMergeTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColors,
        typography = Typography(),
        content = content
    )
}
