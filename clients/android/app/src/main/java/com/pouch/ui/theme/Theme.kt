package com.pouch.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/*
 * The design tokens from docs/DESIGN_SYSTEM.md, transcribed for Compose.
 *
 * Same two layers the CSS has: brand tokens that do not change across themes,
 * and semantic tokens that resolve per theme. Components use semantic ones
 * only — a component reaching for a brand colour directly reads correctly in
 * one theme and fails contrast in the other, which is the amber-on-light
 * failure DESIGN_SYSTEM.md §2.2 records.
 *
 * Every foreground value below carries the measured contrast ratio the CSS
 * carries, because these are the same colours and the same measurements.
 * scripts/check-contrast.mjs verifies the CSS on every CI run; it does not
 * read this file, so the ratios here are copied rather than verified. If a
 * token changes, it changes in both places.
 *
 * Material 3's dynamic colour is deliberately not used. It would repaint this
 * app in the user's wallpaper palette, and the palette here is doing a job:
 * verified-green, pending-amber and alarm-red are the Custody Strip's whole
 * vocabulary. A theme that reassigns them is a theme that can make an
 * unverified contact look verified.
 */

/* ---- brand tokens (theme-independent) ----------------------------------- */

private val Ink = Color(0xFF131A24)
private val Slate = Color(0xFF1F2A36)
private val Paper = Color(0xFFE8E9E4)
private val PaperFold = Color(0xFFD6D8D1)
private val Verdigris = Color(0xFF4E8C7D)
private val VerdigrisDeep = Color(0xFF2F5F53)

/** Semantic colours that Material 3's scheme has no slot for. */
data class PouchColors(
    val verified: Color,
    val pending: Color,
    val alarm: Color,
    val mute: Color,
    val bubbleSent: Color,
    val bubbleReceived: Color,
    val border: Color,
    val sunken: Color,
)

private val LightPouchColors = PouchColors(
    verified = Color(0xFF3B6A5F), // 5.04:1 on paper
    pending = Color(0xFF7F5D27), // 4.92:1 on paper
    alarm = Color(0xFF9C3F35), // 5.42:1 on paper
    mute = Color(0xFF5B6470), // 4.91:1 on paper
    bubbleSent = Color(0x294E8C7D),
    bubbleReceived = Color(0xFFFFFFFF),
    border = PaperFold,
    sunken = PaperFold,
)

private val DarkPouchColors = PouchColors(
    verified = Color(0xFF5CA492), // 5.98:1 on ink
    pending = Color(0xFFC99A4B), // 6.83:1 on ink
    alarm = Color(0xFFD4837A), // 6.10:1 on ink
    mute = Color(0xFF8B96A2), // 5.81:1 on ink
    bubbleSent = Color(0x2E5CA492),
    bubbleReceived = Slate,
    border = Color(0xFF2C3947),
    sunken = Color(0xFF0D131B),
)

val LocalPouchColors = staticCompositionLocalOf { LightPouchColors }

private val LightScheme = lightColorScheme(
    primary = Verdigris,
    onPrimary = Color.White,
    background = Paper,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
    surfaceVariant = PaperFold,
    onSurfaceVariant = Color(0xFF5B6470),
    outline = Color(0xFFB9BCB4),
    error = Color(0xFF9C3F35),
)

private val DarkScheme = darkColorScheme(
    primary = Color(0xFF5CA492),
    onPrimary = Ink,
    background = Ink,
    onBackground = Paper,
    surface = Slate,
    onSurface = Paper,
    surfaceVariant = Color(0xFF2C3947),
    onSurfaceVariant = Color(0xFF8B96A2),
    outline = Color(0xFF3D4C5C),
    error = Color(0xFFD4837A),
)

/** Type scale from DESIGN_SYSTEM.md, in sp. */
private val PouchTypography = Typography(
    displaySmall = TextStyle(fontSize = 40.sp, lineHeight = 50.sp, fontWeight = FontWeight.SemiBold),
    headlineMedium = TextStyle(fontSize = 28.sp, lineHeight = 35.sp, fontWeight = FontWeight.SemiBold),
    titleLarge = TextStyle(fontSize = 20.sp, lineHeight = 25.sp, fontWeight = FontWeight.Medium),
    bodyLarge = TextStyle(fontSize = 16.sp, lineHeight = 25.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 22.sp),
    labelSmall = TextStyle(fontSize = 12.sp, lineHeight = 18.sp, fontWeight = FontWeight.Medium),
)

/**
 * Monospace, letter-spaced, for safety numbers and fingerprints.
 *
 * The spacing is not decoration: the user is comparing this string character
 * by character against another device's screen, and every aid to that
 * comparison is a real usability gain (DESIGN_SYSTEM.md).
 */
val SecurityTextStyle = TextStyle(
    fontFamily = FontFamily.Monospace,
    fontSize = 16.sp,
    lineHeight = 28.sp,
    letterSpacing = 1.9.sp,
)

/** Minimum touch target, SPEC §6 (44dp). */
val MinTouchTarget = 44.dp

object Space {
    val x1 = 4.dp
    val x2 = 8.dp
    val x3 = 12.dp
    val x4 = 16.dp
    val x5 = 24.dp
    val x6 = 32.dp
    val x7 = 48.dp
}

@Composable
fun PouchTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    CompositionLocalProvider(
        LocalPouchColors provides if (darkTheme) DarkPouchColors else LightPouchColors,
    ) {
        MaterialTheme(
            colorScheme = if (darkTheme) DarkScheme else LightScheme,
            typography = PouchTypography,
            content = content,
        )
    }
}
