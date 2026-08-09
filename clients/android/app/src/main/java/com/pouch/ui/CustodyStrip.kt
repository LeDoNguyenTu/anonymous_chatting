package com.pouch.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.pouch.ui.theme.LocalPouchColors
import com.pouch.ui.theme.MinTouchTarget
import com.pouch.ui.theme.Space

/*
 * The Custody Strip — DESIGN_SYSTEM.md §4.
 *
 * Three facts, always visible, always monospace, never collapsing on scroll.
 * The rule that governs every change to this file:
 *
 *   It must never show a reassuring state when the underlying state is
 *   uncertain.
 *
 * There is deliberately no "unknown falls back to something friendly" path.
 * An identity that is not confirmed verified renders UNVERIFIED in amber, and
 * a transport that is not known renders as its own state rather than as the
 * last good one.
 *
 * ## The copy below is duplicated, and that is a known problem
 *
 * These strings also exist in clients/desktop/src/components/CustodyStrip.tsx.
 * Two hand-maintained copies of security copy drift, which is exactly the
 * failure that moved the view shapes into core::views (D-046). The right fix
 * is the same one: these belong on the core types, the way Route::explanation
 * already does for transport.
 *
 * It is not done here because it means changing the desktop client's rendering
 * path as well, and doing that in the same change as a new client's first
 * screens would make both harder to review. Tracked as an open item in
 * docs/PROGRESS.md rather than left to be discovered.
 */

enum class Tone { VERIFIED, PENDING, ALARM, MUTE }

data class CustodyField(
    val label: String,
    val caption: String,
    val tone: Tone,
    /** What the field means. Read aloud, and shown when the field is opened. */
    val explanation: String,
)

/**
 * Identity states, keyed by the label the core sends.
 *
 * Keyed by label rather than by an enum this file defines, so a state the core
 * knows about and this app does not cannot silently match the wrong entry —
 * [identityField] returns an explicit unknown instead.
 */
private val IDENTITY = mapOf(
    "VERIFIED" to CustodyField(
        "VERIFIED", "identity", Tone.VERIFIED,
        "You compared this contact's safety number out of band and marked it as matching.",
    ),
    "UNVERIFIED" to CustodyField(
        "UNVERIFIED", "identity", Tone.PENDING,
        "You have not compared safety numbers with this contact yet. You can still " +
            "message them. Until you compare, this stays amber.",
    ),
    "KEY CHANGED" to CustodyField(
        "KEY CHANGED", "identity", Tone.ALARM,
        "This contact's identity key changed. That usually means they reinstalled or " +
            "switched devices. It can also mean someone is intercepting your messages. " +
            "Compare the new safety number before continuing.",
    ),
)

private val TRANSPORT = mapOf(
    "TOR" to CustodyField(
        "TOR", "transport", Tone.VERIFIED,
        "Messages route through a Tor onion circuit. The relay never learns your IP " +
            "address. Your internet provider can still see that you are using Tor.",
    ),
    "DIRECT" to CustodyField(
        "DIRECT", "transport", Tone.PENDING,
        "Messages go straight to the relay over TLS 1.3. The relay sees the IP address " +
            "you connect from. Message content stays encrypted either way.",
    ),
    "OFFLINE" to CustodyField(
        "OFFLINE", "transport", Tone.MUTE,
        "No connection to the relay. Messages you write are queued on this device and " +
            "send when you reconnect.",
    ),
)

private val RETENTION = mapOf(
    "forever" to CustodyField(
        "KEEP", "retention", Tone.MUTE,
        "Messages in this conversation are kept until you delete them.",
    ),
    "30d" to CustodyField(
        "30-DAY", "retention", Tone.VERIFIED,
        "Messages in this conversation are erased after 30 days.",
    ),
    "7d" to CustodyField(
        "7-DAY", "retention", Tone.VERIFIED,
        "Messages in this conversation are erased after 7 days.",
    ),
    "24h" to CustodyField(
        "24-HOUR", "retention", Tone.VERIFIED,
        "Messages in this conversation are erased after 24 hours.",
    ),
)

/**
 * The field for a state this build does not recognise.
 *
 * Amber and explicit, never green and never blank. A strip that renders an
 * unrecognised identity as neutral grey reads as "nothing to worry about",
 * which is precisely the reassurance-under-uncertainty this component exists
 * to prevent.
 */
private fun unknown(caption: String) = CustodyField(
    label = "UNKNOWN",
    caption = caption,
    tone = Tone.PENDING,
    explanation = "This version of the app does not recognise the state the core " +
        "reported for $caption. Treat it as unconfirmed.",
)

fun identityField(label: String): CustodyField = IDENTITY[label] ?: unknown("identity")

fun transportField(label: String): CustodyField = TRANSPORT[label] ?: unknown("transport")

fun retentionField(policy: String): CustodyField = RETENTION[policy] ?: unknown("retention")

@Composable
private fun toneColor(tone: Tone): Color {
    val colors = LocalPouchColors.current
    return when (tone) {
        Tone.VERIFIED -> colors.verified
        Tone.PENDING -> colors.pending
        Tone.ALARM -> colors.alarm
        Tone.MUTE -> colors.mute
    }
}

@Composable
private fun Field(field: CustodyField, modifier: Modifier = Modifier) {
    val color = toneColor(field.tone)
    Column(
        modifier = modifier
            .defaultMinSize(minHeight = MinTouchTarget)
            .padding(vertical = Space.x2)
            // The label alone reads as an abbreviation out of context, so
            // TalkBack gets the caption and the full explanation too.
            .semantics {
                contentDescription = "${field.caption}: ${field.label}. ${field.explanation}"
            },
        verticalArrangement = Arrangement.Center,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            // Colour is never the only carrier: the dot sits beside a text
            // label that says the same thing (DESIGN_SYSTEM.md).
            Column(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(color),
            ) {}
            Text(
                text = field.label,
                color = color,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(start = Space.x2),
            )
        }
        Text(
            text = field.caption,
            color = LocalPouchColors.current.mute,
            style = MaterialTheme.typography.labelSmall,
        )
    }
}

@Composable
fun CustodyStrip(
    identity: String,
    transport: String,
    retention: String,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = Space.x4)
            .semantics { contentDescription = "Custody state for this conversation" },
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Field(identityField(identity))
        Field(transportField(transport))
        Field(retentionField(retention))
    }
}
