package com.pouch.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.pouch.core.IdentityChange
import com.pouch.ui.theme.LocalPouchColors
import com.pouch.ui.theme.Space

/**
 * Screen 8 — Identity change (SPEC §6.7.6).
 *
 * A contact's identity key changing has two explanations: they reinstalled, or
 * someone is now in the middle. Nothing on this device can tell which.
 *
 * ## Why this blocks
 *
 * `onDismissRequest` is deliberately empty, so a tap outside and the back
 * gesture both do nothing. The only ways out are acknowledging it or opening the
 * safety number screen.
 *
 * That is a deliberate cost imposed on the user, and it earns it: a toast for
 * this is a toast that gets swiped away during a conversation the user then
 * continues in the belief it is private. The threat model (§3, key substitution)
 * treats the out-of-band comparison as the only defence, and a defence that can
 * be dismissed without being noticed is not one.
 *
 * Acknowledging does **not** mark the contact verified. It records that the
 * warning was seen; the contact stays UNVERIFIED until a safety number is
 * actually compared.
 */
@Composable
fun IdentityChangeDialog(
    change: IdentityChange,
    onCompare: () -> Unit,
    onAcknowledge: () -> Unit,
) {
    val colors = LocalPouchColors.current

    AlertDialog(
        onDismissRequest = { },
        title = {
            Text(
                text = "${change.contactName}'s key changed",
                color = colors.alarm,
                style = MaterialTheme.typography.titleMedium,
            )
        },
        text = {
            Column {
                Text(
                    text = "The identity key for ${change.contactName} is not the one " +
                        "this device saw before.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = "This happens when someone reinstalls or switches device. " +
                        "It also happens when someone has placed themselves between " +
                        "you. Nothing on this phone can tell the two apart.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(top = Space.x2),
                )
                Text(
                    text = "Compare safety numbers with them over a channel you " +
                        "trust before sending anything else.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(top = Space.x2),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onCompare) { Text("Compare safety numbers") }
        },
        dismissButton = {
            TextButton(onClick = onAcknowledge) { Text("Not now") }
        },
    )
}
