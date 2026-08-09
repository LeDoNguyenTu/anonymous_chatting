package com.pouch.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import com.pouch.ui.theme.LocalPouchColors
import com.pouch.ui.theme.Space

/**
 * Which relay this install talks to (D-051).
 *
 * ## Why this screen exists at all
 *
 * On desktop the relay address is an environment variable read once at startup,
 * and D-049 says plainly that nothing the UI can write should reach it: a client
 * that can be pointed at an arbitrary relay from its own interface is a client
 * that can be *talked into* being pointed there.
 *
 * Android has no shell and no per-app environment. Holding that line here would
 * mean a separate APK per relay — which in practice means people install a
 * pre-configured APK from whoever set it up, making the binary *and* the address
 * someone else's choice. This screen is the lesser of those two.
 *
 * ## So it states the cost rather than hiding it
 *
 * The copy below does not say "enter your relay" and stop. It says what handing
 * an address to the wrong operator actually costs, in the terms
 * `THREAT_MODEL.md` §5 already uses: not message content, which the relay never
 * holds a key for, but the inbox identifiers and connection timing it does see.
 *
 * ## Restart, not hot-swap
 *
 * Saving closes the app. The core reads its relay once and holds it for the
 * process lifetime, so re-pointing a live session would put some messages in a
 * conversation on one relay and some on another with the Custody Strip unable to
 * say which. The button says so before it does it.
 */
@Composable
fun RelayScreen(
    initialUrl: String,
    initialOnion: String,
    isFirstRun: Boolean,
    onSave: (url: String, onion: String) -> Unit,
    onBack: (() -> Unit)?,
) {
    var url by remember { mutableStateOf(initialUrl) }
    var onion by remember { mutableStateOf(initialOnion) }
    var error by remember { mutableStateOf<String?>(null) }

    val colors = LocalPouchColors.current

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(Space.x4),
        verticalArrangement = Arrangement.spacedBy(Space.x3),
    ) {
        Text(
            if (isFirstRun) "Where is your relay?" else "Relay",
            style = MaterialTheme.typography.headlineSmall,
        )

        Text(
            "Pouch does not run a server for you. Somebody — you or the person " +
                "you are talking to — runs the relay, and both apps have to point " +
                "at the same one.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Text(
            "The relay only ever holds encrypted blobs it has no key for. Pointing " +
                "at the wrong one does not expose what you write. It does show that " +
                "operator which inboxes are being polled and when, and messages will " +
                "not reach anyone who is not using the same relay.",
            style = MaterialTheme.typography.bodySmall,
            color = colors.mute,
        )

        error?.let {
            Text(
                text = it,
                color = colors.alarm,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(vertical = Space.x2),
            )
        }

        OutlinedTextField(
            value = url,
            onValueChange = { url = it; error = null },
            label = { Text("Relay address") },
            placeholder = { Text("http://192.168.1.10:8443") },
            singleLine = true,
            textStyle = MaterialTheme.typography.bodyMedium.copy(
                fontFamily = FontFamily.Monospace,
            ),
            modifier = Modifier.fillMaxWidth(),
        )

        Text(
            "A relay on the same wifi as this phone, or a machine you can reach. " +
                "Remote addresses need a pinned certificate, so on a home network " +
                "this is usually the host's local address.",
            style = MaterialTheme.typography.bodySmall,
            color = colors.mute,
        )

        OutlinedTextField(
            value = onion,
            onValueChange = { onion = it; error = null },
            label = { Text("Onion address (optional)") },
            placeholder = { Text("abc…xyz.onion") },
            singleLine = true,
            textStyle = MaterialTheme.typography.bodyMedium.copy(
                fontFamily = FontFamily.Monospace,
            ),
            modifier = Modifier.fillMaxWidth(),
        )

        Text(
            "Fill this in to reach a relay that is not on your network, without the " +
                "host forwarding a port. Leave it blank and the Tor route stays " +
                "unavailable — the transport screen will say so rather than offer a " +
                "choice that cannot be made.",
            style = MaterialTheme.typography.bodySmall,
            color = colors.mute,
        )

        Button(
            onClick = {
                // Validation lives in RelaySetting so it is a plain JVM test.
                // The message it throws is written to be shown, so it is shown
                // rather than replaced with wording invented here.
                try {
                    val checked = com.pouch.core.validate(url, onion)
                    onSave(checked.relayUrl, checked.onionHost)
                } catch (e: IllegalArgumentException) {
                    error = e.message
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = Space.x2),
        ) {
            Text(if (isFirstRun) "Save and continue" else "Save and close Pouch")
        }

        if (!isFirstRun) {
            Text(
                "Changing the relay closes the app. It reads this once at startup, " +
                    "so switching while running would put some of a conversation on " +
                    "one relay and some on another.",
                style = MaterialTheme.typography.bodySmall,
                color = colors.mute,
            )
        }

        onBack?.let {
            TextButton(onClick = it, modifier = Modifier.fillMaxWidth()) {
                Text("Back")
            }
        }
    }
}
