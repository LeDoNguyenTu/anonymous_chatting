package com.pouch.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import com.pouch.core.Pouch
import com.pouch.core.PouchException
import com.pouch.ui.theme.LocalPouchColors
import com.pouch.ui.theme.SecurityTextStyle
import com.pouch.ui.theme.Space
import kotlinx.coroutines.launch

/**
 * Screen 4 — Safety number (SPEC §6.7.4).
 *
 * The number, how to compare it, and two buttons.
 *
 * ## The wording of the buttons is the whole screen
 *
 * "They match" and "They do not match" — not OK and Cancel. The user is being
 * asked to report an observation, and the button they press should be the
 * sentence they would say out loud. An OK button invites the reflex of
 * confirming without looking, which is the single failure this screen exists to
 * prevent: an unverified contact is exactly as trustworthy as whatever channel
 * carried the invite code.
 *
 * Marking a mismatch does not silently do nothing. It clears any verification
 * and says what to do next, because a mismatch is a finding, not a cancel.
 */
@Composable
fun SafetyNumberScreen(
    contactId: String,
    contactName: String,
    verified: Boolean,
    onDone: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val colors = LocalPouchColors.current

    var number by remember { mutableStateOf<String?>(null) }
    var mismatch by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(contactId) {
        try {
            number = Pouch.safetyNumber(contactId)
        } catch (e: PouchException) {
            error = e.message
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(Space.x4),
    ) {
        Text("Safety number", style = MaterialTheme.typography.titleLarge)
        Text(
            text = "for $contactName",
            style = MaterialTheme.typography.bodyMedium,
            color = colors.mute,
        )

        Surface(
            color = colors.sunken,
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = Space.x4),
        ) {
            Text(
                text = number ?: "…",
                style = SecurityTextStyle,
                fontFamily = FontFamily.Monospace,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(Space.x4),
            )
        }

        Text(
            text = "Read this aloud to $contactName over a channel you already " +
                "trust — a phone call, or in person. They should be reading the " +
                "same digits back.",
            style = MaterialTheme.typography.bodyMedium,
        )

        Text(
            text = "Both of you see the same number because it is derived from " +
                "both identity keys. If someone had substituted a key, the two " +
                "numbers would differ.",
            style = MaterialTheme.typography.bodySmall,
            color = colors.mute,
            modifier = Modifier.padding(vertical = Space.x3),
        )

        error?.let {
            Text(text = it, color = colors.alarm, modifier = Modifier.padding(vertical = Space.x2))
        }

        if (mismatch) {
            Surface(
                color = colors.sunken,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = Space.x3),
            ) {
                Column(modifier = Modifier.padding(Space.x3)) {
                    Text(
                        text = "Marked unverified.",
                        style = MaterialTheme.typography.titleMedium,
                        color = colors.alarm,
                    )
                    Text(
                        text = "Do not treat this conversation as private. Delete the " +
                            "contact and exchange invite codes again over a channel " +
                            "you are confident in. If the numbers still differ, stop.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }

        Button(
            onClick = {
                scope.launch {
                    try {
                        Pouch.verifyContact(contactId, true)
                        onDone()
                    } catch (e: PouchException) {
                        error = e.message
                    }
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = Space.x4),
            enabled = number != null,
        ) {
            Text("They match")
        }

        Button(
            onClick = {
                scope.launch {
                    try {
                        Pouch.verifyContact(contactId, false)
                        mismatch = true
                    } catch (e: PouchException) {
                        error = e.message
                    }
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = Space.x2),
            enabled = number != null,
        ) {
            Text("They do not match")
        }

        if (verified) {
            Text(
                text = "You have marked this contact verified before.",
                style = MaterialTheme.typography.bodySmall,
                color = colors.verified,
                modifier = Modifier.padding(top = Space.x3),
            )
        }

        TextButton(onClick = onDone, modifier = Modifier.padding(top = Space.x2)) {
            Text("Back")
        }
    }
}
