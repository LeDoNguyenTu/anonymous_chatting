package com.pouch.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import com.pouch.core.Pouch
import com.pouch.core.PouchException
import com.pouch.ui.theme.LocalPouchColors
import com.pouch.ui.theme.SecurityTextStyle
import com.pouch.ui.theme.Space
import kotlinx.coroutines.launch

/**
 * Screen 2 — Add contact (SPEC §6.7.4).
 *
 * Your own invite code at the top, a field for theirs below.
 *
 * ## Why the warning is not dismissible
 *
 * An invite code is how each side learns the other's identity key. Someone who
 * can rewrite a code in transit substitutes their own key, and every message
 * after that is encrypted to them. Pouch cannot detect that — the safety number
 * comparison is what detects it, afterwards.
 *
 * So the sentence about using a different channel is plain body text that is
 * always on screen, not a tooltip and not a one-time notice. A warning the user
 * can make disappear is a warning that will be absent exactly when it matters.
 */
@Composable
fun AddContactScreen(onAdded: (String) -> Unit, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    val colors = LocalPouchColors.current
    val clipboard = LocalClipboardManager.current

    var myCode by remember { mutableStateOf<String?>(null) }
    var theirName by remember { mutableStateOf("") }
    var theirCode by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        try {
            myCode = Pouch.inviteCode()
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
        Text("Add contact", style = MaterialTheme.typography.titleLarge)

        Text(
            text = "Send your code to them and paste theirs below. Use a channel " +
                "you already trust — a phone call, or in person. Anyone who can " +
                "change a code while it travels can read everything that follows.",
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(vertical = Space.x3),
        )

        Text("Your invite code", style = MaterialTheme.typography.titleMedium)
        Surface(
            color = colors.sunken,
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = Space.x2),
        ) {
            Text(
                text = myCode ?: "…",
                style = SecurityTextStyle,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(Space.x3),
            )
        }
        TextButton(
            onClick = { myCode?.let { clipboard.setText(AnnotatedString(it)) } },
            enabled = myCode != null,
        ) {
            Text("Copy my code")
        }

        Text(
            text = "It contains a public key, an inbox address, and one key package. " +
                "No name, no phone number, no email.",
            style = MaterialTheme.typography.bodySmall,
            color = colors.mute,
            modifier = Modifier.padding(bottom = Space.x5),
        )

        Text("Their code", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = theirName,
            onValueChange = { theirName = it },
            label = { Text("What to call them") },
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = Space.x2),
            enabled = !busy,
        )
        Text(
            text = "This name is stored on this device only. It is never sent anywhere.",
            style = MaterialTheme.typography.bodySmall,
            color = colors.mute,
        )
        OutlinedTextField(
            value = theirCode,
            onValueChange = { theirCode = it },
            label = { Text("Their invite code") },
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = Space.x2),
            enabled = !busy,
            minLines = 3,
        )

        error?.let {
            Text(
                text = it,
                color = colors.alarm,
                modifier = Modifier.padding(vertical = Space.x2),
            )
        }

        Button(
            onClick = {
                busy = true
                error = null
                scope.launch {
                    try {
                        val id = Pouch.addContact(theirName.trim(), theirCode.trim())
                        onAdded(id)
                    } catch (e: PouchException) {
                        error = e.message
                    } finally {
                        busy = false
                    }
                }
            },
            modifier = Modifier.padding(top = Space.x3),
            enabled = !busy && theirName.isNotBlank() && theirCode.isNotBlank(),
        ) {
            Text(if (busy) "Adding…" else "Add contact")
        }

        Text(
            text = "They will start as UNVERIFIED. Compare safety numbers before " +
                "you treat the conversation as confirmed.",
            style = MaterialTheme.typography.bodySmall,
            color = colors.pending,
            modifier = Modifier.padding(vertical = Space.x3),
        )

        TextButton(onClick = onBack, enabled = !busy) { Text("Back") }
    }
}
