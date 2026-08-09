package com.pouch.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.pouch.core.Message
import com.pouch.core.Pouch
import com.pouch.core.PouchException
import com.pouch.core.SendResult
import com.pouch.ui.theme.LocalPouchColors
import com.pouch.ui.theme.SecurityTextStyle
import com.pouch.ui.theme.Space
import kotlinx.coroutines.launch

/**
 * Screen 3 — Conversation view (SPEC §6.7.3).
 *
 * Custody Strip pinned at the top, messages below, composer at the bottom.
 *
 * **Message state is text, not icons** — `sending` / `sent` / `failed — retry`.
 * SPEC §6.7.3 requires this and the reason is worth restating: an icon has to be
 * learned, and the one state a user must never misread is the failed one. A grey
 * tick and a green tick differ by a glance; "failed" and "sent" do not.
 *
 * A failed send shows its reason inline rather than a generic apology, and the
 * reason comes from the core's own error text, never reworded here.
 */
@Composable
fun ConversationScreen(
    conversationId: String,
    contactName: String,
    identity: String,
    transport: String,
    retention: String,
    onBack: () -> Unit,
    onSafetyNumber: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val colors = LocalPouchColors.current

    var messages by remember { mutableStateOf(emptyList<Message>()) }
    var draft by remember { mutableStateOf("") }
    var sending by remember { mutableStateOf(false) }
    var lastSend by remember { mutableStateOf<SendResult?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    val listState = rememberLazyListState()

    suspend fun reload() {
        messages = Pouch.messages(conversationId)
    }

    LaunchedEffect(conversationId) {
        try {
            // Collect anything waiting before showing the thread, so opening a
            // conversation does not display a stale view of it.
            Pouch.receiveMessages()
            reload()
        } catch (e: PouchException) {
            error = e.message
        }
    }

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
    }

    Column(modifier = Modifier.fillMaxSize()) {
        CustodyStrip(
            identity = identity,
            transport = transport,
            retention = retention,
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = Space.x4, vertical = Space.x2),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(text = contactName, style = MaterialTheme.typography.titleMedium)
            Row {
                Button(onClick = onSafetyNumber) { Text("Safety number") }
                Button(onClick = onBack, modifier = Modifier.padding(start = Space.x2)) {
                    Text("Back")
                }
            }
        }

        error?.let {
            Text(
                text = it,
                color = colors.alarm,
                modifier = Modifier.padding(horizontal = Space.x4, vertical = Space.x2),
            )
        }

        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .padding(horizontal = Space.x4),
            verticalArrangement = Arrangement.spacedBy(Space.x2),
        ) {
            items(messages, key = { it.id }) { message ->
                MessageBubble(message)
            }
        }

        // The manifest for the most recent send. Shown under the composer rather
        // than in a dialog: SPEC §6.5 treats it as ambient evidence, not an
        // interruption, and a modal would make it something to dismiss.
        lastSend?.let { result ->
            Surface(
                color = colors.sunken,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = Space.x4, vertical = Space.x2),
            ) {
                Column(modifier = Modifier.padding(Space.x3)) {
                    Text(
                        text = result.summary,
                        style = SecurityTextStyle,
                        color = if (result.failed) colors.alarm else colors.verified,
                    )
                    result.rows.forEach { row ->
                        Text(
                            text = "%02d  %-18s %s".format(
                                row.number,
                                row.label,
                                if (row.ran) row.detail else "not yet implemented",
                            ),
                            style = SecurityTextStyle,
                            color = if (row.ran) colors.mute else colors.pending,
                        )
                    }
                }
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(Space.x4),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it },
                modifier = Modifier.weight(1f),
                label = { Text("Message") },
                enabled = !sending,
            )
            Button(
                onClick = {
                    val body = draft.trim()
                    if (body.isEmpty() || sending) return@Button
                    sending = true
                    error = null
                    scope.launch {
                        try {
                            val result = Pouch.sendMessage(conversationId, body)
                            lastSend = result
                            // Cleared only on success. A failed send leaves the
                            // text where the user can retry it rather than
                            // making them retype what was lost.
                            if (!result.failed) draft = ""
                            reload()
                        } catch (e: PouchException) {
                            error = e.message
                        } finally {
                            sending = false
                        }
                    }
                },
                modifier = Modifier.padding(start = Space.x2),
                enabled = !sending && draft.isNotBlank(),
            ) {
                Text(if (sending) "Sending…" else "Send")
            }
        }
    }
}

@Composable
private fun MessageBubble(message: Message) {
    val colors = LocalPouchColors.current
    Box(
        modifier = Modifier.fillMaxWidth(),
        contentAlignment = if (message.outgoing) Alignment.CenterEnd else Alignment.CenterStart,
    ) {
        Surface(
            color = if (message.outgoing) colors.bubbleSent else colors.bubbleReceived,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.widthIn(max = 280.dp),
        ) {
            Column(modifier = Modifier.padding(Space.x3)) {
                Text(text = message.body, style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = message.at.toString(),
                    style = SecurityTextStyle,
                    color = colors.mute,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}
