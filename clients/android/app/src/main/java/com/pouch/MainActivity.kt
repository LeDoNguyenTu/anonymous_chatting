package com.pouch

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import com.pouch.core.Conversation
import com.pouch.core.IdentityChange
import com.pouch.core.Pouch
import com.pouch.core.PouchException
import com.pouch.core.RelaySetting
import com.pouch.ui.AddContactScreen
import com.pouch.ui.ConversationScreen
import com.pouch.ui.CustodyStrip
import com.pouch.ui.IdentityChangeDialog
import com.pouch.ui.RelayScreen
import com.pouch.ui.SafetyNumberScreen
import com.pouch.ui.SettingsScreen
import com.pouch.ui.theme.LocalPouchColors
import com.pouch.ui.theme.PouchTheme
import com.pouch.ui.theme.Space
import kotlinx.coroutines.launch
import java.io.File

/**
 * The shell.
 *
 * Navigation is a sealed class and a single `when`, not a nav library. There
 * are six destinations and no deep links; a graph definition would be more
 * moving parts than the thing it routes.
 *
 * SPEC §6.7 screens present here: first run (1), conversation list (2),
 * conversation view (3), add contact (4), safety number (5), identity change
 * (6), privacy and storage (7), transport (9), security details (12).
 *
 * **Not** present, and the settings screen says so on its face rather than
 * hiding it: attachment preview (8), backup export and import (10), and wipe
 * (11). Those exist in the core and on the desktop client. A phone build that
 * quietly omitted them would look complete and lose someone their data the
 * first time they assumed backup was there.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // filesDir is this app's private directory. On Android that is already
        // unreadable by other apps — which is not a substitute for encrypting
        // the database, since a rooted device or an adb backup reads it anyway.
        // SQLCipher is underneath for exactly that reason.
        val dbPath = File(filesDir, "pouch.db").absolutePath
        // A sibling of the database, never inside it: Tor bootstrap and circuit
        // state is not message content, and wiping the database should not
        // throw away a working bootstrap.
        val torStateDir = File(filesDir, "tor-state").absolutePath

        setContent {
            PouchTheme {
                App(
                    dbPath = dbPath,
                    torStateDir = torStateDir,
                    relayUrl = RelaySetting.current(this),
                    onionHost = RelaySetting.onionHost(this),
                    relayConfigured = RelaySetting.isConfigured(this),
                    onSaveRelay = { url, onion ->
                        RelaySetting.set(this, url, onion)
                        // Restart rather than reconfigure. The core reads its
                        // relay once and holds it for the process lifetime, so
                        // there is no correct way to change it in place — and a
                        // half-changed session is one where the Custody Strip
                        // cannot say which relay a message went to.
                        finishAffinity()
                        Runtime.getRuntime().exit(0)
                    },
                )
            }
        }
    }
}

/** Where the user is. */
private sealed interface Screen {
    data object List : Screen
    data object AddContact : Screen
    data object Settings : Screen
    data class Thread(val conversation: Conversation) : Screen
    data class Safety(val conversation: Conversation) : Screen
}

@Composable
private fun App(
    dbPath: String,
    torStateDir: String,
    relayUrl: String,
    onionHost: String,
    relayConfigured: Boolean,
    onSaveRelay: (String, String) -> Unit,
) {
    val scope = rememberCoroutineScope()

    var ready by remember { mutableStateOf(false) }
    var hasIdentity by remember { mutableStateOf(false) }
    var conversations by remember { mutableStateOf(emptyList<Conversation>()) }
    var transport by remember { mutableStateOf("") }
    var retention by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var screen by remember { mutableStateOf<Screen>(Screen.List) }
    var pendingChange by remember { mutableStateOf<IdentityChange?>(null) }
    var editingRelay by remember { mutableStateOf(false) }

    suspend fun refresh() {
        conversations = Pouch.conversations()
        transport = Pouch.transportState()
        retention = Pouch.retentionPolicy()
        // Checked on every refresh rather than at startup only. A key can change
        // while the app is open, and the warning has to arrive then, not at the
        // next cold start.
        pendingChange = Pouch.identityChanges().firstOrNull()
    }

    LaunchedEffect(Unit) {
        try {
            Pouch.start(dbPath, torStateDir, relayUrl, onionHost)
            hasIdentity = Pouch.hasIdentity()
            if (hasIdentity) {
                Pouch.openIdentity()
                refresh()
            }
        } catch (e: PouchException) {
            error = e.message
        } finally {
            ready = true
        }
    }

    // Before anything else, and before an identity exists. A relay address is
    // the one piece of configuration this app cannot infer, and starting an
    // identity against the build's emulator default would leave someone sending
    // into a queue that never drains — looking, from the inside, exactly like
    // the other person not replying.
    if (!relayConfigured || editingRelay) {
        RelayScreen(
            initialUrl = relayUrl,
            initialOnion = onionHost,
            isFirstRun = !relayConfigured,
            onSave = onSaveRelay,
            onBack = if (relayConfigured) ({ editingRelay = false }) else null,
        )
        return
    }

    // The modal outranks whatever screen is showing, including a conversation
    // the user is mid-way through typing into. That is the point of it.
    pendingChange?.let { change ->
        IdentityChangeDialog(
            change = change,
            onCompare = {
                val match = conversations.firstOrNull { it.contactId == change.contactId }
                scope.launch {
                    runCatching { Pouch.acknowledgeIdentityChange(change.contactId) }
                    pendingChange = null
                    if (match != null) screen = Screen.Safety(match)
                }
            },
            onAcknowledge = {
                scope.launch {
                    try {
                        // Records that the warning was seen. Does not verify the
                        // contact — they stay UNVERIFIED until a safety number
                        // is actually compared.
                        Pouch.acknowledgeIdentityChange(change.contactId)
                        refresh()
                    } catch (e: PouchException) {
                        error = e.message
                    }
                }
            },
        )
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            error?.let {
                Text(
                    text = it,
                    color = LocalPouchColors.current.alarm,
                    modifier = Modifier.padding(Space.x4),
                )
            }

            when {
                !ready -> Text("Opening…", modifier = Modifier.padding(Space.x4))

                !hasIdentity -> FirstRun(
                    onCreate = { name ->
                        scope.launch {
                            try {
                                Pouch.createIdentity(name)
                                hasIdentity = true
                                refresh()
                            } catch (e: PouchException) {
                                error = e.message
                            }
                        }
                    },
                )

                else -> when (val current = screen) {
                    is Screen.List -> {
                        // The strip reports what is true right now. `transport`
                        // is whatever the core last resolved, including OFFLINE
                        // — it is never defaulted to DIRECT to look tidier.
                        CustodyStrip(
                            identity = conversations.firstOrNull()?.identity ?: "UNVERIFIED",
                            transport = transport,
                            retention = retention,
                        )
                        ConversationList(
                            conversations = conversations,
                            onOpen = { screen = Screen.Thread(it) },
                            onAddContact = { screen = Screen.AddContact },
                            onSettings = { screen = Screen.Settings },
                            onRefresh = {
                                scope.launch {
                                    try {
                                        Pouch.receiveMessages()
                                        refresh()
                                    } catch (e: PouchException) {
                                        error = e.message
                                    }
                                }
                            },
                        )
                    }

                    is Screen.AddContact -> AddContactScreen(
                        onAdded = {
                            scope.launch {
                                refresh()
                                screen = Screen.List
                            }
                        },
                        onBack = { screen = Screen.List },
                    )

                    is Screen.Settings -> SettingsScreen(
                        onBack = { screen = Screen.List },
                        onStateChanged = { scope.launch { refresh() } },
                        onChangeRelay = { editingRelay = true },
                    )

                    is Screen.Thread -> ConversationScreen(
                        conversationId = current.conversation.id,
                        contactName = current.conversation.contactName,
                        identity = current.conversation.identity,
                        transport = transport,
                        retention = retention,
                        onBack = {
                            scope.launch { refresh() }
                            screen = Screen.List
                        },
                        onSafetyNumber = { screen = Screen.Safety(current.conversation) },
                    )

                    is Screen.Safety -> SafetyNumberScreen(
                        contactId = current.conversation.contactId,
                        contactName = current.conversation.contactName,
                        verified = current.conversation.identity == "VERIFIED",
                        onDone = {
                            scope.launch { refresh() }
                            screen = Screen.Thread(current.conversation)
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun FirstRun(onCreate: (String) -> Unit) {
    var name by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(Space.x4),
        verticalArrangement = Arrangement.spacedBy(Space.x4),
    ) {
        Text("Pouch", style = MaterialTheme.typography.headlineMedium)
        Text(
            "This name is stored on this device only. It is never sent to the relay " +
                "and nobody else sees it.",
            style = MaterialTheme.typography.bodyMedium,
            color = LocalPouchColors.current.mute,
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text("Display name") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = { onCreate(name) },
            enabled = name.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Create identity")
        }
    }
}

@Composable
private fun ConversationList(
    conversations: List<Conversation>,
    onOpen: (Conversation) -> Unit,
    onAddContact: () -> Unit,
    onSettings: () -> Unit,
    onRefresh: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.x4, vertical = Space.x2),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Button(onClick = onAddContact) { Text("Add contact") }
        Row {
            TextButton(onClick = onRefresh) { Text("Check") }
            TextButton(onClick = onSettings) { Text("Settings") }
        }
    }

    if (conversations.isEmpty()) {
        Column(modifier = Modifier.padding(Space.x4)) {
            Text("No conversations yet.", style = MaterialTheme.typography.bodyLarge)
            Text(
                "Add someone using their invite code. You will need to send them " +
                    "yours as well.",
                style = MaterialTheme.typography.bodyMedium,
                color = LocalPouchColors.current.mute,
                modifier = Modifier.padding(top = Space.x2),
            )
        }
        return
    }

    LazyColumn(modifier = Modifier.fillMaxSize()) {
        items(conversations, key = { it.id }) { conversation ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onOpen(conversation) }
                    .padding(Space.x4),
            ) {
                Text(conversation.contactName, style = MaterialTheme.typography.titleLarge)
                Text(
                    conversation.identity,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelSmall,
                    color = when (conversation.identity) {
                        "VERIFIED" -> LocalPouchColors.current.verified
                        "KEY CHANGED" -> LocalPouchColors.current.alarm
                        else -> LocalPouchColors.current.pending
                    },
                )
                conversation.lastMessage?.let {
                    Text(
                        it,
                        style = MaterialTheme.typography.bodyMedium,
                        color = LocalPouchColors.current.mute,
                    )
                }
            }
            HorizontalDivider()
        }
    }
}
