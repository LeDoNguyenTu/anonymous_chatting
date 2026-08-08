package com.pouch

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import com.pouch.core.Conversation
import com.pouch.core.Pouch
import com.pouch.core.PouchException
import com.pouch.ui.CustodyStrip
import com.pouch.ui.theme.LocalPouchColors
import com.pouch.ui.theme.PouchTheme
import com.pouch.ui.theme.Space
import kotlinx.coroutines.launch
import java.io.File

/**
 * The shell.
 *
 * ## What this is, and what it is not
 *
 * This is Phase 5's foundation: the native bridge is wired, the database opens
 * in the app's private directory, an identity can be created, and the
 * conversation list and Custody Strip render from real core state.
 *
 * The rest of SPEC §6.7's screens — conversation view, safety number, add
 * contact, privacy and storage, security details, transport settings, backup
 * and restore, and the identity-change modal — are **not built yet**. The
 * desktop client has all of them; this one does not, and the app says so on
 * its face rather than presenting a shell that looks finished.
 *
 * Stated here because a half-built client that hides what it lacks is the same
 * category of dishonesty as a UI that shows a reassuring indicator over an
 * uncertain state.
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
                App(dbPath = dbPath, torStateDir = torStateDir)
            }
        }
    }
}

@Composable
private fun App(dbPath: String, torStateDir: String) {
    val scope = rememberCoroutineScope()

    var ready by remember { mutableStateOf(false) }
    var hasIdentity by remember { mutableStateOf(false) }
    var conversations by remember { mutableStateOf(emptyList<Conversation>()) }
    var transport by remember { mutableStateOf("") }
    var retention by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    suspend fun refresh() {
        conversations = Pouch.conversations()
        transport = Pouch.transportState()
        retention = Pouch.retentionPolicy()
    }

    LaunchedEffect(Unit) {
        try {
            Pouch.start(dbPath, torStateDir, BuildConfig.RELAY_URL)
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

                else -> {
                    // The strip reports what is true right now. `transport` is
                    // whatever the core last resolved, including OFFLINE — it
                    // is never defaulted to DIRECT to look tidier.
                    CustodyStrip(
                        identity = conversations.firstOrNull()?.identity ?: "UNVERIFIED",
                        transport = transport,
                        retention = retention,
                    )
                    ConversationList(conversations)
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
private fun ConversationList(conversations: List<Conversation>) {
    if (conversations.isEmpty()) {
        Column(modifier = Modifier.padding(Space.x4)) {
            Text("No conversations yet.", style = MaterialTheme.typography.bodyLarge)
            Text(
                "Adding a contact is not built in this client yet — the desktop client " +
                    "has it. This build can open an identity and show what it holds.",
                style = MaterialTheme.typography.bodyMedium,
                color = LocalPouchColors.current.mute,
                modifier = Modifier.padding(top = Space.x2),
            )
        }
        return
    }

    LazyColumn(modifier = Modifier.fillMaxSize()) {
        items(conversations, key = { it.id }) { conversation ->
            Column(modifier = Modifier.padding(Space.x4)) {
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
        }
    }
}
