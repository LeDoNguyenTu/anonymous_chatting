package com.pouch.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
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
import com.pouch.core.Pouch
import com.pouch.core.PouchException
import com.pouch.core.SecurityDetails
import com.pouch.core.TransportOption
import com.pouch.ui.theme.LocalPouchColors
import com.pouch.ui.theme.SecurityTextStyle
import com.pouch.ui.theme.Space
import kotlinx.coroutines.launch

/**
 * Screens 7, 9 and 12 — Privacy and storage, Transport, Security details.
 *
 * One scrolling screen on a phone rather than three, because three settings
 * screens on a handset is three taps to find one control. The section headings
 * keep the SPEC structure.
 *
 * ## Transport is a choice, not a recommendation
 *
 * Neither route is labelled "the secure one" (SPEC §6.7.9). Each option shows
 * the core's own [TransportOption.explanation], never wording invented here —
 * so the sentence describing what Tor costs cannot drift from the sentence the
 * desktop client shows for the same route.
 *
 * Switching to Tor is slow and can fail. When it fails the app says so and
 * stays on the route it was on; it never silently falls back, because falling
 * back would send over a route the user did not choose.
 */
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onStateChanged: () -> Unit,
    onChangeRelay: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val colors = LocalPouchColors.current

    var options by remember { mutableStateOf(emptyList<TransportOption>()) }
    var current by remember { mutableStateOf("") }
    var retention by remember { mutableStateOf("") }
    var details by remember { mutableStateOf<SecurityDetails?>(null) }
    var passphraseProtected by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var note by remember { mutableStateOf<String?>(null) }

    suspend fun reload() {
        options = Pouch.transportOptions()
        current = Pouch.transportState()
        retention = Pouch.retentionPolicy()
        details = Pouch.securityDetails()
        passphraseProtected = Pouch.isPassphraseProtected()
    }

    LaunchedEffect(Unit) {
        try {
            reload()
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
        Text("Settings", style = MaterialTheme.typography.titleLarge)

        error?.let {
            Text(text = it, color = colors.alarm, modifier = Modifier.padding(vertical = Space.x2))
        }
        note?.let {
            Text(text = it, color = colors.verified, modifier = Modifier.padding(vertical = Space.x2))
        }

        /* -- transport ----------------------------------------------------- */

        Text(
            "How messages travel",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = Space.x4),
        )

        Button(
            onClick = onChangeRelay,
            enabled = !busy,
            modifier = Modifier.padding(vertical = Space.x2),
        ) {
            Text("Change relay")
        }

        options.forEach { option ->
            val selected = current.equals(option.route, ignoreCase = true)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .selectable(
                        selected = selected,
                        enabled = !busy,
                        onClick = {
                            if (selected) return@selectable
                            busy = true
                            error = null
                            note = null
                            scope.launch {
                                try {
                                    if (option.route.equals("Tor", ignoreCase = true)) {
                                        note = "Connecting through Tor. This can take " +
                                            "tens of seconds."
                                        Pouch.connectTor()
                                    } else {
                                        Pouch.useDirectRelay()
                                    }
                                    note = null
                                    reload()
                                    onStateChanged()
                                } catch (e: PouchException) {
                                    // Deliberately not reverting the radio by
                                    // hand: reload() re-reads the route the core
                                    // is actually on, so a failed switch shows
                                    // the old route rather than the wanted one.
                                    note = null
                                    error = e.message
                                    runCatching { reload() }
                                } finally {
                                    busy = false
                                }
                            }
                        },
                    )
                    .padding(vertical = Space.x2),
                verticalAlignment = Alignment.Top,
            ) {
                RadioButton(selected = selected, onClick = null, enabled = !busy)
                Column(modifier = Modifier.padding(start = Space.x2)) {
                    Text(option.name, style = MaterialTheme.typography.bodyLarge)
                    Text(
                        option.explanation,
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.mute,
                    )
                }
            }
        }

        HorizontalDivider(modifier = Modifier.padding(vertical = Space.x4))

        /* -- retention ----------------------------------------------------- */

        Text("Keep messages", style = MaterialTheme.typography.titleMedium)

        listOf(
            "forever" to "Until you delete them.",
            "30d" to "Erased after 30 days.",
            "7d" to "Erased after 7 days.",
            "24h" to "Erased after 24 hours.",
        ).forEach { (policy, consequence) ->
            val selected = retention == policy
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .selectable(
                        selected = selected,
                        enabled = !busy,
                        onClick = {
                            if (selected) return@selectable
                            busy = true
                            error = null
                            scope.launch {
                                try {
                                    val erased = Pouch.setRetentionPolicy(policy)
                                    note = if (erased > 0) {
                                        "$erased message${if (erased == 1) "" else "s"} erased."
                                    } else {
                                        null
                                    }
                                    reload()
                                    onStateChanged()
                                } catch (e: PouchException) {
                                    error = e.message
                                } finally {
                                    busy = false
                                }
                            }
                        },
                    )
                    .padding(vertical = Space.x2),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = selected, onClick = null, enabled = !busy)
                Column(modifier = Modifier.padding(start = Space.x2)) {
                    Text(
                        retentionField(policy).label,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Text(consequence, style = MaterialTheme.typography.bodySmall, color = colors.mute)
                }
            }
        }

        Text(
            text = "Shortening this erases messages already past the new limit, " +
                "immediately and permanently.",
            style = MaterialTheme.typography.bodySmall,
            color = colors.pending,
            modifier = Modifier.padding(top = Space.x2),
        )

        HorizontalDivider(modifier = Modifier.padding(vertical = Space.x4))

        /* -- device protection --------------------------------------------- */

        Text("This device", style = MaterialTheme.typography.titleMedium)
        Text(
            text = if (passphraseProtected) {
                "Protected by a passphrase. The database key is derived from it " +
                    "with Argon2id and is not stored anywhere."
            } else {
                "No passphrase set. The database key is a file next to the " +
                    "database, so anyone who can read this device's storage can " +
                    "open it. Setting a passphrase is the only real protection " +
                    "against a lost or rooted phone."
            },
            style = MaterialTheme.typography.bodyMedium,
            color = if (passphraseProtected) colors.verified else colors.pending,
            modifier = Modifier.padding(vertical = Space.x2),
        )

        HorizontalDivider(modifier = Modifier.padding(vertical = Space.x4))

        /* -- security details ---------------------------------------------- */

        Text("What is protecting this", style = MaterialTheme.typography.titleMedium)

        details?.let { d ->
            Surface(
                color = colors.sunken,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = Space.x2),
            ) {
                Column(modifier = Modifier.padding(Space.x3)) {
                    listOf(
                        "protocol" to d.protocol,
                        "ciphersuite" to d.ciphersuite,
                        "aead" to d.aead,
                        "key agreement" to d.keyAgreement,
                        "signature" to d.signature,
                        "kdf" to d.kdf,
                        "local database" to d.localDatabase,
                        "passphrase" to d.passphraseDerivation,
                        "transport" to d.transport,
                        "relay" to d.relayAddress,
                        "openmls" to d.openmlsVersion,
                        "app version" to d.appVersion,
                    ).forEach { (label, value) ->
                        Text(
                            text = "%-16s %s".format(label, value),
                            style = SecurityTextStyle,
                            fontFamily = FontFamily.Monospace,
                            color = colors.mute,
                        )
                    }
                }
            }
        }

        Text(
            text = "Unaudited student software. No cryptographer has reviewed it.",
            style = MaterialTheme.typography.bodySmall,
            color = colors.pending,
            modifier = Modifier.padding(vertical = Space.x2),
        )

        Text(
            text = "Backup export, backup import and wipe-all are not on this " +
                "screen yet. They exist in the core and on the desktop client; " +
                "this build does not reach them from the phone.",
            style = MaterialTheme.typography.bodySmall,
            color = colors.mute,
            modifier = Modifier.padding(top = Space.x3),
        )

        Button(onClick = onBack, modifier = Modifier.padding(top = Space.x4), enabled = !busy) {
            Text("Back")
        }
    }
}
