package com.pouch.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/*
 * The Kotlin side of `pouch_core::views`.
 *
 * Every type here mirrors one in core/src/views.rs, field for field. They are
 * hand-written rather than generated, which is a real risk: the two can drift,
 * and what drifts is security state — a field added in Rust and missed here
 * renders as a blank on a screen whose whole job is to say what is protecting
 * the user.
 *
 * Two things reduce that risk to something reviewable. `ignoreUnknownKeys` is
 * *on*, so a new Rust field does not crash an older app; and the JNI crate's
 * own tests assert that every field of the security details view arrives
 * non-empty, so a rename on the Rust side fails in `cargo test` rather than on
 * a phone. Neither catches a field that Kotlin simply never learned about, so
 * changing a view means changing this file in the same commit.
 *
 * @SerialName is on every field because Rust writes snake_case and Kotlin
 * reads camelCase. Spelled out per field rather than configured globally: a
 * global naming strategy is invisible at the point where it goes wrong.
 */

/** A conversation, as a list row shows it. */
@Serializable
data class Conversation(
    val id: String,
    @SerialName("contact_id") val contactId: String,
    @SerialName("contact_name") val contactName: String,
    /** `VERIFIED` / `UNVERIFIED` / `KEY CHANGED` — the Custody Strip label. */
    val identity: String,
    @SerialName("last_message") val lastMessage: String? = null,
)

/** One message. */
@Serializable
data class Message(
    val id: String,
    val outgoing: Boolean,
    val body: String,
    val at: Long,
)

/** One row of a message manifest (SPEC §6.5). */
@Serializable
data class ManifestRow(
    val number: Int,
    val label: String,
    val detail: String,
    /** False means the stage did not run. It is still shown. */
    val ran: Boolean,
)

/** What a send actually did. */
@Serializable
data class SendResult(
    val summary: String,
    val rows: List<ManifestRow>,
    val failed: Boolean,
)

/** What the relay could see about a message (SPEC §6.5.4). */
@Serializable
data class RelayVisibility(
    @SerialName("inbox_id") val inboxId: String,
    @SerialName("blob_size") val blobSize: Int,
    val visible: List<String>,
    @SerialName("not_visible") val notVisible: List<String>,
    @SerialName("still_inferable") val stillInferable: List<String>,
)

/** Every mechanism in use (SPEC §6.7.5). */
@Serializable
data class SecurityDetails(
    val ciphersuite: String,
    val aead: String,
    @SerialName("key_agreement") val keyAgreement: String,
    val signature: String,
    val kdf: String,
    val protocol: String,
    @SerialName("local_database") val localDatabase: String,
    @SerialName("passphrase_derivation") val passphraseDerivation: String,
    /** The transport in use right now, not the one available. */
    val transport: String,
    @SerialName("relay_address") val relayAddress: String,
    @SerialName("openmls_version") val openmlsVersion: String,
    @SerialName("app_version") val appVersion: String,
)

/** A contact's identity key having changed (SPEC §6.7.6). */
@Serializable
data class IdentityChange(
    @SerialName("contact_id") val contactId: String,
    @SerialName("contact_name") val contactName: String,
    @SerialName("changed_at") val changedAt: Long,
)

/** One transport the user can choose (SPEC §6.7.9). */
@Serializable
data class TransportOption(
    val route: String,
    val name: String,
    val explanation: String,
)

/** A decrypted attachment on its way to the screen. */
@Serializable
data class Attachment(
    val filename: String,
    val content: List<Byte>,
) {
    fun bytes(): ByteArray = content.toByteArray()
}

/**
 * A freshly exported backup.
 *
 * [recoveryKeyHex] is the one piece of key material that crosses this
 * boundary, and it does so because SPEC §7.3 puts it in the user's hands and
 * nowhere else. Nothing in this project stores it. A screen showing it must
 * not write it anywhere either.
 */
@Serializable
data class ExportedBackup(
    @SerialName("recovery_key_hex") val recoveryKeyHex: String,
    val backup: List<Byte>,
    @SerialName("file_name") val fileName: String,
) {
    fun bytes(): ByteArray = backup.toByteArray()
}

/** What an import reports once a restore succeeds. */
@Serializable
data class ImportedBackup(
    @SerialName("display_name") val displayName: String,
    @SerialName("conversation_count") val conversationCount: Int,
)

/* -- argument payloads ----------------------------------------------------- */

@Serializable
internal data class ConversationArgs(@SerialName("conversation_id") val conversationId: String)

@Serializable
internal data class ContactArgs(@SerialName("contact_id") val contactId: String)

@Serializable
internal data class MessageArgs(@SerialName("message_id") val messageId: String)

@Serializable
internal data class CreateIdentityArgs(
    @SerialName("display_name") val displayName: String,
    val passphrase: String? = null,
)

@Serializable
internal data class OpenIdentityArgs(val passphrase: String? = null)

@Serializable
internal data class AddContactArgs(
    @SerialName("display_name") val displayName: String,
    @SerialName("invite_code") val inviteCode: String,
)

@Serializable
internal data class SendMessageArgs(
    @SerialName("conversation_id") val conversationId: String,
    val body: String,
)

@Serializable
internal data class VerifyContactArgs(
    @SerialName("contact_id") val contactId: String,
    val verified: Boolean,
)

@Serializable
internal data class RelayVisibilityArgs(@SerialName("blob_size") val blobSize: Int)

@Serializable
internal data class RetentionArgs(val policy: String)

@Serializable
internal data class DisappearingArgs(
    @SerialName("conversation_id") val conversationId: String,
    val seconds: Long? = null,
)

@Serializable
internal data class SendAttachmentArgs(
    @SerialName("conversation_id") val conversationId: String,
    val filename: String,
    val content: List<Byte>,
)

@Serializable
internal data class ImportBackupArgs(
    val backup: List<Byte>,
    @SerialName("recovery_key_hex") val recoveryKeyHex: String,
)

@Serializable
internal data class PassphraseArgs(val passphrase: String)
