package com.pouch.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * What the Rust side threw.
 *
 * The message is the core's own error text, which SPEC §6.9 requires to say
 * what happened and what to do. Screens show it directly rather than
 * substituting wording of their own — a UI that rewrites an error is a UI that
 * can accidentally make a failure sound like a success.
 *
 * Named by `lib.rs` as the class it throws; renaming this without renaming it
 * there means every error arrives as a `RuntimeException` instead.
 */
class PouchException(message: String) : RuntimeException(message)

/**
 * The raw JNI boundary. Two functions, both blocking.
 *
 * Nothing outside this file should call these. [Pouch] is the typed facade,
 * and it is the one that guarantees calls happen off the main thread.
 */
internal object PouchNative {
    init {
        System.loadLibrary("pouch_jni")
    }

    external fun nativeStart(
        dbPath: String,
        torStateDir: String,
        relayUrl: String,
        onionHost: String,
    )

    external fun nativeCall(operation: String, argsJson: String): String
}

/**
 * Everything this app can ask the core to do.
 *
 * The Android analogue of the desktop client's `bridge.ts`, and deliberately
 * the same shape: one suspend function per operation, named for what it does,
 * with no general-purpose escape hatch. There is no `call(operation, args)`
 * here for a screen to reach for, because a bridge with a passthrough is a
 * bridge whose surface nobody can review.
 *
 * **Nothing below `Pouch` crosses this boundary** — no key, no cipher, no
 * storage handle, no raw ciphertext blob (D-012). The one exception is
 * [exportBackup], which returns the user's own recovery key because SPEC §7.3
 * puts it in their hands and nowhere else.
 *
 * ## Threads
 *
 * Every native call blocks — a Tor bootstrap can take tens of seconds, which
 * on the main thread is an ANR. Every function here is `suspend` and hops to
 * [Dispatchers.IO] itself, so a caller cannot get this wrong by forgetting.
 */
object Pouch {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    /**
     * Points the bridge at this device's storage. Call once, before anything
     * else.
     *
     * Paths come from the app's own private directory, which on Android is
     * already per-app and unreadable by other apps. That is not a substitute
     * for encrypting the database — a rooted device or an adb backup reads it
     * regardless, which is why SQLCipher is underneath.
     */
    suspend fun start(
        dbPath: String,
        torStateDir: String,
        relayUrl: String,
        onionHost: String,
    ) = withContext(Dispatchers.IO) {
        PouchNative.nativeStart(dbPath, torStateDir, relayUrl, onionHost)
    }

    /* -- identity --------------------------------------------------------- */

    suspend fun hasIdentity(): Boolean = call("has_identity")

    suspend fun needsPassphrase(): Boolean = call("needs_passphrase")

    suspend fun createIdentity(displayName: String, passphrase: String? = null) =
        callUnit("create_identity", CreateIdentityArgs(displayName, passphrase))

    suspend fun openIdentity(passphrase: String? = null) =
        callUnit("open_identity", OpenIdentityArgs(passphrase))

    suspend fun displayName(): String = call("display_name")

    suspend fun inviteCode(): String = call("invite_code")

    suspend fun identityLabels(): List<String> = call("identity_labels")

    /* -- contacts and conversations --------------------------------------- */

    suspend fun addContact(displayName: String, inviteCode: String): String =
        call("add_contact", AddContactArgs(displayName, inviteCode))

    suspend fun conversations(): List<Conversation> = call("conversations")

    suspend fun messages(conversationId: String): List<Message> =
        call("messages", ConversationArgs(conversationId))

    suspend fun safetyNumber(contactId: String): String =
        call("safety_number", ContactArgs(contactId))

    suspend fun verifyContact(contactId: String, verified: Boolean) =
        callUnit("verify_contact", VerifyContactArgs(contactId, verified))

    /* -- messaging -------------------------------------------------------- */

    suspend fun sendMessage(conversationId: String, body: String): SendResult =
        call("send_message", SendMessageArgs(conversationId, body))

    suspend fun receiveMessages(): List<Message> = call("receive_messages")

    suspend fun flushOutbox(): Int = call("flush_outbox")

    suspend fun queuedCount(): Int = call("queued_count")

    /* -- attachments ------------------------------------------------------ */

    suspend fun sendAttachment(
        conversationId: String,
        filename: String,
        content: ByteArray,
    ): SendResult =
        call("send_attachment", SendAttachmentArgs(conversationId, filename, content.toList()))

    suspend fun attachment(messageId: String): Attachment? =
        call("attachment", MessageArgs(messageId))

    /* -- transport -------------------------------------------------------- */

    suspend fun transportState(): String = call("transport_state")

    suspend fun transportOptions(): List<TransportOption> = call("transport_options")

    suspend fun connectTor() = callUnit("connect_tor")

    suspend fun useDirectRelay() = callUnit("use_direct_relay")

    /* -- what the user is told -------------------------------------------- */

    suspend fun securityDetails(): SecurityDetails = call("security_details")

    suspend fun relayVisibility(blobSize: Int): RelayVisibility =
        call("relay_visibility", RelayVisibilityArgs(blobSize))

    /* -- storage controls ------------------------------------------------- */

    suspend fun retentionPolicy(): String = call("retention_policy")

    suspend fun setRetentionPolicy(policy: String): Int =
        call("set_retention_policy", RetentionArgs(policy))

    suspend fun disappearingMessages(conversationId: String): Long? =
        call("disappearing_messages", ConversationArgs(conversationId))

    suspend fun setDisappearingMessages(conversationId: String, seconds: Long?) =
        callUnit("set_disappearing_messages", DisappearingArgs(conversationId, seconds))

    suspend fun identityChanges(): List<IdentityChange> = call("identity_changes")

    suspend fun acknowledgeIdentityChange(contactId: String) =
        callUnit("acknowledge_identity_change", ContactArgs(contactId))

    suspend fun isPassphraseProtected(): Boolean = call("is_passphrase_protected")

    suspend fun setPassphrase(passphrase: String) =
        callUnit("set_passphrase", PassphraseArgs(passphrase))

    suspend fun clearPassphrase() = callUnit("clear_passphrase")

    /* -- backup ----------------------------------------------------------- */

    suspend fun exportBackup(): ExportedBackup = call("export_backup")

    suspend fun importBackup(backup: ByteArray, recoveryKeyHex: String): ImportedBackup =
        call("import_backup", ImportBackupArgs(backup.toList(), recoveryKeyHex))

    /* -- destruction ------------------------------------------------------ */

    suspend fun wipeAll() = callUnit("wipe_all")

    /* -- the two functions everything above goes through ------------------ */

    private suspend inline fun <reified T> call(operation: String): T =
        decode(operation, invoke(operation, "{}"))

    private suspend inline fun <reified A, reified T> call(operation: String, args: A): T =
        decode(operation, invoke(operation, json.encodeToString(args)))

    private suspend fun callUnit(operation: String) {
        invoke(operation, "{}")
    }

    private suspend inline fun <reified A> callUnit(operation: String, args: A) {
        invoke(operation, json.encodeToString(args))
    }

    /**
     * The only place a native call is made.
     *
     * `PouchException` passes through untouched: it already carries the core's
     * own wording. Anything else — a `RuntimeException` from a missing
     * exception class, an `UnsatisfiedLinkError` from a missing .so — is
     * wrapped rather than swallowed, because a screen that receives no error
     * concludes the operation succeeded.
     */
    suspend fun invoke(operation: String, argsJson: String): String =
        withContext(Dispatchers.IO) {
            try {
                PouchNative.nativeCall(operation, argsJson)
            } catch (e: PouchException) {
                throw e
            } catch (e: Throwable) {
                throw PouchException(
                    "Pouch could not complete '$operation' on this device: ${e.message ?: e}",
                )
            }
        }

    /**
     * Decodes a result, or says which operation produced something unreadable.
     *
     * A decode failure here means the Rust and Kotlin views of a shape have
     * diverged, which is a build-time mistake showing up at runtime. Naming the
     * operation is the difference between a one-line fix and an afternoon.
     */
    private inline fun <reified T> decode(operation: String, payload: String): T =
        try {
            json.decodeFromString<T>(payload)
        } catch (e: Exception) {
            throw PouchException(
                "Pouch received a result for '$operation' that this app could not read. " +
                    "This build's app and core may not match.",
            )
        }
}
