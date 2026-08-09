package com.pouch.core

import android.content.Context

/**
 * Which relay this install talks to.
 *
 * ## Why this exists on Android and not on desktop
 *
 * D-049 made the relay address deployment configuration read from the
 * environment, and said plainly that nothing the UI can write should reach it:
 * a client that can be pointed at an arbitrary relay from its own interface is
 * a client that can be *talked into* being pointed there.
 *
 * That boundary costs nothing on desktop, where a shell exists and
 * `POUCH_RELAY` can be set before launch. **Android has no shell and no
 * per-app environment.** Holding the same line here would mean a separate APK
 * build per relay, which in practice means people sideload a pre-configured APK
 * from whoever set it up — so the address *and* the binary become someone
 * else's choice. That is strictly worse than the risk D-049 was guarding
 * against (D-051).
 *
 * So the address is settable here, and the screen that sets it says what it
 * costs rather than presenting it as a neutral field.
 *
 * ## What is and is not at stake
 *
 * Pointing at a hostile relay does **not** expose message content. The relay
 * never holds a key and the server-blindness test asserts it. What it does hand
 * that operator is the inbox identifiers and connection timing
 * `THREAT_MODEL.md` §5 already lists as visible to whichever relay is in use,
 * and — if the address is simply wrong — silent non-delivery.
 *
 * Stored in plain SharedPreferences deliberately. This is an address, not a
 * secret; encrypting it would imply it needed protecting and would put a second
 * key next to the one that actually matters.
 */
object RelaySetting {

    private const val PREFS = "pouch.relay"
    private const val KEY_URL = "url"
    private const val KEY_ONION = "onion"

    /**
     * The compiled-in fallback, used until someone sets an address.
     *
     * `BuildConfig.RELAY_URL` defaults to the emulator's route to the host
     * loopback, which is right for development and unreachable from a real
     * phone. A handset that has not been pointed anywhere will therefore queue
     * everything locally rather than appear to send — which is the honest
     * outcome, and is why [isConfigured] exists for the UI to check.
     */
    fun default(): String = com.pouch.BuildConfig.RELAY_URL

    /** The address in use, which is [default] until one is stored. */
    fun current(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_URL, null)
            ?.takeIf { it.isNotBlank() }
            ?: default()

    /** Whether the user has actually chosen, rather than inheriting the build's default. */
    fun isConfigured(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_URL, null)
            ?.isNotBlank() == true

    /**
     * The relay's onion address, or empty if none has been set.
     *
     * Empty means the Tor route is unavailable on this install and the
     * transport screen says so, rather than offering a choice that cannot be
     * made. The core treats a non-`.onion` value as no Tor at all.
     */
    fun onionHost(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_ONION, null)
            ?.trim()
            .orEmpty()

    /**
     * Stores an address. Takes effect on next launch, never mid-session.
     *
     * The core reads its relay once, when the bridge starts, and holds it for
     * the process lifetime. Re-pointing a live session would mean some messages
     * in one conversation went to one relay and some to another, with the
     * Custody Strip unable to say which — so the app closes instead and the
     * caller tells the user that is what will happen.
     *
     * `commit` rather than `apply`, deliberately: the caller's next act is to
     * restart the process, and `apply` writes asynchronously. A setting that
     * loses the race is a user who restarts and finds nothing changed.
     *
     * @throws IllegalArgumentException if the address is not one the core will accept.
     */
    fun set(context: Context, url: String, onionHost: String = "") {
        val checked = validate(url, onionHost)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_URL, checked.relayUrl)
            .putString(KEY_ONION, checked.onionHost)
            .commit()
    }
}

/** A pair of addresses that have passed [validate]. */
data class RelayAddresses(val relayUrl: String, val onionHost: String)

/**
 * Checks and normalises a pair of addresses, without touching storage.
 *
 * Separate from [RelaySetting.set] so it is a plain JVM test rather than an
 * instrumented one — the same split `CustodyStrip` uses. What is tested here is
 * the rule that a non-onion value in the onion field is refused, and that
 * matters more than it looks: accepting one would produce a route the app calls
 * Tor over a connection that never entered the Tor network, which is the
 * reassuring-but-false readout SPEC §1 forbids outright.
 *
 * @throws IllegalArgumentException with wording meant to be shown to the user.
 */
fun validate(url: String, onionHost: String): RelayAddresses {
    val cleaned = url.trim().removeSuffix("/")
    require(cleaned.isNotBlank()) { "Enter a relay address." }
    require(cleaned.startsWith("http://") || cleaned.startsWith("https://")) {
        "A relay address starts with http:// or https://"
    }
    require(cleaned.length > "http://".length + 1) { "That relay address is incomplete." }

    // Tolerated on the way in because people paste what they were sent, and a
    // scheme or a trailing slash on an onion host is a typo rather than a
    // different intent. The core wants the bare host.
    val onion = onionHost.trim()
        .removePrefix("http://")
        .removePrefix("https://")
        .removeSuffix("/")
    require(onion.isEmpty() || onion.endsWith(".onion")) {
        "An onion address ends in .onion, or leave it blank for no Tor route."
    }

    return RelayAddresses(relayUrl = cleaned, onionHost = onion)
}
