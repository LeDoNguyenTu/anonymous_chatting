package com.pouch.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The relay address rules, as tests.
 *
 * Plain JVM tests, no device: what is checked here is the validation, and that
 * is where this screen can accept something that produces a false claim later.
 *
 * D-051 allows the address to be set from the app on Android, because there is
 * no shell to set an environment variable in. The trade is that the app is now
 * the thing enforcing what the core used to be handed already-correct — so
 * these rules are the boundary, and they are tested rather than assumed.
 */
class RelaySettingTest {

    @Test
    fun `an onion address in the onion field is accepted and normalised`() {
        val result = validate(
            "http://192.168.1.10:8443/",
            "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion/",
        )

        // Trailing slash and scheme stripped: the core wants a bare host, and a
        // pasted address usually carries both.
        assertEquals("http://192.168.1.10:8443", result.relayUrl)
        assertEquals(
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion",
            result.onionHost,
        )
    }

    @Test
    fun `a relay address without a scheme is refused`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            validate("192.168.1.10:8443", "")
        }
        assertTrue(error.message!!.contains("http://"))
    }

    @Test
    fun `a blank relay address is refused`() {
        assertThrows(IllegalArgumentException::class.java) { validate("   ", "") }
    }

    /**
     * The one that matters most.
     *
     * Someone pasting their direct relay URL into the onion field would
     * otherwise get a build that reports the Tor route while connecting
     * straight to the relay. The Custody Strip would read TOR over a
     * connection that never entered the Tor network — a reassuring indicator
     * over an untrue state, which SPEC §1 forbids.
     */
    @Test
    fun `a non-onion value in the onion field is refused rather than ignored`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            validate("http://127.0.0.1:8443", "relay.example.com")
        }
        assertTrue(error.message!!.contains(".onion"))

        assertThrows(IllegalArgumentException::class.java) {
            validate("http://127.0.0.1:8443", "http://192.168.1.10:8443")
        }
    }

    @Test
    fun `an empty onion field is allowed and means no Tor route`() {
        assertEquals("", validate("http://127.0.0.1:8443", "").onionHost)
        assertEquals("", validate("http://127.0.0.1:8443", "   ").onionHost)
    }
}
