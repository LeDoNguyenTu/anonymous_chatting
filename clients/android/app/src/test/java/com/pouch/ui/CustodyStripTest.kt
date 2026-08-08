package com.pouch.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Custody Strip's honesty rules, as tests.
 *
 * These are plain JVM tests — no device, no emulator, no Compose runtime —
 * because what they check is the mapping from a core state to a rendered
 * claim, and that mapping is where this component can lie. Whether the dot is
 * eight density-independent pixels wide is not.
 */
class CustodyStripTest {

    @Test
    fun `an unrecognised identity is never rendered as verified`() {
        // The failure this prevents: the core gains a state, an older app does
        // not know it, and a map lookup falls through to something friendly.
        val field = identityField("SOMETHING_NEW")

        assertNotEquals(Tone.VERIFIED, field.tone)
        assertEquals("UNKNOWN", field.label)
        assertTrue(field.explanation.contains("unconfirmed"))
    }

    @Test
    fun `an unrecognised transport is never rendered as verified`() {
        val field = transportField("QUANTUM_TUNNEL")

        assertNotEquals(Tone.VERIFIED, field.tone)
        assertEquals("UNKNOWN", field.label)
    }

    @Test
    fun `an unrecognised retention policy is never rendered as verified`() {
        val field = retentionField("90d")

        assertNotEquals(Tone.VERIFIED, field.tone)
    }

    @Test
    fun `an empty state is treated as unknown rather than as a default`() {
        // A missing value must not select the first entry in a map, and must
        // not render as blank — a blank field reads as "nothing to report".
        for (field in listOf(identityField(""), transportField(""), retentionField(""))) {
            assertEquals("UNKNOWN", field.label)
            assertNotEquals(Tone.VERIFIED, field.tone)
            assertTrue(field.explanation.isNotBlank())
        }
    }

    @Test
    fun `unverified is amber, not neutral`() {
        // Amber because it is a real state the user can act on, not because it
        // is a mild failure. Rendering it as mute grey would let it read as
        // "fine, nothing to do here".
        assertEquals(Tone.PENDING, identityField("UNVERIFIED").tone)
    }

    @Test
    fun `a changed key is an alarm, not a warning`() {
        val field = identityField("KEY CHANGED")

        assertEquals(Tone.ALARM, field.tone)
        // The explanation must name the benign cause *and* the malicious one.
        // Naming only the benign one is a reassurance the app cannot support.
        assertTrue(field.explanation.contains("reinstalled"))
        assertTrue(field.explanation.contains("intercepting"))
    }

    @Test
    fun `the direct transport states what it exposes`() {
        val field = transportField("DIRECT")

        // Not marked as a failure — it is the default route — but it must say
        // the relay sees an IP address rather than leaving that to be assumed.
        assertTrue(field.explanation.contains("IP address"))
        assertNotEquals(Tone.VERIFIED, field.tone)
    }

    @Test
    fun `the tor transport does not overclaim`() {
        val field = transportField("TOR")

        // SPEC §2.3: state the limit alongside the protection. Tor hides the
        // IP from the relay; it does not hide Tor use from an ISP.
        assertTrue(field.explanation.contains("relay never learns your IP"))
        assertTrue(field.explanation.contains("internet provider"))
    }

    @Test
    fun `offline is muted rather than alarming`() {
        // Queued messages are not a security failure and must not look like
        // one — an alarm here would train the user to ignore the alarm colour.
        val field = transportField("OFFLINE")

        assertEquals(Tone.MUTE, field.tone)
        assertTrue(field.explanation.contains("queued"))
    }

    @Test
    fun `every known field carries a caption and an explanation`() {
        val known = listOf(
            identityField("VERIFIED"),
            identityField("UNVERIFIED"),
            identityField("KEY CHANGED"),
            transportField("TOR"),
            transportField("DIRECT"),
            transportField("OFFLINE"),
            retentionField("forever"),
            retentionField("30d"),
            retentionField("7d"),
            retentionField("24h"),
        )

        for (field in known) {
            assertTrue("label empty", field.label.isNotBlank())
            assertTrue("caption empty for ${field.label}", field.caption.isNotBlank())
            assertTrue("explanation empty for ${field.label}", field.explanation.isNotBlank())
        }
    }

    @Test
    fun `retention words match the ones the core sends`() {
        // The bridge sends the core's own vocabulary. If these keys drift, the
        // strip renders UNKNOWN for a perfectly ordinary policy — visible, but
        // wrong, and it would look like a bug in the core.
        for (word in listOf("forever", "30d", "7d", "24h")) {
            assertNotEquals(
                "retention '$word' is not recognised by the strip",
                "UNKNOWN",
                retentionField(word).label,
            )
        }
    }
}
