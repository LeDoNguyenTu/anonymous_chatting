/*
 * The bridge's job at the boundary is to narrow untrusted strings into the
 * labels the interface renders. The rule under test is the direction it fails
 * in: an unrecognised value must resolve to the *cautious* state, never the
 * reassuring one.
 *
 * This is a small function and an easy thing to "simplify" into a cast. These
 * tests are here to make that a build failure.
 */

import { describe, expect, it, vi } from "vitest";
import { asIdentityLabel, asTransportLabel, tauriBridge } from "./bridge";

describe("asIdentityLabel", () => {
  it("passes through the labels the core actually emits", () => {
    expect(asIdentityLabel("VERIFIED")).toBe("VERIFIED");
    expect(asIdentityLabel("UNVERIFIED")).toBe("UNVERIFIED");
    expect(asIdentityLabel("KEY CHANGED")).toBe("KEY CHANGED");
  });

  it("resolves anything it does not recognise to UNVERIFIED", () => {
    // If the two sides ever disagree about the vocabulary, the interface must
    // fail towards amber. Showing VERIFIED for a state it cannot interpret is
    // precisely what Prime Directive 3 forbids.
    for (const value of ["", "verified", "TRUSTED", "ok", "null", "🔒"]) {
      expect(asIdentityLabel(value)).toBe("UNVERIFIED");
    }
  });
});

describe("asTransportLabel", () => {
  it("passes through the labels the core actually emits", () => {
    expect(asTransportLabel("TOR")).toBe("TOR");
    expect(asTransportLabel("DIRECT")).toBe("DIRECT");
    expect(asTransportLabel("OFFLINE")).toBe("OFFLINE");
  });

  it("never invents a Tor circuit it cannot confirm", () => {
    // Claiming an onion route that is not there is a lie about where the
    // message went, and the manifest accuracy rule (SPEC §8.6) applies to the
    // Custody Strip for the same reason.
    for (const value of ["", "tor", "ONION", "SECURE", "unknown"]) {
      expect(asTransportLabel(value)).toBe("OFFLINE");
    }
  });
});

describe("tauriBridge", () => {
  it("converts the wire's snake_case into one naming convention", async () => {
    const invoke = vi.fn().mockResolvedValue([
      {
        id: "conv-1",
        contact_id: "contact-1",
        contact_name: "Mai",
        identity: "UNVERIFIED",
        last_message: "hello",
      },
    ]);

    const [conversation] = await tauriBridge(invoke).conversations();

    expect(conversation).toEqual({
      id: "conv-1",
      contactId: "contact-1",
      contactName: "Mai",
      identity: "UNVERIFIED",
      lastMessage: "hello",
    });
  });

  it("narrows an unknown identity from the wire rather than trusting it", async () => {
    const invoke = vi.fn().mockResolvedValue([
      {
        id: "c",
        contact_id: "c",
        contact_name: "Mallory",
        identity: "TOTALLY-FINE",
        last_message: null,
      },
    ]);

    const conversations = await tauriBridge(invoke).conversations();
    expect(conversations).toHaveLength(1);
    expect(conversations[0]?.identity).toBe("UNVERIFIED");
  });

  it("carries the relay-visibility leak block through unchanged", async () => {
    const invoke = vi.fn().mockResolvedValue({
      inbox_id: "7f3ac219",
      blob_size: 1024,
      visible: ["the inbox this was filed under"],
      not_visible: ["message content"],
      still_inferable: ["that you connected", "roughly when"],
    });

    const v = await tauriBridge(invoke).relayVisibility(1024);

    expect(v.stillInferable).toEqual(["that you connected", "roughly when"]);
    expect(v.notVisible).toEqual(["message content"]);
  });

  it("exposes no way to call an arbitrary command", () => {
    const bridge = tauriBridge(vi.fn());
    // The bridge is the readable answer to "what can the interface do". A
    // passthrough would make that answer "anything", and would let a screen
    // reach past `Pouch` (D-012).
    const names = Object.keys(bridge);
    for (const escape of ["invoke", "call", "raw", "command", "exec"]) {
      expect(names).not.toContain(escape);
    }
  });
});
