/*
 * The Custody Strip's contract is behavioural, not visual, so it is tested
 * rather than eyeballed.
 *
 * The rule under test: it must never show a reassuring state when the
 * underlying state is uncertain (SPEC §6.4, Prime Directive 3). That rule is
 * the kind that erodes quietly — someone adds a default, or a fallback, and
 * unverified starts rendering as verified for a subset of cases nobody looks
 * at. These assertions make that a build failure.
 */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  CustodyStrip,
  type IdentityState,
  type RetentionState,
  type TransportState,
} from "./CustodyStrip";

function render(
  identity: IdentityState,
  transport: TransportState = "direct",
  retention: RetentionState = "keep",
) {
  return renderToStaticMarkup(
    <CustodyStrip
      identity={identity}
      transport={transport}
      retention={retention}
    />,
  );
}

describe("CustodyStrip", () => {
  it("shows all three facts at once, always", () => {
    const html = render("verified", "tor", "7-day");
    expect(html).toContain("VERIFIED");
    expect(html).toContain("TOR");
    expect(html).toContain("7-DAY");
  });

  it("renders unverified identity as pending, never as verified", () => {
    const html = render("unverified");
    expect(html).toContain("UNVERIFIED");
    expect(html).toContain("custody-field--pending");
    expect(html).not.toContain("custody-field--verified");
  });

  it("renders a key change with the alarm tone", () => {
    const html = render("key-changed");
    expect(html).toContain("KEY CHANGED");
    expect(html).toContain("custody-field--alarm");
  });

  it("reserves the alarm tone for key changes alone", () => {
    // --seal is semantic and rare. If it starts appearing on ordinary states it
    // stops meaning "your trust assumption changed".
    for (const identity of ["verified", "unverified"] as const) {
      for (const transport of ["tor", "direct", "offline"] as const) {
        for (const retention of ["keep", "30-day", "7-day", "24-hour"] as const) {
          expect(render(identity, transport, retention)).not.toContain(
            "custody-field--alarm",
          );
        }
      }
    }
  });

  it("does not describe direct transport as private", () => {
    // Direct transport exposes the client IP to the relay. The copy has to say
    // so rather than reassure.
    const html = render("verified", "direct");
    expect(html).toContain("DIRECT");
    expect(html).toContain("custody-field--pending");
    expect(html).toMatch(/sees the IP address you connect from/);
  });

  it("pairs every state with a text label, never colour alone", () => {
    // DESIGN_SYSTEM.md §8. The tone class carries colour; the label carries
    // meaning. Every rendered field must have both.
    const html = render("key-changed", "offline", "24-hour");
    const tones = html.match(/custody-field--\w+/g) ?? [];
    const labels = html.match(/custody-field__label/g) ?? [];
    expect(tones).toHaveLength(3);
    expect(labels).toHaveLength(3);
  });

  it("gives every field an accessible name carrying the full explanation", () => {
    const html = render("unverified", "direct", "keep");
    expect(html).toMatch(/aria-label="identity: UNVERIFIED\./);
    expect(html).toMatch(/aria-label="transport: DIRECT\./);
    expect(html).toMatch(/aria-label="retention: KEEP\./);
  });

  it("uses no padlock, and no reassurance without a named mechanism", () => {
    const html = render("verified", "tor", "24-hour");
    expect(html.toLowerCase()).not.toContain("padlock");
    expect(html.toLowerCase()).not.toContain("🔒");
    // §2.4 terms must never reach a rendered string.
    expect(html.toLowerCase()).not.toMatch(
      /unbreakable|uncrackable|military.grade|100% secure/, // guardrail-allow: asserts these never render
    );
  });
});
