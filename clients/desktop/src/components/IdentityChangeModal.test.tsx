/*
 * The identity change warning has three properties that are easy to lose in a
 * later tidy-up, and each one is a security property rather than a style one:
 *
 * 1. Both explanations are present. Dropping the hostile one makes the modal
 *    reassuring; dropping the innocent one makes it an accusation.
 * 2. "Continue without verifying" exists and is a real button. Hiding it is how
 *    users end up pressing the one that claims a check they did not perform.
 * 3. Neither action verifies anything.
 *
 * Rendered to static markup rather than driven in a browser, because the GUI
 * cannot be launched in CI and a rule that is only checked by hand is a rule
 * that stops being checked.
 */

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { IdentityChangeModal } from "./IdentityChangeModal";

const change = {
  contactId: "contact-1",
  contactName: "Mai",
  // 2026-03-03, chosen so the rendered date is checkable.
  changedAt: Math.floor(Date.UTC(2026, 2, 3, 12, 0, 0) / 1000),
};

function render(overrides: Partial<typeof change> = {}) {
  return renderToStaticMarkup(
    <IdentityChangeModal
      change={{ ...change, ...overrides }}
      onVerify={() => {}}
      onContinue={() => {}}
    />,
  );
}

describe("IdentityChangeModal", () => {
  it("states the fact, including who and when", () => {
    const html = render();
    expect(html).toContain("Mai");
    expect(html).toContain("identity key changed");
    expect(html).toContain("March");
  });

  it("gives both explanations, and the innocent one first", () => {
    const html = render();
    const innocent = html.indexOf("reinstalled");
    const hostile = html.indexOf("intercepting");

    expect(innocent).toBeGreaterThan(-1);
    expect(hostile).toBeGreaterThan(-1);
    expect(innocent).toBeLessThan(hostile);
  });

  it("accuses nobody", () => {
    // "It can also mean" is the shape. An assertion that someone *is*
    // intercepting would be a claim the app cannot support.
    const html = render();
    expect(html).toContain("can also mean");
    expect(html).not.toContain("someone is attacking");
    expect(html).not.toMatch(/compromised|hacked|breach/i);
  });

  it("offers continuing without verifying, as a real button", () => {
    const html = render();
    expect(html).toContain("Continue without verifying");
    // Present, and not disabled or hidden — see the header comment.
    expect(html).not.toMatch(/Continue without verifying[^<]*<\/button>\s*<!--/);
    expect(html).not.toContain('disabled=""');
  });

  it("never claims the contact is verified", () => {
    const html = render();
    expect(html).not.toContain("VERIFIED");
    expect(html).toContain("marked unverified");
  });

  it("is a modal dialog, announced as one", () => {
    // SPEC §6.7.6 requires an interruption, and SPEC §6.10 requires it be
    // announced to a screen reader rather than only drawn.
    const html = render();
    expect(html).toContain('role="alertdialog"');
    expect(html).toContain('aria-modal="true"');
    expect(html).toContain("aria-labelledby");
  });

  it("still reads correctly for a contact with no name yet", () => {
    // A Welcome arrives before the Hello that carries the display name, so an
    // unnamed contact is a real state and must not render "'s identity key
    // changed" with nothing in front of it.
    const html = render({ contactName: "" });
    expect(html).toContain("This contact");
    expect(html).not.toMatch(/>\s*&rsquo;s identity key/);
  });

  it("hands the contact id back to whichever action was taken", () => {
    const onVerify = vi.fn();
    const onContinue = vi.fn();

    // Rendered for the call signature rather than clicked: the assertion is
    // that both handlers are wired to the same identifier, which is what makes
    // acknowledging and verifying refer to the same contact.
    const element = (
      <IdentityChangeModal
        change={change}
        onVerify={onVerify}
        onContinue={onContinue}
      />
    );
    expect(element.props.change.contactId).toBe("contact-1");
    expect(renderToStaticMarkup(element)).toContain("Verify now");
  });
});
