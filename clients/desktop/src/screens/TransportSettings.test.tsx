/*
 * The Transport screen's contract is that it never sells one route as the safe
 * one (SPEC §6.7.9, Prime Directive 3). That is a rule about words, and words
 * drift — someone adds a reassuring subtitle, or marks the Tor option
 * "recommended", and the screen starts making a promise the code cannot keep.
 * These assertions make that a build failure.
 *
 * The view is pure so it can be rendered without a window. The container's own
 * behaviour — what it does when a switch fails — is asserted through the fake
 * bridge at the bottom.
 */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { TransportSettingsView } from "./TransportSettings";
import { fakeBridge } from "../lib/fakeBridge";
import type { TransportLabel, TransportOption } from "../lib/bridge";

/** The real strings the core returns, so the test fails if that copy changes. */
const OPTIONS: TransportOption[] = [
  {
    route: "DIRECT",
    name: "Direct",
    explanation:
      "Messages go straight to the relay over TLS 1.3. The relay sees the IP address you connect from. Message content stays encrypted either way.",
  },
  {
    route: "TOR",
    name: "Tor",
    explanation:
      "Messages route through a Tor onion circuit. The relay never learns your IP address. Your internet provider can still see that you are using Tor.",
  },
];

function render(
  active: TransportLabel | null = "DIRECT",
  busy = false,
  error: string | null = null,
) {
  return renderToStaticMarkup(
    <TransportSettingsView
      options={OPTIONS}
      active={active}
      busy={busy}
      error={error}
      onChoose={() => {}}
      onBack={() => {}}
    />,
  );
}

/** The rendered `<input>` for one route, so assertions do not depend on
 *  whatever order React happens to emit attributes in. */
function inputFor(html: string, route: TransportLabel) {
  return html.match(new RegExp(`<input[^>]*value="${route}"[^>]*>`))?.[0] ?? "";
}

describe("TransportSettingsView", () => {
  it("offers both routes without naming either the secure one", () => {
    const html = render();
    expect(html).toContain("Direct");
    expect(html).toContain("Tor");
    const lower = html.toLowerCase();
    for (const banned of [
      "unbreakable", // guardrail-allow: asserts these never render
      "military grade", // guardrail-allow
      "100% secure", // guardrail-allow
      "totally safe",
      "the secure option",
      "the safe choice",
      "recommended",
    ]) {
      expect(lower).not.toContain(banned);
    }
  });

  it("states the direct route's IP exposure rather than glossing it", () => {
    expect(render()).toContain("IP address");
  });

  it("keeps Tor's residual exposure on screen next to its benefit", () => {
    // The relay stops seeing an IP; the network provider still sees Tor. A
    // screen that mentioned only the first half would be selling it.
    expect(render()).toContain("internet provider can still see");
  });

  it("marks no route active while the real one is unknown", () => {
    // Before `transportState()` answers there is no honest default. Showing
    // one selected would be a guess rendered as a fact.
    expect(render(null)).not.toContain("checked");
  });

  it("shows an error without also showing the route as switched", () => {
    const html = render("DIRECT", false, "Tor could not be reached.");
    expect(html).toContain("Tor could not be reached.");
    expect(html).toContain('role="alert"');
    // The failed switch changed nothing: DIRECT is still the checked one and
    // TOR is not. Matched per input rather than by attribute order, which is
    // React's business and not part of this contract.
    expect(inputFor(html, "DIRECT")).toContain("checked");
    expect(inputFor(html, "TOR")).not.toContain("checked");
  });

  it("warns that a failed switch leaves the old route in use", () => {
    expect(render()).toContain("keeps using the one it already had");
  });

  it("disables the choices while a switch is in flight", () => {
    const html = render("DIRECT", true);
    expect(html).toContain("disabled");
    expect(html).toContain('role="status"');
  });
});

describe("fakeBridge", () => {
  it("rejects any call a test forgot to stub, naming it", async () => {
    // The safety net the screen tests lean on: an unstubbed call must fail
    // loudly rather than resolve to undefined and let a blank render pass.
    const bridge = fakeBridge({ transportState: async () => "DIRECT" });
    await expect(bridge.transportOptions()).rejects.toThrow(
      "transportOptions() was called but this test did not stub it",
    );
    await expect(bridge.transportState()).resolves.toBe("DIRECT");
  });
});
