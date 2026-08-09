/*
 * The Hosting screen's contract is that a relay address it shows is one that is
 * currently being served (Prime Directive 3).
 *
 * That matters more than it sounds. The address is the one thing on this screen
 * a user copies and hands to another person. A stale one — left on screen after
 * the relay stopped, or shown while Tor is still publishing — sends that person
 * to something that is not listening, and the resulting silence looks like being
 * ignored rather than like a bug. So the rule is asserted rather than trusted:
 * no `running: false` state may render an address, whatever else the status
 * carries.
 *
 * The view is pure, so these render without a window.
 */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { RelayHostingView } from "./RelayHosting";
import type { LocalRelayStatus } from "../lib/bridge";

const ADDRESS =
  "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion";

function render(status: LocalRelayStatus | null, error: string | null = null) {
  return renderToStaticMarkup(
    <RelayHostingView
      status={status}
      busy={false}
      error={error}
      onStart={() => undefined}
      onStop={() => undefined}
      onCopy={() => undefined}
      onBack={() => undefined}
    />,
  );
}

const RUNNING: LocalRelayStatus = {
  running: true,
  onionAddress: ADDRESS,
  bindAddress: "127.0.0.1:8443",
  error: null,
};

describe("RelayHostingView", () => {
  it("shows the address when a relay is actually serving it", () => {
    expect(render(RUNNING)).toContain(ADDRESS);
  });

  it("does not show an address while the relay is still publishing one", () => {
    const html = render({ ...RUNNING, onionAddress: null });
    expect(html).not.toContain(".onion");
    // The distinction the user needs: starting is not the same as broken.
    expect(html).toContain("Starting");
  });

  /*
   * The one that matters. A stopped relay carrying a leftover address in its
   * status must not render it — this is the case where a user would copy an
   * address that goes nowhere.
   */
  it("never shows an address once the relay has stopped", () => {
    const html = render({ ...RUNNING, running: false });
    expect(html).not.toContain(ADDRESS);
    expect(html).not.toContain("Copy address");
  });

  it("says nothing is hosted before anything has been started", () => {
    const html = render(null);
    expect(html).not.toContain(".onion");
    expect(html).toContain("Start hosting");
  });

  it("surfaces the reason a relay died rather than only that it is stopped", () => {
    const html = render({
      running: false,
      onionAddress: null,
      bindAddress: null,
      error: "the bundled relay exited with status 1",
    });
    expect(html).toContain("the bundled relay exited with status 1");
  });

  /*
   * The honesty rule about durability. This relay is a desktop process, not a
   * server: a message sent while the machine is off is not delivered. Somebody
   * who assumed otherwise would use this as their only inbox and quietly lose
   * messages, so the screen has to say it where hosting is offered rather than
   * in a document nobody opens.
   */
  it("states that closing Pouch stops delivery", () => {
    const html = render(null);
    expect(html).toContain("not delivered");
  });

  it("does not claim stopping erases what the relay holds", () => {
    expect(render(RUNNING)).toContain("Stopping does not erase");
  });

  /*
   * A relay is trusted for availability and nothing else, and the screen should
   * not imply the person hosting can read anything. The core claim is stated
   * positively; these words would undo it.
   */
  it("makes no reassuring claim about the relay's strength", () => {
    const html = render(RUNNING).toLowerCase();
    for (const word of [
      "unbreakable",
      "uncrackable",
      "military grade",
      "military-grade",
      "completely secure",
      "totally anonymous",
    ]) {
      expect(html).not.toContain(word);
    }
  });
});
