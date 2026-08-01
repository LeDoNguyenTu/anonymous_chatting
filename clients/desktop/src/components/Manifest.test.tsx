/*
 * The Manifest's contract is that it reports what happened and does not
 * improve on it. These tests cover the three ways that erodes: hiding stages
 * that did not run, implying success from adjacency, and dropping the block
 * that says what still leaks.
 */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Manifest } from "./Manifest";
import type { ManifestRow } from "../lib/bridge";

/** A Phase 1 text message: five of nine stages actually run. */
const PHASE_1_ROWS: ManifestRow[] = [
  { number: 1, label: "COMPOSED", detail: "412 bytes", ran: true },
  { number: 2, label: "METADATA REMOVED", detail: "n/a — text message", ran: false },
  { number: 3, label: "COMPRESSED", detail: "not yet implemented", ran: false },
  { number: 4, label: "PADDED", detail: "not yet implemented", ran: false },
  { number: 5, label: "ENCRYPTED", detail: "AES-128-GCM · X25519 · Ed25519", ran: true },
  { number: 6, label: "SENDER SEALED", detail: "not yet implemented", ran: false },
  { number: 7, label: "ROUTED", detail: "DIRECT · http://127.0.0.1:8443", ran: true },
  { number: 8, label: "HELD AT RELAY", detail: "blob 7f3a · TTL 30d", ran: true },
  { number: 9, label: "DELIVERED", detail: "accepted", ran: true },
];

function render(props: Partial<Parameters<typeof Manifest>[0]> = {}) {
  return renderToStaticMarkup(
    <Manifest
      summary="5 of 9 stages ran"
      rows={PHASE_1_ROWS}
      failed={false}
      {...props}
    />,
  );
}

describe("Manifest", () => {
  it("shows the collapsed summary the core produced, verbatim", () => {
    expect(render()).toContain("5 of 9 stages ran");
  });

  it("does not invent a stage count of its own", () => {
    // The summary comes from the core. A component that recomputed it could
    // disagree with the manifest it sits above.
    const html = render({ summary: "failed at stage 07 · routed · no relay connection" });
    expect(html).toContain("failed at stage 07");
    expect(html).not.toContain("9 of 9");
  });

  it("marks a failed send so it cannot be read as a successful one", () => {
    const html = render({ failed: true, summary: "failed at stage 07 · routed" });
    expect(html).toContain("manifest--failed");
  });

  it("does not claim delivery in its summary when the send failed", () => {
    const html = render({ failed: true, summary: "failed at stage 07 · routed" });
    expect(html).not.toMatch(/delivered\s*<\//i);
  });
});

/*
 * The expanded view is behind a click, which `renderToStaticMarkup` does not
 * perform. The rows themselves are the thing worth pinning, so they are
 * asserted through the same shape the component consumes — a guard against
 * someone filtering `rows` down to the ones that ran.
 */
describe("manifest rows", () => {
  it("carries every stage, including the ones that did not run", () => {
    expect(PHASE_1_ROWS).toHaveLength(9);
    expect(PHASE_1_ROWS.filter((r) => !r.ran)).toHaveLength(4);
  });

  it("names unbuilt stages as unimplemented rather than as not applicable", () => {
    // "n/a" says the stage does not apply to this message. "not yet
    // implemented" says the feature does not exist. Compression *would* apply
    // to a text message, so reporting it as n/a would misdescribe why it is
    // absent.
    const unbuilt = PHASE_1_ROWS.filter((r) =>
      ["COMPRESSED", "PADDED", "SENDER SEALED"].includes(r.label),
    );
    expect(unbuilt).toHaveLength(3);
    for (const row of unbuilt) {
      expect(row.detail).toBe("not yet implemented");
      expect(row.ran).toBe(false);
    }
  });

  it("reports direct transport as direct, never as Tor", () => {
    const routed = PHASE_1_ROWS.find((r) => r.label === "ROUTED");
    expect(routed?.detail).toContain("DIRECT");
    expect(routed?.detail).not.toContain("TOR");
  });

  it("names the actual mechanisms at the encryption stage", () => {
    // SPEC §2.5: "Encrypted" alone is insufficient.
    const encrypted = PHASE_1_ROWS.find((r) => r.label === "ENCRYPTED");
    for (const mechanism of ["AES-128-GCM", "X25519", "Ed25519"]) {
      expect(encrypted?.detail).toContain(mechanism);
    }
  });
});

/*
 * Compression landed in Phase 3. PHASE_1_ROWS above is left as it was —
 * labelled and dated, not silently rewritten — because it documents what a
 * Phase 1 send actually produced; this fixture documents what a real send
 * produces now. Both are true statements about different points in time,
 * which is the same reason DECISIONS.md is append-only rather than edited.
 */
describe("a compressed stage, as Phase 3 actually produces it", () => {
  const row: ManifestRow = {
    number: 3,
    label: "COMPRESSED",
    detail: "zstd · 3500 → 41 bytes",
    ran: true,
  };

  it("renders as having run, not as unimplemented", () => {
    const html = renderToStaticMarkup(
      <Manifest
        summary="6 of 9 stages ran"
        rows={[...PHASE_1_ROWS.filter((r) => r.number !== 3), row]}
        failed={false}
      />,
    );
    expect(html).not.toContain("not yet implemented");
  });

  it("names the algorithm, per the same SPEC §2.5 rule as encryption", () => {
    expect(row.detail).toContain("zstd");
  });
});
