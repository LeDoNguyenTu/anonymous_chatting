/*
 * The Manifest — DESIGN_SYSTEM.md §5, SPEC §6.5.
 *
 * Renders exactly what the core reported and nothing else. It does no
 * inference: it does not assume a stage ran because a later one did, it does
 * not hide stages that did not run, and it has no notion of a "complete"
 * manifest to fall back on.
 *
 * The core already refuses to claim a stage it did not perform. This component
 * exists to not undo that on the way to the screen.
 */

import { useState } from "react";
import type { ManifestRow, RelayVisibilityView } from "../lib/bridge";
import "./Manifest.css";

interface ManifestProps {
  summary: string;
  rows: ManifestRow[];
  failed: boolean;
  /** Loads the relay-visibility panel when the last row is opened. */
  onOpenRelayVisibility?: () => Promise<RelayVisibilityView>;
}

export function Manifest({
  summary,
  rows,
  failed,
  onOpenRelayVisibility,
}: ManifestProps) {
  const [expanded, setExpanded] = useState(false);
  const [visibility, setVisibility] = useState<RelayVisibilityView | null>(null);
  const [visibilityError, setVisibilityError] = useState<string | null>(null);

  const ran = rows.filter((r) => r.ran).length;

  async function openVisibility() {
    if (!onOpenRelayVisibility) return;
    try {
      setVisibility(await onOpenRelayVisibility());
      setVisibilityError(null);
    } catch (e) {
      // Reported rather than swallowed. A panel that silently shows nothing
      // reads as "nothing is visible to the relay", which is the opposite of
      // what a failure means.
      setVisibilityError(
        e instanceof Error ? e.message : "Could not read what the relay can see.",
      );
    }
  }

  return (
    <div className={`manifest ${failed ? "manifest--failed" : ""}`}>
      <button
        type="button"
        className="manifest__summary mono"
        aria-expanded={expanded}
        onClick={() => setExpanded(!expanded)}
      >
        <span aria-hidden="true">{expanded ? "⌄" : "⟩"}</span> {summary}
      </button>

      {expanded && (
        <div className="manifest__detail">
          <h3 className="manifest__title mono">MESSAGE MANIFEST</h3>

          <ol className="manifest__stages">
            {rows.map((row) => (
              <li
                key={row.number}
                className={`manifest__stage ${row.ran ? "" : "manifest__stage--idle"}`}
              >
                <span className="manifest__number mono" aria-hidden="true">
                  {String(row.number).padStart(2, "0")}
                </span>
                <span className="manifest__label mono">{row.label}</span>
                <span className="manifest__value mono">{row.detail}</span>
              </li>
            ))}
          </ol>

          <p className="manifest__count">
            {ran} of {rows.length} stages ran on this message.
          </p>

          {onOpenRelayVisibility && !visibility && !visibilityError && (
            <button
              type="button"
              className="manifest__relay-open"
              onClick={openVisibility}
            >
              What the relay could see ⟩
            </button>
          )}

          {visibilityError && (
            <p className="manifest__error" role="alert">
              {visibilityError}
            </p>
          )}

          {visibility && <RelayVisibility visibility={visibility} />}
        </div>
      )}
    </div>
  );
}

/**
 * The three blocks of SPEC §6.5.4.
 *
 * The third is not optional and is not conditional on having something to say.
 * Listing what is protected while omitting what still leaks is the reassuring
 * half-truth Prime Directive 3 exists to forbid, and the easiest way for that
 * to happen is for someone to render the block only when it is non-empty.
 */
function RelayVisibility({ visibility }: { visibility: RelayVisibilityView }) {
  return (
    <section className="relay-vis" aria-label="What the relay could see">
      <h3 className="relay-vis__title mono">WHAT THE RELAY COULD SEE</h3>

      <dl className="relay-vis__facts">
        <dt className="mono">inbox id</dt>
        <dd className="mono">{visibility.inboxId} (random, not you)</dd>
        <dt className="mono">blob size</dt>
        <dd className="mono">{visibility.blobSize} bytes</dd>
      </dl>

      <h4 className="relay-vis__heading mono">VISIBLE</h4>
      <ul className="relay-vis__list">
        {visibility.visible.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>

      <h4 className="relay-vis__heading mono">NOT VISIBLE</h4>
      <ul className="relay-vis__list">
        {visibility.notVisible.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>

      <h4 className="relay-vis__heading relay-vis__heading--leak mono">
        STILL INFERABLE BY A NETWORK OBSERVER
      </h4>
      <ul className="relay-vis__list">
        {visibility.stillInferable.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </section>
  );
}
