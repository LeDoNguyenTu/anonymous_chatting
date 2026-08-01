/*
 * Screen 5 — Safety number (SPEC §6.7.5).
 *
 * Sixty digits, grouped in fives, in mono. Two actions, and the second one is
 * not hidden: a user whose numbers do not match needs somewhere to go, and
 * offering only the reassuring button is how a mismatch gets clicked past.
 */

import { useEffect, useState } from "react";
import type { PouchBridge } from "../lib/bridge";
import "./screens.css";

interface SafetyNumberProps {
  bridge: PouchBridge;
  contactId: string;
  contactName: string;
  onDone: () => void;
}

export function SafetyNumber({
  bridge,
  contactId,
  contactName,
  onDone,
}: SafetyNumberProps) {
  const [number, setNumber] = useState<string | null>(null);
  const [mismatch, setMismatch] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    bridge
      .safetyNumber(contactId)
      .then(setNumber)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [bridge, contactId]);

  async function markVerified() {
    try {
      await bridge.verifyContact(contactId, true);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <main className="screen screen--narrow">
      <h1 className="screen__title">Safety number</h1>
      <p className="screen__lede">
        Compare this number with {contactName || "your contact"} in person or
        over a call you trust. If it matches, mark them verified.
      </p>

      {error && (
        <p className="screen__error" role="alert">
          {error}
        </p>
      )}

      <p className="safety-number mono" aria-label="Safety number">
        {number ?? "Deriving…"}
      </p>

      {mismatch ? (
        <section className="panel panel--alarm" role="alert">
          <h2 className="panel__h">If the numbers do not match</h2>
          <p className="panel__note">
            Two things cause this. The likely one is that your contact
            reinstalled Pouch or switched devices, which changes their key. The
            other is that someone is intercepting your messages.
          </p>
          <p className="panel__note">
            Do not mark them verified. Reach them through a channel you already
            trust and confirm they reinstalled. If they did not, stop using this
            conversation.
          </p>
          <button type="button" className="button-quiet" onClick={() => setMismatch(false)}>
            Back to the number
          </button>
        </section>
      ) : (
        <div className="screen__actions screen__actions--stacked">
          <button
            type="button"
            className="button-primary"
            onClick={markVerified}
            disabled={!number}
          >
            Numbers match — mark verified
          </button>
          <button
            type="button"
            className="button-quiet"
            onClick={() => setMismatch(true)}
          >
            They don't match
          </button>
          <button type="button" className="button-quiet" onClick={onDone}>
            Not now
          </button>
        </div>
      )}
    </main>
  );
}
