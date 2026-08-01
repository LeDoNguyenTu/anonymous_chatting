/*
 * Screen 6 — Identity change warning (SPEC §6.7.6).
 *
 * A modal, not a toast, because the user has to make a decision and a
 * notification can be missed. Three rules govern the copy:
 *
 * 1. It states the fact and both explanations, and accuses nobody. The innocent
 *    reading is the likely one and is given first.
 * 2. "Continue without verifying" is present and not hidden. Users have
 *    reasons, and burying the escape makes people click the reassuring button
 *    instead — which is worse, because that one claims a check they did not do.
 * 3. Neither action verifies anything. Verification only ever happens on the
 *    safety number screen, after a comparison the user actually performed.
 */

import type { IdentityChangeView } from "../lib/bridge";
import "./IdentityChangeModal.css";

interface IdentityChangeModalProps {
  change: IdentityChangeView;
  onVerify: (contactId: string) => void;
  onContinue: (contactId: string) => void;
}

/** Formats the change date as a plain day, which is what the copy needs. */
function changedOn(at: number): string {
  return new Date(at * 1000).toLocaleDateString(undefined, {
    day: "numeric",
    month: "long",
  });
}

export function IdentityChangeModal({
  change,
  onVerify,
  onContinue,
}: IdentityChangeModalProps) {
  const who = change.contactName || "This contact";

  return (
    <div className="modal-backdrop">
      <div
        className="modal"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="identity-change-title"
        aria-describedby="identity-change-body"
      >
        <h2 id="identity-change-title" className="modal__h">
          {who}&rsquo;s identity key changed
        </h2>

        <div id="identity-change-body">
          <p className="modal__body">
            {who}&rsquo;s identity key changed on {changedOn(change.changedAt)}.
            This usually means they reinstalled Pouch or switched devices. It
            can also mean someone is intercepting your messages.
          </p>
          <p className="modal__body">
            Verify the new safety number before continuing. Until you do, this
            conversation is marked unverified.
          </p>
        </div>

        <div className="modal__actions">
          <button
            type="button"
            className="button-primary"
            onClick={() => onVerify(change.contactId)}
          >
            Verify now
          </button>
          <button
            type="button"
            className="button-quiet"
            onClick={() => onContinue(change.contactId)}
          >
            Continue without verifying
          </button>
        </div>
      </div>
    </div>
  );
}
