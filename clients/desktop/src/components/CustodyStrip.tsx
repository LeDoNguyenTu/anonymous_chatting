/*
 * The Custody Strip — DESIGN_SYSTEM.md §4.
 *
 * Three facts, always visible, always in monospace, never collapsing on
 * scroll. The rule that governs every change to this file:
 *
 *   It must never show a reassuring state when the underlying state is
 *   uncertain.
 *
 * There is deliberately no "unknown falls back to something friendly" path.
 * If identity is not confirmed verified, it renders UNVERIFIED in amber.
 */

import "./CustodyStrip.css";

export type IdentityState = "verified" | "unverified" | "key-changed";
export type TransportState = "tor" | "direct" | "offline";
export type RetentionState = "keep" | "30-day" | "7-day" | "24-hour";

/** Tone drives colour *and* is paired with a text label, never used alone. */
type Tone = "verified" | "pending" | "alarm" | "mute";

interface FieldView {
  label: string;
  caption: string;
  tone: Tone;
  /** What the field means, read aloud and shown when the field is opened. */
  explanation: string;
}

const IDENTITY: Record<IdentityState, FieldView> = {
  verified: {
    label: "VERIFIED",
    caption: "identity",
    tone: "verified",
    explanation:
      "You compared this contact's safety number out of band and marked it as matching.",
  },
  unverified: {
    label: "UNVERIFIED",
    caption: "identity",
    tone: "pending",
    explanation:
      "You have not compared safety numbers with this contact yet. You can still message them. Until you compare, this stays amber.",
  },
  "key-changed": {
    label: "KEY CHANGED",
    caption: "identity",
    tone: "alarm",
    explanation:
      "This contact's identity key changed. That usually means they reinstalled or switched devices. It can also mean someone is intercepting your messages. Compare the new safety number before continuing.",
  },
};

const TRANSPORT: Record<TransportState, FieldView> = {
  tor: {
    label: "TOR",
    caption: "transport",
    tone: "verified",
    explanation:
      "Messages route through a Tor onion circuit. The relay never learns your IP address. Your internet provider can still see that you are using Tor.",
  },
  direct: {
    label: "DIRECT",
    caption: "transport",
    tone: "pending",
    explanation:
      "Messages go straight to the relay over TLS 1.3. The relay sees the IP address you connect from. Message content stays encrypted either way.",
  },
  offline: {
    label: "OFFLINE",
    caption: "transport",
    tone: "mute",
    explanation:
      "No connection to the relay. Messages you write are queued on this device and send when you reconnect.",
  },
};

const RETENTION: Record<RetentionState, FieldView> = {
  keep: {
    label: "KEEP",
    caption: "retention",
    tone: "mute",
    explanation: "Messages in this conversation are kept until you delete them.",
  },
  "30-day": {
    label: "30-DAY",
    caption: "retention",
    tone: "verified",
    explanation: "Messages in this conversation are erased after 30 days.",
  },
  "7-day": {
    label: "7-DAY",
    caption: "retention",
    tone: "verified",
    explanation: "Messages in this conversation are erased after 7 days.",
  },
  "24-hour": {
    label: "24-HOUR",
    caption: "retention",
    tone: "verified",
    explanation: "Messages in this conversation are erased after 24 hours.",
  },
};

export interface CustodyStripProps {
  identity: IdentityState;
  transport: TransportState;
  retention: RetentionState;
  /** Opens the explanation and the control behind a field. */
  onOpenField?: (field: "identity" | "transport" | "retention") => void;
}

function Field({
  view,
  field,
  onOpen,
}: {
  view: FieldView;
  field: "identity" | "transport" | "retention";
  onOpen?: (field: "identity" | "transport" | "retention") => void;
}) {
  return (
    <button
      type="button"
      className={`custody-field custody-field--${view.tone}`}
      onClick={() => onOpen?.(field)}
      // The label alone reads as an abbreviation out of context, so screen
      // readers get the caption and the full explanation too.
      aria-label={`${view.caption}: ${view.label}. ${view.explanation}`}
    >
      <span className="custody-field__row">
        <span className="custody-field__dot" aria-hidden="true" />
        <span className="custody-field__label mono">{view.label}</span>
      </span>
      <span className="custody-field__caption" aria-hidden="true">
        {view.caption}
      </span>
    </button>
  );
}

export function CustodyStrip({
  identity,
  transport,
  retention,
  onOpenField,
}: CustodyStripProps) {
  return (
    <div
      className="custody-strip"
      role="group"
      aria-label="Custody state for this conversation"
    >
      <Field view={IDENTITY[identity]} field="identity" onOpen={onOpenField} />
      <span className="custody-strip__rule" aria-hidden="true" />
      <Field
        view={TRANSPORT[transport]}
        field="transport"
        onOpen={onOpenField}
      />
      <span className="custody-strip__rule" aria-hidden="true" />
      <Field
        view={RETENTION[retention]}
        field="retention"
        onOpen={onOpenField}
      />
    </div>
  );
}
