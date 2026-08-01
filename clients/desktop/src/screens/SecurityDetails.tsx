/*
 * Screen 12 — Security details (SPEC §6.7.12).
 *
 * A plainly formatted mono list of every mechanism in use, each with a
 * one-line explanation of what it does. Nothing here is secret, and the opening
 * copy says why publishing it costs nothing (D-014).
 */

import { useEffect, useState } from "react";
import type { PouchBridge, SecurityDetailsView } from "../lib/bridge";
import "./screens.css";

interface SecurityDetailsProps {
  bridge: PouchBridge;
  onBack: () => void;
}

/** What each mechanism is for, in one line. */
const EXPLANATIONS: Record<string, string> = {
  protocol: "Manages session keys and group membership.",
  ciphersuite: "The exact set of primitives every message uses.",
  aead: "Encrypts and authenticates each message. Invoked through the protocol, never directly.",
  keyAgreement: "How two devices agree on a shared secret without sending it.",
  signature: "Proves a message came from the key it claims.",
  kdf: "Derives keys from other keys. A hash — not encryption, and it provides no confidentiality.",
  localDatabase: "Encrypts messages and keys stored on this device.",
  passphraseDerivation: "Turns a passphrase into a key, slowly, to resist guessing.",
  transport: "Protects the connection to the relay, beneath the end-to-end layer.",
  relayAddress: "The relay this client is configured to use.",
  openmlsVersion: "The pinned version of the MLS implementation.",
  appVersion: "This build.",
};

const ORDER: Array<[keyof SecurityDetailsView, string]> = [
  ["protocol", "protocol"],
  ["ciphersuite", "ciphersuite"],
  ["aead", "AEAD"],
  ["keyAgreement", "key agreement"],
  ["signature", "signature"],
  ["kdf", "KDF"],
  ["localDatabase", "local database"],
  ["passphraseDerivation", "passphrase to key"],
  ["transport", "transport"],
  ["relayAddress", "relay"],
  ["openmlsVersion", "openmls"],
  ["appVersion", "version"],
];

export function SecurityDetails({ bridge, onBack }: SecurityDetailsProps) {
  const [details, setDetails] = useState<SecurityDetailsView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    bridge
      .securityDetails()
      .then(setDetails)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [bridge]);

  return (
    <main className="screen">
      <header className="screen__header">
        <h1 className="screen__title">Security details</h1>
        <button type="button" className="button-quiet" onClick={onBack}>
          Back
        </button>
      </header>

      <p className="screen__lede">
        Nothing here is secret. The security of this app rests on your keys, not
        on hiding how it works.
      </p>

      {error && (
        <p className="screen__error" role="alert">
          {error}
        </p>
      )}

      {details && (
        <dl className="mechanisms">
          {ORDER.map(([key, label]) => (
            <div className="mechanisms__row" key={key}>
              <dt className="mechanisms__label mono">{label}</dt>
              <dd className="mechanisms__value">
                <span className="mono">{details[key]}</span>
                <span className="mechanisms__why">{EXPLANATIONS[key]}</span>
              </dd>
            </div>
          ))}
        </dl>
      )}

      <p className="screen__footnote">
        This app is unaudited student work. Do not rely on it if you face a
        serious adversary.
      </p>
    </main>
  );
}
