/*
 * Screen 4 — Add contact (SPEC §6.7.4).
 *
 * Two modes side by side: show my code, and enter theirs. The copy states what
 * the code contains, and that claim is true — the core's invite code carries a
 * public key, an inbox address, and a single-use key package, and a test
 * asserts the display name does not survive into it.
 */

import { useEffect, useState } from "react";
import type { PouchBridge } from "../lib/bridge";
import "./screens.css";

interface AddContactProps {
  bridge: PouchBridge;
  onAdded: (conversationId: string) => void;
  onBack: () => void;
}

export function AddContact({ bridge, onAdded, onBack }: AddContactProps) {
  const [myCode, setMyCode] = useState<string | null>(null);
  const [theirCode, setTheirCode] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    bridge
      .inviteCode()
      .then(setMyCode)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [bridge]);

  async function add(event: React.FormEvent) {
    event.preventDefault();
    if (!name.trim() || !theirCode.trim() || busy) return;

    setBusy(true);
    setError(null);
    try {
      onAdded(await bridge.addContact(name.trim(), theirCode.trim()));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <main className="screen">
      <header className="screen__header">
        <h1 className="screen__title">Add someone</h1>
        <button type="button" className="button-quiet" onClick={onBack}>
          Back
        </button>
      </header>

      <section className="panel">
        <h2 className="panel__h">Your invite code</h2>
        <p className="panel__note">
          This code holds your public key and inbox address. It contains no
          personal information.
        </p>
        <pre className="code-block mono">{myCode ?? "Preparing a code…"}</pre>
      </section>

      <section className="panel">
        <h2 className="panel__h">Their invite code</h2>
        <form className="screen__form" onSubmit={add}>
          <label className="field">
            <span className="field__label">What to call them</span>
            <input
              className="field__input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={64}
            />
            <span className="field__hint">
              Stored on this device only. They never see it unless you tell them.
            </span>
          </label>

          <label className="field">
            <span className="field__label">Their code</span>
            <textarea
              className="field__input field__input--mono"
              rows={4}
              value={theirCode}
              onChange={(e) => setTheirCode(e.target.value)}
            />
          </label>

          {error && (
            <p className="screen__error" role="alert">
              {error}
            </p>
          )}

          <button
            type="submit"
            className="button-primary"
            disabled={!name.trim() || !theirCode.trim() || busy}
          >
            {busy ? "Starting conversation" : "Start conversation"}
          </button>

          <p className="panel__note">
            They will be UNVERIFIED until you compare safety numbers in person
            or over a call you trust.
          </p>
        </form>
      </section>
    </main>
  );
}
