/*
 * Screen 1 — First run (SPEC §6.7.1).
 *
 * Job: create an identity in under thirty seconds with no personal data
 * requested. No phone number, no email, no username on a server. The display
 * name is local and is shared only with contacts the user adds by hand.
 */

import { useState } from "react";
import type { PouchBridge } from "../lib/bridge";
import "./screens.css";

interface FirstRunProps {
  bridge: PouchBridge;
  onCreated: () => void;
}

export function FirstRun({ bridge, onCreated }: FirstRunProps) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function create(event: React.FormEvent) {
    event.preventDefault();
    if (!name.trim() || busy) return;

    setBusy(true);
    setError(null);
    try {
      await bridge.createIdentity(name.trim());
      onCreated();
    } catch (e) {
      // The core's errors already say what happened and what to do
      // (SPEC §6.9), so they are shown as written rather than replaced with
      // something vaguer.
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <main className="screen screen--narrow">
      <h1 className="screen__title">Pouch</h1>

      <p className="screen__lede">
        Your account lives on this device. Nothing about you is sent to a
        server.
      </p>

      <form className="screen__form" onSubmit={create}>
        <label className="field">
          <span className="field__label">Display name</span>
          <input
            className="field__input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            maxLength={64}
          />
          <span className="field__hint">
            Stored on this device and shared only with contacts you add. It is
            never sent to the relay.
          </span>
        </label>

        {error && (
          <p className="screen__error" role="alert">
            {error}
          </p>
        )}

        <button
          type="submit"
          className="button-primary"
          disabled={!name.trim() || busy}
        >
          {busy ? "Creating identity" : "Create identity"}
        </button>
      </form>

      <p className="screen__footnote">
        Pouch is unaudited student work. Do not rely on it if you face a serious
        adversary.
      </p>
    </main>
  );
}
