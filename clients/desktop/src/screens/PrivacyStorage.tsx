/*
 * Screen 7 — Privacy and storage (SPEC §6.7.7).
 *
 * Every control here is named for what the user controls, never for how the
 * system works: "Keep messages", not "Retention TTL policy". Each carries a
 * one-line consequence, and each reports what it actually did afterwards — a
 * control that deletes forty messages and then says nothing is a control the
 * user has no reason to trust.
 *
 * The two things this build does not do are stated on the screen rather than
 * omitted from it. A settings screen that silently lacks a control the product
 * describes is the same failure as a manifest claiming a stage that never ran.
 */

import { useCallback, useEffect, useState } from "react";
import type {
  PouchBridge,
  RetentionChoice,
  RetentionValue,
} from "../lib/bridge";
import "./screens.css";

interface PrivacyStorageProps {
  bridge: PouchBridge;
  onBack: () => void;
  onWiped: () => void;
  onExportBackup: () => void;
  onTransportSettings: () => void;
}

export function PrivacyStorage({
  bridge,
  onBack,
  onWiped,
  onExportBackup,
  onTransportSettings,
}: PrivacyStorageProps) {
  const [choices, setChoices] = useState<RetentionChoice[]>([]);
  const [policy, setPolicy] = useState<RetentionValue | null>(null);
  const [protectedByPassphrase, setProtectedByPassphrase] = useState(false);
  const [queued, setQueued] = useState(0);

  const [passphrase, setPassphrase] = useState("");
  const [wipeConfirm, setWipeConfirm] = useState("");

  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [c, p, prot, q] = await Promise.all([
      bridge.retentionChoices(),
      bridge.retentionPolicy(),
      bridge.isPassphraseProtected(),
      bridge.queuedCount(),
    ]);
    setChoices(c);
    setPolicy(p);
    setProtectedByPassphrase(prot);
    setQueued(q);
  }, [bridge]);

  useEffect(() => {
    refresh().catch((e) =>
      setError(e instanceof Error ? e.message : String(e)),
    );
  }, [refresh]);

  function report(e: unknown) {
    setNote(null);
    setError(e instanceof Error ? e.message : String(e));
  }

  async function chooseRetention(value: RetentionValue) {
    try {
      setError(null);
      const deleted = await bridge.setRetentionPolicy(value);
      const label = choices.find((c) => c.value === value)?.label ?? value;
      // Says what happened, including when nothing did.
      setNote(
        deleted === 0
          ? `Messages are kept ${label}. Nothing was old enough to delete.`
          : `Messages are kept ${label}. ${deleted} ${
              deleted === 1 ? "message was" : "messages were"
            } older than that and ${deleted === 1 ? "has" : "have"} been deleted.`,
      );
      await refresh();
    } catch (e) {
      report(e);
    }
  }

  async function protectWithPassphrase() {
    try {
      setError(null);
      await bridge.setPassphrase(passphrase);
      setPassphrase("");
      setNote(
        "This device now requires your passphrase. The database has been re-encrypted and the old key file deleted.",
      );
      await refresh();
    } catch (e) {
      report(e);
    }
  }

  async function removePassphrase() {
    try {
      setError(null);
      await bridge.clearPassphrase();
      setNote(
        "Passphrase removed. The key is now in a file beside the database again.",
      );
      await refresh();
    } catch (e) {
      report(e);
    }
  }

  async function wipe() {
    try {
      setError(null);
      await bridge.wipeAll();
      onWiped();
    } catch (e) {
      report(e);
    }
  }

  return (
    <main className="screen screen--narrow">
      <h1 className="screen__title">Privacy and storage</h1>
      <p className="screen__lede">
        What this device keeps, and what protects it.
      </p>

      {error && (
        <p className="screen__error" role="alert">
          {error}
        </p>
      )}
      {note && (
        <p className="screen__note" role="status">
          {note}
        </p>
      )}

      {/* -- retention ------------------------------------------------------ */}
      <section className="panel">
        <h2 className="panel__h">Keep messages</h2>
        <p className="panel__note">
          Applies to this device only. It does not delete anything from the
          person you were talking to.
        </p>
        <fieldset className="field-group">
          <legend className="visually-hidden">How long to keep messages</legend>
          {choices.map((choice) => (
            <label key={choice.value} className="choice">
              <input
                type="radio"
                name="retention"
                value={choice.value}
                checked={policy === choice.value}
                onChange={() => void chooseRetention(choice.value)}
              />
              <span>{choice.label}</span>
            </label>
          ))}
        </fieldset>
      </section>

      {/* -- passphrase ----------------------------------------------------- */}
      <section className="panel">
        <h2 className="panel__h">Passphrase-protect this device</h2>
        {protectedByPassphrase ? (
          <>
            <p className="panel__note">
              This device is protected. Your passphrase is required to open it,
              and nothing stored on this machine can be turned back into the
              key.
            </p>
            <button
              type="button"
              className="button-quiet"
              onClick={() => void removePassphrase()}
            >
              Remove passphrase protection
            </button>
            <p className="panel__note">
              Removing it puts the key back in a file beside the database, where
              anyone who can read the database can read the key. That is weaker
              than what you have now.
            </p>
          </>
        ) : (
          <>
            <p className="panel__note">
              Right now the key to this database sits in a file next to it, so
              anyone who can read the database can read the key. A passphrase
              replaces that with something only you know.
            </p>
            <label className="field">
              <span className="field__label">Passphrase</span>
              <input
                type="password"
                className="field__input"
                value={passphrase}
                autoComplete="new-password"
                onChange={(e) => setPassphrase(e.target.value)}
              />
            </label>
            <button
              type="button"
              className="button-primary"
              disabled={passphrase.trim().length === 0}
              onClick={() => void protectWithPassphrase()}
            >
              Protect this device
            </button>
            <p className="panel__note">
              There is no recovery. If you forget it, the messages on this
              device cannot be read again — by you or by anyone else.
            </p>
          </>
        )}
      </section>

      {/* -- what is waiting ------------------------------------------------ */}
      <section className="panel">
        <h2 className="panel__h">Waiting to send</h2>
        <p className="panel__note">
          {queued === 0
            ? "Nothing is waiting."
            : `${queued} ${queued === 1 ? "message is" : "messages are"} waiting for a connection. ${
                queued === 1 ? "It" : "They"
              } will send when you reconnect.`}
        </p>
      </section>

      {/* -- transport -------------------------------------------------------- */}
      <section className="panel">
        <h2 className="panel__h">Transport</h2>
        <p className="panel__note">
          How this device reaches the relay: straight there, or through Tor.
          Each has a different cost, stated on the next screen.
        </p>
        <button
          type="button"
          className="button-quiet"
          onClick={onTransportSettings}
        >
          Transport settings
        </button>
      </section>

      {/* -- backup ----------------------------------------------------------- */}
      <section className="panel">
        <h2 className="panel__h">Move your history to a new device</h2>
        <p className="panel__note">
          Encrypted with a key only you hold, and never uploaded anywhere.
          Restoring is done from the first-run screen, on the device you are
          moving to.
        </p>
        <button
          type="button"
          className="button-primary"
          onClick={onExportBackup}
        >
          Export encrypted backup
        </button>
      </section>

      {/* -- what this build does not do ------------------------------------ */}
      <section className="panel">
        <h2 className="panel__h">Not in this build</h2>
        <p className="panel__note">
          <strong>Key from the operating system's keystore.</strong> Not
          implemented. Until it is, a device with no passphrase is protected by
          a key file sitting beside the database.
        </p>
      </section>

      {/* -- wipe ------------------------------------------------------------ */}
      <section className="panel panel--alarm">
        <h2 className="panel__h">Wipe all local data</h2>
        <p className="panel__note">
          Destroys every message, contact, and key on this device, including
          anything still waiting to send. Your contacts keep their copies. This
          cannot be undone.
        </p>
        <label className="field">
          <span className="field__label">
            Type <span className="mono">wipe</span> to confirm
          </span>
          <input
            type="text"
            className="field__input"
            value={wipeConfirm}
            autoComplete="off"
            onChange={(e) => setWipeConfirm(e.target.value)}
          />
        </label>
        <button
          type="button"
          className="button-alarm"
          disabled={wipeConfirm !== "wipe"}
          onClick={() => void wipe()}
        >
          Wipe all data
        </button>
      </section>

      <div className="screen__actions">
        <button type="button" className="button-quiet" onClick={onBack}>
          Back
        </button>
      </div>
    </main>
  );
}
