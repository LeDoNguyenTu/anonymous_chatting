/*
 * Screen 10 — Backup export / import (SPEC §6.7.10, §7.3).
 *
 * Two modes, gated by which one is reachable from where a device already
 * stands: export needs an identity open (Privacy and storage screen),
 * import needs one *not* open yet (`Pouch::import_backup` creates a device
 * from nothing — the same precondition `create_identity` has, so this
 * screen never offers import to a device that already has an identity).
 *
 * The recovery key is shown exactly once, here, and never again — nothing
 * in this project stores it. The confirm-you-saved-it gate before the
 * download button exists so a key never leaves the screen unread.
 */

import { useState } from "react";
import type { PouchBridge } from "../lib/bridge";
import "./screens.css";

interface ExportBackupProps {
  mode: "export";
  bridge: PouchBridge;
  onBack: () => void;
}

interface ImportBackupProps {
  mode: "import";
  bridge: PouchBridge;
  onRestored: () => void;
  onBack?: () => void;
}

type BackupRestoreProps = ExportBackupProps | ImportBackupProps;

export function BackupRestore(props: BackupRestoreProps) {
  return props.mode === "export" ? (
    <ExportScreen bridge={props.bridge} onBack={props.onBack} />
  ) : (
    <ImportScreen
      bridge={props.bridge}
      onRestored={props.onRestored}
      onBack={props.onBack}
    />
  );
}

function ExportScreen({
  bridge,
  onBack,
}: {
  bridge: PouchBridge;
  onBack: () => void;
}) {
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [backup, setBackup] = useState<Uint8Array | null>(null);
  const [fileName, setFileName] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function generate() {
    setBusy(true);
    setError(null);
    setConfirmed(false);
    setDownloaded(false);
    try {
      const r = await bridge.exportBackup();
      setRecoveryKey(r.recoveryKeyHex);
      setBackup(r.backup);
      setFileName(r.fileName);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function download() {
    if (!backup) return;
    const blob = new Blob([backup], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
    setDownloaded(true);
  }

  return (
    <main className="screen screen--narrow">
      <h1 className="screen__title">Export encrypted backup</h1>
      <p className="screen__lede">
        Move your history to a new device without trusting the server. The
        file is encrypted with a key only you hold — it is never uploaded
        anywhere.
      </p>

      {error && (
        <p className="screen__error" role="alert">
          {error}
        </p>
      )}

      {!recoveryKey && (
        <button
          type="button"
          className="button-primary"
          disabled={busy}
          onClick={() => void generate()}
        >
          {busy ? "Preparing backup" : "Generate backup"}
        </button>
      )}

      {recoveryKey && (
        <>
          <section className="panel panel--alarm">
            <h2 className="panel__h">Your recovery key</h2>
            <p className="panel__note">
              This key is the only way to open your backup. It is not stored
              anywhere. If you lose it, the backup cannot be recovered.
            </p>
            <pre className="code-block mono" aria-label="Recovery key">
              {recoveryKey}
            </pre>
            <label className="choice">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />
              <span>I have saved this key somewhere safe</span>
            </label>
          </section>

          <button
            type="button"
            className="button-primary"
            disabled={!confirmed}
            onClick={download}
          >
            Download backup file
          </button>

          {downloaded && (
            <p className="screen__note" role="status">
              Saved as {fileName}. Store it and the recovery key separately —
              anyone with both can read your history.
            </p>
          )}
        </>
      )}

      <div className="screen__actions">
        <button type="button" className="button-quiet" onClick={onBack}>
          Back
        </button>
      </div>
    </main>
  );
}

function ImportScreen({
  bridge,
  onRestored,
  onBack,
}: {
  bridge: PouchBridge;
  onRestored: () => void;
  onBack?: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [recoveryKeyHex, setRecoveryKeyHex] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function restore(event: React.FormEvent) {
    event.preventDefault();
    if (!file || !recoveryKeyHex.trim() || busy) return;

    setBusy(true);
    setError(null);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      await bridge.importBackup(recoveryKeyHex.trim(), bytes);
      onRestored();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <main className="screen screen--narrow">
      <h1 className="screen__title">Restore from backup</h1>
      <p className="screen__lede">
        Choose a Pouch backup file and enter the recovery key it was made
        with. This replaces whatever is on this device with the backup's
        contents.
      </p>

      <form className="screen__form" onSubmit={restore}>
        <label className="field">
          <span className="field__label">Backup file</span>
          <input
            type="file"
            accept=".pouchbk"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
        </label>

        <label className="field">
          <span className="field__label">Recovery key</span>
          <input
            className="field__input field__input--mono"
            value={recoveryKeyHex}
            onChange={(e) => setRecoveryKeyHex(e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
          <span className="field__hint">
            The key shown once, at export time. Not stored anywhere — if it
            is lost, this backup cannot be recovered by anyone, including us.
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
          disabled={!file || !recoveryKeyHex.trim() || busy}
        >
          {busy ? "Restoring" : "Restore backup"}
        </button>
      </form>

      {onBack && (
        <div className="screen__actions">
          <button type="button" className="button-quiet" onClick={onBack}>
            Back
          </button>
        </div>
      )}
    </main>
  );
}
