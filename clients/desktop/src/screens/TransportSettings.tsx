/*
 * Screen 9 — Transport settings (SPEC §6.7.9).
 *
 * Two options, named for what each costs rather than which one is "secure".
 * SPEC is explicit that neither is labelled the secure one, and the copy comes
 * from the core (`Route::name`/`Route::explanation`, via `transportOptions()`)
 * rather than being written again here — so this screen cannot drift from what
 * the Custody Strip and the message manifest tell the same user.
 *
 * Split in two on purpose. `TransportSettingsView` is pure, so its honesty
 * rules can be asserted with `renderToStaticMarkup` the way `CustodyStrip`'s
 * are; effects do not run under that renderer, so a screen that fetched inside
 * itself could only be tested for how it looks before it has anything to say.
 * `TransportSettings` is the container that does the talking.
 */

import { useCallback, useEffect, useState } from "react";
import type {
  PouchBridge,
  TransportLabel,
  TransportOption,
} from "../lib/bridge";
import "./screens.css";

interface TransportSettingsViewProps {
  options: TransportOption[];
  /** The route actually in use, or `null` while that is not yet known. */
  active: TransportLabel | null;
  busy: boolean;
  error: string | null;
  onChoose: (route: TransportLabel) => void;
  onBack: () => void;
}

export function TransportSettingsView({
  options,
  active,
  busy,
  error,
  onChoose,
  onBack,
}: TransportSettingsViewProps) {
  return (
    <main className="screen screen--narrow">
      <h1 className="screen__title">Transport</h1>
      <p className="screen__lede">How this device reaches the relay.</p>

      {error && (
        <p className="screen__error" role="alert">
          {error}
        </p>
      )}

      <fieldset className="field-group" disabled={busy}>
        <legend className="visually-hidden">How to reach the relay</legend>
        {options.map((option) => (
          <label key={option.route} className="choice choice--block">
            <input
              type="radio"
              name="transport"
              value={option.route}
              checked={active === option.route}
              onChange={() => onChoose(option.route)}
            />
            <span>
              <strong>{option.name}</strong>
              <span className="panel__note">{option.explanation}</span>
            </span>
          </label>
        ))}
      </fieldset>

      {busy && (
        <p className="screen__note" role="status">
          Connecting. The first Tor connection can take a while — it builds a
          circuit before anything is sent.
        </p>
      )}

      {/* Stated on the screen rather than left for the user to discover. A
          failed switch leaves the previous route in use, and someone who
          assumed otherwise would think they were on Tor while sending
          directly. */}
      <p className="screen__footnote">
        If a transport cannot be reached, this device keeps using the one it
        already had. It does not switch quietly.
      </p>

      <div className="screen__actions">
        <button type="button" className="button-quiet" onClick={onBack}>
          Back
        </button>
      </div>
    </main>
  );
}

interface TransportSettingsProps {
  bridge: PouchBridge;
  onBack: () => void;
}

export function TransportSettings({ bridge, onBack }: TransportSettingsProps) {
  const [options, setOptions] = useState<TransportOption[]>([]);
  const [active, setActive] = useState<TransportLabel | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [opts, current] = await Promise.all([
      bridge.transportOptions(),
      bridge.transportState(),
    ]);
    setOptions(opts);
    setActive(current);
  }, [bridge]);

  useEffect(() => {
    refresh().catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [refresh]);

  async function choose(route: TransportLabel) {
    setBusy(true);
    setError(null);
    try {
      if (route === "TOR") {
        await bridge.connectTor();
      } else {
        await bridge.useDirectRelay();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      // Re-read the route whether the switch worked or not. On failure the
      // core kept the old connection, and asking it is the only way this
      // screen can be sure which one that is — assuming the switch failed
      // cleanly would be guessing about the thing the user came here to
      // check.
      await refresh().catch((e) =>
        setError(e instanceof Error ? e.message : String(e)),
      );
    }
  }

  return (
    <TransportSettingsView
      options={options}
      active={active}
      busy={busy}
      error={error}
      onChoose={(route) => void choose(route)}
      onBack={onBack}
    />
  );
}
