/*
 * Phase 0 shell.
 *
 * This is not the application. It is the token layer made visible, so that the
 * design system can be reviewed against docs/DESIGN_SYSTEM.md before any real
 * screen is built on top of it. Phase 1 replaces this with the screens in
 * SPEC §6.6.
 *
 * The state below is hardcoded and labelled as such. Per Prime Directive 3, a
 * demonstration must not be able to be mistaken for a live security state.
 */

import { useEffect, useState } from "react";
import {
  CustodyStrip,
  type IdentityState,
  type RetentionState,
  type TransportState,
} from "./components/CustodyStrip";
import "./App.css";

type Theme = "light" | "dark";

export default function App() {
  const [theme, setTheme] = useState<Theme>("light");
  const [identity, setIdentity] = useState<IdentityState>("unverified");
  const [transport, setTransport] = useState<TransportState>("direct");
  const [retention, setRetention] = useState<RetentionState>("keep");
  const [opened, setOpened] = useState<string | null>(null);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  return (
    <div className="shell">
      <CustodyStrip
        identity={identity}
        transport={transport}
        retention={retention}
        onOpenField={(f) => setOpened(f)}
      />

      <main className="shell__body">
        <header className="shell__header">
          <h1 className="shell__title">Pouch</h1>
          <p className="shell__sub">
            Phase 0 — design tokens only. No messaging, no keys, no network.
          </p>
        </header>

        <section className="panel" aria-labelledby="strip-h">
          <h2 id="strip-h" className="panel__h">
            Custody Strip states
          </h2>
          <p className="panel__note">
            Every state is reachable here so the palette can be checked against
            both themes. The strip above is live and driven by these controls.
          </p>

          <div className="control-row">
            <span className="control-row__label">Identity</span>
            {(["verified", "unverified", "key-changed"] as const).map((s) => (
              <button
                key={s}
                type="button"
                className="chip mono"
                aria-pressed={identity === s}
                onClick={() => setIdentity(s)}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="control-row">
            <span className="control-row__label">Transport</span>
            {(["tor", "direct", "offline"] as const).map((s) => (
              <button
                key={s}
                type="button"
                className="chip mono"
                aria-pressed={transport === s}
                onClick={() => setTransport(s)}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="control-row">
            <span className="control-row__label">Retention</span>
            {(["keep", "30-day", "7-day", "24-hour"] as const).map((s) => (
              <button
                key={s}
                type="button"
                className="chip mono"
                aria-pressed={retention === s}
                onClick={() => setRetention(s)}
              >
                {s}
              </button>
            ))}
          </div>

          {opened && (
            <p className="panel__note" role="status">
              Opened the <span className="mono">{opened}</span> field. Phase 1
              wires this to the explanation and control behind it.
            </p>
          )}
        </section>

        <section className="panel" aria-labelledby="type-h">
          <h2 id="type-h" className="panel__h">
            Typographic registers
          </h2>
          <p className="panel__note">
            Human content is sans. Machine-verifiable truth is mono. The
            typeface tells the reader which register they are in.
          </p>
          <p className="specimen-sans">
            Compare this number with your contact in person or over a call you
            trust.
          </p>
          <p className="specimen-mono">
            41927 30518 64203 97158 22640 38715
          </p>
          <p className="panel__note">
            Safety number specimen — grouped in fives, 20px mono, spaced for
            character-by-character comparison against another screen.
          </p>
        </section>

        <section className="panel" aria-labelledby="theme-h">
          <h2 id="theme-h" className="panel__h">
            Theme
          </h2>
          <p className="panel__note">
            Both themes ship from Phase 1. Every text token is measured against
            both surfaces in docs/DESIGN_SYSTEM.md §2.2.
          </p>
          <div className="control-row">
            <button
              type="button"
              className="button-primary"
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
            >
              Switch to {theme === "light" ? "dark" : "light"}
            </button>
          </div>
        </section>

        <footer className="shell__footer">
          <p>
            Pouch is unaudited student work. Do not rely on it if you face a
            serious adversary.
          </p>
        </footer>
      </main>
    </div>
  );
}
