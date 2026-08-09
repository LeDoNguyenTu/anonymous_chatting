/*
 * Hosting screen — the relay that ships inside this installer (D-051).
 *
 * Pouch used to be half a product on first run: the client installed, and the
 * relay it needed was a second binary someone downloaded separately and ran in
 * a terminal. This screen is the other half, and the reason the installer now
 * carries both.
 *
 * ## What this screen must never do
 *
 * Show an address that is not currently being served. An onion address is
 * something the user copies and sends to another person; one that outlives the
 * relay that published it sends that person somewhere nothing is listening, and
 * the failure looks like the other person ignoring them. So the address is
 * rendered straight from the latest status and never from remembered state —
 * when `running` goes false the address disappears with it.
 *
 * Split in two like `TransportSettings`: `RelayHostingView` is pure so its
 * honesty rules can be asserted with `renderToStaticMarkup`, and the container
 * does the polling.
 */

import { useCallback, useEffect, useState } from "react";
import type { LocalRelayStatus, PouchBridge } from "../lib/bridge";
import "./screens.css";

interface RelayHostingViewProps {
  status: LocalRelayStatus | null;
  busy: boolean;
  error: string | null;
  onStart: () => void;
  onStop: () => void;
  onCopy: (address: string) => void;
  onBack: () => void;
}

export function RelayHostingView({
  status,
  busy,
  error,
  onStart,
  onStop,
  onCopy,
  onBack,
}: RelayHostingViewProps) {
  const running = status?.running === true;
  // Only ever from the live status. See the note at the top of this file.
  const address = running ? status?.onionAddress : null;
  const publishing = running && !address;

  return (
    <main className="screen screen--narrow">
      <h1 className="screen__title">Host a relay</h1>
      <p className="screen__lede">
        A relay holds encrypted messages until the other person collects them.
        It cannot read any of them.
      </p>

      {error && (
        <p className="screen__error" role="alert">
          {error}
        </p>
      )}
      {status?.error && (
        <p className="screen__error" role="alert">
          {status.error}
        </p>
      )}

      {!running && (
        <>
          <p className="screen__note">
            Nothing is being hosted from this device. You can still use Pouch —
            you need somebody&apos;s relay address, either yours or theirs.
          </p>
          <p className="screen__footnote">
            Starting one publishes a Tor address and accepts traffic for as long
            as Pouch is open. Messages sent to it while your computer is off are
            not delivered: there is no always-on server behind this, and closing
            Pouch closes the relay.
          </p>
        </>
      )}

      {publishing && (
        <p className="screen__note" role="status">
          Starting. Publishing a Tor address takes tens of seconds the first
          time. This screen will show the address when there is one.
        </p>
      )}

      {address && (
        <section className="panel">
          <h2 className="panel__title">Your relay address</h2>
          <p className="mono-block">{address}</p>
          <button type="button" className="button" onClick={() => onCopy(address)}>
            Copy address
          </button>
          <p className="panel__note">
            Send this to the person you want to talk to. They paste it into
            their own copy of Pouch. It is not secret in the way a key is — the
            relay cannot read anything — but anyone holding it can reach your
            relay, so do not post it publicly.
          </p>
        </section>
      )}

      <div className="screen__actions">
        {running ? (
          <button
            type="button"
            className="button"
            onClick={onStop}
            disabled={busy}
          >
            Stop hosting
          </button>
        ) : (
          <button
            type="button"
            className="button"
            onClick={onStart}
            disabled={busy}
          >
            Start hosting
          </button>
        )}
        <button type="button" className="button-quiet" onClick={onBack}>
          Back
        </button>
      </div>

      <p className="screen__footnote">
        Stopping does not erase what the relay is holding. Blobs stay in its
        database until their expiry passes, encrypted, unreadable by it.
      </p>
    </main>
  );
}

interface RelayHostingProps {
  bridge: PouchBridge;
  onBack: () => void;
}

/** How often the status is re-read while the window is on this screen. */
const POLL_MS = 2000;

export function RelayHosting({ bridge, onBack }: RelayHostingProps) {
  const [status, setStatus] = useState<LocalRelayStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setStatus(await bridge.localRelayStatus());
  }, [bridge]);

  // Polled rather than pushed. The interesting transition — an onion address
  // appearing — happens tens of seconds after the start call resolves, in a
  // different process, so there is nothing to await on.
  useEffect(() => {
    let cancelled = false;
    const tick = () => {
      if (cancelled) return;
      refresh().catch((e) =>
        setError(e instanceof Error ? e.message : String(e)),
      );
    };
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [refresh]);

  async function run(action: () => Promise<LocalRelayStatus>) {
    setBusy(true);
    setError(null);
    try {
      setStatus(await action());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      // Re-read rather than assume. A start that threw may still have left a
      // process running, and showing "stopped" over a relay that is up would
      // have the user start a second one.
      await refresh().catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }

  return (
    <RelayHostingView
      status={status}
      busy={busy}
      error={error}
      onStart={() => void run(() => bridge.startLocalRelay())}
      onStop={() => void run(() => bridge.stopLocalRelay())}
      onCopy={(address) => void navigator.clipboard?.writeText(address)}
      onBack={onBack}
    />
  );
}
