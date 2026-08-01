/*
 * Screen 3 — Conversation view (SPEC §6.7.3).
 *
 * Custody Strip pinned at top, always. Messages in sans, timestamps in mono.
 * Message state is text, never an icon: `sending` / `sent` / `failed — retry`.
 *
 * The rule this screen must not break: the Custody Strip shows the state the
 * core reported, and when the core has not reported one yet, it shows the
 * cautious value rather than an optimistic guess.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { CustodyStrip } from "../components/CustodyStrip";
import type {
  IdentityState,
  RetentionState,
  TransportState,
} from "../components/CustodyStrip";
import { Manifest } from "../components/Manifest";
import type {
  ConversationView,
  MessageView,
  PouchBridge,
  SendResult,
} from "../lib/bridge";
import "./screens.css";

interface ConversationProps {
  bridge: PouchBridge;
  conversation: ConversationView;
  onBack: () => void;
  onOpenSafetyNumber: () => void;
}

/** Maps the core's label onto the Custody Strip's identity state. */
function identityState(label: string): IdentityState {
  if (label === "VERIFIED") return "verified";
  if (label === "KEY CHANGED") return "key-changed";
  // Anything else — including a value this build does not recognise — is
  // unverified. Never the reassuring one.
  return "unverified";
}

/** Maps the core's transport label onto the Custody Strip's state. */
function transportState(label: string | null): TransportState {
  if (label === "TOR") return "tor";
  if (label === "DIRECT") return "direct";
  // Before the first poll answers, the honest value is offline: the client has
  // not established that anything is reachable.
  return "offline";
}

interface Outgoing {
  id: string;
  body: string;
  state: "sending" | "sent" | "failed";
  error?: string;
  manifest?: SendResult;
}

/** The prefix `core::api::attachments::attachment_placeholder` writes. A
 * message with this body carries an attachment fetchable by its id — see
 * SPEC §7.1, §6.7.8. */
const ATTACHMENT_PREFIX = "[attachment] ";

/** The image formats the core will strip metadata from and accept (D-038).
 * Video is refused with an honest error rather than sent unstripped. */
const ACCEPTED_ATTACHMENT_TYPES = "image/jpeg,image/png,image/webp";

/**
 * Fetches and renders one attachment's stripped content.
 *
 * Loads on demand rather than the conversation loading every attachment
 * up front — a thread can hold many images, and nothing here needs them
 * until they are on screen.
 */
function AttachmentImage({
  bridge,
  messageId,
  fallbackLabel,
}: {
  bridge: PouchBridge;
  messageId: string;
  fallbackLabel: string;
}) {
  const [url, setUrl] = useState<string | null>(null);
  const [filename, setFilename] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let objectUrl: string | null = null;
    let cancelled = false;

    bridge
      .attachment(messageId)
      .then((a) => {
        if (cancelled || !a) return;
        const blob = new Blob([a.content]);
        objectUrl = URL.createObjectURL(blob);
        setUrl(objectUrl);
        setFilename(a.filename);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });

    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [bridge, messageId]);

  if (error) {
    return <p className="screen__error">{fallbackLabel} — {error}</p>;
  }
  if (!url) {
    return <p className="bubble__body">{fallbackLabel}</p>;
  }
  return (
    <figure className="attachment">
      <img className="attachment__image" src={url} alt={filename ?? fallbackLabel} />
      <figcaption className="mono">{filename}</figcaption>
    </figure>
  );
}

export function Conversation({
  bridge,
  conversation,
  onBack,
  onOpenSafetyNumber,
}: ConversationProps) {
  const [messages, setMessages] = useState<MessageView[]>([]);
  const [pending, setPending] = useState<Outgoing[]>([]);
  const [draft, setDraft] = useState("");
  const [transport, setTransport] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attaching, setAttaching] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const refresh = useCallback(async () => {
    try {
      setMessages(await bridge.messages(conversation.id));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [bridge, conversation.id]);

  useEffect(() => {
    void refresh();
    bridge
      .transportState()
      .then(setTransport)
      // A failure here leaves transport null, which renders OFFLINE. That is
      // the correct reading: the client could not confirm a route.
      .catch(() => setTransport(null));
  }, [bridge, refresh]);

  async function send(event: React.FormEvent) {
    event.preventDefault();
    const body = draft.trim();
    if (!body) return;

    const id = `pending-${Date.now()}`;
    setPending((p) => [...p, { id, body, state: "sending" }]);
    setDraft("");

    try {
      const result = await bridge.sendMessage(conversation.id, body);
      setPending((p) =>
        p.map((m) =>
          m.id === id
            ? { ...m, state: result.failed ? "failed" : "sent", manifest: result }
            : m,
        ),
      );
      if (!result.failed) await refresh();
    } catch (e) {
      setPending((p) =>
        p.map((m) =>
          m.id === id
            ? {
                ...m,
                state: "failed",
                error: e instanceof Error ? e.message : String(e),
              }
            : m,
        ),
      );
    }
  }

  async function attachAndSend(file: File) {
    const id = `pending-${Date.now()}`;
    const label = `${ATTACHMENT_PREFIX}${file.name}`;
    setAttaching(true);
    setPending((p) => [...p, { id, body: label, state: "sending" }]);

    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const result = await bridge.sendAttachment(
        conversation.id,
        file.name,
        bytes,
      );
      setPending((p) =>
        p.map((m) =>
          m.id === id
            ? { ...m, state: result.failed ? "failed" : "sent", manifest: result }
            : m,
        ),
      );
      if (!result.failed) await refresh();
    } catch (e) {
      setPending((p) =>
        p.map((m) =>
          m.id === id
            ? {
                ...m,
                state: "failed",
                error: e instanceof Error ? e.message : String(e),
              }
            : m,
        ),
      );
    } finally {
      setAttaching(false);
    }
  }

  async function poll() {
    try {
      await bridge.receiveMessages();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="conversation">
      <CustodyStrip
        identity={identityState(conversation.identity)}
        transport={transportState(transport)}
        // Retention controls arrive in Phase 2. `keep` is the actual default
        // and is shown in mute, which is what the strip does for a default.
        retention={"keep" as RetentionState}
        onOpenField={(field) => {
          if (field === "identity") onOpenSafetyNumber();
        }}
      />

      <header className="conversation__header">
        <button type="button" className="button-quiet" onClick={onBack}>
          Back
        </button>
        <h1 className="conversation__title">
          {conversation.contactName || "Unnamed contact"}
        </h1>
        <button type="button" className="button-quiet" onClick={poll}>
          Check for messages
        </button>
      </header>

      {error && (
        <p className="screen__error" role="alert">
          {error}
        </p>
      )}

      <ol className="thread">
        {messages.map((m) => (
          <li
            key={m.id}
            className={`bubble ${m.outgoing ? "bubble--sent" : "bubble--received"}`}
          >
            {m.body.startsWith(ATTACHMENT_PREFIX) ? (
              <AttachmentImage
                bridge={bridge}
                messageId={m.id}
                fallbackLabel={m.body}
              />
            ) : (
              <p className="bubble__body">{m.body}</p>
            )}
            <p className="bubble__meta mono">
              {new Date(m.at * 1000).toLocaleTimeString()}
            </p>
          </li>
        ))}

        {pending.map((m) => (
          <li key={m.id} className="bubble bubble--sent">
            <p className="bubble__body">{m.body}</p>
            <p
              className={`bubble__meta mono ${m.state === "failed" ? "bubble__meta--failed" : ""}`}
            >
              {m.state === "sending" && "sending"}
              {m.state === "sent" && "sent"}
              {m.state === "failed" && `failed — ${m.error ?? "not sent"}`}
            </p>
            {m.manifest && (
              <Manifest
                summary={m.manifest.summary}
                rows={m.manifest.rows}
                failed={m.manifest.failed}
                onOpenRelayVisibility={() =>
                  bridge.relayVisibility(m.body.length)
                }
              />
            )}
          </li>
        ))}
      </ol>

      <form className="composer" onSubmit={send}>
        <label className="visually-hidden" htmlFor="composer-input">
          Message
        </label>
        <input
          id="composer-input"
          className="composer__input"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Write a message"
        />
        <input
          ref={fileInput}
          type="file"
          accept={ACCEPTED_ATTACHMENT_TYPES}
          className="visually-hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (file) void attachAndSend(file);
          }}
        />
        <button
          type="button"
          className="button-quiet"
          disabled={attaching}
          onClick={() => fileInput.current?.click()}
        >
          {attaching ? "Sending image" : "Attach image"}
        </button>
        <button type="submit" className="button-primary" disabled={!draft.trim()}>
          Send
        </button>
      </form>
    </div>
  );
}
