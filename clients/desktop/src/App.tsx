/*
 * The shell: which screen is showing, and the one place the bridge is created.
 *
 * Routing is a discriminated union rather than a URL router. This is a desktop
 * app with a handful of screens and no addressable state, and a union means an
 * unreachable screen is a compile error rather than a blank page.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AddContact } from "./screens/AddContact";
import { Conversation } from "./screens/Conversation";
import { ConversationList } from "./screens/ConversationList";
import { FirstRun } from "./screens/FirstRun";
import { SafetyNumber } from "./screens/SafetyNumber";
import { SecurityDetails } from "./screens/SecurityDetails";
import { tauriBridge, type ConversationView, type PouchBridge } from "./lib/bridge";
import "./App.css";

type Route =
  | { name: "loading" }
  | { name: "first-run" }
  | { name: "list" }
  | { name: "conversation"; id: string }
  | { name: "safety"; contactId: string; contactName: string }
  | { name: "add-contact" }
  | { name: "security" };

export default function App({ bridge: injected }: { bridge?: PouchBridge } = {}) {
  const bridge = useMemo(() => injected ?? tauriBridge(invoke), [injected]);

  const [route, setRoute] = useState<Route>({ name: "loading" });
  const [conversations, setConversations] = useState<ConversationView[]>([]);
  const [error, setError] = useState<string | null>(null);

  const loadConversations = useCallback(async () => {
    setConversations(await bridge.conversations());
  }, [bridge]);

  const openList = useCallback(async () => {
    try {
      await loadConversations();
      setRoute({ name: "list" });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [loadConversations]);

  useEffect(() => {
    (async () => {
      try {
        if (await bridge.hasIdentity()) {
          await bridge.openIdentity();
          await openList();
        } else {
          setRoute({ name: "first-run" });
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        setRoute({ name: "first-run" });
      }
    })();
  }, [bridge, openList]);

  const current = conversations.find(
    (c) => route.name === "conversation" && c.id === route.id,
  );

  return (
    <div className="shell">
      {error && (
        <p className="screen__error shell__error" role="alert">
          {error}
        </p>
      )}

      {route.name === "loading" && <p className="screen">Opening…</p>}

      {route.name === "first-run" && (
        <FirstRun bridge={bridge} onCreated={openList} />
      )}

      {route.name === "list" && (
        <ConversationList
          conversations={conversations}
          onOpen={(id) => setRoute({ name: "conversation", id })}
          onAddContact={() => setRoute({ name: "add-contact" })}
          onSecurityDetails={() => setRoute({ name: "security" })}
        />
      )}

      {route.name === "conversation" && current && (
        <Conversation
          bridge={bridge}
          conversation={current}
          onBack={openList}
          onOpenSafetyNumber={() =>
            setRoute({
              name: "safety",
              contactId: current.contactId,
              contactName: current.contactName,
            })
          }
        />
      )}

      {route.name === "add-contact" && (
        <AddContact
          bridge={bridge}
          onAdded={() => void openList()}
          onBack={openList}
        />
      )}

      {route.name === "safety" && (
        <SafetyNumber
          bridge={bridge}
          contactId={route.contactId}
          contactName={route.contactName}
          onDone={openList}
        />
      )}

      {route.name === "security" && (
        <SecurityDetails bridge={bridge} onBack={openList} />
      )}
    </div>
  );
}
