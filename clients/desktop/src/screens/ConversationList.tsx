/*
 * Screen 2 — Conversation list (SPEC §6.7.2).
 *
 * Job: show who is waiting, and nothing else.
 *
 * No unread-count badges: a count that tracks notification traffic is a count
 * an observer of that traffic can infer. Rows carry an amber dot where identity
 * is unverified, paired with a text label, because state is never conveyed
 * through colour alone.
 */

import type { ConversationView } from "../lib/bridge";
import "./screens.css";

interface ConversationListProps {
  conversations: ConversationView[];
  onOpen: (id: string) => void;
  onAddContact: () => void;
  onSecurityDetails: () => void;
  onPrivacyStorage: () => void;
}

export function ConversationList({
  conversations,
  onOpen,
  onAddContact,
  onSecurityDetails,
  onPrivacyStorage,
}: ConversationListProps) {
  return (
    <main className="screen">
      <header className="screen__header">
        <h1 className="screen__title">Conversations</h1>
        <div className="screen__actions">
          <button type="button" className="button-quiet" onClick={onAddContact}>
            Add someone
          </button>
          <button type="button" className="button-quiet" onClick={onPrivacyStorage}>
            Privacy and storage
          </button>
          <button type="button" className="button-quiet" onClick={onSecurityDetails}>
            Security details
          </button>
        </div>
      </header>

      {conversations.length === 0 ? (
        <div className="empty">
          <p className="empty__copy">
            No conversations yet. Add someone using their invite code.
          </p>
          <button type="button" className="button-primary" onClick={onAddContact}>
            Add someone
          </button>
        </div>
      ) : (
        <ul className="conversations">
          {conversations.map((c) => (
            <li key={c.id}>
              <button
                type="button"
                className="conversation-row"
                onClick={() => onOpen(c.id)}
              >
                <span className="conversation-row__top">
                  <span className="conversation-row__name">
                    {c.contactName || "Unnamed contact"}
                  </span>
                  <span
                    className={`badge badge--${c.identity === "VERIFIED" ? "verified" : c.identity === "KEY CHANGED" ? "alarm" : "pending"} mono`}
                  >
                    {c.identity}
                  </span>
                </span>
                <span className="conversation-row__preview">
                  {c.lastMessage ?? "No messages yet"}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
