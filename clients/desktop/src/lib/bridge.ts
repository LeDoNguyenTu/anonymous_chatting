/*
 * The boundary between the interface and the core.
 *
 * Every call the UI can make is declared here, once, as a type. That matters
 * for more than convenience: this file is the readable answer to "what can the
 * interface actually do", and anything absent from it is something no screen
 * can reach. There is deliberately no escape hatch that forwards an arbitrary
 * command name.
 *
 * `PouchBridge` is an interface rather than a set of free functions so screens
 * can be tested against a fake. A UI whose honesty rules can only be verified
 * by launching a desktop window is a UI whose honesty rules do not get
 * verified.
 */

/** The Custody Strip's identity field. Mirrors `IdentityState` in the core. */
export type IdentityLabel = "VERIFIED" | "UNVERIFIED" | "KEY CHANGED";

/** The Custody Strip's transport field. Mirrors `Route` in the core. */
export type TransportLabel = "DIRECT" | "TOR" | "OFFLINE";

export interface ConversationView {
  id: string;
  contactId: string;
  contactName: string;
  identity: IdentityLabel;
  lastMessage: string | null;
}

export interface MessageView {
  id: string;
  outgoing: boolean;
  body: string;
  at: number;
}

export interface ManifestRow {
  number: number;
  label: string;
  detail: string;
  ran: boolean;
}

export interface SendResult {
  summary: string;
  rows: ManifestRow[];
  failed: boolean;
}

export interface RelayVisibilityView {
  inboxId: string;
  blobSize: number;
  visible: string[];
  notVisible: string[];
  stillInferable: string[];
}

export interface SecurityDetailsView {
  ciphersuite: string;
  aead: string;
  keyAgreement: string;
  signature: string;
  kdf: string;
  protocol: string;
  localDatabase: string;
  passphraseDerivation: string;
  transport: string;
  relayAddress: string;
  openmlsVersion: string;
  appVersion: string;
}

export interface PouchBridge {
  hasIdentity(): Promise<boolean>;
  createIdentity(displayName: string): Promise<string>;
  openIdentity(): Promise<void>;
  displayName(): Promise<string>;
  inviteCode(): Promise<string>;
  addContact(displayName: string, code: string): Promise<string>;
  conversations(): Promise<ConversationView[]>;
  messages(conversationId: string): Promise<MessageView[]>;
  sendMessage(conversationId: string, body: string): Promise<SendResult>;
  receiveMessages(): Promise<MessageView[]>;
  safetyNumber(contactId: string): Promise<string>;
  verifyContact(contactId: string, verified: boolean): Promise<void>;
  transportState(): Promise<TransportLabel>;
  securityDetails(): Promise<SecurityDetailsView>;
  relayVisibility(blobSize: number): Promise<RelayVisibilityView>;
  wipeAll(): Promise<void>;
}

/* -- wire shapes -----------------------------------------------------------
 * The Rust side serialises snake_case. Converting at the boundary keeps the
 * rest of the codebase in one naming convention, and keeps the conversion in
 * one place where it can be read.
 */

interface WireConversation {
  id: string;
  contact_id: string;
  contact_name: string;
  identity: string;
  last_message: string | null;
}

interface WireSendResult {
  summary: string;
  rows: ManifestRow[];
  failed: boolean;
}

interface WireRelayVisibility {
  inbox_id: string;
  blob_size: number;
  visible: string[];
  not_visible: string[];
  still_inferable: string[];
}

interface WireSecurityDetails {
  ciphersuite: string;
  aead: string;
  key_agreement: string;
  signature: string;
  kdf: string;
  protocol: string;
  local_database: string;
  passphrase_derivation: string;
  transport: string;
  relay_address: string;
  openmls_version: string;
  app_version: string;
}

/**
 * Narrows a string from the core to an identity label.
 *
 * An unrecognised value becomes `UNVERIFIED`, not `VERIFIED`. If the two sides
 * ever disagree about the vocabulary, the interface must fail towards the
 * amber state — showing a reassuring label for a state it does not understand
 * is exactly what Prime Directive 3 forbids.
 */
export function asIdentityLabel(value: string): IdentityLabel {
  return value === "VERIFIED" || value === "KEY CHANGED" ? value : "UNVERIFIED";
}

/**
 * Narrows a string from the core to a transport label.
 *
 * Same rule, same reason: anything unrecognised is `OFFLINE` rather than
 * `TOR`, because claiming an onion circuit that is not there would be a lie
 * about where the message went.
 */
export function asTransportLabel(value: string): TransportLabel {
  return value === "TOR" || value === "DIRECT" ? value : "OFFLINE";
}

/** The real bridge, talking to the Rust side over Tauri IPC. */
export function tauriBridge(
  invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>,
): PouchBridge {
  return {
    hasIdentity: () => invoke<boolean>("has_identity"),

    createIdentity: (displayName) =>
      invoke<string>("create_identity", { displayName }),

    openIdentity: () => invoke<void>("open_identity"),

    displayName: () => invoke<string>("display_name"),

    inviteCode: () => invoke<string>("invite_code"),

    addContact: (displayName, code) =>
      invoke<string>("add_contact", { displayName, code }),

    conversations: async () => {
      const rows = await invoke<WireConversation[]>("conversations");
      return rows.map((r) => ({
        id: r.id,
        contactId: r.contact_id,
        contactName: r.contact_name,
        identity: asIdentityLabel(r.identity),
        lastMessage: r.last_message,
      }));
    },

    messages: (conversationId) =>
      invoke<MessageView[]>("messages", { conversationId }),

    sendMessage: async (conversationId, body) => {
      const r = await invoke<WireSendResult>("send_message", {
        conversationId,
        body,
      });
      return { summary: r.summary, rows: r.rows, failed: r.failed };
    },

    receiveMessages: () => invoke<MessageView[]>("receive_messages"),

    safetyNumber: (contactId) =>
      invoke<string>("safety_number", { contactId }),

    verifyContact: (contactId, verified) =>
      invoke<void>("verify_contact", { contactId, verified }),

    transportState: async () =>
      asTransportLabel(await invoke<string>("transport_state")),

    securityDetails: async () => {
      const d = await invoke<WireSecurityDetails>("security_details");
      return {
        ciphersuite: d.ciphersuite,
        aead: d.aead,
        keyAgreement: d.key_agreement,
        signature: d.signature,
        kdf: d.kdf,
        protocol: d.protocol,
        localDatabase: d.local_database,
        passphraseDerivation: d.passphrase_derivation,
        transport: d.transport,
        relayAddress: d.relay_address,
        openmlsVersion: d.openmls_version,
        appVersion: d.app_version,
      };
    },

    relayVisibility: async (blobSize) => {
      const v = await invoke<WireRelayVisibility>("relay_visibility", {
        blobSize,
      });
      return {
        inboxId: v.inbox_id,
        blobSize: v.blob_size,
        visible: v.visible,
        notVisible: v.not_visible,
        stillInferable: v.still_inferable,
      };
    },

    wipeAll: () => invoke<void>("wipe_all"),
  };
}
