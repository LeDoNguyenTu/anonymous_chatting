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

/**
 * One transport the user can choose, on the Transport settings screen.
 *
 * `route` is the same token `transportState()` returns, so the screen can tell
 * which option is active by comparing the two rather than tracking a second,
 * drift-prone idea of the current transport. `name` and `explanation` are the
 * core's own words — nothing here is written twice.
 */
export interface TransportOption {
  route: TransportLabel;
  name: string;
  explanation: string;
}

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

/**
 * How long this device keeps messages.
 *
 * The wire values, not the labels. Kept as a union so a screen cannot invent a
 * setting the core does not implement.
 */
export type RetentionValue = "forever" | "30d" | "7d" | "24h";

export interface RetentionChoice {
  value: RetentionValue;
  label: string;
}

export interface IdentityChangeView {
  contactId: string;
  contactName: string;
  changedAt: number;
}

/** What the export screen shows and turns into a download (SPEC §6.7.10). */
export interface ExportBackupView {
  recoveryKeyHex: string;
  backup: Uint8Array;
  fileName: string;
}

/** What the import screen reports once a restore succeeds. */
export interface ImportBackupView {
  displayName: string;
  conversationCount: number;
}

/** A sent or received attachment's stripped content (SPEC §7.1, §6.7.8). */
export interface AttachmentView {
  filename: string;
  content: Uint8Array;
}

/**
 * What the bundled relay is doing (D-050).
 *
 * Four fields rather than one enum because the interesting states are
 * combinations: running with no address yet (Tor is still publishing), running
 * with an address (ready to share), stopped with an error (it died and the
 * reason matters), stopped without one (nobody started it).
 *
 * `onionAddress` is `null` until the relay prints one. A screen must show the
 * address only when this field carries it — never a remembered value, because a
 * remembered address outlives the relay that owned it and would send a friend
 * to something that is no longer listening.
 */
export interface LocalRelayStatus {
  running: boolean;
  onionAddress: string | null;
  bindAddress: string | null;
  error: string | null;
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

  /* Transport settings (SPEC §6.7.9). `connectTor` is slow — a real Tor
   * bootstrap — and rejects rather than falling back to the direct route, so
   * a screen must not treat a rejection as "still fine". */
  transportOptions(): Promise<TransportOption[]>;
  connectTor(): Promise<void>;
  useDirectRelay(): Promise<void>;

  /* The bundled relay (D-050). `startLocalRelay` is slow — publishing an onion
   * service takes tens of seconds — and its resolution means the process
   * started, not that an address exists yet. `localRelayStatus` is what says
   * whether there is an address, and it is the only thing a screen may show an
   * address from: a screen that remembers one it printed earlier would keep
   * showing it after the relay died. */
  startLocalRelay(): Promise<LocalRelayStatus>;
  stopLocalRelay(): Promise<LocalRelayStatus>;
  localRelayStatus(): Promise<LocalRelayStatus>;
  securityDetails(): Promise<SecurityDetailsView>;
  relayVisibility(blobSize: number): Promise<RelayVisibilityView>;
  wipeAll(): Promise<void>;

  /* Storage controls (SPEC §6.7.7). Each mutating call returns how many
   * messages it deleted, so the screen can report the consequence rather than
   * leaving the user to guess. */
  retentionPolicy(): Promise<RetentionValue>;
  setRetentionPolicy(policy: RetentionValue): Promise<number>;
  retentionChoices(): Promise<RetentionChoice[]>;
  disappearingMessages(conversationId: string): Promise<number | null>;
  setDisappearingMessages(
    conversationId: string,
    seconds: number | null,
  ): Promise<number>;
  queuedCount(): Promise<number>;
  identityChanges(): Promise<IdentityChangeView[]>;
  acknowledgeIdentityChange(contactId: string): Promise<void>;
  isPassphraseProtected(): Promise<boolean>;
  setPassphrase(passphrase: string): Promise<void>;
  clearPassphrase(): Promise<void>;

  /* Backup export/import (SPEC §6.7.10, §7.3). Export is only meaningful on a
   * device that already has an identity open; import is only meaningful on
   * one that does not — `Pouch::import_backup` creates a device from
   * nothing, the same precondition `createIdentity` has. */
  exportBackup(): Promise<ExportBackupView>;
  importBackup(
    recoveryKeyHex: string,
    backup: Uint8Array,
  ): Promise<ImportBackupView>;

  /* Attachments (SPEC §7.1, §6.7.8). Images only (JPEG/PNG/WebP) — a video
   * file is refused by the core with an honest error, not silently sent
   * unstripped (D-038). */
  sendAttachment(
    conversationId: string,
    filename: string,
    bytes: Uint8Array,
  ): Promise<SendResult>;
  attachment(messageId: string): Promise<AttachmentView | null>;
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

interface WireTransportOption {
  route: string;
  name: string;
  explanation: string;
}

interface WireIdentityChange {
  contact_id: string;
  contact_name: string;
  changed_at: number;
}

interface WireExportBackup {
  recovery_key_hex: string;
  backup: number[];
  file_name: string;
}

interface WireImportBackup {
  display_name: string;
  conversation_count: number;
}

interface WireAttachment {
  filename: string;
  content: number[];
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

/**
 * Narrows a string from the core to a retention setting.
 *
 * Same rule as the two above, applied to the setting whose failure mode is
 * deletion: anything unrecognised becomes `forever`. If the interface cannot
 * tell what the device is set to, it must not act as though messages are being
 * deleted on a schedule it invented, and it must never round *towards* a
 * shorter retention than the user chose.
 */
export function asRetentionValue(value: string): RetentionValue {
  return value === "30d" || value === "7d" || value === "24h"
    ? value
    : "forever";
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

    transportOptions: async () => {
      const rows = await invoke<WireTransportOption[]>("transport_options");
      return rows.map((r) => ({
        route: asTransportLabel(r.route),
        name: r.name,
        explanation: r.explanation,
      }));
    },

    connectTor: () => invoke<void>("connect_tor"),

    useDirectRelay: () => invoke<void>("use_direct_relay"),

    startLocalRelay: () => invoke<LocalRelayStatus>("start_local_relay"),

    stopLocalRelay: () => invoke<LocalRelayStatus>("stop_local_relay"),

    localRelayStatus: () => invoke<LocalRelayStatus>("local_relay_status"),

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

    retentionPolicy: async () =>
      asRetentionValue(await invoke<string>("retention_policy")),

    setRetentionPolicy: (policy) =>
      invoke<number>("set_retention_policy", { policy }),

    retentionChoices: async () => {
      const rows = await invoke<[string, string][]>("retention_choices");
      return rows.map(([value, label]) => ({
        value: asRetentionValue(value),
        label,
      }));
    },

    disappearingMessages: async (conversationId) => {
      const seconds = await invoke<number | null>("disappearing_messages", {
        conversationId,
      });
      return seconds ?? null;
    },

    setDisappearingMessages: (conversationId, seconds) =>
      invoke<number>("set_disappearing_messages", { conversationId, seconds }),

    queuedCount: () => invoke<number>("queued_count"),

    identityChanges: async () => {
      const rows = await invoke<WireIdentityChange[]>("identity_changes");
      return rows.map((r) => ({
        contactId: r.contact_id,
        contactName: r.contact_name,
        changedAt: r.changed_at,
      }));
    },

    acknowledgeIdentityChange: (contactId) =>
      invoke<void>("acknowledge_identity_change", { contactId }),

    isPassphraseProtected: () => invoke<boolean>("is_passphrase_protected"),

    setPassphrase: (passphrase) =>
      invoke<void>("set_passphrase", { passphrase }),

    clearPassphrase: () => invoke<void>("clear_passphrase"),

    sendAttachment: async (conversationId, filename, bytes) => {
      const r = await invoke<WireSendResult>("send_attachment", {
        conversationId,
        filename,
        bytes: Array.from(bytes),
      });
      return { summary: r.summary, rows: r.rows, failed: r.failed };
    },

    attachment: async (messageId) => {
      const r = await invoke<WireAttachment | null>("attachment", {
        messageId,
      });
      return r ? { filename: r.filename, content: Uint8Array.from(r.content) } : null;
    },

    exportBackup: async () => {
      const r = await invoke<WireExportBackup>("export_backup");
      return {
        recoveryKeyHex: r.recovery_key_hex,
        backup: Uint8Array.from(r.backup),
        fileName: r.file_name,
      };
    },

    importBackup: async (recoveryKeyHex, backup) => {
      const r = await invoke<WireImportBackup>("import_backup", {
        recoveryKeyHex,
        backup: Array.from(backup),
      });
      return {
        displayName: r.display_name,
        conversationCount: r.conversation_count,
      };
    },
  };
}
