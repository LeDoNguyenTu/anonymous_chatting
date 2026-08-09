/*
 * A `PouchBridge` for tests, where every call fails until a test says
 * otherwise.
 *
 * The point is the default. A fake whose unstubbed methods quietly return
 * `undefined` lets a screen call something the test never thought about and
 * still pass — which for this project's screens is the exact failure worth
 * catching, because a screen that silently gets nothing back is a screen that
 * renders a blank where a warning should be. Here an unstubbed call throws and
 * names itself, so the test fails and says which method it was.
 *
 * `bridge.ts` exists so screens can be tested against a fake rather than a
 * desktop window; this is that fake, written once so the next screen test does
 * not have to invent it again.
 */

import type { PouchBridge } from "./bridge";

/** Every method name on the bridge, so the proxy below can be exhaustive. */
const METHODS: (keyof PouchBridge)[] = [
  "hasIdentity",
  "createIdentity",
  "openIdentity",
  "displayName",
  "inviteCode",
  "addContact",
  "conversations",
  "messages",
  "sendMessage",
  "receiveMessages",
  "safetyNumber",
  "verifyContact",
  "transportState",
  "transportOptions",
  "connectTor",
  "useDirectRelay",
  "startLocalRelay",
  "stopLocalRelay",
  "localRelayStatus",
  "securityDetails",
  "relayVisibility",
  "wipeAll",
  "retentionPolicy",
  "setRetentionPolicy",
  "retentionChoices",
  "disappearingMessages",
  "setDisappearingMessages",
  "queuedCount",
  "identityChanges",
  "acknowledgeIdentityChange",
  "isPassphraseProtected",
  "setPassphrase",
  "clearPassphrase",
  "exportBackup",
  "importBackup",
  "sendAttachment",
  "attachment",
];

/**
 * Builds a bridge where `overrides` are answered and everything else throws.
 *
 * Rejecting rather than throwing synchronously, because every bridge method is
 * async and a screen's `.catch` is what would run in the real failure — a
 * synchronous throw would take a path production never takes.
 */
export function fakeBridge(overrides: Partial<PouchBridge> = {}): PouchBridge {
  const bridge = {} as Record<string, unknown>;
  for (const method of METHODS) {
    bridge[method] = () =>
      Promise.reject(
        new Error(
          `fakeBridge: ${method}() was called but this test did not stub it`,
        ),
      );
  }
  return Object.assign(bridge, overrides) as unknown as PouchBridge;
}
