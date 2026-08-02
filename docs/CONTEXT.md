# Working context for Pouch

Start-of-session notes: what this project is, the rules that govern it, and
where the work stands.

Read this, then `PROGRESS.md`, then SPEC §1, §2, and the section for the
current phase. That is enough to resume without re-reading session history.

---

## What this project is

An end-to-end encrypted messenger built on MLS (RFC 9420), with a relay designed
to store nothing worth stealing. Author: Le Do Nguyen Tu (Brian). Portfolio
project, built in phases.

`SPEC.md` at the repository root is the authoritative build specification. **It
wins over any in-session request on security matters.** If a request conflicts
with it, say so and quote the section.

## The five rules that override everything

1. **Do not invent cryptography.** No custom ciphers, protocols, KDFs, padding,
   or nonce generation. Audited libraries through their intended interfaces.
2. **No security theatre.** Never claim unbreakable, uncrackable, military grade,
   or stronger than Signal — anywhere, including commit messages.
3. **Honesty about limits is a feature.** The UI must never show a reassuring
   indicator when the underlying state is uncertain.
4. **Ship narrow and working.** Do not start a phase before the previous one
   meets its exit criteria.
5. **When uncertain about a security decision, stop and ask.** The list is
   SPEC §2.6.

## Conventions that are easy to get wrong

- **Git author is `Brian <188601252+LeDoNguyenTu@users.noreply.github.com>`** —
  the GitHub noreply address, deliberately, so the owner's real address stays
  out of public commit metadata. Commits carry no co-author trailers and no
  third-party attribution of any kind.
- **Branch:** `develop`. Push after each phase.
- **Pin every dependency with `=`.** Record any version change in
  `docs/DECISIONS.md`. `openmls` breaks its API across minor versions.
- **`docs/DECISIONS.md` is append-only.** Supersede, never edit away.
- **Update `docs/PROGRESS.md` before finishing a session.**
- **Bump the version number after each phase or each critical fix** — project
  owner instruction, 2026-08-02. Four places have to move together: root
  `Cargo.toml`'s `[workspace.package] version` (covers `core`, `server`,
  `clients/cli`), `clients/desktop/src-tauri/Cargo.toml`'s own `version`
  (outside the workspace, not inherited), `clients/desktop/src-tauri/tauri.conf.json`'s
  `version`, and `clients/desktop/package.json`'s `version`. `SecurityDetailsView.app_version`
  reads `env!("CARGO_PKG_VERSION")` from the desktop crate's own `Cargo.toml`
  at compile time, which is why that one has to move even though it is not
  part of the workspace.
- The UI layer never touches a key, a cipher, or a raw ciphertext blob. If a
  client seems to need one, the core is missing an operation — add it to
  `core/src/api.rs` rather than reaching around it.
- Components use semantic CSS tokens (`--fg-*`), never brand tokens
  (`--amber`, `--seal`) directly. Brand tokens fail contrast in one theme or the
  other; that is why the semantic layer exists.

## Layout

```
core/                 Rust — all crypto, storage, transport. api.rs is the
                      only surface clients touch. unsafe_code forbidden.
server/               Rust relay — axum + SQLite. Four fields, no logs.
clients/desktop/      Tauri v2 + React. Excluded from the Cargo workspace
                      because it needs WebKitGTK.
clients/cli/          Headless client. Makes the Phase 1 exit criterion
                      testable in CI.
docs/                 THREAT_MODEL, DECISIONS, ARCHITECTURE, LIMITATIONS,
                      DESIGN_SYSTEM, PROGRESS.
scripts/              check-guardrails.sh, check-contrast.mjs — both run in CI
                      and both fail the build.
```

## Verifying locally

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/check-guardrails.sh
node scripts/check-contrast.mjs
cd clients/desktop && npm ci && npm run typecheck && npm test && npm run build
```

The Tauri shell cannot be compiled in a headless container — no GTK or
WebKitGTK. Its CI job installs them. Do not treat a local failure to build it as
a code defect without checking that first.

## Settled decisions worth not relitigating

Full reasoning is in `docs/DECISIONS.md` (D-001…D-038). The short version:

- Name is **Pouch** (D-015); "Courier" in the spec was a placeholder.
- MLS via `openmls =0.8.1`, not Signal Protocol (D-002).
- Starting ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (D-003).
  AES-**128** is deliberate and is not a weakness — do not "upgrade" it to look
  serious.
- Cipher cascading is permanently rejected (D-005). Hybrid X25519 + ML-KEM-768
  is the only legitimate combining (D-004).
- AEAD is only ever invoked through MLS; application code never picks a nonce
  (D-006) — **except** the one narrow, project-owner-approved exception in
  D-037: a fresh, single-use AES-128-GCM key per file, for exactly the case
  D-006 does not cover (a file is not a group message). No new dependency —
  it calls the same audited backend already in the tree. Backup export and
  the attachment pipeline both use it — done.
- Attachment metadata stripping is `img-parts`, scoped to JPEG/PNG/WebP —
  video is explicitly refused, not silently sent unstripped (D-038). The
  attachment blob uploads to a random relay identifier of its own, never
  either party's inbox and never inside an MLS message — no relay change,
  since a "bucket id" is just another opaque id the existing
  `POST /inbox/{id}` already accepts.
- Relay stores four fields, `message_id` random rather than sequential (D-010).
- Compress → pad → encrypt, each payload compressed in isolation (D-009).
  Compression itself now runs, unconditionally, no size threshold (D-036) —
  padding still does not.
- Phases 1–3 use a self-signed relay certificate pinned by SPKI hash (D-017).
- SHA-256 is a hash, not encryption (D-001). It appears only inside HKDF.
- The offline queue stores ciphertext, never plaintext (D-031) — encrypting
  advances the MLS ratchet, so a retry re-POSTs the blob rather than
  re-encrypting it.
- `secure_delete` is on for every open, not only at wipe (D-032) — retention
  exists to limit what a later compromise can reach, and an unlinked-but-not-
  overwritten row defeats that between deletes.
- A passphrase-protected database with no passphrase supplied is a hard error,
  never a fallback to the placeholder key (D-035).

## Where things stand

Phases 0, 1, and 2 are code complete — **Phase 2 fully**, including backup
export/import (D-037), wired all the way through the desktop client
(`commands.rs`, `bridge.ts`, `BackupRestore.tsx`). **Phase 3 meets its exit
criteria**: compression (D-036), and the attachment pipeline — strip
(D-038, `img-parts`, images only), pad, encrypt (D-037's shape), upload to
a random relay bucket id — are built in `core`, the CLI, **and the desktop
client** (`Conversation.tsx`'s "Attach image" button and `AttachmentImage`
component). Sealed sender stays out of Phase 3's exit requirement, moved
to Phase 4 (SPEC.md's phase table says so): the relay's wire protocol
already carries no sender field, so what remains is the TCP/TLS source IP
a direct connection exposes, which only Tor removes.

Two things are deliberately not built, both recorded as scoped decisions
rather than gaps: SPEC §6.7.8's *dedicated pre-send* attachment preview
screen (what ships shows the same manifest information *after* sending,
reusing the existing `Manifest` component rather than a separate step),
and offline-queue retry for a failed attachment blob upload (unlike a text
message, attachment encryption never touches the MLS ratchet, so a manual
retry has none of the cost D-028 built the message-retry queue to avoid —
see `docs/PROGRESS.md`'s Phase 3 section for the full reasoning).

**Phase 4 (Tor transport, then sealed sender) is in progress, not
complete** — 1 of 14 planned tasks done. The work is happening in an
isolated worktree, not on this branch directly: `.worktrees/phase-4-tor/`
on branch `phase-4-tor-sealed-sender` (pushed to origin), driven by the
plan at `docs/superpowers/plans/2026-08-02-phase-4-tor-and-sealed-sender.md`
via `superpowers:subagent-driven-development`. Task 1 (pinning
`arti-client`/`tor-hsservice`/`tor-rtcompat`) surfaced a real dependency
conflict with the existing `rusqlite` pin, resolved and recorded as D-040 —
see `docs/PROGRESS.md`'s new Phase 4 section for the summary, or the SDD
ledger inside the worktree for the exact task-by-task state. **Resume
there, not by re-planning from scratch.**

163 Rust tests and 36 frontend tests pass, verified locally on Windows; the
Phase 2, initial-compression, and desktop-backup-UI commits are confirmed
green via `gh run list`. The attachment pipeline and desktop attachment UI
commits have not yet been observed going green in GitHub Actions — confirm
before trusting them the way Phase 0/1's "CI green" was trusted. Anything
that touches a screen (backup, attachments) has also never been seen in a
running window — this environment cannot launch the Tauri shell — so
"verified" for those means build/typecheck/test only, not a GUI
click-through. One CSP change shipped blind for exactly this reason:
`tauri.conf.json`'s `img-src`/`default-src` now allow `blob:` so an
`<img>` tag and the backup screen's download link can use object URLs —
correct on paper, unverified in a real window.

The version number moved to `0.1.1`, then `0.1.2`, this session — bump it
after each phase or critical fix from here on (project owner instruction,
see the conventions list above for the four files that have to move
together).

Full detail, the runnable demo, the manual checks still owed, and the ordered
list of what is next are in `docs/PROGRESS.md`. Read that before starting work.

## The map of the code

`core/src/api/` and `core/src/storage/` are directories, not single files —
have been since Phase 1. If you find yourself looking for `api.rs` or
`storage.rs`, that is this table having been wrong before; it is fixed now.

| File | What lives there |
|---|---|
| `core/src/api/mod.rs` | `Pouch` — the only type clients touch. Start here. |
| `core/src/api/storage_controls.rs` | Retention, disappearing messages, identity-change acknowledgement, passphrase set/clear |
| `core/src/api/messaging.rs` | Send, receive, and `flush_outbox` — the offline-queue retry |
| `core/src/api/compression.rs` | Per-message zstd, isolated calls only — D-036 |
| `core/src/api/backup.rs` | Backup file format, export/import — D-037 |
| `core/src/api/attachments.rs` | `send_attachment`, attachment fetch/open, the random-bucket-id upload — SPEC §7.1 |
| `core/src/attachments/` | Strip (`metadata.rs`, `img-parts`, images only — D-038), pad (`padding.rs`), and `prepare`/`open` (`mod.rs`, D-037's AEAD shape) |
| `core/src/crypto/file_crypto.rs` | The AEAD-outside-MLS exception itself: fresh-key AES-128-GCM + HKDF, no new dependency — D-037 |
| `core/src/crypto/identity.rs` | Identity creation, invite codes |
| `core/src/crypto/session.rs` | MLS groups, encrypt, decrypt, ratchet config |
| `core/src/crypto/safety_number.rs` | 60-digit out-of-band verification |
| `core/src/crypto/provider.rs` | MLS provider with reachable, snapshottable storage |
| `core/src/storage/mod.rs` | SQLCipher open/wipe/rekey. Holds plaintext and keys. |
| `core/src/storage/schema.rs` | Versioned migrations, tracked in `PRAGMA user_version` |
| `core/src/storage/settings.rs` | Retention policy, per-conversation disappearing messages, purge |
| `core/src/storage/outbox.rs` | The offline queue's storage — holds ciphertext, not plaintext |
| `core/src/storage/attachments.rs` | Received attachment content (schema v3), keyed by the message id that references it |
| `core/src/transport.rs` | Relay client, pinning policy |
| `core/src/manifest.rs` | The per-message record of what actually ran |
| `core/src/keying.rs` | Where the database key comes from: device-file placeholder or Argon2id passphrase. OS keystore route still not implemented — see D-035. |
| `server/src/store.rs` | The relay's four columns |
| `server/src/http.rs` | Three endpoints, no logging middleware |
| `clients/cli/src/commands/storage.rs` | `keep`, `disappear`, `queue`, `changes`, `acknowledge`, `passphrase` |
| `clients/cli/src/commands/backup.rs` | `backup export`, `backup import` |
| `clients/cli/src/commands/attachments.rs` | `send-file`, `save-attachment` |
| `clients/desktop/src-tauri/src/commands.rs` | 30 IPC commands, each one `Pouch` call — includes `export_backup`/`import_backup` |
| `clients/desktop/src/lib/bridge.ts` | The typed IPC boundary. No passthrough by design. |
| `clients/desktop/src/screens/PrivacyStorage.tsx` | Screen 7, SPEC §6.7.7 |
| `clients/desktop/src/screens/BackupRestore.tsx` | Screen 10, SPEC §6.7.10 — export (from Privacy and storage) and import (from First run), gated by the same has-an-identity-or-not precondition `core` already has |
| `clients/desktop/src/components/IdentityChangeModal.tsx` | Screen 6, SPEC §6.7.6 — the one modal in the product |

## Hard-won lessons from Phase 1

Each of these cost real debugging time. They are in `docs/DECISIONS.md` in full.

- **A security control that fails silently is worse than one that is absent**
  (D-024). Two `rusqlite` entries in the workspace unified into a plain SQLite
  build; `PRAGMA key` was silently ignored and every local database was
  plaintext while the app reported an encrypted store. There is now a runtime
  `PRAGMA cipher_version` check. Anywhere the project depends on a library
  actually doing something, check that it did — do not assume an error would
  have surfaced.
- **Persisting state and rehydrating it are different jobs** (D-027).
  Conversations vanished on restart while their keys sat intact on disk.
- **Two individually correct decisions can produce a defect between them**
  (D-028). The relay returns blobs in random order for privacy; MLS tolerates 5
  out of order by default; a twelve-message run lost half of itself.
- **Unit tests could not have caught any of the three above.** They needed the
  real relay, a real restart, and a real batch. When adding a feature, ask what
  only an end-to-end run would reveal.
- **Bucketing a timestamp requires bucketing the input, not the output**
  (D-020).
- **`starts_with` is not a host check.** `http://127.0.0.1.evil.com` is someone
  else's domain.
- **An exact version pin constrains one dependency, not the graph** (D-029).
  Only a lock file does that. Any crate outside the workspace needs its own
  committed `Cargo.lock` — the Android JNI library in Phase 5 is the next one.
- **`cargo audit` failing is information, not an obstacle** (D-030). Assess
  each advisory for reachability, fix what upgrades fix, and list the rest in
  `.cargo/audit.toml` *with a reason*. Never make one invisible. The four
  accepted entries are re-reviewed on any `openmls` release.
- **`&self` on an async method makes its future non-`Send`.** `Pouch` is `Send`
  but not `Sync` (`rusqlite::Connection` holds a `RefCell`), and Tauri requires
  every command future to be `Send`. Async methods on `Pouch` take `&mut self`.
  A test in `core/src/api/mod.rs` asserts this, because the alternative is
  finding out from the one CI job that needs GTK.
- **Verify a guard by making it fail.** The `Send` assertion above was checked
  by reverting the signature and confirming the compiler rejected it. A guard
  that has never been seen to fail is a guard nobody has checked. The same
  applies to `check-guardrails.sh` and the server-blindness suite, both of
  which were negative-tested when written.

## What cannot be done from this environment

Worth knowing before spending time on it:

- **The Tauri crate does not compile here** — no GTK or WebKitGTK. Write it,
  push it, and read the `Tauri shell — build` CI job. Assumptions it depends on
  should be asserted in `core`, which builds everywhere.
- **Branch deletion is blocked** — the git proxy returns 403 on a delete
  refspec. Pushes work; deletes do not.
- **The GUI cannot be run**, so the frontend's honesty rules are tested through
  `renderToStaticMarkup` and a fake bridge rather than a browser.

## Two constraints that shape design decisions

- **The relay must never learn who talks to whom.** This is why the sender's
  inbox address travels inside the encrypted channel rather than beside the
  Welcome (D-026), and why the relay has no sender column. Any feature that
  would give the relay a correlation it lacks is a stop-and-ask (SPEC §2.6).
- **The UI must never claim something the build does not do.** The manifest
  reports five of nine stages today and names the other four as
  `not yet implemented`. `RelayVisibility` lists the IP exposure and the
  missing sealed sender under what the relay *can* see. Keep it that way as
  features land — update the honest text in the same commit as the feature.
