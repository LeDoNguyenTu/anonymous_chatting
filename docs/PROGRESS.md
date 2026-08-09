# Progress log

Session log for a multi-session build. **Read this first at the start of every
session**, together with SPEC §1 (Prime Directives), §2 (Guardrails), and the
section for the current phase.

Do not begin a phase before the previous phase meets its exit criteria.

---

## Current position

| | |
|---|---|
| **Phase complete** | 0 · 1 · 2 · 3 · 4, all **fully**. Phase 4's exit criteria were verified against the live Tor network, not asserted. Merged to `develop` by the project owner via PR #3 (`c2f3197`). |
| **Phase in progress** | 5 — Android client. **Does not meet its exit criteria and is not close to.** Foundation built and verified as far as this environment allows; every SPEC §6.7 screen except the conversation list is unwritten. See the Phase 5 section below for exactly what exists and what does not. |
| **Branches** | `main` and `develop`, both pushed; `main` intentionally behind `develop`. `phase-5-android` holds the Phase 5 work, pushed to origin, **not merged**. No worktree this time — the Phase 4 worktree at `.worktrees/phase-4-tor/` is merged and can be removed. |
| **Blocked on** | Nothing in code. **Two design items need the project owner**, both recorded rather than improvised: cover traffic (D-044) and Android Keystore (D-035, SPEC §2.6 — "an implementation shortcut would mean storing a key in a less protected location"). |
| **Tests** | 148 Rust core + 14 end-to-end + 14 relay + 4 server-blindness = **180 Rust workspace** (1 ignored — the live-Tor test, run by hand) · **11 Android bridge** (`clients/android/jni`, run on the host) · **44 desktop frontend** · **11 Android JVM** (Custody Strip state mapping, passing in CI). Was 177 Rust / 44 frontend at the end of Phase 4. |
| **CI** | Two new jobs, `android-bridge` and `android-app`, **both green on the first run**. `android-bridge`: fmt, clippy, the 11 host tests, `cargo audit` on its own lock file, and the four-ABI cross-compile — so the arti, openmls and SQLCipher trees **do** link for Android (D-047 confirmed, not predicted). `android-app`: the 11 Custody Strip JVM tests, lint, `assembleDebug`, and a check on the *merged* manifest showing INTERNET and nothing else. Everything else was verified locally on Windows: fmt, clippy `-D warnings`, the full workspace suite, both guardrail scripts, the desktop crate's `cargo check --all-targets --locked`, and the JNI crate's own `--locked` test run. What CI does **not** show is anything executing on a device — see the Phase 5 section. |
| **Version** | `0.1.4`. Marks **Phase 5 in progress**, not Phase 5 complete. Six files now move together — see `docs/CONTEXT.md`, whose explanation of *why* was wrong until this session. |

### Owed to the project owner

Both outstanding items were cleared on 2026-08-01. `main` is now the repository
default branch, and `claude/private-messaging-app-xjc6n1` is deleted on the
remote and locally.

The earlier note that a git proxy returned HTTP 403 on the delete was a
misdiagnosis. Run from a normal workstation, GitHub gave the actual reason:

```
! [remote rejected] refusing to delete the current branch: refs/heads/claude/...
```

The branch could not be deleted because it was still the repository's default.
The two items were never independent — one was the precondition for the other.

---

## Phase 0 — Foundation · complete · 2026-08-01

### Landed

- Repository structure per SPEC §4.4, plus `clients/cli` (D-018).
- Cargo workspace: `pouch-core`, `pouch-relay`, `pouch-cli`. Every dependency
  pinned with `=` (D-016). All versions verified to resolve and build.
- `docs/THREAT_MODEL.md` — adversaries defended and undefended, three honest
  metadata tiers, trust assumptions stated explicitly.
- `docs/DECISIONS.md` — 18 entries (D-001…D-018), each with rejected
  alternatives.
- `docs/ARCHITECTURE.md` — components, send and receive paths, trust boundaries.
- `docs/LIMITATIONS.md` — plain language, no hedging.
- `docs/DESIGN_SYSTEM.md` — tokens, Custody Strip, Manifest, copy rules,
  accessibility floor.
- `README.md` — unaudited warning prominent, no unsupportable claims.
- Design tokens implemented in `clients/desktop/src/styles/tokens.css`, with a
  Phase 0 shell rendering the Custody Strip in every state, both themes.
- Tauri v2 shell scaffolded (excluded from the workspace — needs WebKitGTK).
- CI: fmt, clippy `-D warnings`, build, test, `cargo audit`, `npm audit`,
  frontend typecheck/test/build, Tauri shell compile, plus the two guardrail
  scripts.

### Decisions taken this session

- **Product name is Pouch** (D-015). "Courier" was a placeholder in the spec.
- **Relay deployment is local/self-hosted for Phases 1–3** (D-017), self-signed
  certificate pinned by SPKI hash. Decided by the project owner, 2026-08-01.
- **A headless CLI client ships alongside the desktop client** (D-018), so the
  Phase 1 exit criterion is verifiable in CI rather than by hand only.

### Notable finding

The specification predicted amber on light would fail WCAG AA. It does, and
worse than expected: `--amber` #C4913E is **2.30:1** on `--paper`, below even the
3:1 large-text floor. `--mute` (3.78:1) and `--verdigris` (3.20:1) also fail body
text.

Resolved by splitting the palette into brand tokens (identity of a colour, fixed)
and semantic per-theme text variants (measured, AA-compliant). Hue is preserved;
only lightness moves. All 23 ratios are recomputed by
`scripts/check-contrast.mjs` on every CI run, so the numbers in the design system
are derived rather than asserted. See `DESIGN_SYSTEM.md` §2.2.

### Exit criteria

| Criterion | State |
|---|---|
| Threat model complete | met |
| CI green | met |
| README free of unsupportable claims | met — enforced by `check-guardrails.sh` |
| Design tokens implemented in the desktop shell | met — 23/23 contrast checks pass |

---

## Phase 1 — Working 1:1 encrypted chat · code complete

### Scope (SPEC §9)

- `openmls` integrated; two-party group creation
- SQLCipher local store
- Relay: POST blob to inbox, GET and drain inbox, TLS with pinning, access
  logging disabled
- Desktop client: first run, add contact, conversation list, conversation view,
  Custody Strip, safety number screen, security details screen
- Light and dark themes
- Manifest at partial scope. Corrected 2026-08-01 against the manifest a real
  send actually printed — the stage numbers previously recorded here were wrong.
  What ships today:

  | Stage | State |
  |---|---|
  | 01 COMPOSED · 05 ENCRYPTED · 07 ROUTED · 08 HELD AT RELAY · 09 DELIVERED | reported, five of nine |
  | 03 COMPRESSED · 04 PADDED · 06 SENDER SEALED | `not yet implemented`, never shown as complete |
  | 02 METADATA REMOVED | `n/a — text message` |
- Live stage progression and the "what the relay could see" screen

### Exit criteria

- Two clients on different machines exchange text reliably
- Server blindness test (§8.3) passes
- Manifest accuracy test (§8.6) passes
- Manual DB dump reviewed and confirmed clean

**This is the milestone at which the project becomes portfolio-presentable.
Stop and write it up when it lands, even if work continues.**

### Order of work

1. ~~Relay, with the server-blindness test written first~~ — **done**
2. ~~`core` identity and MLS group creation~~ — **done**
3. ~~`core` storage on SQLCipher~~ — **done**
4. ~~`core` transport with pinning~~ — **done** (offline queue still to do)
5. ~~`core/api.rs`~~ — **done**
6. ~~CLI client~~ — **done**
7. **Desktop screens, in SPEC §6.6 order** — next, and the bulk of what is left

### What works right now

Verified by running it, not only by unit tests:

```sh
cargo build --workspace

# terminal 1
POUCH_RELAY_DB=/tmp/relay.db POUCH_RELAY_BIND=127.0.0.1:8551 ./target/debug/pouch-relay

# terminal 2 — two clients, two encrypted databases, one relay
export R=http://127.0.0.1:8551
K1=$(python3 -c "import os;print(os.urandom(32).hex())")
K2=$(python3 -c "import os;print(os.urandom(32).hex())")
B="POUCH_DB=/tmp/brian.db POUCH_KEY=$K1 POUCH_RELAY=$R"
M="POUCH_DB=/tmp/mai.db   POUCH_KEY=$K2 POUCH_RELAY=$R"

env $B pouch-cli create Brian
env $M pouch-cli create Mai
CODE=$(env $M pouch-cli invite | head -1)
env $B pouch-cli add Mai "$CODE"          # prints the conversation id
env $M pouch-cli receive                  # joins, learns Brian's name
env $B pouch-cli send <conversation> "the meeting is at dawn"
env $M pouch-cli receive
env $M pouch-cli safety <contact>         # matches Brian's, digit for digit
```

The send prints a real manifest — five of nine stages, with compression,
padding and sealed sender named as `not yet implemented` rather than hidden.

### Phase 1 exit criteria

| Criterion | State |
|---|---|
| Two clients exchange text reliably | **met** for two CLI clients against a live relay, automated in `core/tests/end_to_end.rs`. The literal "different machines" half is still a manual check — see below. |
| Server blindness test (§8.3) passes | **met** — `server/tests/server_blindness.rs`, plus a second assertion against a real conversation in `end_to_end.rs` |
| Manifest accuracy test (§8.6) passes | **met** — `core/src/manifest.rs` tests |
| Manual DB dump reviewed and confirmed clean | **met** — relay database contains no message text, no display name, no fragment |
| Desktop client screens | **built** — first run, conversation list, conversation view with the Custody Strip, add contact, safety number, security details, plus the Manifest and the relay-visibility panel |

### What is left in Phase 1

Nothing that blocks the milestone in code. What remains is verification that
needs real hardware, plus three deferrals carried into Phase 2:

- **Offline queue.** `send_message` returns an error with the right copy when
  the relay is unreachable, but nothing retries. The manifest already reports
  `failed at stage 07`.
- **Real TLS.** `RelayConfig::pinned` exists and `RelayClient::new` refuses
  unpinned remote relays, but the relay itself serves plain HTTP and the SPKI
  pin is not yet checked against a presented certificate. Loopback development
  works today; a remote deployment does not.
- **Key from the OS keystore.** `core/src/keying.rs` is the single answer to
  where a key comes from. It holds a real Argon2id path with pinned parameters
  and a `development_device_key` placeholder whose own documentation says it
  protects against nothing — the key file sits beside the database it unlocks.
  Replacing it means replacing exactly one function. **This is the first task
  of Phase 2.**
- **QR codes** on the invite-code and safety-number screens. Both currently
  show the mono text block, which is the half that matters for correctness;
  the QR is a convenience.
- **Retention controls.** The Custody Strip's third field is hardcoded to
  `KEEP`, which is the true default. Phase 2 makes it settable.

---

## Phase 1 session log — 2026-08-01

### Landed

- **Relay** (`server/`): four columns, three endpoints, no logs. Random
  `message_id`, `WITHOUT ROWID` so SQLite's monotonic rowid cannot reintroduce
  an ordering oracle, hourly-bucketed `expires_at`, collect and acknowledge as
  separate requests.
- **Core crypto** (`core/src/crypto/`): identity, invite codes, two-party MLS
  groups, message encrypt and decrypt, 60-digit safety numbers.
- **Core storage** (`core/src/storage.rs`): SQLCipher, key zeroized in place,
  `VACUUM` on wipe.
- **Core transport** (`core/src/transport.rs`): relay client, refuses unpinned
  remote relays as a hard error.
- **Manifest** (`core/src/manifest.rs`): reports only what actually ran.
- **API** (`core/src/api.rs`): the single surface clients touch.
- **CLI client** (`clients/cli/`): eleven commands, full send and receive.
- **Tests**: 76, including a server-blindness suite and an end-to-end suite
  that runs two clients against the real relay.

### Five bugs worth remembering

Three of these were invisible to unit tests and only appeared when the pieces
were run together.

1. **The dangerous one (D-024).** The relay had plain `rusqlite` and the core
   had it aliased with `bundled-sqlcipher`. Cargo unifies features across a
   workspace for one package version, so both collapsed into a plain SQLite
   build. SQLite ignores pragmas it does not recognise, so `PRAGMA key`
   returned success and encrypted nothing — every local database was plaintext
   on disk while the application reported an encrypted store. Nothing in the
   code was wrong; the dependency graph was. Now one SQLCipher build for the
   workspace, plus a runtime `PRAGMA cipher_version` check that fails hard.
2. **Conversations vanished on restart (D-027).** MLS state persisted fine but
   was never rehydrated into an `MlsGroup`. Looked like data loss; was not.
3. **Messages lost in a run (D-028).** The relay returns blobs in random-id
   order on purpose, so batches always arrive shuffled, and MLS's default
   out-of-order tolerance of 5 dropped over half of a twelve-message run. Two
   individually correct decisions producing a defect between them.
4. **Expiry was an arrival clock (D-020).** Bucketing `now + TTL` still varies
   with `now`. The arrival instant has to be bucketed first, by flooring.
5. **A lookalike loopback host.** `http://127.0.0.1.evil.com` is a registrable
   domain someone else controls, and a `starts_with` check treated it as
   loopback — disabling certificate pinning against an attacker's host.

### CI, and what it caught

All five jobs green. Getting there surfaced three faults, each only visible once
the previous was fixed — the ordinary shape of unblocking a build that fails
early.

1. **A transitive dependency had drifted** (D-029). `tauri-build` was pinned;
   its transitive `tauri-utils` was not, and `clients/desktop/src-tauri` sits
   outside the workspace so it had no lock file of its own. An exact pin
   constrains one dependency; only a lock file constrains the graph. Now
   committed, with `--locked` in CI.
2. **`cargo audit` failed with 19 advisories** (D-030). The guardrail working,
   not misfiring. Two fixed by upgrading, eleven not reachable, four accepted
   with reasoning in `.cargo/audit.toml`. One of the four —
   RUSTSEC-2026-0072, a missing RFC 9180 zero-check in the HPKE backend — is a
   real deviation and is now in `THREAT_MODEL.md` §4.
3. **The declared app icon did not exist**, then existed in the wrong format.
   `tauri.conf.json` had always referenced `icons/icon.png`; the old broken
   build never got far enough to notice. Tauri needs RGBA, not RGB.

The audit job also went from five minutes to five seconds by installing a
prebuilt `cargo-audit` instead of compiling it every run.

### The desktop client, as built

```
clients/desktop/
├── src-tauri/src/
│   ├── main.rs       window + the command registry
│   ├── state.rs      the one Pouch, behind an async mutex
│   └── commands.rs   17 commands, each a thin wrapper over one Pouch call
└── src/
    ├── lib/bridge.ts     the typed IPC boundary — the readable answer to
    │                     "what can the interface do". No passthrough.
    ├── components/       CustodyStrip, Manifest (+ relay visibility)
    ├── screens/          FirstRun, ConversationList, Conversation,
    │                     AddContact, SafetyNumber, SecurityDetails
    └── App.tsx           route union
```

Two properties worth not breaking, both tested:

- **`bridge.ts` narrows towards caution.** An identity label it does not
  recognise becomes `UNVERIFIED`, never `VERIFIED`. An unrecognised transport
  becomes `OFFLINE`, never `TOR`. If the two sides drift apart, the interface
  must not claim a verification that did not happen.
- **The Manifest reports, it does not infer.** No stage is assumed from an
  adjacent one, none are hidden, and the relay-visibility panel renders all
  three blocks including the one saying what still leaks.

### Manual checks still owed for Phase 1 exit

Partially closed on 2026-08-01 from a Windows workstation. What one machine can
prove has been proved; what needs two machines or a running GUI has not.

- [x] **Copy a locked database file off a device and confirm it cannot be read.**
  The client database was copied to a second path and inspected raw. Its first
  fifteen bytes are not `SQLite format 3`, and the message text, both display
  names, and every fragment searched for are absent from the file. Opening the
  copy with a wrong key fails with `this passphrase does not open the database`.
- [x] **Relay database confirmed clean against a real conversation.** The relay
  store is plain SQLite by design, one table, `queue`. It contains no message
  text, no display name, and neither participant's name.
- [~] **Safety numbers match.** Verified digit for digit — all 60 digits
  identical from both sides — but between two CLI clients on *one* machine.
  The two-physical-device half still stands.
- [ ] Two desktop clients on different machines exchange text
- [ ] Safety numbers compared on two physical devices
- [ ] Keyboard-only navigation completes a full send — needs the GUI running

---

## Phase 2 — Storage control and hardening · 2026-08-02

### Scope (SPEC §9) and what happened to each item

| Item | State |
|---|---|
| Disappearing messages, per conversation | **done** |
| Retention settings (forever / 30d / 7d / 24h) | **done** |
| Wipe-all | **done** — already existed from Phase 1; extended to cover every table Phase 2 added |
| Passphrase option with Argon2id | **done** |
| Offline queue and retry on reconnect | **done** — SPEC §8.2 names this explicitly; Phase 1 left it as a promise in error copy ("will send when you reconnect") that nothing kept |
| Identity change detection and the warning modal | **done** |
| Encrypted backup export and import | **done — `core`, the CLI, and the desktop client.** Was blocked, then unblocked; see below. |
| Full test suite, §8.1/§8.2/§8.8 | **done**, including two gaps found and closed this session — see below |

### Backup export/import: blocked, then built, same session

SPEC §7.3 and screen 10 (§6.7.10) describe it. It stayed out of this phase at
first on purpose, not by oversight: the reason was D-006, corrected earlier
this session — this project's standing rule is that application code never
invokes an AEAD directly or picks a nonce, and the one documented exception
path (`D-013`) turned out on inspection to be a stale cross-reference to the
Tor-vs-VPN decision, not an actual authorization for anything. A backup file
is not an MLS group message, so encrypting one necessarily means an AEAD
invocation this project had never actually decided how to do safely — SPEC
§2.6's stop-and-ask list, twice over.

That question was put to the project owner directly rather than assumed, and
approved: a fresh, single-use AES-128-GCM key per file, derived from the
recovery key via HKDF, via the same audited backend already in the dependency
graph (no new crate). Full reasoning is `docs/DECISIONS.md` D-037. Built and
verified the same session: `core/src/crypto/file_crypto.rs` (the AEAD and
HKDF primitives), `core/src/api/backup.rs` (the file format and the
export/import operations), and `pouch-cli backup export|import`. A live CLI
run — export, delete the original device's database entirely, import onto a
fresh path, send from the restored device, confirm the original peer
receives it — round-tripped correctly, matching what the automated
end-to-end test already proved.

**The desktop screen now has working backup buttons.** Landed in the
following session: two new Tauri commands (`export_backup`, `import_backup`
in `commands.rs`), typed IPC in `bridge.ts`, and a new screen,
`BackupRestore.tsx` — SPEC's screen 10. It renders as two different flows
depending on where it is reached from, matching the precondition
`Pouch::import_backup` already has (it creates a device from nothing, the
same precondition `create_identity` has — it is not a merge):

- **Export** — reached from Privacy and storage's new "Move your history to
  a new device" panel. Generates a fresh recovery key and backup file,
  shows the key in mono behind a "confirm you saved it" checkbox
  (SPEC §6.7.10's exact gate and copy), then turns the encrypted bytes into
  a browser-style download (`Blob` + `<a download>`) once confirmed —
  no OS "save as" dialog was added; that would have meant a new Tauri
  plugin (`tauri-plugin-dialog`) and its own capability/permission wiring,
  a bigger and unverifiable-by-GUI addition for what a standard webview
  download already does honestly.
- **Import** — reached from First run's new "Restore from a backup instead"
  link, i.e. only reachable before an identity exists on the device, which
  is the only precondition `Pouch::import_backup` supports. Uses a plain
  `<input type="file">` (no plugin needed — this is a standard web API a
  Tauri webview already supports) plus a recovery-key text field.

One small, low-risk dependency addition: `hex = "=0.4.3"` in
`clients/desktop/src-tauri/Cargo.toml`, to encode/decode the recovery key
over IPC the same way the CLI already does. Not a new choice for the
project — `hex` is already pinned at the workspace level and used by
`core` and the CLI; this crate sits outside the workspace (needs its own
copy of the pin, D-029) and had not needed it before. `Cargo.lock` picked
it up without changing any other resolved version.

Verified: `cargo build`/`cargo check --all-targets --locked`/`cargo clippy
-- -D warnings` all clean for the desktop crate outside the workspace,
`cargo fmt --all -- --check` at the repo root (which is what CI actually
runs — the desktop crate is excluded from the workspace so it is not part
of that check, and running `cargo fmt` scoped to the crate directory
turned up pre-existing formatting the project has apparently never had
checked, on code this session did not touch — left alone rather than
reformatted as a drive-by), and `npm run typecheck && npm test && npm run
build` for the frontend, all clean. **Not verified**: actually launching
the GUI and clicking through the two flows — this environment cannot run
the Tauri shell (no GTK/WebKitGTK story that applies to a real window,
and even on Windows this is a headless session). That is a real gap, not
a formality; say so if asked whether it has been "tested."

The attachment pipeline (Phase 3) needed the identical AEAD-outside-MLS
question and is unblocked by the same D-037 approval. What it still needs
is a second, narrower decision D-037 does not answer: which library strips
EXIF/GPS/device metadata, and whether it covers video containers as SPEC
§7.1 itself flags as open. See the Phase 3 section below.

### Two test-coverage gaps found and closed this session

Neither was a bug in Phase 2's own new code; both were things Phase 1 had
never had reason to expose.

1. **`INSERT OR REPLACE` was silently erasing conversations (D-033).**
   `put_contact` and `put_conversation` used it since Phase 1. SQLite
   implements `REPLACE` as delete-then-insert, foreign keys are enforced with
   `ON DELETE CASCADE`, and re-adding a contact already known — which the
   Hello-handling path does on every message after the first from someone —
   deleted the contact row and cascaded through `conversations` into
   `messages`. The entire thread with that person was gone, silently, as a
   side effect of them saying hello a second time. No Phase 1 test exercised
   the sequence "contact exists, has a conversation, gets re-added," because
   no fixture happened to do that. Found while writing a Phase 2 test helper
   that legitimately needed to. Fixed as an upsert that deliberately leaves
   `verified` and `public_key` alone on conflict — touching either would open
   a second, quieter route around the identity-change warning and the
   verification rule.
2. **SPEC §8.1's "key rotation" requirement had no test.** Nothing asserted
   that MLS's per-message ratchet was actually advancing — every existing
   test used a fresh conversation per message, so two messages were never
   compared to each other. Closed with the one property observable from
   outside `openmls` without touching its internals: identical plaintext,
   encrypted twice in a row, must not produce identical ciphertext.

### Manual check owed for Phase 2

- [ ] **Identity change modal, on a real screen.** Covered by an in-crate test
  that drives the API surface directly (`core/src/api/storage_controls.rs`)
  and by a component test rendering the modal to static markup
  (`IdentityChangeModal.test.tsx`), because the GUI cannot be launched in this
  environment. Neither is a substitute for seeing the actual interrupt-modal
  behavior in a running window. SPEC §9's Phase 2 exit criteria names this
  explicitly: "identity change modal verified manually."

### Verified, this session, on a Windows workstation

```
cargo fmt --all -- --check          clean
cargo clippy --workspace --all-targets -- -D warnings   clean
cargo test --workspace              119 passed, 0 failed
npm run typecheck / test / build    clean · 34/34 · builds
scripts/check-guardrails.sh         4/4 groups pass
scripts/check-contrast.mjs          23/23 pass
```

Also run manually against a live relay, not only compiled: the offline
queue (send while unreachable, confirm it queues, reconnect, confirm it
flushes and the peer decrypts it), retention deleting on a real clock,
disappearing-messages override, and passphrase protection end to end —
including that the pre-passphrase key stops opening the database and a
missing passphrase refuses rather than silently falling back to the
placeholder key. The exact commands are in `docs/DECISIONS.md` D-031–D-035
and in the CLI's own `--help` text (`keep`, `disappear`, `queue`, `changes`,
`acknowledge`, `passphrase`).

---

## Phase 3 — Attachments and sealed sender · started 2026-08-02

### What Phase 3 actually needs, and why most of it did not start today

SPEC §9 scopes Phase 3 as: the attachment pipeline, the attachment preview
screen, per-message compression, sealed sender, image/file rendering, and
activating manifest stages 2, 3, and 6.

Investigated all three headline pieces before writing any code. Two turned
out to need a decision rather than an implementation — one of those two was
put to the project owner directly and approved the same session, the other
was not (see below for which and why):

- **Attachments (stage 2, metadata stripping)** need a per-file encryption
  key generated outside MLS — a file is not a group message. D-006 says
  application code never invokes an AEAD directly, and the one place that was
  supposed to already authorize the exception (a stale "D-013" cross-reference,
  fixed this session) turned out to authorize nothing. **The encryption half of
  this is now resolved** — D-037, approved by the project owner, the same
  approval that unblocked Phase 2's backup export. What is *not* resolved is a
  second, separate question D-037 does not touch: which library strips
  EXIF/GPS/device metadata, and whether it handles video containers, which
  SPEC §7.1 itself flags as open ("Flag if the chosen library does not handle
  the container"). That is a new dependency to choose and pin, not a crypto
  question — worth its own short look before writing the pipeline, not
  something to default into.
- **Sealed sender (stage 6)** turned out to need more than expected. Reading
  `server/src/http.rs` and `core/src/transport.rs` end to end: the wire
  protocol already carries no sender field of any kind — `POST /inbox/{id}`
  takes only the recipient's inbox and a ciphertext body, confirmed by
  checking both the relay's request handling and the client's request
  construction. What the relay *can* still learn is the TCP/TLS source IP of
  whoever connects to submit a blob, correlated against which recipient inbox
  they posted to. That is not a message-field problem D-026's design already
  solved; it is a network-layer one, and the only mechanism this project has
  planned to solve it is Phase 4's Tor onion service. Building an interim
  anonymity layer to close it before Tor arrives would mean designing a new
  routing/anonymity construction — the same SPEC §2.6 stop-and-ask class as
  the AEAD question above, arguably a larger one.
- **Compression (stage 3)** needed neither. It sits entirely before MLS
  encryption, uses `zstd` — already a pinned dependency, never actually
  invoked until now — through its plainest one-shot interface, and SPEC
  §6.5.2 already specifies the isolation mitigation precisely enough to
  implement without inventing anything. Built and shipped; see below.

### Compression, done

`core/src/api/compression.rs`: `compress`/`decompress`, each a single
stateless `zstd` call with no dictionary and no encoder held across calls —
which is what makes the SPEC §6.5.2 isolation property hold structurally
rather than by discipline. Wired into both places a payload is serialized
before encryption (`send_payload`, used for the `Hello` introduction, and
`send_message`), and reversed in the one place a payload is decrypted before
parsing (`receive_messages`). Full reasoning, including why every payload is
compressed unconditionally rather than only above some size threshold, is
`docs/DECISIONS.md` D-036.

**Wire compatibility note.** A build from before this commit sends
uncompressed JSON; this build cannot decompress that and drops it silently,
the same way it already drops anything else that fails to parse as a
payload. Both clients in any conversation need to be this build or newer.
Explained in D-036 — this project has no live population of mismatched
builds to protect, so a clean break was the honest choice over adding
version-sniffing complexity to preserve compatibility nothing needs.

Verified against a real relay, real binary, not only the test suite:

```
$ pouch-cli send <conversation> "meeting "×200
6 of 9 stages ran
  03  COMPRESSED         zstd · 1611 → 35 bytes
...
$ pouch-cli receive   # on the other client
meeting meeting meeting ...   (1600 characters, byte-identical)
```

125 Rust tests (up from 119), 36 frontend tests (up from 34). New coverage:
a compression-isolation test matching §8.7's own wording, an end-to-end test
sending a real highly-compressible message through two live clients against
a real relay, and a frontend test confirming the Manifest component renders
a completed compression stage rather than "not yet implemented."

### D-037: the AEAD-outside-MLS question, resolved

Put to the project owner directly rather than assumed. Approved: a fresh,
single-use AES-128-GCM key per file, derived via HKDF where a key has to come
from something else (a recovery key, for backup), through the same audited
backend `PouchProvider` already wraps for MLS — no new dependency. Full
reasoning in `docs/DECISIONS.md` D-037.

Also decided the same round: sealed sender moves out of Phase 3's exit
requirement and into Phase 4, since it turns out to depend on what Tor
provides — everything else in Phase 3 does not depend on Tor and is
unaffected. SPEC.md's phase table is edited to say so: Phase 3 is now
"Attachments and compression," Phase 4 is "Tor transport, then sealed
sender," with the reasoning recorded inline in both sections rather than
only here.

Implemented with this approval: Phase 2's backup export/import, in full —
see that phase's section above. Not yet implemented at the time: the
attachment pipeline itself, which still needed the metadata-stripping
library decision. See D-038 below — that decision is made and the pipeline
is built.

### D-038: metadata stripping, and the attachment pipeline, built

Investigated the Rust ecosystem for an EXIF/metadata-stripping library
(`cargo info` against crates.io) rather than guessing. `img-parts` — pure
Rust, no `unsafe`, maintained — edits JPEG/PNG/WebP containers directly,
removing EXIF/ICC/XMP/comment segments without decoding pixel data. Video
had no comparable option: metadata hides in different container-specific
places, and the realistic alternative wraps FFmpeg's C libraries against
attacker-controlled input, a materially bigger attack surface than
anything else in this dependency graph. Put to the project owner directly:
approved images-only for Phase 3 (JPEG/PNG/WebP via `img-parts`), video
attachments explicitly refused with an honest message rather than silently
sent unstripped. Full reasoning in `docs/DECISIONS.md` D-038; SPEC.md's
Phase 3 section and exit criterion both say so inline.

Built the same session, in `core/src/attachments/`:

- `metadata.rs` — format detection by signature, and stripping. JPEG: every
  APPn segment (0–15) and every comment segment removed, not only EXIF/ICC —
  XMP, Photoshop IRB, and JFIF thumbnails can all carry metadata too, and
  SPEC says "strip all metadata," not "strip the two things the library has
  a convenience method for." PNG: `eXIf`, `tEXt`, `zTXt`, `iTXt`, `tIME`,
  `iCCP` removed the same way. WebP: EXIF, ICC, and XMP chunks removed.
  Every removal goes through `img-parts`'s structured segment/chunk API —
  never hand-parsed bytes, which SPEC §7.1 explicitly forbids.
- `padding.rs` — the same five fixed buckets SPEC §7.1 names (64 KB/256
  KB/1 MB/4 MB/16 MB, then 16 MB increments), with an 8-byte length prefix
  so padding is reversible.
- `mod.rs` — `prepare`/`open`, the one entry point that orders strip → pad →
  encrypt correctly rather than trusting a caller to. Encryption reuses
  D-037's exact shape (`crypto::file_crypto`, fresh AES-128-GCM key per
  file) — no new AEAD decision needed, D-037 already covers this case.

Wiring into `Pouch` (`core/src/api/attachments.rs`, plus a new
`Payload::Attachment` variant and `Manifest::new_for_attachment`): the
attachment ciphertext is **not** sent inside an MLS application message —
it is uploaded on its own to a freshly generated random relay identifier,
via the exact same `POST /inbox/{id}` the relay already exposes for
messages (a "bucket id" is just another opaque identifier, generated by
the sender instead of being either party's own inbox — no new relay
endpoint, no relay change at all). Only a small reference — where to fetch
it, the fresh key, the filename — travels through the normal encrypted
message channel, so a multi-megabyte blob never sits in the same queue
slot a text message does. The recipient fetches the bucket, decrypts and
unpads with the referenced key, stores it, and acknowledges the bucket so
it does not linger — made idempotent against a crash between those two
steps (`has_attachment` check before re-fetching).

Storage: a new `attachments` table (schema v3), sharing its primary key
with the `messages` row that references it, holding the *stripped* content
— never the original file, which never crosses the network at all.

Verified against a real relay, real binary, via new end-to-end tests
(`core/tests/end_to_end.rs`) rather than only unit tests:

- **SPEC §8.4, verbatim as a test.** Upload an image with known GPS EXIF and
  a distinctive filename, retrieve and decrypt it on the other device, dump
  the relay's raw database file, assert none of it — GPS, camera model,
  comment, filename, either party's name — appears anywhere.
- **SPEC §8.5, verbatim as a test.** Send 70 KB and 200 KB attachments,
  read the relay's stored blob lengths directly from its database, assert
  they are byte-identical.
- A non-image file is refused before anything is uploaded — the relay
  database stays empty of the attempt entirely, not merely of its metadata.

A CLI surface exists for manual verification and demos: `pouch-cli
send-file <conversation> <path>` and `pouch-cli save-attachment <id>
<path>`; `receive`/`read` print an attachment's id alongside its
`[attachment] <filename>` placeholder body so `save-attachment` has
something to act on.

**Known gap, honestly scoped rather than hidden:** a failed attachment
*blob* upload is not queued for offline retry the way a text message is —
`send_message`'s failure path re-queues the MLS ciphertext for
`flush_outbox` to retry; `send_attachment`'s does not, because the
blob upload happens outside MLS and there is nowhere established yet to
hold "an unsent file" the way the outbox holds "an unsent message." The
small reference message *is* queued and retried, matching `send_message`
exactly. Tracked below.

### Attachments, wired into the desktop client

Two new Tauri commands (`send_attachment`, `attachment`), typed IPC in
`bridge.ts`, and changes to `Conversation.tsx`: an "Attach image" button
(hidden file input, `accept="image/jpeg,image/png,image/webp"`) that reads
the file, calls `send_attachment`, and renders the same `Manifest`
component text messages already use — the strip/pad/encrypt rows show
exactly like compress/encrypt do for text, no separate code path. A new
`AttachmentImage` component fetches a stored attachment's content on
demand (not all up front) and renders it via a `Blob`/object URL, with the
filename as a caption; a message whose body is the
`[attachment] <filename>` placeholder renders this instead of the raw
placeholder text.

**Scope reduction, stated rather than silently taken:** SPEC §6.7.8
describes a *dedicated preview screen* shown *before* sending — file,
strip manifest, "Padded to: X" — as its own step. What is built instead
shows the same information (the Manifest component, including the strip
row) *after* the send completes, the same place and the same way a text
message's manifest already appears. This is honest about what actually
happened rather than a mid-send confirmation step, but it is not the
separate screen SPEC describes. Revisit if this workflow is confirmed as
good enough.

One CSP change was required and easy to miss: `tauri.conf.json`'s
`img-src` did not include `blob:`, which an `<img>` tag rendering
attachment content needs, and `default-src` was widened the same way as a
defensive measure for the backup screen's `<a download>` blob link, since
that code path could not be verified in a running window either. Neither
change widens what the app can reach over the network — both directives
already start from `'self'`, and `blob:` only ever holds bytes this
process itself created.

### What is still owed before Phase 3 can be called done

- [x] **Pick a metadata-stripping library** and build the attachment
  pipeline — done this session (D-038), see above.
- [x] **Wire backup into the desktop client** — done, see Phase 2's section.
- [x] **Attachment UI in the desktop client** — done this session, see
  above. The dedicated pre-send preview screen SPEC §6.7.8 describes is
  still not built; what ships shows the same information after sending.
- [ ] **Offline-queue retry for a failed attachment blob upload.** Looked
  at this session and *not* built on purpose rather than by oversight: text
  messages retry a failed send without re-encrypting because MLS's ratchet
  already advanced by the time the relay call fails, and re-encrypting
  would burn a generation (D-028's lesson). Attachment encryption is
  D-037's AEAD, entirely outside MLS — nothing about it touches the
  ratchet, so there is no equivalent cost to redoing `prepare()` on a
  manual retry. Automatic requeueing would need genuinely new
  infrastructure (a two-phase "blob uploaded, reference not yet sent"
  state) for a case a plain retry already handles safely and cheaply.
  Revisit only if manual retry turns out to be a real usability problem in
  practice, not as a default "more robust is more correct" instinct.
- [ ] **Sealed sender itself** — waits on Phase 4 existing, per the reorder
  above.
- [ ] **Manual GUI check for the backup screens and the attachment flow**,
  once a window can actually be launched — verified by
  build/typecheck/test only so far, per the note above. This specifically
  includes confirming the CSP change above actually lets an attachment
  image render in a real WebView2/WebKitGTK window, not just that it
  typechecks.

---

## Phase 4 — Tor transport, then sealed sender · complete · 2026-08-09

Exit criteria met, and the important ones were verified against the live Tor
network rather than asserted. What was *not* verified is stated at the end of
this section rather than left for someone to discover.

**Where the work lives.** Worktree `.worktrees/phase-4-tor/`, branch
`phase-4-tor-sealed-sender` (branched from `develop` at `dd3eaa2`, pushed to
origin, not yet merged). The 14-task plan is
`docs/superpowers/plans/2026-08-02-phase-4-tor-and-sealed-sender.md`; the SDD
ledger beside it in `.superpowers/sdd/` records per-task findings and is
gitignored, so it exists only in that worktree.

### What shipped

- **Relay as a Tor v3 onion service** (`server/src/onion.rs`), opt-in via
  `POUCH_RELAY_TOR_STATE`. The direct listener is untouched; both serve the
  same `axum::Router`. A failed onion launch is printed, not swallowed — an
  operator who asked for one and silently got only the direct listener would
  believe they had a protection they do not have.
- **Tor-routed client transport** (`core/src/transport/tor.rs`) on
  `arti-client` + `hyper`, because `reqwest` has no custom-connector hook and
  arti has no in-process SOCKS listener.
- **`Pouch::connect_tor` / `use_direct_relay`**, with `current_route()` feeding
  the manifest, the Custody Strip, and `RelayVisibility`. `connect_tor` never
  falls back to Direct on failure.
- **Message payloads padded** into the same fixed buckets attachments already
  used (D-041). This is a wire-format break; there is no deployed population to
  migrate.
- **Manifest stage 4 (`PADDED`) and stage 6 (`SENDER SEALED`) now report
  honestly per route.** Over Tor, stage 6 reads as ran; on the direct route it
  reads not-applicable *with the reason*, rather than disappearing.
- **`RelayVisibility` is route-aware.** Over Tor the IP exposure moves
  explicitly into `not_visible` rather than vanishing from the list, and
  `still_inferable` gains "that you are using Tor" plus the guard-node note.
- **CLI over Tor**, covering every relay-facing command — `add`, `send`,
  `send-file`, `receive` — through one `config::open_for_relay()` helper
  (D-045).
- **Desktop Transport settings screen** (SPEC §6.7.9) plus the three commands
  behind it, and `src/lib/fakeBridge.ts`, this project's first reusable test
  fake for `PouchBridge`.

### What was decided

| | |
|---|---|
| D-039 | `arti` pinned at 0.43.0; workspace `rust-version` raised to 1.89. |
| D-040 | `rusqlite` 0.32.1 → 0.39.0 to resolve a real arti conflict, plus two forced companion bumps. |
| D-041 | Fixed-size padding extended to message payloads; wire-format break. |
| D-042 | `arti-client` needs the `onion-service-client` feature. D-039's feature reasoning was wrong. |
| D-043 | Four dependencies the onion service needed, and the rustls crypto-provider choice. |
| D-044 | Cover traffic deferred as a stop-and-ask, not built. |
| D-045 | Tor applies to every relay-facing command; the env-var contract lives in the core. |

### Verified against the live Tor network

The relay published a real v3 onion address —
`vl2bppfcivlq7667zp2ayegkpc7i4425kbj7q4dis6go7atpq7w7fjad.onion` (deterministic
for a given state directory, so it is reproducible). Descriptor publication took
roughly 100 seconds before a client could find it. A separate client then
bootstrapped its own Tor connection (~7 s cold), dialled that address, and got
**200 from `/health`** — the whole path: circuit, `TorConnector`, `TorStream`,
hyper, the relay's real axum router, and back. An earlier attempt at `/`
returned 404, which was itself evidence the genuine router was answering rather
than a stub.

`core/src/transport/tor.rs`'s ignored test
`a_real_tor_bootstrap_succeeds_against_the_live_network` performs exactly this
check when `POUCH_TEST_ONION=host:port` names a Pouch relay, and asserts
bootstrap alone when it does not. Run it with `cargo test -- --ignored`.

Note for anyone repeating this: the onion service accepts streams on **any**
port, because `handle_rend_requests` is not port-filtered. The client used
`:80`.

### Two findings that would have shipped

Both compiled clean, passed clippy, and passed the entire test suite. Only
running a real circuit exposed them, and both are the D-024 pattern again — a
dependency accepting a configuration and quietly not providing the capability.

1. **`arti-client` was missing `onion-service-client`** (D-042). Without it
   arti refuses `.onion` addresses *at runtime*. Every Tor send would have
   failed in the field.
2. **A dead `rustls = "=0.23.20"` pin** (D-043). No workspace member named it,
   so the lock had already resolved 0.23.43 through arti. Once the relay named
   rustls directly, keeping the old pin would have put two rustls versions in
   the graph — and installed a crypto provider into the registry of the version
   arti is *not* using. A silent no-op.

### What was NOT verified

- **The Tauri window has never been launched.** This environment cannot run a
  GUI. Everything claimed about the Transport settings screen rests on
  `tsc --noEmit`, `vite build`, and `renderToStaticMarkup` assertions. Nobody
  has seen it render.
- **The desktop client has never talked to a relay over Tor.** The backend
  commands compile and the core path beneath them is the same one the CLI and
  the live-network test exercise, but that specific end-to-end path was not run.
- **The CLI-over-Tor demo in the plan's Task 10 Step 4 was not executed.** The
  Tor path it exercises was proven at the transport layer (above); the
  full two-client demo through onion addressing was not run end to end.

### Open

- **Cover traffic (D-044).** Named in Phase 4's scope, deliberately not built.
  Needs a design decision from the project owner — frequency, size, trigger,
  and how a receiver distinguishes it from real traffic without that
  distinction leaking — before anyone implements it.
- **One unreproducible flake.**
  `two_clients_exchange_text_and_the_relay_learns_nothing` (end-to-end) failed
  once during Task 8, then passed in isolation and in every full run since. The
  assertion text was not captured before it stopped reproducing. The test
  spawns a relay on an ephemeral port, so a transient bind/timing issue is
  plausible — but that is a hypothesis, not a diagnosis. **If CI hits it,
  capture the failure output before doing anything else.**

---

---

## Phase 5 — Android client · in progress · 2026-08-09

**This phase does not meet its exit criteria and is not close to.** SPEC §9
requires an APK installed on a physical device exchanging messages with a
desktop client, and requires the Kotlin UI to mirror the desktop feature set.
Neither has happened. What follows is what exists, what verified it, and what
did not.

### The environment, because it determined the design

Checked before any code was written:

| | |
|---|---|
| Android SDK | absent |
| Android NDK | absent |
| Gradle | absent |
| `cargo-ndk` | absent |
| Rust Android targets | none — only `x86_64-pc-windows-msvc` |
| JDK | 24 present, but AGP 8.7 supports 17–21 |
| Emulator / device | none |

So *nothing* Android could be compiled locally, let alone run. That is worse
than the Tauri situation, where at least a CI job builds the shell. The
response was to build bottom-up: verify what a machine can check, and make the
part that cannot be checked as small as possible.

### What shipped

**`core/src/views.rs` — the ten client view shapes (D-046).** Not Android work,
but caused by it. The desktop client defined `ConversationView`,
`SecurityDetailsView`, `SendResult` and seven others privately in
`commands.rs`; the Android client needs the same ten. Two hand-maintained
copies of structures carrying security state drift, and the drift is silent —
a field added to `SecurityDetails` and missed in one client renders a blank
where a mechanism should be named. Nothing fails, no test breaks, the screen
just under-reports what is protecting the user. They now live in the core and
`commands.rs` converts rather than defines. 3 new tests; desktop `cargo check`,
clippy and fmt clean on Windows.

**`clients/android/jni/` — the bridge (D-048).** A `cdylib` with its own
committed `Cargo.lock`, which is exactly the case D-029 named in advance.

The whole JNI surface is **two exported functions**: `nativeStart`, and
`nativeCall(operation, argsJson)` returning JSON. The desktop equivalent is 35
separate Tauri commands. The reason for collapsing it is the environment: 35
hand-marshalled JNI functions would have been 35 pieces of code executable
nowhere, each an opportunity for a mishandled `JString` or an escaping panic,
discoverable only on hardware nobody had. One function means the untestable
surface is one function, and everything behind it — `session.rs`, holding every
operation and every decision about what happens when no identity is open — is
ordinary Rust that runs under `cargo test`.

**11 tests pass on this Windows host.** They cover what would otherwise only
appear on a phone:

- an unlisted operation is refused, not forwarded to the core
- thirteen operations report `NotOpen` rather than panicking — a panic
  unwinding across FFI is undefined behaviour
- a failed send still returns all nine manifest stages
- a retention typo (`30` for `30d`) is refused rather than silently selecting
  a policy that deletes messages
- a malformed recovery key is refused *before* anything is written to disk

**`clients/android/app/` — Gradle, Kotlin, Compose.** `Pouch.kt` is a typed
facade, one suspend function per operation, no general-purpose passthrough —
the same discipline `bridge.ts` has, for the same reason. Every function hops
to `Dispatchers.IO` itself rather than documenting that callers should, because
a Tor bootstrap on the main thread is an ANR and "the caller will remember" is
not a property.

The Custody Strip is keyed by the label the core sends, not by an enum the app
defines, so a state the core knows and this build does not returns `UNKNOWN` in
amber rather than matching the wrong entry. 11 JVM unit tests assert what it
must never do: render an unknown state as verified, treat an empty string as a
default, describe a changed key without naming interception, or describe Tor
without naming what it does not hide.

**Two CI jobs**, because they are the only verification available:

- `android-bridge` — fmt, clippy, the 11 host tests, `cargo audit` against this
  crate's own lock file (the repo-root audit job reads the *workspace* lock, so
  this tree was previously unscanned), then a four-ABI cross-compile. The
  cross-compile step does not trust its own exit code: it stats four `.so`
  files and fails on any missing, because `cargo ndk` exiting 0 with a silently
  empty target would ship as an APK that crashes on exactly the devices nobody
  tested. D-024's pattern.
- `android-app` — JVM unit tests, lint, `assembleDebug`, and a check that the
  **merged** manifest requests `INTERNET` and nothing else. Merged rather than
  source, because a permission can arrive from a library's own manifest during
  merge without anyone editing a file here.

**Two guardrails** (`scripts/check-guardrails.sh` now runs 6 checks):

- no client may import `pouch_core::crypto::` or `::storage::`. D-012 was a
  convention held up by review, and a second client is exactly when such a
  convention slips, because the new one is written by copying shapes.
- every `#[no_mangle]` export must have a `catch_unwind`. Counted rather than
  grepped, because the failure mode is additive: someone adds a third entry
  point and forgets the wrapper.

Both were **negative-tested**. An uncaught entry point produced "3 JNI entry
points but only 2 catch_unwind"; a `crypto::` import named the file and line.
Exit 1 in both cases.

### Two documentation errors found and corrected

Neither was introduced this session; both had been wrong for some time.

- **`CONTEXT.md` explained the version-bump convention incorrectly.** It said
  the desktop crate's version must move because
  `SecurityDetailsView.app_version` reads `env!("CARGO_PKG_VERSION")` from that
  crate. The macro is invoked in `core/src/api/mod.rs`, so it expands to the
  **core** crate's version. The desktop version still has to move — it is what
  the installer reports — but not for the stated reason.
- **`pouch_core::SPEC_PHASE` read `2`** through the whole of Phases 3 and 4.
  Nothing referenced it, so nothing forced it to move. That is how an honesty
  marker rots: under-claiming never breaks a test, so nobody notices. Now `4`.

### RUSTSEC-2026-0212, re-checked as the audit file asked

`.cargo/audit.toml` carried a note left in advance: *"Not reachable today —
nothing in the compiled graph calls it — but it is the entry to re-check first
when the Android client lands in Phase 5, since that is aarch64."*

Re-checked, and **the finding changed.** `cargo tree -i libcrux-traits --target
aarch64-linux-android` resolves `libcrux-secrets 0.0.5` through `libcrux-sha3`,
`hpke-rs` and `openmls_rust_crypto`. It is genuinely compiled for aarch64 now.
The old wording described an x86_64-only project.

Still accepted, on different grounds, both written into the file: the
advisory's own impact is availability only (`VC:N/VI:N/VA:H`), and the path
that reaches it is `libcrux-sha3`'s SHAKE code, which a SHA-256 ciphersuite
never calls — the same reasoning already recorded for -0074, -0207 and -0208.
Not fixable by upgrading: `libcrux-traits 0.0.5` requires `libcrux-secrets
0.0.5` and 0.0.6 is semver-incompatible under Cargo's 0.0.x rules.

### What was NOT verified, and what is NOT built

Read this before believing anything above implies a working Android app.

- **Nothing has run on a device or an emulator.** This is the important one, and
  everything below is a qualification of it. CI now proves the code *compiles*
  and that its host-testable decisions are *correct*; it proves nothing about
  what happens when the JVM actually calls across the boundary. The JNI
  marshalling itself — `read_string`, the exception throw, the `jstring` return
  — has still never executed anywhere.
- **The cross-compile does pass**, which was an open question when the section
  above was drafted. All four ABIs link, so `arti`, `openmls` and SQLCipher do
  build for Android and D-047's vendored OpenSSL was the right call rather than
  a guess: `aarch64` 37.0 MB, `armv7` 26.5 MB, `x86_64` 36.5 MB, `i686` 36.2 MB,
  each confirmed by stat rather than by the build's exit code.
- **The Kotlin does compile**, which was also open. `:app:testDebugUnitTest`,
  `:app:lintDebug` and `:app:assembleDebug` all pass, and the 11 Custody Strip
  tests run green. An earlier draft of this section said no Kotlin had been
  compiled anywhere and that the job should be expected to need iteration; it
  passed first time, and leaving that claim would have under-reported what is
  actually verified.
- **The merged manifest was checked, not just the source one.** It requests
  INTERNET and nothing else, which is the only way to know a library did not
  contribute a permission during manifest merge.
- **No APK exists.** No device, no emulator, no signing key. The release build
  is deliberately unsigned: a release keystore is the project owner's to hold,
  and generating one in CI would put the app's identity somewhere it does not
  belong.
- **Most screens are not written.** Conversation view, add contact, safety
  number, privacy and storage, security details, transport settings, backup and
  restore, and the identity-change modal — the desktop client has all of them,
  this one has none. The app says so on its own empty state rather than
  presenting a shell that looks finished.
- **The Custody Strip copy is duplicated** from `CustodyStrip.tsx`. That is the
  same drift D-046 just removed from the view shapes, and the same fix applies:
  move it onto the core types the way `Route::explanation` already is. Not done
  here because it means changing the desktop rendering path in the same commit
  as a new client's first screens.

### Open, and needing the project owner

1. **Android Keystore (D-035).** The largest gap in this client. It uses the
   same device-file placeholder as the desktop client — a random key in a file
   beside the database it unlocks. This is a **SPEC §2.6 stop-and-ask**: "an
   implementation shortcut would mean storing a key in a less protected
   location." The realistic design has Kotlin unwrap a Keystore-wrapped key and
   pass the bytes across JNI, which puts key material in a JVM `ByteArray` that
   cannot be reliably zeroed — a real trade-off, not an obvious win, and one
   the owner should decide rather than have decided for them.
2. **Cover traffic (D-044).** Unchanged from Phase 4.
3. **Video attachments.** SPEC §8.4's video case is still open (D-038).
4. **The unreproducible flake**,
   `two_clients_exchange_text_and_the_relay_learns_nothing`. Not seen since.

### Next, in order

1. Read the `android-bridge` and `android-app` CI results and fix what they
   find. Nothing else should start first — everything above rests on code that
   has never been compiled for its target.
2. Decide the Keystore question (1 above).
3. Build the remaining SPEC §6.7 screens for Android.
4. Move the Custody Strip copy into the core, for both clients.
5. An APK on a real device — the actual exit criterion.

---

## Building and running on Windows · verified 2026-08-01

The project was built in a Linux container and every command recorded above is
POSIX. It builds and runs on Windows, but three things have to be in place
first, and one test disappears.

### Prerequisites

| Need | Why |
|---|---|
| `rustup`, `stable-x86_64-pc-windows-msvc` | — |
| VS Build Tools with the **VCTools** workload | `ring`, `zstd-sys` and SQLCipher are C. Without a linker nothing in the workspace compiles. |
| OpenSSL **with headers and libraries** | `bundled-sqlcipher` links OpenSSL. Linux CI has it; Windows does not. |

OpenSSL has to be pointed at explicitly, because the common Windows
distribution puts its libraries in `lib\VC\x64\MD` rather than `lib\`, which is
where `libsqlite3-sys` looks. Setting both variables makes its build script skip
the search entirely (`build.rs:156`):

```powershell
[Environment]::SetEnvironmentVariable("OPENSSL_LIB_DIR",     "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD", "User")
[Environment]::SetEnvironmentVariable("OPENSSL_INCLUDE_DIR", "C:\Program Files\OpenSSL-Win64\include",       "User")
```

Without them the build fails at `Missing environment variable OPENSSL_DIR`.
That is an environment fault, not a code defect — see `CONTEXT.md`.

### The test count is 86 on Windows, not 87

`the_key_file_is_not_world_readable` in `core/src/keying.rs` is `#[cfg(unix)]`,
so it is compiled out. The reason it is `cfg(unix)` is the part that matters:
`write_private` applies its `0o600` restriction only on Unix. The doc comment
says "where the platform supports it", so the limitation is stated honestly —
but on Windows the device key file has **no permission restriction and no test
asserting anything about it**.

Do not patch this with Windows ACL code. Phase 2's first task replaces
`development_device_key` with the OS keystore, which on Windows means DPAPI or
Credential Manager and removes the file altogether. Fixing it in that order
deletes the gap instead of decorating it.

### The demo, in PowerShell

The same run as the POSIX version above, confirmed working end to end.

```powershell
# terminal 1 — the relay
$env:POUCH_RELAY_DB = "$env:TEMP\relay.db"; $env:POUCH_RELAY_BIND = "127.0.0.1:8551"
.\target\debug\pouch-relay.exe

# terminal 2 — two clients, two encrypted databases, one relay
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
function New-Key { $b = New-Object byte[] 32; $rng.GetBytes($b); ($b | ForEach-Object { '{0:x2}' -f $_ }) -join '' }
$K1 = New-Key; $K2 = New-Key
$env:POUCH_RELAY = "http://127.0.0.1:8551"

$env:POUCH_DB = "$env:TEMP\brian.db"; $env:POUCH_KEY = $K1
.\target\debug\pouch-cli.exe create Brian
$env:POUCH_DB = "$env:TEMP\mai.db";   $env:POUCH_KEY = $K2
.\target\debug\pouch-cli.exe create Mai
$CODE = (.\target\debug\pouch-cli.exe invite | Select-Object -First 1)

$env:POUCH_DB = "$env:TEMP\brian.db"; $env:POUCH_KEY = $K1
.\target\debug\pouch-cli.exe add Mai $CODE      # prints the conversation id
$env:POUCH_DB = "$env:TEMP\mai.db";   $env:POUCH_KEY = $K2
.\target\debug\pouch-cli.exe receive            # joins, learns Brian's name
```

Two traps, both of which fail quietly rather than loudly:

- **`[RandomNumberGenerator]::Fill` does not exist in Windows PowerShell 5.1.**
  It is .NET Core only. Use `RNGCryptoServiceProvider` as above.
- **Assigning an empty string to `$env:POUCH_KEY` removes the variable**, and
  the CLI then falls back to `development_device_key` without complaint. A key
  generation failure therefore looks like a successful run against a *different*
  keying path. Check `$K1.Length -eq 64` before trusting a run.

---

## Notes for whoever picks this up

- `SPEC.md` at the repository root is authoritative and wins over any session
  request on security matters.
- The stop-and-ask list is SPEC §2.6. Use it — an unasked question costs a
  message, a wrong cryptographic assumption costs the project.
- `docs/DECISIONS.md` is append-only. Superseded entries stay; a new entry
  supersedes them.
- Never add a dependency without pinning it exactly and recording why.
- `docs/CONTEXT.md` holds the working context for resuming a session without
  re-reading the whole history.
