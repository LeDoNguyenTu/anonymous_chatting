# Progress log

Session log for a multi-session build. **Read this first at the start of every
session**, together with SPEC §1 (Prime Directives), §2 (Guardrails), and the
section for the current phase.

Do not begin a phase before the previous phase meets its exit criteria.

---

## Current position

| | |
|---|---|
| **Phase complete** | 0 — Foundation |
| **Phase in progress** | 1 — Working 1:1 encrypted chat. **Core, relay and CLI done and working end to end. Desktop screens are what remain.** |
| **Branch** | `claude/private-messaging-app-xjc6n1` |
| **Blocked on** | nothing |
| **Tests** | 76 passing |

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

## Phase 1 — Working 1:1 encrypted chat · in progress

### Scope (SPEC §9)

- `openmls` integrated; two-party group creation
- SQLCipher local store
- Relay: POST blob to inbox, GET and drain inbox, TLS with pinning, access
  logging disabled
- Desktop client: first run, add contact, conversation list, conversation view,
  Custody Strip, safety number screen, security details screen
- Light and dark themes
- Manifest at partial scope — stages 1, 4, 5, 8, 9 only. Stages 2, 3, 6, 7
  display as `not yet implemented`, never as complete.
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
| Desktop client screens | **not started** — this is what stands between here and the milestone |

### What is left in Phase 1

The desktop client, which is currently a Phase 0 token shell. In SPEC §6.6
order:

1. First run — create identity, offer but do not force a passphrase
2. Conversation list
3. Conversation view with the Custody Strip (component already exists and is
   tested; it needs wiring to `Pouch`)
4. Add contact — invite code as QR plus mono text
5. Safety number — 60 digits, grouped in fives, plus QR
6. Security details — `Pouch::security_details()` already returns everything
   this screen needs
7. The Manifest UI — collapsed line, expanded view, live stage progression,
   and "what the relay could see" (`RelayVisibility` already returns the three
   honest blocks)

The Tauri bridge in `clients/desktop/src-tauri/src/main.rs` is a bare window
with no commands. It needs `#[tauri::command]` wrappers over `Pouch`, and
nothing lower level than `Pouch` (D-012).

Also outstanding in Phase 1, smaller:

- **Offline queue.** `send_message` returns an error with the right copy when
  the relay is unreachable, but nothing retries. The manifest already reports
  `failed at stage 07`.
- **Real TLS.** `RelayConfig::pinned` exists and `RelayClient::new` refuses
  unpinned remote relays, but the relay itself serves plain HTTP and the SPKI
  pin is not yet checked against a presented certificate. Loopback development
  works today; a remote deployment does not.
- **Key from the OS keystore.** The CLI takes the database key from
  `POUCH_KEY`, which is development-grade and says so in its own help text.

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

### Manual checks still owed for Phase 1 exit

Run these on two real machines before calling the milestone done:

- [ ] Two desktop clients on different machines exchange text
- [ ] Safety numbers match on both physical devices
- [ ] Copy a locked database file off a device and confirm it cannot be read
- [ ] Keyboard-only navigation completes a full send

---

## Notes for whoever picks this up

- `SPEC.md` at the repository root is authoritative and wins over any session
  request on security matters.
- The stop-and-ask list is SPEC §2.6. Use it — an unasked question costs a
  message, a wrong cryptographic assumption costs the project.
- `docs/DECISIONS.md` is append-only. Superseded entries stay; a new entry
  supersedes them.
- Never add a dependency without pinning it exactly and recording why.
- `CLAUDE.md` holds the working context for resuming a session without re-reading
  the whole history.
