# Progress log

Session log for a multi-session build. **Read this first at the start of every
session**, together with SPEC §1 (Prime Directives), §2 (Guardrails), and the
section for the current phase.

Do not begin a phase before the previous phase meets its exit criteria.

---

## Current position

| | |
|---|---|
| **Phase complete** | 0 — Foundation · 1 — Working 1:1 encrypted chat (code complete) |
| **Phase next** | 2 — Storage control and hardening |
| **Branches** | `main` (repository default) and `develop`, both at the same commit |
| **Blocked on** | nothing |
| **Tests** | 87 Rust on Linux · 86 on Windows · 24 frontend |
| **CI** | green on `main` and `develop` — all five jobs |

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
