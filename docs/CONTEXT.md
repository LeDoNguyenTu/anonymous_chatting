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

- **Git author is `Le Do Nguyen Tu <ledonguyentu@gmail.com>`.** Commits carry no
  co-author trailers and no third-party attribution of any kind.
- **Branch:** `develop`. Push after each phase.
- **Pin every dependency with `=`.** Record any version change in
  `docs/DECISIONS.md`. `openmls` breaks its API across minor versions.
- **`docs/DECISIONS.md` is append-only.** Supersede, never edit away.
- **Update `docs/PROGRESS.md` before finishing a session.**
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

Full reasoning is in `docs/DECISIONS.md` (D-001…D-018). The short version:

- Name is **Pouch** (D-015); "Courier" in the spec was a placeholder.
- MLS via `openmls =0.8.1`, not Signal Protocol (D-002).
- Starting ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (D-003).
  AES-**128** is deliberate and is not a weakness — do not "upgrade" it to look
  serious.
- Cipher cascading is permanently rejected (D-005). Hybrid X25519 + ML-KEM-768
  is the only legitimate combining (D-004).
- AEAD is only ever invoked through MLS; application code never picks a nonce
  (D-006).
- Relay stores four fields, `message_id` random rather than sequential (D-010).
- Compress → pad → encrypt, each payload compressed in isolation (D-009).
- Phases 1–3 use a self-signed relay certificate pinned by SPKI hash (D-017).
- SHA-256 is a hash, not encryption (D-001). It appears only inside HKDF.

## Where things stand

Phase 0 complete. Phase 1's **core, relay and CLI are done and working end to
end**; the desktop screens are what remain. 76 tests pass. Full detail, the
runnable demo, and the ordered list of what is next are in `docs/PROGRESS.md` —
read that before starting work.

## The map of the code

| File | What lives there |
|---|---|
| `core/src/api.rs` | `Pouch` — the only type clients touch. Start here. |
| `core/src/crypto/identity.rs` | Identity creation, invite codes |
| `core/src/crypto/session.rs` | MLS groups, encrypt, decrypt, ratchet config |
| `core/src/crypto/safety_number.rs` | 60-digit out-of-band verification |
| `core/src/crypto/provider.rs` | MLS provider with reachable, snapshottable storage |
| `core/src/storage.rs` | SQLCipher. Holds plaintext and keys. |
| `core/src/transport.rs` | Relay client, pinning policy |
| `core/src/manifest.rs` | The per-message record of what actually ran |
| `server/src/store.rs` | The relay's four columns |
| `server/src/http.rs` | Three endpoints, no logging middleware |
| `clients/cli/src/main.rs` | Headless client, eleven commands |

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
