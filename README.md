# Pouch

An end-to-end encrypted messenger built on MLS (RFC 9420), with a relay designed
to hold nothing worth stealing.

---

## Read this first

**Pouch is unaudited student work. It has not been reviewed by any
cryptographer. Do not rely on it if you face a serious adversary — if you are a
journalist, an activist, a source, or anyone who would suffer real consequences
from your messages being read, use [Signal](https://signal.org).**

That warning is not modesty and it is not a disclaimer bolted on for legal cover.
It is the single most accurate statement on this page. Good primitives assembled
by an unreviewed hand are not the same thing as a reviewed system, and the
difference is invisible from the outside — including to the person who wrote it.

`docs/LIMITATIONS.md` says the same thing at length, in plain language. It is the
honest place to start.

---

## What it is

A one-to-one encrypted messenger with a deliberately ignorant relay server. Three
clients — desktop, Android, and a headless CLI — sit as thin UI over a single
Rust core that holds every security-relevant line of code.

The relay stores four fields per queued message: a random ID, an opaque inbox
identifier, a ciphertext blob, and a TTL. It has no concept of a user. There is
no account table, no directory, no presence, and no sender field, because a field
that does not exist cannot be subpoenaed, leaked, or sold.

An automated test dumps the entire relay database and asserts that a known string
from a real conversation appears nowhere in it. That test is the architecture's
proof of work.

## What it actually uses

Nothing here is secret. The security of this app rests on the keys, not on
hiding how it works.

| Purpose | Mechanism |
|---|---|
| Session and group key management | MLS (RFC 9420) via `openmls` |
| Starting ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` |
| AEAD | AES-128-GCM, through the protocol, never called directly |
| Key agreement | X25519 (hybrid X25519 + ML-KEM-768 planned) |
| Signatures | Ed25519 |
| Hash and KDF | SHA-256 inside HKDF |
| Local database | SQLCipher, AES-256 |
| Passphrase to key | Argon2id |
| Transport, phases 1–3 | TLS 1.3, relay certificate pinned by SPKI hash |
| Transport, phase 4 | Tor onion service via `arti` |

SHA-256 appears in that table as a **hash function**, used for integrity and key
derivation. It is not encryption and provides no confidentiality. See
`docs/DECISIONS.md` D-001 — it is the first entry because it is the most common
misunderstanding in this space.

## Status

Built in phases. Only what is listed as done actually works.

| Phase | Scope | State |
|---|---|---|
| 0 | Repo, docs, design tokens, CI | **done** |
| 1 | One-to-one encrypted text, relay, desktop client | in progress |
| 2 | Retention, wipe, passphrase, backup, identity-change warning | not started |
| 3 | Attachments, metadata stripping, sealed sender | not started |
| 4 | Tor transport | not started |
| 5 | Android client | not started |
| 6 | Multi-device and groups | roadmap only |

Until Phase 3, the relay can see which inbox sent a message. Until Phase 4 it can
see your IP address. The interface says so, in amber, while that is true.

## How it is meant to be honest

Two ideas do most of the work.

**The Custody Strip.** A band at the top of every conversation showing three
facts — identity, transport, retention — in monospace, permanently. It never
shows a reassuring state when the real state is uncertain. An unverified contact
stays amber until you have actually compared a safety number with them, not until
you have dismissed a prompt about it.

**The Manifest.** Every message carries a record of the nine stages it passed
through, each one inspectable. Stages that did not run say so. Stages that are
not built yet say `not yet implemented` rather than quietly disappearing. Its
last row opens "What the relay could see", which lists what the operator can
observe about that specific message — including a required third block for what
still leaks to a network observer. Showing only the good half is the kind of
reassuring half-truth this project is built to avoid.

## What it does not do

Summarised here, detailed in `docs/THREAT_MODEL.md` §4:

- It does not protect you from a compromised device. If there is a keylogger on
  your machine, encryption is irrelevant.
- It does not defeat an adversary watching both ends of a conversation and
  correlating timing.
- It does not help if you are compelled to unlock it.
- It does not stop the person you are talking to from repeating what you said.
- It does not guarantee availability. A hostile relay can block messages; it
  cannot read them.

It is also not stronger than Signal. It uses the same class of primitives, which
are already infeasible to break, so there is no headroom to compete over. Where
it differs is policy: no phone number, self-hostable relay, no server-side
backup, Tor by default from Phase 4. That is a real difference, and it does not
outweigh being unaudited.

## Repository layout

```
core/                 Rust crate — all crypto, storage, transport
server/               Rust relay — axum + SQLite, opaque blob queue
clients/desktop/      Tauri + React
clients/cli/          headless client, used for integration tests and demos
clients/android/      Kotlin + Compose (Phase 5)
docs/                 threat model, decisions, architecture, limitations,
                      design system, progress log
scripts/              CI guardrails
```

## Building

Requires Rust 1.82+ and Node 22+.

```sh
cargo build --workspace          # core, relay, CLI client
cargo test  --workspace
./scripts/check-guardrails.sh    # forbidden logging, marketing, relay logging
node scripts/check-contrast.mjs  # WCAG AA on the token palette

cd clients/desktop && npm ci && npm run build
```

The Tauri desktop shell additionally needs WebKitGTK on Linux
(`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`); it is excluded from the Cargo
workspace so the rest builds on a headless machine.

## Documentation

| File | What it is for |
|---|---|
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Who this defends against, and who it does not |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Every crypto and architecture decision, with the rejected options and why |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Components, send and receive paths, trust boundaries |
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | Plain language, no hedging |
| [`docs/DESIGN_SYSTEM.md`](docs/DESIGN_SYSTEM.md) | Tokens, the Custody Strip, the Manifest, copy rules |
| [`docs/PROGRESS.md`](docs/PROGRESS.md) | Session log — what landed, what is next |

## Licence

AGPL-3.0-or-later.
