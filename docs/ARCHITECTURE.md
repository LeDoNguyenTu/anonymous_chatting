# Architecture

**Last revised:** 2026-08-01 (Phase 0)

---

## 1. Components

```
┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│   Desktop client     │  │   Android client     │  │   CLI client         │
│   Tauri + React      │  │   Kotlin + Compose   │  │   Rust               │
│   (UI only)          │  │   (UI only, ph. 5)   │  │   (testing + demo)   │
└──────────┬───────────┘  └──────────┬───────────┘  └──────────┬───────────┘
           │                          │                         │
           │  FFI                     │  JNI                    │  direct
           └──────────────┬───────────┴─────────────────────────┘
                          │
             ┌────────────▼─────────────┐
             │   core  (Rust crate)     │
             │                          │
             │   MLS state machine      │
             │   key storage            │
             │   message encrypt/decrypt│
             │   attachment pipeline    │
             │   SQLCipher access       │
             │   transport + retry      │
             └────────────┬─────────────┘
                          │
                          │  TLS 1.3, SPKI-pinned   (phases 1–3)
                          │  Tor onion service      (phase 4+)
                          │
             ┌────────────▼─────────────┐
             │   relay server (Rust)    │
             │   axum + SQLite          │
             │                          │
             │   opaque blob queue      │
             │   no identity, no logs   │
             └──────────────────────────┘
```

The important structural property: **every arrow into the core is a UI layer, and
no UI layer knows what a key is.** The core exposes high-level operations only —
`send_message`, `receive_messages`, `create_conversation`, `verify_contact`,
`set_retention`, `wipe_all`. Three clients, one implementation of the security
logic.

## 2. The core crate

```
core/src/
├── crypto/        MLS integration, identity keys, safety numbers
├── storage/       SQLCipher, retention, backup
├── transport/     TLS, pinning, Tor, retry, offline queue
├── attachments/   per-file keys, metadata stripping, padding
└── api.rs         the only surface clients touch
```

`api.rs` is a hard boundary, not a convention. Anything a client needs is a
function there. If a client appears to need something lower-level, the correct
response is to add an operation to `api.rs` — never to expose the module beneath
it. See `DECISIONS.md` D-012.

`unsafe_code` is forbidden crate-wide.

## 3. Send path

The nine stages the UI surfaces as a Manifest correspond to real steps in this
path. The Manifest reports what actually happened, including stages that did not
run — a stage that reports success it did not perform is a worse defect than a
missing feature (test §8.6).

```
  plaintext
     │
  1. compose        measure byte length (local only, never transmitted)
     │
  2. strip          attachments only — EXIF, GPS, device model, timestamps
     │              text messages: not applicable
     │
  3. compress       zstd, each payload in isolation (D-009)
     │              every payload, unconditionally — see below
     │
  4. pad            to a fixed bucket, blunting size fingerprinting
     │
  5. encrypt        MLS application message
     │              AEAD + key agreement + signature per ciphersuite
     │
  6. seal           sealed sender — relay cannot see who sent this (phase 4 —
     │              moved from phase 3, 2026-08-02: it depends on Tor, below)
     │
  7. route          direct TLS, or Tor onion circuit (phase 4)
     │
  8. queue          relay holds the blob under a random ID until collected
     │
  9. deliver        recipient drains inbox; relay copy erased
```

Ordering is security-relevant in two places, and both are load-bearing:

- **Strip before encrypt.** Metadata removed after encryption is metadata that
  was never removed.
- **Compress before pad, pad before encrypt.** Compression only works on
  plaintext; padding only hides size if it is the last thing before the
  ciphertext boundary.
- **Every payload is compressed, with no size threshold.** An earlier sketch
  of this diagram had short messages skip compression, on the reasoning that
  zstd's frame overhead can make a very short payload a few bytes larger than
  it started. That is true and harmless on its own — but skipping compression
  *sometimes* means a receiver has to know, for a given blob, whether it is
  looking at compressed or raw bytes before it can decode it. That requires an
  explicit marker in the wire format, which is protocol design, not a size
  tweak, and it is exactly the kind of ambiguous-format decision SPEC §2.1
  warns against admitting a downgrade path through. Compressing unconditionally
  needs no marker and has no such path. The few bytes lost on a two-word
  message are negligible next to MLS's own fixed 128-byte padding on every
  application message regardless.

## 4. Receive path

Drain inbox → verify AEAD → MLS decrypt → decompress → store to SQLCipher →
surface to UI.

A message that fails authentication is surfaced as a visible error. It is never
silently dropped and never rendered as if it had arrived intact. A silent drop
hides exactly the event the user most needs to know about.

## 5. The relay

A queue for opaque blobs. It has no concept of a user.

| Field | Type | Notes |
|---|---|---|
| `message_id` | random 128-bit | No ordering information (D-010) |
| `inbox_id` | opaque random identifier | Not a username, phone, or email |
| `blob` | ciphertext bytes | The relay holds no key for this |
| `expires_at` | timestamp | TTL only, default 30 days |

Blobs are deleted on successful delivery, or at TTL expiry, whichever comes
first. Access logging is explicitly disabled, and CI asserts that it is.

There is no account creation endpoint, no directory, no presence, no read
receipts, and no backup feature. Each of these is absent by design; adding any of
them would let the relay learn something it currently cannot, which is a
stop-and-ask per SPEC §2.6.

## 6. Data at rest

| Where | Protection |
|---|---|
| Client database | SQLCipher (AES-256); key from OS keystore or Argon2id passphrase |
| Client identity key | Same database, zeroized in memory on drop |
| Relay database | Nothing to protect — it holds only ciphertext and random identifiers |
| Backup export | Encrypted under a user-held recovery key; never uploaded anywhere |

The relay row is the point of the architecture. The relay database is not
protected because there is nothing in it worth protecting.

## 7. Trust boundaries

```
   ┌─ user's device ────────────────────────┐
   │  plaintext, keys, identity             │   ← everything sensitive is here
   │  TRUSTED                               │
   └────────────────┬───────────────────────┘
                    │  ciphertext only
   ┌────────────────▼───────────────────────┐
   │  network                               │
   │  UNTRUSTED — assumed fully observed    │
   └────────────────┬───────────────────────┘
                    │  ciphertext only
   ┌────────────────▼───────────────────────┐
   │  relay                                 │
   │  UNTRUSTED — assumed hostile           │
   └────────────────────────────────────────┘
```

Only the first box is trusted, and `THREAT_MODEL.md` §4 is explicit that a
compromised device ends the game. That is not a gap in the design; it is the
boundary of what encryption can do.
