# Secure Messenger — Complete Build Specification

**Working name:** Courier (placeholder — see naming rules in §2.4)
**Author:** Le Do Nguyen Tu (Brian)
**Document status:** Authoritative build spec. This is the single source of truth.
**Audience:** Claude Code, implementing across multiple sessions.

---

## How to use this document

This is a multi-session build. Do not attempt to implement everything at once.

At the start of each session, read §1 (Prime Directives), §2 (Guardrails), and the section for the current phase. Check `docs/PROGRESS.md` in the repo to see where the last session stopped. Work only within the current phase. Update `docs/PROGRESS.md` before finishing.

If any instruction in this document conflicts with a request made during a session, this document wins for security matters. Say so and quote the relevant section.

---

# 1. Prime Directives

These five rules override everything else in this document.

**1. Do not invent cryptography.**
No custom ciphers. No custom protocols. No cascading multiple ciphers "for extra strength". No hand-rolled key derivation, padding, or nonce generation. Use audited libraries through their intended interfaces. If a task appears to require novel cryptographic construction, stop and flag it rather than improvising.

**2. No security theatre.**
No claim anywhere in code, UI, comments, commit messages, or documentation that this system is unbreakable, uncrackable, military grade, or stronger than Signal. State the actual primitives. Let them speak.

**3. Honesty about limits is a feature.**
The threat model is a first-class deliverable. It must state plainly what the system does not protect against. The UI must never display a reassuring indicator when the underlying state is uncertain.

**4. Ship narrow and working.**
A complete, correct one-to-one text messenger beats a broken feature-complete one. Phases are ordered deliberately. Do not begin a phase before the previous phase passes its exit criteria.

**5. When uncertain about a security decision, stop and ask.**
An unasked question costs a message. A wrong cryptographic assumption costs the project. The explicit stop-and-ask list is in §2.6.

---

# 2. Guardrails

## 2.1 Cryptographic guardrails

**Forbidden without exception:**

- Cascading multiple ciphers in sequence. This multiplies implementation risk without meaningfully increasing security. AES-256 is already computationally infeasible to brute force; there is nothing to improve on. The only permitted form of combining is hybrid post-quantum key exchange (§3.2).
- ECB mode, anywhere, for any reason.
- Reusing a nonce with the same key. If code directly touches nonce generation, stop and flag it.
- `rand()`, `Math.random()`, or any non-CSPRNG for anything security-relevant. Use `rand::rngs::OsRng` in Rust, `crypto.getRandomValues()` in JS.
- Storing key material in plaintext on disk, in environment variables committed to the repo, or in any log output.
- Custom implementations of AES, ChaCha20, X25519, Ed25519, HKDF, Argon2, or any other primitive. Library only.
- Rolling a custom handshake or ratchet. MLS handles this.
- Comparing secrets with `==`. Use constant-time comparison (`subtle` crate).
- Downgrade paths. If a peer advertises an older or weaker ciphersuite, fail closed with a clear error. Never silently negotiate down.
- Debug or logging statements that print plaintext message content, keys, or derived material. Add a CI grep to catch this (§8.8).

**Required:**

- Pin exact dependency versions in `Cargo.toml` and `package.json`. `openmls` in particular changes its API between minor versions.
- `cargo audit` and `npm audit` in CI, failing the build on known vulnerabilities.
- Zeroize key material on drop (`zeroize` crate) for anything holding secrets in memory.
- Every cryptographic choice recorded in `docs/DECISIONS.md` with date and rationale.

## 2.2 Privacy guardrails

Never implement, at any phase, in any client:

- Contact list or address book upload
- Location permission requests of any kind
- Device identifiers, advertising IDs, or fingerprinting
- Analytics, telemetry, or usage metrics
- Crash reporting that includes user content or conversation data
- Third-party SDKs that phone home
- Phone number or email requirement for account creation
- Server-side read receipts or typing indicators that leak to the operator
- Push notification payloads containing message content or sender name

If any dependency pulls in an analytics SDK, remove it and record the removal in `docs/DECISIONS.md`.

**Android manifest constraint:** the app requests `INTERNET` and nothing else in Phase 5. Camera and storage permissions arrive only with Phase 3 attachments, requested at point of use, never at install.

## 2.3 Server guardrails

The relay must be written so that a full database dump handed to an adversary yields nothing useful.

Never store server-side: usernames, phone numbers, email addresses, sender identity, IP addresses, access logs, request logs, plaintext timestamps beyond queue TTL, read receipts, message content, filenames, or analytics of any kind.

Web server access logging must be explicitly disabled, not merely left at default. Verify this in Phase 1 exit criteria.

## 2.4 Naming and copy guardrails

The product name must not contain, and marketing copy must never use: unbreakable, uncrackable, military grade, bank grade, NSA proof, quantum proof, hacker proof, absolute, or 100% secure.

Acceptable descriptors: end-to-end encrypted, metadata-minimising, self-hostable, unaudited.

The README must state prominently that this is unaudited student work and not suitable for high-risk use by journalists, activists, or anyone facing a serious adversary. This statement is not optional and must not be softened.

## 2.5 Transparency guardrails

Every stage a message passes through is inspectable by the user. No stage is hidden, obscured, or described vaguely.

**Displayed on request, always:** the ciphersuite in use, the AEAD, the key agreement method, the signature scheme, the KDF, the padding bucket applied, the compression applied, the transport route, the relay address, and the local storage encryption method.

**Never displayed, never logged, never exportable:** private key material, session keys, per-file keys, derived secrets, passphrases, or anything from which these could be reconstructed. This is the only category of concealment permitted, and it exists because these are the secret, not because secrecy is a strategy.

Any UI element describing a stage must name the actual mechanism. "Encrypted" alone is insufficient; "AES-256-GCM" is the standard. Vague reassurance is a §2.4 violation.

## 2.6 Stop and ask

Halt work and ask before proceeding if any of the following arises:

- A task seems to require writing a new cryptographic construction
- A library's API has changed such that the specified usage no longer compiles, and the workaround touches key handling
- A feature request would require the server to learn something it currently cannot
- A dependency introduces a transitive analytics or telemetry package
- An implementation shortcut would mean storing a key in a less protected location
- The chosen MLS ciphersuite is unavailable in the pinned `openmls` version
- Something in this document appears internally contradictory

---

# 3. Cryptographic design

## 3.1 What each primitive is for

A recurring confusion worth stating plainly in `docs/DECISIONS.md`: SHA-256, SHA-384, and SHA-512 are **hash functions, not encryption**. They are one-way, take no key, and produce nothing that can be decrypted. They belong in integrity checking, HMAC, and key derivation. They do not provide confidentiality. Any request to "encrypt with SHA-512" is a category error and should be answered by pointing at this section.

## 3.2 Primitives

| Purpose | Choice | Rationale |
|---|---|---|
| Session and group key management | MLS (RFC 9420) via `openmls` | IETF standard designed for multi-device and groups from the start. Avoids inventing a protocol. |
| AEAD | AES-256-GCM or ChaCha20-Poly1305, per MLS ciphersuite | Standard, audited, fast. Used through the protocol, never directly. |
| Key agreement, classical | X25519 | Standard, fast, widely audited. |
| Key agreement, post-quantum | ML-KEM-768, hybrid with X25519 | Hybrid survives if either primitive falls. This is the **only** permitted cryptographic combining in this project. |
| Signatures | Ed25519 | Standard. |
| Hash and KDF | SHA-256 or SHA-384 inside HKDF, per ciphersuite | Integrity and key derivation. Not encryption. |
| Local database encryption | SQLCipher (AES-256) | Battle-tested, straightforward integration. |
| Password to key | Argon2id | Memory-hard, resists GPU cracking. |
| Transport, phases 1–3 | TLS 1.3 with certificate pinning | Defence in depth beneath E2EE. |
| Transport, phase 4 | Tor onion service via `arti` | Server never learns client IP. No exit node involved. |

**Starting ciphersuite:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` — chosen for best `openmls` support in the first working build. Document the upgrade path to a hybrid PQ ciphersuite once library support stabilises. Record this decision and its date.

## 3.3 Why not the alternatives

Record these in `docs/DECISIONS.md`, because interviewers ask:

- **Why not Signal Protocol?** Excellent, but MLS was designed for multi-device and group scenarios from the outset, which the product requires. Signal Protocol handles these through additional machinery layered on top.
- **Why not stack four ciphers?** Security is not additive. Stacking gives roughly the strength of the strongest cipher plus four times the code, four times the bug surface, and four times the side-channel exposure. Every significant real-world break in the past two decades came from implementation, key management, or protocol design. Essentially none came from brute-forcing AES-256.
- **Why not a VPN instead of Tor?** A VPN relocates trust to a single company that can log everything and be compelled to hand it over. Onion routing distributes trust across independent relays.
- **Why not build browser-based?** A web app served over HTTPS lets the server ship fresh JavaScript on every load, so the operator can silently push a backdoored build to one targeted user. Native clients are signed and updated visibly.
- **Why not keep the algorithms secret from users?** Kerckhoffs's principle: a system must stay secure even when everything except the key is public. Hiding the algorithm is security through obscurity. It fails because the user is not the adversary — an attacker reads the algorithm out of the decompiled binary or the network traffic, not out of the settings screen. Concealment costs user trust and gains nothing against anyone capable of attacking the system. AES-256 has been fully public for twenty-five years and remains unbroken precisely because publication invited attack and the attacks failed. An unreviewed algorithm is untested, not strong.

**The secret is the key. The algorithm is a credential.** Every algorithm this product uses is displayed in the UI on request and published in the repository.

## 3.4 Key verification

Users verify each other out of band by comparing a safety number derived from both identity keys, displayed as grouped digits and as a QR code. Verification is never blocking — users can message before verifying — but unverified state must be visible, not hidden. See §6.4 and §6.7.

---

# 4. System architecture

## 4.1 Component diagram

```
┌──────────────────────┐        ┌──────────────────────┐
│   Desktop client     │        │   Android client     │
│   Tauri + React      │        │   Kotlin + Compose   │
│   (UI only)          │        │   (UI only)          │
└──────────┬───────────┘        └──────────┬───────────┘
           │                                │
           │  FFI                           │  JNI
           └────────────┬───────────────────┘
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
                        │  TLS 1.3        (phases 1–3)
                        │  Tor onion      (phase 4+)
                        │
           ┌────────────▼─────────────┐
           │   relay server (Rust)    │
           │   axum + SQLite          │
           │                          │
           │   opaque blob queue      │
           │   no identity, no logs   │
           └──────────────────────────┘
```

## 4.2 The core crate

A single Rust crate holding all security-relevant logic. Every client is a thin UI over it. This is deliberate: cryptographic logic is written and reviewed once, not reimplemented per platform.

**The UI layer must never touch a key, a cipher, or a raw ciphertext blob.** The core exposes only high-level operations: `send_message`, `receive_messages`, `create_conversation`, `verify_contact`, `set_retention`, `wipe_all`. If a UI task appears to need lower-level access, that is a signal the core is missing an operation. Add it to the core rather than reaching around it.

## 4.3 The relay server

A queue for opaque blobs. Nothing more.

Stored per queued message:

| Field | Type | Notes |
|---|---|---|
| `message_id` | random 128-bit | No ordering information |
| `inbox_id` | opaque random identifier | Not a username, phone, or email |
| `blob` | ciphertext bytes | Server cannot decrypt |
| `expires_at` | timestamp | TTL only, default 30 days |

Blobs are deleted immediately on successful delivery, or at TTL expiry, whichever comes first.

## 4.4 Repository structure

```
/
├── core/                  Rust crate: all crypto, storage, transport
│   ├── src/
│   │   ├── crypto/        MLS integration, key handling
│   │   ├── storage/       SQLCipher, retention, backup
│   │   ├── transport/     TLS, Tor, retry
│   │   ├── attachments/   encryption, metadata stripping, padding
│   │   └── api.rs         the only surface clients touch
│   └── tests/
├── server/                Rust relay: axum + SQLite
├── clients/
│   ├── desktop/           Tauri + React
│   └── android/           Kotlin + Compose (phase 5)
├── docs/
│   ├── THREAT_MODEL.md
│   ├── DECISIONS.md
│   ├── ARCHITECTURE.md
│   ├── LIMITATIONS.md
│   ├── DESIGN_SYSTEM.md
│   └── PROGRESS.md
└── README.md
```

---

# 5. Threat model

Turn this section into `docs/THREAT_MODEL.md` as the first Phase 0 deliverable, and keep it current as phases land.

## 5.1 Adversaries defended against

| Adversary | Capability | Defence |
|---|---|---|
| Malicious or compromised server operator | Full read/write on server DB and code | Server holds only ciphertext it cannot decrypt; no identity fields exist to correlate |
| Passive network observer (ISP, public wifi) | Reads all traffic on one link | TLS 1.3 beneath E2EE; onion transport from phase 4 |
| Legal compulsion against the operator | Full handover of stored data | There is nothing meaningful to hand over |
| Theft of a locked device | Physical possession, no passphrase | SQLCipher with key in OS keystore; optional Argon2id passphrase |
| Server-side message tampering | Modify blobs in transit or at rest | AEAD authentication; tampering fails decryption visibly |
| Impersonation via key substitution | Server swaps a contact's key | Safety number verification; loud identity-change warning |

## 5.2 Adversaries explicitly not defended against

State these plainly. This section is the single most valuable page in the repository.

| Adversary | Why not |
|---|---|
| Global passive adversary correlating traffic timing at both endpoints | Fundamental limitation of low-latency messaging. Only high-delay mixnets address this, at a cost this product does not accept. |
| Compromised endpoint — malware, keylogger, screen capture | No application-layer defence exists. If the device is owned, the game is over. |
| Coercion of a participant | Out of technical scope. Partially mitigated by disappearing messages. |
| Malicious recipient screenshotting or forwarding | Inherent to any system a human can read. |
| Targeted supply-chain attack on a pinned dependency | Reduced by pinning and `cargo audit`, not eliminated. |

## 5.3 Metadata: three honest tiers

**Eliminated.** Message content, attachment content, filenames, file types, profile display names, group membership, sender identity as seen by the relay (sealed sender), plaintext timestamps in server storage.

**Reduced but present.** Message size, blunted by padding into fixed buckets. IP address, eliminated with respect to the server from phase 4 via onion service, but still visible to the local network and to the Tor guard node. Existence of an account and rough activity volume.

**Not addressed.** Timing correlation between send and receive events observable by an adversary watching both endpoints. Total traffic volume over long observation periods.

## 5.4 Honest positioning

The product does not beat Signal on cipher strength. It cannot — both use the same primitives, and those primitives are already infeasible to break. It differentiates on **policy and metadata**: no phone number required, self-hostable relay, Tor by default rather than optional, local-only storage by default, user-held backup keys, and a published threat model.

Against Messenger and iMessage the comparison is easier and can be stated factually: Messenger is not end-to-end encrypted in all contexts by default, and iMessage backs up to iCloud in a form Apple can read unless Advanced Data Protection is enabled.

---

# 6. UI and UX design

The design goal is **trust through legibility**. The user should feel the app is telling them the truth about their security state, rather than hiding uncertainty behind a padlock icon. Every visual decision below serves that.

Write this section into `docs/DESIGN_SYSTEM.md` and implement tokens before building any screen.

## 6.1 Design direction

The visual world is **sealed correspondence** — diplomatic pouches, wax seals, security envelope paper, courier manifests. Not cyberpunk, not hacker-terminal, not the green-on-black cliché. That aesthetic promises invulnerability, which is exactly the promise this product refuses to make. Sealed mail promises something more accurate: careful custody, honest handling, a visible record of who touched what.

Deliberately avoided: high-contrast serif on cream with a terracotta accent; near-black with an acid-green accent; broadsheet columns with hairline rules. These read as templated.

## 6.2 Color tokens

```
--ink            #131A24   primary text on light, base surface on dark
--slate          #1F2A36   elevated surface, dark mode
--paper          #E8E9E4   base surface, light mode (security envelope stock)
--paper-fold     #D6D8D1   dividers, inactive surface
--verdigris      #4E8C7D   primary accent: verified, sent, active
--verdigris-deep #2F5F53   pressed and focus states
--amber          #C4913E   pending, unverified, degraded — never alarming, always visible
--seal           #A8443A   reserved exclusively for identity-change warnings and destructive confirmation
--mute           #6B7684   secondary text, timestamps, metadata
```

`--seal` is semantic and rare. It must not be used for branding, buttons, or decoration. When a user sees that red, it means their trust assumption changed. Diluting it destroys its meaning.

Both light and dark themes ship from Phase 1. Dark uses `--ink` as base and `--slate` as elevated surface; light uses `--paper` and white.

## 6.3 Typography

```
Display / UI      IBM Plex Sans        400, 500, 600
Security data     IBM Plex Mono        400, 500
```

The monospace choice is structural, not decorative. **Every piece of machine-verifiable truth is set in mono**: safety numbers, key fingerprints, onion addresses, message IDs, retention timers. Every piece of human content is set in sans. The typeface itself tells the user which register they are reading. This distinction must be applied consistently or it loses its meaning.

Type scale: 12 / 14 / 16 / 20 / 28 / 40. Body copy at 16 with 1.55 line height. Safety numbers at 20 mono with generous letter spacing, grouped in blocks of five digits.

## 6.4 The signature element: the Custody Strip

A persistent band at the top of every conversation showing exactly three facts, always, in monospace:

```
┌─────────────────────────────────────────────────┐
│  ⬤ VERIFIED        ⬤ TOR         ⬤ 7-DAY        │
│    identity          transport      retention    │
└─────────────────────────────────────────────────┘
```

States:

| Field | States |
|---|---|
| Identity | `VERIFIED` (verdigris) · `UNVERIFIED` (amber) · `KEY CHANGED` (seal) |
| Transport | `TOR` (verdigris) · `DIRECT` (amber) · `OFFLINE` (mute) |
| Retention | `KEEP` · `30-DAY` · `7-DAY` · `24-HOUR` (verdigris when set, mute at default) |

Rules the strip must obey:

- It never shows a reassuring state when the underlying state is uncertain. Unverified is amber and stays amber until the user actually compares a safety number.
- It is tappable. Each field opens the relevant explanation and control.
- It never collapses or hides on scroll. Persistent visibility is the point.
- It uses text labels, never a lone padlock icon. A padlock means nothing to a user and can be read as a false guarantee.

This is the one element the product is remembered by. Everything around it stays quiet.

## 6.5 Pipeline transparency: the Manifest

The second signature element. Every message carries a visible record of every stage it passed through, in the courier-manifest idiom the design is built on.

### 6.5.1 The stage model

Nine stages, each with a machine name, a plain-language label, and an inspectable detail:

| # | Stage | Label shown | Detail on tap |
|---|---|---|---|
| 1 | `compose` | Composed | Byte length of plaintext, local only |
| 2 | `strip` | Metadata removed | Which fields were removed (attachments only) |
| 3 | `compress` | Compressed | Algorithm, before and after size |
| 4 | `pad` | Padded | Bucket size chosen, bytes added |
| 5 | `encrypt` | Encrypted | Ciphersuite, AEAD, key agreement, signature scheme |
| 6 | `seal` | Sender sealed | Explanation that the relay cannot see who sent this |
| 7 | `route` | Routed | Direct or Tor; hop count if Tor; relay address |
| 8 | `queue` | Held at relay | Blob ID, TTL remaining |
| 9 | `deliver` | Delivered | Time delivered, time relay copy deleted |

Stages 2 and 3 are skipped for plain text messages and shown as `not applicable`, never hidden. An absent stage is itself information.

### 6.5.2 Compression, and a security caveat

Compression must be applied **before** encryption to be effective at all, which introduces a known risk: compressing attacker-influenced content together with secret content enables compression-ratio side channels of the CRIME and BREACH family.

Mitigation for this product: compress each message payload in isolation, never across messages, never mixing user content with protocol fields. Pad after compressing, which is the ordering in §7.1. Record this reasoning in `docs/DECISIONS.md`.

If a task would compress two independently sourced pieces of content into one unit, stop and flag it per §2.6.

### 6.5.3 Presentation

Collapsed by default as a single mono line beneath each message, tappable:

```
⟩ 9 stages · AES-256-GCM · Tor · delivered 14:02
```

Expanded, it becomes a vertical manifest:

```
┌────────────────────────────────────────────────┐
│  MESSAGE MANIFEST                              │
│                                                │
│  01  COMPOSED           412 bytes              │
│  02  METADATA REMOVED   n/a — text message     │
│  03  COMPRESSED         zstd · 412 → 288       │
│  04  PADDED             → 1024 bytes (+736)    │
│  05  ENCRYPTED          AES-256-GCM            │
│      key agreement      X25519                 │
│      signature          Ed25519                │
│      protocol           MLS · RFC 9420         │
│  06  SENDER SEALED      relay cannot see you   │
│  07  ROUTED             Tor · 3 hops           │
│  08  HELD AT RELAY      1.4s · TTL 30d         │
│  09  DELIVERED          14:02:19               │
│      relay copy erased  14:02:19               │
│                                                │
│  What the relay could see  ⟩                   │
└────────────────────────────────────────────────┘
```

All values in mono, per the typographic rule in §6.3. Labels in `--mute`, values in body ink, stage numbers in `--verdigris`.

The numbered markers are justified here because this genuinely is an ordered pipeline where sequence carries meaning the reader needs — stage 4 padding after stage 3 compression is a security-relevant ordering.

### 6.5.4 "What the relay could see"

The manifest's final row opens the most valuable screen in the product for demonstrating the architecture. It shows, for this specific message, the complete set of fields visible to the relay operator:

```
┌────────────────────────────────────────────────┐
│  WHAT THE RELAY COULD SEE                      │
│                                                │
│  inbox id      7f3a…c219  (random, not you)    │
│  blob size     1024 bytes (padded)             │
│  arrival       within a 30-day TTL window      │
│                                                │
│  NOT VISIBLE                                   │
│  message content · your name · recipient name  │
│  sender identity · filename · file type        │
│  your IP address · exact send time             │
│                                                │
│  STILL INFERABLE BY A NETWORK OBSERVER         │
│  that you connected · roughly when · how often │
└────────────────────────────────────────────────┘
```

The third block is required. Showing only what is protected while omitting what leaks is exactly the reassuring half-truth Prime Directive 3 forbids.

### 6.5.5 Live stage progression

While sending, the collapsed line animates through the stages in sequence rather than showing a generic spinner. Each stage lights as it completes. On failure, the line stops at the failed stage and names it: `⟩ failed at stage 07 · routing · no relay connection`.

This turns error reporting into diagnosis for free, and it is the single most compelling thing to show in a demo.

`prefers-reduced-motion` replaces the progression with the final state appearing instantly.

## 6.6 Screen inventory

Build in this order. Each is listed with its single job.

| # | Screen | Job |
|---|---|---|
| 1 | First run | Create an identity in under 30 seconds with no personal data requested |
| 2 | Conversation list | Show who is waiting, and nothing else |
| 3 | Conversation view | Read and write, with custody state always visible |
| 4 | Add contact | Exchange keys with a person who is physically or remotely present |
| 5 | Safety number | Let two people compare a value out of band and mark verified |
| 6 | Identity change warning | Interrupt, explain, and require a decision |
| 7 | Privacy and storage | Give real control over what is kept and for how long |
| 8 | Attachment preview | Show what will be stripped before sending |
| 9 | Transport settings | Choose direct or Tor, and explain the trade honestly |
| 10 | Backup export / import | Move history without trusting the server |
| 11 | Wipe local data | Destroy, with a confirmation proportional to the consequence |
| 12 | Security details | Publish exactly what this app uses, with no vagueness |

## 6.7 Screen specifications

**1. First run.** No phone number, no email, no username on a server. Generate an identity keypair locally. Ask for a display name that is local-only and shared only with contacts the user adds. Offer, but do not force, a passphrase for the local database. Copy: "Your account lives on this device. Nothing about you is sent to a server." One primary action: "Create identity."

**2. Conversation list.** Rows show contact name, last message preview, and relative time. A small amber dot on rows where identity is unverified. No unread-count badges that could be inferred by an observer of notification traffic. Empty state: "No conversations yet. Add someone using their invite code." with the primary action inline, not floating.

**3. Conversation view.** Custody Strip pinned at top. Messages in sans. Timestamps in mono, muted, small. Sent messages align right on `--verdigris` at low opacity; received align left on surface. Message state uses text, not icons: `sending` / `sent` / `failed — retry`. A failed message shows the reason inline.

**4. Add contact.** Two modes side by side: show my invite code (QR plus mono text block), and enter theirs (paste or scan). Copy explains what the code contains: "This code holds your public key and inbox address. It contains no personal information."

**5. Safety number.** Both parties' numbers shown as a 60-digit block, mono, grouped in fives, plus a QR. Copy: "Compare this number with your contact in person or over a call you trust. If it matches, mark them verified." Two actions: "Numbers match — mark verified" and "They don't match." The second leads to a clear explanation of what a mismatch may mean.

**6. Identity change warning.** A modal, not a toast. `--seal` header. Copy states the fact and the two explanations without accusing: "This contact's identity key changed on 3 March. This usually means they reinstalled the app or switched devices. It can also mean someone is intercepting your messages. Verify the new safety number before continuing." Actions: "Verify now" (primary) and "Continue without verifying" (secondary, not hidden — users have reasons). Messages sent after an unverified key change are marked in the thread.

**7. Privacy and storage.** Plain-language controls, each with a one-line consequence:
- Keep messages: forever / 30 days / 7 days / 24 hours
- Disappearing messages, per conversation
- Passphrase-protect this device
- Export encrypted backup
- Wipe all local data

Each label names what the user controls, not how the system works. "Keep messages" rather than "Retention TTL policy."

**8. Attachment preview.** Before sending, show the file and a mono manifest of what is being removed: `EXIF: removed` / `GPS: removed` / `Original filename: not sent` / `Padded to: 256 KB`. This turns an invisible safety feature into visible product value, and it is the second-most demonstrable screen in the whole app.

**9. Transport settings.** Two options with honest copy. Direct: "Faster. The server sees the IP address you connect from." Tor: "Adds one to three seconds per message. The server never learns your IP address. Your internet provider can still see that you are using Tor." No option is labelled as the secure one; the trade is stated and the user chooses.

**10. Backup export / import.** Generate a recovery key, display in mono, require the user to confirm they have saved it. Copy: "This key is the only way to open your backup. It is not stored anywhere. If you lose it, the backup cannot be recovered."

**11. Wipe local data.** Requires typing the word `wipe` to confirm. Copy states exactly what is destroyed and that it cannot be undone.

**12. Security details.** A plainly formatted mono list of every mechanism in use: MLS ciphersuite, AEAD, key agreement, signature scheme, KDF, local database encryption, passphrase derivation, compression algorithm, padding buckets, transport. Each with a one-line explanation of what it does. Includes the app version, the pinned `openmls` version, and a link to the repository.

Opening copy: "Nothing here is secret. The security of this app rests on your keys, not on hiding how it works." Closing copy: "This app is unaudited student work. Do not rely on it if you face a serious adversary."

Reachable from settings and from the manifest's encryption stage.

## 6.8 Motion

Restrained. One orchestrated moment: on send, a brief seal-press — the message bubble compresses 2% and settles as state moves from `sending` to `sent`, 180ms, ease-out. Everything else is a 120ms opacity or position transition, or nothing.

`prefers-reduced-motion` removes the seal-press and all transitions, leaving instant state changes. Not optional.

## 6.9 Copy rules

- Active voice. A control says what happens: "Wipe all data", not "Submit".
- An action keeps the same word through the whole flow. The button that says "Verify" produces a confirmation that says "Verified."
- Name things by what people control, never by how the system is built. "Keep messages for 7 days", not "Set TTL policy".
- Errors explain what happened and what to do. Never "Something went wrong." Instead: "Message not sent — no connection to the relay. It will send automatically when you reconnect."
- Errors do not apologise and are never vague.
- Empty states invite an action and include the control to take it.
- No exclamation marks in system copy. No emoji in system copy.
- Never use the words in §2.4.

## 6.10 Accessibility floor

Non-negotiable from Phase 1:

- All text meets WCAG AA contrast (4.5:1 body, 3:1 large). Verify `--amber` and `--mute` against both themes explicitly; amber on light is the likely failure.
- Visible keyboard focus on every interactive element. Never `outline: none` without a replacement.
- Full keyboard navigation, logical tab order, Escape closes modals.
- Touch targets minimum 44×44px on Android.
- Semantic labels on all controls for screen readers. The Custody Strip announces its three states as text.
- `prefers-reduced-motion` respected.
- Responsive down to 360px width.
- Never convey state through colour alone. The Custody Strip pairs every colour with a text label for this reason.

---

# 7. Data handling

## 7.1 Attachment pipeline

Order matters. Strip before encrypt, always.

1. Generate a fresh random symmetric key for this file.
2. Strip all metadata client-side: EXIF, GPS coordinates, device make and model, capture timestamps, editing history. Use a maintained library. Do not hand-parse EXIF.
3. Pad to a fixed size bucket — 64 KB, 256 KB, 1 MB, 4 MB, 16 MB, then 16 MB increments — to blunt size fingerprinting.
4. Encrypt with the per-file key.
5. Upload ciphertext to the relay, which stores it under a random ID and never sees the key.
6. Send the file key and blob ID inside the E2EE message payload.

Original filenames never travel unencrypted. They live inside the encrypted payload.

Video requires stripping container-level metadata as well as frame metadata. Flag if the chosen library does not handle the container.

## 7.2 Local storage

SQLCipher. Key derived from the OS keystore (Keychain on macOS, DPAPI on Windows, Secret Service on Linux, Keystore on Android), or from a user passphrase via Argon2id when the user opts in.

Default retention: keep forever, with the setting surfaced during first run rather than buried. Record the reasoning in `docs/DECISIONS.md`.

## 7.3 Backup

Encrypted with a key derived from a user-held recovery phrase. Never uploaded. Exported as a file the user places where they choose. The server has no backup feature and must not gain one.

---

# 8. Test and verification matrix

## 8.1 Core unit tests
Message encrypt and decrypt round trip. MLS group creation and member addition. Key rotation. Retention expiry logic. Argon2id derivation determinism. Constant-time comparison usage.

## 8.2 Integration tests
Full send and receive through a local relay. Offline queue and retry on reconnect. Multi-message ordering. Failed decryption surfaces an error rather than silently dropping.

## 8.3 Server blindness test
**The single highest-value test in the repository.** Automated: run a conversation containing a known unique string, dump the entire server database, and assert the string appears nowhere in it. Extend to assert no field contains a display name, no field contains a sender identifier, and no timestamp beyond TTL exists.

Write this test before the feature it verifies.

## 8.4 Metadata stripping test
Upload an image with known GPS EXIF and a distinctive original filename. Retrieve and decrypt. Assert EXIF is absent, GPS is absent, and the filename is not present in any server-visible field. Repeat for video.

## 8.5 Padding test
Send files of 70 KB and 200 KB. Assert both produce blobs of identical size on the server.

## 8.6 Manifest accuracy test
The manifest must never claim a stage that did not run. Assert that a message sent with compression disabled reports `not applicable` at stage 3 rather than a compressed size, and that a message sent over direct transport reports `direct` at stage 7 rather than `Tor`. A manifest that lies is worse than no manifest.

## 8.7 Compression isolation test
Assert that each message payload is compressed in isolation. Send two messages where one contains attacker-chosen content and the other contains a secret, and assert their compressed sizes are independent of each other. This guards the CRIME-family side channel described in §6.5.2.

## 8.8 Guardrail tests in CI
- `cargo audit` and `npm audit`, failing on known vulnerabilities
- Grep the codebase for forbidden logging of plaintext or key material, failing the build on a hit
- Grep documentation and UI strings for the banned marketing terms in §2.4
- Contrast ratio check on the token palette
- Assert the server binary's access logging is disabled in its default config

## 8.9 Manual verification checklist
Identity change triggers the modal, not a toast. Safety number matches on both devices. Wipe actually removes the database file. Locked device with the DB file copied off cannot be read. Tor mode shows a real onion connection and no IP in server state. Keyboard-only navigation completes a full send.

---

# 9. Build phases

Do not begin a phase before the previous phase meets its exit criteria. Update `docs/PROGRESS.md` at the end of every session.

### Phase 0 — Foundation (≈1 week)
Repo structure per §4.4. `docs/THREAT_MODEL.md` written from §5. `docs/DECISIONS.md` started with every choice in §3 recorded with rationale and date. `docs/DESIGN_SYSTEM.md` from §6 with tokens implemented. CI running build, test, clippy, and audit. README per §2.4.

**Exit:** threat model complete; CI green; README free of unsupportable claims; design tokens implemented in the desktop client shell.

### Phase 1 — Working 1:1 encrypted chat (≈3–4 weeks)
`openmls` integrated, two-party group creation. SQLCipher local store. Relay: POST blob to inbox, GET and drain inbox, TLS with pinning, access logging disabled. Desktop client: first run, add contact, conversation list, conversation view, Custody Strip, safety number screen, security details screen. Light and dark themes.

Manifest (§6.5) at partial scope: stages 1, 4, 5, 8, 9 only, since stripping, sealing, and Tor arrive in later phases. Unimplemented stages display as `not yet implemented`, never as complete. Live stage progression and the "what the relay could see" screen ship here — the latter is what makes the architecture demonstrable.

**Exit:** two desktop clients on different machines exchange text reliably. Server blindness test (§8.3) and manifest accuracy test (§8.6) pass. Manual DB dump reviewed and confirmed clean. **This is the milestone at which the project becomes portfolio-presentable — stop and write it up here even if you continue.**

### Phase 2 — Storage control and hardening (≈2 weeks)
Disappearing messages, retention settings, wipe-all. Passphrase option with Argon2id. Encrypted backup export and import. Identity change detection and the warning modal. Full test suite from §8.1, §8.2, §8.8.

**Exit:** every storage control functional; identity change modal verified manually; suite green in CI.

### Phase 3 — Attachments and compression (≈3 weeks)
Attachment pipeline per §7.1. Attachment preview screen with the strip manifest. Per-message compression with the isolation constraint in §6.5.2. Image and file rendering. Manifest stages 2 and 3 activated.

Sealed sender (manifest stage 6) was originally scoped here but is **not** a Phase 3 exit requirement — see the note under Phase 4 for why, decided 2026-08-02. Everything else in this phase does not depend on Tor and proceeds on its own schedule.

**Exit:** metadata stripping test (§8.4) and padding test (§8.5) pass. An image sent through the system and inspected server-side reveals no EXIF, no filename, no sender.

### Phase 4 — Tor transport, then sealed sender (≈2 weeks + sealed sender)
Relay as an onion service. `arti` embedded in core. Transport settings screen. Fixed-size padding, optional cover traffic. Threat model updated to reflect what changed.

**Sealed sender moved here from Phase 3, decided 2026-08-02.** The relay's wire protocol already carries no sender field — confirmed by reading `server/src/http.rs` and `core/src/transport.rs` — so the only remaining signal of who sent a message is the TCP/TLS source IP a direct connection necessarily exposes. That is a network-layer problem, not a message-field one, and this project has exactly one planned mechanism for closing it: this phase's onion service. Building a separate anonymity layer to close it earlier would mean designing a new routing construction outside an audited protocol — the same class of decision SPEC §2.6 reserves for a stop-and-ask, and a larger one than Phase 3's attachment encryption turned out to be. Manifest stage 6 activates here, once Tor exists for it to report honestly.

**Exit:** messaging works end to end over Tor; server state confirmed to contain no client IP; Custody Strip shows `TOR` accurately; manifest stage 6 (`SENDER SEALED`) reports as ran rather than not yet implemented.

### Phase 5 — Android client (≈4+ weeks)
Core compiled for Android via JNI. Kotlin and Compose UI mirroring the desktop feature set and design system. Keystore integration. Signed APK.

**Exit:** APK installs on a physical device and exchanges messages with a desktop client. Manifest requests only the permissions in §2.2.

### Phase 6 — Multi-device and groups (stretch)
Genuinely hard. MLS makes it tractable, but this is where scope explodes. Treat as documented roadmap unless Phases 0–5 are complete and solid.

---

# 10. Documentation deliverables

For portfolio purposes these matter as much as the code.

| File | Contents |
|---|---|
| `README.md` | What this is, primitives used, honest status, build instructions, the unaudited warning |
| `docs/THREAT_MODEL.md` | §5 expanded, kept current per phase |
| `docs/DECISIONS.md` | Every crypto and architecture decision with date and rationale, **including rejected options and why** |
| `docs/ARCHITECTURE.md` | §4 with data flow diagrams |
| `docs/LIMITATIONS.md` | Plain-language statement of what this does not protect against |
| `docs/DESIGN_SYSTEM.md` | §6 tokens, components, copy rules |
| `docs/PROGRESS.md` | Session log: what landed, what is next, what is blocked |

`DECISIONS.md` is the highest-value artifact for interviews. It demonstrates reasoning, which is what is actually being assessed.

---

# 11. How to describe this project

**Accurate, for a CV or interview:**

> End-to-end encrypted messenger built on MLS (RFC 9420) with a metadata-minimising relay architecture. Desktop and Android clients share a Rust core handling MLS state, encrypted local storage, and transport. The relay stores only opaque ciphertext blobs with no identifying metadata, verified by an automated server-blindness test. Optional Tor onion transport removes client IP exposure to the server. Ships with a written threat model documenting both defended and undefended adversary classes.

**Never:**

> Unbreakable military-grade encryption, stronger than Signal.

The first invites a follow-up question. The second ends the conversation.
