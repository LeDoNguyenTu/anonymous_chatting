# Threat model

**Status:** current as of Phase 0. Updated at the end of every phase.
**Last revised:** 2026-08-01

This document states what Pouch defends against and — more importantly — what it
does not. The second list is the one worth reading. A threat model that only
lists wins is marketing.

Pouch is unaudited student work. Nothing below should be read as a guarantee.

---

## 1. What is being protected

| Asset | Where it lives | Protected by |
|---|---|---|
| Message plaintext | Client device only | MLS group encryption; SQLCipher at rest |
| Identity private key | Client device only | OS keystore, optional Argon2id passphrase |
| Who is talking to whom | Nowhere as a stored fact | Opaque inbox identifiers; sealed sender (Phase 3) |
| Attachment content and filenames | Client device; ciphertext at relay | Per-file key inside the E2EE payload |
| Client IP address | Visible to relay until Phase 4 | Onion service from Phase 4 |

## 2. Trust assumptions

Stated plainly, because every one of these is a place the model breaks if the
assumption is wrong.

1. **The user's device is not compromised.** This is the big one. See §4.
2. **The audited libraries are correct.** `openmls`, `rustls`, `argon2`,
   SQLCipher. Pouch writes no primitives of its own (Prime Directive 1), so
   Pouch inherits their correctness and their bugs.
3. **The OS keystore protects what it claims to protect** while the device is
   locked.
4. **The user actually compares safety numbers** out of band before treating a
   contact as verified. Until they do, the UI says `UNVERIFIED` in amber and
   keeps saying it.
5. **`OsRng` is a real CSPRNG** on the platform in question.

## 3. Adversaries defended against

| Adversary | Capability assumed | Defence | Residual risk |
|---|---|---|---|
| Malicious or compromised relay operator | Full read/write on the relay database and the relay source code | The relay holds ciphertext it has no key for. There are no identity fields to correlate: no username, no phone, no email, no sender field. Verified automatically by the server-blindness test (`docs/../core/tests`, SPEC §8.3). | Operator still sees blob sizes (padded), inbox identifiers, and connection timing. See §5. |
| Passive network observer — ISP, public wifi, campus network | Reads every byte on one link | TLS 1.3 beneath the E2EE layer, with the relay certificate pinned by SPKI hash so a rogue CA is not sufficient. Onion transport from Phase 4. | Observer sees that the user connected to a relay, and roughly when and how often. |
| Legal compulsion against the operator | Compelled full handover of everything stored | There is nothing meaningful to hand over. No account records exist because accounts are not created on the server. | A compelled operator can start logging *future* connections. Pouch cannot prevent this; Phase 4 onion transport is what reduces it. |
| Theft of a locked device | Physical possession, no passphrase, ability to image the disk | Local database is SQLCipher (AES-256) with the key held in the OS keystore, or derived from an Argon2id passphrase when the user opts in. | A device stolen *unlocked*, or with a weak passphrase, is not protected. Coldboot and DMA attacks are out of scope. |
| Relay-side message tampering | Modify or replace blobs at rest or in flight | AEAD authentication. A modified blob fails to decrypt and surfaces as a visible error, never as a silently dropped message. | The relay can still *withhold* or *delay* messages. Denial of service is not defended against. |
| Impersonation via key substitution | The relay serves a contact's key that the relay controls | Safety numbers derived from both identity keys, compared out of band. An identity key change raises a blocking modal in `--seal`, not a dismissible toast. | Effective only if the user actually performs the comparison. An unverified contact is exactly as trustworthy as the delivery channel for their invite code. |
| Retrospective decryption of recorded traffic | Records ciphertext now, breaks it later | Forward secrecy through MLS key rotation: compromising today's keys does not open yesterday's messages. | The starting ciphersuite is classical (X25519). A future adversary with a cryptographically relevant quantum computer could open recorded traffic. The hybrid PQ upgrade path is tracked in `DECISIONS.md`. |

## 4. Adversaries explicitly **not** defended against

This is the most valuable section in the repository. Read it before trusting
anything here with anything that matters.

| Adversary | Why Pouch does not defend against it |
|---|---|
| **Compromised endpoint** — malware, keylogger, screen capture, a hostile person with the unlocked device | No application-layer defence exists. Encryption protects a message in transit and at rest; it cannot protect a message being read off the screen it is displayed on. If the device is owned, the game is over. This is true of Signal too. |
| **Global passive adversary** correlating traffic timing at both ends | A fundamental limitation of low-latency messaging. Only high-delay mixnets address it, at a usability cost this product does not accept. Tor raises the bar; it does not clear it. |
| **Coercion of a participant** — rubber-hose, subpoena against a user, a border officer demanding an unlock | Out of technical scope. Disappearing messages reduce how much exists to be surrendered. They do not help against coercion applied before the timer expires. |
| **A malicious recipient** screenshotting, forwarding, or simply repeating what they read | Inherent to any system a human can read. No product solves this, and any product claiming to is lying. |
| **Targeted supply-chain attack** on a pinned dependency | Exact version pinning and `cargo audit` reduce exposure to *known* vulnerabilities and to surprise upgrades. Neither detects a deliberate backdoor in a dependency that has not been discovered yet. Pouch has no reproducible-build story yet. |
| **Traffic analysis of message frequency** over a long observation window | Padding blunts size. It does nothing about how often a user connects. Cover traffic is a Phase 4 option, not a default. |
| **A compromised OS keystore** or a platform-level backdoor | Pouch trusts the keystore. If the keystore lies, the local database key is exposed. |
| **A known deviation from RFC 9180 in the HPKE backend** | The `hpke-rs` version that `openmls` pins does not check that an X25519 Diffie-Hellman shared secret is non-zero, which RFC 9180 requires (RUSTSEC-2026-0072). The fix exists upstream in a release `openmls` cannot yet use. Recorded rather than hidden; full reasoning in `DECISIONS.md` D-030. |
| **Denial of service** — the relay refusing to accept or deliver | The relay is trusted for availability and for nothing else. A hostile operator can stop messages. It cannot read them. |

## 5. Metadata: three honest tiers

Not "we protect your metadata". Three tiers, because the truth has three tiers.

### Eliminated

Never exists in a form the relay can read, at any point:

- Message content
- Attachment content, filenames, and file types
- Profile display names
- Group membership
- Plaintext timestamps in relay storage (only a TTL expiry column exists)
- Sender identity as seen by the relay — **from Phase 3**, via sealed sender

### Reduced but present

Exists, but blunted:

- **Message size** — padded into fixed buckets, so a 70 KB file and a 200 KB
  file produce identically sized blobs.
- **Client IP address** — visible to the relay in Phases 1–3. Eliminated with
  respect to the relay from Phase 4 via onion service. Still visible to the
  local network operator and to the Tor guard node, always.
- **Existence of an account** — the relay knows some inbox identifier is being
  polled. It does not know whose.
- **Rough activity volume** — how much traffic an inbox sees.

### Not addressed

Present, unmitigated, and worth understanding before relying on this:

- **Timing correlation** between a send event and a receive event, observable by
  an adversary watching both endpoints.
- **Total traffic volume** over a long observation period.
- **The fact that Tor is in use**, visible to the user's ISP.

## 6. Honest positioning

Pouch does not beat Signal on cipher strength. It cannot. Both use primitives
that are already computationally infeasible to break, so there is no headroom to
compete over. Anyone claiming a strength advantage here is describing a
misunderstanding of where systems actually fail — which is implementation, key
management, and protocol design, essentially never brute force.

Where Pouch differs is **policy and metadata**:

- No phone number or email required to create an account
- Self-hostable relay
- Tor as the default transport from Phase 4, not an option buried in settings
- Local-only storage by default, with no server-side backup feature at all
- User-held backup keys
- A published threat model — this file

Against Messenger and iMessage the comparison is factual rather than
competitive: Messenger is not end-to-end encrypted in all contexts by default,
and iMessage backs up to iCloud in a form Apple can read unless Advanced Data
Protection is switched on.

And the part that belongs in the same breath: Signal is audited by
cryptographers. Pouch is not audited by anyone. For a person facing a serious
adversary, that difference outweighs every policy advantage listed above.

## 7. Phase log

| Phase | What changed in this model |
|---|---|
| 0 | Initial model written from the specification. No code paths exist yet, so nothing here is yet verified by a running test. |
| 1 | Relay blindness now verified by an automated test against a real conversation, not asserted. Local storage encryption verified by reading the database file. Added the RFC 9180 deviation above, found by `cargo audit` — an unfixable-for-now advisory in a dependency is part of the threat model, not a CI nuisance. |
