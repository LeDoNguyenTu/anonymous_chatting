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
| Identity private key | Client device only | SQLCipher at rest, keyed by an optional Argon2id passphrase — or, when none is set, by a device file beside the database (D-035). The OS keystore route SPEC §7.2 names is **not built on any platform**, desktop or Android. |
| Who is talking to whom | Nowhere as a stored fact | Opaque inbox identifiers; sealed sender (Phase 4 — moved from Phase 3, 2026-08-02, once it turned out to depend on Tor) |
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
| Theft of a locked device | Physical possession, no passphrase, ability to image the disk | Local database is SQLCipher (AES-256) with the key held in the OS keystore, or derived from an Argon2id passphrase when the user opts in. | A device stolen *unlocked*, or with a weak passphrase, is not protected. Coldboot and DMA attacks are out of scope. **On both desktop and Android the "OS keystore" half of this is not built** — the key is a file beside the database (D-035). Only the passphrase route offers real protection today. |
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
| **Traffic analysis of message frequency** over a long observation window | Padding blunts size. It does nothing about how often a user connects. Cover traffic was named in Phase 4's scope and was **not built** — SPEC does not specify its shape, and an improvised version an observer can distinguish is worse than none. Deferred pending an explicit design decision (D-044). |
| **A compromised OS keystore** or a platform-level backdoor | Pouch trusts the keystore. If the keystore lies, the local database key is exposed. |
| **A known deviation from RFC 9180 in the HPKE backend** | The `hpke-rs` version that `openmls` pins does not check that an X25519 Diffie-Hellman shared secret is non-zero, which RFC 9180 requires (RUSTSEC-2026-0072). The fix exists upstream in a release `openmls` cannot yet use. Recorded rather than hidden; full reasoning in `DECISIONS.md` D-030. |
| **A defect in the Tor implementation itself** | From Phase 4 the relay hosts a v3 onion service through `tor-hsservice`, whose own documentation describes its hosting API as "a low-level implementation that may not be suitable for typical users". The arti family is actively developed and is younger, less battle-tested code than `openmls` or `rusqlite` — and considerably younger than the C Tor daemon it reimplements. Chosen anyway (D-039) because the alternative was shelling out to a separate process, but the maturity difference is real and belongs here rather than in a footnote. A defect here would affect IP exposure and reachability; it would not touch message confidentiality, which is MLS and independent of the transport. |
| **A defect in the JNI boundary on Android** | From Phase 5 the Android client reaches the core across FFI. A Rust panic unwinding across that boundary is undefined behaviour, so every exported function catches; a guardrail counts exports against `catch_unwind` wrappers and fails the build if one arrives without it. What that does **not** cover is the JNI marshalling itself, which — uniquely in this project — has never been executed anywhere. No device, no emulator, no JVM was available while it was written. The design response was to make that surface one function rather than thirty-five (D-048), with every decision behind it under test, but "small and reviewed" is not "run". Treat the Android client as the least-exercised code here until it has run on hardware. |
| **A key extracted from the Android device file** | The Android client uses the same device-file key placeholder as the desktop client (D-035): a random key in a file beside the database it unlocks. Anyone who can read one can read the other. Android's per-app private directory means that is not *nothing* — another installed app cannot reach it — but a rooted device, an unlocked bootloader, or a physical extraction reads both. Android Keystore is named by SPEC §7.2 and is **not implemented**; it is the single largest gap in this client. `allowBackup="false"` and an explicit `data_extraction_rules` at least stop the platform copying database and key together to Google Drive, which was the default. |
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
- Sender identity as seen by the relay — **from Phase 4**, via sealed sender
  (moved from Phase 3, 2026-08-02 — the relay's wire protocol already has no
  sender field; what remains is the TCP/TLS source IP, which only the Phase 4
  onion service removes)

### Reduced but present

Exists, but blunted:

- **Message size** — padded into fixed buckets, so a 70 KB file and a 200 KB
  file produce identically sized blobs. From Phase 4 this covers message
  payloads too, not attachments alone (D-041).
- **Client IP address** — visible to the relay in Phases 1–3. From Phase 4,
  eliminated with respect to the relay **when Tor is selected**, and still
  exposed on the direct route, which remains available and remains a choice
  the user can make. This is deliberately not stated as "IP address hidden":
  which of the two is true depends on the transport in use at that moment, and
  the interface reports the actual route rather than the available one. Even
  over Tor, the local network operator and the Tor guard node retain partial
  visibility, always.
- **Existence of an account** — the relay knows some inbox identifier is being
  polled. It does not know whose.
- **Rough activity volume** — how much traffic an inbox sees.

### Not addressed

Present, unmitigated, and worth understanding before relying on this:

- **Timing correlation** between a send event and a receive event, observable by
  an adversary watching both endpoints.
- **Total traffic volume** over a long observation period.
- **The fact that Tor is in use**, visible to the user's ISP.
- **Traffic patterns over time.** Cover traffic was named in Phase 4's scope
  and deliberately not built — SPEC does not specify its shape, and an
  improvised version that an observer can distinguish from real traffic is
  worse than none at all. Deferred pending an explicit design decision
  (D-044).

## 6. Honest positioning

Pouch does not beat Signal on cipher strength. It cannot. Both use primitives
that are already computationally infeasible to break, so there is no headroom to
compete over. Anyone claiming a strength advantage here is describing a
misunderstanding of where systems actually fail — which is implementation, key
management, and protocol design, essentially never brute force.

Where Pouch differs is **policy and metadata**:

- No phone number or email required to create an account
- Self-hostable relay
- Tor available as a transport from Phase 4, chosen on a settings screen that
  states what each route costs rather than marking one "secure". It is **not**
  the default: the direct route is what a fresh install uses, and Tor is opted
  into. An earlier version of this file called Tor the default transport,
  which the code does not support and this line corrects.
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
| 4 | Client IP moves from "reduced but present" to route-conditional: eliminated with respect to the relay over Tor, still exposed on the direct route. Stated that way rather than as a blanket claim, because which is true depends on the transport in use. Verified end to end against the live Tor network — a real v3 onion address published, dialled from a separate client, answered. Padding extended from attachments to every message payload (D-041). Cover traffic named in scope and deliberately not built (D-044) — recorded in two places above rather than quietly dropped. Added the `tor-hsservice` maturity caveat: a newer, less battle-tested dependency than the rest of the stack, accepted knowingly. Corrected a claim in §6 that called Tor the default transport; it is opt-in. |
| 5 | A second client changes what "the device" means, and two claims in this file were corrected because of it. §1 said the identity private key is protected by the "OS keystore, optional Argon2id passphrase"; the keystore half has never been built on any platform (D-035), so only the passphrase route offers real protection, and both §1 and §3 now say so. Added two adversaries: a defect in the JNI boundary — the only code in this project never executed anywhere, since no device, emulator or JVM was available while it was written — and extraction of the Android device-file key, which is the largest gap in that client. Android's auto-backup was found to copy the database and its keying sidecar to Google Drive by default; `allowBackup="false"` plus explicit `data_extraction_rules` turn that off, and it is worth recording that the platform default would have created the server-side backup SPEC §7.3 says this project does not have. RUSTSEC-2026-0212 was re-checked as `.cargo/audit.toml` asked: `libcrux-secrets` is genuinely compiled for aarch64 now, where before it was not, and the acceptance rests on different grounds as a result. |
