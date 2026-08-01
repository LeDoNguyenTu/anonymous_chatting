# Decisions

Every cryptographic and architectural decision, with the date it was made, the
reasoning, and — the part that actually matters — the options that were rejected
and why.

Entries are append-only. When a decision is reversed, the original stays and a
new entry supersedes it. A decision log that has been tidied up is a decision log
that has lost its evidence.

---

## D-001 — SHA-256/384/512 are hash functions, not encryption
**Date:** 2026-08-01 · **Status:** accepted

Stated first because it is the most common category error in this problem space,
and because the rest of this document assumes it is settled.

A hash function is one-way. It takes no key. It produces no output that can be
turned back into the input. SHA-256, SHA-384, and SHA-512 provide **integrity**
and are used as building blocks inside HMAC and HKDF. They provide **no
confidentiality whatsoever**.

"Encrypt it with SHA-512" is not a stronger version of "encrypt it with AES." It
is not a weaker version either. It is a different category of operation, in the
way that "weigh it in metres" is not a coarser way of measuring mass.

In this project: SHA-256/384 appear only inside HKDF for key derivation and
inside the MLS transcript hash. They never appear as a confidentiality mechanism,
because they cannot be one.

---

## D-002 — MLS (RFC 9420) for session and group key management
**Date:** 2026-08-01 · **Status:** accepted · **Library:** `openmls =0.8.1`

**Decision.** All session establishment, key agreement, ratcheting, and group
membership goes through MLS via `openmls`. No handshake or ratchet is written by
hand.

**Why.** MLS is an IETF standard designed from the outset for groups and multiple
devices per identity, which the product roadmap requires (Phase 6). It provides
forward secrecy and post-compromise security as protocol properties rather than
as things this project has to construct. It is specified in public, has multiple
independent implementations, and has received academic analysis.

**Rejected: Signal Protocol (X3DH + Double Ratchet).** Excellent, and more
battle-tested in deployment than MLS. Rejected because it is fundamentally a
pairwise protocol; groups and multi-device are handled by layering additional
machinery on top (sender keys, per-device fan-out). That layering is exactly the
kind of protocol design work Prime Directive 1 forbids inventing. MLS moves that
complexity into a standard someone else has already reviewed.

**Rejected: rolling our own ratchet.** Not seriously considered. Recorded here
because "it's just a KDF chain" is a thought people have, and it is wrong. Every
significant real-world break in the last two decades came from implementation,
key management, or protocol design — essentially none from breaking a cipher.

---

## D-003 — Starting ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
**Date:** 2026-08-01 · **Status:** accepted, with a documented upgrade path

**Decision.** Ship the first working build on
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.

**Why.** It is the ciphersuite with the most solid support in `openmls 0.8.1`,
and Prime Directive 4 says ship narrow and working. Every component is standard:
X25519 for key agreement, AES-128-GCM as the AEAD, SHA-256 inside HKDF, Ed25519
for signatures.

**On the "128".** AES-128 is not a weak spot and is not a compromise made to save
effort. A 128-bit key space is beyond exhaustive search by any foreseeable
classical adversary — the energy cost, not the time cost, is the binding
constraint. Choosing AES-256 here would change nothing an attacker experiences.
It is recorded rather than quietly upgraded because someone will ask, and
"we used the bigger number to look serious" is a §2.4 violation dressed as
engineering.

**Upgrade path.** A hybrid post-quantum ciphersuite (X25519 + ML-KEM-768) is the
intended destination, tracked in D-004. The blocker is library support, not
appetite.

**Downgrade policy.** If a peer advertises a ciphersuite other than the one in
use, the session fails closed with a named error. There is no negotiation path
downward. A protocol that can be talked into weakening itself is one request away
from being weak.

---

## D-004 — Hybrid X25519 + ML-KEM-768 is the only permitted "combining"
**Date:** 2026-08-01 · **Status:** planned, blocked on library support

**Decision.** When `openmls` ships a stable hybrid PQ ciphersuite, migrate to
X25519 + ML-KEM-768. This is the **sole** place in the project where two
cryptographic primitives are deliberately combined.

**Why this combination is legitimate and cipher-stacking is not.** Hybrid key
exchange derives a shared secret from both a classical and a post-quantum KEM,
combined through a KDF, such that the result is secure if *either* component
holds. It is defence against a specific, named uncertainty: ML-KEM is young, and
X25519 is vulnerable to an adversary with a large quantum computer. Neither is
known to be broken; each covers the other's known unknown.

That is a different thing from encrypting a message with AES, then with
ChaCha20, then with Serpent. See D-005.

---

## D-005 — Rejected: cascading multiple ciphers
**Date:** 2026-08-01 · **Status:** rejected, permanently

**Rejected because security is not additive.** Encrypting four times gives
roughly the strength of the strongest layer, plus four times the code, four
times the implementation bug surface, four times the side-channel exposure, and
four independent opportunities for a nonce-handling mistake.

The reasoning error underneath the idea is treating cipher strength as the
bottleneck. It is not, and has not been for twenty-five years. AES-256 has never
been broken in a way that matters operationally. What gets broken is key
management, protocol design, random number generation, and implementations that
leak through timing. Cascading makes every one of those worse while improving the
one thing that was never the problem.

There is also a distinct failure mode worth naming: a cascade is only as
trustworthy as its *weakest orchestration*. Getting nonce derivation wrong once,
in the glue between two layers, can destroy the security of all of them.

---

## D-006 — AEAD used only through MLS, never directly
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** AES-128-GCM (or ChaCha20-Poly1305, per ciphersuite) is invoked by
`openmls` as part of the protocol. Application code never calls an AEAD directly
on message content, and never generates a nonce.

**Why.** Nonce reuse under the same key is catastrophic for GCM — it leaks the
authentication key, not merely one message. The way to never reuse a nonce is to
never be the code that picks one. MLS owns the key schedule and the nonce
derivation; this project stays out of it.

The one place a per-file key is generated directly is the attachment pipeline
(Phase 3, D-013), and that is flagged there as the single highest-risk piece of
code in the repository.

---

## D-007 — SQLCipher for local storage; Argon2id for passphrases
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** The local message database is SQLCipher (AES-256). The database key
comes from the OS keystore — Keychain on macOS, DPAPI on Windows, Secret Service
on Linux, Keystore on Android — or, when the user opts in, is derived from a
passphrase via Argon2id.

**Why SQLCipher.** Mature, widely deployed, page-level encryption with
authentication, and it integrates as a drop-in at the SQLite layer rather than
requiring the application to encrypt individual fields. Field-level encryption
was rejected: it leaves indexes, table structure, and row counts in the clear.

**Why Argon2id specifically.** Memory-hard, so a GPU or ASIC attacker gains far
less than they would against PBKDF2 or bcrypt. The `id` variant is the one to use
by default: it takes Argon2i's side-channel resistance in the first pass and
Argon2d's GPU resistance in the rest. Parameters will be pinned and recorded when
the passphrase path lands in Phase 2.

**Rejected: PBKDF2.** Still acceptable, but purely compute-hard. A modern GPU
farm evaluates it enormously faster than a laptop can, and there is no reason to
choose it for a greenfield project.

---

## D-008 — Default retention is "keep forever", surfaced at first run
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** Messages are kept until the user deletes them. The retention
control appears during first run rather than being buried in settings.

**Why not default to disappearing messages.** A messenger that silently destroys
history surprises people, and surprise in a security product costs trust in
exactly the wrong direction — the user learns the app does things it did not tell
them about. The honest arrangement is a predictable default plus a prominent,
easy control.

**The counter-argument, recorded because it is a real one.** Aggressive default
retention limits the damage from device seizure. The judgement here is that a
user who *chooses* 7-day retention understands their exposure, and a user who had
it chosen for them does not. Making the control impossible to miss is the
mitigation.

---

## D-009 — Compress before encrypt, in isolation, then pad
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** Pipeline order is compress → pad → encrypt. Each message payload is
compressed **in isolation** — never across messages, never mixing user content
with protocol fields.

**Why this ordering.** Compression after encryption accomplishes nothing;
ciphertext is incompressible by construction. So compression has to come first if
it is to happen at all.

**The risk this creates, stated plainly.** Compressing attacker-influenced
content together with secret content enables compression-ratio side channels of
the CRIME and BREACH family: the attacker varies their input and watches the
output size to learn about the secret.

**Why it is acceptable here.** That attack needs the attacker's data and the
secret in the same compression context. Compressing each payload in isolation
removes the shared context. Padding to fixed buckets after compression removes
the size signal that the attack reads. Test §8.7 asserts the isolation property
holds, and any future task that would compress two independently sourced pieces
of content into one unit is a stop-and-ask per §2.6.

---

## D-010 — Relay stores four fields and nothing else
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** Queued messages carry `message_id` (random 128-bit), `inbox_id`
(opaque random identifier), `blob` (ciphertext), and `expires_at`. Nothing else
is stored, and web server access logging is explicitly disabled rather than left
at its default.

**Why `message_id` is random rather than sequential.** An autoincrement column is
an ordering oracle. It reveals relative arrival order across all inboxes, and
lets an observer estimate total system traffic from any two IDs.

**Why "explicitly disabled" matters.** Almost every HTTP stack logs by default.
Not configuring logging is not the same as configuring no logging, and the
difference is a full request log containing IP addresses and timing. Phase 1
exit criteria include verifying this, and CI asserts it (§8.8).

**The design test.** A full database dump handed to an adversary should yield
nothing useful. This is verified automatically, not asserted by hand — see
`docs/../core/tests` and SPEC §8.3.

---

## D-011 — Native clients, not a web app
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** Desktop is Tauri + React; Android is Kotlin + Compose. There is no
browser-based client, and adding one would be a security regression rather than a
feature.

**Why.** A web app served over HTTPS lets the server ship fresh JavaScript on
every page load. That means the operator can silently push a backdoored build to
a single targeted user, and neither that user nor anyone else can detect it —
there is no artifact to inspect after the fact. Native clients are built once,
signed, and updated visibly.

This is the reason the threat model can list "malicious operator" as defended
against at all. With a web client, it could not.

**Rejected: Electron.** Would work, but ships a full Chromium per app and gives a
much larger native attack surface for no benefit here. Tauri uses the system
webview.

---

## D-012 — All security logic lives in one Rust crate
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** `core/` holds MLS state, key storage, encryption, the attachment
pipeline, SQLCipher access, and transport. Clients are thin UI over it. The UI
layer never touches a key, a cipher, or a raw ciphertext blob.

**Why.** Cryptographic logic should be written once and reviewed once. Two
implementations means two chances to get nonce handling wrong, and the second one
gets less scrutiny than the first.

**The rule this implies.** If a UI task appears to need lower-level access, that
is evidence the core is missing an operation. Add the operation to the core
rather than reaching around it. `unsafe_code = "forbid"` is set on the crate.

---

## D-013 — Tor via `arti` rather than a VPN
**Date:** 2026-08-01 · **Status:** planned for Phase 4

**Decision.** Phase 4 runs the relay as an onion service, with `arti` embedded in
the core.

**Why not a VPN.** A VPN relocates trust to a single company that sees every
connection, can log all of it, and can be compelled to hand it over. That is the
same trust problem as the relay, moved one hop sideways. Onion routing
distributes trust across independent relays chosen per circuit, and an onion
service means no exit node is involved at all — traffic never leaves the Tor
network.

**What it does not fix,** recorded so the UI copy stays honest: the user's ISP
still sees that Tor is in use, and the guard node still sees the user's IP.

---

## D-014 — Algorithms are published, not hidden
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** Every algorithm in use is displayed in the UI on request and
published in this repository. The only concealed values are secrets: private
keys, session keys, per-file keys, derived material, passphrases.

**Why.** Kerckhoffs's principle — a system must remain secure when everything
except the key is public. Hiding the algorithm is security through obscurity, and
it fails for a specific structural reason: *the user is not the adversary*. An
attacker reads the algorithm out of the decompiled binary or off the wire, not
out of a settings screen. So concealment costs the user's ability to evaluate the
product and gains nothing against anyone capable of attacking it.

AES has been fully public for twenty-five years and remains unbroken precisely
because publication invited attack and the attacks failed. An unreviewed
algorithm is not strong; it is untested.

**The secret is the key. The algorithm is a credential.**

---

## D-015 — Product name: Pouch
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** The product is called Pouch. The working name in the specification
was Courier, marked explicitly as a placeholder.

**Why.** It sits in the sealed-correspondence design world of §6.1 — a
diplomatic pouch is precisely the idiom the interface is built on: careful
custody, honest handling, a visible record of who touched what. It is short
enough to sit in a Custody Strip header. It contains none of the terms banned by
§2.4.

**Why not Courier.** It collides with an established mail transfer agent and with
one of the best-known monospace typefaces, both of which are in this project's
own subject area.

**Why not Manifest.** It names the signature element rather than the product, and
overloads a word that already means something specific in software packaging.

---

## D-016 — Exact version pinning, no caret ranges
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** Every dependency in `Cargo.toml` is pinned with `=`. Changing a
version requires an entry in this file.

**Why.** `openmls` changes its API across minor versions, and a caret range means
a fresh `cargo update` on a different machine can silently produce a different
key-handling code path. More generally: in a security-relevant dependency tree,
the ability to reproduce exactly what was built and reviewed is worth more than
automatic patch updates.

**The cost, acknowledged.** Security patches are not picked up automatically.
`cargo audit` runs in CI and fails the build on a known vulnerability, which
converts that cost into a visible task rather than a silent risk.

---

## D-017 — Self-signed relay certificate with SPKI pinning for Phases 1–3
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** For local and self-hosted deployment, the relay generates a
self-signed TLS certificate at first run. Clients pin it by SPKI hash, supplied
in client configuration. Certificate-authority validation is not used and no
public CA is involved.

**Why.** The deployment target for Phases 1–3 is a machine the user controls
(decision taken by the project owner, 2026-08-01). A public CA adds a trusted
third party who can issue a certificate for the relay's name — precisely the
attacker the pinning is meant to exclude. Pinning a known key is stronger than
validating a chain, when the operator and the user are the same person.

**What this costs.** Key rotation requires redistributing the pin. That is
acceptable at this scale and becomes irrelevant in Phase 4, where an onion
service address *is* a public key and pinning is intrinsic.

**Note.** TLS here is defence in depth *beneath* end-to-end encryption. If TLS
fails entirely, the relay still only sees ciphertext it cannot read.

---

## D-018 — A headless CLI client ships alongside the desktop client
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** `clients/cli` is a thin headless client over the same core,
built and tested in CI.

**Why.** Phase 1's exit criterion is two clients exchanging text reliably. A GUI
cannot be driven in a headless CI environment, which would leave the single most
important integration path unverified by automation. A CLI client makes the full
send-and-receive path testable end to end, and makes the system demonstrable over
SSH.

It uses the same `core` API surface as the desktop client, per D-012 — it is not
a privileged back door into the internals. If the CLI needs an operation the
desktop client does not have, that is a signal about the API, not a licence to
bypass it.
