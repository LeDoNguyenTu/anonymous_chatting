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

---

## D-019 — The relay database is deliberately *not* encrypted
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** The relay stores its queue in plain SQLite. No SQLCipher, no
at-rest encryption of any kind.

**Why.** There is nothing in it to protect. The blobs are ciphertext the relay
holds no key for, the inbox identifiers are random, and the expiry column is
bucketed. Encrypting that would protect nothing that is not already protected.

**The reason it would be actively harmful.** An encrypted relay database invites
the belief that the relay's confidentiality matters — that the system's security
rests partly on the operator keeping a key safe. It does not, and must not. The
whole architecture is arranged so that the operator can be hostile. Adding a lock
to a box that is empty by design is security theatre, which SPEC §2.2 forbids,
and it would make the honest sentence in the README ("there is nothing meaningful
to hand over") harder to say.

The client database is a different matter entirely and *is* SQLCipher (D-007).
That one holds plaintext.

---

## D-020 — `expires_at` is bucketed to the hour
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** The relay's expiry column is computed by flooring the arrival
instant to an hour boundary, then adding the TTL plus one bucket. Every blob
arriving within the same hour carries a byte-identical expiry.

**Why this is not a micro-optimisation.** A second-precision expiry column is an
exact arrival clock wearing a different hat: subtract the known TTL and you have
the moment each message was sent, for every blob in the queue. SPEC §2.3 forbids
storing plaintext timestamps beyond the queue TTL, and the product's "what the
relay could see" screen lists *exact send time* under NOT VISIBLE. Either that
claim is true in the storage layer or the screen is lying, and a manifest that
lies is worse than no manifest (§8.6).

**The ordering matters and is easy to get wrong.** Adding the TTL first and
bucketing the sum does not work — the result still varies with the arrival
instant, so the column stays a clock. The arrival has to be bucketed first. The
first implementation here made exactly that mistake and the test caught it.

Flooring rather than ceiling, because ceiling splits the hour at its boundary
(14:00:00 and 14:00:01 land in different buckets), which groups nothing. Flooring
gives away up to an hour of TTL, so one bucket is added back; a blob therefore
lives at least its full TTL and at most one hour longer.

**Cost.** Up to one hour of over-retention. Accepted: the alternative is an
arrival clock, and the shortest retention setting the product offers is 24 hours.

---

## D-021 — Collection and deletion are separate requests
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** `GET /inbox/{id}` returns waiting blobs without erasing them. The
client erases them with an explicit `POST /inbox/{id}/ack` after it has stored
them locally.

**Why not delete on read.** A client whose connection drops mid-response would
lose the message permanently, and a message the relay silently destroyed is
indistinguishable — from the user's side — from one that was never sent. SPEC
§6.9 requires errors to explain what happened; silent loss cannot.

**What it costs.** A blob lives slightly longer than strictly necessary, and a
client that never acknowledges leaves blobs until TTL. Bounded by the TTL either
way, and the relay cannot read them regardless.

**Acknowledgement is scoped to the inbox**, so possession of a message
identifier is not on its own sufficient to delete another inbox's mail.

---

## D-022 — `openmls` panics on tampered ciphertext in debug builds
**Date:** 2026-08-01 · **Status:** accepted with a recorded caveat · **Library finding**

**What was found.** `openmls 0.8.1` carries a `debug_assert!(false, "Ciphertext
decryption failed")` in `framing/private_message_in.rs` on the AEAD failure
path. A blob whose ciphertext has been altered therefore:

- **panics** in a debug build, and
- returns `MessageDecryptionError::AeadError` in a release build, which Pouch
  surfaces as `CryptoError::Decryption`.

**Why this is not a security defect in the shipped product.** Release is what
ships. In a release build the assertion is compiled out, tampering is detected,
and the error reaches the user as a named failure rather than a silent drop —
which is the property the threat model depends on. This is verified by running
the tampering test under `--release` as well as under the default profile.

**Why it is still worth recording.** The failure path is reachable by anyone who
can modify a blob in transit — which, by the threat model, includes the relay
operator. A developer running a debug build gets a crash on adversarial input.
That is a denial of service against developers rather than users, but it is
exactly the kind of thing that gets rediscovered six months later and
misdiagnosed as a bug in this project's code.

**How it is handled.** The test asserts the outcome in both profiles: the
tampered blob must never be accepted as a message, and a *release* build must
return an error rather than panic. It does not paper over the debug panic by
skipping the test in debug builds, because a skipped test is how this stops
being visible.

**Not worked around in library code.** Wrapping `openmls` calls in
`catch_unwind` was considered and rejected: `panic = "abort"` is set on the
release profile, so it would do nothing where it would matter, and it would add
a confusing layer around the one part of the system that must stay easy to
reason about. If the debug panic becomes a practical obstacle, the fix belongs
upstream.

---

## D-023 — MLS state is persisted as a serialized snapshot, not through a storage provider
**Date:** 2026-08-01 · **Status:** accepted for Phase 1, to be revisited

**Decision.** `PouchProvider` pairs `openmls`'s audited `RustCrypto` with
`MemoryStorage`, and persists the whole MLS state by serializing the storage map
into the SQLCipher database as one encrypted blob.

**Why not `OpenMlsRustCrypto` directly.** Its storage field is private and it
offers no way to be rebuilt from a snapshot, so a client built on it would lose
every conversation on exit. `PouchProvider` is the same two components with the
storage reachable — it implements no primitive and no storage logic of its own.

**Why a snapshot rather than a real storage provider.** Implementing
`StorageProvider` against SQLCipher directly is the better long-term answer and
is the intended Phase 2 work. For Phase 1 it is a large amount of key-handling
code standing between the project and a working messenger, and Prime Directive 4
says ship narrow and working.

**What it costs, stated plainly.** The whole state is rewritten on every save,
which is O(total state) per message rather than O(change). At one-to-one scale
this is milliseconds. It would not be acceptable for groups, which is why this
entry says "to be revisited" rather than "settled".

**What it does not cost.** Nothing about the security of the state at rest: the
snapshot goes into the same SQLCipher database, under the same key, as
everything else. A test asserts message plaintext does not survive inside the
snapshot.

---

## D-024 — One SQLCipher build for the workspace, and a runtime check that it is real
**Date:** 2026-08-01 · **Status:** accepted · **Bug found during development**

**What went wrong.** The relay was given `rusqlite` with the `bundled` feature
(plain SQLite, since the relay database holds nothing worth protecting, D-019)
and the core was given the same crate under an alias with
`bundled-sqlcipher`. Cargo unifies features across a workspace for a single
package version, so the two collapsed into one library built with the union of
the features — and the plain SQLite build won.

**Why this was dangerous rather than merely broken.** SQLite silently ignores
pragmas it does not recognise. On the resulting build, `PRAGMA key` returned
success, reported no error anywhere, and encrypted nothing. Every local database
written was plaintext on disk — message bodies and the identity private key —
while the application, its logs, and its error handling all reported an
encrypted store.

Nothing in the code was wrong. The dependency graph was wrong, and the symptom
was invisible from inside the program.

**Two changes.**

1. **One `rusqlite` for the workspace**, built with `bundled-sqlcipher`. The
   relay links the same library and simply never sets a key, which is exactly
   the behaviour D-019 asks for — its database is unencrypted because there is
   nothing in it to protect, not because it failed to be encrypted.

2. **A runtime check, before the key is set.** `LocalStore::open` queries
   `PRAGMA cipher_version`, which only SQLCipher answers, and returns
   `StorageError::SqlCipherMissing` if it is absent. A hard failure, not a
   warning: an application that cannot encrypt its database must refuse to
   write to it rather than carry on and produce a plaintext file the user
   believes is protected.

**The general lesson, recorded because it will recur.** A security control that
fails *silently* is worse than one that is absent, because the absent one is
visible. Anywhere this project depends on a library actually doing something,
there should be a positive check that it did — not an assumption that an error
would have been raised. The test asserting that message plaintext is not present
in the database file is what caught this; a test asserting only that
`open()` returned `Ok` would have passed.

---

## D-025 — The identity private key lives in exactly one place
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** The identity row in the local database holds the display name, the
inbox address, and the **public** key. The private half is written into the MLS
storage provider by `Identity::create` and travels inside the `mls_state`
snapshot, and is read back with `SignatureKeyPair::read`.

**Why not a `signer_secret` column.** The first implementation had one, which
meant the private key existed twice in the same file — once in its own column
and once inside the snapshot. Two copies means two things to zeroize, two things
to wipe, and a way for them to disagree. It also required
`SignatureKeyPair::private()`, which `openmls_basic_credential` gates behind its
`test-utils` feature; enabling a test feature in a shipped build to extract a
private key is the wrong direction of travel.

**What this buys.** One copy, one lifetime, and the extraction path is the
library's own public accessor rather than a reconstruction from bytes stored
alongside.

---

## D-026 — The sender introduces themselves inside the encrypted channel
**Date:** 2026-08-01 · **Status:** accepted

**Decision.** After creating a conversation, the initiator sends a `Hello`
payload — their inbox address and display name — as an ordinary encrypted
application message. The recipient learns where to reply from that, not from
anything attached to the Welcome.

**The problem it solves.** An MLS Welcome carries no inbox address, so a client
that joins from one has no way to reply.

**The obvious solution, and why it was rejected.** Wrapping the Welcome in a
small envelope carrying the sender's inbox would work and is one line of code.
It would also hand the relay the exact correlation the whole architecture denies
it: *this inbox is talking to that inbox*. The relay stores no sender field
precisely so it cannot answer that question, and putting the answer in the blob
would make the omission decorative.

**Consequence for message ordering.** Blobs come back from the relay in
random-identifier order — deliberately, since any other order leaks arrival
sequence — so a message can arrive before the Welcome that opens its
conversation. `receive_messages` therefore processes Welcomes in a pass of their
own before attempting to decrypt anything.

**A `Hello` does not make a contact verified.** It arrives over an authenticated
channel, so the relay cannot have forged it, but authenticity of the channel is
not identity of the person. The contact is stored unverified and the Custody
Strip shows amber until the user compares a safety number out of band.

---

## D-027 — Conversations are rebuilt from MLS state on open
**Date:** 2026-08-01 · **Status:** accepted · **Bug found during development**

**What went wrong.** An `MlsGroup` is a state machine held in memory, and the
first working build only ever put one there when a conversation was created or
joined. The MLS state persisted correctly into SQLCipher, but the in-memory map
was empty on every restart, so the first end-to-end run failed with "no
conversation with that contact exists yet" immediately after successfully
creating one.

**The fix.** `Pouch::open` walks the stored conversations and reconstitutes each
group with `MlsGroup::load` from the restored provider.

**Why it is worth an entry.** The failure looked like data loss and was not — the
keys and the ratchet state were all present and correct on disk. Persisting
state and *rehydrating* it are separate pieces of work, and having done the
first one well is what makes it easy to forget the second. The end-to-end run
caught it; no unit test would have, because every unit test held its
conversation in memory for the length of the test.
