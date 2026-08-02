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

The attachment pipeline (Phase 3, SPEC §7.1) will need a per-file key generated
outside MLS, since a file is not a group message. **This entry previously cited
"D-013" as the decision authorizing that; D-013 is the Tor-vs-VPN decision and
says nothing about attachments.** No entry currently designs or authorizes
AEAD-outside-MLS usage for either the attachment pipeline or backup export
(SPEC §7.3, which has the identical shape — a file, not a group message). Both
are stop-and-ask under SPEC §2.6 when Phase 3 starts them, precisely because
this decision's own rule is "application code never calls an AEAD directly,"
and a file-encryption feature is exactly a case where it must.

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

---

## D-028 — The MLS out-of-order window follows from the relay's random ordering
**Date:** 2026-08-01 · **Status:** accepted · **Found by the end-to-end test**

**What happened.** A run of twelve messages sent in sequence arrived as five.
Not lost in transit — the relay had all twelve — but silently dropped by the
receiving client.

**Why.** The relay returns queued blobs ordered by their *random* identifier,
deliberately, because returning them in arrival order would hand anyone reading
a response the sequence in which they were sent (D-010). So a client always
receives a batch shuffled. MLS's sender ratchet tolerates a bounded amount of
out-of-order delivery and discards anything beyond it; the library default is 5.
A shuffled batch of twelve routinely exceeds that.

Two decisions that were individually correct combined into a defect. Neither the
relay's ordering nor the library's default was wrong on its own.

**Decision.** `out_of_order_tolerance` is set to 64, applied identically to
groups this client creates and groups it joins — if the two sides disagree, one
direction of a conversation drops messages the other keeps.
`maximum_forward_distance` stays at the library default of 2000, which bounds
the work an attacker can force by claiming a far-future generation.

**The trade, stated plainly.** A larger window means the receiver retains more
unused message keys, and a key that still exists is a key that can be
compromised. This weakens forward secrecy *within a single epoch* in exchange
for not losing messages. MLS discards the whole retained set at the next key
rotation, so the exposure is bounded in time as well as in count.

**The alternative that was rejected.** Having the relay return blobs in arrival
order would remove the need for any window at all. It would also make the
response an arrival clock, which is precisely what D-010 and D-020 exist to
prevent. Losing forward secrecy for at most 64 message keys inside one epoch is
a smaller cost than handing every observer the send order of every conversation.

**Why it was only found by an end-to-end test.** Every unit test sent messages
in order, because in a unit test there is no relay to shuffle them. The failure
needed the real server's real ordering to appear.

---

## D-029 — A crate outside the workspace needs its own committed lock file
**Date:** 2026-08-01 · **Status:** accepted · **Bug found by CI**

**What broke.** The Tauri shell stopped compiling in CI with four type errors
*inside `tauri-build`* — a dependency, not our code. `tauri-build` was pinned at
`=2.0.4` exactly as D-016 requires, but its transitive `tauri-utils` was not
pinned by anything, so CI resolved a newer `tauri-utils` whose
`external_binaries` signature had gained an argument.

**The lesson, which generalises.** An exact pin on a *direct* dependency
constrains that dependency and nothing beneath it. Only a lock file constrains
the graph. The workspace has always had `Cargo.lock` committed, so this never
came up there — but `clients/desktop/src-tauri` is deliberately excluded from
the workspace (it needs WebKitGTK, which most CI jobs do not install), and an
excluded crate resolves independently. It had no lock file, and `.gitignore`
would not have stopped one existing — nobody had generated one.

**Fix.** `clients/desktop/src-tauri/Cargo.lock` is generated and committed, its
`.gitignore` says explicitly why it is not ignored, and the CI job runs
`cargo check --locked` so a lock file that has drifted fails the build rather
than being silently regenerated.

`tauri` and `tauri-build` were also moved to current releases (2.11.5 and 2.6.3)
so the pinned versions are ones that actually work together.

**Where else this applies.** Any future crate placed outside the workspace —
the Android JNI library in Phase 5 is the obvious candidate — needs the same
treatment on the day it is created.

---

## D-030 — Accepting four hpke-rs advisories, and what would change that
**Date:** 2026-08-01 · **Status:** accepted with review triggers

**What CI found.** `cargo audit` failed the build with 19 advisories. That is
the guardrail working, not the guardrail misfiring, and the fix is not to
silence it. Each was assessed for reachability and impact; the exception list
with per-advisory reasoning is `.cargo/audit.toml`.

**Fixed by upgrading:** `anyhow` 1.0.95 → 1.0.104 (RUSTSEC-2026-0190,
unsoundness in `Error::downcast_mut`), `tokio` 1.42.0 → 1.53.1
(RUSTSEC-2025-0023).

**Not reachable at all:** eleven advisories against `libcrux-*` crates that
appear in `Cargo.lock` but are never compiled. `cargo-audit` reads the lock
file, which records resolutions for optional dependencies no enabled feature
selects. Verified three ways: `cargo tree -i` finds no edge across every target
and every edge kind, and no build artifact for them exists after a full build.
They enter through `hpke-rs`'s libcrux backend, which `openmls_rust_crypto`
does not enable.

**Genuinely reachable, and accepted for now — the four that matter:**

`openmls_rust_crypto 0.5.0` requires `hpke-rs ^0.5.1`. Every one of these is
fixed in `hpke-rs 0.6.0`, which is semver-incompatible, and there is no newer
`openmls_rust_crypto` to pull it in. The project is pinned by its upstream.

| Advisory | What it is | Why it is accepted |
|---|---|---|
| RUSTSEC-2026-0071 | Nonce reuse after 2³² operations on one reusable HPKE context | MLS uses HPKE single-shot, for key packages and Welcome. Not a context driven four billion times. |
| RUSTSEC-2026-0070 | Panic when `HpkeExport` is the AEAD | The ciphersuite sets AES-128-GCM. `HpkeExport` is never selected. |
| RUSTSEC-2026-0069 | Wrong length encoding above 65535-byte exports | MLS exporter outputs are tens of bytes. |
| **RUSTSEC-2026-0072** | **Missing check that the X25519 shared secret is non-zero, in the RustCrypto backend this project uses** | **See below. This one has real substance.** |

**On RUSTSEC-2026-0072, honestly.** RFC 9180 requires HPKE implementations to
reject an all-zero Diffie-Hellman shared secret, and the backend in use does
not perform that check. This is a genuine deviation from the specification the
protocol is built on, in code this project actually executes. It is accepted
because the alternatives are worse: vendoring or patching an audited crypto
library to work around it would put this project in the business of maintaining
cryptographic code, which Prime Directive 1 exists to prevent, and abandoning
`openmls` over it would discard the entire protocol layer.

It is recorded in `docs/THREAT_MODEL.md` rather than only here, because it is
the kind of thing a reader evaluating this project deserves to find without
reading a decision log.

**Rejected: raising the audit to warnings-only.** That would satisfy CI by
making the check meaningless. An advisory that cannot be fixed should be listed
with a reason, not made invisible.

**Review triggers — the entries above are re-examined when any of these occur:**

- `openmls` or `openmls_rust_crypto` publishes a release. This is the one that
  clears most of the list, and it should be checked on every upgrade.
- The crypto backend changes. Everything marked "not reachable" is reachable
  again the moment the libcrux backend is enabled.
- Phase 5 lands the Android client. RUSTSEC-2026-0212 concerns constant-time
  operations on aarch64 and is currently ignored as unreachable; aarch64 is
  what Android runs on.
- Real TLS lands. RUSTSEC-2025-0134 (`rustls-pemfile` unmaintained) is ignored
  because nothing parses PEM today.

---

## D-031 — The offline queue stores ciphertext, not plaintext
**Date:** 2026-08-02 · **Status:** accepted

**Decision.** A message that fails to reach the relay is encrypted once, at
send time, and the finished MLS ciphertext is what sits in the queue. A retry
re-POSTs that blob. It never re-encrypts.

**Why this needed a decision rather than being obvious.** The queue could
instead have stored the plaintext body and encrypted at flush time, which
looks simpler and avoids a new BLOB column. It is wrong for a reason specific
to MLS: encrypting advances the ratchet. Re-encrypting on every failed
attempt would burn a generation per attempt rather than per message, and
would hand the recipient gaps in the generation sequence that its
out-of-order tolerance has to absorb. That tolerance is small — five, by
default — and D-028 already recorded what happens when it is exceeded: half
of a twelve-message run was silently lost. Storing plaintext and
re-encrypting at flush time would reintroduce that fault through a new door.

**Rejected: pin the ratchet until delivery confirms.** Would avoid the
generation-burn problem, but blocks every *other* conversation's use of the
same client state on one unreachable peer, and openmls has no supported API
for suspending a single group's epoch progression independent of the rest.

**Consequence accepted.** The queue holds ciphertext, which is useless
without the MLS state that produced it — consistent with everything else this
project stores, but worth stating because it means a queued message cannot be
inspected or edited before it sends. There was never a requirement that it
should be.

---

## D-032 — Retention deletes are `secure_delete`, not merely `DELETE`
**Date:** 2026-08-02 · **Status:** accepted

**Decision.** `PRAGMA secure_delete = ON` is set on every database open, in
addition to the `VACUUM` that `wipe()` already ran.

**Why `VACUUM` on wipe was not enough once retention shipped.** `wipe()` is
rare and already paid `VACUUM`'s cost. Retention purges are frequent — every
open, every receive, every settings change — and SQLite's ordinary `DELETE`
unlinks a row without overwriting its bytes; they sit in a free page until
something else happens to reuse it. A user who sets 24-hour retention
specifically to limit what a later compromise can reach would have every
"deleted" message still recoverable from the file until an unrelated write
happened to land on that page. `secure_delete` overwrites on every delete, at
the cost of one extra page write each time — a cost worth paying continuously
rather than only at `VACUUM` time, which for retention would be never.

**Rejected: `VACUUM` after every purge.** Correct, but `VACUUM` rewrites the
entire database file. Doing that after every retention sweep turns a
background purge into an operation whose cost scales with total history size,
on every receive.

---

## D-033 — `INSERT OR REPLACE` was silently deleting conversations
**Date:** 2026-08-02 · **Status:** fixed, not merely mitigated

**What was found.** `put_contact` and `put_conversation` used `INSERT OR
REPLACE`, present since Phase 1. SQLite implements `REPLACE` as delete-then-
insert, and this schema enforces foreign keys with `ON DELETE CASCADE`.
Re-adding a contact already known — which happens on every Hello received
after the first, since the Hello path always calls `put_contact` — deleted
the contact row, which cascaded into `conversations`, which cascaded into
`messages`. The entire thread with that contact was erased, silently, as a
side effect of receiving a message from them.

**Why Phase 1's tests did not catch it.** No test re-added a contact that
already existed with a live conversation attached; every existing fixture
created each contact exactly once. Found while writing a Phase 2 test helper
that (correctly, per the schema) called `put_contact` twice for the same
person across two conversations.

**Fix.** Both became upserts (`ON CONFLICT DO UPDATE`) that touch only the
mutable fields — display name and inbox address — and leave `verified` and
`public_key` untouched on conflict. That second part is deliberate and not
incidental to the fix: a rewrite that touched the key would be a route for an
identity-key change to bypass the warning modal entirely (D-034), and a
rewrite that touched `verified` would silently drop a mark the user
established out of band, which Prime Directive 3 forbids regardless of cause.

**Verified by making it fail.** A test reproduces the exact sequence —
contact, conversation, message, re-add the same contact — against the
pre-fix code first, confirmed it destroyed the thread, then confirmed the
upsert preserves it. The same test also asserts the rename still applies,
so the fix is not simply "never update."

**Where else this applies.** Any future table with a foreign key and an
`INSERT OR REPLACE` on its parent has the same failure shape. None remain in
the schema as of this entry.

---

## D-034 — Identity change detection compares the authenticated sender key
**Date:** 2026-08-02 · **Status:** accepted

**Decision.** On every received message, the sender's MLS credential key —
authenticated by the protocol, not asserted by the relay — is compared
against the key the conversation was established with. A mismatch calls
`replace_identity_key`, which records the old key and the date, and
unconditionally clears `verified`.

**Why clearing verification is not optional.** The user compared a safety
number derived from the *old* key. That comparison is evidence about nothing
regarding a new key. Leaving `verified` set after a key change would be the
interface asserting a check that was never performed against the key
actually in use — the exact shape Prime Directive 3 exists to forbid, applied
to a case Phase 1 had no mechanism to even detect.

**Acknowledging is not verifying, deliberately kept as two separate booleans
rather than one.** SPEC §6.7.6 requires "continue without verifying" to be a
real, unhidden option, because burying it is how a user ends up clicking the
reassuring button instead — which would be worse, since that one claims a
check that did not happen. Collapsing "the user answered the modal" and "the
user verified a safety number" into a single flag would make that impossible
to represent: there would be no way to silence the modal without also lying
about verification.

**Rejected: deriving a new contact record for the new key.** Simpler to
implement — no need to touch existing rows — but turns a key change into what
looks like a second person, losing the conversation history's connection to
the original contact and giving the user nothing to compare against or be
warned about.

---

## D-035 — Passphrase protection re-encrypts in place; the OS keystore route is deferred
**Date:** 2026-08-02 · **Status:** partially implemented — see below

**Decision.** SPEC §7.2 names two acceptable sources for the database key:
the OS keystore, or Argon2id over a user passphrase. This phase implements
the second. Turning it on derives a key with the parameters already pinned in
`keying.rs`, calls SQLCipher's `PRAGMA rekey` so every page is rewritten under
the new key in one operation, and deletes the placeholder device-key file.
Which route a given database uses is recorded in a plaintext sidecar file
beside it (a version byte plus, for the passphrase route, the salt — never
key material), because that answer has to be readable *before* the encrypted
database can be opened at all.

**Why a missing passphrase is a hard error, never a silent fallback.** The
device-file placeholder remains the answer when no sidecar exists, which is
necessary for every Phase 1 database to keep opening. But once a sidecar
names the passphrase route, a caller supplying no passphrase gets
`KeyingError::PassphraseRequired`, not the placeholder key. Falling back
would silently reopen a database the user was told is passphrase-protected
under a key that protects against nothing — turning "protected" into "not"
without saying so anywhere.

**Why the sidecar is written before the rekey, with rollback on failure.**
`PRAGMA rekey` either completes or the database stays under the old key;
SQLCipher does not leave it half-migrated. Writing the sidecar first and
rolling it back on a rekey failure means an error leaves the database exactly
as openable as it was before the call. The one gap this cannot close is a
process crash between the sidecar write and the rekey completing — in that
window the sidecar would claim a passphrase the data does not yet honor. This
fails as a wrong-key error on the next open, not as silent data exposure,
which is the failure direction to prefer when only one is available.

**The OS keystore route is not implemented, and that is a stop-and-ask
(SPEC §2.6), not an oversight.** It requires a real platform dependency —
Windows Credential Manager or DPAPI, Keychain, Secret Service — chosen and
wired per platform, which is exactly the kind of decision this project does
not make while passing through unrelated work. Recorded here so it is not
mistaken for done.

---

## D-036 — Compression activated for every payload, unconditionally
**Date:** 2026-08-02 · **Status:** accepted

**Decision.** Manifest stage 3 (`COMPRESSED`) is live. Every payload —
`Payload::Text` and the `Hello` introduction alike — is compressed with
`zstd` immediately after JSON encoding and before the single MLS `encrypt`
call, via one-shot, dictionary-free, stateless calls
(`api::compression::compress`/`decompress`). No size threshold: everything
is compressed, always.

**Why no threshold, when the architecture sketch had one.** `docs/ARCHITECTURE.md`
originally read "text messages below the threshold: not applicable," with no
number ever assigned anywhere. A threshold means *some* payloads are
compressed and some are not, which means a receiver has to know which case a
given blob is before it can decode it — that requires an explicit marker in
the wire format. Designing that marker is protocol work, not a size
optimization, and it opens exactly the kind of ambiguous-format question
SPEC §2.1 treats as a downgrade path to avoid. Compressing unconditionally
needs no marker, so there is nothing to get wrong. The cost — a two-word
message can end up a handful of bytes larger than it started, since zstd's
frame header is not free — is negligible next to MLS's own fixed 128-byte
padding on every application message regardless.

**Isolation, and why it holds by construction rather than by discipline.**
SPEC §6.5.2 requires each payload be compressed in isolation — never across
messages, never mixing user content with protocol fields — because
compressing attacker-influenced content together with secret content in a
shared context is the CRIME/BREACH mechanism: vary the attacker's part,
read the secret's length off the output size. `compress`/`decompress` here
are one-shot library calls with no dictionary and no encoder object that
outlives a single call, so there is no shared context for a future change to
accidentally introduce *unless* it starts holding a compressor across calls
— which is precisely what `compression_is_isolated_across_calls` asserts
does not happen, by compressing a fixed "secret" payload before and after
compressing two different "attacker" payloads and asserting its compressed
size never moves.

**Why compression breaks wire compatibility with anything sent before this
commit, and why that is accepted.** `receive_messages` now treats a
decompression failure exactly like a malformed payload — silently skipped,
never rendered as a message (matching the project's already-established rule
that unparseable bytes are protocol noise, not content). A client built
before this change sends raw, uncompressed JSON; a client built after this
change will not be able to decompress it and will silently drop it. This
project has no version negotiation and no live population running mismatched
builds against each other, so a clean break is the honest choice over adding
complexity — a version byte, content-sniffing, or a fallback decompression
attempt — to paper over compatibility this project does not actually need to
maintain. If that changes, it is worth a decision of its own rather than an
assumption baked in here.

**What this does not touch.** The attachment pipeline (SPEC §7.1) has no
compression step in its own spec — strip, pad, encrypt — so this decision
does not extend there. Padding (stage 4) and sealed sender (stage 6) remain
not yet implemented; see D-006's note on why neither has an authorizing
decision. Backup export (SPEC §7.3) is unaffected and still deferred for the
same reason.

---

## D-037 — A narrow, explicit exception to D-006 for file encryption
**Date:** 2026-08-02 · **Status:** accepted — project owner approved 2026-08-02

**The problem D-006 leaves unanswered.** A file — a backup, an attachment —
is not an MLS group message, so it cannot go through `Conversation::encrypt`.
D-006's rule is "application code never calls an AEAD directly and never
generates a nonce." Backup export (SPEC §7.3) and the attachment pipeline
(SPEC §7.1) both require encrypting a file. Something has to give, and it
should not be decided implicitly by whichever feature gets built first.

**What was checked before proposing anything.** Whether reusing the crypto
backend already in the dependency graph — rather than adding a new AEAD
crate — was even possible. It is:
`openmls_traits::crypto::OpenMlsCrypto::aead_encrypt`/`aead_decrypt` are
public methods on the same provider `PouchProvider` already wraps, backed in
`openmls_rust_crypto 0.5.0` by the audited `aes-gcm` crate directly
(`provider.rs`, `AeadType::Aes128Gcm` arm — unconditionally implemented, not
gated behind the negotiated MLS ciphersuite). The same provider also exposes
`hkdf_extract`/`hkdf_expand`. So this decision adds **no new dependency**:
every primitive it uses is already pinned, already audited, already in this
binary.

**Decision, approved by the project owner rather than assumed.** File
encryption uses `PouchProvider`'s own `aead_encrypt`/`aead_decrypt` with
`AeadType::Aes128Gcm` — the same AEAD the MLS ciphersuite already names, for
the same reason D-003 gives for not treating AES-128 as something to
"upgrade" past. The key is:

1. Freshly random, generated with `OsRng`, exactly the width AES-128-GCM
   needs (16 bytes).
2. Used for **exactly one** encryption operation, then held only as long as
   the operation needs it and zeroized after.
3. Never derived from, or stored alongside, anything else — a backup's key
   comes from the recovery key via HKDF; an attachment's key is random and
   travels inside the E2EE payload, per SPEC §7.1 step 6.

**Why a random nonce is safe here despite D-006's stated reason not to pick
one.** GCM's catastrophic failure mode is reusing a (key, nonce) pair. D-006
was written for MLS application messages, where the same key persists across
many messages and picking nonces by hand invites exactly that reuse. Here the
key exists for one encryption and is discarded — there is no second message
under this key for a nonce to collide with, so even a *fixed* nonce would be
safe. A random 96-bit nonce via `OsRng` is used anyway, as ordinary hygiene
and because it costs nothing.

**What this does not open up.** This is not a general license to call an
AEAD anywhere convenient. It is scoped to the fresh-key-single-use shape
above. A future feature that would encrypt more than one thing under the
same directly-generated key is a new decision, not covered by this one.

**Consequence.** Backup export/import (SPEC §7.3, deferred from Phase 2) and
the attachment pipeline (SPEC §7.1, Phase 3) are both unblocked. Implemented
this session: backup export/import. The attachment pipeline's remaining
work — EXIF/metadata stripping specifically — needs a decision of its own
about which library handles it and whether it covers video containers (SPEC
§7.1's own flag), so it is not automatically unblocked by this entry alone.
See D-038 for that decision.

---

## D-038 — Metadata stripping via `img-parts`; video attachments deferred, not silently unsupported
**Date:** 2026-08-02 · **Status:** accepted — project owner approved 2026-08-02

**The problem.** SPEC §7.1 step 2 requires stripping EXIF, GPS, device make
and model, capture timestamps, and editing history from every attachment,
client-side, before encryption, "using a maintained library" and explicitly
forbidding hand-parsed EXIF. §7.1 also names video separately: "requires
stripping container-level metadata as well as frame metadata. Flag if the
chosen library does not handle the container" — SPEC itself anticipates that
one library might not cover both.

**What was checked.** The Rust ecosystem for image metadata handling
(`cargo info` against crates.io, 2026-08-02):

- `img-parts` (0.4.0, MIT/Apache-2.0, `no_std`-capable, maintained by
  paolobarbolini) edits JPEG, PNG, and RIFF (WebP) containers directly —
  removing EXIF/ICC/XMP segments without decoding or re-encoding pixel
  data. Three small dependencies (`bytes`, `crc32fast`, `miniz_oxide`), no
  `unsafe`. This is squarely "a maintained library," not hand-parsed EXIF,
  and it covers the three formats a messaging app's photo attachments are
  overwhelmingly going to be.
- Video has no comparable option. Metadata lives in different places per
  container — MP4 `udta` atoms, QuickTime `©xyz` GPS atoms, embedded
  thumbnail images carrying their own EXIF, timed-metadata tracks — and the
  realistic choices are: a pure-Rust MP4 box parser (`mp4`, 0.14.0) that
  does not claim to enumerate or strip the full space of metadata locations
  and has not been used for this purpose here, or a crate wrapping FFmpeg's
  C libraries, which means feeding attacker-controlled video through a
  large, historically CVE-heavy native codec — a materially bigger attack
  surface than anything else in this project's dependency graph, for a
  library whose job would be reading untrusted, adversarial input by
  definition.

**Decision, put to the project owner rather than assumed** (SPEC §2.6: a new
dependency with a real security trade-off, and a decision that narrows
product scope, both warrant asking rather than defaulting). Approved:

1. `img-parts` strips metadata for JPEG, PNG, and WebP. Pinned exactly in
   `core/Cargo.toml`, workspace-level.
2. Video attachments are **not** supported in Phase 3. The attachment
   picker refuses video files with an honest message rather than accepting
   them and forwarding a file whose metadata may not be fully stripped.
   This is SPEC §7.1's own "flag if the chosen library does not handle the
   container" clause, exercised rather than quietly skipped — the
   difference between an absent feature and a feature that lies about what
   it did is Prime Directive 3.
3. Video support is a tracked, open item for a later phase, not a silent
   gap — recorded in `docs/PROGRESS.md`.

**Why this does not block Phase 3's exit criterion.** SPEC's own Phase 3
exit line (§9) is "an image sent through the system and inspected
server-side reveals no EXIF, no filename, no sender" — video is not named
there. §8.4's test matrix entry does say "repeat for video," which stays
open and unmet until video is supported; the phase gate itself does not.

**What this does not open up.** `img-parts` is scoped to the attachment
pipeline's metadata-stripping step. It is not a general "add an image
library" precedent — anything that needs to decode or render pixel data
(rather than edit a container's metadata segments) is a separate choice.

---

## D-039 — `arti` pinned at 0.43.0; workspace `rust-version` raised to 1.89
**Date:** 2026-08-02 · **Status:** accepted — project owner approved 2026-08-02

**The problem.** Phase 4 needs the Tor Project's own Rust implementation,
`arti`, to run the relay as a v3 onion service (`tor-hsservice`) and to
route the client's connection to it through Tor (`arti-client`). Checking
crates.io metadata (2026-08-02) before pinning anything, as the workspace's
own convention requires: the newest stable release of both crates,
0.44.0 (2026-06-30), declares an MSRV of Rust 1.91 — well past this
workspace's `rust-version = "1.82"` — and its docs.rs build (#3730389)
failed outright, a caution sign independent of the MSRV question. Walking
back through recent releases, 0.43.0's MSRV is 1.89 and it last built
cleanly on docs.rs.

**Decision.** Pin `arti-client = "=0.43.0"` and `tor-hsservice = "=0.43.0"`
(plus `tor-rtcompat` at the matching version for the tokio runtime glue).
Raise `rust-version` from `1.82` to `1.89` in both places it is declared
(root `Cargo.toml` and `clients/desktop/src-tauri/Cargo.toml` — the latter
sits outside the workspace and does not inherit the former, same reason
the version-number convention in `docs/CONTEXT.md` calls out four files
that move together). `tokio = "=1.53.1"`, already pinned, satisfies
arti-client 0.43.0's own `^1.47.1` requirement without a bump.

**Why this is not a bigger risk than it looks.** CI resolves its toolchain
via `dtolnay/rust-toolchain@stable` in every job (`.github/workflows/*.yml`),
not a pinned version, so it already builds with whatever is current —
raising the declared floor does not risk breaking CI. It only raises what a
from-source build documents as required, which was always going to move
for *some* dependency eventually.

**Rejected alternatives.**
- *Pin an older arti release compatible with 1.82.* Rejected: that means
  giving up several months of fixes in code whose entire job is anonymity
  and correctness against a network adversary — the wrong place to save an
  MSRV bump.
- *Pin 0.44.0 anyway and bump to 1.91.* Rejected on the docs.rs build
  failure alone, independent of the larger MSRV jump.

**Scope note, stated rather than assumed away.** `tor-hsservice`'s own
documentation describes itself as "a low-level implementation... that may
not be suitable for typical users." Its onion-service-hosting API
(`launch_onion_service`, `handle_rend_requests`, `StreamRequest`) is not
behind an `experimental` Cargo feature and ships in the stable 0.43.0
release, so it is being used through its intended interface per D-001's
sibling rule against inventing constructions — but it is newer, less
battle-tested code than `openmls` or `rusqlite`, and that is worth knowing
rather than treating 0.43.0 as equivalent in maturity to this project's
other pinned dependencies.

**A related, non-cryptographic architecture consequence recorded here
because it follows directly from this pin:** `reqwest` (already pinned,
used by `RelayClient` for the direct-transport path) exposes no hook for a
custom low-level connector, and `arti-client` 0.43.0 has no in-process SOCKS
listener of its own — only the separate `arti` CLI binary runs one, which
would mean shelling out to a subprocess and losing the "audited library
through its intended interface" property this project holds to. The
Tor-routed transport therefore is not built as a drop-in swap inside the
existing `reqwest`-based `RelayClient`; it is a second implementation built
directly on `hyper`/`hyper-util`, wrapping `TorClient::connect` in a small
`tower::Service<Uri>` connector — the same low-level primitives the relay
side needs anyway to bridge incoming onion-service streams into `axum`, so
this adds one dependency category, not two.

---

## D-040 — `rusqlite` bumped 0.32.1 → 0.39.0 to resolve an arti-client conflict; two forced companion bumps
**Date:** 2026-08-02 · **Status:** accepted — project owner approved 2026-08-02

**The problem, found while executing D-039.** `arti-client =0.43.0`
unconditionally depends on `tor-dirmgr =0.43.0` (needed to fetch and cache
the Tor consensus — required to build *any* circuit, not only onion
services), which unconditionally requires `rusqlite >=0.36.0,<0.40.0`,
confirmed via crates.io's own dependency metadata (`optional: false`, no
feature gate on either side — `tor-dirmgr`'s `static` feature only controls
whether SQLite is bundled, not whether the dependency exists). This
workspace's `rusqlite = "=0.32.1"` pin, in place since Phase 0/1 for the
SQLCipher-encrypted local database and the relay's own store (D-019,
D-024), cannot coexist with that range: both ultimately link the native
`sqlite3` library through `libsqlite3-sys`, and Cargo hard-blocks two
versions of a `links`-declaring crate in one build graph — not a version
negotiation, a wall. Confirmed with the actual Cargo resolver error before
concluding anything, not assumed from reading version ranges alone.

**Decision.** Bump the workspace `rusqlite` pin to `=0.39.0` — inside
`tor-dirmgr`'s required range, the newest 0.3x release, still ships
`bundled-sqlcipher` (confirmed on crates.io before choosing it, same
diligence D-038 applied to `img-parts`). This is the crate D-024's incident
was about, so it was not changed without real verification: reproduced the
conflict, applied the bump, and ran the **full existing test suite (163
tests) to completion, green**, including the SQLCipher-specific tests (wrong
key correctly refused, passphrase re-encryption, the runtime
`PRAGMA cipher_version` guard) — not just a clean compile. Verified on the
project's own Windows development environment, where SQLCipher/OpenSSL
linkage has caused problems before (`docs/PROGRESS.md`'s Windows build
notes).

**Two forced companion bumps, both low-risk.** `rusqlite 0.39.0`'s own
dependency tree (via a `sqlite-wasm-rs` entry, present regardless of target)
requires `thiserror ^2.0.12`; separately, `arti-client`'s `tor-config` →
`toml 1.0.3` chain requires `serde_core ^1.0.225`, which forces the paired
`serde_derive` to the same version as `serde` itself. Bumped
`thiserror = "=2.0.9"` → `"=2.0.19"` and `serde = "=1.0.216"` → `"=1.0.225"`.
Neither is a security-relevant crate in the way `rusqlite` is; both are
widely used, API-stable derive/error crates, and the full test suite passing
after both bumps is the real evidence, not an assumption that "minor version
bumps of popular crates are usually fine."

**One forced code fix, not a design change.** `rusqlite 0.39.0` dropped its
built-in `ToSql` implementation for raw `u64` — SQLite's native integer type
is signed 64-bit, and the crate now requires an explicit cast rather than
silently reinterpreting a `u64` as `i64`. `core/src/storage/` already cast
explicitly everywhere (`as i64`) before this bump; `server/src/store.rs` had
three call sites that did not, because they never needed to before. Fixed
with the same `as i64` cast pattern already established in `core` — every
value involved is a Unix timestamp or an expiry bucket, nowhere near
`i64::MAX`, so the cast is lossless for every realistic input.

**Rejected alternatives.**
- *Restructure Tor networking behind a separate OS process, avoiding the
  `rusqlite` conflict entirely by never linking `arti-client` into the same
  binary as `core`.* Rejected for this decision specifically (though see the
  note below): the `links` conflict applies to whatever gets linked into one
  final binary, not to Cargo workspace or lockfile boundaries — if the same
  executable still needs both `pouch-core` and an arti-wrapping crate as
  direct or transitive Rust dependencies, the conflict recurs regardless of
  which workspace member each lives in. A real fix along these lines would
  need an actual IPC boundary between two OS processes, which is a
  substantially larger architecture change than a dependency version bump,
  and was not what was being decided here.
- *Switch to the system `tor` daemon via its ControlPort instead of
  `arti-client`.* A legitimate, more involved alternative — sidesteps the
  Rust dependency graph entirely — but SPEC §3.2 names `arti` explicitly for
  Phase 4 transport, so this would be a SPEC.md amendment, not a dependency
  pin change, and a substantially larger rewrite of this plan's remaining
  tasks. Not chosen; recorded here so it is not silently forgotten as an
  option if `arti-client` causes further friction later in this phase.

**What this does not open up.** This is a version bump of an
already-audited, already-relied-upon crate, verified by the same test suite
that already exists for it — not a new trust decision about SQLCipher or
about how the local database is protected. D-019 and D-024's reasoning is
otherwise unchanged.
