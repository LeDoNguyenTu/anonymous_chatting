# Roadmap — what is left, what it costs, and what I would do first

Written 2026-08-09, at version 0.1.5, for the project owner to decide against.
Nothing here is started. Each item states what it buys, what it costs, and the
argument against doing it, because the argument against is the part that is
usually missing.

The ordering below is my recommendation, not SPEC's. Where it departs from
SPEC's phase order, it says so and why.

---

## First: run the two-person test

**Not a build item.** Cost: an evening. Value: higher than anything else on
this page.

Everything in this repository is verified by tests and CI. Nothing has been
verified by two people using it. The walkthrough in
`docs/TESTING_WITH_A_FRIEND.md` is a procedure I wrote from reading the code; it
has never been executed, and procedures written that way are wrong in small ways
that only contact discovers — a step in the wrong order, a screen that does not
say what I claimed, an onion address that takes longer to publish than the
guide implies.

Do this before building anything else. What it finds changes what is worth
building next, and no amount of further code makes the finding cheaper.

---

## The three real options

### Option A — Finish the Android client (SPEC Phase 5)

**What is left:** eight of twelve screens. Conversation view, add contact,
safety number, privacy and storage, security details, transport settings, backup
and restore, identity-change modal. The bridge, the design tokens, the Custody
Strip and the conversation list exist and compile.

**Cost:** large. Each screen is Compose plus a JNI operation plus tests. Say a
week of focused work for the set, plus whatever the first real device run
uncovers — and that is the part I cannot estimate, because the JNI marshalling
has never executed anywhere. `read_string`, the exception throw and the
`jstring` return are reviewed and unrun.

**What it buys:** the phone client, which is where a messenger actually gets
used. Also closes the one SPEC phase that is genuinely open.

**Argument against, and it is a real one:** I cannot verify any of it. No
device, no emulator, no SDK in this environment. I would be writing eight
screens that compile in CI and have never displayed a pixel. The first person to
run it finds every mistake at once. If you have an Android device and are
willing to be that person, this is a good use of time; if not, it is eight
screens of hope.

**Blocked sub-item:** Android Keystore (D-035) is a SPEC §2.6 stop-and-ask and
needs your decision before it is built. The realistic design has Kotlin unwrap a
Keystore-wrapped key and pass bytes across JNI, which puts key material in a JVM
`ByteArray` that cannot be reliably zeroed. That is a genuine trade, not an
implementation detail, and I should not pick it unilaterally.

### Option B — Harden what already ships

**What it is:** the desktop client works and is now distributable. It is also
the least-attacked code in the project, because nobody has attacked it.

Candidates, roughly in value order:

1. **Relay TLS.** `pouch-relay` serves plain HTTP. That is why the only
   two-machine route is Tor. Terminating TLS in the relay — or documenting a
   reverse-proxy setup properly — makes the direct pinned route real, which
   matters if Tor's added latency proves annoying in practice.
2. **A passphrase that is actually the default.** D-035's device-key file
   protects against nothing that has your disk. The passphrase path exists and
   is opt-in. Making it the default changes the honest answer to "what happens
   if someone steals this laptop" from "they read everything" to "they need
   your passphrase."
3. **macOS and Linux builds.** Mostly a CI matrix entry. Each needs its own
   artifact naming and neither has been tried.
4. **Auto-update.** Tauri supports it. Needs a signing key and a hosted
   manifest, both yours to hold. Worth it only once there are users to update.

**Cost:** each is small to medium and independent. This is the option you can
stop halfway through without leaving anything broken.

**Argument against:** none of it is visible. It makes the existing thing better
rather than making a new thing exist, which is worth less in a portfolio
conversation and more to anyone actually using it.

### Option C — Multi-device and groups (SPEC's actual Phase 6)

**SPEC's own words:** "Genuinely hard... this is where scope explodes. Treat as
documented roadmap unless Phases 0–5 are complete and solid."

Phase 5 is not complete. By SPEC's rule this does not start.

**Why it is hard, concretely.** MLS handles groups natively — that is the point
of the protocol and why it was chosen — so the cryptography is mostly not the
problem. The problem is everything around it: a second device needs your
identity key, so now there is a key-transfer flow to design, which is a
stop-and-ask. Group membership changes need to be delivered to everyone,
which means the relay learns more about group shape than it currently learns
about anything. That last part is a direct tension with the constraint the whole
architecture is built around.

**My recommendation: do not start this.** Not because it is too hard, but
because the metadata question needs answering first and answering it well is a
design exercise, not a coding one.

---

## Smaller open items, all previously recorded

| Item | Status | Needs |
|---|---|---|
| Cover traffic (D-044) | Deferred, stop-and-ask | Your design decision — SPEC does not specify shape, and cover traffic an observer can distinguish is worse than none |
| Video attachments (D-038) | Deferred | A metadata-stripping approach for video containers that is not "wrap FFmpeg and hope" |
| Android Keystore (D-035) | Deferred, stop-and-ask | Your decision on the JVM `ByteArray` trade above |
| The flaky server-blindness test | Unreproduced | It failed once, in Phase 4, and has not failed since. Unresolved is the honest status |
| `SPEC_PHASE` still reads 4 | Correct | Moves when Phase 5 closes, not before |

---

## What I would actually do

1. **Run the two-person test.** Everything else is speculation until this
   happens.
2. **Fix whatever that finds.** It will find something.
3. **Then Option B items 1 and 2** — relay TLS and passphrase-by-default. Both
   are small, both are verifiable here, and both make the thing you can already
   hand someone meaningfully better.
4. **Option A only if you have a device** and are prepared to be the first
   person to run the JNI boundary. It is good work and I cannot check it.
5. **Option C not yet**, on SPEC's own instruction.

The honest summary: this project is at the point where the next real
information comes from use, not from code. I would go and get that information
before writing more.
