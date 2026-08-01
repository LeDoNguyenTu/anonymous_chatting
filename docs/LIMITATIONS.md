# Limitations

Plain language, no hedging. If you are deciding whether to trust this with
something that matters, read this page and not the README.

**Last revised:** 2026-08-01 (Phase 0)

---

## The short version

Pouch is unaudited student work. No cryptographer has reviewed it. It uses good
building blocks, and using good building blocks correctly is a thing that is easy
to get wrong in ways that are invisible from the outside — including invisible to
the person who wrote it.

If you are a journalist, an activist, a source, or anyone else who would face
real consequences if your messages were read, **use Signal**. That is not
modesty. Signal is audited, has a decade of adversarial attention, and is
maintained by people whose full-time job it is. This project has none of those
things.

---

## What this does not protect against

**Someone who controls your device.** Malware, a keylogger, screen-recording
software, or a person holding your unlocked phone. Encryption protects a message
while it travels and while it sits on disk. It cannot protect a message that is
being displayed on a screen someone else is watching. Every messenger has this
limitation, including Signal.

**Someone watching both ends of the conversation.** If an adversary can observe
your internet connection and your contact's at the same time, they can match up
the timing of a message leaving you and arriving with them — without reading
anything. Tor makes this harder. It does not make it impossible. Only systems
that deliberately delay messages by minutes or hours defeat this, and Pouch is
not one of those.

**Being made to unlock it.** A court order, a border officer, or someone
threatening you. Disappearing messages mean there is less to hand over, which
helps only if the timer already ran.

**The person you are talking to.** They can screenshot, forward, or simply tell
someone. No software fixes this.

**A backdoor hidden in a dependency.** Pouch pins exact versions of everything
and checks them against known-vulnerability databases in CI. That catches
*published* problems. It does not catch a deliberate backdoor nobody has found
yet. There is no reproducible-build story here.

**Someone stopping your messages.** A hostile relay operator can refuse to accept
or deliver. They cannot read anything, but they can block. Availability is not
defended.

---

## What leaks, even when everything works

**That you are using it, and roughly how much.** The relay sees connections from
some inbox identifier. It does not know whose. Your internet provider sees you
connecting to a relay, or — from Phase 4 — that you are using Tor.

**Message sizes, approximately.** Messages are padded into fixed size buckets, so
a 70 KB file and a 200 KB file look identical. A 12 KB message and a 12 MB
message still do not.

**Your IP address, until Phase 4.** Until the Tor transport lands, the relay sees
the address you connect from. After Phase 4 it does not — but your local network
and your Tor guard node still do, always.

**When you connect.** Not what you sent, not to whom. Just that something
happened, and roughly when.

---

## What is not built yet

Pouch is being built in phases. Anything below is documented intent, not working
software. The UI is required to show unimplemented pipeline stages as
`not yet implemented` rather than as complete — a status display that lies is
worse than no status display.

| Feature | Phase | State |
|---|---|---|
| One-to-one encrypted text | 1 | in progress |
| Disappearing messages, wipe, backup | 2 | not started |
| Attachments, metadata stripping, sealed sender | 3 | not started |
| Tor transport | 4 | not started |
| Android client | 5 | not started |
| Groups and multi-device | 6 | roadmap only |

Until Phase 3, the relay can see which inbox sent a message. Until Phase 4, it
can see your IP address. The Custody Strip shows `DIRECT` in amber during that
time, and it is telling you the truth.

---

## Things this project deliberately will not claim

It is not unbreakable, uncrackable, military grade, bank grade, NSA proof,
quantum proof, hacker proof, or 100% secure. Nothing is. Those phrases are
marketing, and in a security product they are a warning sign about the people who
use them.

It is also not "stronger than Signal." It uses the same class of primitives, and
those primitives are already infeasible to break, so there is no headroom to
compete over. Where Pouch differs is policy — no phone number, self-hostable, no
server-side backup — and that difference does not outweigh being unaudited.
