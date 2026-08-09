# Testing Pouch with another person

Two people, two Windows laptops, one relay. This is the shortest path that
actually exercises the system rather than a loopback demo.

**Read this first:** Pouch is unaudited student software. No cryptographer has
reviewed it. Use it to test that it works, not to say anything you would mind
being read. `docs/THREAT_MODEL.md` §4 lists what it does not defend against.

---

## What you are setting up

One of you runs the relay. The relay stores encrypted blobs and can read none
of them — that is the whole point of the architecture and there is a test in
CI asserting it (`server-blindness`). It still needs to be somewhere you can
both reach.

```
  You (relay host)                        Your friend
  ────────────────                        ───────────
  pouch-relay.exe                              │
    ├── listens on 127.0.0.1:8443              │
    └── publishes a Tor onion address ─────────┘
                                          reaches it over Tor
  Pouch.exe ──► 127.0.0.1:8443            Pouch.exe ──► the onion address
    (direct, same machine)                  (Tor, no port forwarding needed)
```

The onion service is what makes this work without port forwarding, a domain
name, a TLS certificate, or a cloud host. Your friend's client builds a Tor
circuit to your relay; neither of you configures a router.

**Why not plain HTTP over the internet?** `pouch-relay.exe` serves plain HTTP.
A client refuses to talk to a non-loopback relay unless its TLS key is pinned
(D-017), and there is no TLS to pin without a reverse proxy in front of it. So
the direct route works on one machine, and Tor is the route between two. That
refusal is deliberate: an unpinned remote relay cannot be shown to be the relay
you meant.

---

## Step 1 — Get the binaries

Download from the [v0.1.5 release](https://github.com/LeDoNguyenTu/anonymous_chatting/releases/tag/v0.1.5).
You want `Pouch-setup.exe` (both of you) and `pouch-relay.exe` (whoever hosts).

**The binaries are not code-signed.** There is no certificate for this project.
Windows SmartScreen will say the publisher is unknown, and it is right to.

Verify the download instead of clicking through the warning:

```powershell
Get-FileHash .\Pouch-setup.exe -Algorithm SHA256
```

Compare that against `SHA256SUMS.txt` on the release. Matching hashes mean you
have the file the build produced. They do **not** mean the software is safe —
only that it is unmodified since it was built.

## Step 2 — Host starts the relay

Open PowerShell where you saved `pouch-relay.exe`:

```powershell
$env:POUCH_RELAY_TOR_STATE = "tor-state"
.\pouch-relay.exe
```

Setting `POUCH_RELAY_TOR_STATE` is what turns the onion service on. Without it
the relay is loopback-only and your friend cannot reach it.

The first start is slow — Tor has to fetch a consensus and publish the service,
which takes tens of seconds. It prints:

```
pouch-relay listening on 127.0.0.1:8443 (access logging disabled)
pouch-relay onion service listening at <56-characters>.onion
```

Send your friend that onion address. It is not a secret in the way a key is —
it names your relay, and the relay is untrusted by design — but anyone who has
it can reach your relay, so do not post it publicly.

Leave this window open. Closing it takes the relay and the onion service down.

## Step 3 — Host runs their client

Install `Pouch-setup.exe`, launch it, create an identity. Nothing to configure:
the client defaults to `http://127.0.0.1:8443`, which is the relay you just
started on the same machine.

Set a passphrase when it offers. Without one the database key is a file sitting
next to the database (D-035), which protects against nothing that has your
disk.

## Step 4 — Friend points their client at the onion address

Before launching Pouch, in PowerShell:

```powershell
$env:POUCH_RELAY_TOR_ONION = "<the address from step 2, no http://, no .onion port>"
& "$env:LOCALAPPDATA\Programs\Pouch\Pouch.exe"
```

It has to be launched from that shell — an environment variable set in one
window does not reach a program started from the Start menu. To make it stick:

```powershell
[Environment]::SetEnvironmentVariable("POUCH_RELAY_TOR_ONION", "<address>", "User")
```

Then open **Transport settings** in the app and choose **Tor**. The first
connection takes tens of seconds. If Tor cannot be reached the app says so and
stays on the route it was on — it never silently falls back, because falling
back would send over a route you did not choose.

The Custody Strip at the top should read `TOR`. If it reads `DIRECT`, the
switch did not take, and messages would be going nowhere — the friend's machine
has no relay on `127.0.0.1:8443`.

## Step 5 — Add each other

Each of you: open **Add contact**, where your own **invite code** is shown at
the top. Copy it. Send the two codes to each other **over a different channel
than Pouch** — Signal, a phone call, in person.

That channel matters more than it sounds. An invite code is how each client
learns the other's identity key. If someone can rewrite the code in transit,
they can substitute their own key, and everything after that is encrypted to
them. Pouch cannot detect this; the safety number check in step 6 is what
detects it.

Then **Add contact** → paste the code you received.

## Step 6 — Compare safety numbers

Open the conversation, open **Safety number**. Both of you will see a string of
digits.

**Read them aloud to each other over that same out-of-band channel.** If they
match, mark the contact verified. If they do not match, stop — something is
between you, and it is not a bug to work around.

Until you do this the app shows `UNVERIFIED` in amber and keeps showing it.
That is not a nag to dismiss; it is the accurate state.

## Step 7 — Send something

Type a message, send. Open **What the relay could see** to see what your relay
host's `pouch-relay.exe` actually stored: a padded blob, an inbox identifier,
and an expiry. No sender, no name, no plaintext.

Attachments are JPEG, PNG and WebP only — video is refused with a message
explaining why (D-038). Metadata is stripped before encryption; the strip
manifest shows each stage that ran.

---

## When it does not work

| What you see | What it means |
|---|---|
| SmartScreen blocks the installer | Expected; the binary is unsigned. Verify the hash first. |
| Custody Strip says `DIRECT` on the friend's machine | The Tor switch did not take. Check `POUCH_RELAY_TOR_ONION` is set in the shell that launched the app. |
| "No Tor relay address is configured for this build" | `POUCH_RELAY_TOR_ONION` was not set when the app started. Set it, restart the app. |
| Tor connection fails | Some networks block Tor. Try another network. There is no fallback by design. |
| Messages send but never arrive | Both clients must reach the *same* relay. Confirm the host's relay window is still open. |
| "could not be verified against a pinned key" | You set `POUCH_RELAY` to a non-loopback address without `POUCH_RELAY_PIN`. Use the onion route instead. |
| Relay start is slow the first time | Publishing an onion service takes tens of seconds. Subsequent starts reuse `tor-state` and are faster. |

## What this test does and does not prove

**Does:** two clients on different machines exchange messages through a relay
that holds only ciphertext; Tor transport works end to end; the manifest and
Custody Strip report the real route.

**Does not:** anything about the Android client, which has never run on a
device. Anything about resistance to an actual attacker. Anything an audit
would tell you.
