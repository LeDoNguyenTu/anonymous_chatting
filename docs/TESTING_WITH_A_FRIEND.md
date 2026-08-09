# Testing Pouch with another person

Two people, one relay. This is the shortest path that actually exercises the
system rather than a loopback demo.

**Read this first:** Pouch is unaudited student software. No cryptographer has
reviewed it. Use it to test that it works, not to say anything you would mind
being read. `docs/THREAT_MODEL.md` §4 lists what it does not defend against.

---

## What you are setting up

One of you runs the relay. It ships inside the desktop installer — there is
nothing extra to download and no terminal involved. The relay stores encrypted
blobs and can read none of them; there is a test in CI asserting that
(`server-blindness`). It still has to be somewhere you can both reach.

```
  You (hosting)                           Your friend
  ─────────────                           ───────────
  Pouch.exe
    └── Privacy and storage → Hosting
          starts the bundled relay
          publishes a Tor address ────────► pasted into their
                                            Relay screen
    talks to its own relay                  reaches yours over Tor
    on 127.0.0.1:8443                       (no port forwarding)
```

**Both of you install one thing.** Whoever hosts presses one button. The other
pastes an address.

### The honest limitation

**This is not Signal, and the difference matters.** Signal works when your
friend's phone is off because Signal runs servers that are always up. Here the
relay is a program on somebody's laptop. Close Pouch, sleep the machine, or walk
out of wifi range and messages sent to you are not delivered — they wait at the
sender until your relay is reachable again.

So pick a host whose machine is on when you are both using it, or run a relay
somewhere permanent if you want the always-available behaviour.

**Why Tor rather than a plain address?** `pouch-relay` serves plain HTTP. A
client refuses a non-loopback relay unless its TLS key is pinned (D-017), and
there is no TLS to pin without a reverse proxy in front of it. The onion service
needs no certificate, no domain, and no port forwarding — which is what makes
"press one button" possible at all.

---

## Step 1 — Get the binaries

From the [releases page](https://github.com/LeDoNguyenTu/anonymous_chatting/releases).

| You want | If |
|---|---|
| `Pouch-setup.exe` | Windows. Contains the client *and* the relay. |
| `Pouch-debug.apk` | Android. **This is the one to sideload today.** |
| `Pouch.apk` | Android, once the project has a signing key. Absent until then. |

**On Android, take the debug APK.** Releases so far ship
`Pouch-unsigned.apk`, and Android refuses to install an unsigned APK — there is
nothing to click through. `Pouch-debug.apk` is signed with the debug key, so it
installs, and it carries the `.debug` suffix so it sits alongside a release
build rather than replacing one. It is a debug build: anything with adb access
can inspect it. `docs/SIGNING_ANDROID.md` is how that changes.

**The binaries are not code-signed.** There is no certificate for this project.
Windows SmartScreen will say the publisher is unknown, and Android will warn
about installing from an unknown source. Both are right to.

Verify the download instead of clicking through the warning:

```powershell
Get-FileHash .\Pouch-setup.exe -Algorithm SHA256
```

Compare against `SHA256SUMS.txt` on the release. A matching hash means you have
the file the build produced. It does **not** mean the software is safe — only
that it is unmodified since it was built.

## Step 2 — Host starts the relay

Install `Pouch-setup.exe`, launch it, create an identity. Set a passphrase when
it offers: without one the database key is a file next to the database (D-035),
which protects against nothing that has your disk.

Then **Privacy and storage → Hosting → Start hosting**.

The first start is slow. Publishing an onion service means bootstrapping Tor and
announcing the service, which takes tens of seconds. The screen says *Starting*
until there is an address, then shows it.

Copy that address and send it to the other person. It is not secret the way a
key is — the relay cannot read anything — but anyone holding it can reach your
relay, so do not post it publicly.

Leave Pouch open. Closing it stops the relay.

## Step 3 — The other person points at it

**Windows:** install `Pouch-setup.exe`, launch it. Before creating an identity,
go to **Privacy and storage → Transport** and choose **Tor**, then set the onion
address. The Custody Strip at the top should read `TOR`.

**Android:** install the APK. The first screen asks where the relay is. Put the
onion address in the second field and leave the first at its default. Tap
**Save and continue**.

The first Tor connection takes tens of seconds. If Tor cannot be reached the app
says so and stays on the route it was on — it never silently falls back, because
falling back would send over a route you did not choose.

## Step 4 — Add each other

Each of you: open **Add contact**, where your own invite code is shown. Copy it.
Send the two codes to each other **over a different channel than Pouch** — a
phone call, in person, another messenger.

That channel matters more than it sounds. An invite code is how each client
learns the other's identity key. Someone who can rewrite a code in transit can
substitute their own key, and everything after that is encrypted to them. Pouch
cannot detect that; the safety number check in step 5 is what detects it.

Then paste the code you received, give them a name, and add.

## Step 5 — Compare safety numbers

Open the conversation, open **Safety number**. Both of you see a block of digits.

**Read them aloud to each other over that same out-of-band channel.** If they
match, press *They match*. If they do not, stop — something is between you, and
it is not a bug to work around.

Until you do this the app shows `UNVERIFIED` in amber and keeps showing it. That
is not a nag to dismiss; it is the accurate state.

## Step 6 — Send something

Type a message and send. The manifest under the composer shows each stage that
ran: composed, padded, encrypted, routed, held at relay, delivered. Stages that
are not implemented say so rather than showing as complete.

On desktop, **What the relay could see** shows what the host's relay actually
stored: a padded blob, an inbox identifier, an expiry. No sender, no name, no
plaintext.

Attachments are JPEG, PNG and WebP only — video is refused with an explanation
(D-038). Metadata is stripped before encryption.

---

## When it does not work

| What you see | What it means |
|---|---|
| SmartScreen blocks the installer | Expected; unsigned. Verify the hash first. |
| Hosting screen says *Starting* for minutes | Tor is slow or blocked on this network. Some networks block it outright. |
| Custody Strip says `DIRECT` on the joining machine | The Tor switch did not take. Re-check the onion address. |
| "No Tor relay address is configured" | No onion address was set. Android: first screen. Desktop: `POUCH_RELAY_TOR_ONION`. |
| Messages send but never arrive | Both clients must reach the *same* relay, and the host's Pouch must be open. |
| Android refuses to install the APK at all | You have `Pouch-unsigned.apk`. Android will not install an unsigned APK. Use `Pouch-debug.apk`. |
| Android app installs but crashes on launch | The APK was built without native libraries for your phone's ABI. Report it with your device model. |
| "could not be verified against a pinned key" | A non-loopback `POUCH_RELAY` without `POUCH_RELAY_PIN`. Use the onion route. |
| Messages queue and never send on Android | The relay address is still the build default (`10.0.2.2`), which is an emulator address. Settings → Change relay. |

## What this test does and does not prove

**Does:** two clients on different machines exchange messages through a relay
that holds only ciphertext; Tor transport works end to end; the manifest and
Custody Strip report the real route.

**Does not:** anything about resistance to an actual attacker, and nothing an
audit would tell you. The Android client in particular has never run on a
device — if you are doing this, you are the first person to execute that code.
