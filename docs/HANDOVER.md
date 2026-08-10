# Where this stands — 2026-08-11

Supersedes the 2026-08-10 handover, which was written mid-session while the
release was broken and is now wrong in every particular. `docs/DECISIONS.md`
D-054 through D-057 have the reasoning; this file has the state.

---

## The v0.1.8 release is complete

Nine assets, both checksum files, tag at `69ec369`:

| Asset | Bytes |
|---|---|
| `Pouch-setup.exe` | 13,765,877 |
| `Pouch.msi` | 20,099,072 |
| `pouch-relay.exe` | 16,407,040 |
| `pouch-cli.exe` | 19,501,056 |
| `Pouch-debug.apk` | 145,326,197 |
| `Pouch-unsigned.apk` | 142,959,135 |
| `Pouch.aab` | 55,614,023 |
| `SHA256SUMS.txt` | 320 |
| `SHA256SUMS-android.txt` | 243 |

The Windows half was missing until `69ec369`. Both release jobs are green on
that tag and all seven CI jobs are green on `develop`.

## The bug that caused it, and the proof it is fixed

`Pouch-setup.exe` from v0.1.7 would not start:

> The code execution cannot proceed because libcrypto-3-x64.dll was not found.

Every Windows binary in that release imported an OpenSSL DLL. `rusqlite`'s
`bundled-sqlcipher` compiles SQLCipher from source and then links the **build
machine's** OpenSSL. The CI runner has one, so everything built, hashed and
published; a clean Windows install does not, so the app died before drawing a
window. Android was never affected — its crate already used
`bundled-sqlcipher-vendored-openssl` (D-047), and that decision's own comment
described this failure a phase before it shipped.

The workspace now selects `bundled-sqlcipher-vendored-openssl` for every
target. What makes this different from v0.1.7 is not that a check went green;
it is that the **published** artifacts were pulled back down and taken apart:

- All four Windows checksums recomputed from the downloaded files and matched
  `SHA256SUMS.txt`.
- `Pouch.msi` extracted administratively. The packaged
  `pouch-desktop.exe` has 31 imports, all system; the packaged
  `pouch-relay.exe` has 26, all system. Neither imports `libcrypto`.
- The relay inside the MSI is byte-identical to the standalone
  `pouch-relay.exe` (`822e07e8…`).
- Both binaries were executed. The relay printed
  `pouch-relay listening on 127.0.0.1:8443 (access logging disabled)` and had
  to be killed on a timeout — it loaded, rather than dying on a loader error.

**The guardrail:** `scripts/check-no-openssl-dll.py` parses each binary's PE
import directory against a permitted set of system DLLs, and runs in the
release job *before* the checksum and publish steps. Proven in both directions
— it passes the rebuilt binaries and still fails the **published v0.1.7 relay**
on `libcrypto-3-x64.dll`, exit 1.

Two build-host details this now depends on, both of which will fail loudly
rather than silently if they move: the release workflow's "Locate OpenSSL" step
is deleted, not tidied away (`openssl-sys` prefers a located copy over
vendoring, so leaving it would have rebuilt the same broken artifact — D-055);
and `OPENSSL_SRC_PERL` names Strawberry Perl outright rather than trusting
`PATH`, because `shell: bash` on a Windows runner is Git Bash and its
`/usr/bin/perl` lacks two modules OpenSSL's `Configure` loads first (D-056).

## The one thing not verified

**Nobody has run `Pouch-setup.exe`.** It is a GUI installer, so it did not fit
in this session's tooling. Every layer underneath it has been checked — the
binaries it carries are the ones taken apart above — but the exact failure
mode of v0.1.7 was an installer that produced an app that would not start, and
the only test that ever caught it was a double-click. Worth five minutes.

## The CI failure on 2026-08-11

`Rust — build, test, clippy` failed on `69ec369` with
`"Mai" survives in the relay database` — the SPEC §8.3 server-blindness
assertion. Not a leak: `"Mai"` is three bytes and the relay database is ~811 KB
of ciphertext, so it collides by chance in about one run in twenty. Reproduced
locally 2 times in 27 runs, the match landing mid-ciphertext beside no readable
field. Fixed in `c38e6d7` by giving both blindness tests canaries long enough
to be unique and enforcing a minimum canary length in the assertion itself.
Full reasoning in D-057.

---

## Then: get it on a phone

`Pouch-debug.apk` **installs today** — v2-signed, verified by parsing its
signing block. The release APK is unsigned and Android refuses those outright.

First launch asks for the relay address and cannot be skipped; the build
default `10.0.2.2:8443` is an emulator address, unreachable from a handset.
Start the relay from the desktop app (**Privacy and storage → Hosting**), copy
the `.onion` address, paste it into the phone's second field.

This will be the first time any of that Kotlin or its JNI marshalling has
executed anywhere. Treat first launch as the test.

## Still yours to decide

1. **A release keystore** — `docs/SIGNING_ANDROID.md` has the procedure.
   Needed for a signed APK or a Play upload. I did not generate one: that key
   is the app's permanent identity and losing it means never updating the app
   again.
2. **Android Keystore for database keying** (D-035) — a SPEC §2.6 stop-and-ask.
3. **Cover traffic** (D-044), **video attachments** (D-038).

## Lessons worth keeping

- **A green release is not a working artifact.** Three green jobs, four
  matching checksums and a successful local build all reported a working
  v0.1.7. Only installing it found the bug. Every check that passed was a check
  of something the build controlled; none was a check of the thing a user runs.
- **The developer machine hid it twice.** It has `OPENSSL_DIR` exported
  globally and carries `libcrypto-4-x64.dll` — a *different major version* than
  the runner linked. A local success that depends on an unexported environment
  variable is not evidence a build is self-contained.
- **Check timestamps before trusting a measurement.** One `libcrypto-4` reading
  came from a `pouch-desktop.exe` left by an interrupted build. The lock file
  and the binary disagreed, and the binary was stale.
- **Guardrails must be shown to fail.** The first DLL check used `strings`,
  absent from a stock Windows runner; it would have passed everything by never
  running. Same for D-057's canary bound — both directions were demonstrated
  before either was trusted.
- **A flaky privacy test invites its own weakening.** The response to a test
  that fails 5% of the time is to soften it, and in this case that assertion
  was the one proving the server sees nothing. The bound is now enforced in
  code with a message saying to lengthen the string, not lower the bound.
