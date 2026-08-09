# Where this stands — 2026-08-10

Written mid-session because credit was running out. This is the handover:
what is fixed, what is verified, what is broken right now, and the exact next
command. `docs/DECISIONS.md` D-054 has the reasoning; this file has the state.

---

## The bug you hit

`Pouch-setup.exe` from v0.1.7 would not start:

> The code execution cannot proceed because libcrypto-3-x64.dll was not found.

Every Windows binary in that release — client, relay, CLI — imported an OpenSSL
DLL. `rusqlite`'s `bundled-sqlcipher` compiles SQLCipher from source and then
links the **build machine's** OpenSSL. The CI runner has one, so everything
built, hashed and published; a clean Windows install does not, so the app died
before drawing a window.

Android was never affected: its crate already used
`bundled-sqlcipher-vendored-openssl` (D-047), and that decision's own comment
described this failure a phase before it shipped.

## Fixed and verified

**The fix:** the workspace now selects `bundled-sqlcipher-vendored-openssl` for
every target, so OpenSSL is compiled from source into each binary.

Verified by building locally with `OPENSSL_DIR` cleared and parsing the PE
import tables — not by reading a green check:

| Artifact | Result |
|---|---|
| `pouch-relay.exe` | no `libcrypto`, 26 imports all system, 12.2 MB → 16.4 MB |
| `pouch-desktop.exe` | no `libcrypto`, 33 imports all system, 31.4 MB → 35.5 MB |
| `Pouch_0.1.8_x64_en-US.msi` | contains `Bin_pouch_relay.exe` at 16,358,400 bytes (matches the verified relay) and the client at 35.5 MB |

**The guardrail:** `scripts/check-no-openssl-dll.py` parses each binary's import
directory against a permitted set of system DLLs, and runs in the release job
*before* the checksum and publish steps. Proven in both directions — it passes
the rebuilt binaries and still fails the **published v0.1.7 relay** on
`libcrypto-3-x64.dll`. A check never shown to fail is not known to work.

**Deleted:** the release workflow's "Locate OpenSSL" step. Not cleanup — part of
the fix. `openssl-sys` prefers a located copy over vendoring, so leaving it
would have silently rebuilt the same broken artifact.

Committed on `develop`: `a95fb6a`, `196cae1`, `ed4b949`. All seven CI jobs green
on `a95fb6a`. 181 workspace tests pass, fmt and clippy clean, six guardrails
pass.

---

## Broken right now — do this first

**The `v0.1.8` release on GitHub is half-published.** It has only
`Pouch-debug.apk`, `Pouch-unsigned.apk` and `Pouch.aab`. The Windows job failed,
so there is no installer, no relay, no CLI, and **no `SHA256SUMS.txt`** — the
Android sums file is there but the Windows one is not. Anyone landing on that
page sees a release that looks like an Android-only build.

**The tag points at the wrong commit.** `v0.1.8` → `a95fb6a`, which predates the
perl fix in `196cae1`. Re-running it fails the same way in the same 33 seconds.

### Why the Windows job failed

```
Can't locate Locale/Maketext/Simple.pm in @INC ... perl in use: /usr/bin/perl
```

`shell: bash` on a Windows runner is Git Bash, whose `/usr/bin/perl` is a
minimal build missing the two modules OpenSSL's `Configure` loads first. The
runner image ships Strawberry Perl, which has both, but `/usr/bin` shadows it.
Fixed in `196cae1` by prepending Strawberry to `GITHUB_PATH`.

This one is on me: I hit the identical wall locally, fixed it by installing
Strawberry Perl and putting it first on `PATH`, then carried only half of that
across to CI — the `OPENSSL_DIR` clearing but not the `PATH`. The check caught
it in 33 seconds with the module name in the error, rather than fifteen minutes
in under a cargo build script, which is the one thing that went right.

### The exact next step

Delete the half-published release and the tag, then re-tag at `develop`:

```bash
gh release delete v0.1.8 --yes && git tag -d v0.1.8 && git push origin :refs/tags/v0.1.8 && git tag -a v0.1.8 -m "v0.1.8" ed4b949 && git push origin v0.1.8
```

Deleting is safe: nothing under `v0.1.8` is worth keeping, since the Android
artifacts will be rebuilt identically and the Windows half never existed. The
run takes ~50 minutes — the Android job cross-compiles four ABIs and now builds
OpenSSL from source for each.

**Watch for:** the Windows job reaching `Confirm no binary depends on a DLL the
target may not have`. That step passing is the actual proof the crash is fixed
in a *published* artifact rather than only in a local build.

---

## Then: get it on a phone

`Pouch-debug.apk` on the v0.1.8 release **installs today** — v2-signed,
verified by parsing its signing block. The release APK is unsigned and Android
refuses those outright.

First launch asks for the relay address and cannot be skipped; the build default
`10.0.2.2:8443` is an emulator address, unreachable from a handset. Start the
relay from the desktop app (**Privacy and storage → Hosting**), copy the
`.onion` address, paste it into the phone's second field.

This will be the first time any of that Kotlin or its JNI marshalling has
executed anywhere. Treat first launch as the test.

## Still yours to decide

1. **A release keystore** — `docs/SIGNING_ANDROID.md` has the procedure. Needed
   for a signed APK or a Play upload. I did not generate one: that key is the
   app's permanent identity and losing it means never updating the app again.
2. **Android Keystore for database keying** (D-035) — a SPEC §2.6 stop-and-ask.
3. **Cover traffic** (D-044), **video attachments** (D-038).

## Lessons worth keeping

- **A green release is not a working artifact.** Three green jobs, four matching
  checksums and a successful local build all reported a working v0.1.7. Only
  installing it found the bug. Every check that passed was a check of something
  the build controlled; none was a check of the thing a user runs.
- **The developer machine hid it twice.** It has `OPENSSL_DIR` exported globally
  and carries `libcrypto-4-x64.dll` — a *different major version* than the
  runner linked. A local success that depends on an unexported environment
  variable is not evidence a build is self-contained.
- **Check timestamps before trusting a measurement.** One `libcrypto-4` reading
  came from a `pouch-desktop.exe` left by an interrupted build. The lock file
  and the binary disagreed, and the binary was stale.
- **Guardrails must be shown to fail.** The first DLL check used `strings`,
  absent from a stock Windows runner; it would have passed everything by never
  running.
