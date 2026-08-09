# Signing the Android release

Everything for a signed APK is wired. What is missing is a key, and a key is
yours to make — not CI's, and not mine.

This is the only step between the current release and an APK someone can
install.

---

## Why this is not automated

The key you sign with is your app's permanent identity. Play accepts an update
only when it is signed by the same key as the version before it, so **losing
this file means you can never update this app again** — not under this package
name, not for anyone who already installed it. There is no recovery process.

Generating one inside a CI run would put that identity in a build log on a
machine you do not control, for a key that has to outlive every build. So the
workflow does not create one. If no keystore is configured it produces
`Pouch-unsigned.apk` and says so in the release notes, which is the honest
outcome rather than a convenient one.

---

## Make the key

Needs a JDK — `keytool` ships with it.

```bash
keytool -genkeypair -v -keystore pouch-release.jks -alias pouch -keyalg RSA -keysize 4096 -validity 10000
```

It asks for a keystore password, your name and organisation, and then a key
password. `-validity 10000` is about 27 years; Play requires a key valid past
2033, and a certificate that expires is a certificate that ends the app.

**Back up `pouch-release.jks` and both passwords somewhere you would not lose a
passport.** Not only on the machine that made it. Losing it is unrecoverable in
the strict sense — no support ticket fixes it.

---

## Signing locally

Create `clients/android/keystore.properties`. It is gitignored, and it must
stay that way — verify with `git check-ignore -v clients/android/keystore.properties`
before you put a password in it.

```properties
storeFile=/absolute/path/to/pouch-release.jks
storePassword=...
keyAlias=pouch
keyPassword=...
```

Then:

```bash
cd clients/android && gradle :app:assembleRelease
```

The build prints `Pouch: no release keystore configured` when it cannot find
one, so a silent fallback to an unsigned APK is not possible. The output is
`app/build/outputs/apk/release/`.

---

## Signing in CI

Four repository secrets, at **Settings → Secrets and variables → Actions**:

| Secret | Value |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | the keystore file, base64-encoded |
| `ANDROID_KEYSTORE_PASSWORD` | keystore password |
| `ANDROID_KEY_ALIAS` | `pouch`, or whatever `-alias` you used |
| `ANDROID_KEY_PASSWORD` | key password |

Encode the file:

```bash
base64 -w0 pouch-release.jks > pouch-release.jks.b64
```

On Windows PowerShell:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("pouch-release.jks")) | Set-Content pouch-release.jks.b64
```

Paste the contents of that `.b64` file as the secret value, then delete it — it
is the keystore, in a form that is trivially decoded.

The workflow decodes it to a file under `RUNNER_TEMP` and fails if it decodes to
nothing, so a truncated paste surfaces as a failed build rather than as an
unsigned artifact that looks deliberate. The three passwords stay in the
environment and are never written to disk.

Tag a release and the job produces `Pouch.apk` instead of
`Pouch-unsigned.apk`:

```bash
git tag v0.1.8 && git push origin v0.1.8
```

---

## Checking what you got

An unsigned APK cannot be installed. Confirm before sending it to anyone:

```bash
apksigner verify --verbose Pouch.apk
```

`apksigner` lives in `$ANDROID_HOME/build-tools/<version>/`. Expect
`Verified using v2 scheme: true`. Without the Android SDK, the crude check is
that a signed APK contains an `APK Sig Block 42` marker near its end and an
unsigned one does not.

`Pouch-debug.apk` is always signed, with the debug key. It installs, and it is
suffixed `.debug` so it sits alongside a release build rather than replacing
one. It is for testing — a debug build is debuggable, which means anything with
adb access can inspect it.

---

## Play

`Pouch.aab` is the upload artifact; the APK is what you sideload.

Play will ask about **Play App Signing**, where Google holds the signing key and
you keep an upload key. It makes losing your key survivable, and it means Google
can sign builds as you. Either answer is defensible. Decide it deliberately
rather than by clicking through, because the choice is made once per app and
cannot be undone.

Two things about this app that a Play listing has to be honest about:

- It is unaudited student software. The listing should not imply otherwise, and
  the same rule that governs this repository governs the store description: no
  claim of unbreakable, uncrackable, military-grade, or better-than-Signal.
- Messages depend on someone running a relay. If nobody hosts, nothing is
  delivered. A store listing that omits this is describing software the user is
  not getting.
