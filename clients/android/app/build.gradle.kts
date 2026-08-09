// Pouch for Android.
//
// The Rust core is not built by Gradle. `clients/android/jni` cross-compiles
// with cargo-ndk in CI and the resulting .so files are placed under
// `src/main/jniLibs/<abi>/`. Keeping the two build systems separate means a
// Kotlin change does not trigger a fifteen-minute Rust rebuild, and the CI job
// that proves the ABIs link stays readable.
//
// The consequence, stated because it is a real one: a developer who edits the
// Rust and forgets to re-run cargo-ndk builds an APK against a stale library.
// `nativeLibsPresent` below fails the build rather than letting that ship.

import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.pouch"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.pouch"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "0.1.7"

        // The four ABIs the CI job cross-compiles. Named explicitly so a fifth
        // cannot appear in a release APK without a library behind it.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }

        // The relay this build *falls back* to, not the one it is locked to.
        //
        // On desktop the relay address comes from the environment and nothing
        // the UI can write reaches it (D-049). Android has no per-app
        // environment, so that boundary would leave only one way to point a
        // phone at a relay: rebuild the APK per relay. D-051 records why that
        // is worse rather than safer — it pushes people toward installing a
        // stranger's pre-configured build, which hands over the address *and*
        // the binary. The app therefore asks for the address on first run and
        // stores it in its own private preferences.
        //
        // This value is what a fresh install shows in that field before the
        // user changes it. 10.0.2.2:8443 is the emulator's route to the host
        // machine's loopback, which is where a development relay runs; on a
        // handset it is unreachable and everything queues, which is why the
        // first-run screen cannot be skipped.
        //
        // Overridable at build time for a deployment with a known relay:
        //
        //   gradle :app:assembleRelease -PpouchRelayUrl=https://relay.example:8443
        val relayUrl = (findProperty("pouchRelayUrl") as String?)
            ?: "http://10.0.2.2:8443"
        buildConfigField("String", "RELAY_URL", "\"$relayUrl\"")
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // Signing.
    //
    // A release keystore is the project owner's to hold, so none is committed
    // and none is generated in CI. What *is* here is the wiring, so signing is
    // one properties file away rather than a research task.
    //
    // Set these in `clients/android/keystore.properties` (gitignored) to sign
    // locally:
    //
    //   storeFile=/absolute/path/pouch-release.jks
    //   storePassword=...
    //   keyAlias=pouch
    //   keyPassword=...
    //
    // Generate one with:
    //   keytool -genkeypair -v -keystore pouch-release.jks -alias pouch \
    //           -keyalg RSA -keysize 4096 -validity 10000
    //
    // Losing this file means Play will not accept another update of this app,
    // ever. Back it up somewhere you would not lose a passport.
    //
    // In CI the same four values arrive as environment variables from repository
    // secrets, so a tagged release can produce a signed artifact without a
    // keystore ever being committed. Absent both, the release build is unsigned
    // and says so.
    //
    // `Properties` is imported at the top of this file rather than written as
    // `java.util.Properties` here: inside an `android { }` block the bare name
    // `java` resolves to the Java plugin extension, not the JDK package, so the
    // fully-qualified form is a compile error that reads like a working line.
    val keystoreProperties = Properties().apply {
        val file = rootProject.file("keystore.properties")
        if (file.exists()) file.inputStream().use { this.load(it) }
    }

    // The properties file wins over the environment. A developer who has both
    // is working locally, and a local keystore is the one they meant.
    //
    // Blank counts as absent, not as present-and-empty. That distinction is the
    // whole reason this reads as a function rather than four `?:` chains: the
    // release workflow passes POUCH_KEYSTORE_FILE as an *empty string* when the
    // repository has no signing secrets, so `System.getenv` returned "" rather
    // than null, the null check below passed, and `file("")` threw
    // `path may not be null or empty string` while Gradle was still configuring
    // — before a single task ran.
    //
    // Worth stating plainly, because it is the same shape as the OpenSSL
    // failure in the Windows job: the unsigned path is the one every build
    // without a keystore takes, and it was the only path never exercised
    // locally, because a developer machine leaves the variable unset rather
    // than setting it to nothing.
    fun signingSetting(propertyName: String, envName: String): String? =
        (keystoreProperties.getProperty(propertyName) ?: System.getenv(envName))
            ?.takeIf { it.isNotBlank() }

    // Resolved to a File once, here, rather than re-derived inside the signing
    // config. Both the missing-value case and the missing-file case collapse to
    // null, so there is exactly one thing for the block below to test.
    val storePath = signingSetting("storeFile", "POUCH_KEYSTORE_FILE")
    val keystoreFile = storePath?.let { file(it) }?.takeIf { it.exists() }

    // Said out loud at configuration time. An unsigned APK cannot be installed,
    // and learning that from `adb install` is worse than reading it in the build
    // log. `println` rather than `logger`, because inside `android { }` the
    // receiver chain is the extension before the project, and this file has
    // already been bitten once by a bare name resolving to the wrong scope.
    if (keystoreFile == null) {
        println(
            if (storePath == null) {
                "Pouch: no release keystore configured. assembleRelease will " +
                    "produce an unsigned APK, which cannot be installed."
            } else {
                "Pouch: no keystore at $storePath. assembleRelease will " +
                    "produce an unsigned APK, which cannot be installed."
            },
        )
    }

    signingConfigs {
        if (keystoreFile != null) {
            create("release") {
                storeFile = keystoreFile
                storePassword = signingSetting("storePassword", "POUCH_KEYSTORE_PASSWORD")
                keyAlias = signingSetting("keyAlias", "POUCH_KEY_ALIAS")
                keyPassword = signingSetting("keyPassword", "POUCH_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            // Suffixed so a debug build installs alongside a release one rather
            // than one silently replacing the other — and so a sideloaded test
            // build cannot be mistaken for the real thing.
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            // Off, deliberately, and this is a reversal — it was `true`, which
            // is the template default and was never argued for.
            //
            // Three reasons, in order of weight:
            //
            // 1. Obfuscating this app protects nothing. The source is public.
            //    Renaming `PouchNative` to `a` in a build whose code anyone can
            //    read is the definition of security theatre, which SPEC §2.5
            //    forbids — and it costs something real, because a stack trace
            //    from a stranger's crash becomes unreadable without a mapping
            //    file that nothing here collects.
            //
            // 2. The size win is a rounding error. This APK is ~37 MB of native
            //    library per ABI, none of which R8 touches. Shrinking Kotlin and
            //    Compose bytecode off that saves single-digit megabytes.
            //
            // 3. Every way R8 can break this app breaks it at runtime, on a
            //    build that has never launched anywhere. The Rust side reaches
            //    back for `com.pouch.core.PouchNative` and `PouchException` by
            //    name, and 25 DTOs are decoded by field name; a wrong keep rule
            //    surfaces as UnsatisfiedLinkError or a field that silently
            //    decodes to its default. Prime Directive 4 — ship narrow and
            //    working.
            //
            // `proguard-rules.pro` is written and correct regardless, so this is
            // one line to reverse once the app has run on a device and there is
            // a reason to want it.
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Signed only when keystore.properties exists. Without it this
            // produces an unsigned APK, which is correct: it cannot be
            // installed, and that is better than being signed by a key that
            // was generated somewhere it should not have been.
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.material3)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
}

/**
 * Fails the build when an ABI has no native library behind it.
 *
 * Without this, a missing .so produces an APK that installs happily and then
 * throws UnsatisfiedLinkError on first launch — on exactly the devices whose
 * ABI nobody tested. This is the D-024 pattern: check that the thing did what
 * it was configured to do, rather than assuming an error would have surfaced.
 *
 * Debug builds warn instead of failing, so that someone working on Kotlin
 * alone is not forced to install the NDK first.
 */
val nativeLibsPresent by tasks.registering {
    val abis = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
    val jniLibs = layout.projectDirectory.dir("src/main/jniLibs")
    doLast {
        val missing = abis.filterNot {
            jniLibs.file("$it/libpouch_jni.so").asFile.exists()
        }
        if (missing.isNotEmpty()) {
            error(
                "No libpouch_jni.so for: ${missing.joinToString()}.\n" +
                    "Build it first:\n" +
                    "  cd clients/android/jni && cargo ndk -t arm64-v8a -t armeabi-v7a " +
                    "-t x86_64 -t x86 -o ../app/src/main/jniLibs build --release",
            )
        }
    }
}

// bundleRelease as well as assembleRelease. The AAB is what goes to Play, and
// it is the artifact where a missing ABI is least visible — Play splits the
// bundle per device, so an absent arm64 library would produce installs that
// crash on launch for most of the world while the x86 emulator here looked fine.
tasks.matching { it.name == "assembleRelease" || it.name == "bundleRelease" }
    .configureEach {
        dependsOn(nativeLibsPresent)
    }
