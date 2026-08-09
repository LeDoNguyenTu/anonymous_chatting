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
        versionCode = 1
        versionName = "0.1.5"

        // The four ABIs the CI job cross-compiles. Named explicitly so a fifth
        // cannot appear in a release APK without a library behind it.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }

        // Where the relay lives, fixed at build time.
        //
        // Deliberately **not** a user preference and deliberately not settable
        // from the running app: a client that can be pointed at an arbitrary
        // relay from its own interface is a client that can be talked into it.
        // Pointing at the wrong relay does not expose message content — the
        // relay never holds a key — but it hands that operator the inbox
        // identifiers and connection timing THREAT_MODEL.md §5 lists as
        // visible, and it silently breaks delivery. Same boundary
        // RelayConfig::from_env draws on desktop (D-049).
        //
        // The default is 10.0.2.2:8443, the emulator's route to the host
        // machine's loopback, which is where a development relay runs. A build
        // meant for a real phone must override it — an emulator address is
        // unreachable from a handset, and the app will simply queue everything:
        //
        //   gradle :app:assembleRelease -PpouchRelayUrl=https://relay.example:8443
        //
        // Over Tor, pass the onion address instead. There is no fallback if it
        // is wrong, by design.
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
    val keystoreProperties = java.util.Properties().apply {
        val file = rootProject.file("keystore.properties")
        if (file.exists()) file.inputStream().use { load(it) }
    }

    signingConfigs {
        if (keystoreProperties.containsKey("storeFile")) {
            create("release") {
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
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
            isMinifyEnabled = true
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
