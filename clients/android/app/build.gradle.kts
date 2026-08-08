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
        versionName = "0.1.4"

        // The four ABIs the CI job cross-compiles. Named explicitly so a fifth
        // cannot appear in a release APK without a library behind it.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }

        // Where the relay lives for a debug build. 10.0.2.2 is the emulator's
        // route to the host machine's loopback, which is where the development
        // relay runs. Not a user preference: a client that can be pointed at an
        // arbitrary address is a client that can be talked into pointing at
        // someone else's relay (the same reasoning state.rs applies on desktop).
        buildConfigField("String", "RELAY_URL", "\"http://10.0.2.2:8443\"")
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Deliberately unsigned here. A release keystore is the project
            // owner's to hold, and committing signing config — or generating a
            // key in CI — would put the app's identity somewhere it does not
            // belong. `assembleRelease` produces an unsigned APK; signing is a
            // separate, manual step.
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

tasks.matching { it.name == "assembleRelease" }.configureEach {
    dependsOn(nativeLibsPresent)
}
