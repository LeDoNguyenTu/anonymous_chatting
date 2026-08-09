# R8 / ProGuard rules for Pouch.
#
# This file was referenced by build.gradle.kts before it existed, which meant a
# release build failed the moment it got far enough to read it. It is now real,
# and the rules below are correct — but note that `isMinifyEnabled` is `false`,
# so nothing here is applied today. See the release block in build.gradle.kts
# for why. These rules exist so that turning minification on is a one-line
# change rather than a debugging session on a device nobody has.
#
# Everything below keeps something that is reached by *name at runtime*. R8
# cannot see any of these references, because none of them are Kotlin call
# sites — they are strings in Rust, symbol names in a .so, and reflection
# inside kotlinx.serialization. R8's whole model is "unreferenced means
# unused", and each of these is referenced somewhere R8 cannot look.

# --- The JNI boundary -------------------------------------------------------
#
# The Rust side exports exactly two symbols, and their names encode the Kotlin
# package and class:
#
#   Java_com_pouch_core_PouchNative_nativeStart
#   Java_com_pouch_core_PouchNative_nativeCall
#
# Renaming `PouchNative`, moving it out of `com.pouch.core`, or stripping either
# method leaves `System.loadLibrary` succeeding and the first native call dying
# with UnsatisfiedLinkError. That is a launch-time crash on every device, which
# is the failure mode `nativeLibsPresent` in build.gradle.kts exists to prevent
# for the other half of the same problem.
-keep,includedescriptorclasses class com.pouch.core.PouchNative {
    native <methods>;
}

# `lib.rs` throws through the JVM by looking this class up as the literal
# string "com/pouch/core/PouchException". A rename turns every core error into
# a bare RuntimeException carrying a message about a class that cannot be
# found — which is to say, it turns a readable failure into an unreadable one,
# exactly where SPEC §6.9 requires the opposite.
-keep class com.pouch.core.PouchException { <init>(...); }

# The general form of the rule, so a third native method added later is kept
# without anyone remembering this file.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# --- The view DTOs ----------------------------------------------------------
#
# Everything crossing the bridge is JSON, decoded by kotlinx.serialization into
# the types in Views.kt. The library resolves each generated `$$serializer`
# reflectively, so R8 sees the data classes as unconstructed and their fields
# as unread. Field *names* matter as much as class names here: they are the
# JSON keys the Rust side wrote, so a renamed field silently decodes to its
# default instead of failing.
-keep,includedescriptorclasses class com.pouch.core.**$$serializer { *; }
-keepclassmembers class com.pouch.core.** {
    *** Companion;
}
-keepclasseswithmembers class com.pouch.core.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Enum constants are matched by name during deserialization.
-keepclassmembers enum com.pouch.core.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# --- Noise ------------------------------------------------------------------
#
# arti and its dependency tree are Rust; nothing here touches them. These are
# the standard suppressions for optional desugaring targets that Kotlin's
# coroutines and serialization artifacts reference but never call on Android.
-dontwarn kotlinx.serialization.**
-dontwarn java.lang.invoke.**
