//! The Pouch Android bridge.
//!
//! Kotlin loads this as a shared library and reaches `pouch-core` through it.
//! The whole JNI surface is two entry points: one to start a session, one to
//! run a named operation. Everything else lives in [`session`], which has no
//! JNI types in it and therefore runs under `cargo test` on any machine.
//!
//! **That split is the point.** No Android SDK, NDK, emulator, or JVM was
//! available while this was written, so the code that could not be executed
//! was made as small as it could be: the marshalling below, and nothing else.
//! The decisions — which operations exist, what they return, what happens when
//! no identity is open — are all in `session.rs`, under test.
//!
//! ## What crosses
//!
//! Operation names and JSON. No key, no cipher, no storage handle, no raw
//! ciphertext blob (D-012). The one place key material crosses is
//! `export_backup`, which hands the user their own recovery key because SPEC
//! §7.3 puts it in their hands and nowhere else.
//!
//! ## Threads
//!
//! Every operation blocks. Kotlin must call from a background dispatcher, and
//! the facade in `PouchNative.kt` is written so that it cannot do otherwise.
//! A Tor bootstrap takes seconds to tens of seconds; on the main thread that
//! is an ANR.

#![deny(missing_docs)]

pub mod session;

use std::panic::AssertUnwindSafe;
use std::sync::OnceLock;

use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use tokio::runtime::Runtime;

use session::{BridgeError, Session, SessionConfig};

/// The exception Kotlin catches. Defined in the Android source set.
///
/// Falls back to `RuntimeException` if the class cannot be found, because a
/// failure to *report* a failure is the worst outcome available here: the
/// alternative is a call that returns a null the Kotlin side reads as success.
const EXCEPTION_CLASS: &str = "com/pouch/core/PouchException";

/// The process-wide session, and the runtime its async work runs on.
///
/// One per process, like the desktop client's `AppState`: this app opens one
/// identity against one database. A handle-per-session design would hand
/// Kotlin a pointer it could outlive, which is a use-after-free waiting for a
/// configuration change to trigger it.
struct Bridge {
    runtime: Runtime,
    session: Session,
}

static BRIDGE: OnceLock<Bridge> = OnceLock::new();

/// Starts the bridge. Idempotent; a second call with different paths is
/// ignored rather than silently repointing the app at another database.
///
/// # Errors
///
/// Throws if the paths are unreadable or the runtime cannot be built.
// Exported by name so the JVM can find it. `#[no_mangle]` is unsafe only in
// the link-time sense — two libraries exporting one symbol — and this name is
// namespaced by the JNI convention to a class only this project defines.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_com_pouch_core_PouchNative_nativeStart<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    db_path: JString<'local>,
    tor_state_dir: JString<'local>,
    relay_url: JString<'local>,
) {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let db_path = read_string(&mut env, &db_path)?;
        let tor_state_dir = read_string(&mut env, &tor_state_dir)?;
        let relay_url = read_string(&mut env, &relay_url)?;

        if BRIDGE.get().is_some() {
            return Ok(());
        }

        let runtime = Runtime::new().map_err(|e| {
            BridgeError::Core(format!("The background runtime could not be started: {e}"))
        })?;

        let session = Session::new(SessionConfig {
            db_path,
            tor_state_dir,
            relay_url,
        });

        // `set` failing means another thread won the race, which is the same
        // outcome as the early return above.
        let _ = BRIDGE.set(Bridge { runtime, session });

        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("pouch"),
        );

        Ok(())
    }));

    if let Err(e) = flatten(result) {
        throw(&mut env, &e.to_string());
    }
}

/// Runs one named operation and returns its result as a JSON string.
///
/// # Errors
///
/// Throws [`EXCEPTION_CLASS`] carrying the core's own message, which SPEC §6.9
/// requires to say what happened and what to do. Kotlin shows that text rather
/// than inventing its own.
// Exported by name so the JVM can find it. `#[no_mangle]` is unsafe only in
// the link-time sense — two libraries exporting one symbol — and this name is
// namespaced by the JNI convention to a class only this project defines.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_com_pouch_core_PouchNative_nativeCall<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    operation: JString<'local>,
    args_json: JString<'local>,
) -> jstring {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let operation = read_string(&mut env, &operation)?;
        let args_json = read_string(&mut env, &args_json)?;

        let bridge = BRIDGE.get().ok_or_else(|| {
            BridgeError::Core(
                "The Pouch bridge has not been started on this device yet.".to_string(),
            )
        })?;

        let args: serde_json::Value = if args_json.trim().is_empty() {
            serde_json::Value::Object(Default::default())
        } else {
            serde_json::from_str(&args_json).map_err(|e| BridgeError::BadArguments {
                operation: operation.clone(),
                detail: e.to_string(),
            })?
        };

        let value = bridge
            .runtime
            .block_on(bridge.session.dispatch(&operation, args))?;

        serde_json::to_string(&value).map_err(|_| BridgeError::Encoding(operation))
    }));

    match flatten(result) {
        Ok(json) => match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                throw(&mut env, "The result could not be returned to the app.");
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            throw(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Reads a Java string, or reports why it could not be read.
fn read_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Result<String, BridgeError> {
    env.get_string(value)
        .map(|s| s.into())
        .map_err(|e| BridgeError::Core(format!("A value could not be read from the app: {e}")))
}

/// Collapses a caught panic into the same error channel everything else uses.
///
/// A panic that unwinds across the FFI boundary is undefined behaviour, so it
/// is caught here and turned into an exception. The message is deliberately
/// generic: a panic payload can carry anything a `panic!` was given, and this
/// crate should not be the reason a stray string reaches logcat.
fn flatten<T>(result: std::thread::Result<Result<T, BridgeError>>) -> Result<T, BridgeError> {
    match result {
        Ok(inner) => inner,
        Err(_) => Err(BridgeError::Core(
            "Something went wrong inside Pouch and the operation was stopped.".to_string(),
        )),
    }
}

/// Throws an exception Kotlin can catch.
///
/// If the project's own exception class is missing — a packaging error rather
/// than anything a user did — this falls back to `RuntimeException` so the
/// failure still surfaces instead of the call appearing to succeed.
fn throw(env: &mut JNIEnv<'_>, message: &str) {
    if env.throw_new(EXCEPTION_CLASS, message).is_ok() {
        return;
    }
    // Clear the ClassNotFoundException the failed lookup left pending, or the
    // next JNI call on this thread fails for the wrong reason.
    let _ = env.exception_clear();
    let _ = env.throw_new("java/lang/RuntimeException", message);
}
