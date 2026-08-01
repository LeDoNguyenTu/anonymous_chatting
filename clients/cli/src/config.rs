//! Where the client reads its settings from.
//!
//! Isolated so there is exactly one place that decides how a key reaches the
//! process. That matters more than it looks: the environment variable below is
//! development-grade and has to be replaced, and a single call site is a single
//! thing to replace.

use anyhow::{bail, Context, Result};
use pouch_core::transport::RelayConfig;

/// Path to the local encrypted database.
pub fn db_path() -> String {
    std::env::var("POUCH_DB").unwrap_or_else(|_| "pouch.db".to_string())
}

/// Which relay to talk to, and whether its key is pinned.
pub fn relay() -> RelayConfig {
    let url = std::env::var("POUCH_RELAY").unwrap_or_else(|_| "http://127.0.0.1:8443".to_string());
    match std::env::var("POUCH_RELAY_PIN") {
        Ok(pin) if !pin.is_empty() => RelayConfig::pinned(url, pin),
        _ => RelayConfig::insecure_local(url),
    }
}

/// Reads the database key.
///
/// Returned as an owned buffer because `Pouch` zeroizes it in place.
///
/// Three routes, in order:
///
/// 1. `POUCH_KEY`, a raw key. **Development-grade only** — an environment
///    variable is readable by other processes and lands in shell history. It
///    stays because the automated tests and the demo use it.
/// 2. Otherwise `keying::unlock`, which reads the sidecar beside the database
///    and decides. A passphrase-protected database takes `POUCH_PASSPHRASE`.
/// 3. A database with no sidecar gets the device-file placeholder, which is
///    what every Phase 1 database used and protects against nothing.
///
/// A passphrase-protected database with no passphrase supplied is an error, not
/// a fall back to the placeholder. Falling back would open a database the user
/// believes is protected.
pub fn db_key() -> Result<Vec<u8>> {
    if let Ok(hex_key) = std::env::var("POUCH_KEY") {
        let key = hex::decode(hex_key.trim()).context("POUCH_KEY must be valid hex")?;
        if key.len() != 32 {
            bail!(
                "POUCH_KEY must be 64 hex characters (32 bytes), not {}",
                key.len() * 2
            );
        }
        return Ok(key);
    }

    let passphrase = std::env::var("POUCH_PASSPHRASE").ok();
    pouch_core::keying::unlock(&db_path(), passphrase.as_deref())
        .context("could not obtain the database key")
}

/// The passphrase supplied for this invocation, if any.
pub fn passphrase() -> Option<String> {
    std::env::var("POUCH_PASSPHRASE").ok()
}
