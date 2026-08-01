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
/// **Development-grade only.** An environment variable is readable by other
/// processes and lands in shell history. The desktop and Android clients take
/// this from the OS keystore or derive it from a passphrase with Argon2id
/// (D-007); Phase 2 brings the passphrase path here too.
pub fn db_key() -> Result<Vec<u8>> {
    let hex_key =
        std::env::var("POUCH_KEY").context("POUCH_KEY is not set; it must be 64 hex characters")?;
    let key = hex::decode(hex_key.trim()).context("POUCH_KEY must be valid hex")?;
    if key.len() != 32 {
        bail!(
            "POUCH_KEY must be 64 hex characters (32 bytes), not {}",
            key.len() * 2
        );
    }
    Ok(key)
}
