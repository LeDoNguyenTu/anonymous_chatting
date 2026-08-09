//! Where the client reads its settings from.
//!
//! Isolated so there is exactly one place that decides how a key reaches the
//! process. That matters more than it looks: the environment variable below is
//! development-grade and has to be replaced, and a single call site is a single
//! thing to replace.

use anyhow::{bail, Context, Result};
use pouch_core::transport::{RelayConfig, TorRelayConfig};
use pouch_core::Pouch;

/// Path to the local encrypted database.
pub fn db_path() -> String {
    std::env::var("POUCH_DB").unwrap_or_else(|_| "pouch.db".to_string())
}

/// Which relay to talk to, and whether its key is pinned.
///
/// The variables and their meaning are [`RelayConfig::from_env`]'s to define,
/// not this client's. This used to be a hand-written copy here, and the desktop
/// client had the address compiled in — so `POUCH_RELAY` worked on the CLI and
/// was silently ignored by the window. One reader means that cannot recur.
pub fn relay() -> RelayConfig {
    RelayConfig::from_env("http://127.0.0.1:8443")
}

/// Where this client keeps Tor's state when `POUCH_TOR_STATE_DIR` is unset.
///
/// The working directory, matching how `POUCH_DB` defaults — a headless
/// client run from a directory should keep what it accumulates there, where
/// the operator can see and delete it.
const DEFAULT_TOR_STATE_DIR: &str = "pouch-tor-state";

/// Opens the database for a command that is going to reach the relay, routing
/// through Tor if one is configured.
///
/// One place, not four. Every command that talks to the relay — `add`,
/// `send`, `send-file`, `receive` — opens through here, so a configured Tor
/// target cannot apply to some of them and quietly not to others. Wiring only
/// the obvious two would mean a user who set `POUCH_RELAY_TOR_ONION` still
/// handed their IP address to the relay while adding a contact, holding a
/// protection they believed in and did not have. A fifth network command
/// added later gets Tor by construction rather than by remembering.
///
/// Which environment variables name a Tor target is
/// [`TorRelayConfig::from_env`]'s to define, not this client's — see there
/// for why that lives in the core.
///
/// Slow when Tor is configured: bootstrapping a circuit is real network I/O,
/// seconds to tens of seconds against a cold state directory. Commands that
/// only read local state call [`Pouch::open`] directly and stay instant.
///
/// A Tor connection that fails is an error, never a quiet fall back to the
/// direct route — `Pouch::connect_tor` leaves the existing connection alone
/// on failure, and the `?` here means the command stops rather than sending
/// over a route the user did not choose.
pub async fn open_for_relay() -> Result<Pouch> {
    let mut key = db_key()?;
    let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;
    if let Some(tor) = TorRelayConfig::from_env(DEFAULT_TOR_STATE_DIR) {
        pouch.connect_tor(tor).await?;
    }
    Ok(pouch)
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
