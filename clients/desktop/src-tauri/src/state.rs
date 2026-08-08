//! The one `Pouch` this process owns.
//!
//! Held behind an async mutex because commands are async and a std mutex guard
//! cannot be held across an await point.

use std::path::{Path, PathBuf};

use pouch_core::transport::{RelayConfig, TorRelayConfig};
use pouch_core::Pouch;
use tokio::sync::Mutex;

/// Everything the window needs, and nothing more.
#[derive(Default)]
pub struct AppState {
    inner: Mutex<Option<Pouch>>,
}

impl AppState {
    /// Runs `f` against the open client, or returns a message saying no
    /// identity is open yet.
    ///
    /// Every command goes through this rather than reaching for the field, so
    /// there is exactly one place that decides what "not unlocked" means.
    pub async fn with<T, F>(&self, f: F) -> Result<T, String>
    where
        F: FnOnce(&mut Pouch) -> Result<T, String>,
    {
        let mut guard = self.inner.lock().await;
        match guard.as_mut() {
            Some(pouch) => f(pouch),
            None => Err("No identity is open on this device yet.".to_string()),
        }
    }

    /// Same, for commands that need to await inside.
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, Option<Pouch>> {
        self.inner.lock().await
    }

    /// Installs a freshly created or opened client.
    pub async fn set(&self, pouch: Pouch) {
        *self.inner.lock().await = Some(pouch);
    }

    /// Whether an identity is currently open.
    pub async fn is_open(&self) -> bool {
        self.inner.lock().await.is_some()
    }
}

/// Where the local database lives.
///
/// One file per identity, under the OS application-data directory. Not
/// configurable from the UI: a database path is not a user preference, and a
/// UI that can point the client at an arbitrary file is a UI that can be talked
/// into pointing it somewhere unencrypted.
pub fn database_path(app_data_dir: PathBuf) -> PathBuf {
    app_data_dir.join("pouch.db")
}

/// The relay this build talks to.
///
/// Loopback and unpinned for now, which `RelayClient::new` only tolerates
/// because it is loopback (D-017). Phase 4 replaces this with an onion address.
pub fn relay_config() -> RelayConfig {
    RelayConfig::insecure_local("http://127.0.0.1:8443")
}

/// Where this device's Tor state persists across runs.
///
/// A sibling of the database, not a directory inside it. What Tor keeps here
/// — guard relays, a consensus cache, circuit state — is not message content,
/// so it does not belong under `SQLCipher`; and keeping it separate means
/// wiping the database does not also throw away a working bootstrap and force
/// a slow cold start.
pub fn tor_state_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("tor-state")
}

/// The Tor target this build talks to, if one is configured.
///
/// Deployment configuration, not a user preference — the same reasoning
/// [`relay_config`] already applies to the direct address. The Transport
/// screen lets someone choose *whether* to use Tor, not *which* onion service
/// to trust: a UI that can be pointed at an arbitrary address is a UI that can
/// be talked into pointing at someone else's relay. If entering an address
/// ever becomes a feature it should be designed deliberately rather than
/// arriving as a side effect of this one.
///
/// Which variables name that target is the core's to define, so this cannot
/// drift from the CLI. Only the fallback state directory is this client's
/// business, because only this client knows where its app data lives.
pub fn tor_config(app_data_dir: &Path) -> Option<TorRelayConfig> {
    TorRelayConfig::from_env(&tor_state_dir(app_data_dir).to_string_lossy())
}
