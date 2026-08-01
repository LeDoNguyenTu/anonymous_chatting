//! The only surface clients touch.
//!
//! This is a hard boundary, not a convention (D-012). The desktop, Android, and
//! CLI clients call the operations here and nothing beneath them. No key, no
//! cipher, no nonce, and no raw ciphertext blob crosses this line.
//!
//! If a client appears to need something lower level, the correct response is to
//! add an operation here — never to expose the module underneath.

mod contacts;
mod error;
mod messaging;
mod payload;
mod storage_controls;
mod types;

pub use error::ApiError;
pub(crate) use payload::Payload;
pub use types::{
    ConversationSummary, IdentityChangeNotice, IdentityState, Message, Received, SecurityDetails,
};

/// Re-exported so a client can offer the retention choices without reaching
/// past this module into storage.
pub use crate::storage::RetentionPolicy;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use crate::crypto::{
    Conversation, CryptoError, Identity, PouchProvider, AEAD_NAME, CIPHERSUITE_NAME, KDF_NAME,
    KEY_AGREEMENT_NAME, PROTOCOL_NAME, SIGNATURE_NAME,
};
use crate::storage::LocalStore;
use crate::transport::{RelayClient, RelayConfig, Route};

/// A running Pouch client.
///
/// Owns the identity, the MLS state, the local database, and the relay
/// connection. Clients hold one of these and call methods on it.
pub struct Pouch {
    identity: Identity,
    provider: PouchProvider,
    store: LocalStore,
    relay: RelayClient,
    /// Where the database lives.
    ///
    /// Kept because changing how the database is protected has to update the
    /// keying sidecar beside it, and the alternative is making every client
    /// pass the path back in on a call that has nothing else to do with it.
    db_path: String,
    /// Live conversations, keyed by conversation id.
    ///
    /// Rebuilt from the MLS snapshot on open. Held in memory because an
    /// `MlsGroup` is a state machine, not a record.
    conversations: HashMap<String, Conversation>,
}

impl Pouch {
    /// Creates a new identity and the database that holds it.
    ///
    /// `db_key` is zeroized before this returns.
    pub fn create(
        display_name: &str,
        db_path: &str,
        db_key: &mut [u8],
        relay: RelayConfig,
    ) -> Result<Self, ApiError> {
        let store = LocalStore::open(db_path, db_key)?;
        let provider = PouchProvider::new();
        let identity = Identity::create(display_name, &provider)?;

        // The public half and the local metadata go in the identity row. The
        // private half was written into the MLS storage provider by
        // `Identity::create` and is captured by the snapshot below, so it lives
        // in exactly one place rather than two (D-025).
        store.put_identity(
            identity.display_name(),
            identity.inbox_id(),
            identity.public_key(),
        )?;
        store.put_mls_state(&provider.snapshot()?)?;

        Ok(Self {
            identity,
            provider,
            store,
            relay: RelayClient::new(relay)?,
            conversations: HashMap::new(),
            db_path: db_path.to_string(),
        })
    }

    /// Opens an existing identity.
    ///
    /// `db_key` is zeroized before this returns.
    pub fn open(db_path: &str, db_key: &mut [u8], relay: RelayConfig) -> Result<Self, ApiError> {
        let store = LocalStore::open(db_path, db_key)?;
        let (display_name, inbox_id, public) = store.identity()?;

        let provider = match store.mls_state()? {
            Some(snapshot) => PouchProvider::restore(&snapshot)?,
            None => PouchProvider::new(),
        };

        // The signer comes back out of the MLS storage provider, where the
        // library put it. Reading it through the library's own accessor rather
        // than reconstructing it from separately stored bytes means there is no
        // second copy of the private key to keep in sync or fail to zeroize.
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &public,
            crate::crypto::CIPHERSUITE.signature_algorithm(),
        )
        .ok_or(ApiError::Crypto(CryptoError::IdentityCreation))?;

        let identity = Identity::restore(display_name, inbox_id, signer)?;

        let mut pouch = Self {
            identity,
            provider,
            store,
            relay: RelayClient::new(relay)?,
            conversations: HashMap::new(),
            db_path: db_path.to_string(),
        };
        pouch.reload_conversations()?;

        // Retention is applied on open, not only when the setting changes. A
        // device that was switched off for a month under a 7-day policy must
        // not come back holding a month of messages.
        pouch.store.purge_expired(now())?;

        Ok(pouch)
    }

    /// Rebuilds the in-memory conversation map from the MLS state.
    ///
    /// The protocol state persists in the snapshot, but an `MlsGroup` is a
    /// state machine that has to be reconstituted. Without this a client that
    /// restarts finds every conversation gone despite the keys still being
    /// there — which is what the first end-to-end run did.
    fn reload_conversations(&mut self) -> Result<(), ApiError> {
        for contact in self.store.contacts()? {
            for conversation_id in self.store.conversations_for(&contact.id)? {
                if let Some(conversation) = Conversation::load(
                    &conversation_id,
                    &contact.inbox_id,
                    &contact.public_key,
                    &self.provider,
                )? {
                    self.conversations.insert(conversation_id, conversation);
                }
            }
        }
        Ok(())
    }

    /// Whether a device already holds an identity, without unlocking anything
    /// else. Drives whether the client shows first run or the conversation list.
    pub fn exists(db_path: &str, db_key: &mut [u8]) -> Result<bool, ApiError> {
        let store = LocalStore::open(db_path, db_key)?;
        Ok(store.has_identity()?)
    }

    /// The local-only display name.
    pub fn display_name(&self) -> &str {
        self.identity.display_name()
    }

    /// This identity's opaque inbox address.
    pub fn inbox_id(&self) -> &str {
        self.identity.inbox_id()
    }

    /// Whether the relay is answering. Drives the Custody Strip's transport
    /// field between `DIRECT` and `OFFLINE`.
    /// Takes `&mut self` rather than `&self` deliberately.
    ///
    /// A future holding `&Pouch` across an await is `Send` only if
    /// `Pouch: Sync`, and it is not — `rusqlite::Connection` is `Send` but not
    /// `Sync`. The desktop shell needs every command future to be `Send`, so
    /// an async method that borrows shared would compile here and fail only in
    /// the one CI job that can build Tauri. `&mut Pouch` is `Send` because
    /// `Pouch` is.
    pub async fn transport_state(&mut self) -> Route {
        if self.relay.reachable().await {
            Route::Direct
        } else {
            Route::Offline
        }
    }

    /// Every mechanism in use, for the Security details screen.
    pub fn security_details(&self) -> SecurityDetails {
        SecurityDetails {
            ciphersuite: CIPHERSUITE_NAME,
            aead: AEAD_NAME,
            key_agreement: KEY_AGREEMENT_NAME,
            signature: SIGNATURE_NAME,
            kdf: KDF_NAME,
            protocol: PROTOCOL_NAME,
            local_database: "SQLCipher (AES-256)",
            passphrase_derivation: "Argon2id",
            transport: "TLS 1.3, relay certificate pinned by SPKI hash",
            relay_address: self.relay.address().to_string(),
            openmls_version: "0.8.1",
            app_version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Destroys everything on this device.
    ///
    /// Irreversible, and the UI must confirm proportionally (SPEC §6.7.11).
    pub fn wipe_all(&mut self) -> Result<(), ApiError> {
        self.conversations.clear();
        self.store.wipe()?;
        Ok(())
    }

    /// Writes the MLS state back to the encrypted database.
    ///
    /// Called after every operation that advances the protocol. Missing one
    /// means a ratchet step is lost on restart and the conversation breaks.
    fn persist_mls_state(&self) -> Result<(), ApiError> {
        self.store.put_mls_state(&self.provider.snapshot()?)?;
        Ok(())
    }
}

/// Seconds since the Unix epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Re-exported so clients can render a manifest without reaching into a module.
pub use crate::manifest::{Stage, StageOutcome};

#[cfg(test)]
mod thread_safety {
    use super::Pouch;

    /// The desktop shell keeps one `Pouch` in Tauri-managed state behind a
    /// mutex, which requires `Send`. That crate needs GTK to compile and so
    /// cannot be built on a headless machine — this assertion checks the
    /// assumption here, where it builds everywhere, instead of discovering it
    /// in CI twenty minutes later.
    #[test]
    fn pouch_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Pouch>();
    }

    /// Every async operation must produce a `Send` future.
    ///
    /// Tauri requires it of every command, and the failure mode is nasty: an
    /// async method taking `&self` compiles perfectly in this crate and fails
    /// only in the GTK-dependent job, because `&Pouch` is `Send` only if
    /// `Pouch: Sync` — which it is not, since `rusqlite::Connection` is not
    /// `Sync`. Asserting it here turns a twenty-minute CI round trip into a
    /// compile error.
    ///
    /// If this stops compiling, an async method has started borrowing shared.
    /// Change it to `&mut self`.
    #[test]
    fn async_operations_produce_send_futures() {
        fn assert_send_future<F: std::future::Future + Send>(_: F) {}

        // Never executed — the assertion is that this type-checks. Verified
        // to actually catch a regression: changing `transport_state` back to
        // `&self` makes this fail with "has type `&Pouch` which is not `Send`,
        // because `Pouch` is not `Sync`".
        #[allow(dead_code, unreachable_code, clippy::diverging_sub_expression)]
        fn check(pouch: &mut Pouch) {
            assert_send_future(pouch.transport_state());
            assert_send_future(pouch.receive_messages());
            assert_send_future(pouch.send_message("", ""));
            assert_send_future(pouch.add_contact("", ""));
        }
    }
}
