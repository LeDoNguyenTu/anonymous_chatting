//! The OpenMLS provider Pouch uses.
//!
//! `openmls` takes its randomness, its primitives, and its storage through a
//! provider trait. This type pairs the audited `RustCrypto` implementation with
//! `MemoryStorage`, and adds the one thing the bundled provider does not
//! offer: the ability to be rebuilt from a stored snapshot.
//!
//! No primitive is implemented here. This is wiring.

use std::collections::HashMap;

use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

use super::CryptoError;

/// Crypto, randomness, and storage for one identity's MLS state.
///
/// `openmls_rust_crypto::OpenMlsRustCrypto` would serve for a process that
/// never restarts, but its storage is private and cannot be restored from a
/// snapshot, so a client built on it would lose every conversation on exit.
/// This type is the same two components with the storage reachable.
#[derive(Debug, Default)]
pub struct PouchProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for PouchProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl PouchProvider {
    /// A provider with empty storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Serializes the whole MLS state.
    ///
    /// The result is **key material** — it contains the group's secrets. It is
    /// written only into the SQLCipher database and is never logged, displayed,
    /// or exported (SPEC §2.5). Callers must treat it accordingly.
    pub fn snapshot(&self) -> Result<Vec<u8>, CryptoError> {
        let values = self
            .storage
            .values
            .read()
            .map_err(|_| CryptoError::StateSerialization)?;
        // Serialized as a list of pairs, not as a map. JSON object keys must
        // be strings, and MLS storage keys are arbitrary bytes — encoding them
        // as a map silently fails at runtime rather than at compile time.
        let pairs: Vec<(&Vec<u8>, &Vec<u8>)> = values.iter().collect();
        serde_json::to_vec(&pairs).map_err(|_| CryptoError::StateSerialization)
    }

    /// Rebuilds a provider from a snapshot produced by [`Self::snapshot`].
    pub fn restore(snapshot: &[u8]) -> Result<Self, CryptoError> {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> =
            serde_json::from_slice(snapshot).map_err(|_| CryptoError::StateSerialization)?;
        let map: HashMap<Vec<u8>, Vec<u8>> = pairs.into_iter().collect();
        let provider = Self::default();
        {
            let mut values = provider
                .storage
                .values
                .write()
                .map_err(|_| CryptoError::StateSerialization)?;
            *values = map;
        }
        Ok(provider)
    }
}
