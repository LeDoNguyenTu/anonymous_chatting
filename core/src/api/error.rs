//! What a client operation can fail with.

use crate::crypto::CryptoError;
use crate::storage::StorageError;
use crate::transport::TransportError;

/// Anything a client operation can fail with.
///
/// Every variant reaches the user as text explaining what happened and what to
/// do (SPEC §6.9). There is no "something went wrong".
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Local storage failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Talking to the relay failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The named contact is not known on this device.
    #[error("no contact with that identifier exists on this device")]
    UnknownContact,
    /// No conversation exists with that contact yet.
    #[error("no conversation with that contact exists yet")]
    UnknownConversation,
}
