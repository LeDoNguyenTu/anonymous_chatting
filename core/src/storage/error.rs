//! What local storage can fail with.

/// Anything that can go wrong reading or writing local state.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The database could not be opened or a statement failed.
    #[error("could not open the local database")]
    Database(#[from] rusqlite::Error),
    /// The supplied key did not open the database.
    ///
    /// Distinguished from a generic failure because it is the one the user can
    /// act on: it means a wrong passphrase, not a corrupt file.
    #[error("this passphrase does not open the database")]
    WrongKey,
    /// No identity has been created yet.
    #[error("no identity exists on this device yet")]
    NoIdentity,
    /// The build is not linked against SQLCipher.
    ///
    /// A hard failure, never a warning. SQLite silently ignores pragmas it does
    /// not recognise, so on a plain-SQLite build `PRAGMA key` succeeds, returns
    /// no error, and encrypts nothing — leaving an application that believes
    /// its database is protected sitting on a plaintext file.
    #[error(
        "this build is not linked against SQLCipher; the local database would not be encrypted"
    )]
    SqlCipherMissing,
}
