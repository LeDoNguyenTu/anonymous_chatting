//! The device identity row, and the MLS state blob beside it.
//!
//! One row each, both singletons. The private key is *not* here — it lives
//! inside the MLS state snapshot, so it exists in exactly one place in this
//! file rather than two (D-025).

use rusqlite::{params, OptionalExtension};

use super::{LocalStore, StorageError};

impl LocalStore {
    /// Stores the identity. Called once, at first run.
    pub fn put_identity(
        &self,
        display_name: &str,
        inbox_id: &str,
        signer_public: &[u8],
    ) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO identity (id, display_name, inbox_id, signer_public)
             VALUES (1, ?1, ?2, ?3)",
            params![display_name, inbox_id, signer_public],
        )?;
        Ok(())
    }

    /// Reads the identity back.
    ///
    /// Returns the display name, the inbox address, and the *public* key. The
    /// private half is recovered from the MLS state snapshot by the caller,
    /// which is where the library put it.
    pub fn identity(&self) -> Result<(String, String, Vec<u8>), StorageError> {
        self.conn
            .query_row(
                "SELECT display_name, inbox_id, signer_public FROM identity WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(StorageError::NoIdentity)
    }

    /// Whether an identity has been created on this device.
    pub fn has_identity(&self) -> Result<bool, StorageError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM identity", [], |r| r.get(0))?;
        Ok(n > 0)
    }

    /// Saves the MLS state snapshot.
    ///
    /// This blob is key material. It goes here and nowhere else — never to a
    /// log, never to an export, never to the relay (D-023).
    pub fn put_mls_state(&self, snapshot: &[u8]) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO mls_state (id, snapshot) VALUES (1, ?1)",
            params![snapshot],
        )?;
        Ok(())
    }

    /// Reads the MLS state snapshot, if one has been saved.
    pub fn mls_state(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT snapshot FROM mls_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?)
    }
}
