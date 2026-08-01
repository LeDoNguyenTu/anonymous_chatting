//! Contacts and the conversations attached to them.
//!
//! `verified` is the field to be careful with: it is false on insert and only
//! ever set true by an explicit user action after an out-of-band comparison.

use rusqlite::{params, OptionalExtension};

use super::{LocalStore, StorageError, StoredContact};

impl LocalStore {
    /// Adds a contact. New contacts are always unverified.
    pub fn put_contact(&self, contact: &StoredContact) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO contacts (id, display_name, inbox_id, public_key, verified)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                contact.id,
                contact.display_name,
                contact.inbox_id,
                contact.public_key,
                contact.verified as i64
            ],
        )?;
        Ok(())
    }

    /// Marks a contact verified, or removes that mark.
    ///
    /// Only ever called from an explicit user action after comparing a safety
    /// number out of band.
    pub fn set_verified(&self, contact_id: &str, verified: bool) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE contacts SET verified = ?1 WHERE id = ?2",
            params![verified as i64, contact_id],
        )?;
        Ok(())
    }

    /// Reads one contact.
    pub fn contact(&self, contact_id: &str) -> Result<Option<StoredContact>, StorageError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, display_name, inbox_id, public_key, verified
                 FROM contacts WHERE id = ?1",
                params![contact_id],
                |row| {
                    Ok(StoredContact {
                        id: row.get(0)?,
                        display_name: row.get(1)?,
                        inbox_id: row.get(2)?,
                        public_key: row.get(3)?,
                        verified: row.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .optional()?)
    }

    /// Every contact.
    pub fn contacts(&self) -> Result<Vec<StoredContact>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, display_name, inbox_id, public_key, verified
             FROM contacts ORDER BY display_name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredContact {
                id: row.get(0)?,
                display_name: row.get(1)?,
                inbox_id: row.get(2)?,
                public_key: row.get(3)?,
                verified: row.get::<_, i64>(4)? != 0,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Records a conversation against a contact.
    pub fn put_conversation(
        &self,
        conversation_id: &str,
        contact_id: &str,
    ) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO conversations (id, contact_id) VALUES (?1, ?2)",
            params![conversation_id, contact_id],
        )?;
        Ok(())
    }

    /// Every conversation with a contact.
    pub fn conversations_for(&self, contact_id: &str) -> Result<Vec<String>, StorageError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM conversations WHERE contact_id = ?1 ORDER BY id")?;
        let rows = stmt.query_map(params![contact_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// The contact a conversation belongs to.
    pub fn conversation_contact(
        &self,
        conversation_id: &str,
    ) -> Result<Option<String>, StorageError> {
        Ok(self
            .conn
            .query_row(
                "SELECT contact_id FROM conversations WHERE id = ?1",
                params![conversation_id],
                |r| r.get(0),
            )
            .optional()?)
    }
}
