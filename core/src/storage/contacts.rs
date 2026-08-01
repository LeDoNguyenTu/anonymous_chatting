//! Contacts and the conversations attached to them.
//!
//! `verified` is the field to be careful with: it is false on insert and only
//! ever set true by an explicit user action after an out-of-band comparison.

use rusqlite::{params, OptionalExtension};

use super::{LocalStore, StorageError, StoredContact};

impl LocalStore {
    /// Adds a contact, or updates the mutable parts of one already known.
    ///
    /// New contacts are always unverified.
    ///
    /// This is an upsert rather than `INSERT OR REPLACE` for three separate
    /// reasons, each of which would be a defect on its own:
    ///
    /// 1. **REPLACE destroys the thread.** SQLite implements it as
    ///    delete-then-insert, and foreign keys are enforced, so removing the
    ///    contact row cascades into `conversations` and then `messages`. Adding
    ///    someone already known would silently erase the history with them.
    /// 2. **REPLACE resets verification.** The struct carries `verified: false`
    ///    on every ordinary insert, so a rewrite would quietly drop a mark the
    ///    user established out of band. Verification is changed only by
    ///    `set_verified`.
    /// 3. **REPLACE would change the identity key without a warning.** A key
    ///    swap has to travel through `replace_identity_key`, which records what
    ///    it replaced and drops verification. Letting it happen here would be a
    ///    route around the identity-change modal that SPEC §6.7.6 requires.
    ///
    /// So a conflict updates the display name and the inbox address, and
    /// nothing else.
    pub fn put_contact(&self, contact: &StoredContact) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO contacts (id, display_name, inbox_id, public_key, verified)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                 display_name = excluded.display_name,
                 inbox_id     = excluded.inbox_id",
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

    /// Replaces a contact's identity key, recording that it changed.
    ///
    /// Three things happen together, and they have to happen together:
    ///
    /// 1. The new key becomes the key in use.
    /// 2. The old key and the date are kept, so the warning can state when.
    /// 3. **Verification is dropped.** The user compared a safety number
    ///    against the *previous* key. That comparison says nothing about this
    ///    one, and leaving the contact marked verified would be the interface
    ///    claiming a check that never happened — Prime Directive 3.
    ///
    /// Returns `false` and changes nothing if the key is unchanged, so callers
    /// can run this on every received message without inventing an event.
    pub fn replace_identity_key(
        &self,
        contact_id: &str,
        new_key: &[u8],
        now: u64,
    ) -> Result<bool, StorageError> {
        let Some(existing) = self.contact(contact_id)? else {
            return Ok(false);
        };
        if existing.public_key == new_key {
            return Ok(false);
        }

        self.conn.execute(
            "UPDATE contacts SET public_key = ?1, verified = 0 WHERE id = ?2",
            params![new_key, contact_id],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO identity_changes
                 (contact_id, previous_key, changed_at, acknowledged)
             VALUES (?1, ?2, ?3, 0)",
            params![contact_id, existing.public_key, now as i64],
        )?;
        Ok(true)
    }

    /// The recorded identity change for a contact, if their key ever changed.
    pub fn identity_change(
        &self,
        contact_id: &str,
    ) -> Result<Option<super::IdentityChange>, StorageError> {
        Ok(self
            .conn
            .query_row(
                "SELECT contact_id, previous_key, changed_at, acknowledged
                 FROM identity_changes WHERE contact_id = ?1",
                params![contact_id],
                |row| {
                    Ok(super::IdentityChange {
                        contact_id: row.get(0)?,
                        previous_key: row.get(1)?,
                        changed_at: row.get::<_, i64>(2)? as u64,
                        acknowledged: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()?)
    }

    /// Every identity change the user has not yet answered.
    ///
    /// Drives the modal at SPEC §6.7.6, which interrupts rather than notifies.
    pub fn unacknowledged_identity_changes(
        &self,
    ) -> Result<Vec<super::IdentityChange>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT contact_id, previous_key, changed_at, acknowledged
             FROM identity_changes WHERE acknowledged = 0 ORDER BY changed_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(super::IdentityChange {
                contact_id: row.get(0)?,
                previous_key: row.get(1)?,
                changed_at: row.get::<_, i64>(2)? as u64,
                acknowledged: row.get::<_, i64>(3)? != 0,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Marks an identity change as seen and answered.
    ///
    /// Deliberately separate from verification. A user who picks "continue
    /// without verifying" has answered the question; they have not compared a
    /// safety number, and `verified` stays false.
    pub fn acknowledge_identity_change(&self, contact_id: &str) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE identity_changes SET acknowledged = 1 WHERE contact_id = ?1",
            params![contact_id],
        )?;
        Ok(())
    }

    /// Records a conversation against a contact.
    ///
    /// An upsert for the same reason as `put_contact`: `INSERT OR REPLACE`
    /// deletes the conversation row first, which cascades into `messages` and
    /// takes the thread with it. Recording a conversation that already exists
    /// has to be a no-op, not a deletion.
    ///
    /// `disappear_after` is deliberately left alone on conflict — it is the
    /// user's setting, not something a re-registration should reset.
    pub fn put_conversation(
        &self,
        conversation_id: &str,
        contact_id: &str,
    ) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO conversations (id, contact_id) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET contact_id = excluded.contact_id",
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
