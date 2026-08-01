//! Device-wide settings, and the retention rules built on them.
//!
//! Only settings the user controls live here. Nothing in this module is a
//! secret, but everything in it is inside the encrypted database anyway —
//! "this device keeps messages for 24 hours" is itself information about the
//! user, and there is no reason to leak it to get a marginal simplification.

use rusqlite::{params, OptionalExtension};

use super::{LocalStore, RetentionPolicy, StorageError};

/// The settings key holding the device-wide retention policy.
const RETENTION: &str = "retention";

impl LocalStore {
    /// Reads a raw setting.
    fn setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Writes a raw setting.
    fn put_setting(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// How long this device keeps messages. Defaults to forever.
    pub fn retention_policy(&self) -> Result<RetentionPolicy, StorageError> {
        Ok(self
            .setting(RETENTION)?
            .map(|v| RetentionPolicy::parse(&v))
            .unwrap_or(RetentionPolicy::Forever))
    }

    /// Sets how long this device keeps messages.
    ///
    /// Does not itself delete anything. The caller purges, so that the deletion
    /// is an explicit step that can be counted and reported rather than a side
    /// effect of changing a setting.
    pub fn set_retention_policy(&self, policy: RetentionPolicy) -> Result<(), StorageError> {
        self.put_setting(RETENTION, policy.as_str())
    }

    /// The per-conversation disappearing-message interval, if one is set.
    ///
    /// `None` means the conversation follows the device-wide policy.
    pub fn disappear_after(&self, conversation_id: &str) -> Result<Option<u64>, StorageError> {
        let raw: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT disappear_after FROM conversations WHERE id = ?1",
                params![conversation_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(raw.flatten().map(|v| v as u64))
    }

    /// Sets, or clears, disappearing messages for one conversation.
    pub fn set_disappear_after(
        &self,
        conversation_id: &str,
        seconds: Option<u64>,
    ) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE conversations SET disappear_after = ?1 WHERE id = ?2",
            params![seconds.map(|s| s as i64), conversation_id],
        )?;
        Ok(())
    }

    /// Deletes everything that has outlived its retention.
    ///
    /// A conversation with its own disappearing interval uses that; every other
    /// conversation follows the device-wide policy. Returns how many messages
    /// went, because a control that claims to delete things should be able to
    /// say how many it deleted.
    ///
    /// `now` is a parameter rather than read from the clock so the tests can
    /// age messages without sleeping.
    pub fn purge_expired(&self, now: u64) -> Result<usize, StorageError> {
        let global = self.retention_policy()?.seconds();

        // One statement covering both rules. Doing it as two passes would
        // delete per-conversation messages the device-wide rule had already
        // taken, and double-count them in the total.
        let deleted = self.conn.execute(
            "DELETE FROM messages WHERE id IN (
                 SELECT m.id FROM messages m
                 JOIN conversations c ON c.id = m.conversation_id
                 WHERE (c.disappear_after IS NOT NULL AND m.at < ?1 - c.disappear_after)
                    OR (c.disappear_after IS NULL AND ?2 IS NOT NULL AND m.at < ?1 - ?2)
             )",
            params![now as i64, global.map(|g| g as i64)],
        )?;

        // The outbox holds plaintext too. A message that expired while waiting
        // for the relay must not be delivered later as though the user had
        // never set a retention policy.
        let deleted_queued = self.conn.execute(
            "DELETE FROM outbox WHERE id IN (
                 SELECT o.id FROM outbox o
                 JOIN conversations c ON c.id = o.conversation_id
                 WHERE (c.disappear_after IS NOT NULL AND o.at < ?1 - c.disappear_after)
                    OR (c.disappear_after IS NULL AND ?2 IS NOT NULL AND o.at < ?1 - ?2)
             )",
            params![now as i64, global.map(|g| g as i64)],
        )?;

        Ok(deleted + deleted_queued)
    }
}
