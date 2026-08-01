//! Received attachment rows.

use rusqlite::{params, OptionalExtension};

use super::{LocalStore, StorageError, StoredAttachment};

impl LocalStore {
    /// Stores a received attachment's stripped content.
    pub fn put_attachment(&self, attachment: &StoredAttachment) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO attachments
                 (id, conversation_id, filename, format, content, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                attachment.id,
                attachment.conversation_id,
                attachment.filename,
                attachment.format,
                attachment.content,
                attachment.at as i64
            ],
        )?;
        Ok(())
    }

    /// The attachment stored under a message id, if that message carried one.
    pub fn attachment(&self, message_id: &str) -> Result<Option<StoredAttachment>, StorageError> {
        self.conn
            .query_row(
                "SELECT id, conversation_id, filename, format, content, at
                 FROM attachments WHERE id = ?1",
                params![message_id],
                |row| {
                    Ok(StoredAttachment {
                        id: row.get(0)?,
                        conversation_id: row.get(1)?,
                        filename: row.get(2)?,
                        format: row.get(3)?,
                        content: row.get(4)?,
                        at: row.get::<_, i64>(5)? as u64,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Whether an attachment is already stored under this message id.
    ///
    /// Used to make fetching idempotent: if a crash happens between erasing
    /// the relay's copy of a blob and acknowledging the reference message
    /// that pointed to it, the next receive must not try to fetch a bucket
    /// that is now empty by design rather than by loss.
    pub fn has_attachment(&self, message_id: &str) -> Result<bool, StorageError> {
        Ok(self.attachment(message_id)?.is_some())
    }
}
