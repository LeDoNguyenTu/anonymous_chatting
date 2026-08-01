//! Message rows.

use rusqlite::params;

use super::{Direction, LocalStore, StorageError, StoredMessage};

impl LocalStore {
    /// Stores a message.
    pub fn put_message(&self, message: &StoredMessage) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO messages (id, conversation_id, direction, body, at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                message.id,
                message.conversation_id,
                message.direction.as_str(),
                message.body,
                message.at as i64
            ],
        )?;
        Ok(())
    }

    /// Every message in a conversation, oldest first.
    pub fn messages(&self, conversation_id: &str) -> Result<Vec<StoredMessage>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conversation_id, direction, body, at FROM messages
             WHERE conversation_id = ?1 ORDER BY at, id",
        )?;
        let rows = stmt.query_map(params![conversation_id], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                direction: Direction::parse(&row.get::<_, String>(2)?),
                body: row.get(3)?,
                at: row.get::<_, i64>(4)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}
