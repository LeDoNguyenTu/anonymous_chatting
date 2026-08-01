//! Messages composed while the relay was unreachable.
//!
//! SPEC §8.2 requires an offline queue that retries on reconnect. Phase 1
//! reported `failed at stage 07` and stopped there, which was honest but meant
//! a message written on a train was simply lost.
//!
//! The queue holds the ciphertext MLS already produced, not the plaintext.
//! Encrypting advances the ratchet, so re-encrypting at delivery time would
//! burn a generation on every failed attempt and hand the recipient gaps their
//! out-of-order tolerance has to absorb — the same fault as D-028, reached from
//! the other direction. Queueing the finished blob makes a retry a re-POST.

use rusqlite::params;

use super::{LocalStore, QueuedMessage, StorageError};

impl LocalStore {
    /// Adds a message to the queue.
    pub fn enqueue(&self, message: &QueuedMessage) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO outbox
                 (id, conversation_id, peer_inbox, blob, at, attempts, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                message.id,
                message.conversation_id,
                message.peer_inbox,
                message.blob,
                message.at as i64,
                message.attempts as i64,
                message.last_error,
            ],
        )?;
        Ok(())
    }

    /// Everything waiting, oldest first.
    ///
    /// Order matters: MLS tolerates only a small amount of reordering, and a
    /// queue that flushed newest-first would hand the recipient a sequence its
    /// ratchet rejects. This is the same fault as D-028, reached by a different
    /// road.
    pub fn queued(&self) -> Result<Vec<QueuedMessage>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conversation_id, peer_inbox, blob, at, attempts, last_error
             FROM outbox ORDER BY at, id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(QueuedMessage {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                peer_inbox: row.get(2)?,
                blob: row.get(3)?,
                at: row.get::<_, i64>(4)? as u64,
                attempts: row.get::<_, i64>(5)? as u32,
                last_error: row.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// How many messages are waiting.
    pub fn queued_count(&self) -> Result<usize, StorageError> {
        let n: i64 = self
            .conn
            .query_row("SELECT count(*) FROM outbox", [], |row| row.get(0))?;
        Ok(n as usize)
    }

    /// Removes a message from the queue, after it has been delivered.
    pub fn dequeue(&self, id: &str) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM outbox WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Records a failed delivery attempt and why.
    ///
    /// The reason is kept so the thread can show it inline rather than a bare
    /// "failed" (SPEC §6.7.3, §6.9).
    pub fn record_attempt(&self, id: &str, error: &str) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE outbox SET attempts = attempts + 1, last_error = ?1 WHERE id = ?2",
            params![error, id],
        )?;
        Ok(())
    }
}
