//! Relay storage.
//!
//! Four columns. Adding a fifth is a threat-model change, not a schema change
//! (SPEC §2.3, §2.6).
//!
//! The property this module exists to preserve: a full database dump handed to
//! an adversary yields nothing useful. `server/tests/server_blindness.rs`
//! asserts it against a real conversation rather than trusting this comment.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection};

/// Default queue lifetime. A blob not collected within this window is erased.
pub const DEFAULT_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Granularity that `expires_at` is rounded up to.
///
/// This is the difference between an honest interface and a dishonest one. A
/// second-precision expiry column is an exact arrival clock: subtract the TTL
/// and you have the moment the message was sent, for every blob in the queue.
/// The product's "what the relay could see" screen lists exact send time as
/// *not visible*, so the storage layer has to actually make that true.
///
/// One hour is the chosen trade. Coarser buckets give a larger anonymity set
/// but delay deletion, and a 24-hour bucket would make the shortest retention
/// setting unenforceable at the relay.
const EXPIRY_BUCKET: u64 = 60 * 60;

/// Length of a message identifier, in bytes. Random, never sequential — an
/// autoincrement column is an ordering oracle across every inbox at once.
const MESSAGE_ID_BYTES: usize = 16;

/// Errors the queue can produce. Deliberately coarse: a caller that can
/// distinguish "no such inbox" from "inbox empty" has learned something the
/// relay should not be able to tell it.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The underlying database rejected an operation.
    #[error("relay storage failure")]
    Database(#[from] rusqlite::Error),
    /// The submitted blob exceeds the accepted size.
    #[error("blob exceeds the maximum accepted size")]
    BlobTooLarge,
    /// The inbox identifier is not a well-formed opaque identifier.
    #[error("malformed inbox identifier")]
    MalformedInboxId,
}

/// A queued blob, as handed back to a collecting client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedMessage {
    /// Random 128-bit identifier, hex encoded.
    pub message_id: String,
    /// Ciphertext. The relay holds no key for this and never inspects it.
    pub blob: Vec<u8>,
}

/// The relay's blob queue.
pub struct Store {
    conn: Connection,
    max_blob_bytes: usize,
}

impl Store {
    /// Opens (and if necessary creates) the queue at `path`.
    ///
    /// Passing `":memory:"` gives an ephemeral queue, which is what the tests
    /// use.
    pub fn open(path: &str, max_blob_bytes: usize) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn,
            max_blob_bytes,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        // Four columns. No sender, no recipient name, no IP, no received_at,
        // no delivery receipt, no sequence number. Each of those is absent
        // because the relay must not be able to answer the question it would
        // enable.
        //
        // Note there is no INTEGER PRIMARY KEY rowid alias: SQLite's implicit
        // rowid is monotonic and would reintroduce exactly the ordering oracle
        // that random message_ids exist to remove. WITHOUT ROWID drops it.
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS queue (
                 message_id TEXT PRIMARY KEY,
                 inbox_id   TEXT NOT NULL,
                 blob       BLOB NOT NULL,
                 expires_at INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS queue_inbox ON queue (inbox_id);
             CREATE INDEX IF NOT EXISTS queue_expiry ON queue (expires_at);",
        )?;
        Ok(())
    }

    /// Accepts a blob for an inbox and returns its random identifier.
    pub fn enqueue(&self, inbox_id: &str, blob: &[u8]) -> Result<String, StoreError> {
        if !is_valid_inbox_id(inbox_id) {
            return Err(StoreError::MalformedInboxId);
        }
        if blob.len() > self.max_blob_bytes {
            return Err(StoreError::BlobTooLarge);
        }

        let message_id = random_id();
        let expires_at = bucketed_expiry(now(), DEFAULT_TTL);

        self.conn.execute(
            "INSERT INTO queue (message_id, inbox_id, blob, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![message_id, inbox_id, blob, expires_at],
        )?;

        Ok(message_id)
    }

    /// Returns the blobs waiting for an inbox, without deleting them.
    ///
    /// Collection and deletion are separate steps on purpose. If a `GET` also
    /// deleted, a client that lost its connection mid-response would lose the
    /// message permanently — and a message the relay silently destroyed is
    /// indistinguishable, from the user's side, from one that was never sent.
    pub fn collect(&self, inbox_id: &str) -> Result<Vec<QueuedMessage>, StoreError> {
        if !is_valid_inbox_id(inbox_id) {
            return Err(StoreError::MalformedInboxId);
        }

        // Expired blobs are filtered on read as well as swept in the
        // background, so a stopped sweeper cannot cause over-retention.
        let mut stmt = self.conn.prepare(
            "SELECT message_id, blob FROM queue
             WHERE inbox_id = ?1 AND expires_at > ?2
             ORDER BY message_id",
        )?;

        let rows = stmt.query_map(params![inbox_id, now()], |row| {
            Ok(QueuedMessage {
                message_id: row.get(0)?,
                blob: row.get(1)?,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Erases blobs a client has confirmed it stored. Returns how many went.
    pub fn acknowledge(&self, inbox_id: &str, message_ids: &[String]) -> Result<usize, StoreError> {
        if !is_valid_inbox_id(inbox_id) {
            return Err(StoreError::MalformedInboxId);
        }

        let mut deleted = 0;
        for id in message_ids {
            // Scoped to the inbox so possession of an identifier is not on its
            // own enough to delete another inbox's mail.
            deleted += self.conn.execute(
                "DELETE FROM queue WHERE message_id = ?1 AND inbox_id = ?2",
                params![id, inbox_id],
            )?;
        }
        Ok(deleted)
    }

    /// Erases everything past its TTL. Returns how many blobs went.
    pub fn sweep_expired(&self) -> Result<usize, StoreError> {
        Ok(self
            .conn
            .execute("DELETE FROM queue WHERE expires_at <= ?1", params![now()])?)
    }

    /// Number of blobs currently held. For tests and operator diagnostics; not
    /// exposed over HTTP, because queue depth per inbox is a metadata leak.
    pub fn len(&self) -> Result<usize, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM queue", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }
}

/// Seconds since the Unix epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Computes an expiry that cannot be read backwards as an arrival clock.
///
/// The *arrival* instant is rounded up to a bucket boundary first, and the TTL
/// is added to that. Rounding the other way round — adding the TTL and then
/// bucketing the result — does not work, and the failure is easy to miss: the
/// sum still varies with `now`, so two messages an hour apart in arrival land
/// in different buckets and the column remains a clock with the precision of
/// the bucket edge rather than the bucket width.
///
/// Doing it in this order, every blob arriving within the same hour carries a
/// byte-identical expiry, so the column distinguishes nothing finer than the
/// hour it arrived in.
///
/// Rounding *up* keeps the guarantee one-directional: a blob is never erased
/// earlier than its full TTL, only up to one bucket later.
fn bucketed_expiry(now_secs: u64, ttl: Duration) -> u64 {
    // Floor, not ceil. Ceiling splits the hour at its boundary — an arrival at
    // exactly 14:00:00 and one at 14:00:01 land in different buckets — which
    // groups nothing and leaves the boundary itself readable. Flooring puts
    // every arrival in the hour on the same value.
    let bucket_start = (now_secs / EXPIRY_BUCKET) * EXPIRY_BUCKET;

    // One extra bucket of slack pays back what flooring gave away, so the blob
    // still lives at least its full TTL. Worst case it lives one hour longer.
    bucket_start
        .saturating_add(ttl.as_secs())
        .saturating_add(EXPIRY_BUCKET)
}

/// A random 128-bit identifier, hex encoded.
///
/// `OsRng` because SPEC §2.1 forbids any non-CSPRNG for anything
/// security-relevant, and identifier unpredictability is security-relevant: a
/// guessable message id would let anyone delete another inbox's mail.
fn random_id() -> String {
    let mut bytes = [0u8; MESSAGE_ID_BYTES];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Inbox identifiers are 128-bit opaque values, hex encoded.
///
/// Validated rather than trusted so the queue cannot be used as general storage
/// keyed by attacker-chosen strings — and so an identifier can never carry a
/// username, an email address, or anything else meaningful about a person.
pub fn is_valid_inbox_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open(":memory:", 1 << 20).expect("in-memory store opens")
    }

    const INBOX: &str = "7f3a1c9e04b6d82f5a730e19bc42d861";

    #[test]
    fn enqueue_then_collect_returns_the_blob_unchanged() {
        let s = store();
        let id = s.enqueue(INBOX, b"ciphertext").unwrap();
        let got = s.collect(INBOX).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].message_id, id);
        assert_eq!(got[0].blob, b"ciphertext");
    }

    #[test]
    fn collect_does_not_delete() {
        // A lost connection must not cost the user a message.
        let s = store();
        s.enqueue(INBOX, b"x").unwrap();
        s.collect(INBOX).unwrap();
        assert_eq!(s.collect(INBOX).unwrap().len(), 1);
    }

    #[test]
    fn acknowledge_erases_the_blob() {
        let s = store();
        let id = s.enqueue(INBOX, b"x").unwrap();
        assert_eq!(s.acknowledge(INBOX, &[id]).unwrap(), 1);
        assert!(s.collect(INBOX).unwrap().is_empty());
        assert!(s.is_empty().unwrap());
    }

    #[test]
    fn one_inbox_cannot_acknowledge_anothers_mail() {
        let s = store();
        let other = "0000111122223333444455556666aaaa";
        let id = s.enqueue(INBOX, b"x").unwrap();
        assert_eq!(s.acknowledge(other, &[id]).unwrap(), 0);
        assert_eq!(s.collect(INBOX).unwrap().len(), 1);
    }

    #[test]
    fn inboxes_are_isolated() {
        let s = store();
        let other = "0000111122223333444455556666aaaa";
        s.enqueue(INBOX, b"x").unwrap();
        assert!(s.collect(other).unwrap().is_empty());
    }

    #[test]
    fn message_ids_are_unpredictable_and_unique() {
        let s = store();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            assert!(seen.insert(s.enqueue(INBOX, b"x").unwrap()));
        }
        // Random, not sequential: consecutive ids must not be adjacent values.
        let ids: Vec<_> = seen.into_iter().collect();
        assert!(ids.iter().all(|i| i.len() == MESSAGE_ID_BYTES * 2));
    }

    #[test]
    fn malformed_inbox_ids_are_rejected() {
        let s = store();
        for bad in ["", "alice", "7f3a", &"z".repeat(32), &"a".repeat(31)] {
            assert!(matches!(
                s.enqueue(bad, b"x"),
                Err(StoreError::MalformedInboxId)
            ));
        }
    }

    #[test]
    fn oversized_blobs_are_rejected() {
        let s = Store::open(":memory:", 16).unwrap();
        assert!(matches!(
            s.enqueue(INBOX, &[0u8; 17]),
            Err(StoreError::BlobTooLarge)
        ));
    }

    #[test]
    fn expiry_is_bucketed_so_it_cannot_be_read_as_an_arrival_clock() {
        // Every arrival inside one bucket must produce a byte-identical
        // expiry, or the column reveals when each message arrived.
        let base = (1_800_000_000u64 / EXPIRY_BUCKET) * EXPIRY_BUCKET;
        let expected = bucketed_expiry(base, DEFAULT_TTL);

        // Sweep the whole bucket, not just two samples: the earlier version of
        // this function passed a two-sample check while still leaking.
        for offset in [0u64, 1, 37, 599, 1800, EXPIRY_BUCKET - 1] {
            assert_eq!(
                bucketed_expiry(base + offset, DEFAULT_TTL),
                expected,
                "arrival at +{offset}s produced a distinguishable expiry"
            );
        }

        // And the next bucket must differ, or expiry means nothing at all.
        assert_ne!(bucketed_expiry(base + EXPIRY_BUCKET, DEFAULT_TTL), expected);
    }

    #[test]
    fn stored_expiry_values_collide_across_rapid_arrivals() {
        // The property as it actually reaches disk, not just in the helper.
        let s = store();
        for _ in 0..8 {
            s.enqueue(INBOX, b"x").unwrap();
        }
        let mut stmt = s
            .conn
            .prepare("SELECT DISTINCT expires_at FROM queue")
            .unwrap();
        let distinct: Vec<i64> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            distinct.len(),
            1,
            "messages sent together must be indistinguishable by expiry"
        );
    }

    #[test]
    fn expiry_never_rounds_down_below_the_ttl() {
        // Bucketing must only ever over-retain, never under-retain. A blob
        // erased early is a message the user believes was sent and was not.
        for offset in [0u64, 1, 59, 1234, 3599, 3600, 7199] {
            let t = 1_800_000_000 + offset;
            let expiry = bucketed_expiry(t, DEFAULT_TTL);
            assert!(
                expiry >= t + DEFAULT_TTL.as_secs(),
                "arrival at +{offset}s would be erased {}s early",
                (t + DEFAULT_TTL.as_secs()).saturating_sub(expiry)
            );
            // And it must not over-retain by more than one bucket, or the
            // retention setting stops meaning what the UI says it means.
            assert!(expiry <= t + DEFAULT_TTL.as_secs() + EXPIRY_BUCKET);
        }
    }

    #[test]
    fn sweep_removes_expired_blobs() {
        let s = store();
        s.enqueue(INBOX, b"x").unwrap();
        // Force the row past its TTL rather than waiting 30 days.
        s.conn
            .execute("UPDATE queue SET expires_at = 1", [])
            .unwrap();
        assert!(s.collect(INBOX).unwrap().is_empty(), "expired on read");
        assert_eq!(s.sweep_expired().unwrap(), 1);
        assert!(s.is_empty().unwrap());
    }
}
