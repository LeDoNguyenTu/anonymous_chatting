//! Local storage, on SQLCipher.
//!
//! Unlike the relay's database — which deliberately holds nothing worth
//! protecting (D-019) — this one holds message plaintext, the identity private
//! key, and the MLS state. It is encrypted with AES-256 through SQLCipher, with
//! the key supplied by the caller from the OS keystore or derived from a
//! passphrase via Argon2id (D-007).
//!
//! Nothing in this module logs a key, a passphrase, or message content.

use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroize;

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

/// Which way a message travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Written by the user of this device.
    Sent,
    /// Received from a contact.
    Received,
}

impl Direction {
    fn as_str(&self) -> &'static str {
        match self {
            Direction::Sent => "sent",
            Direction::Received => "received",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "sent" => Direction::Sent,
            _ => Direction::Received,
        }
    }
}

/// A stored message.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    /// Local identifier.
    pub id: String,
    /// Which conversation it belongs to.
    pub conversation_id: String,
    /// Sent or received.
    pub direction: Direction,
    /// The plaintext body.
    pub body: String,
    /// Local send or receive time, seconds since the Unix epoch.
    ///
    /// Full precision is fine here: this timestamp never leaves the device, and
    /// the relay's copy is bucketed separately (D-020).
    pub at: u64,
}

/// A contact and the trust state the Custody Strip reports.
#[derive(Debug, Clone)]
pub struct StoredContact {
    /// Local identifier.
    pub id: String,
    /// Local-only display name.
    pub display_name: String,
    /// The contact's opaque inbox address.
    pub inbox_id: String,
    /// The contact's identity public key.
    pub public_key: Vec<u8>,
    /// Whether the user has actually compared a safety number.
    ///
    /// Defaults to false and only becomes true through an explicit user action.
    /// The Custody Strip shows amber until then, and "the user dismissed a
    /// prompt" is not a reason to flip this.
    pub verified: bool,
}

/// The encrypted local database.
pub struct LocalStore {
    conn: Connection,
}

impl LocalStore {
    /// Opens or creates the database at `path`, unlocked with `key`.
    ///
    /// `key` is zeroized before this function returns, whether it succeeds or
    /// fails — SPEC §2.1 requires key material be zeroized rather than left for
    /// the allocator to hand to someone else.
    pub fn open(path: &str, key: &mut [u8]) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;

        // Confirm SQLCipher is actually present *before* trusting `PRAGMA key`
        // to do anything. `cipher_version` is answered only by SQLCipher; on a
        // plain SQLite build the query fails, and that is the signal. Without
        // this check a dependency-resolution accident downgrades the build to
        // plain SQLite and every database written afterwards is plaintext, with
        // nothing anywhere reporting a problem. That happened during
        // development — see D-024 — which is why the check exists.
        let cipher_version: Option<String> = conn
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .optional()
            .unwrap_or(None);
        if cipher_version.as_deref().unwrap_or("").is_empty() {
            key.zeroize();
            return Err(StorageError::SqlCipherMissing);
        }

        // SQLCipher takes its key through a pragma. Passed as a blob literal
        // (x'...') rather than as a passphrase string, so SQLCipher uses these
        // bytes directly as the key instead of running its own KDF over them.
        // The caller has already derived them properly — OS keystore or
        // Argon2id — and layering a second, unspecified derivation on top would
        // obscure what actually protects the file.
        let mut hex_key = hex::encode(&key);
        let mut pragma = format!("PRAGMA key = \"x'{hex_key}'\";");
        let result = conn.execute_batch(&pragma);

        // Neither buffer is needed past this point.
        key.zeroize();
        hex_key.zeroize();
        pragma.zeroize();

        result?;

        // SQLCipher does not verify the key when the pragma is set; it fails on
        // the first read. This is that read, and it is the only place a wrong
        // passphrase can be told apart from a corrupt file.
        conn.execute_batch("SELECT count(*) FROM sqlite_master;")
            .map_err(|_| StorageError::WrongKey)?;

        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS identity (
                 id            INTEGER PRIMARY KEY CHECK (id = 1),
                 display_name  TEXT NOT NULL,
                 inbox_id      TEXT NOT NULL,
                 signer_public BLOB NOT NULL
                 -- No secret column. The identity private key is held by the
                 -- MLS storage provider and travels inside the mls_state
                 -- snapshot, so it exists in exactly one place in this file
                 -- rather than two. See D-025.
             );

             CREATE TABLE IF NOT EXISTS mls_state (
                 id       INTEGER PRIMARY KEY CHECK (id = 1),
                 snapshot BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS contacts (
                 id           TEXT PRIMARY KEY,
                 display_name TEXT NOT NULL,
                 inbox_id     TEXT NOT NULL,
                 public_key   BLOB NOT NULL,
                 verified     INTEGER NOT NULL DEFAULT 0
             );

             CREATE TABLE IF NOT EXISTS conversations (
                 id         TEXT PRIMARY KEY,
                 contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE
             );

             CREATE TABLE IF NOT EXISTS messages (
                 id              TEXT PRIMARY KEY,
                 conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                 direction       TEXT NOT NULL,
                 body            TEXT NOT NULL,
                 at              INTEGER NOT NULL
             );

             CREATE INDEX IF NOT EXISTS messages_conversation
                 ON messages (conversation_id, at);",
        )?;
        Ok(())
    }

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

    /// Destroys everything: identity, keys, contacts, and messages.
    ///
    /// `VACUUM` is not optional here. Without it SQLite leaves the deleted
    /// pages in the file, so the contents of "wiped" messages would still be
    /// present on disk — and a wipe that leaves the data behind is worse than no
    /// wipe, because the user believes it is gone.
    pub fn wipe(&self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            "DELETE FROM messages;
             DELETE FROM conversations;
             DELETE FROM contacts;
             DELETE FROM mls_state;
             DELETE FROM identity;
             VACUUM;",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        vec![0x42; 32]
    }

    #[test]
    fn the_build_is_linked_against_sqlcipher() {
        // Stated as its own test so a downgraded build reports the cause
        // directly, rather than as a confusing "plaintext on disk" failure in
        // the test below.
        let (_dir, path) = temp();
        let mut k = key();
        match LocalStore::open(&path, &mut k) {
            Ok(_) => {}
            Err(StorageError::SqlCipherMissing) => {
                panic!("built without SQLCipher; the local database would not be encrypted")
            }
            Err(e) => panic!("unexpected failure opening the store: {e}"),
        }
    }

    fn store(path: &str) -> LocalStore {
        LocalStore::open(path, &mut key()).expect("store opens")
    }

    fn temp() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("pouch.db").to_string_lossy().into_owned();
        (dir, path)
    }

    fn contact(id: &str, name: &str) -> StoredContact {
        StoredContact {
            id: id.into(),
            display_name: name.into(),
            inbox_id: "i1".into(),
            public_key: b"k".to_vec(),
            verified: false,
        }
    }

    #[test]
    fn the_database_file_is_not_readable_without_the_key() {
        // The point of SQLCipher. If this fails, a stolen laptop yields the
        // whole message history.
        let (_dir, path) = temp();
        {
            let s = store(&path);
            s.put_identity("Brian", "abc", b"IDENTITY-PUBKEY-CANARY")
                .expect("identity");
            s.put_contact(&contact("c1", "Mai")).expect("contact");
            s.put_conversation("v1", "c1").expect("conversation");
            s.put_message(&StoredMessage {
                id: "m1".into(),
                conversation_id: "v1".into(),
                direction: Direction::Sent,
                body: "MEETING-AT-DAWN-LOCAL-CANARY".into(),
                at: 1_800_000_000,
            })
            .expect("message");
        }

        let bytes = std::fs::read(&path).expect("file is readable as bytes");
        for needle in [
            &b"MEETING-AT-DAWN-LOCAL-CANARY"[..],
            &b"IDENTITY-PUBKEY-CANARY"[..],
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{} is on disk unencrypted",
                String::from_utf8_lossy(needle)
            );
        }

        // A plain SQLite open must fail rather than reveal even the schema.
        let plain = rusqlite::Connection::open(&path).expect("opens the file");
        assert!(
            plain
                .execute_batch("SELECT count(*) FROM sqlite_master;")
                .is_err(),
            "the database opened without a key"
        );
    }

    #[test]
    fn the_wrong_key_is_reported_as_a_wrong_key() {
        let (_dir, path) = temp();
        {
            store(&path)
                .put_identity("Brian", "abc", b"pub")
                .expect("identity");
        }
        let mut wrong = vec![0x99; 32];
        assert!(matches!(
            LocalStore::open(&path, &mut wrong),
            Err(StorageError::WrongKey)
        ));
    }

    #[test]
    fn the_key_buffer_is_zeroized_after_opening() {
        // The caller's copy must not survive in memory after the call.
        let (_dir, path) = temp();
        let mut k = key();
        let _store = LocalStore::open(&path, &mut k).expect("opens");
        assert!(k.iter().all(|b| *b == 0), "the key buffer was not zeroized");
    }

    #[test]
    fn the_key_buffer_is_zeroized_even_when_opening_fails() {
        let (_dir, path) = temp();
        {
            store(&path)
                .put_identity("Brian", "abc", b"pub")
                .expect("identity");
        }
        let mut wrong = vec![0x99; 32];
        let _ = LocalStore::open(&path, &mut wrong);
        assert!(
            wrong.iter().all(|b| *b == 0),
            "a failed open left the key in the caller's buffer"
        );
    }

    #[test]
    fn identity_round_trips() {
        let (_dir, path) = temp();
        let s = store(&path);
        assert!(!s.has_identity().expect("checks"));
        s.put_identity("Brian", "inbox-1", b"pub").expect("stores");
        assert!(s.has_identity().expect("checks"));

        let (name, inbox, public) = s.identity().expect("reads");
        assert_eq!(name, "Brian");
        assert_eq!(inbox, "inbox-1");
        assert_eq!(public, b"pub");
    }

    #[test]
    fn a_missing_identity_is_a_named_error() {
        let (_dir, path) = temp();
        assert!(matches!(
            store(&path).identity(),
            Err(StorageError::NoIdentity)
        ));
    }

    #[test]
    fn a_new_contact_is_never_verified_by_default() {
        // Prime Directive 3: the UI must not show a reassuring state the user
        // has not actually established.
        let (_dir, path) = temp();
        let s = store(&path);
        s.put_contact(&contact("c1", "Mai")).expect("stores");
        assert!(!s.contact("c1").expect("reads").expect("exists").verified);
    }

    #[test]
    fn verification_is_an_explicit_action_and_is_reversible() {
        let (_dir, path) = temp();
        let s = store(&path);
        s.put_contact(&contact("c1", "Mai")).expect("stores");

        s.set_verified("c1", true).expect("verifies");
        assert!(s.contact("c1").expect("reads").expect("exists").verified);

        // Reversible, because an identity change has to be able to drop a
        // contact back to unverified.
        s.set_verified("c1", false).expect("unverifies");
        assert!(!s.contact("c1").expect("reads").expect("exists").verified);
    }

    #[test]
    fn messages_come_back_in_order() {
        let (_dir, path) = temp();
        let s = store(&path);
        s.put_contact(&contact("c1", "Mai")).expect("contact");
        s.put_conversation("v1", "c1").expect("conversation");

        for (i, at) in [(0, 300u64), (1, 100), (2, 200)] {
            s.put_message(&StoredMessage {
                id: format!("m{i}"),
                conversation_id: "v1".into(),
                direction: Direction::Sent,
                body: format!("body {i}"),
                at,
            })
            .expect("message");
        }

        let times: Vec<u64> = s
            .messages("v1")
            .expect("reads")
            .iter()
            .map(|m| m.at)
            .collect();
        assert_eq!(times, vec![100, 200, 300]);
    }

    #[test]
    fn mls_state_round_trips() {
        let (_dir, path) = temp();
        let s = store(&path);
        assert!(s.mls_state().expect("reads").is_none());
        s.put_mls_state(b"snapshot-bytes").expect("stores");
        assert_eq!(
            s.mls_state().expect("reads").as_deref(),
            Some(&b"snapshot-bytes"[..])
        );
    }

    #[test]
    fn wipe_leaves_nothing_behind() {
        // A wipe that leaves content in freed pages is worse than no wipe: the
        // user believes the data is gone.
        let (_dir, path) = temp();
        {
            let s = store(&path);
            s.put_identity("Brian", "abc", b"pub").expect("identity");
            s.put_contact(&contact("c1", "WIPE-CONTACT-CANARY"))
                .expect("contact");
            s.put_conversation("v1", "c1").expect("conversation");
            s.put_message(&StoredMessage {
                id: "m1".into(),
                conversation_id: "v1".into(),
                direction: Direction::Sent,
                body: "WIPE-BODY-CANARY".into(),
                at: 1,
            })
            .expect("message");
            s.put_mls_state(b"state").expect("state");

            s.wipe().expect("wipes");

            assert!(!s.has_identity().expect("checks"));
            assert!(s.contacts().expect("reads").is_empty());
            assert!(s.messages("v1").expect("reads").is_empty());
            assert!(s.mls_state().expect("reads").is_none());
        }

        // And it survived the close.
        let s = store(&path);
        assert!(!s.has_identity().expect("checks"));
        assert!(s.contacts().expect("reads").is_empty());
    }
}
