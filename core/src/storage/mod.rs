//! Local storage, on SQLCipher.
//!
//! Unlike the relay's database — which deliberately holds nothing worth
//! protecting (D-019) — this one holds message plaintext, the identity private
//! key, and the MLS state. It is encrypted with AES-256 through SQLCipher, with
//! the key supplied by the caller from the OS keystore or derived from a
//! passphrase via Argon2id (D-007).
//!
//! Nothing in this module logs a key, a passphrase, or message content.

mod contacts;
mod error;
mod identity;
mod messages;
mod schema;
mod types;

pub use error::StorageError;
pub use types::{Direction, StoredContact, StoredMessage};

use rusqlite::{Connection, OptionalExtension};
use zeroize::Zeroize;

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

    /// present on disk — and a wipe that leaves the data behind is worse than no
    /// wipe, because the user believes it is gone.
    /// Destroys everything: identity, keys, contacts, and messages.
    ///
    /// `VACUUM` is not optional here. Without it SQLite leaves the deleted
    /// pages in the file, so the contents of "wiped" messages would still be
    /// present on disk — and a wipe that leaves the data behind is worse than
    /// no wipe, because the user believes it is gone.
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
