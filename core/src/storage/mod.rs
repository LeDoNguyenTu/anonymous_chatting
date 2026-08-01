//! Local storage, on SQLCipher.
//!
//! Unlike the relay's database — which deliberately holds nothing worth
//! protecting (D-019) — this one holds message plaintext, the identity private
//! key, and the MLS state. It is encrypted with AES-256 through SQLCipher, with
//! the key supplied by the caller from the OS keystore or derived from a
//! passphrase via Argon2id (D-007).
//!
//! Nothing in this module logs a key, a passphrase, or message content.

mod attachments;
mod contacts;
mod error;
mod identity;
mod messages;
mod outbox;
mod schema;
mod settings;
mod types;

pub use error::StorageError;
pub use types::{
    Direction, IdentityChange, QueuedMessage, RetentionPolicy, StoredAttachment, StoredContact,
    StoredMessage,
};

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

        // Overwrite deleted rows instead of merely unlinking them.
        //
        // Retention exists to limit what a later compromise can reach. Without
        // this, a message deleted by a 24-hour policy stays in the file's free
        // pages until something happens to reuse them, so the key that opens
        // the database still opens data the user was told was gone. `VACUUM`
        // would also clear it, but only when it runs; this holds continuously
        // and costs one extra page write per delete.
        conn.execute_batch("PRAGMA secure_delete = ON;")?;

        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Re-encrypts the database under a new key.
    ///
    /// `PRAGMA rekey` rewrites every page with the new key, so the change is
    /// complete when it returns rather than applying to pages written later.
    /// A half-rekeyed database would be unopenable under either key, which is
    /// why this is one statement and not a copy-and-swap.
    ///
    /// `new_key` is zeroized before this returns, on both paths.
    pub fn rekey(&self, new_key: &mut [u8]) -> Result<(), StorageError> {
        let mut hex_key = hex::encode(&new_key);
        let mut pragma = format!("PRAGMA rekey = \"x'{hex_key}'\";");
        let result = self.conn.execute_batch(&pragma);

        new_key.zeroize();
        hex_key.zeroize();
        pragma.zeroize();

        result?;
        Ok(())
    }

    /// Destroys everything: identity, keys, contacts, and messages.
    ///
    /// `VACUUM` is not optional here. Without it SQLite leaves the deleted
    /// pages in the file, so the contents of "wiped" messages would still be
    /// present on disk — and a wipe that leaves the data behind is worse than
    /// no wipe, because the user believes it is gone.
    pub fn wipe(&self) -> Result<(), StorageError> {
        // Every table, including the ones Phase 2 added. A wipe that misses a
        // table leaves the user believing something is gone when it is not —
        // the outbox holds undelivered ciphertext and `messages` holds the
        // readable copy of the same text.
        self.conn.execute_batch(
            "DELETE FROM outbox;
             DELETE FROM attachments;
             DELETE FROM identity_changes;
             DELETE FROM messages;
             DELETE FROM conversations;
             DELETE FROM contacts;
             DELETE FROM settings;
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

    // ---- Phase 2: retention ------------------------------------------------

    /// A conversation with `count` messages, aged `ages` seconds before `now`.
    fn conversation_with(s: &LocalStore, id: &str, now: u64, ages: &[u64]) {
        if s.contact("c1").expect("reads").is_none() {
            s.put_contact(&contact("c1", "Mai")).expect("contact");
        }
        s.put_conversation(id, "c1").expect("conversation");
        for (i, age) in ages.iter().enumerate() {
            s.put_message(&StoredMessage {
                id: format!("{id}-m{i}"),
                conversation_id: id.into(),
                direction: Direction::Sent,
                body: format!("body {i}"),
                at: now - age,
            })
            .expect("message");
        }
    }

    #[test]
    fn re_adding_a_known_contact_does_not_destroy_their_history() {
        // `put_contact` is INSERT OR REPLACE, and SQLite implements REPLACE as
        // delete-then-insert. With foreign keys enforced, that delete cascades
        // through conversations into messages — so re-adding someone already
        // known would silently erase the thread. Found while writing the
        // retention tests, where a helper inserted the same contact twice.
        let (_dir, path) = temp();
        let s = store(&path);
        s.put_contact(&contact("c1", "Mai")).expect("contact");
        s.put_conversation("v1", "c1").expect("conversation");
        s.put_message(&StoredMessage {
            id: "m1".into(),
            conversation_id: "v1".into(),
            direction: Direction::Sent,
            body: "still here".into(),
            at: 1_700_000_000,
        })
        .expect("message");

        s.set_verified("c1", true).expect("verifies");
        s.put_contact(&contact("c1", "Mai renamed")).expect("again");

        assert_eq!(
            s.conversations_for("c1").expect("reads").len(),
            1,
            "re-adding a contact dropped their conversation"
        );
        assert_eq!(
            s.messages("v1").expect("reads").len(),
            1,
            "re-adding a contact dropped their messages"
        );

        let back = s.contact("c1").expect("reads").expect("exists");
        assert_eq!(back.display_name, "Mai renamed", "the rename did not apply");
        assert!(
            back.verified,
            "re-adding a contact silently dropped a verification the user established"
        );
        assert_eq!(
            back.public_key,
            b"k".to_vec(),
            "re-adding a contact changed the identity key without recording a change"
        );
    }

    #[test]
    fn re_registering_a_conversation_does_not_drop_its_messages() {
        // The same cascade as above, one level down: REPLACE on conversations
        // deletes the row and takes its messages with it.
        let (_dir, path) = temp();
        let s = store(&path);
        s.put_contact(&contact("c1", "Mai")).expect("contact");
        s.put_conversation("v1", "c1").expect("conversation");
        s.put_message(&StoredMessage {
            id: "m1".into(),
            conversation_id: "v1".into(),
            direction: Direction::Received,
            body: "still here".into(),
            at: 1_700_000_000,
        })
        .expect("message");
        s.set_disappear_after("v1", Some(3600)).expect("set");

        s.put_conversation("v1", "c1").expect("again");

        assert_eq!(
            s.messages("v1").expect("reads").len(),
            1,
            "re-registering a conversation dropped its messages"
        );
        assert_eq!(
            s.disappear_after("v1").expect("reads"),
            Some(3600),
            "re-registering a conversation reset the user's disappearing setting"
        );
    }

    #[test]
    fn retention_defaults_to_keeping_everything() {
        // Anything else would delete a user's history because they never
        // opened a settings screen.
        let (_dir, path) = temp();
        assert_eq!(
            store(&path).retention_policy().expect("reads"),
            RetentionPolicy::Forever
        );
    }

    #[test]
    fn keeping_forever_purges_nothing() {
        let (_dir, path) = temp();
        let s = store(&path);
        let now = 1_800_000_000;
        conversation_with(&s, "v1", now, &[0, 400 * 86_400]);

        assert_eq!(s.purge_expired(now).expect("purges"), 0);
        assert_eq!(s.messages("v1").expect("reads").len(), 2);
    }

    #[test]
    fn a_retention_policy_deletes_only_what_has_outlived_it() {
        let (_dir, path) = temp();
        let s = store(&path);
        let now = 1_800_000_000;
        // Ages: fresh, 6 days, 8 days.
        conversation_with(&s, "v1", now, &[60, 6 * 86_400, 8 * 86_400]);
        s.set_retention_policy(RetentionPolicy::Days7).expect("set");

        assert_eq!(s.purge_expired(now).expect("purges"), 1);
        let left: Vec<u64> = s
            .messages("v1")
            .expect("reads")
            .iter()
            .map(|m| now - m.at)
            .collect();
        assert_eq!(left, vec![6 * 86_400, 60]);
    }

    #[test]
    fn a_conversation_can_disappear_faster_than_the_device_setting() {
        let (_dir, path) = temp();
        let s = store(&path);
        let now = 1_800_000_000;
        conversation_with(&s, "v1", now, &[2 * 3600, 30 * 3600]);
        conversation_with(&s, "v2", now, &[2 * 3600, 30 * 3600]);

        s.set_retention_policy(RetentionPolicy::Days30)
            .expect("set");
        s.set_disappear_after("v1", Some(24 * 3600)).expect("set");

        assert_eq!(s.purge_expired(now).expect("purges"), 1);
        assert_eq!(s.messages("v1").expect("reads").len(), 1);
        assert_eq!(
            s.messages("v2").expect("reads").len(),
            2,
            "v2 was untouched"
        );
    }

    #[test]
    fn a_conversation_can_also_be_kept_longer_than_the_device_setting() {
        // The override is an override in both directions. A per-conversation
        // interval of 30 days on a device set to 24 hours keeps 30 days.
        let (_dir, path) = temp();
        let s = store(&path);
        let now = 1_800_000_000;
        conversation_with(&s, "v1", now, &[10 * 86_400]);

        s.set_retention_policy(RetentionPolicy::Hours24)
            .expect("set");
        s.set_disappear_after("v1", Some(30 * 86_400)).expect("set");

        assert_eq!(s.purge_expired(now).expect("purges"), 0);
    }

    #[test]
    fn clearing_a_disappearing_interval_returns_to_the_device_setting() {
        let (_dir, path) = temp();
        let s = store(&path);
        let now = 1_800_000_000;
        conversation_with(&s, "v1", now, &[10 * 86_400]);

        s.set_disappear_after("v1", Some(30 * 86_400)).expect("set");
        assert_eq!(s.disappear_after("v1").expect("reads"), Some(30 * 86_400));

        s.set_disappear_after("v1", None).expect("clear");
        assert_eq!(s.disappear_after("v1").expect("reads"), None);

        s.set_retention_policy(RetentionPolicy::Days7).expect("set");
        assert_eq!(s.purge_expired(now).expect("purges"), 1);
    }

    #[test]
    fn an_unrecognised_retention_value_keeps_everything() {
        // A database written by a newer build must not lose history when an
        // older build reads a setting it does not know.
        let (_dir, path) = temp();
        let s = store(&path);
        s.conn
            .execute_batch("INSERT OR REPLACE INTO settings (key, value) VALUES ('retention','7y')")
            .expect("writes");
        assert_eq!(
            s.retention_policy().expect("reads"),
            RetentionPolicy::Forever
        );
    }

    #[test]
    fn purging_also_takes_queued_messages() {
        // Otherwise a message that expired while offline is delivered later,
        // after the user was told it would be gone.
        let (_dir, path) = temp();
        let s = store(&path);
        let now = 1_800_000_000;
        conversation_with(&s, "v1", now, &[]);
        s.enqueue(&QueuedMessage {
            id: "q1".into(),
            conversation_id: "v1".into(),
            peer_inbox: "inbox".into(),
            blob: b"ciphertext".to_vec(),
            at: now - 10 * 86_400,
            attempts: 3,
            last_error: None,
        })
        .expect("enqueues");

        s.set_retention_policy(RetentionPolicy::Days7).expect("set");
        assert_eq!(s.purge_expired(now).expect("purges"), 1);
        assert_eq!(s.queued_count().expect("counts"), 0);
    }

    // ---- Phase 2: the offline queue ---------------------------------------

    #[test]
    fn the_queue_comes_back_oldest_first() {
        // MLS tolerates little reordering. Flushing newest-first would hand the
        // recipient a sequence its ratchet rejects — D-028 by another route.
        let (_dir, path) = temp();
        let s = store(&path);
        conversation_with(&s, "v1", 1_000, &[]);

        for (id, at) in [("q3", 300u64), ("q1", 100), ("q2", 200)] {
            s.enqueue(&QueuedMessage {
                id: id.into(),
                conversation_id: "v1".into(),
                peer_inbox: "inbox".into(),
                blob: id.as_bytes().to_vec(),
                at,
                attempts: 0,
                last_error: None,
            })
            .expect("enqueues");
        }

        let order: Vec<String> = s
            .queued()
            .expect("reads")
            .iter()
            .map(|q| q.id.clone())
            .collect();
        assert_eq!(order, vec!["q1", "q2", "q3"]);
    }

    #[test]
    fn a_failed_attempt_keeps_its_reason() {
        let (_dir, path) = temp();
        let s = store(&path);
        conversation_with(&s, "v1", 1_000, &[]);
        s.enqueue(&QueuedMessage {
            id: "q1".into(),
            conversation_id: "v1".into(),
            peer_inbox: "inbox".into(),
            blob: b"ciphertext".to_vec(),
            at: 100,
            attempts: 0,
            last_error: None,
        })
        .expect("enqueues");

        s.record_attempt("q1", "no connection to the relay")
            .expect("records");

        let q = &s.queued().expect("reads")[0];
        assert_eq!(q.attempts, 1);
        assert_eq!(q.last_error.as_deref(), Some("no connection to the relay"));
        assert_eq!(q.blob, b"ciphertext".to_vec(), "the blob changed on retry");
        assert_eq!(q.peer_inbox, "inbox");

        s.dequeue("q1").expect("dequeues");
        assert_eq!(s.queued_count().expect("counts"), 0);
    }

    // ---- Phase 2: identity change detection --------------------------------

    #[test]
    fn an_identity_key_change_drops_verification() {
        // The user compared a safety number against the old key. That
        // comparison says nothing about the new one.
        let (_dir, path) = temp();
        let s = store(&path);
        s.put_contact(&contact("c1", "Mai")).expect("contact");
        s.set_verified("c1", true).expect("verifies");

        let changed = s
            .replace_identity_key("c1", b"new-key", 1_700_000_000)
            .expect("replaces");

        assert!(changed);
        assert!(
            !s.contact("c1").expect("reads").expect("exists").verified,
            "a changed identity key left the contact marked verified"
        );
    }

    #[test]
    fn an_identity_change_records_what_it_replaced_and_when() {
        let (_dir, path) = temp();
        let s = store(&path);
        s.put_contact(&contact("c1", "Mai")).expect("contact");
        s.replace_identity_key("c1", b"new-key", 1_700_000_000)
            .expect("replaces");

        let change = s.identity_change("c1").expect("reads").expect("recorded");
        assert_eq!(change.previous_key, b"k".to_vec());
        assert_eq!(change.changed_at, 1_700_000_000);
        assert!(!change.acknowledged);
        assert_eq!(s.unacknowledged_identity_changes().expect("reads").len(), 1);
    }

    #[test]
    fn the_same_key_is_not_an_identity_change() {
        // Called on every received message, so an unchanged key must be silent.
        let (_dir, path) = temp();
        let s = store(&path);
        s.put_contact(&contact("c1", "Mai")).expect("contact");
        s.set_verified("c1", true).expect("verifies");

        assert!(!s
            .replace_identity_key("c1", b"k", 1_700_000_000)
            .expect("checks"));
        assert!(
            s.contact("c1").expect("reads").expect("exists").verified,
            "an unchanged key dropped verification"
        );
        assert!(s.identity_change("c1").expect("reads").is_none());
    }

    #[test]
    fn acknowledging_an_identity_change_does_not_verify_the_contact() {
        // "Continue without verifying" answers the question. It does not
        // establish that the person on the other end is who they were.
        let (_dir, path) = temp();
        let s = store(&path);
        s.put_contact(&contact("c1", "Mai")).expect("contact");
        s.replace_identity_key("c1", b"new-key", 1_700_000_000)
            .expect("replaces");

        s.acknowledge_identity_change("c1").expect("acknowledges");

        assert!(
            s.identity_change("c1")
                .expect("reads")
                .expect("exists")
                .acknowledged
        );
        assert!(s
            .unacknowledged_identity_changes()
            .expect("reads")
            .is_empty());
        assert!(
            !s.contact("c1").expect("reads").expect("exists").verified,
            "acknowledging a key change marked the contact verified"
        );
    }

    // ---- Phase 2: migration ------------------------------------------------

    #[test]
    fn a_phase_one_database_is_carried_forward() {
        // The upgrade path that matters: a database written before the Phase 2
        // tables existed has to open, keep its contents, and gain the new
        // columns. Simulated by stamping user_version back to 1 and dropping
        // what v2 added.
        let (_dir, path) = temp();
        {
            let s = store(&path);
            s.put_identity("Brian", "abc", b"pub").expect("identity");
            s.put_contact(&contact("c1", "Mai")).expect("contact");
            s.put_conversation("v1", "c1").expect("conversation");
            s.put_message(&StoredMessage {
                id: "m1".into(),
                conversation_id: "v1".into(),
                direction: Direction::Sent,
                body: "survives the migration".into(),
                at: 1_700_000_000,
            })
            .expect("message");

            s.conn
                .execute_batch(
                    "DROP TABLE settings;
                     DROP TABLE identity_changes;
                     DROP TABLE outbox;
                     ALTER TABLE conversations DROP COLUMN disappear_after;
                     PRAGMA user_version = 1;",
                )
                .expect("reverts to the v1 shape");
        }

        let s = store(&path);
        assert_eq!(
            s.messages("v1").expect("reads")[0].body,
            "survives the migration"
        );
        assert_eq!(
            s.retention_policy().expect("reads"),
            RetentionPolicy::Forever
        );
        assert_eq!(s.queued_count().expect("counts"), 0);
        assert_eq!(s.disappear_after("v1").expect("reads"), None);
    }

    #[test]
    fn migrating_twice_is_harmless() {
        let (_dir, path) = temp();
        let s = store(&path);
        s.migrate().expect("second migration");
        s.migrate().expect("third migration");
        assert_eq!(
            s.retention_policy().expect("reads"),
            RetentionPolicy::Forever
        );
    }

    #[test]
    fn wipe_takes_the_queue_and_the_identity_history_too() {
        let (_dir, path) = temp();
        let s = store(&path);
        s.put_contact(&contact("c1", "Mai")).expect("contact");
        s.put_conversation("v1", "c1").expect("conversation");
        s.enqueue(&QueuedMessage {
            id: "q1".into(),
            conversation_id: "v1".into(),
            peer_inbox: "inbox".into(),
            blob: b"QUEUED-BODY-CANARY".to_vec(),
            at: 1,
            attempts: 0,
            last_error: None,
        })
        .expect("enqueues");
        s.replace_identity_key("c1", b"new-key", 1)
            .expect("replaces");
        s.set_retention_policy(RetentionPolicy::Days7).expect("set");

        s.wipe().expect("wipes");

        assert_eq!(s.queued_count().expect("counts"), 0);
        assert!(s
            .unacknowledged_identity_changes()
            .expect("reads")
            .is_empty());
        assert_eq!(
            s.retention_policy().expect("reads"),
            RetentionPolicy::Forever,
            "a wipe left the previous retention setting behind"
        );

        let bytes = std::fs::read(&path).expect("readable");
        let needle = &b"QUEUED-BODY-CANARY"[..];
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "a queued message body survived the wipe on disk"
        );
    }
}
