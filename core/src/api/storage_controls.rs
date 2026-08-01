//! What the user controls about their own data.
//!
//! SPEC §6.7.7 lists these as plain-language controls with a one-line
//! consequence each. That framing is not only a UI concern: every operation
//! here is named for what the user gets, and each one either does the thing or
//! reports that it did not. Nothing here reports success on a partial result.

use crate::keying::{self, KeyingError};
use crate::storage::RetentionPolicy;

use super::{now, ApiError, IdentityChangeNotice, Pouch};

impl Pouch {
    /// How long this device keeps messages.
    pub fn retention_policy(&self) -> Result<RetentionPolicy, ApiError> {
        Ok(self.store.retention_policy()?)
    }

    /// Changes how long this device keeps messages, and applies it immediately.
    ///
    /// Applying it now rather than at the next restart matters: a user who
    /// switches from "forever" to "24 hours" has just asked for the older
    /// messages to go. Leaving them until some later sweep would mean the
    /// setting said one thing while the disk said another.
    ///
    /// Returns how many messages were deleted as a result.
    pub fn set_retention_policy(&mut self, policy: RetentionPolicy) -> Result<usize, ApiError> {
        self.store.set_retention_policy(policy)?;
        Ok(self.store.purge_expired(now())?)
    }

    /// The disappearing-message interval for one conversation, in seconds.
    ///
    /// `None` means the conversation follows the device-wide setting.
    pub fn disappearing_messages(&self, conversation_id: &str) -> Result<Option<u64>, ApiError> {
        Ok(self.store.disappear_after(conversation_id)?)
    }

    /// Sets, or clears, disappearing messages for one conversation, and applies
    /// it immediately.
    ///
    /// Returns how many messages were deleted as a result.
    pub fn set_disappearing_messages(
        &mut self,
        conversation_id: &str,
        seconds: Option<u64>,
    ) -> Result<usize, ApiError> {
        if self.store.conversation_contact(conversation_id)?.is_none() {
            return Err(ApiError::UnknownConversation);
        }
        self.store.set_disappear_after(conversation_id, seconds)?;
        Ok(self.store.purge_expired(now())?)
    }

    /// Deletes everything that has outlived its retention.
    ///
    /// Called on open and after every receive, so a device left running for a
    /// week does not hold a month of messages under a 24-hour policy.
    pub fn purge_expired(&mut self) -> Result<usize, ApiError> {
        Ok(self.store.purge_expired(now())?)
    }

    /// Identity changes the user has not yet answered.
    ///
    /// Drives the modal at SPEC §6.7.6. Returns the contact's name and the date
    /// so the copy can state a fact rather than a vague warning.
    pub fn identity_changes(&self) -> Result<Vec<IdentityChangeNotice>, ApiError> {
        let mut out = Vec::new();
        for change in self.store.unacknowledged_identity_changes()? {
            // A change whose contact has since been removed is not something to
            // interrupt anyone about.
            let Some(contact) = self.store.contact(&change.contact_id)? else {
                continue;
            };
            out.push(IdentityChangeNotice {
                contact_id: change.contact_id,
                contact_name: contact.display_name,
                changed_at: change.changed_at,
            });
        }
        Ok(out)
    }

    /// Records that the user has seen and answered an identity change warning.
    ///
    /// This is not verification. A user who chose "continue without verifying"
    /// has answered the question and nothing more — the contact stays
    /// unverified, and the Custody Strip keeps saying so.
    pub fn acknowledge_identity_change(&self, contact_id: &str) -> Result<(), ApiError> {
        self.store.acknowledge_identity_change(contact_id)?;
        Ok(())
    }

    /// How many messages are waiting for the relay to come back.
    pub fn queued_count(&self) -> Result<usize, ApiError> {
        Ok(self.store.queued_count()?)
    }

    /// Whether opening this device requires a passphrase.
    pub fn is_passphrase_protected(&self) -> Result<bool, ApiError> {
        Ok(keying::key_source(&self.db_path)?.needs_passphrase())
    }

    /// Protects this device with a passphrase, re-encrypting the database.
    ///
    /// The passphrase becomes the key through Argon2id with the parameters
    /// pinned in `keying`. Nothing derived from it is stored: the salt beside
    /// the database is not secret and is useless alone, and the device key file
    /// is deleted, so after this call the database cannot be opened by anyone
    /// who has only the disk.
    ///
    /// **This cannot be undone by guessing.** A forgotten passphrase means the
    /// history is gone, which is the point, and the UI has to say so before
    /// calling this.
    ///
    /// The sidecar is written before the re-encryption and rolled back if the
    /// re-encryption fails, so an error leaves the database openable exactly as
    /// it was. A crash between the two steps is the one case this cannot
    /// repair: the file would then be encrypted under the passphrase while the
    /// sidecar still named the old source. It fails loudly as a wrong key
    /// rather than quietly, which is the behaviour to prefer if only one is
    /// available.
    pub fn set_passphrase(&mut self, passphrase: &str) -> Result<(), ApiError> {
        let previous = keying::key_source(&self.db_path)?;
        let salt = keying::new_salt();
        let mut key =
            keying::key_from_passphrase(passphrase, &salt).map_err(|_| KeyingError::Derivation)?;

        keying::set_key_source(&self.db_path, &keying::KeySource::Passphrase { salt })?;

        if let Err(err) = self.store.rekey(&mut key) {
            // Put it back the way it was rather than leaving a sidecar that
            // describes a re-encryption which did not happen.
            keying::set_key_source(&self.db_path, &previous)?;
            return Err(err.into());
        }

        // Only now is the placeholder key redundant. Removing it earlier would
        // mean a failed rekey had destroyed the only way in.
        let device_key = keying::device_key_path(&self.db_path);
        if device_key.exists() {
            std::fs::remove_file(&device_key).map_err(KeyingError::Io)?;
        }

        Ok(())
    }

    /// Removes passphrase protection, returning to the device-file placeholder.
    ///
    /// Offered because a user who turned it on must be able to turn it off, but
    /// it is a downgrade and the UI is required to say so: the replacement key
    /// sits in a file beside the database and protects against nothing.
    pub fn clear_passphrase(&mut self) -> Result<(), ApiError> {
        let previous = keying::key_source(&self.db_path)?;
        if !previous.needs_passphrase() {
            return Ok(());
        }

        // Generated before the sidecar changes, so a failure anywhere below
        // leaves a database whose key still exists.
        let device_key = keying::device_key_path(&self.db_path);
        let mut key = keying::development_device_key(&device_key)?;

        keying::set_key_source(&self.db_path, &keying::KeySource::DeviceFile)?;

        if let Err(err) = self.store.rekey(&mut key) {
            keying::set_key_source(&self.db_path, &previous)?;
            return Err(err.into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StoredContact, StoredMessage};
    use crate::transport::RelayConfig;
    use crate::IdentityState;

    /// A client with one contact and one conversation, and no relay behind it.
    ///
    /// In-crate rather than in `tests/` because reaching the store directly is
    /// the point: an identity key changing is something a *peer* does, and
    /// staging a second device to do it would test MLS rather than this
    /// client's reaction to the fact.
    fn client(dir: &tempfile::TempDir) -> (Pouch, String) {
        let db = dir.path().join("pouch.db").to_string_lossy().into_owned();
        let mut key = vec![0x31; 32];
        let pouch = Pouch::create(
            "Brian",
            &db,
            &mut key,
            RelayConfig::insecure_local("http://127.0.0.1:1"),
        )
        .expect("client");

        let contact_id = "c1".to_string();
        pouch
            .store
            .put_contact(&StoredContact {
                id: contact_id.clone(),
                display_name: "Mai".into(),
                inbox_id: "inbox".into(),
                public_key: b"the original key".to_vec(),
                verified: false,
            })
            .expect("contact");
        pouch
            .store
            .put_conversation("v1", &contact_id)
            .expect("conversation");

        (pouch, contact_id)
    }

    #[test]
    fn a_changed_identity_key_reaches_the_custody_strip_and_survives_until_answered() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (pouch, contact_id) = client(&dir);

        pouch.verify_contact(&contact_id, true).expect("verifies");
        assert_eq!(
            pouch.conversations().expect("reads")[0].identity,
            IdentityState::Verified
        );
        assert!(pouch.identity_changes().expect("reads").is_empty());

        // The peer presents a different identity key.
        pouch
            .store
            .replace_identity_key(&contact_id, b"a different key", 1_700_000_000)
            .expect("records");

        assert_eq!(
            pouch.conversations().expect("reads")[0].identity,
            IdentityState::KeyChanged,
            "a changed identity key did not reach the Custody Strip"
        );

        let changes = pouch.identity_changes().expect("reads");
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].contact_name, "Mai");
        assert_eq!(changes[0].changed_at, 1_700_000_000);

        // Answering the modal clears the interruption without claiming a
        // verification the user never performed.
        pouch
            .acknowledge_identity_change(&contact_id)
            .expect("acknowledges");
        assert!(pouch.identity_changes().expect("reads").is_empty());
        assert_eq!(
            pouch.conversations().expect("reads")[0].identity,
            IdentityState::Unverified,
            "acknowledging a key change marked the contact verified"
        );
    }

    #[test]
    fn changing_retention_deletes_immediately_and_reports_how_much() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (mut pouch, _) = client(&dir);

        let now = super::now();
        for (i, age) in [60u64, 10 * 86_400].iter().enumerate() {
            pouch
                .store
                .put_message(&StoredMessage {
                    id: format!("m{i}"),
                    conversation_id: "v1".into(),
                    direction: crate::storage::Direction::Sent,
                    body: format!("body {i}"),
                    at: now - age,
                })
                .expect("message");
        }

        assert_eq!(
            pouch
                .set_retention_policy(RetentionPolicy::Days7)
                .expect("sets"),
            1,
            "switching to a shorter policy did not delete the older message"
        );
        assert_eq!(pouch.messages("v1").expect("reads").len(), 1);
    }

    #[test]
    fn disappearing_messages_cannot_be_set_on_a_conversation_that_does_not_exist() {
        // Otherwise the setting is accepted, stored nowhere, and silently does
        // nothing — a control that lies about being in effect.
        let dir = tempfile::tempdir().expect("temp dir");
        let (mut pouch, _) = client(&dir);

        assert!(matches!(
            pouch.set_disappearing_messages("no-such-conversation", Some(60)),
            Err(ApiError::UnknownConversation)
        ));
    }
}
