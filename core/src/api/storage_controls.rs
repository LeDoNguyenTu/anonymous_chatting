//! What the user controls about their own data.
//!
//! SPEC §6.7.7 lists these as plain-language controls with a one-line
//! consequence each. That framing is not only a UI concern: every operation
//! here is named for what the user gets, and each one either does the thing or
//! reports that it did not. Nothing here reports success on a partial result.

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
}
