//! Contacts: exchanging invite codes and verifying who is on the other end.
//!
//! Separated from messaging because these are the operations that decide *who*
//! a conversation is with, and a reviewer should be able to read them end to
//! end without wading through send and receive.

use crate::crypto::{Conversation, InviteCode, SafetyNumber};
use crate::storage::StoredContact;

use super::{ApiError, ConversationSummary, IdentityState, Payload, Pouch};

impl Pouch {
    /// Produces an invite code to hand to someone.
    ///
    /// Contains a public key, an inbox address, and a single-use key package.
    /// No name, no phone number, no email (SPEC §6.7.4).
    pub fn invite_code(&mut self) -> Result<String, ApiError> {
        let code = self.identity.invite_code(&self.provider)?;
        self.persist_mls_state()?;
        Ok(code.encode()?)
    }

    /// Starts a conversation from someone else's invite code.
    ///
    /// The contact is stored **unverified**. It stays that way until the user
    /// compares a safety number out of band and says so.
    pub async fn add_contact(
        &mut self,
        display_name: &str,
        encoded_invite: &str,
    ) -> Result<String, ApiError> {
        let invite = InviteCode::decode(encoded_invite)?;

        let (conversation, welcome) =
            Conversation::create(&self.identity, &invite, &self.provider)?;

        let contact_id = hex::encode(&invite.public_key);
        let conversation_id = conversation.group_id();

        self.store.put_contact(&StoredContact {
            id: contact_id.clone(),
            display_name: display_name.to_string(),
            inbox_id: invite.inbox_id.clone(),
            public_key: invite.public_key.clone(),
            verified: false,
        })?;
        self.store.put_conversation(&conversation_id, &contact_id)?;

        // The Welcome goes to the peer's inbox like any other blob. The relay
        // cannot tell it apart from a message.
        self.relay.send(&invite.inbox_id, &welcome).await?;

        self.conversations
            .insert(conversation_id.clone(), conversation);
        self.persist_mls_state()?;

        // Tell them where to reply, inside the encrypted channel.
        let hello = Payload::Hello {
            inbox_id: self.identity.inbox_id().to_string(),
            display_name: self.identity.display_name().to_string(),
        };
        self.send_payload(&conversation_id, &hello).await?;

        Ok(conversation_id)
    }

    /// The safety number for a contact, to compare out of band.
    pub fn safety_number(&self, contact_id: &str) -> Result<SafetyNumber, ApiError> {
        let contact = self
            .store
            .contact(contact_id)?
            .ok_or(ApiError::UnknownContact)?;
        Ok(SafetyNumber::derive(
            self.identity.public_key(),
            &contact.public_key,
        ))
    }

    /// Marks a contact verified, or clears that mark.
    ///
    /// Only ever called from an explicit user action after the user has
    /// actually compared the number.
    pub fn verify_contact(&self, contact_id: &str, verified: bool) -> Result<(), ApiError> {
        self.store.set_verified(contact_id, verified)?;
        Ok(())
    }

    /// Every conversation on this device.
    pub fn conversations(&self) -> Result<Vec<ConversationSummary>, ApiError> {
        let mut out = Vec::new();
        for contact in self.store.contacts()? {
            for conversation_id in self.store.conversations_for(&contact.id)? {
                let messages = self.store.messages(&conversation_id).unwrap_or_default();
                out.push(ConversationSummary {
                    id: conversation_id,
                    contact_name: contact.display_name.clone(),
                    contact_id: contact.id.clone(),
                    // Never Verified unless the user actually said so.
                    identity: if contact.verified {
                        IdentityState::Verified
                    } else {
                        IdentityState::Unverified
                    },
                    last_message: messages.last().map(|m| m.body.clone()),
                });
            }
        }
        Ok(out)
    }
}
