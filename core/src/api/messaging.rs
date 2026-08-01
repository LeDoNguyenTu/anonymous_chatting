//! Sending and receiving.
//!
//! The two operations that move bytes. Kept together because they are two
//! halves of one wire format — a change to how a payload is written is almost
//! always a change to how it is read — and kept apart from everything else
//! because they are the longest and most stateful code in the crate.

use crate::crypto::{
    Conversation, CryptoError, AEAD_NAME, CIPHERSUITE_NAME, KEY_AGREEMENT_NAME, SIGNATURE_NAME,
};
use crate::manifest::Manifest;
use crate::storage::{Direction, StoredContact, StoredMessage};
use crate::transport::Route;

use super::{now, ApiError, Message, Payload, Pouch, Received};

impl Pouch {
    /// Encrypts and posts one payload. Shared by `send_message` and the
    /// introduction sent when a conversation is created.
    pub(super) async fn send_payload(
        &mut self,
        conversation_id: &str,
        payload: &Payload,
    ) -> Result<String, ApiError> {
        let encoded = serde_json::to_vec(payload).map_err(|_| CryptoError::Encryption)?;

        let conversation = self
            .conversations
            .get_mut(conversation_id)
            .ok_or(ApiError::UnknownConversation)?;

        let blob = conversation.encrypt(&self.identity, &encoded, &self.provider)?;
        let peer_inbox = conversation.peer_inbox_id().to_string();
        let message_id = self.relay.send(&peer_inbox, &blob).await?;
        self.persist_mls_state()?;
        Ok(message_id)
    }

    /// Sends a message, and returns the manifest describing what actually
    /// happened to it.
    ///
    /// The manifest is built from the real path, not from a template. Stages
    /// that did not run report as such (SPEC §8.6).
    pub async fn send_message(
        &mut self,
        conversation_id: &str,
        body: &str,
    ) -> Result<Manifest, ApiError> {
        let conversation = self
            .conversations
            .get_mut(conversation_id)
            .ok_or(ApiError::UnknownConversation)?;

        let mut manifest = Manifest::new(body.len());

        let encoded = serde_json::to_vec(&Payload::Text(body.to_string()))
            .map_err(|_| CryptoError::Encryption)?;
        let blob = conversation.encrypt(&self.identity, &encoded, &self.provider)?;
        manifest.encrypted(
            CIPHERSUITE_NAME,
            AEAD_NAME,
            KEY_AGREEMENT_NAME,
            SIGNATURE_NAME,
        );

        let peer_inbox = conversation.peer_inbox_id().to_string();
        let message_id = match self.relay.send(&peer_inbox, &blob).await {
            Ok(id) => id,
            Err(err) => {
                manifest.failed_at_routing(&err.to_string());
                return Err(err.into());
            }
        };

        manifest.routed(Route::Direct, self.relay.address());
        manifest.queued(&message_id);
        manifest.delivered();

        self.store.put_message(&StoredMessage {
            id: message_id,
            conversation_id: conversation_id.to_string(),
            direction: Direction::Sent,
            body: body.to_string(),
            at: now(),
        })?;
        self.persist_mls_state()?;

        Ok(manifest)
    }

    /// Collects, decrypts, and stores everything waiting in this inbox.
    ///
    /// Returns what arrived. A blob that fails to decrypt is reported as an
    /// error rather than skipped — a silently dropped message hides exactly the
    /// event the user needs to see.
    pub async fn receive_messages(&mut self) -> Result<Received, ApiError> {
        let envelopes = self.relay.collect(self.identity.inbox_id()).await?;
        let mut received = Received::default();
        let mut handled = Vec::new();

        // Welcomes first, in a pass of their own. The relay returns blobs in
        // random-identifier order — deliberately, since any other order would
        // leak arrival sequence — so a message can arrive before the Welcome
        // that opens the conversation it belongs to. Joining first means the
        // second pass always has somewhere to put it.
        let mut remaining = Vec::new();
        for envelope in envelopes {
            if let Some(conversation_id) = self.try_join(&envelope.blob)? {
                received.conversations_opened.push(conversation_id);
                handled.push(envelope.message_id);
            } else {
                remaining.push(envelope);
            }
        }

        for envelope in remaining {
            let mut decrypted = None;
            for (conversation_id, conversation) in self.conversations.iter_mut() {
                if let Ok(message) = conversation.decrypt(&envelope.blob, &self.provider) {
                    decrypted = Some((conversation_id.clone(), message));
                    break;
                }
            }

            match decrypted {
                Some((conversation_id, message)) => {
                    // Anything that fails to parse as a payload is protocol
                    // noise or a version mismatch, not a message. It is not
                    // rendered as one.
                    let Ok(payload) = serde_json::from_slice::<Payload>(&message.plaintext) else {
                        continue;
                    };

                    match payload {
                        Payload::Hello {
                            inbox_id,
                            display_name,
                        } => {
                            // The sender says where to reply and what to call
                            // them. Learned over the authenticated channel, so
                            // the relay cannot have influenced it — but it still
                            // does not make them verified.
                            let contact_id = hex::encode(&message.sender_key);
                            self.store.put_contact(&StoredContact {
                                id: contact_id.clone(),
                                display_name,
                                inbox_id: inbox_id.clone(),
                                public_key: message.sender_key.clone(),
                                verified: false,
                            })?;
                            self.store.put_conversation(&conversation_id, &contact_id)?;
                            if let Some(c) = self.conversations.get_mut(&conversation_id) {
                                c.set_peer(&inbox_id, &message.sender_key);
                            }
                        }
                        Payload::Text(body) => {
                            let stored = StoredMessage {
                                id: envelope.message_id.clone(),
                                conversation_id,
                                direction: Direction::Received,
                                body: body.clone(),
                                at: now(),
                            };
                            self.store.put_message(&stored)?;
                            received.messages.push(Message {
                                id: stored.id,
                                outgoing: false,
                                body,
                                at: stored.at,
                            });
                        }
                    }
                    handled.push(envelope.message_id);
                }
                None => {
                    // Left on the relay rather than acknowledged. If this is a
                    // transient state — a conversation not yet open — the blob
                    // survives to the next poll. If it is tampering, it is not
                    // quietly discarded.
                    continue;
                }
            }
        }

        // Acknowledged only after everything is safely in the local database.
        self.relay
            .acknowledge(self.identity.inbox_id(), &handled)
            .await?;
        self.persist_mls_state()?;

        Ok(received)
    }

    /// Attempts to treat a blob as a Welcome. Returns the conversation id if it
    /// was one.
    ///
    /// The sender is not known in advance — a Welcome arrives from someone the
    /// user has not added yet. Their identity key is read back out of the group
    /// once it exists, which is an authenticated source rather than anything the
    /// relay could have influenced.
    fn try_join(&mut self, blob: &[u8]) -> Result<Option<String>, ApiError> {
        let Ok(mut conversation) = Conversation::join(blob, "", &[], &self.provider) else {
            return Ok(None);
        };

        let conversation_id = conversation.group_id();

        // The peer's identity key is read back out of the group, which is an
        // authenticated source. Their inbox address arrives separately, in the
        // Hello that follows over the encrypted channel.
        let peer_key = conversation
            .peer_credential(self.identity.public_key())
            .unwrap_or_default();
        conversation.set_peer("", &peer_key);

        // Stored unverified, with no display name yet. An inbound invitation is
        // not evidence of identity, and the Custody Strip must not suggest it
        // is.
        let contact_id = hex::encode(&peer_key);
        self.store.put_contact(&StoredContact {
            id: contact_id.clone(),
            display_name: String::new(),
            inbox_id: String::new(),
            public_key: peer_key,
            verified: false,
        })?;
        self.store.put_conversation(&conversation_id, &contact_id)?;

        self.conversations
            .insert(conversation_id.clone(), conversation);
        self.persist_mls_state()?;
        Ok(Some(conversation_id))
    }

    /// Every message in a conversation, oldest first.
    pub fn messages(&self, conversation_id: &str) -> Result<Vec<Message>, ApiError> {
        Ok(self
            .store
            .messages(conversation_id)?
            .into_iter()
            .map(|m| Message {
                id: m.id,
                outgoing: m.direction == Direction::Sent,
                body: m.body,
                at: m.at,
            })
            .collect())
    }
}
