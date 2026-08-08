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
use crate::storage::{Direction, QueuedMessage, StoredAttachment, StoredContact, StoredMessage};
use crate::transport::Route;

use super::compression;
use super::{now, ApiError, Message, Payload, Pouch, Received};

/// The one name this build ever writes to the manifest's compression stage.
///
/// Naming the algorithm is what SPEC §2.5 asks the manifest to do everywhere
/// else — "encrypted" alone was never good enough either.
const COMPRESSION_ALGORITHM: &str = "zstd";

/// A local identifier for a message the relay has not accepted yet.
///
/// Delivered messages are keyed by the identifier the relay returns. A queued
/// message has no such identifier yet but still has to appear in the thread, so
/// it gets a random one of its own. Random rather than sequential for the same
/// reason the relay's are (D-010): a counter is an ordering oracle.
fn local_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

impl Pouch {
    /// Encrypts and posts one payload. Shared by `send_message` and the
    /// introduction sent when a conversation is created.
    pub(super) async fn send_payload(
        &mut self,
        conversation_id: &str,
        payload: &Payload,
    ) -> Result<String, ApiError> {
        let encoded = serde_json::to_vec(payload).map_err(|_| CryptoError::Encryption)?;
        // Every payload is compressed, always — see send_message for why this
        // is not a per-message choice. Padded after compressing, same ordering
        // as the attachment pipeline (SPEC §7.1) — padding before compression
        // would defeat compression, and padding after encryption would not
        // hide size at all.
        let compressed = compression::compress(&encoded).map_err(|_| CryptoError::Encryption)?;
        let padded = crate::padding::pad(&compressed);

        let conversation = self
            .conversations
            .get_mut(conversation_id)
            .ok_or(ApiError::UnknownConversation)?;

        let blob = conversation.encrypt(&self.identity, &padded, &self.provider)?;
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
        // Anything already waiting goes first, so a reconnected client does not
        // deliver today's message ahead of yesterday's.
        self.flush_outbox().await?;

        let conversation = self
            .conversations
            .get_mut(conversation_id)
            .ok_or(ApiError::UnknownConversation)?;

        let mut manifest = Manifest::new(body.len());

        let encoded = serde_json::to_vec(&Payload::Text(body.to_string()))
            .map_err(|_| CryptoError::Encryption)?;

        // Compress before encrypt, in isolation (D-009, SPEC §6.5.2) — never
        // across messages, never sharing state with any other call. This is
        // the one place a message's compressed size is reported, because it
        // is the one place a real Payload is being compressed rather than a
        // synthetic one in a test.
        let compressed = compression::compress(&encoded).map_err(|_| CryptoError::Encryption)?;
        manifest.compressed(COMPRESSION_ALGORITHM, encoded.len(), compressed.len());

        // Pad after compressing, before encrypting (SPEC §7.1's ordering, the
        // same one the attachment pipeline already enforces). Every message
        // lands in a fixed bucket, so blob size stops distinguishing a
        // two-word reply from a paragraph — D-041.
        let padded = crate::padding::pad(&compressed);
        manifest.padded(compressed.len(), padded.len());

        let blob = conversation.encrypt(&self.identity, &padded, &self.provider)?;
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

                // The ratchet advanced when this was encrypted, so the blob has
                // to be kept and the advance has to be recorded. Dropping
                // either would mean the next send reuses a generation the peer
                // has already been promised.
                let local_id = local_id();
                self.store.put_message(&StoredMessage {
                    id: local_id.clone(),
                    conversation_id: conversation_id.to_string(),
                    direction: Direction::Sent,
                    body: body.to_string(),
                    at: now(),
                })?;
                self.store.enqueue(&QueuedMessage {
                    id: local_id,
                    conversation_id: conversation_id.to_string(),
                    peer_inbox,
                    blob,
                    at: now(),
                    attempts: 1,
                    last_error: Some(err.to_string()),
                })?;
                self.persist_mls_state()?;

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

    /// Posts everything waiting, oldest first, and stops at the first failure.
    ///
    /// Returns how many were delivered. SPEC §8.2 requires the queue retry on
    /// reconnect; this is the retry, and every path that touches the relay
    /// calls it first so "reconnect" needs no separate detection.
    ///
    /// Stopping at the first failure rather than continuing is deliberate. The
    /// blobs are ratchet generations in order, and posting a later one past a
    /// blocked earlier one hands the recipient exactly the out-of-order
    /// sequence that cost half a run in D-028.
    pub async fn flush_outbox(&mut self) -> Result<usize, ApiError> {
        let mut delivered = 0;

        for queued in self.store.queued()? {
            match self.relay.send(&queued.peer_inbox, &queued.blob).await {
                Ok(_) => {
                    self.store.dequeue(&queued.id)?;
                    delivered += 1;
                }
                Err(err) => {
                    self.store.record_attempt(&queued.id, &err.to_string())?;
                    break;
                }
            }
        }

        Ok(delivered)
    }

    /// Collects, decrypts, and stores everything waiting in this inbox.
    ///
    /// Returns what arrived. A blob that fails to decrypt is reported as an
    /// error rather than skipped — a silently dropped message hides exactly the
    /// event the user needs to see.
    pub async fn receive_messages(&mut self) -> Result<Received, ApiError> {
        // Reaching the relay at all means the connection is back, so this is
        // the natural retry point for anything queued while it was not.
        self.flush_outbox().await?;

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
                    // Every payload this build sends is compressed (D-009) and
                    // padded (D-041), so every payload it receives is unpadded
                    // and decompressed before being parsed. Anything that fails
                    // any of those steps — corrupt, tampered, or sent by a
                    // build from before either landed — is protocol noise or a
                    // version mismatch, not a message. It is not rendered as
                    // one.
                    let Some(unpadded) = crate::padding::unpad(&message.plaintext) else {
                        continue;
                    };
                    let Ok(decompressed) = compression::decompress(&unpadded) else {
                        continue;
                    };
                    let Ok(payload) = serde_json::from_slice::<Payload>(&decompressed) else {
                        continue;
                    };

                    // Identity change detection, before anything is acted on.
                    //
                    // `sender_key` comes from the authenticated MLS credential,
                    // so it is what the sender proved rather than what the relay
                    // asserted. If it differs from the key this conversation was
                    // established with, the person on the other end is presenting
                    // a different identity: `replace_identity_key` records the
                    // old one, notes the date, and drops verification. The user
                    // is told; nothing is decided for them (SPEC §6.7.6).
                    if let Some(existing) = self.store.conversation_contact(&conversation_id)? {
                        self.store
                            .replace_identity_key(&existing, &message.sender_key, now())?;
                    }

                    match payload {
                        Payload::Hello {
                            inbox_id,
                            display_name,
                        } => {
                            // The sender says where to reply and what to call
                            // them. Learned over the authenticated channel, so
                            // the relay cannot have influenced it — but it still
                            // does not make them verified.
                            //
                            // The contact already attached to this conversation
                            // wins over one derived from the key. Deriving it
                            // afresh would turn a key change into a second
                            // contact rather than a warning about the first.
                            let contact_id = self
                                .store
                                .conversation_contact(&conversation_id)?
                                .unwrap_or_else(|| hex::encode(&message.sender_key));
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
                        Payload::Attachment {
                            bucket_id,
                            key,
                            filename,
                            format,
                        } => {
                            // Fetched before the message row is written, but
                            // stored after it — `attachments.id` references
                            // `messages.id`, so the message row has to exist
                            // first, even though the network round trip that
                            // can fail happens before either write.
                            let already_have_it =
                                self.store.has_attachment(&envelope.message_id)?;
                            let content = if already_have_it {
                                None
                            } else {
                                let Some(content) = self.fetch_attachment(&bucket_id, &key).await?
                                else {
                                    // Not there yet, or already collected by
                                    // a run that crashed before storing it.
                                    // Left unacknowledged, same as a message
                                    // that fails to decrypt — it survives to
                                    // the next poll rather than being lost.
                                    continue;
                                };
                                Some(content)
                            };

                            let stored = StoredMessage {
                                id: envelope.message_id.clone(),
                                conversation_id,
                                direction: Direction::Received,
                                body: super::attachments::attachment_placeholder(&filename),
                                at: now(),
                            };
                            self.store.put_message(&stored)?;

                            // Idempotent: a crash between erasing the bucket
                            // and acknowledging this reference must not try
                            // to re-fetch a bucket that is now empty by
                            // design rather than by loss — `already_have_it`
                            // covers exactly that replay.
                            if let Some(content) = content {
                                self.store.put_attachment(&StoredAttachment {
                                    id: envelope.message_id.clone(),
                                    conversation_id: stored.conversation_id.clone(),
                                    filename: filename.clone(),
                                    format,
                                    content,
                                    at: now(),
                                })?;
                            }

                            received.messages.push(Message {
                                id: stored.id,
                                outgoing: false,
                                body: stored.body,
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

        // Retention is enforced here as well as on open, so a client left
        // running for a week under a 24-hour policy does not accumulate one.
        self.store.purge_expired(now())?;

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
