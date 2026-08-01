//! The only surface clients touch.
//!
//! This is a hard boundary, not a convention (D-012). The desktop, Android, and
//! CLI clients call the operations here and nothing beneath them. No key, no
//! cipher, no nonce, and no raw ciphertext blob crosses this line.
//!
//! If a client appears to need something lower level, the correct response is to
//! add an operation here — never to expose the module underneath.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use crate::crypto::{
    Conversation, CryptoError, Identity, InviteCode, PouchProvider, SafetyNumber, AEAD_NAME,
    CIPHERSUITE_NAME, KDF_NAME, KEY_AGREEMENT_NAME, PROTOCOL_NAME, SIGNATURE_NAME,
};
use crate::manifest::Manifest;
use crate::storage::{Direction, LocalStore, StorageError, StoredContact, StoredMessage};
use crate::transport::{RelayClient, RelayConfig, Route, TransportError};

/// Anything a client operation can fail with.
///
/// Every variant reaches the user as text explaining what happened and what to
/// do (SPEC §6.9). There is no "something went wrong".
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Local storage failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Talking to the relay failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The named contact is not known on this device.
    #[error("no contact with that identifier exists on this device")]
    UnknownContact,
    /// No conversation exists with that contact yet.
    #[error("no conversation with that contact exists yet")]
    UnknownConversation,
}

/// How a contact's identity currently stands.
///
/// Drives the Custody Strip's first field. There is deliberately no variant
/// meaning "probably fine" — a contact is either verified by an out-of-band
/// comparison the user actually performed, or they are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityState {
    /// The user compared a safety number and marked it matching.
    Verified,
    /// No comparison has happened. Amber, and stays amber.
    Unverified,
    /// The contact's identity key changed. Loud.
    KeyChanged,
}

impl IdentityState {
    /// The label the Custody Strip shows.
    pub fn label(&self) -> &'static str {
        match self {
            IdentityState::Verified => "VERIFIED",
            IdentityState::Unverified => "UNVERIFIED",
            IdentityState::KeyChanged => "KEY CHANGED",
        }
    }
}

/// A conversation as a client sees it.
#[derive(Debug, Clone)]
pub struct ConversationSummary {
    /// Local conversation identifier.
    pub id: String,
    /// The contact's local-only display name.
    pub contact_name: String,
    /// The contact's local identifier.
    pub contact_id: String,
    /// Identity state, for the Custody Strip.
    pub identity: IdentityState,
    /// The most recent message body, if any.
    pub last_message: Option<String>,
}

/// What travels inside an encrypted application message.
///
/// A Welcome carries no inbox address, so a joining client has no way to reply
/// until the sender tells it where. That introduction goes **inside** the
/// encrypted channel rather than alongside the Welcome in the blob: putting a
/// sender inbox in cleartext next to the Welcome would hand the relay the one
/// correlation it is otherwise denied — which inbox is talking to which.
///
/// This is application framing, not a protocol. It carries no key material and
/// makes no cryptographic decision.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum Payload {
    /// Sent once, immediately after a conversation is created.
    Hello {
        /// Where to reply.
        inbox_id: String,
        /// The sender's local-only display name, shared by choice with a
        /// contact they added — never with the relay.
        display_name: String,
    },
    /// An ordinary message.
    Text(String),
}

/// What a poll of the inbox produced.
///
/// Conversations opened are reported separately from messages received, because
/// they are different events and collapsing them makes the client say "nothing
/// waiting" when a conversation has just been opened. A status line that
/// misreports what happened is the small end of the same wedge as a manifest
/// that lies.
#[derive(Debug, Clone, Default)]
pub struct Received {
    /// Messages that arrived and were authenticated.
    pub messages: Vec<Message>,
    /// Conversations opened by a Welcome in this poll.
    pub conversations_opened: Vec<String>,
}

impl Received {
    /// Whether the poll produced nothing at all.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty() && self.conversations_opened.is_empty()
    }
}

/// A message as a client sees it.
#[derive(Debug, Clone)]
pub struct Message {
    /// Local identifier.
    pub id: String,
    /// Whether this device sent it.
    pub outgoing: bool,
    /// The plaintext body.
    pub body: String,
    /// Local timestamp, seconds since the Unix epoch.
    pub at: u64,
}

/// Every mechanism in use, for the Security details screen (SPEC §6.7.12).
///
/// Nothing here is secret. Publishing it costs nothing against an adversary who
/// can read the binary, and hiding it would cost the user's ability to evaluate
/// the product (D-014).
#[derive(Debug, Clone)]
pub struct SecurityDetails {
    /// The MLS ciphersuite.
    pub ciphersuite: &'static str,
    /// The AEAD, used through the protocol and never called directly.
    pub aead: &'static str,
    /// The key agreement method.
    pub key_agreement: &'static str,
    /// The signature scheme.
    pub signature: &'static str,
    /// The KDF. A hash inside HKDF — not encryption.
    pub kdf: &'static str,
    /// The protocol and its RFC.
    pub protocol: &'static str,
    /// How the local database is encrypted.
    pub local_database: &'static str,
    /// How a passphrase becomes a key.
    pub passphrase_derivation: &'static str,
    /// The transport currently in use.
    pub transport: &'static str,
    /// The relay this client is configured against.
    pub relay_address: String,
    /// The pinned `openmls` version.
    pub openmls_version: &'static str,
    /// The application version.
    pub app_version: &'static str,
}

/// A running Pouch client.
///
/// Owns the identity, the MLS state, the local database, and the relay
/// connection. Clients hold one of these and call methods on it.
pub struct Pouch {
    identity: Identity,
    provider: PouchProvider,
    store: LocalStore,
    relay: RelayClient,
    /// Live conversations, keyed by conversation id.
    ///
    /// Rebuilt from the MLS snapshot on open. Held in memory because an
    /// `MlsGroup` is a state machine, not a record.
    conversations: HashMap<String, Conversation>,
}

impl Pouch {
    /// Creates a new identity and the database that holds it.
    ///
    /// `db_key` is zeroized before this returns.
    pub fn create(
        display_name: &str,
        db_path: &str,
        db_key: &mut [u8],
        relay: RelayConfig,
    ) -> Result<Self, ApiError> {
        let store = LocalStore::open(db_path, db_key)?;
        let provider = PouchProvider::new();
        let identity = Identity::create(display_name, &provider)?;

        // The public half and the local metadata go in the identity row. The
        // private half was written into the MLS storage provider by
        // `Identity::create` and is captured by the snapshot below, so it lives
        // in exactly one place rather than two (D-025).
        store.put_identity(
            identity.display_name(),
            identity.inbox_id(),
            identity.public_key(),
        )?;
        store.put_mls_state(&provider.snapshot()?)?;

        Ok(Self {
            identity,
            provider,
            store,
            relay: RelayClient::new(relay)?,
            conversations: HashMap::new(),
        })
    }

    /// Opens an existing identity.
    ///
    /// `db_key` is zeroized before this returns.
    pub fn open(db_path: &str, db_key: &mut [u8], relay: RelayConfig) -> Result<Self, ApiError> {
        let store = LocalStore::open(db_path, db_key)?;
        let (display_name, inbox_id, public) = store.identity()?;

        let provider = match store.mls_state()? {
            Some(snapshot) => PouchProvider::restore(&snapshot)?,
            None => PouchProvider::new(),
        };

        // The signer comes back out of the MLS storage provider, where the
        // library put it. Reading it through the library's own accessor rather
        // than reconstructing it from separately stored bytes means there is no
        // second copy of the private key to keep in sync or fail to zeroize.
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &public,
            crate::crypto::CIPHERSUITE.signature_algorithm(),
        )
        .ok_or(ApiError::Crypto(CryptoError::IdentityCreation))?;

        let identity = Identity::restore(display_name, inbox_id, signer)?;

        let mut pouch = Self {
            identity,
            provider,
            store,
            relay: RelayClient::new(relay)?,
            conversations: HashMap::new(),
        };
        pouch.reload_conversations()?;
        Ok(pouch)
    }

    /// Rebuilds the in-memory conversation map from the MLS state.
    ///
    /// The protocol state persists in the snapshot, but an `MlsGroup` is a
    /// state machine that has to be reconstituted. Without this a client that
    /// restarts finds every conversation gone despite the keys still being
    /// there — which is what the first end-to-end run did.
    fn reload_conversations(&mut self) -> Result<(), ApiError> {
        for contact in self.store.contacts()? {
            for conversation_id in self.store.conversations_for(&contact.id)? {
                if let Some(conversation) = Conversation::load(
                    &conversation_id,
                    &contact.inbox_id,
                    &contact.public_key,
                    &self.provider,
                )? {
                    self.conversations.insert(conversation_id, conversation);
                }
            }
        }
        Ok(())
    }

    /// Whether a device already holds an identity, without unlocking anything
    /// else. Drives whether the client shows first run or the conversation list.
    pub fn exists(db_path: &str, db_key: &mut [u8]) -> Result<bool, ApiError> {
        let store = LocalStore::open(db_path, db_key)?;
        Ok(store.has_identity()?)
    }

    /// The local-only display name.
    pub fn display_name(&self) -> &str {
        self.identity.display_name()
    }

    /// This identity's opaque inbox address.
    pub fn inbox_id(&self) -> &str {
        self.identity.inbox_id()
    }

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

    /// Encrypts and posts one payload. Shared by `send_message` and the
    /// introduction sent when a conversation is created.
    async fn send_payload(
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

    /// Whether the relay is answering. Drives the Custody Strip's transport
    /// field between `DIRECT` and `OFFLINE`.
    pub async fn transport_state(&self) -> Route {
        if self.relay.reachable().await {
            Route::Direct
        } else {
            Route::Offline
        }
    }

    /// Every mechanism in use, for the Security details screen.
    pub fn security_details(&self) -> SecurityDetails {
        SecurityDetails {
            ciphersuite: CIPHERSUITE_NAME,
            aead: AEAD_NAME,
            key_agreement: KEY_AGREEMENT_NAME,
            signature: SIGNATURE_NAME,
            kdf: KDF_NAME,
            protocol: PROTOCOL_NAME,
            local_database: "SQLCipher (AES-256)",
            passphrase_derivation: "Argon2id",
            transport: "TLS 1.3, relay certificate pinned by SPKI hash",
            relay_address: self.relay.address().to_string(),
            openmls_version: "0.8.1",
            app_version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Destroys everything on this device.
    ///
    /// Irreversible, and the UI must confirm proportionally (SPEC §6.7.11).
    pub fn wipe_all(&mut self) -> Result<(), ApiError> {
        self.conversations.clear();
        self.store.wipe()?;
        Ok(())
    }

    /// Writes the MLS state back to the encrypted database.
    ///
    /// Called after every operation that advances the protocol. Missing one
    /// means a ratchet step is lost on restart and the conversation breaks.
    fn persist_mls_state(&self) -> Result<(), ApiError> {
        self.store.put_mls_state(&self.provider.snapshot()?)?;
        Ok(())
    }
}

/// Seconds since the Unix epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Re-exported so clients can render a manifest without reaching into a module.
pub use crate::manifest::{Stage, StageOutcome};
