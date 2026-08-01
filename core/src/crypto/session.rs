//! Conversations — MLS groups, and the messages that travel through them.
//!
//! Every operation here delegates to `openmls`. This module chooses *when* to
//! call the library; it never decides how encryption works. In particular it
//! never touches a nonce, a key schedule, or an AEAD directly (D-006).

use super::{provider::PouchProvider, CryptoError, Identity, InviteCode, CIPHERSUITE};
use openmls::prelude::{
    tls_codec::{Deserialize as _, Serialize as _},
    GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    ProcessedMessageContent, ProtocolMessage, SenderRatchetConfiguration, StagedWelcome,
};
use openmls_traits::OpenMlsProvider;

/// Padding applied by MLS to every application message, in bytes.
///
/// This is the protocol's own padding, applied inside the AEAD boundary. The
/// product's bucket padding (SPEC §7.1, manifest stage 4) sits outside it and
/// is a separate mechanism — the manifest reports the bucket, not this value,
/// and conflating them in the UI would misreport what ran.
const MLS_PADDING_SIZE: usize = 128;

/// How far out of order a message may arrive and still be decryptable.
///
/// This is not a tuning knob; it follows from a deliberate privacy decision
/// elsewhere. The relay returns queued blobs ordered by their *random*
/// identifier, because returning them in arrival order would hand an observer
/// the sequence in which they were sent (D-010). A client therefore always
/// receives a batch shuffled, and MLS's default tolerance of 5 silently drops
/// anything further out of place than that — a run of a dozen messages loses
/// half of itself.
///
/// **The trade, stated plainly.** A larger window means the receiver retains
/// more unused message keys, and a key that still exists is a key that can be
/// compromised. It weakens forward secrecy within one epoch, in exchange for
/// not losing messages. 64 is chosen to comfortably cover a normal batch while
/// keeping the retained set small; MLS discards the whole set on the next key
/// rotation regardless.
const OUT_OF_ORDER_TOLERANCE: u32 = 64;

/// How far ahead of the expected generation a message may be.
///
/// Left at the library's default. This bounds the work an attacker can force by
/// submitting a blob claiming a far-future generation.
const MAXIMUM_FORWARD_DISTANCE: u32 = 2000;

/// The ratchet window, applied identically to groups this client creates and
/// groups it joins.
///
/// Both sides must agree, or one direction of a conversation drops messages the
/// other keeps.
fn sender_ratchet_configuration() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, MAXIMUM_FORWARD_DISTANCE)
}

/// A message that arrived and was successfully authenticated.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// The plaintext, once MLS has authenticated and decrypted it.
    pub plaintext: Vec<u8>,
    /// The sender's credential identity — their public signature key.
    ///
    /// This is the value the safety number is derived from, so a caller can
    /// check that the message came from the key the user actually verified,
    /// rather than trusting the conversation it arrived in.
    pub sender_key: Vec<u8>,
}

/// One conversation: an MLS group plus the peer's inbox address.
pub struct Conversation {
    group: MlsGroup,
    /// Where blobs for the peer are posted. Opaque; not a name.
    peer_inbox_id: String,
    /// The peer's identity public key, for safety number derivation.
    peer_public_key: Vec<u8>,
}

impl Conversation {
    /// Starts a conversation with someone from their invite code.
    ///
    /// Returns the conversation and the Welcome the peer needs in order to
    /// join. The caller posts that Welcome to the peer's inbox — this module
    /// does no networking.
    pub fn create(
        identity: &Identity,
        invite: &InviteCode,
        provider: &PouchProvider,
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        // Fails closed if the peer's key package names another ciphersuite.
        // There is no downgrade path (SPEC §2.1).
        let key_package = invite.key_package(provider)?;

        let config = MlsGroupCreateConfig::builder()
            .padding_size(MLS_PADDING_SIZE)
            .sender_ratchet_configuration(sender_ratchet_configuration())
            .ciphersuite(CIPHERSUITE)
            // The ratchet tree travels with the group rather than being fetched
            // from the relay. The relay is assumed hostile, so it must not be
            // a source of group state.
            .use_ratchet_tree_extension(true)
            .build();

        let mut group = MlsGroup::new(
            provider,
            identity.signer(),
            &config,
            identity.credential().clone(),
        )
        .map_err(|_| CryptoError::ConversationCreation)?;

        let (_commit, welcome, _group_info) = group
            .add_members(
                provider,
                identity.signer(),
                core::slice::from_ref(&key_package),
            )
            .map_err(|_| CryptoError::ConversationCreation)?;

        // The commit is applied locally. Nobody else is in the group yet, so
        // there is no one to distribute it to.
        group
            .merge_pending_commit(provider)
            .map_err(|_| CryptoError::ConversationCreation)?;

        let welcome_bytes = welcome
            .tls_serialize_detached()
            .map_err(|_| CryptoError::ConversationCreation)?;

        Ok((
            Self {
                group,
                peer_inbox_id: invite.inbox_id.clone(),
                peer_public_key: invite.public_key.clone(),
            },
            welcome_bytes,
        ))
    }

    /// Reloads a conversation whose MLS state is already in the provider.
    ///
    /// An `MlsGroup` is a state machine, not a record, so it is held in memory
    /// while a client runs and rebuilt here on open. Without this every restart
    /// would lose every conversation even though the protocol state survived in
    /// the database — which is exactly the bug the first end-to-end run hit.
    pub fn load(
        group_id_hex: &str,
        peer_inbox_id: &str,
        peer_public_key: &[u8],
        provider: &PouchProvider,
    ) -> Result<Option<Self>, CryptoError> {
        let raw = hex::decode(group_id_hex).map_err(|_| CryptoError::StateSerialization)?;
        let group_id = GroupId::from_slice(&raw);

        let group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|_| CryptoError::StateSerialization)?;

        Ok(group.map(|group| Self {
            group,
            peer_inbox_id: peer_inbox_id.to_string(),
            peer_public_key: peer_public_key.to_vec(),
        }))
    }

    /// The other member's identity key, read from the group itself.
    ///
    /// Used after joining from a Welcome, where the peer's details are not
    /// known in advance — the group is the only source for them, and it is an
    /// authenticated one.
    pub fn peer_credential(&self, own_public_key: &[u8]) -> Option<Vec<u8>> {
        self.group
            .members()
            .map(|m| m.credential.serialized_content().to_vec())
            .find(|key| key != own_public_key)
    }

    /// Sets the peer's inbox address once it is known.
    pub fn set_peer(&mut self, inbox_id: &str, public_key: &[u8]) {
        self.peer_inbox_id = inbox_id.to_string();
        self.peer_public_key = public_key.to_vec();
    }

    /// Joins a conversation from a Welcome that arrived in the inbox.
    pub fn join(
        welcome_bytes: &[u8],
        peer_inbox_id: &str,
        peer_public_key: &[u8],
        provider: &PouchProvider,
    ) -> Result<Self, CryptoError> {
        let message =
            MlsMessageIn::tls_deserialize_exact(welcome_bytes).map_err(|_| CryptoError::Welcome)?;
        // `into_welcome` is gated behind the library's test-utils feature, so
        // the body is matched directly. A message that is not a Welcome is a
        // named error rather than a panic — it is the shape a malformed or
        // misrouted blob takes.
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(CryptoError::Welcome),
        };

        let config = MlsGroupJoinConfig::builder()
            .padding_size(MLS_PADDING_SIZE)
            .sender_ratchet_configuration(sender_ratchet_configuration())
            .build();

        let staged = StagedWelcome::new_from_welcome(provider, &config, welcome, None)
            .map_err(|_| CryptoError::Welcome)?;
        let group = staged
            .into_group(provider)
            .map_err(|_| CryptoError::Welcome)?;

        Ok(Self {
            group,
            peer_inbox_id: peer_inbox_id.to_string(),
            peer_public_key: peer_public_key.to_vec(),
        })
    }

    /// Encrypts a payload for the conversation.
    ///
    /// The returned bytes are what goes to the relay. No key, nonce, or
    /// ciphertext detail crosses back out of here to a caller (D-012).
    pub fn encrypt(
        &mut self,
        identity: &Identity,
        payload: &[u8],
        provider: &PouchProvider,
    ) -> Result<Vec<u8>, CryptoError> {
        let out = self
            .group
            .create_message(provider, identity.signer(), payload)
            .map_err(|_| CryptoError::Encryption)?;

        out.tls_serialize_detached()
            .map_err(|_| CryptoError::Encryption)
    }

    /// Authenticates and decrypts a blob collected from the inbox.
    ///
    /// A blob that fails authentication returns an error. It is never treated
    /// as an empty message, never silently dropped, and never rendered as if it
    /// arrived intact — a silent drop hides tampering, which is exactly the
    /// event the user most needs to see (SPEC §8.2).
    pub fn decrypt(
        &mut self,
        blob: &[u8],
        provider: &PouchProvider,
    ) -> Result<ReceivedMessage, CryptoError> {
        let message =
            MlsMessageIn::tls_deserialize_exact(blob).map_err(|_| CryptoError::Decryption)?;
        let protocol: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|_| CryptoError::Decryption)?;

        let processed = self
            .group
            .process_message(provider, protocol)
            .map_err(|_| CryptoError::Decryption)?;

        let sender_key = processed.credential().serialized_content().to_vec();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(ReceivedMessage {
                plaintext: app.into_bytes(),
                sender_key,
            }),
            // Handshake traffic is protocol machinery, not something a user
            // sent. Reporting it as a message would put protocol bytes in the
            // conversation view.
            _ => Err(CryptoError::Decryption),
        }
    }

    /// Applies a commit or proposal that arrived from the peer.
    ///
    /// Separate from [`Self::decrypt`] so that a caller cannot accidentally
    /// render protocol traffic as a message.
    pub fn process_handshake(
        &mut self,
        blob: &[u8],
        provider: &PouchProvider,
    ) -> Result<(), CryptoError> {
        let message =
            MlsMessageIn::tls_deserialize_exact(blob).map_err(|_| CryptoError::Decryption)?;
        let protocol: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|_| CryptoError::Decryption)?;

        let processed = self
            .group
            .process_message(provider, protocol)
            .map_err(|_| CryptoError::Decryption)?;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(provider, *staged)
                    .map_err(|_| CryptoError::Decryption)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// The peer's opaque inbox address.
    pub fn peer_inbox_id(&self) -> &str {
        &self.peer_inbox_id
    }

    /// The peer's identity public key.
    pub fn peer_public_key(&self) -> &[u8] {
        &self.peer_public_key
    }

    /// How many members the group holds. Two, for a one-to-one conversation.
    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }

    /// The MLS group identifier, hex encoded, for display in the manifest.
    pub fn group_id(&self) -> String {
        hex::encode(self.group.group_id().as_slice())
    }

    /// The current epoch. Increments on every key rotation.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SafetyNumber;

    /// Builds two identities and connects them, as the product's Add contact
    /// flow does: Mai publishes an invite code, Brian starts the conversation
    /// from it, Mai joins from the Welcome.
    fn connected() -> (
        PouchProvider,
        Identity,
        Conversation,
        PouchProvider,
        Identity,
        Conversation,
    ) {
        let brian_provider = PouchProvider::new();
        let mai_provider = PouchProvider::new();

        let brian = Identity::create("Brian", &brian_provider).expect("brian identity");
        let mai = Identity::create("Mai", &mai_provider).expect("mai identity");

        let mai_invite = mai.invite_code(&mai_provider).expect("mai invite code");

        let (brian_conv, welcome) =
            Conversation::create(&brian, &mai_invite, &brian_provider).expect("conversation");

        let mai_conv = Conversation::join(
            &welcome,
            brian.inbox_id(),
            brian.public_key(),
            &mai_provider,
        )
        .expect("mai joins");

        (
            brian_provider,
            brian,
            brian_conv,
            mai_provider,
            mai,
            mai_conv,
        )
    }

    #[test]
    fn a_message_round_trips_between_two_people() {
        let (bp, brian, mut bc, mp, _mai, mut mc) = connected();

        let blob = bc
            .encrypt(&brian, b"the meeting is at dawn", &bp)
            .expect("encrypts");
        let got = mc.decrypt(&blob, &mp).expect("decrypts");

        assert_eq!(got.plaintext, b"the meeting is at dawn");
    }

    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        // The most basic property, and worth asserting rather than assuming.
        let (bp, brian, mut bc, _mp, _mai, _mc) = connected();
        let blob = bc
            .encrypt(&brian, b"MEETING-AT-DAWN-CANARY", &bp)
            .expect("encrypts");

        let needle = b"MEETING-AT-DAWN-CANARY";
        assert!(
            !blob.windows(needle.len()).any(|w| w == needle),
            "plaintext survives in the ciphertext"
        );
    }

    #[test]
    fn both_directions_work() {
        let (bp, brian, mut bc, mp, mai, mut mc) = connected();

        let to_mai = bc.encrypt(&brian, b"from brian", &bp).expect("encrypts");
        assert_eq!(
            mc.decrypt(&to_mai, &mp).expect("decrypts").plaintext,
            b"from brian"
        );

        let to_brian = mc.encrypt(&mai, b"from mai", &mp).expect("encrypts");
        assert_eq!(
            bc.decrypt(&to_brian, &bp).expect("decrypts").plaintext,
            b"from mai"
        );
    }

    #[test]
    fn messages_arrive_in_order_across_a_run() {
        let (bp, brian, mut bc, mp, _mai, mut mc) = connected();

        let mut blobs = Vec::new();
        for i in 0..25 {
            blobs.push(
                bc.encrypt(&brian, format!("message {i}").as_bytes(), &bp)
                    .expect("encrypts"),
            );
        }
        for (i, blob) in blobs.iter().enumerate() {
            let got = mc.decrypt(blob, &mp).expect("decrypts");
            assert_eq!(got.plaintext, format!("message {i}").as_bytes());
        }
    }

    #[test]
    fn identical_plaintext_produces_different_ciphertext_each_time() {
        // SPEC §8.1 requires key rotation be tested. The ratchet itself is
        // `openmls`'s (D-006: this project never touches a nonce or a key
        // schedule directly), so there is nothing to unit-test inside it — but
        // whether it is actually advancing generation to generation is
        // observable from outside without reaching in: the same plaintext,
        // encrypted twice in a row, must not produce the same bytes. If it
        // did, either the key or the nonce repeated, which for an AEAD is the
        // one failure that breaks confidentiality outright rather than merely
        // degrading it.
        let (bp, brian, mut bc, _mp, _mai, _mc) = connected();

        let first = bc
            .encrypt(&brian, b"the same message", &bp)
            .expect("encrypts");
        let second = bc
            .encrypt(&brian, b"the same message", &bp)
            .expect("encrypts");

        assert_ne!(
            first, second,
            "encrypting identical plaintext twice produced identical ciphertext — \
             the ratchet is not advancing"
        );
    }

    #[test]
    fn a_tampered_message_fails_visibly_rather_than_decoding_to_something() {
        // AEAD authentication is what makes "the relay cannot alter messages"
        // true. If a flipped byte produced a plausible plaintext, the claim
        // would be false.
        //
        // openmls 0.8.1 carries a `debug_assert!(false)` on AEAD failure
        // (framing/private_message_in.rs), so a tampered blob *panics* in a
        // debug build and returns `MessageDecryptionError::AeadError` in a
        // release build. Release is what ships, so the security property holds
        // in the shipped artifact — but the assertion below has to cover both
        // profiles or it would only be testing the build it happened to run
        // under. Recorded in DECISIONS.md D-022.
        //
        // What must never happen, in either profile, is the tampered blob
        // being accepted as a message.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (bp, brian, mut bc, mp, _mai, mut mc) = connected();
            let mut blob = bc.encrypt(&brian, b"transfer 100", &bp).expect("encrypts");

            let mid = blob.len() / 2;
            blob[mid] ^= 0x01;

            mc.decrypt(&blob, &mp)
        }));

        match outcome {
            Ok(Ok(message)) => panic!(
                "tampering was not detected; a modified blob decoded to {:?}",
                String::from_utf8_lossy(&message.plaintext)
            ),
            Ok(Err(err)) => assert!(
                matches!(err, CryptoError::Decryption),
                "tampering produced the wrong error: {err}"
            ),
            Err(_) => {
                // Constant per build, and that is exactly the assertion: this
                // arm must be unreachable in a release build. Clippy flags
                // constant assertions as pointless, but a constant that must
                // hold in the shipped profile is the thing worth pinning.
                #[allow(clippy::assertions_on_constants)]
                {
                    assert!(
                        cfg!(debug_assertions),
                        "a release build must return an error on tampering, never panic"
                    );
                }
            }
        }
    }

    #[test]
    fn a_truncated_message_fails() {
        let (bp, brian, mut bc, mp, _mai, mut mc) = connected();
        let blob = bc.encrypt(&brian, b"hello", &bp).expect("encrypts");
        let truncated = &blob[..blob.len() / 2];
        assert!(mc.decrypt(truncated, &mp).is_err());
    }

    #[test]
    fn a_stranger_cannot_read_the_conversation() {
        let (bp, brian, mut bc, _mp, _mai, _mc) = connected();

        // A third party in a group of her own. Eve needs a separate peer to
        // form a group with — you cannot add yourself to your own group.
        let eve_provider = PouchProvider::new();
        let eve = Identity::create("Eve", &eve_provider).expect("eve identity");

        let bystander_provider = PouchProvider::new();
        let bystander = Identity::create("Bystander", &bystander_provider).expect("bystander");
        let bystander_invite = bystander
            .invite_code(&bystander_provider)
            .expect("bystander code");

        let (mut eve_conv, _) =
            Conversation::create(&eve, &bystander_invite, &eve_provider).expect("eve conversation");

        let blob = bc.encrypt(&brian, b"private", &bp).expect("encrypts");
        assert!(eve_conv.decrypt(&blob, &eve_provider).is_err());
    }

    #[test]
    fn a_replayed_message_is_rejected() {
        // MLS tracks which generations it has seen. Accepting a replay would
        // let the relay show a message twice.
        let (bp, brian, mut bc, mp, _mai, mut mc) = connected();
        let blob = bc.encrypt(&brian, b"once", &bp).expect("encrypts");

        assert!(mc.decrypt(&blob, &mp).is_ok(), "first delivery succeeds");
        assert!(mc.decrypt(&blob, &mp).is_err(), "replay was accepted");
    }

    #[test]
    fn both_sides_are_in_the_same_two_person_group() {
        let (_bp, _brian, bc, _mp, _mai, mc) = connected();
        assert_eq!(bc.member_count(), 2);
        assert_eq!(mc.member_count(), 2);
        assert_eq!(bc.group_id(), mc.group_id());
    }

    #[test]
    fn the_sender_key_matches_the_verified_safety_number() {
        // A message identifies its sender by the same key the safety number is
        // derived from. Without this, "verified" would apply to a contact
        // rather than to the key their messages actually arrive under.
        let (bp, brian, mut bc, mp, _mai, mut mc) = connected();

        let blob = bc.encrypt(&brian, b"hello", &bp).expect("encrypts");
        let got = mc.decrypt(&blob, &mp).expect("decrypts");

        assert_eq!(
            got.sender_key,
            brian.public_key(),
            "the sender key is not the identity key the safety number covers"
        );

        let from_message = SafetyNumber::derive(mc.peer_public_key(), &got.sender_key);
        let from_identity = SafetyNumber::derive(mc.peer_public_key(), brian.public_key());
        assert_eq!(from_message, from_identity);
    }

    #[test]
    fn a_conversation_survives_being_stored_and_restored() {
        // The MLS state has to outlive the process, or every restart loses
        // every conversation.
        let (bp, brian, mut bc, mp, _mai, mut mc) = connected();

        let first = bc
            .encrypt(&brian, b"before restart", &bp)
            .expect("encrypts");
        assert_eq!(
            mc.decrypt(&first, &mp).expect("decrypts").plaintext,
            b"before restart"
        );

        let snapshot = bp.snapshot().expect("snapshot");
        let restored_provider = PouchProvider::restore(&snapshot).expect("restore");
        assert!(!snapshot.is_empty());

        // The restored provider holds the same key material, so the identity's
        // signer still works against it.
        let second = bc
            .encrypt(&brian, b"after restart", &restored_provider)
            .expect("encrypts");
        assert_eq!(
            mc.decrypt(&second, &mp).expect("decrypts").plaintext,
            b"after restart"
        );
    }

    #[test]
    fn a_snapshot_is_not_readable_as_plaintext_conversation() {
        // The snapshot is key material and goes into SQLCipher. It must not
        // additionally carry message plaintext around.
        let (bp, brian, mut bc, _mp, _mai, _mc) = connected();
        let _ = bc
            .encrypt(&brian, b"SNAPSHOT-CANARY-PLAINTEXT", &bp)
            .expect("encrypts");

        let snapshot = bp.snapshot().expect("snapshot");
        let needle = b"SNAPSHOT-CANARY-PLAINTEXT";
        assert!(
            !snapshot.windows(needle.len()).any(|w| w == needle),
            "message plaintext is retained in the MLS state snapshot"
        );
    }
}
