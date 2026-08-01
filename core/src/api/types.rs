//! The shapes a client sees.
//!
//! Deliberately separate from the operations that produce them: a UI needs
//! these types to lay out a screen, and keeping them in their own module means
//! reading them does not require reading the messaging logic too.

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

/// A contact's identity key having changed, waiting to be answered.
///
/// Carries the facts SPEC §6.7.6 requires the modal to state — who, and when —
/// and no verdict. The copy explains both innocent and hostile readings and
/// leaves the decision with the user.
#[derive(Debug, Clone)]
pub struct IdentityChangeNotice {
    /// Which contact.
    pub contact_id: String,
    /// Their local-only display name.
    pub contact_name: String,
    /// When the change was noticed, seconds since the Unix epoch.
    pub changed_at: u64,
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
