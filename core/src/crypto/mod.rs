//! MLS integration, identity, and key verification.
//!
//! Everything in this module goes through `openmls`. No handshake, ratchet,
//! KDF, padding scheme, or nonce is written here (Prime Directive 1). Where
//! this module appears to "do crypto" it is arranging inputs for a library
//! call and nothing more.

pub mod file_crypto;
mod identity;
mod provider;
mod safety_number;
mod session;

pub use identity::{Identity, InviteCode};
pub use provider::PouchProvider;
pub use safety_number::SafetyNumber;
pub use session::{Conversation, ReceivedMessage};

use openmls::prelude::Ciphersuite;

/// The ciphersuite every Pouch session uses.
///
/// X25519 for key agreement, AES-128-GCM as the AEAD, SHA-256 inside HKDF,
/// Ed25519 for signatures. Recorded with its full rationale — including why the
/// 128 is deliberate and not a shortcut — in `docs/DECISIONS.md` D-003.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Human-readable name of the ciphersuite, for the Security details screen and
/// the manifest's encryption stage.
///
/// SPEC §2.5: any UI element describing a stage must name the actual
/// mechanism. "Encrypted" alone is insufficient.
pub const CIPHERSUITE_NAME: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

/// The AEAD in use, named for display.
pub const AEAD_NAME: &str = "AES-128-GCM";
/// The key agreement method in use, named for display.
pub const KEY_AGREEMENT_NAME: &str = "X25519";
/// The signature scheme in use, named for display.
pub const SIGNATURE_NAME: &str = "Ed25519";
/// The KDF in use, named for display. A hash inside HKDF — not encryption.
pub const KDF_NAME: &str = "HKDF-SHA256";
/// The protocol, named for display.
pub const PROTOCOL_NAME: &str = "MLS · RFC 9420";

/// Anything that can go wrong in the cryptographic layer.
///
/// Failures are named rather than collapsed into a generic error, because SPEC
/// §6.9 requires the UI to say what happened and a message that fails to
/// decrypt must surface visibly rather than disappear (SPEC §8.2).
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Identity generation failed inside the library.
    #[error("could not create an identity")]
    IdentityCreation,
    /// A conversation could not be created.
    #[error("could not create the conversation")]
    ConversationCreation,
    /// An invite code was malformed or truncated.
    #[error("this invite code is not readable")]
    MalformedInviteCode,
    /// A peer advertised a ciphersuite other than the one in use.
    ///
    /// Fails closed by design. SPEC §2.1 forbids downgrade paths: a protocol
    /// that can be talked into weakening itself is one request away from being
    /// weak.
    #[error("this contact is using a different ciphersuite ({0}); Pouch will not negotiate down")]
    CiphersuiteMismatch(String),
    /// A message could not be encrypted.
    #[error("could not encrypt the message")]
    Encryption,
    /// A message arrived but could not be authenticated or decrypted.
    ///
    /// Surfaced to the user, never swallowed. A silently dropped message hides
    /// exactly the event they most need to know about — tampering.
    #[error("a message arrived that could not be decrypted; it may have been altered in transit")]
    Decryption,
    /// The MLS state could not be serialized or restored.
    #[error("could not read the stored session state")]
    StateSerialization,
    /// A welcome message could not be processed into a group.
    #[error("could not join the conversation from this invitation")]
    Welcome,
}
