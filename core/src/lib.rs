//! Pouch core.
//!
//! Every security-relevant line in this project lives here. The desktop,
//! Android, and CLI clients are thin UI over this crate — they never touch a
//! key, a cipher, or a raw ciphertext blob (DECISIONS.md D-012).
//!
//! `api` is a hard boundary rather than a convention. If a client appears to
//! need something lower level, the correct response is to add an operation to
//! `api`, never to expose the module beneath it.
//!
//! Phase 0: module skeleton only. The MLS integration lands in Phase 1.

#![deny(missing_docs)]

/// The only surface clients touch.
pub mod api;
/// Attachment pipeline: per-file keys, metadata stripping, padding (Phase 3).
pub mod attachments;
/// MLS integration, identity keys, safety numbers (Phase 1).
pub mod crypto;
/// The per-message record of what actually happened (SPEC §6.5).
pub mod manifest;
/// SQLCipher access, retention, backup (Phase 1–2).
pub mod storage;
/// TLS with SPKI pinning, offline queue, Tor (Phase 1 and 4).
pub mod transport;

pub use api::{ApiError, ConversationSummary, IdentityState, Message, Pouch, SecurityDetails};

/// The build phase this crate implements. Anything above this is documented
/// intent, not working software.
pub const SPEC_PHASE: u8 = 1;
