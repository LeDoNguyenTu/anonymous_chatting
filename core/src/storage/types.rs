//! The records the local database stores.
//!
//! Kept apart from the queries so a reader can see the shape of what is
//! persisted without reading the SQL that persists it.

/// Which way a message travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Written by the user of this device.
    Sent,
    /// Received from a contact.
    Received,
}

impl Direction {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Direction::Sent => "sent",
            Direction::Received => "received",
        }
    }

    pub(super) fn parse(s: &str) -> Self {
        match s {
            "sent" => Direction::Sent,
            _ => Direction::Received,
        }
    }
}

/// A stored message.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    /// Local identifier.
    pub id: String,
    /// Which conversation it belongs to.
    pub conversation_id: String,
    /// Sent or received.
    pub direction: Direction,
    /// The plaintext body.
    pub body: String,
    /// Local send or receive time, seconds since the Unix epoch.
    ///
    /// Full precision is fine here: this timestamp never leaves the device, and
    /// the relay's copy is bucketed separately (D-020).
    pub at: u64,
}

/// How long messages are kept on this device.
///
/// Named for what the user chooses, not for how it is implemented (SPEC §6.9).
/// The default is [`RetentionPolicy::Forever`] because that is the honest
/// default — a messenger that silently deleted history would be surprising —
/// and SPEC §7.2 requires the choice be surfaced at first run rather than
/// buried in settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionPolicy {
    /// Keep everything until the user deletes it.
    Forever,
    /// Keep 30 days.
    Days30,
    /// Keep 7 days.
    Days7,
    /// Keep 24 hours.
    Hours24,
}

impl RetentionPolicy {
    /// How long a message survives, or `None` for forever.
    pub fn seconds(&self) -> Option<u64> {
        match self {
            RetentionPolicy::Forever => None,
            RetentionPolicy::Days30 => Some(30 * 24 * 60 * 60),
            RetentionPolicy::Days7 => Some(7 * 24 * 60 * 60),
            RetentionPolicy::Hours24 => Some(24 * 60 * 60),
        }
    }

    pub(super) fn as_str(&self) -> &'static str {
        match self {
            RetentionPolicy::Forever => "forever",
            RetentionPolicy::Days30 => "30d",
            RetentionPolicy::Days7 => "7d",
            RetentionPolicy::Hours24 => "24h",
        }
    }

    /// Parses a stored value.
    ///
    /// An unrecognised value falls back to `Forever` rather than to a deleting
    /// policy. A build that does not understand a setting written by a newer
    /// build must not destroy the user's history because of it.
    pub(super) fn parse(s: &str) -> Self {
        match s {
            "30d" => RetentionPolicy::Days30,
            "7d" => RetentionPolicy::Days7,
            "24h" => RetentionPolicy::Hours24,
            _ => RetentionPolicy::Forever,
        }
    }

    /// The label shown to the user.
    pub fn label(&self) -> &'static str {
        match self {
            RetentionPolicy::Forever => "forever",
            RetentionPolicy::Days30 => "30 days",
            RetentionPolicy::Days7 => "7 days",
            RetentionPolicy::Hours24 => "24 hours",
        }
    }
}

/// A message waiting for the relay to come back.
///
/// Carries ciphertext. The readable body lives in the `messages` row that
/// shares this identifier, so the thread can show what was written while this
/// row carries only what still has to be posted.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    /// Local identifier, shared with the `messages` row.
    pub id: String,
    /// Which conversation it belongs to.
    pub conversation_id: String,
    /// Where the blob has to go.
    pub peer_inbox: String,
    /// The finished MLS ciphertext, ready to post unchanged.
    pub blob: Vec<u8>,
    /// When the user pressed send.
    pub at: u64,
    /// How many delivery attempts have failed.
    pub attempts: u32,
    /// Why the last attempt failed, for the inline reason SPEC §6.7.3 requires.
    pub last_error: Option<String>,
}

/// A contact's identity key changing under them.
///
/// Recorded rather than acted on. The decision belongs to the user (SPEC
/// §6.7.6), so this carries the facts the modal needs and nothing more.
#[derive(Debug, Clone)]
pub struct IdentityChange {
    /// Which contact.
    pub contact_id: String,
    /// The key that was in use before.
    pub previous_key: Vec<u8>,
    /// When the change was noticed, seconds since the Unix epoch.
    pub changed_at: u64,
    /// Whether the user has seen and answered the warning.
    ///
    /// Acknowledging is not verifying. A user who chooses "continue without
    /// verifying" sets this true while `verified` stays false.
    pub acknowledged: bool,
}

/// A contact and the trust state the Custody Strip reports.
#[derive(Debug, Clone)]
pub struct StoredContact {
    /// Local identifier.
    pub id: String,
    /// Local-only display name.
    pub display_name: String,
    /// The contact's opaque inbox address.
    pub inbox_id: String,
    /// The contact's identity public key.
    pub public_key: Vec<u8>,
    /// Whether the user has actually compared a safety number.
    ///
    /// Defaults to false and only becomes true through an explicit user action.
    /// The Custody Strip shows amber until then, and "the user dismissed a
    /// prompt" is not a reason to flip this.
    pub verified: bool,
}
