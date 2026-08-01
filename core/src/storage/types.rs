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
