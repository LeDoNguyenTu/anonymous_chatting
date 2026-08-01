//! What travels inside an encrypted application message.
//!
//! Application framing, not a protocol. It carries no key material and makes no
//! cryptographic decision — but it is the one place message *structure* is
//! decided, so it lives on its own where a change to it is visible in review.

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
pub(crate) enum Payload {
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
