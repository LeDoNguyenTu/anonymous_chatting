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
    /// A reference to an attachment uploaded separately (SPEC §7.1 step 6).
    ///
    /// The attachment ciphertext itself never travels through this payload —
    /// it is already uploaded to `bucket_id`, a random relay identifier of
    /// its own, unrelated to either party's inbox. Only the small reference
    /// travels through the encrypted channel: where to fetch it and the key
    /// to open it. This keeps a multi-megabyte blob out of the same queue
    /// slot text messages use, without adding any relay endpoint — `bucket_id`
    /// is just another opaque identifier the existing three-endpoint relay
    /// already knows how to hold and serve.
    Attachment {
        /// Where the encrypted blob was uploaded, via `POST /inbox/{bucket_id}`.
        bucket_id: String,
        /// The fresh, single-use key the blob was encrypted under (D-037).
        key: Vec<u8>,
        /// The original filename. Never sent anywhere outside this encrypted
        /// payload (SPEC §7.1: "original filenames never travel unencrypted").
        filename: String,
        /// The stripped container format, e.g. "JPEG" — for display, not a
        /// trust decision; the recipient still detects the format itself
        /// before opening the bytes.
        format: String,
    },
}
