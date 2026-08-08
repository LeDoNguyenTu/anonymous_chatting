//! Pouch relay.
//!
//! A queue for opaque blobs. It has no concept of a user.
//!
//! The design constraint this crate exists to satisfy: **a full database dump
//! handed to an adversary must yield nothing useful.** Four fields are stored
//! per queued message — a random ID, an opaque inbox identifier, a ciphertext
//! blob, and a bucketed TTL — and no request is ever written to a log.
//!
//! Adding a field is a threat-model change, not a schema change (SPEC §2.6).

#![deny(missing_docs)]

pub mod http;
/// Serving the same routes over a Tor v3 onion service (Phase 4).
pub mod onion;
pub mod store;

/// Access logging is off, deliberately and explicitly.
///
/// This constant is not decorative. SPEC §2.3 requires that logging be
/// *explicitly disabled* rather than merely left at its default, because those
/// are different things: almost every HTTP stack logs by default, and "we never
/// configured logging" still produces a full request log containing IP
/// addresses and timing. `scripts/check-guardrails.sh` asserts this declaration
/// exists and that no tracing layer is mounted alongside it.
///
/// The rule it encodes: the relay writes no record of who connected, from
/// where, or when. Not to stdout, not to a file, not to a metrics endpoint.
pub const ACCESS_LOGGING_DISABLED: bool = true;

/// Compile-time enforcement, so flipping the constant fails the build rather
/// than a test someone can mark `#[ignore]`.
const _: () = assert!(
    ACCESS_LOGGING_DISABLED,
    "the relay must never be built with access logging enabled"
);
