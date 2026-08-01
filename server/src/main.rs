//! Pouch relay.
//!
//! A queue for opaque blobs. It has no concept of a user.
//!
//! The design constraint this binary exists to satisfy: **a full database dump
//! handed to an adversary must yield nothing useful.** Everything else is
//! downstream of that. Four fields are stored per queued message — a random ID,
//! an opaque inbox identifier, a ciphertext blob, and a TTL — and no request is
//! ever written to a log.
//!
//! Phase 0: the no-logging stance is declared and asserted here. The queue
//! endpoints arrive in Phase 1, and the server-blindness test (SPEC §8.3) is
//! written before them.

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

fn main() {
    // No tracing subscriber is installed. That is the point. Adding one later
    // to "get some observability" is a change to the threat model, not an
    // operations detail — SPEC §2.6 says stop and ask.
    println!("pouch-relay: Phase 0 stub. Queue endpoints land in Phase 1.");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the most plausible regression path: someone flips this to `false`
    /// while adding request logging to debug something, and forgets.
    ///
    /// `black_box` keeps this an actual runtime assertion. Without it the
    /// compiler folds the constant away and the test asserts nothing — which
    /// is precisely the failure mode a security guard must not have.
    #[test]
    fn access_logging_stays_disabled() {
        assert!(std::hint::black_box(ACCESS_LOGGING_DISABLED));
    }
}
