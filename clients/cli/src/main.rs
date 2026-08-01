//! Pouch CLI client.
//!
//! A headless client over the same `pouch-core` API surface the desktop client
//! uses (DECISIONS.md D-018). It exists so the Phase 1 exit criterion — two
//! clients exchanging text reliably — is verifiable by automation rather than
//! by hand only, and so the system can be demonstrated over SSH.
//!
//! It is not a privileged back door into the core. If this client needs an
//! operation the desktop client does not have, that is a signal about the API,
//! not a licence to reach past it.
//!
//! Phase 0: no commands yet. Phase 1 adds identity creation, contact exchange,
//! send, and receive.

fn main() {
    println!("pouch-cli: Phase 0 stub. Commands land in Phase 1.");
}
