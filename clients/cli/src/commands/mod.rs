//! One module per group of related commands.
//!
//! Split by what the user is doing rather than by size: identity, contacts,
//! messaging, device. A new command goes in the module its verb belongs to, and
//! the dispatch table in `main.rs` stays a table rather than growing into a
//! function.

pub mod contacts;
pub mod device;
pub mod identity;
pub mod messaging;
