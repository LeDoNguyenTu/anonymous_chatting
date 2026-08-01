//! The database schema, in one place.
//!
//! Kept on its own because the shape of what is stored is the thing most worth
//! reviewing in isolation — a new column here is a new thing that exists on a
//! stolen laptop.

use super::{LocalStore, StorageError};

impl LocalStore {
    pub(super) fn migrate(&self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS identity (
                 id            INTEGER PRIMARY KEY CHECK (id = 1),
                 display_name  TEXT NOT NULL,
                 inbox_id      TEXT NOT NULL,
                 signer_public BLOB NOT NULL
                 -- No secret column. The identity private key is held by the
                 -- MLS storage provider and travels inside the mls_state
                 -- snapshot, so it exists in exactly one place in this file
                 -- rather than two. See D-025.
             );

             CREATE TABLE IF NOT EXISTS mls_state (
                 id       INTEGER PRIMARY KEY CHECK (id = 1),
                 snapshot BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS contacts (
                 id           TEXT PRIMARY KEY,
                 display_name TEXT NOT NULL,
                 inbox_id     TEXT NOT NULL,
                 public_key   BLOB NOT NULL,
                 verified     INTEGER NOT NULL DEFAULT 0
             );

             CREATE TABLE IF NOT EXISTS conversations (
                 id         TEXT PRIMARY KEY,
                 contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE
             );

             CREATE TABLE IF NOT EXISTS messages (
                 id              TEXT PRIMARY KEY,
                 conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                 direction       TEXT NOT NULL,
                 body            TEXT NOT NULL,
                 at              INTEGER NOT NULL
             );

             CREATE INDEX IF NOT EXISTS messages_conversation
                 ON messages (conversation_id, at);",
        )?;
        Ok(())
    }
}
