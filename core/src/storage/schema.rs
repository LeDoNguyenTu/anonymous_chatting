//! The database schema, in one place.
//!
//! Kept on its own because the shape of what is stored is the thing most worth
//! reviewing in isolation — a new column here is a new thing that exists on a
//! stolen laptop.
//!
//! Migrations are numbered and applied in order, tracked in `PRAGMA
//! user_version`. A Phase 1 database reports version 0 and is carried forward
//! by running every step; a database this code created reports the current
//! version and skips them. `CREATE TABLE IF NOT EXISTS` alone is not enough
//! once a column has to be *added* to a table that already exists.

use super::{LocalStore, StorageError};

/// The schema version this build writes.
///
/// 1 — Phase 1: identity, MLS state, contacts, conversations, messages.
/// 2 — Phase 2: settings, retention, identity change history, the outbox.
/// 3 — Phase 3: received attachment content.
pub(super) const SCHEMA_VERSION: i64 = 3;

impl LocalStore {
    pub(super) fn migrate(&self) -> Result<(), StorageError> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap_or(0);

        if version < 1 {
            self.migrate_to_v1()?;
        }
        if version < 2 {
            self.migrate_to_v2()?;
        }
        if version < 3 {
            self.migrate_to_v3()?;
        }

        // Pragmas do not accept bound parameters, and this value is a constant
        // in this file rather than anything a caller supplies.
        self.conn
            .execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
        Ok(())
    }

    /// The Phase 1 shape.
    fn migrate_to_v1(&self) -> Result<(), StorageError> {
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

    /// Phase 2: storage control and hardening.
    fn migrate_to_v2(&self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            // Device-wide settings the user controls. Kept as text so a value
            // that is not understood by an older build reads back as an
            // unrecognised string and falls to a safe default, rather than
            // being silently reinterpreted as a different setting.
            "CREATE TABLE IF NOT EXISTS settings (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );

             -- Identity change detection. `public_key` on contacts always holds
             -- the key in use now; these hold what it was and when it changed,
             -- so the warning modal can state a date rather than just a fact.
             -- Null in both means the key has never changed, which is different
             -- from a change the user has already acknowledged.
             CREATE TABLE IF NOT EXISTS identity_changes (
                 contact_id       TEXT PRIMARY KEY REFERENCES contacts(id) ON DELETE CASCADE,
                 previous_key     BLOB NOT NULL,
                 changed_at       INTEGER NOT NULL,
                 acknowledged     INTEGER NOT NULL DEFAULT 0
             );

             -- Messages composed while the relay was unreachable.
             --
             -- Holds the ciphertext MLS already produced, not the plaintext.
             -- Encrypting advances the ratchet, so re-encrypting at delivery
             -- time would burn a generation for every failed attempt and hand
             -- the recipient gaps their out-of-order tolerance has to absorb —
             -- D-028 reached from the other direction. Queueing the finished
             -- blob keeps the ratchet monotonic and makes a retry a re-POST
             -- rather than a re-encryption.
             CREATE TABLE IF NOT EXISTS outbox (
                 id              TEXT PRIMARY KEY,
                 conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                 peer_inbox      TEXT NOT NULL,
                 blob            BLOB NOT NULL,
                 at              INTEGER NOT NULL,
                 attempts        INTEGER NOT NULL DEFAULT 0,
                 last_error      TEXT
             );

             CREATE INDEX IF NOT EXISTS outbox_order ON outbox (at, id);",
        )?;

        // Per-conversation disappearing messages. Null means "follow the
        // device-wide retention setting"; a number is an override in seconds.
        // Added rather than created, because conversations already exist.
        self.add_column_if_missing("conversations", "disappear_after", "INTEGER")?;

        Ok(())
    }

    /// Phase 3: received attachment content (SPEC §7.1).
    fn migrate_to_v3(&self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            // Shares its primary key with the `messages` row referencing it,
            // the same one-to-one link the outbox already uses. The content
            // is the *stripped* image, not the original file — the original
            // never reaches this device's peer, let alone this table.
            "CREATE TABLE IF NOT EXISTS attachments (
                 id              TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
                 conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                 filename        TEXT NOT NULL,
                 format          TEXT NOT NULL,
                 content         BLOB NOT NULL,
                 at              INTEGER NOT NULL
             );",
        )?;
        Ok(())
    }

    /// Adds a column unless the table already has it.
    ///
    /// SQLite has no `ADD COLUMN IF NOT EXISTS`, and a migration that fails
    /// halfway leaves a database that cannot be opened at all. Checking first
    /// makes the step repeatable.
    fn add_column_if_missing(
        &self,
        table: &str,
        column: &str,
        decl: &str,
    ) -> Result<(), StorageError> {
        let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let existing: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<_, _>>()?;

        if !existing.iter().any(|c| c == column) {
            self.conn
                .execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl};"))?;
        }
        Ok(())
    }
}
