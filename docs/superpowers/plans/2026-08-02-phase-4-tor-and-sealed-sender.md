# Phase 4 — Tor transport, then sealed sender — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the relay reachable as a Tor v3 onion service via `arti`, give the desktop and CLI clients a Tor-routed transport alongside the existing direct one, add fixed-size padding to message payloads, activate manifest stage 6 (sealed sender) honestly per route, and update the threat model — closing SPEC.md's Phase 4 exit criteria.

**Architecture:** `core`'s `RelayClient` gains a second, additive backend: today it wraps `reqwest` for direct TLS; a new async `RelayClient::connect_tor` bootstraps an `arti_client::TorClient` and builds a `hyper_util`-based client over a custom `tower::Service<Uri>` connector that dials the target through Tor instead of TCP+DNS. `Pouch::create`/`Pouch::open` are untouched — Tor is switched on and off on an already-open `Pouch` via new `connect_tor`/`use_direct_relay` methods, so none of the ~40 existing call sites across tests, the CLI, and the desktop backend change. On the relay side, `server` gains a second listener: alongside the existing plain-TCP `axum::serve`, an onion-service bridge accepts Tor rendezvous streams via `tor-hsservice` and serves the same `axum::Router` over each one through `hyper_util`'s manual per-connection serving (axum 0.7's `axum::serve` only accepts a concrete `TcpListener`, not arbitrary streams).

**Tech Stack:** Rust, `arti-client`/`tor-hsservice`/`tor-rtcompat` `=0.43.0` (D-039), `hyper` `=1.11.0`, `hyper-util` `=0.1.20`, `http-body-util` `=0.1.4`, `futures-util` `=0.3.33`, existing `axum =0.7.9`/`tokio =1.53.1`/`reqwest =0.12.9`. Desktop: existing Tauri v2 + React/TypeScript stack, no new frontend dependency.

## Global Constraints

- **Pin every dependency with `=`.** Record any version change in `docs/DECISIONS.md`. (`docs/CONTEXT.md`)
- **Git author is `Brian <188601252+LeDoNguyenTu@users.noreply.github.com>`.** Commits carry no co-author trailers.
- **Branch:** `develop`.
- **Do not invent cryptography.** No custom ciphers, protocols, KDFs, padding, or nonce generation — audited libraries through their intended interface only. (SPEC §1, rule 1)
- **No security theatre.** Never claim unbreakable, uncrackable, military grade, or stronger than Signal. (SPEC §1, rule 2)
- **Honesty about limits is a feature.** The UI must never show a reassuring indicator when the underlying state is uncertain; a manifest that lies is worse than no manifest. (SPEC §1, rule 3; SPEC §8.6)
- **The UI layer never touches a key, a cipher, or a raw ciphertext blob.** If a client needs one, add an operation to `core/src/api.rs` instead. (`docs/CONTEXT.md`, D-012)
- **Components use semantic CSS tokens (`--fg-*`), never brand tokens directly.** (`docs/CONTEXT.md`)
- **`docs/DECISIONS.md` is append-only.** Supersede, never edit away.
- **Update `docs/PROGRESS.md` before finishing a session.**
- **Bump the version number after each phase or critical fix** — four files move together: root `Cargo.toml`, `clients/desktop/src-tauri/Cargo.toml`, `clients/desktop/src-tauri/tauri.conf.json`, `clients/desktop/package.json`.
- **`cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all -- --check` must stay clean** after every task.
- **The Tauri crate does not compile in this environment** (no GTK/WebKitGTK). `cargo build --workspace` (which excludes it) is the compile check for `core`/`server`/`clients/cli`; the desktop crate's own compile check is `cd clients/desktop/src-tauri && cargo check --locked` plus `cd clients/desktop && npm run typecheck && npm test && npm run build`.
- **A manifest stage is only ever marked `Ran` by the code that actually performed it.** No stage is inferred from an adjacent one. (`core/src/manifest.rs`)
- **D-039 already recorded** (this session, before this plan): `arti-client`/`tor-hsservice`/`tor-rtcompat` pinned at `=0.43.0`, workspace `rust-version` raised from `1.82` to `1.89`. This plan's Task 1 executes that decision; it does not re-decide it.
- **D-040, found and resolved during Task 1's first dispatch attempt, before any task in this plan had committed code:** `arti-client =0.43.0` unconditionally requires `tor-dirmgr =0.43.0`, which unconditionally requires `rusqlite >=0.36.0,<0.40.0` — confirmed via crates.io's own dependency metadata, not fixable by any `arti-client` feature selection. This workspace's pre-existing `rusqlite =0.32.1` pin (D-019/D-024) cannot coexist with it (both link the native `sqlite3` library; Cargo hard-blocks two versions of a `links`-declaring crate in one graph). Resolved, verified end-to-end on this exact Windows environment before writing this into the plan: bump `rusqlite` to `=0.39.0` (same `bundled-sqlcipher` feature, confirmed present), which cascades into two more required bumps — `thiserror` `=2.0.9` → `=2.0.19` and `serde` `=1.0.216` → `=1.0.225` (both transitively forced by `arti-client`'s own dependency tree, both routine low-risk bumps of extremely API-stable crates) — plus one real behavioral fix: `rusqlite 0.39.0` dropped its built-in `ToSql` impl for raw `u64`, which breaks three call sites in `server/src/store.rs` that pass `u64` timestamps directly into `params!`. All of this is verified by an actual `cargo check -p pouch-core` (with the new deps temporarily wired in) and a full `cargo test --workspace` — 163/163 passing — not assumed. Task 1 below is written to execute this already-verified fix directly; it does not need to rediscover it.
- **Cover traffic is explicitly out of scope for this plan.** SPEC's Phase 4 scope line names "optional cover traffic," but no section of SPEC specifies its shape (frequency, size, triggering), and inventing one now would be exactly the undesigned-construction class of decision SPEC §2.6 reserves for a stop-and-ask. It is not part of Phase 4's exit criteria (SPEC §9's Phase 4 exit lists Tor end-to-end, no client IP in server state, Custody Strip `TOR`, and sealed sender — not cover traffic). Task 14 records this as a deliberate, stated deferral in `docs/DECISIONS.md` (D-042) and `SPEC.md`, the same way Phase 3 recorded video attachments as deferred rather than silently absent.

---

## File Structure

| File | Change |
|---|---|
| `Cargo.toml` | New pinned deps, `rust-version` 1.82 → 1.89, `rusqlite`/`thiserror`/`serde` bumped (D-040) |
| `clients/desktop/src-tauri/Cargo.toml` | `rust-version` 1.82 → 1.89 |
| `server/src/store.rs` | Three `u64` → `i64` casts in `params!` calls, forced by the `rusqlite` bump (D-040) |
| `core/src/padding.rs` | **New** — moved from `core/src/attachments/padding.rs`, now shared |
| `core/src/attachments/padding.rs` | **Deleted** (moved) |
| `core/src/attachments/mod.rs` | `use crate::padding` instead of `mod padding` |
| `core/src/lib.rs` | `pub mod padding;` added; doc comments updated |
| `core/src/manifest.rs` | `Stage::Pad` starts `Pending`; new `Manifest::sealed`; `RelayVisibility::for_message` takes a `Route` |
| `core/src/api/messaging.rs` | Pad before encrypt / unpad after decrypt; `manifest.routed`/`manifest.sealed` use the real route instead of hardcoded `Route::Direct` |
| `core/src/transport.rs` → `core/src/transport/mod.rs` | Existing content, restructured around a `Backend` enum; `route()` accessor; `TransportError::TorBootstrapFailed` |
| `core/src/transport/tor.rs` | **New** — `TorRelayConfig`, `TorConnector` (`tower::Service<Uri>`), Tor-backed send/collect/acknowledge/reachable |
| `core/src/api/mod.rs` | `Pouch::connect_tor`, `Pouch::use_direct_relay`, `Pouch::current_route`; `transport_state` reports the real route |
| `core/src/api/attachments.rs` | `send_attachment`'s `manifest.routed`/new `manifest.sealed` call updated to match messaging.rs's pattern |
| `server/src/onion.rs` | **New** — bootstraps a `TorClient`, launches the onion service, bridges streams into the existing `axum::Router` |
| `server/src/main.rs` | Env-gated onion service alongside the existing direct listener |
| `clients/cli/src/config.rs` | `tor_config()` helper reading Tor env vars |
| `clients/cli/src/commands/messaging.rs` | `send`/`receive` opt into Tor when configured |
| `clients/desktop/src-tauri/src/commands.rs` | `connect_tor`, `use_direct_relay`, `transport_options` commands |
| `clients/desktop/src-tauri/src/state.rs` | Tor state directory helper |
| `clients/desktop/src/lib/bridge.ts` | New bridge methods/types |
| `clients/desktop/src/screens/TransportSettings.tsx` | **New** — SPEC §6.7.9, screen 9 |
| `clients/desktop/src/screens/PrivacyStorage.tsx` | Link to the new screen |
| `clients/desktop/src/App.tsx` | Route wiring |
| `docs/DECISIONS.md` | D-040 (rusqlite bump), D-041 (message padding wire break), D-042 (cover traffic deferral) |
| `docs/THREAT_MODEL.md` | Phase 4 metadata tiers updated |
| `SPEC.md` | Phase 4 section gets the cover-traffic deferral note, matching Phase 3's pattern |
| `docs/PROGRESS.md` | Phase 4 section, version bump note |

---

### Task 1: Pin the Tor/hyper dependencies, raise the MSRV, and resolve the rusqlite conflict (D-039, D-040)

**This task was attempted once already and hit a real, verified blocker before any task in this plan had committed code — the fix below is not speculative, it was reproduced and the full test suite re-run green on this exact Windows environment before being written here.** `arti-client =0.43.0` unconditionally depends on `tor-dirmgr =0.43.0`, which unconditionally requires `rusqlite >=0.36.0,<0.40.0` — incompatible with this workspace's pre-existing `rusqlite =0.32.1` pin (D-019/D-024) because both link the native `sqlite3` library and Cargo will not resolve two versions of a `links`-declaring crate in one graph. This task now includes the fix: bump `rusqlite`, and the two dependency bumps and one code fix that bumping it forces. See Global Constraints' D-040 entry for the full chain.

**Files:**
- Modify: `Cargo.toml`
- Modify: `clients/desktop/src-tauri/Cargo.toml`
- Modify: `server/src/store.rs`
- Modify: `docs/DECISIONS.md`

**Interfaces:**
- Produces: workspace dependencies `arti-client`, `tor-hsservice`, `tor-rtcompat`, `hyper`, `hyper-util`, `http-body-util`, `futures-util`, `http`, `tower-service`, `bytes` available to `core` and `server` via `[workspace.dependencies]`. `rusqlite` moves from `=0.32.1` to `=0.39.0`, `thiserror` from `=2.0.9` to `=2.0.19`, `serde` from `=1.0.216` to `=1.0.225` — all workspace-wide, all already-pinned dependencies moving to a new pinned version, not new dependencies.

- [ ] **Step 1: Raise `rust-version` in both places**

In `Cargo.toml`:
```toml
[workspace.package]
version = "0.1.2"
edition = "2021"
rust-version = "1.89"
```

In `clients/desktop/src-tauri/Cargo.toml`, find the `rust-version = "1.82"` line and change it to `rust-version = "1.89"` (this crate is excluded from the workspace and does not inherit the value above — same reason the version-number convention names four files that move together).

- [ ] **Step 2: Bump `rusqlite`, `thiserror`, and `serde` in `Cargo.toml`**

Change these three existing lines (they are not adjacent to each other in the file — `rusqlite` is under `# --- storage ---`, `serde`/`thiserror` are under `# --- plumbing ---`):

```toml
rusqlite = { version = "=0.39.0", features = ["bundled-sqlcipher"] }
```
```toml
serde = { version = "=1.0.225", features = ["derive"] }
```
```toml
thiserror = "=2.0.19"
```

Add a comment immediately above the `rusqlite` line (above the existing block explaining why there is one `rusqlite` entry for the whole workspace — keep that existing comment, add this one after it):

```toml
# Bumped from 0.32.1 to 0.39.0 for Phase 4 — arti-client's tor-dirmgr
# component requires rusqlite >=0.36.0,<0.40.0 and the two cannot coexist as
# separate versions (both link the native sqlite3 library). See D-040.
# `bundled-sqlcipher` is confirmed still present at 0.39.0. This forces the
# thiserror and serde bumps below via arti-client's own transitive tree, and
# requires three `as i64` casts in server/src/store.rs — see D-040 for why.
```

- [ ] **Step 3: Fix the three `u64` call sites in `server/src/store.rs`**

`rusqlite 0.39.0` no longer implements `ToSql` for raw `u64` (SQLite's native integer is signed 64-bit; the crate now requires an explicit cast rather than silently reinterpreting). `core/src/storage/` already casts explicitly everywhere it passes a `u64` timestamp (e.g. `params![seconds.map(|s| s as i64), conversation_id]` in `core/src/storage/settings.rs`) — `server/src/store.rs` is the only place in the workspace that does not yet, because it never needed to before this bump.

Change:
```rust
        self.conn.execute(
            "INSERT INTO queue (message_id, inbox_id, blob, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![message_id, inbox_id, blob, expires_at],
        )?;
```
to:
```rust
        self.conn.execute(
            "INSERT INTO queue (message_id, inbox_id, blob, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![message_id, inbox_id, blob, expires_at as i64],
        )?;
```

Change:
```rust
        let rows = stmt.query_map(params![inbox_id, now()], |row| {
```
to:
```rust
        let rows = stmt.query_map(params![inbox_id, now() as i64], |row| {
```

Change:
```rust
    pub fn sweep_expired(&self) -> Result<usize, StoreError> {
        Ok(self
            .conn
            .execute("DELETE FROM queue WHERE expires_at <= ?1", params![now()])?)
    }
```
to:
```rust
    pub fn sweep_expired(&self) -> Result<usize, StoreError> {
        Ok(self
            .conn
            .execute(
                "DELETE FROM queue WHERE expires_at <= ?1",
                params![now() as i64],
            )?)
    }
```

These three are exhaustive for this file — `expires_at`/`now()` (both `u64`) are the only raw-`u64`-into-`params!` sites in `server/src/store.rs`. `Store::len`'s `COUNT(*)` result is read via `row.get(0)` into an `i64` already (`let n: i64 = ...`), not written, so it is unaffected.

- [ ] **Step 4: Add the pinned Tor/hyper dependencies to `[workspace.dependencies]`**

Append to `Cargo.toml` after the existing `# --- transport / server ---` block:

```toml
# --- Tor transport (Phase 4) ------------------------------------------------
# D-039: arti-client/tor-hsservice/tor-rtcompat pinned at 0.43.0 — the newest
# release, 0.44.0, needs Rust 1.91 and failed its own docs.rs build; 0.43.0
# needs 1.89 (which rust-version above now declares) and built cleanly.
# `onion-service-service` enables `TorClient::launch_onion_service` — the
# server side needs it; the client only needs `TorClient::connect`, but
# pinning one feature set for the whole workspace is simpler than two.
arti-client = { version = "=0.43.0", default-features = false, features = ["tokio", "rustls", "onion-service-service"] }
tor-hsservice = "=0.43.0"
tor-rtcompat = { version = "=0.43.0", features = ["tokio"] }

# reqwest has no hook for a custom low-level connector, and arti-client has no
# in-process SOCKS listener (only the separate `arti` CLI binary does, which
# would mean shelling out to a subprocess — against this project's rule of
# using an audited library through its intended interface). The Tor-routed
# transport is therefore built directly on hyper/hyper-util instead, which is
# also what bridges the relay's onion-service streams into axum server-side —
# one new dependency category serving both directions, not two.
hyper = "=1.11.0"
hyper-util = { version = "=0.1.20", features = ["client-legacy", "server-auto", "tokio", "service"] }
http-body-util = "=0.1.4"
futures-util = "=0.3.33"
http = "=1.5.0"
tower-service = "=0.3.3"
bytes = "=1.12.1"
```

(`bytes = "=1.12.1"` — already verified against the real resolved graph, not a placeholder to double check; if a later `cargo tree` shows a different resolved version at implementation time, the graph has moved since this plan was written and the pin should track whatever is actually resolved, same principle as before.)

- [ ] **Step 5: Verify the fix resolves the arti-client/rusqlite conflict for real**

`[workspace.dependencies]` entries are inert until a member's own `[dependencies]` table references them — adding them alone will not exercise the fix. Temporarily wire all ten new entries into `core/Cargo.toml`'s `[dependencies]` (each as `name.workspace = true`, marked with a `// TEMPORARY — reverted before commit, real wiring is later tasks' job` comment), then:

Run: `cargo check -p pouch-core 2>&1 | tail -80`
Expected: `Finished` — no `libsqlite3-sys`/`links` conflict, no `thiserror`/`serde_derive` version-selection failure. If any error appears, it means the graph has shifted since this plan was verified (e.g. a newer arti-client patch release changed a transitive requirement) — investigate via crates.io's `/api/v1/crates/<name>/<version>/dependencies` endpoint for the actual conflicting package pair, the same way this conflict was originally found, rather than guessing at version numbers.

Run: `cargo test --workspace 2>&1 | tail -60`
Expected: **163 passed, 0 failed** — the same count as the baseline before this task. Pay particular attention to the SQLCipher-dependent tests (`a_passphrase_re_encrypts_the_database_and_the_old_key_stops_working` and anything in `core/src/storage/`) — these are what would catch a real behavioral break from the `rusqlite` bump, as opposed to a mere compile error. (SQLCipher's own C library prints `WARN MEMORY sqlcipher_mlock: VirtualLock() returned 0 LastError=1453` and, inside the wrong-key test specifically, `ERROR CORE sqlcipher_page_cipher: hmac check failed` to stderr during a normal, passing run on Windows — both are expected noise from SQLCipher itself, not a failure; the test result line is what matters.)

Then revert only the temporary `core/Cargo.toml` wiring (`git checkout -- core/Cargo.toml`) — the real wiring into `core` happens in Task 5+6. Confirm `git diff core/Cargo.toml` is empty afterward.

- [ ] **Step 6: Record D-040 in `docs/DECISIONS.md`**

Read the tail of `docs/DECISIONS.md` first (D-039 is the last entry) and append:

```markdown
---

## D-040 — `rusqlite` bumped 0.32.1 → 0.39.0 to resolve an arti-client conflict; two forced companion bumps
**Date:** 2026-08-02 · **Status:** accepted — project owner approved 2026-08-02

**The problem, found while executing D-039.** `arti-client =0.43.0`
unconditionally depends on `tor-dirmgr =0.43.0` (needed to fetch and cache
the Tor consensus — required to build *any* circuit, not only onion
services), which unconditionally requires `rusqlite >=0.36.0,<0.40.0`,
confirmed via crates.io's own dependency metadata (`optional: false`, no
feature gate on either side — `tor-dirmgr`'s `static` feature only controls
whether SQLite is bundled, not whether the dependency exists). This
workspace's `rusqlite = "=0.32.1"` pin, in place since Phase 0/1 for the
SQLCipher-encrypted local database and the relay's own store (D-019,
D-024), cannot coexist with that range: both ultimately link the native
`sqlite3` library through `libsqlite3-sys`, and Cargo hard-blocks two
versions of a `links`-declaring crate in one build graph — not a version
negotiation, a wall. Confirmed with the actual Cargo resolver error before
concluding anything, not assumed from reading version ranges alone.

**Decision.** Bump the workspace `rusqlite` pin to `=0.39.0` — inside
`tor-dirmgr`'s required range, the newest 0.3x release, still ships
`bundled-sqlcipher` (confirmed on crates.io before choosing it, same
diligence D-038 applied to `img-parts`). This is the crate D-024's incident
was about, so it was not changed without real verification: reproduced the
conflict, applied the bump, and ran the **full existing test suite (163
tests) to completion, green**, including the SQLCipher-specific tests (wrong
key correctly refused, passphrase re-encryption, the runtime
`PRAGMA cipher_version` guard) — not just a clean compile. Verified on the
project's own Windows development environment, where SQLCipher/OpenSSL
linkage has caused problems before (`docs/PROGRESS.md`'s Windows build
notes).

**Two forced companion bumps, both low-risk.** `rusqlite 0.39.0`'s own
dependency tree (via a `sqlite-wasm-rs` entry, present regardless of target)
requires `thiserror ^2.0.12`; separately, `arti-client`'s `tor-config` →
`toml 1.0.3` chain requires `serde_core ^1.0.225`, which forces the paired
`serde_derive` to the same version as `serde` itself. Bumped
`thiserror = "=2.0.9"` → `"=2.0.19"` and `serde = "=1.0.216"` → `"=1.0.225"`.
Neither is a security-relevant crate in the way `rusqlite` is; both are
widely used, API-stable derive/error crates, and the full test suite passing
after both bumps is the real evidence, not an assumption that "minor version
bumps of popular crates are usually fine."

**One forced code fix, not a design change.** `rusqlite 0.39.0` dropped its
built-in `ToSql` implementation for raw `u64` — SQLite's native integer type
is signed 64-bit, and the crate now requires an explicit cast rather than
silently reinterpreting a `u64` as `i64`. `core/src/storage/` already cast
explicitly everywhere (`as i64`) before this bump; `server/src/store.rs` had
three call sites that did not, because they never needed to before. Fixed
with the same `as i64` cast pattern already established in `core` — every
value involved is a Unix timestamp or an expiry bucket, nowhere near
`i64::MAX`, so the cast is lossless for every realistic input.

**Rejected alternatives.**
- *Restructure Tor networking behind a separate OS process, avoiding the
  `rusqlite` conflict entirely by never linking `arti-client` into the same
  binary as `core`.* Rejected for this decision specifically (though see the
  note below): the `links` conflict applies to whatever gets linked into one
  final binary, not to Cargo workspace or lockfile boundaries — if the same
  executable still needs both `pouch-core` and an arti-wrapping crate as
  direct or transitive Rust dependencies, the conflict recurs regardless of
  which workspace member each lives in. A real fix along these lines would
  need an actual IPC boundary between two OS processes, which is a
  substantially larger architecture change than a dependency version bump,
  and was not what was being decided here.
- *Switch to the system `tor` daemon via its ControlPort instead of
  `arti-client`.* A legitimate, more involved alternative — sidesteps the
  Rust dependency graph entirely — but SPEC §3.2 names `arti` explicitly for
  Phase 4 transport, so this would be a SPEC.md amendment, not a dependency
  pin change, and a substantially larger rewrite of this plan's remaining
  tasks. Not chosen; recorded here so it is not silently forgotten as an
  option if `arti-client` causes further friction later in this phase.

**What this does not open up.** This is a version bump of an
already-audited, already-relied-upon crate, verified by the same test suite
that already exists for it — not a new trust decision about SQLCipher or
about how the local database is protected. D-019 and D-024's reasoning is
otherwise unchanged.
```

- [ ] **Step 7: Run the full verification one more time on the final diff**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace 2>&1 | tail -60`
Expected: all clean, 163 passed, 0 failed. (`core/Cargo.toml` should show no diff at all at this point — confirm with `git diff --stat core/Cargo.toml` before committing.)

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock clients/desktop/src-tauri/Cargo.toml server/src/store.rs docs/DECISIONS.md
git commit -m "Pin arti/hyper dependencies for Phase 4; bump rusqlite/thiserror/serde to resolve a real conflict (D-039, D-040)"
```

---

### Task 2: Move fixed-size padding to a shared module

**Files:**
- Create: `core/src/padding.rs` (moved from `core/src/attachments/padding.rs`, content unchanged except the module doc comment)
- Delete: `core/src/attachments/padding.rs`
- Modify: `core/src/attachments/mod.rs`
- Modify: `core/src/lib.rs`

**Interfaces:**
- Produces: `crate::padding::pad(&[u8]) -> Vec<u8>`, `crate::padding::unpad(&[u8]) -> Option<Vec<u8>>` — same signatures as before, new path. Used by `core/src/attachments/mod.rs` (unchanged call sites, `padding::pad`/`padding::unpad`) and by Task 4's `core/src/api/messaging.rs`.

This is a pure relocation — the fixed-bucket scheme (64 KB/256 KB/1 MB/4 MB/16 MB, then 16 MB increments) is about to serve both attachments and general message payloads, so it no longer belongs under a module whose doc comment and `core/src/lib.rs` entry both describe it as attachment-only.

- [ ] **Step 1: Move the file, updating only its header doc comment**

Read `core/src/attachments/padding.rs` in full first (it exists already, tested, working — do not rewrite the logic). Create `core/src/padding.rs` with identical content except replace the top doc comment:

```rust
//! Fixed-size padding buckets (SPEC §7.1 step 3, extended to message
//! payloads in Phase 4).
//!
//! Blunts size fingerprinting: a 70 KB photo and a 200 KB photo — or a short
//! reply and a longer one — produce identically sized blobs once both land
//! in the same bucket, so an observer who sees nothing else about a blob
//! cannot tell them apart by size either.
```

Everything below that (the `KB`/`MB` constants, `FIXED_BUCKETS`, `bucket_for`, `LEN_PREFIX_BYTES`, `pad`, `unpad`, and the full `#[cfg(test)] mod tests` block) is copied verbatim — do not change the bucket sizes, the length-prefix scheme, or any test.

Delete `core/src/attachments/padding.rs`.

- [ ] **Step 2: Update `core/src/attachments/mod.rs`**

Change:
```rust
pub mod metadata;
pub mod padding;
```
to:
```rust
pub mod metadata;

use crate::padding;
```

(`padding::pad`/`padding::unpad` call sites inside this file — in the `prepare`/`open` functions — need no change; only where the symbol resolves from changes.)

- [ ] **Step 3: Update `core/src/lib.rs`**

Add a top-level module declaration and update the `attachments` doc comment:

```rust
/// The only surface clients touch.
pub mod api;
/// Attachment pipeline: per-file keys, metadata stripping (Phase 3).
pub mod attachments;
/// MLS integration, identity keys, safety numbers (Phase 1).
pub mod crypto;
/// Where the local database key comes from.
pub mod keying;
/// The per-message record of what actually happened (SPEC §6.5).
pub mod manifest;
/// Fixed-size padding buckets, shared by attachments and message payloads
/// (SPEC §7.1 step 3, Phase 3 and Phase 4).
pub mod padding;
/// SQLCipher access, retention, backup (Phase 1–2).
pub mod storage;
/// TLS with SPKI pinning, offline queue, Tor (Phase 1 and 4).
pub mod transport;
```

- [ ] **Step 4: Run the existing padding and attachment tests to confirm the move changed nothing**

Run: `cargo test --workspace padding 2>&1 | tail -20` then `cargo test --workspace attachments 2>&1 | tail -20`
Expected: all previously-passing padding tests (now under `core::padding::tests`) and attachment tests still pass, same count.

- [ ] **Step 5: Commit**

```bash
git add core/src/padding.rs core/src/attachments/mod.rs core/src/lib.rs
git rm core/src/attachments/padding.rs
git commit -m "Move fixed-size padding to a shared module ahead of message-level padding"
```

---

### Task 3: Extend the Manifest for message-level padding and sealed sender

**Files:**
- Modify: `core/src/manifest.rs`

**Interfaces:**
- Consumes: `crate::transport::Route` (unchanged, already imported).
- Produces: `Manifest::sealed(&mut self, route: Route)` — new method, used by Task 6's `send_payload`/`send_message`/`core/src/api/attachments.rs`. `Manifest::new`'s `Stage::Pad` now starts `Pending` instead of `NotYetImplemented`.

The `Manifest::padded(&mut self, before: usize, after: usize)` method already exists (added for attachments in Phase 3) and needs no change — Task 4 reuses it for messages.

- [ ] **Step 1: Write the failing tests**

Add to `core/src/manifest.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn a_new_text_manifest_starts_padding_as_pending_not_unimplemented() {
    // Phase 4 implements message-level padding; a manifest built today must
    // not still claim the feature does not exist.
    let m = Manifest::new(10);
    let (_, outcome) = m
        .stages()
        .iter()
        .find(|(s, _)| *s == Stage::Pad)
        .expect("pad present");
    assert_eq!(*outcome, StageOutcome::Pending);
}

#[test]
fn sealing_over_tor_reports_ran() {
    let mut m = Manifest::new(10);
    m.sealed(Route::Tor);
    let (_, outcome) = m
        .stages()
        .iter()
        .find(|(s, _)| *s == Stage::Seal)
        .expect("seal present");
    assert!(outcome.ran(), "a Tor-routed message must report sealed sender as ran");
}

#[test]
fn sealing_over_direct_never_claims_ran() {
    // SPEC §8.6's rule, applied to stage 6 the same way
    // `a_direct_message_never_reports_tor` already applies it to stage 7: a
    // manifest that claims a protection a message did not get is worse than
    // one that admits it did not run.
    let mut m = Manifest::new(10);
    m.sealed(Route::Direct);
    let (_, outcome) = m
        .stages()
        .iter()
        .find(|(s, _)| *s == Stage::Seal)
        .expect("seal present");
    assert!(!outcome.ran(), "a direct message claimed sealed sender");
    assert!(matches!(outcome, StageOutcome::NotApplicable(_)));
}

#[test]
fn sealing_while_offline_never_claims_ran() {
    let mut m = Manifest::new(10);
    m.sealed(Route::Offline);
    let (_, outcome) = m
        .stages()
        .iter()
        .find(|(s, _)| *s == Stage::Seal)
        .expect("seal present");
    assert!(!outcome.ran());
}
```

Also **delete** `Stage::Pad` from the list iterated in `unbuilt_stages_report_as_unimplemented_never_as_complete` (it currently asserts both `Stage::Pad` and `Stage::Seal` are `NotYetImplemented`; after this task neither stage is unbuilt any more, so this whole test becomes vacuous once Task 6 lands `sealed()` calls — for now, in this task, change the test to check only that the *default* `Manifest::new` output for `Stage::Seal` is still `NotYetImplemented` until Task 6 wires `sealed()` into the send path, and drop `Stage::Pad` from the list since Step 1 above already covers it more precisely):

```rust
#[test]
fn seal_remains_unbuilt_in_a_freshly_constructed_manifest() {
    // `Manifest::new` alone cannot know the route a message will take —
    // `sealed()` (called from the send path once Task 6 lands) is what turns
    // this into an honest Ran/NotApplicable. Until that call happens, the
    // default must not claim anything.
    let m = Manifest::new(100);
    let (_, outcome) = m
        .stages()
        .iter()
        .find(|(s, _)| *s == Stage::Seal)
        .expect("seal present");
    assert_eq!(*outcome, StageOutcome::NotYetImplemented);
}
```
(This replaces the old `unbuilt_stages_report_as_unimplemented_never_as_complete` test — delete the old one, add this one in its place.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --workspace -p pouch-core manifest 2>&1 | tail -40`
Expected: FAIL — `sealed` does not exist yet, `Stage::Pad` still constructs as `NotYetImplemented`.

- [ ] **Step 3: Implement**

In `Manifest::new`, change:
```rust
(Stage::Pad, StageOutcome::NotYetImplemented),
```
to:
```rust
(Stage::Pad, StageOutcome::Pending),
```

Add a new method, placed near `padded`/`encrypted`:

```rust
/// Records whether the sender was actually sealed from the relay.
///
/// Only a Tor-routed message gets this — the relay's wire protocol already
/// carries no sender field (D-026), but a direct connection still exposes
/// the TCP/TLS source IP, so sealing depends entirely on which route
/// [`Manifest::routed`] is about to record. This must be called with the
/// same [`Route`] passed to `routed` for the same message; recording a
/// different one would produce a manifest that names one route at stage 7
/// and claims sealing for another.
pub fn sealed(&mut self, route: Route) {
    let outcome = match route {
        Route::Tor => StageOutcome::Ran(
            "Tor onion circuit · relay learns no source IP".to_string(),
        ),
        Route::Direct => StageOutcome::NotApplicable(
            "direct transport exposes the source IP; select Tor in transport settings to seal it"
                .to_string(),
        ),
        Route::Offline => StageOutcome::NotApplicable("not yet sent".to_string()),
    };
    self.set(Stage::Seal, outcome);
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --workspace -p pouch-core manifest 2>&1 | tail -40`
Expected: PASS, all of them, including the pre-existing ones (`a_new_manifest_claims_only_what_has_happened`, `a_direct_message_never_reports_tor`, etc.).

- [ ] **Step 5: Commit**

```bash
git add core/src/manifest.rs
git commit -m "Manifest: message padding starts Pending, add honest per-route sealed-sender reporting"
```

---

### Task 4: Pad message payloads before encryption, unpad after decryption

**Files:**
- Modify: `core/src/api/messaging.rs`
- Create: entry in `docs/DECISIONS.md` (D-041)

**Interfaces:**
- Consumes: `crate::padding::pad`/`crate::padding::unpad` (Task 2), `Manifest::padded` (pre-existing).
- Produces: no new public signatures — `send_payload`, `send_message`, `receive_messages` keep their existing signatures; only their internal byte pipeline changes.

Ordering, per SPEC §6.5.2/§7.1 and the existing attachment pipeline: compress → pad → encrypt on send, decrypt → unpad → decompress on receive.

- [ ] **Step 1: Write the failing test**

Add to `core/tests/end_to_end.rs` (follow the existing pattern in that file — `RelayConfig::insecure_local`, a live relay on a random loopback port, two `Pouch::create` clients):

```rust
#[tokio::test]
async fn a_short_message_reports_padding_and_still_round_trips() {
    let addr = spawn_relay().await; // reuse whatever helper the file already uses to start a relay — check the top of end_to_end.rs for its exact name before writing this line
    let relay = || RelayConfig::insecure_local(format!("http://{addr}"));
    let brian_db = temp_db_path(); // match the existing naming helper in this file
    let mai_db = temp_db_path();

    let mut brian = Pouch::create("Brian", &brian_db, &mut key(0x77), relay()).expect("brian");
    let mut mai = Pouch::create("Mai", &mai_db, &mut key(0x88), relay()).expect("mai");

    let code = mai.invite_code().expect("invite");
    let conversation_id = brian.add_contact("Mai", &code).await.expect("add contact");
    mai.receive_messages().await.expect("mai joins");

    let manifest = brian
        .send_message(&conversation_id, "hi")
        .await
        .expect("send");

    let (_, pad_outcome) = manifest
        .stages()
        .iter()
        .find(|(s, _)| *s == pouch_core::Stage::Pad)
        .expect("pad stage present");
    assert!(pad_outcome.ran(), "padding did not run");

    let received = mai.receive_messages().await.expect("receive");
    assert_eq!(received.messages.len(), 1);
    assert_eq!(received.messages[0].body, "hi");
}
```

Before writing this, open `core/tests/end_to_end.rs` and copy the *exact* names its existing tests use for spawning a relay and generating a temp db path (visible in the file already read during planning — this plan does not repeat them verbatim because minor helper names may have shifted; match what is actually there).

- [ ] **Step 2: Run it to verify it fails on the padding assertion**

Run: `cargo test --workspace -p pouch-core --test end_to_end a_short_message_reports_padding 2>&1 | tail -30`
Expected: FAIL at `pad_outcome.ran()` — today `Stage::Pad` is never set to `Ran` by `send_message`.

- [ ] **Step 3: Implement — `send_payload`**

In `core/src/api/messaging.rs`, change:

```rust
pub(super) async fn send_payload(
    &mut self,
    conversation_id: &str,
    payload: &Payload,
) -> Result<String, ApiError> {
    let encoded = serde_json::to_vec(payload).map_err(|_| CryptoError::Encryption)?;
    // Every payload is compressed, always — see send_message for why this
    // is not a per-message choice.
    let compressed = compression::compress(&encoded).map_err(|_| CryptoError::Encryption)?;

    let conversation = self
        .conversations
        .get_mut(conversation_id)
        .ok_or(ApiError::UnknownConversation)?;

    let blob = conversation.encrypt(&self.identity, &compressed, &self.provider)?;
    let peer_inbox = conversation.peer_inbox_id().to_string();
    let message_id = self.relay.send(&peer_inbox, &blob).await?;
    self.persist_mls_state()?;
    Ok(message_id)
}
```

to:

```rust
pub(super) async fn send_payload(
    &mut self,
    conversation_id: &str,
    payload: &Payload,
) -> Result<String, ApiError> {
    let encoded = serde_json::to_vec(payload).map_err(|_| CryptoError::Encryption)?;
    // Every payload is compressed, always — see send_message for why this
    // is not a per-message choice. Padded after compressing, same ordering
    // as the attachment pipeline (SPEC §7.1) — padding before compression
    // would defeat compression, and padding after encryption would not hide
    // size at all.
    let compressed = compression::compress(&encoded).map_err(|_| CryptoError::Encryption)?;
    let padded = crate::padding::pad(&compressed);

    let conversation = self
        .conversations
        .get_mut(conversation_id)
        .ok_or(ApiError::UnknownConversation)?;

    let blob = conversation.encrypt(&self.identity, &padded, &self.provider)?;
    let peer_inbox = conversation.peer_inbox_id().to_string();
    let message_id = self.relay.send(&peer_inbox, &blob).await?;
    self.persist_mls_state()?;
    Ok(message_id)
}
```

- [ ] **Step 4: Implement — `send_message`**

Change the body between the compression call and the encrypt call:

```rust
        let compressed = compression::compress(&encoded).map_err(|_| CryptoError::Encryption)?;
        manifest.compressed(COMPRESSION_ALGORITHM, encoded.len(), compressed.len());

        let blob = conversation.encrypt(&self.identity, &compressed, &self.provider)?;
```

becomes:

```rust
        let compressed = compression::compress(&encoded).map_err(|_| CryptoError::Encryption)?;
        manifest.compressed(COMPRESSION_ALGORITHM, encoded.len(), compressed.len());

        let padded = crate::padding::pad(&compressed);
        manifest.padded(compressed.len(), padded.len());

        let blob = conversation.encrypt(&self.identity, &padded, &self.provider)?;
```

Leave the rest of `send_message` alone for now — Task 6 changes the `manifest.routed(Route::Direct, ...)` line to use the real route once `RelayClient::route()` exists. Do not change that line in this task.

- [ ] **Step 5: Implement — `receive_messages`**

Change:
```rust
                    let Ok(decompressed) = compression::decompress(&message.plaintext) else {
                        continue;
                    };
                    let Ok(payload) = serde_json::from_slice::<Payload>(&decompressed) else {
                        continue;
                    };
```
to:
```rust
                    let Some(unpadded) = crate::padding::unpad(&message.plaintext) else {
                        continue;
                    };
                    let Ok(decompressed) = compression::decompress(&unpadded) else {
                        continue;
                    };
                    let Ok(payload) = serde_json::from_slice::<Payload>(&decompressed) else {
                        continue;
                    };
```

This is the same "protocol noise or a build mismatch, not a message" handling the surrounding code already uses for the compression and JSON steps — a message that fails to unpad is silently left unacknowledged (survives to the next poll) rather than crashing the receive loop, matching the existing pattern exactly.

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test --workspace -p pouch-core --test end_to_end a_short_message_reports_padding 2>&1 | tail -30`
Expected: PASS.

- [ ] **Step 7: Run the full suite — this is a wire-format break**

Run: `cargo test --workspace 2>&1 | tail -40`

Expected: all pass. If any existing end-to-end test fails on a decrypt/decompress mismatch, it means some fixture is holding a pre-padding blob across the change (unlikely, since every test both sends and receives within the same run) — investigate rather than paper over.

- [ ] **Step 8: Record the wire-format break in `docs/DECISIONS.md`**

Read the tail of `docs/DECISIONS.md` first (D-040 is the last entry after Task 1) and append:

```markdown
---

## D-041 — Fixed-size padding extended to message payloads; wire-format break
**Date:** 2026-08-02 · **Status:** accepted

**Decision.** `core/src/padding.rs`'s fixed buckets (64 KB/256 KB/1 MB/4 MB/
16 MB, then 16 MB increments — SPEC §7.1 step 3), already used for
attachments since D-038, now also pad every message payload: compress → pad
→ encrypt on send, decrypt → unpad → decompress on receive
(`core/src/api/messaging.rs`). Manifest stage 4 (`PADDED`) reports `Ran` for
every message from this build forward, matching stage 3's (`COMPRESSED`)
D-036 precedent.

**Why the smallest bucket (64 KB) for a short text message is not wasteful
in the way it looks.** The relay already accepts blobs up to
`MAX_BLOB_BYTES` (20 MB); the fixed buckets exist to blunt size
fingerprinting, the same property D-038's attachment padding provides — a
two-word reply and a paragraph both land in the 64 KB bucket if both compress
under it, so an observer of blob size alone cannot distinguish message
length classes. This is a bandwidth-for-metadata trade the project already
made once for attachments; extending it to messages is the same trade, not
a new one.

**Wire compatibility, same reasoning as D-036.** A build from before this
commit sends unpadded ciphertext; this build's `unpad` step will find no
valid length prefix in an old peer's message and silently drop it, the same
way an unrecognised payload already is (protocol noise or a version
mismatch, not a message a user should see). Both sides of a conversation
need to be this build or newer. This project has no live population of
mismatched builds to protect, so a clean break is the honest choice over
adding version-sniffing complexity to preserve compatibility nothing needs.

**Rejected alternative.** A separate, message-specific bucket scheme rather
than reusing the attachment one. Rejected: SPEC §7.1 already specifies one
scheme, both message and attachment payloads are compact binary blobs by
the time they reach padding, and a second scheme would be a second thing to
get right for no stated benefit — moved to `core/src/padding.rs` in the same
session (see the relocation itself, a mechanical move with no logic change).
```

- [ ] **Step 9: Commit**

```bash
git add core/src/api/messaging.rs docs/DECISIONS.md
git commit -m "Pad message payloads before encryption, unpad after decryption (D-041)"
```

---

### Task 5: Restructure `core/src/transport.rs` into a directory; add a route accessor

**Files:**
- Create: `core/src/transport/mod.rs` (moved from `core/src/transport.rs`, restructured)
- Delete: `core/src/transport.rs`

**Interfaces:**
- Produces: `RelayClient::route(&self) -> Route`, `TransportError::TorBootstrapFailed(String)` variant. `RelayClient::new` (Direct constructor) keeps its exact existing signature — no caller changes.
- Consumed by: Task 6 (`core/src/transport/tor.rs`, in the same directory), Task 7 (`core/src/api/mod.rs`).

This task only restructures the Direct path and adds the accessor; Task 6 adds the Tor backend into the `Backend` enum this task introduces.

- [ ] **Step 1: Create the directory and move the file**

Read `core/src/transport.rs` in full (already read during planning — reproduced in full below with the changes applied; every doc comment, every existing test, and every existing method body for `send`/`collect`/`acknowledge`/`reachable`/`address` on the Direct path stay byte-for-byte identical except where noted).

Create `core/src/transport/mod.rs`:

```rust
//! Talking to the relay.
//!
//! The relay is assumed hostile (`docs/THREAT_MODEL.md` §3). This module
//! therefore treats every response as untrusted input and never lets the relay
//! influence anything except *which bytes arrive* — the bytes themselves mean
//! nothing until MLS has authenticated them.
//!
//! Phase 1 is direct TLS with the relay certificate pinned by SPKI hash
//! (D-017). Phase 4 adds Tor (`tor` submodule) as a second, additive backend
//! — `RelayClient` picks between them at construction time and reports which
//! one it is actually using via [`RelayClient::route`], which the manifest
//! and the Custody Strip both read rather than assuming.

pub mod tor;

use serde::{Deserialize, Serialize};

pub use tor::TorRelayConfig;

/// How a message reached, or will reach, the relay.
///
/// Reported by the manifest at stage 7 and by the Custody Strip. It must always
/// describe what actually happened — a manifest that claims Tor for a message
/// that went direct is worse than no manifest (SPEC §8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Route {
    /// Straight to the relay over TLS 1.3. The relay sees the client's IP.
    Direct,
    /// Through a Tor onion circuit. The relay never learns the client's IP.
    Tor,
    /// No connection. Messages are queued locally.
    Offline,
}

impl Route {
    /// The label shown in the Custody Strip.
    pub fn label(&self) -> &'static str {
        match self {
            Route::Direct => "DIRECT",
            Route::Tor => "TOR",
            Route::Offline => "OFFLINE",
        }
    }

    /// The honest one-line description shown when the field is opened.
    ///
    /// Neither option is labelled "the secure one". The trade is stated and the
    /// user chooses (SPEC §6.7.9).
    pub fn explanation(&self) -> &'static str {
        match self {
            Route::Direct => {
                "Messages go straight to the relay over TLS 1.3. The relay sees the IP address \
                 you connect from. Message content stays encrypted either way."
            }
            Route::Tor => {
                "Messages route through a Tor onion circuit. The relay never learns your IP \
                 address. Your internet provider can still see that you are using Tor."
            }
            Route::Offline => {
                "No connection to the relay. Messages you write are queued on this device and \
                 send when you reconnect."
            }
        }
    }
}

/// Anything that can go wrong talking to the relay.
///
/// Every variant carries enough for the UI to say what happened and what to do
/// (SPEC §6.9). None of them is "something went wrong".
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// No connection could be made.
    #[error("no connection to the relay at {0}; the message will send when you reconnect")]
    Unreachable(String),
    /// The relay's certificate did not match the pinned key, or a remote relay
    /// was configured without a pin at all.
    ///
    /// This is the loud one. It means the connection is not demonstrably to the
    /// relay the user configured, and the correct response is to stop.
    #[error("the relay at {0} could not be verified against a pinned key; Pouch will not connect")]
    PinMismatch(String),
    /// The relay rejected the request.
    #[error("the relay rejected the request (status {0})")]
    Rejected(u16),
    /// The relay returned something unreadable.
    #[error("the relay returned a response Pouch could not read")]
    MalformedResponse,
    /// The blob exceeded what the relay accepts.
    #[error("this message is too large for the relay to accept")]
    TooLarge,
    /// Bootstrapping a Tor connection failed — no consensus reachable, no
    /// circuit could be built, or the onion address could not be resolved.
    /// Distinct from `Unreachable`, which means a specific relay did not
    /// answer; this means Tor itself never got going.
    #[error("could not establish a Tor connection: {0}")]
    TorBootstrapFailed(String),
}

/// A blob waiting in an inbox.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The relay's random identifier for this blob.
    pub message_id: String,
    /// Ciphertext, exactly as stored. Not yet authenticated — it came from a
    /// hostile source and means nothing until MLS says otherwise.
    pub blob: Vec<u8>,
}

/// Where the relay lives and how its certificate is pinned.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Base URL, e.g. `https://relay.example:8443`.
    pub base_url: String,
    /// SHA-256 of the relay certificate's SubjectPublicKeyInfo, hex encoded.
    ///
    /// `None` disables pinning and is only accepted for a loopback address
    /// during development. [`RelayClient::new`] enforces that.
    pub spki_pin: Option<String>,
}

impl RelayConfig {
    /// A local development relay with no TLS and no pinning.
    ///
    /// Named `insecure_local` rather than `local` so a call site reads as what
    /// it is. No user should ever be running this configuration.
    pub fn insecure_local(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            spki_pin: None,
        }
    }

    /// A relay reached over TLS with its public key pinned.
    pub fn pinned(base_url: impl Into<String>, spki_pin: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            spki_pin: Some(spki_pin.into()),
        }
    }

    /// Whether the configured host is genuinely a loopback address.
    ///
    /// Compared against the host component after an exact prefix match, so a
    /// registered domain like `127.0.0.1.example.com` — which a `starts_with`
    /// check on the whole URL would happily accept — is not treated as local.
    pub fn is_loopback(&self) -> bool {
        let Some(rest) = self.base_url.strip_prefix("http://") else {
            return false;
        };
        // Strip anything after the authority.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();

        // An IPv6 literal is bracketed; anything else splits on the port colon.
        let host = if let Some(end) = authority.strip_prefix('[') {
            match end.split_once(']') {
                Some((inner, after)) if after.is_empty() || after.starts_with(':') => inner,
                _ => return false,
            }
        } else {
            authority.split(':').next().unwrap_or_default()
        };

        matches!(host, "127.0.0.1" | "localhost" | "::1")
    }
}

/// The two ways `RelayClient` can actually reach a relay.
enum Backend {
    Direct(reqwest::Client),
    Tor(tor::TorBackend),
}

/// A client for one relay.
pub struct RelayClient {
    /// Human-readable address for display in the manifest, Custody Strip,
    /// and Security details — an `https://` URL for Direct, `onion:port` for
    /// Tor.
    address: String,
    route: Route,
    backend: Backend,
}

impl RelayClient {
    /// Builds a direct-transport client.
    ///
    /// **Refuses to build an unpinned client for a non-loopback address.** An
    /// unpinned TLS connection to a remote relay relies on the public CA
    /// system, which is exactly the trusted third party pinning exists to
    /// remove (D-017). A hard error rather than a warning means the insecure
    /// configuration cannot be reached by forgetting to set something.
    pub fn new(config: RelayConfig) -> Result<Self, TransportError> {
        if config.spki_pin.is_none() && !config.is_loopback() {
            return Err(TransportError::PinMismatch(config.base_url.clone()));
        }

        let http = reqwest::Client::builder()
            // A hostile relay must not be able to hold a client open forever.
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| TransportError::Unreachable(config.base_url.clone()))?;

        Ok(Self {
            address: config.base_url,
            route: Route::Direct,
            backend: Backend::Direct(http),
        })
    }

    /// Builds a Tor-transport client, bootstrapping a Tor connection.
    ///
    /// This is async and can take real time — Tor bootstrap means fetching a
    /// consensus and building a first circuit, not a local operation. See
    /// `tor::TorBackend::connect` for the implementation.
    pub async fn connect_tor(config: TorRelayConfig) -> Result<Self, TransportError> {
        let address = format!("{}:{}", config.onion_host, config.onion_port);
        let backend = tor::TorBackend::connect(config).await?;
        Ok(Self {
            address,
            route: Route::Tor,
            backend: Backend::Tor(backend),
        })
    }

    /// The relay address, for display in the manifest and Custody Strip.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Which route this client actually uses. Read by the manifest and the
    /// Custody Strip instead of either assuming Direct or reconstructing it
    /// from the address string.
    pub fn route(&self) -> Route {
        self.route
    }

    /// Posts a blob to an inbox. Returns the relay's identifier for it.
    pub async fn send(&self, inbox_id: &str, blob: &[u8]) -> Result<String, TransportError> {
        match &self.backend {
            Backend::Direct(http) => self.send_direct(http, inbox_id, blob).await,
            Backend::Tor(tor_backend) => tor_backend.send(inbox_id, blob).await,
        }
    }

    async fn send_direct(
        &self,
        http: &reqwest::Client,
        inbox_id: &str,
        blob: &[u8],
    ) -> Result<String, TransportError> {
        let url = format!("{}/inbox/{inbox_id}", self.address);

        let response = http
            .post(&url)
            .body(blob.to_vec())
            .send()
            .await
            .map_err(|_| TransportError::Unreachable(self.address.clone()))?;

        let status = response.status();
        if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
            return Err(TransportError::TooLarge);
        }
        if !status.is_success() {
            return Err(TransportError::Rejected(status.as_u16()));
        }

        #[derive(Deserialize)]
        struct Accepted {
            message_id: String,
        }

        let accepted: Accepted = response
            .json()
            .await
            .map_err(|_| TransportError::MalformedResponse)?;

        Ok(accepted.message_id)
    }

    /// Collects what is waiting for an inbox, without erasing it.
    pub async fn collect(&self, inbox_id: &str) -> Result<Vec<Envelope>, TransportError> {
        match &self.backend {
            Backend::Direct(http) => self.collect_direct(http, inbox_id).await,
            Backend::Tor(tor_backend) => tor_backend.collect(inbox_id).await,
        }
    }

    async fn collect_direct(
        &self,
        http: &reqwest::Client,
        inbox_id: &str,
    ) -> Result<Vec<Envelope>, TransportError> {
        use base64::Engine as _;

        let url = format!("{}/inbox/{inbox_id}", self.address);

        let response = http
            .get(&url)
            .send()
            .await
            .map_err(|_| TransportError::Unreachable(self.address.clone()))?;

        if !response.status().is_success() {
            return Err(TransportError::Rejected(response.status().as_u16()));
        }

        #[derive(Deserialize)]
        struct Waiting {
            message_id: String,
            blob: String,
        }
        #[derive(Deserialize)]
        struct Collected {
            messages: Vec<Waiting>,
        }

        let collected: Collected = response
            .json()
            .await
            .map_err(|_| TransportError::MalformedResponse)?;

        collected
            .messages
            .into_iter()
            .map(|m| {
                let blob = base64::engine::general_purpose::STANDARD
                    .decode(m.blob.as_bytes())
                    .map_err(|_| TransportError::MalformedResponse)?;
                Ok(Envelope {
                    message_id: m.message_id,
                    blob,
                })
            })
            .collect()
    }

    /// Tells the relay a set of blobs has been stored and may be erased.
    ///
    /// Called only after the messages are safely in the local database. Doing
    /// it earlier would lose messages on a crash between the two steps.
    pub async fn acknowledge(
        &self,
        inbox_id: &str,
        message_ids: &[String],
    ) -> Result<usize, TransportError> {
        if message_ids.is_empty() {
            return Ok(0);
        }
        match &self.backend {
            Backend::Direct(http) => self.acknowledge_direct(http, inbox_id, message_ids).await,
            Backend::Tor(tor_backend) => tor_backend.acknowledge(inbox_id, message_ids).await,
        }
    }

    async fn acknowledge_direct(
        &self,
        http: &reqwest::Client,
        inbox_id: &str,
        message_ids: &[String],
    ) -> Result<usize, TransportError> {
        let url = format!("{}/inbox/{inbox_id}/ack", self.address);

        #[derive(Serialize)]
        struct Ack<'a> {
            message_ids: &'a [String],
        }
        #[derive(Deserialize)]
        struct Erased {
            erased: usize,
        }

        let response = http
            .post(&url)
            .json(&Ack { message_ids })
            .send()
            .await
            .map_err(|_| TransportError::Unreachable(self.address.clone()))?;

        if !response.status().is_success() {
            return Err(TransportError::Rejected(response.status().as_u16()));
        }

        let erased: Erased = response
            .json()
            .await
            .map_err(|_| TransportError::MalformedResponse)?;

        Ok(erased.erased)
    }

    /// Whether the relay answers at all. Drives the Custody Strip's transport
    /// field between the configured route and `OFFLINE`.
    pub async fn reachable(&self) -> bool {
        match &self.backend {
            Backend::Direct(http) => {
                let url = format!("{}/health", self.address);
                matches!(http.get(&url).send().await, Ok(r) if r.status().is_success())
            }
            Backend::Tor(tor_backend) => tor_backend.reachable().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unpinned_remote_relay_is_refused() {
        let config = RelayConfig::insecure_local("https://relay.example.com");
        assert!(matches!(
            RelayClient::new(config),
            Err(TransportError::PinMismatch(_))
        ));
    }

    #[test]
    fn an_unpinned_loopback_relay_is_allowed_for_development() {
        for url in [
            "http://127.0.0.1:8443",
            "http://localhost:8443",
            "http://[::1]:8443",
            "http://127.0.0.1",
        ] {
            assert!(
                RelayClient::new(RelayConfig::insecure_local(url)).is_ok(),
                "{url} should be usable for local development"
            );
        }
    }

    #[test]
    fn a_pinned_remote_relay_is_allowed() {
        let config = RelayConfig::pinned("https://relay.example.com", "a".repeat(64));
        assert!(RelayClient::new(config).is_ok());
    }

    #[test]
    fn a_hostname_that_merely_begins_with_a_loopback_address_is_not_loopback() {
        for url in [
            "http://127.0.0.1.evil.com",
            "http://127.0.0.1.evil.com:8443/inbox",
            "http://localhost.evil.com",
            "http://[::1].evil.com",
        ] {
            assert!(
                RelayClient::new(RelayConfig::insecure_local(url)).is_err(),
                "{url} must not be treated as loopback"
            );
        }
    }

    #[test]
    fn https_is_never_treated_as_loopback_and_so_always_needs_a_pin() {
        assert!(!RelayConfig::insecure_local("https://127.0.0.1:8443").is_loopback());
    }

    #[test]
    fn every_route_names_what_it_actually_does() {
        assert_eq!(Route::Direct.label(), "DIRECT");
        assert_eq!(Route::Tor.label(), "TOR");
        assert_eq!(Route::Offline.label(), "OFFLINE");

        assert!(Route::Direct.explanation().contains("IP address"));
        assert!(Route::Tor.explanation().contains("internet provider"));
    }

    #[test]
    fn no_route_claims_to_be_the_secure_one() {
        for route in [Route::Direct, Route::Tor, Route::Offline] {
            let text = route.explanation().to_lowercase();
            for banned in [
                "unbreakable",    // guardrail-allow: asserted absent
                "military grade", // guardrail-allow: asserted absent
                "100% secure",    // guardrail-allow: asserted absent
                "totally safe",   // guardrail-allow: asserted absent
            ] {
                assert!(
                    !text.contains(banned),
                    "{banned:?} appears in {} copy",
                    route.label()
                );
            }
        }
    }

    #[test]
    fn a_freshly_built_direct_client_reports_the_direct_route() {
        let client = RelayClient::new(RelayConfig::insecure_local("http://127.0.0.1:8443"))
            .expect("builds");
        assert_eq!(client.route(), Route::Direct);
    }
}
```

Delete `core/src/transport.rs`.

- [ ] **Step 2: Compile-check before Task 6 fills in `tor::TorBackend`**

This will not compile yet — `tor::TorBackend` does not exist. Do not attempt to run tests after this step in isolation; Task 6 is the completion of this same restructuring and the two are one working unit together. If working through this plan strictly sequentially, create a placeholder `core/src/transport/tor.rs` containing only:

```rust
//! Tor-routed transport (Phase 4). Filled in by the next task.
```

so `pub mod tor;` in `mod.rs` resolves, then run `cargo check -p pouch-core 2>&1 | tail -60` and confirm the only errors are about `tor::TorBackend`/`tor::TorRelayConfig` not existing — proof the Direct-path restructuring itself is otherwise sound before Task 6 adds the missing pieces.

- [ ] **Step 3: Commit as work-in-progress, to be completed by Task 6**

```bash
git add core/src/transport/mod.rs core/src/transport/tor.rs
git rm core/src/transport.rs
git commit -m "Restructure transport.rs into a directory; add RelayClient::route (WIP, completed by next commit)"
```

---

### Task 6: Tor-routed `RelayClient` backend

**Files:**
- Modify: `core/src/transport/tor.rs` (replaces the placeholder from Task 5)

**Interfaces:**
- Consumes: `Backend`, `TransportError`, `Envelope` (private to `mod.rs` — `Envelope` is `pub`, `Backend` and the `Backend::Tor` variant are private to the `transport` module, which is fine since `tor.rs` is a submodule and can see them via `super::`).
- Produces: `pub struct TorRelayConfig { pub onion_host: String, pub onion_port: u16, pub state_dir: String }`, `pub(super) struct TorBackend` with `async fn connect(config: TorRelayConfig) -> Result<Self, TransportError>`, `async fn send(&self, inbox_id: &str, blob: &[u8]) -> Result<String, TransportError>`, `async fn collect(&self, inbox_id: &str) -> Result<Vec<Envelope>, TransportError>`, `async fn acknowledge(&self, inbox_id: &str, message_ids: &[String]) -> Result<usize, TransportError>`, `async fn reachable(&self) -> bool`.

**Verified API surface this task relies on** (checked directly against docs.rs for the pinned `=0.43.0` release, not secondhand): `arti_client::TorClient::create_bootstrapped(config: TorClientConfig) -> Result<Arc<Self>>` (async); `TorClient::connect<A: IntoTorAddr>(&self, target: A) -> Result<DataStream>` (async, `DataStream: AsyncRead + AsyncWrite`); `hyper_util::client::legacy::Client::builder(TokioExecutor).build(connector)`; `hyper_util::rt::TokioIo::new(io)`. If any signature in this task's code does not compile as written, check `https://docs.rs/arti-client/0.43.0/` / `https://docs.rs/hyper-util/0.1.20/` for the exact current shape before changing the approach — this is normal integration work against a real external API, not a sign the architecture is wrong.

- [ ] **Step 1: Write the failing test — malformed config is rejected before touching the network**

This is the one part of Tor transport testable without a real Tor bootstrap (which needs live network access and takes real wall-clock time — Steps 6–7 below cover that separately, marked `#[ignore]`). Add to `core/src/transport/tor.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_onion_host_that_is_not_a_valid_hostname_is_rejected_before_bootstrapping() {
        let config = TorRelayConfig {
            onion_host: "not a valid host\0".to_string(),
            onion_port: 8443,
            state_dir: std::env::temp_dir()
                .join("pouch-tor-test-invalid-host")
                .to_string_lossy()
                .to_string(),
        };
        let result = TorBackend::connect(config).await;
        assert!(result.is_err(), "a malformed onion host must not silently proceed");
    }
}
```

- [ ] **Step 2: Run it to verify it fails (does not compile — `TorBackend`/`TorRelayConfig` do not exist yet in real form)**

Run: `cargo test --workspace -p pouch-core -- transport::tor 2>&1 | tail -40`
Expected: compile error, `TorBackend`/`TorRelayConfig` unresolved beyond the placeholder.

- [ ] **Step 3: Implement `TorRelayConfig` and the bootstrap**

Replace `core/src/transport/tor.rs`'s placeholder content with:

```rust
//! Tor-routed transport (Phase 4, D-039).
//!
//! `reqwest` has no hook for a custom low-level connector, and arti-client
//! has no in-process SOCKS listener (only the separate `arti` CLI binary
//! does, which would mean shelling out to a subprocess rather than using an
//! audited library through its intended interface). This backend is
//! therefore built directly on `hyper`/`hyper-util`: a small
//! [`TorConnector`] implements `tower::Service<http::Uri>` by dialing the
//! request's own host:port through an already-bootstrapped
//! [`arti_client::TorClient`], and `hyper_util::client::legacy::Client`
//! drives ordinary HTTP requests over that.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arti_client::{TorClient, TorClientConfig};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use tor_rtcompat::PreferredRuntime;

use super::{Envelope, TransportError};

/// Where the Tor-routed relay lives, and where this client's Tor state
/// (guard relays, consensus cache, onion service keys — none of it a
/// message secret) persists across runs.
#[derive(Debug, Clone)]
pub struct TorRelayConfig {
    /// The relay's onion address, without scheme or port — e.g.
    /// `"abcdefg...onion"`.
    pub onion_host: String,
    /// The port the relay's onion service listens on.
    pub onion_port: u16,
    /// Directory for Tor's own state and cache. Never inside the encrypted
    /// database: this is bootstrap/circuit data, not a key or message.
    pub state_dir: String,
}

/// A single-target Tor connector: every call dials whatever host:port the
/// request's own URI names, through the already-bootstrapped `TorClient`.
#[derive(Clone)]
struct TorConnector {
    tor_client: Arc<TorClient<PreferredRuntime>>,
}

impl tower_service::Service<http::Uri> for TorConnector {
    type Response = TokioIo<arti_client::DataStream>;
    type Error = TransportError;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let tor_client = self.tor_client.clone();
        let host = uri.host().unwrap_or_default().to_string();
        let port = uri.port_u16().unwrap_or(80);
        Box::pin(async move {
            let stream = tor_client
                .connect((host.as_str(), port))
                .await
                .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;
            Ok(TokioIo::new(stream))
        })
    }
}

/// The Tor-routed half of `RelayClient`.
pub(super) struct TorBackend {
    hyper_client: HyperClient<TorConnector, Full<Bytes>>,
    onion_host: String,
    onion_port: u16,
}

impl TorBackend {
    /// Bootstraps a Tor connection and readies a client for one onion
    /// target. Slow by nature — fetching a consensus and building a first
    /// circuit is real network I/O, not a local operation — so this must
    /// never be called from a fast path.
    pub(super) async fn connect(config: TorRelayConfig) -> Result<Self, TransportError> {
        if config.onion_host.trim().is_empty()
            || config.onion_host.contains('\0')
            || config.onion_host.chars().any(|c| c.is_control())
        {
            return Err(TransportError::TorBootstrapFailed(
                "the configured onion address is not a valid hostname".to_string(),
            ));
        }

        let mut tor_config_builder = TorClientConfig::builder();
        tor_config_builder
            .storage()
            .state_dir(config.state_dir.clone().into())
            .cache_dir(config.state_dir.clone().into());
        let tor_config = tor_config_builder
            .build()
            .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;

        let tor_client = TorClient::create_bootstrapped(tor_config)
            .await
            .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;

        let connector = TorConnector {
            tor_client: tor_client.clone(),
        };
        let hyper_client = HyperClient::builder(TokioExecutor::new()).build(connector);

        Ok(Self {
            hyper_client,
            onion_host: config.onion_host,
            onion_port: config.onion_port,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}:{}{path}", self.onion_host, self.onion_port)
    }

    pub(super) async fn send(&self, inbox_id: &str, blob: &[u8]) -> Result<String, TransportError> {
        let uri = self
            .url(&format!("/inbox/{inbox_id}"))
            .parse::<http::Uri>()
            .map_err(|_| TransportError::MalformedResponse)?;

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .body(Full::new(Bytes::copy_from_slice(blob)))
            .map_err(|_| TransportError::MalformedResponse)?;

        let response = self
            .hyper_client
            .request(request)
            .await
            .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;

        let status = response.status();
        if status == http::StatusCode::PAYLOAD_TOO_LARGE {
            return Err(TransportError::TooLarge);
        }
        if !status.is_success() {
            return Err(TransportError::Rejected(status.as_u16()));
        }

        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|_| TransportError::MalformedResponse)?
            .to_bytes();

        #[derive(Deserialize)]
        struct Accepted {
            message_id: String,
        }
        let accepted: Accepted =
            serde_json::from_slice(&body).map_err(|_| TransportError::MalformedResponse)?;
        Ok(accepted.message_id)
    }

    pub(super) async fn collect(&self, inbox_id: &str) -> Result<Vec<Envelope>, TransportError> {
        use base64::Engine as _;

        let uri = self
            .url(&format!("/inbox/{inbox_id}"))
            .parse::<http::Uri>()
            .map_err(|_| TransportError::MalformedResponse)?;

        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .map_err(|_| TransportError::MalformedResponse)?;

        let response = self
            .hyper_client
            .request(request)
            .await
            .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(TransportError::Rejected(response.status().as_u16()));
        }

        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|_| TransportError::MalformedResponse)?
            .to_bytes();

        #[derive(Deserialize)]
        struct Waiting {
            message_id: String,
            blob: String,
        }
        #[derive(Deserialize)]
        struct Collected {
            messages: Vec<Waiting>,
        }
        let collected: Collected =
            serde_json::from_slice(&body).map_err(|_| TransportError::MalformedResponse)?;

        collected
            .messages
            .into_iter()
            .map(|m| {
                let blob = base64::engine::general_purpose::STANDARD
                    .decode(m.blob.as_bytes())
                    .map_err(|_| TransportError::MalformedResponse)?;
                Ok(Envelope {
                    message_id: m.message_id,
                    blob,
                })
            })
            .collect()
    }

    pub(super) async fn acknowledge(
        &self,
        inbox_id: &str,
        message_ids: &[String],
    ) -> Result<usize, TransportError> {
        #[derive(Serialize)]
        struct Ack<'a> {
            message_ids: &'a [String],
        }
        #[derive(Deserialize)]
        struct Erased {
            erased: usize,
        }

        let body_bytes =
            serde_json::to_vec(&Ack { message_ids }).map_err(|_| TransportError::MalformedResponse)?;

        let uri = self
            .url(&format!("/inbox/{inbox_id}/ack"))
            .parse::<http::Uri>()
            .map_err(|_| TransportError::MalformedResponse)?;

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|_| TransportError::MalformedResponse)?;

        let response = self
            .hyper_client
            .request(request)
            .await
            .map_err(|e| TransportError::TorBootstrapFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(TransportError::Rejected(response.status().as_u16()));
        }

        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|_| TransportError::MalformedResponse)?
            .to_bytes();
        let erased: Erased =
            serde_json::from_slice(&body).map_err(|_| TransportError::MalformedResponse)?;
        Ok(erased.erased)
    }

    pub(super) async fn reachable(&self) -> bool {
        let Ok(uri) = self.url("/health").parse::<http::Uri>() else {
            return false;
        };
        let Ok(request) = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
        else {
            return false;
        };
        matches!(self.hyper_client.request(request).await, Ok(r) if r.status().is_success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_onion_host_that_is_not_a_valid_hostname_is_rejected_before_bootstrapping() {
        let config = TorRelayConfig {
            onion_host: "not a valid host\0".to_string(),
            onion_port: 8443,
            state_dir: std::env::temp_dir()
                .join("pouch-tor-test-invalid-host")
                .to_string_lossy()
                .to_string(),
        };
        let result = TorBackend::connect(config).await;
        assert!(result.is_err(), "a malformed onion host must not silently proceed");
    }

    /// Ignored by default: this bootstraps a real Tor connection to the live
    /// Tor network, which needs network access and takes real time (seconds
    /// to tens of seconds). Run explicitly with `cargo test -- --ignored`
    /// when verifying this against the real network — see
    /// `docs/PROGRESS.md`'s Phase 4 manual verification checklist.
    #[tokio::test]
    #[ignore]
    async fn a_real_bootstrap_against_a_well_known_onion_service_succeeds() {
        let config = TorRelayConfig {
            // The Tor Project's own onion mirror — stable, well-known,
            // suitable as a bootstrap smoke test that does not depend on
            // this project's own relay being deployed as an onion service.
            onion_host: "sdscoq7snet5uu3d4mos4ecemqzfgm5oiqu35bwgqrp6irhaad4tkjqd.onion".to_string(),
            onion_port: 80,
            state_dir: std::env::temp_dir()
                .join("pouch-tor-test-real-bootstrap")
                .to_string_lossy()
                .to_string(),
        };
        let backend = TorBackend::connect(config).await.expect("bootstraps");
        assert!(backend.reachable().await);
    }
}
```

- [ ] **Step 4: Update `core/src/transport/mod.rs` to use the real `TorBackend`**

The `mod.rs` from Task 5 already references `tor::TorBackend` and `tor::TorRelayConfig` — no change needed there now that this task fills them in for real. Confirm `pub use tor::TorRelayConfig;` at the top of `mod.rs` still matches.

- [ ] **Step 5: Run the non-network test**

Run: `cargo test --workspace -p pouch-core -- transport::tor::tests::an_onion_host 2>&1 | tail -30`
Expected: PASS. (The `#[ignore]`d real-bootstrap test does not run here.)

- [ ] **Step 6: Full workspace compile and test check**

Run: `cargo check --workspace --locked 2>&1 | tail -80` then `cargo test --workspace 2>&1 | tail -40`
Expected: compiles clean, all tests pass (the ignored test is skipped, not failed).

- [ ] **Step 7: Manual verification, recorded rather than skipped**

Run: `cargo test --workspace -p pouch-core -- --ignored transport::tor 2>&1 | tail -30` from a machine with real internet access (this environment's network reachability to Tor directory authorities was confirmed at the start of this planning session, but re-confirm at implementation time — network policy can change between sessions).
Expected: PASS, `backend.reachable()` returns `true` against the real Tor network. Record the result (pass/fail, and how long bootstrap took) in `docs/PROGRESS.md`'s Phase 4 section (Task 14 does the write-up; note the number here for that task to use).

- [ ] **Step 8: Commit**

```bash
git add core/src/transport/tor.rs
git commit -m "Tor-routed RelayClient backend via arti-client + hyper (D-039)"
```

---

### Task 7: Wire Tor into `Pouch` — `connect_tor`, `use_direct_relay`, real route reporting

**Files:**
- Modify: `core/src/api/mod.rs`
- Modify: `core/src/api/messaging.rs`
- Modify: `core/src/api/attachments.rs`

**Interfaces:**
- Consumes: `RelayClient::connect_tor`, `RelayClient::route` (Task 5/6).
- Produces: `Pouch::connect_tor(&mut self, config: TorRelayConfig) -> Result<(), ApiError>`, `Pouch::use_direct_relay(&mut self, config: RelayConfig) -> Result<(), ApiError>`, `Pouch::current_route(&self) -> Route`. `Pouch::transport_state` now reports the configured route, not always `Direct`. `send_message`/`send_payload`/attachment sending now call `manifest.routed`/`manifest.sealed` with the real route.

`Pouch::create`/`Pouch::open` are **not** touched by this task — this is the whole point of the additive design (see the plan header).

- [ ] **Step 1: Write the failing tests**

Add to `core/src/api/mod.rs`'s test module (create one if none exists at the bottom of the file — check first; `thread_safety` module already exists there, add a sibling `mod tests`):

```rust
#[cfg(test)]
mod transport_switching {
    use super::*;
    use crate::transport::RelayConfig;

    fn temp_db(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("pouch-transport-switch-{name}-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn a_freshly_created_pouch_reports_the_direct_route() {
        let db = temp_db("direct-default");
        let mut key = [0x42u8; 32];
        let pouch = Pouch::create(
            "Test",
            &db,
            &mut key,
            RelayConfig::insecure_local("http://127.0.0.1:1"),
        )
        .expect("creates");
        assert_eq!(pouch.current_route(), Route::Direct);
        let _ = std::fs::remove_file(&db);
    }

    #[tokio::test]
    async fn connect_tor_with_a_malformed_config_does_not_change_the_active_route() {
        // A failed Tor connection attempt must not silently leave the client
        // on some half-switched state, and it must never silently fall back
        // to Direct pretending the user's chosen route was honored.
        let db = temp_db("tor-fails-safe");
        let mut key = [0x43u8; 32];
        let mut pouch = Pouch::create(
            "Test",
            &db,
            &mut key,
            RelayConfig::insecure_local("http://127.0.0.1:1"),
        )
        .expect("creates");
        assert_eq!(pouch.current_route(), Route::Direct);

        let bad_tor_config = crate::transport::TorRelayConfig {
            onion_host: "not a valid host\0".to_string(),
            onion_port: 8443,
            state_dir: std::env::temp_dir()
                .join("pouch-transport-switch-tor-state")
                .to_string_lossy()
                .to_string(),
        };
        let result = pouch.connect_tor(bad_tor_config).await;
        assert!(result.is_err());
        assert_eq!(
            pouch.current_route(),
            Route::Direct,
            "a failed Tor connection attempt must not change the active route"
        );
        let _ = std::fs::remove_file(&db);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --workspace -p pouch-core transport_switching 2>&1 | tail -40`
Expected: FAIL to compile — `current_route`/`connect_tor` do not exist yet.

- [ ] **Step 3: Implement**

In `core/src/api/mod.rs`, add the `Route` import (it is likely already imported via `use crate::transport::{RelayClient, RelayConfig, Route};` — confirm) and add these methods near `transport_state`:

```rust
    /// Which route the relay client is currently configured to use —
    /// independent of whether it is reachable right now. Read by
    /// `transport_state` (which also checks reachability) and by the
    /// Transport settings screen to show which option is active.
    pub fn current_route(&self) -> Route {
        self.relay.route()
    }

    /// Switches this client to a Tor-routed relay connection.
    ///
    /// Bootstraps a real Tor connection, which is slow (seconds to tens of
    /// seconds) and can fail (no network, Tor blocked, bad onion address).
    /// On failure the existing relay client is left exactly as it was —
    /// this never silently falls back to Direct, because that would mean
    /// the app claiming Tor was selected while actually still exposing the
    /// user's IP.
    pub async fn connect_tor(
        &mut self,
        config: crate::transport::TorRelayConfig,
    ) -> Result<(), ApiError> {
        let new_relay = RelayClient::connect_tor(config).await?;
        self.relay = new_relay;
        Ok(())
    }

    /// Switches this client back to a direct relay connection.
    ///
    /// Unlike `connect_tor` this is fast (no bootstrap needed) so it stays
    /// synchronous, matching `RelayClient::new`.
    pub fn use_direct_relay(&mut self, config: RelayConfig) -> Result<(), ApiError> {
        self.relay = RelayClient::new(config)?;
        Ok(())
    }
```

Change `transport_state` from:
```rust
    pub async fn transport_state(&mut self) -> Route {
        if self.relay.reachable().await {
            Route::Direct
        } else {
            Route::Offline
        }
    }
```
to:
```rust
    pub async fn transport_state(&mut self) -> Route {
        if self.relay.reachable().await {
            self.relay.route()
        } else {
            Route::Offline
        }
    }
```

Update `security_details`'s `transport` field, which today hardcodes `"TLS 1.3, relay certificate pinned by SPKI hash"` regardless of route:
```rust
            transport: match self.relay.route() {
                Route::Tor => "Tor onion circuit via arti",
                _ => "TLS 1.3, relay certificate pinned by SPKI hash",
            },
```

`ApiError` needs a `From<TransportError>` impl if one does not already exist — check `core/src/api/error.rs` before adding; `RelayClient::new(relay)?` already works in `create`/`open` today, which means this conversion already exists. No new error-module change needed.

- [ ] **Step 4: Fix the hardcoded `Route::Direct` in `send_message`/`send_payload`**

In `core/src/api/messaging.rs`, change:
```rust
        manifest.routed(Route::Direct, self.relay.address());
        manifest.queued(&message_id);
        manifest.delivered();
```
to:
```rust
        let route = self.relay.route();
        manifest.routed(route, self.relay.address());
        manifest.sealed(route);
        manifest.queued(&message_id);
        manifest.delivered();
```

In the same file's `send_payload` — it does not build a `Manifest` today (it is the shared path used for the `Hello` introduction, not user-facing send), so it needs no manifest change. Confirm this by re-reading the function: it returns `Result<String, ApiError>`, no `Manifest` parameter. Leave it as-is.

- [ ] **Step 5: Apply the same fix in `core/src/api/attachments.rs`**

Open `core/src/api/attachments.rs` and find `send_attachment`'s manifest handling — it will have an analogous `manifest.routed(Route::Direct, ...)` (or equivalent) call following the same pattern as `send_message`'s pre-Task-7 code. Apply the identical change: capture `let route = self.relay.route();` before the routed/queued/delivered sequence, call `manifest.routed(route, self.relay.address())`, then `manifest.sealed(route)` immediately after.

- [ ] **Step 6: Run the new tests**

Run: `cargo test --workspace -p pouch-core transport_switching 2>&1 | tail -40`
Expected: PASS.

- [ ] **Step 7: Run the full suite, including manifest and end-to-end tests**

Run: `cargo test --workspace 2>&1 | tail -60`
Expected: all pass, including the Task 3/4 manifest and padding tests, and the pre-existing `a_direct_message_never_reports_tor` test (still true — nothing here changes Direct's behavior).

- [ ] **Step 8: Commit**

```bash
git add core/src/api/mod.rs core/src/api/messaging.rs core/src/api/attachments.rs
git commit -m "Wire Tor into Pouch: connect_tor/use_direct_relay, honest route reporting in manifest and security details"
```

---

### Task 8: Route-aware `RelayVisibility`

**Files:**
- Modify: `core/src/manifest.rs`
- Modify: `clients/desktop/src-tauri/src/commands.rs`

**Interfaces:**
- Changes: `RelayVisibility::for_message(inbox_id: &str, blob_size: usize) -> Self` becomes `RelayVisibility::for_message(inbox_id: &str, blob_size: usize, route: Route) -> Self`. Only one Rust call site exists outside `manifest.rs` itself (`clients/desktop/src-tauri/src/commands.rs`'s `relay_visibility` command, confirmed by search during planning).

Today `RelayVisibility::for_message` unconditionally lists "the IP address you connect from" and "which inbox submitted it — sealed sender is not built yet" under `visible`. Once Tor is an option, that is only true for a Direct-routed message; a Tor-routed one genuinely does not expose the connecting IP to the relay.

- [ ] **Step 1: Write the failing tests**

In `core/src/manifest.rs`'s test module, update the existing `relay_visibility_admits_what_leaks` test's call site (it currently calls `RelayVisibility::for_message("7f3ac219", 1024)` — add `Route::Direct` as a third argument) and add:

```rust
#[test]
fn relay_visibility_over_tor_does_not_claim_ip_exposure() {
    let v = RelayVisibility::for_message("7f3ac219", 1024, Route::Tor);
    assert!(
        !v.visible.iter().any(|s| s.contains("IP address")),
        "a Tor-routed message must not list IP exposure as visible to the relay"
    );
    assert!(
        v.not_visible.iter().any(|s| s.contains("IP address")),
        "a Tor-routed message should state the IP is NOT visible, not simply omit the line"
    );
    // What Tor does not hide must still be admitted somewhere — the guard
    // node and connection timing remain observable, and Prime Directive 3
    // forbids a screen that lists only what is protected.
    assert!(!v.still_inferable.is_empty());
}

#[test]
fn relay_visibility_over_direct_still_admits_ip_exposure() {
    let v = RelayVisibility::for_message("7f3ac219", 1024, Route::Direct);
    assert!(v.visible.iter().any(|s| s.contains("IP address")));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --workspace -p pouch-core manifest 2>&1 | tail -40`
Expected: FAIL to compile (wrong argument count) and/or assertion failures.

- [ ] **Step 3: Implement**

Change `RelayVisibility::for_message` in `core/src/manifest.rs` from:

```rust
    pub fn for_message(inbox_id: &str, blob_size: usize) -> Self {
        Self {
            inbox_id: inbox_id.to_string(),
            blob_size,
            visible: vec![
                "the inbox this was filed under (random, not you)",
                "the size of this blob",
                "the hour it arrived, within a 30-day TTL window",
                "the IP address you connected from",
                "which inbox submitted it — sealed sender is not built yet",
            ],
            not_visible: vec![
                "message content",
                "your name or your contact's name",
                "the exact second you sent it",
                "whether this is a first message or a reply",
            ],
            still_inferable: vec!["that you connected", "roughly when", "how often"],
        }
    }
```

to:

```rust
    pub fn for_message(inbox_id: &str, blob_size: usize, route: Route) -> Self {
        let mut visible = vec![
            "the inbox this was filed under (random, not you)",
            "the size of this blob",
            "the hour it arrived, within a 30-day TTL window",
        ];
        let mut not_visible = vec![
            "message content",
            "your name or your contact's name",
            "the exact second you sent it",
            "whether this is a first message or a reply",
        ];
        let mut still_inferable = vec!["that you connected", "roughly when", "how often"];

        match route {
            Route::Tor => {
                visible.push("which inbox submitted it — the wire protocol has no sender field, and Tor hides the source IP too");
                not_visible.push("the IP address you connected from — hidden by the Tor circuit");
                still_inferable.push("that you are using Tor");
                still_inferable.push("your Tor guard node can see connection timing, though not the relay you are talking to");
            }
            Route::Direct | Route::Offline => {
                visible.push("the IP address you connected from");
                visible.push("which inbox submitted it — sealed sender requires Tor, see transport settings");
            }
        }

        Self {
            inbox_id: inbox_id.to_string(),
            blob_size,
            visible,
            not_visible,
            still_inferable,
        }
    }
```

- [ ] **Step 4: Update the one external call site**

In `clients/desktop/src-tauri/src/commands.rs`'s `relay_visibility` command, change:
```rust
            let v = RelayVisibility::for_message(p.inbox_id(), blob_size);
```
to:
```rust
            let v = RelayVisibility::for_message(p.inbox_id(), blob_size, p.current_route());
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --workspace -p pouch-core manifest 2>&1 | tail -40`
Expected: PASS.

- [ ] **Step 6: Desktop crate compile check**

Run: `cd clients/desktop/src-tauri && cargo check --locked 2>&1 | tail -60`
Expected: compiles clean.

- [ ] **Step 7: Commit**

```bash
git add core/src/manifest.rs clients/desktop/src-tauri/src/commands.rs
git commit -m "RelayVisibility reflects the real route: Tor hides the IP, direct still admits it"
```

---

### Task 9: Relay as a Tor onion service

**Files:**
- Create: `server/src/onion.rs`
- Modify: `server/src/main.rs`
- Modify: `server/src/lib.rs` (if the crate has one exposing `http`/`store` as `pub mod` — confirm by reading it; if `main.rs` is the only entry point with `mod http; mod store;` declared inline, add `mod onion;` there instead)

**Interfaces:**
- Produces: `pub async fn run_onion_service(state: RelayState, router: axum::Router, tor_state_dir: &str, nickname: &str) -> anyhow::Result<String>` — bootstraps Tor, launches the onion service, spawns the per-connection bridging loop, and returns the resulting onion address once available (so `main.rs` can print it).

**Verified API surface** (checked directly against docs.rs for `tor-hsservice =0.43.0`): `TorClient::launch_onion_service(&self, config: OnionServiceConfig) -> Result<Option<(Arc<RunningOnionService>, impl Stream<Item = RendRequest>)>>`; `tor_hsservice::config::OnionServiceConfigBuilder::new().nickname(...).build()`; `tor_hsservice::handle_rend_requests(rend_requests) -> impl Stream<Item = StreamRequest>`; `RunningOnionService::onion_address(&self) -> Option<...>`; `StreamRequest::accept(self, connected_message: tor_cell::relaycell::msg::Connected) -> Result<DataStream>` (async, consumes `self`) with `Connected::new_empty()` as the reply. If a name differs at implementation time, check `https://docs.rs/tor-hsservice/0.43.0/` before changing approach.

- [ ] **Step 1: Write the smoke test — config construction, not a live bootstrap**

Add to `server/src/onion.rs` (created in the next step) a test that exercises what is realistic without live Tor: building an `OnionServiceConfig` with a nickname succeeds, and an invalid nickname is rejected. This mirrors Task 6's approach — real network behavior is verified manually, not in CI.

- [ ] **Step 2: Implement `server/src/onion.rs`**

```rust
//! The relay as a Tor v3 onion service (Phase 4, D-039).
//!
//! `axum::serve` in the pinned axum 0.7.9 only accepts a concrete
//! `tokio::net::TcpListener`, not an arbitrary stream source, so an onion
//! service's incoming connections cannot go through it directly. Instead,
//! each accepted Tor stream is served individually with
//! `hyper_util::server::conn::auto`, using the same `axum::Router` (via its
//! `tower::Service` implementation) the direct TCP listener already uses —
//! one set of routes, two ways in.

use std::sync::Arc;

use arti_client::{TorClient, TorClientConfig};
use futures_util::StreamExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::service::TowerToHyperService;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_rtcompat::PreferredRuntime;

/// Bootstraps Tor, launches the onion service, and spawns a background task
/// that serves `router` over every incoming Tor stream.
///
/// Returns the onion address once the service is set up, so the caller can
/// print it. Bootstrapping (fetching a consensus, building the first
/// circuits) is real network I/O and can take real time — this is why
/// nothing here has a fixed short timeout; the caller decides how long to
/// wait, if at all.
pub async fn run_onion_service(
    router: axum::Router,
    tor_state_dir: &str,
    nickname: &str,
) -> anyhow::Result<String> {
    let mut tor_config_builder = TorClientConfig::builder();
    tor_config_builder
        .storage()
        .state_dir(tor_state_dir.into())
        .cache_dir(tor_state_dir.into());
    let tor_config = tor_config_builder.build()?;

    let tor_client: Arc<TorClient<PreferredRuntime>> =
        TorClient::create_bootstrapped(tor_config).await?;

    let svc_config = OnionServiceConfigBuilder::new()
        .nickname(nickname.parse()?)
        .build()?;

    let Some((onion_service, rend_requests)) = tor_client.launch_onion_service(svc_config)? else {
        anyhow::bail!("onion service hosting is disabled in this Tor client configuration");
    };

    let onion_address = onion_service
        .onion_address()
        .ok_or_else(|| anyhow::anyhow!("onion service has no address yet"))?
        .to_string();

    tokio::spawn(async move {
        let mut stream_requests = std::pin::pin!(tor_hsservice::handle_rend_requests(rend_requests));
        while let Some(stream_request) = stream_requests.next().await {
            let router = router.clone();
            tokio::spawn(async move {
                let Ok(data_stream) = stream_request.accept(Connected::new_empty()).await else {
                    return;
                };
                let io = TokioIo::new(data_stream);
                let service = TowerToHyperService::new(router);
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
        // The stream ending means the onion service shut down. Nothing to
        // log to — this process writes no logs (SPEC §2.3) — but the
        // `onion_service` handle staying alive in the enclosing scope is
        // what keeps the service running in the first place, so make sure
        // it is not dropped before this point in the real call site (main.rs
        // holds it, not this function).
    });

    Ok(onion_address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_nickname_builds_a_config() {
        let config = OnionServiceConfigBuilder::new().nickname("pouch-relay".parse().expect("valid nickname")).build();
        assert!(config.is_ok());
    }

    #[test]
    fn an_empty_nickname_is_rejected() {
        let parsed: Result<tor_hsservice::HsNickname, _> = "".parse();
        assert!(parsed.is_err(), "an empty nickname must not silently become valid");
    }
}
```

Note the return type of `run_onion_service`: it spawns the serving loop and returns immediately once the address is known, rather than blocking — `main.rs` needs the onion address to print it while the direct listener also runs, and the caller (`main.rs`) is responsible for keeping the returned `onion_service`/`tor_client` alive for the process lifetime. Adjust the function to also return the `Arc<RunningOnionService>` (and hold `tor_client` inside the spawned task's captured closure, which it already does) so `main.rs` has something to keep alive:

Update the function's return type and final `Ok` to:
```rust
pub async fn run_onion_service(
    router: axum::Router,
    tor_state_dir: &str,
    nickname: &str,
) -> anyhow::Result<(String, Arc<tor_hsservice::RunningOnionService>)> {
    // ... (unchanged body up through building `onion_address`) ...
    Ok((onion_address, onion_service))
}
```

(and add `Arc<tor_hsservice::RunningOnionService>` to the imports accordingly — it is already the type `launch_onion_service` returns as the first tuple element, already bound to `onion_service` above).

- [ ] **Step 3: Wire into `server/src/main.rs`**

Add new env vars and an optional spawn, keeping the existing direct listener untouched:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db_path = std::env::var("POUCH_RELAY_DB").unwrap_or_else(|_| "pouch-relay.db".to_string());
    let bind = std::env::var("POUCH_RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());

    let store = Store::open(&db_path, MAX_BLOB_BYTES)?;
    let state = RelayState::new(store);

    let sweeper = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            if let Ok(store) = sweeper.store().lock() {
                let _ = store.sweep_expired();
            }
        }
    });

    // Held for the process lifetime — dropping it would tear the onion
    // service down. `_onion_service_guard` intentionally unused beyond that.
    let _onion_service_guard = if let Ok(tor_state_dir) = std::env::var("POUCH_RELAY_TOR_STATE") {
        let nickname =
            std::env::var("POUCH_RELAY_ONION_NICKNAME").unwrap_or_else(|_| "pouch-relay".to_string());
        match pouch_relay::onion::run_onion_service(router(state.clone()), &tor_state_dir, &nickname)
            .await
        {
            Ok((address, service)) => {
                // The second line this process ever prints. Still names
                // nothing about a request — an operational address, same
                // class of information the bind address on the next line
                // already is.
                println!("pouch-relay onion service listening at {address}.onion");
                Some(service)
            }
            Err(e) => {
                println!("pouch-relay: onion service failed to start: {e}");
                None
            }
        }
    } else {
        None
    };

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("pouch-relay listening on {bind} (access logging disabled)");

    axum::serve(listener, router(state)).await?;
    Ok(())
}
```

Note: `router(state)` is called twice (once for the onion bridge, once for the direct `axum::serve`) because `axum::Router` does not implement `Clone` cheaply enough to share the exact instance across both — check `server/src/http.rs`'s `router` function; if `Router: Clone` already (axum routers usually are, cheaply, via `Arc` internally), a single `let app = router(state.clone());` reused via `.clone()` for both call sites is preferable to constructing it twice. Prefer that if it compiles; fall back to calling `router()` twice only if `Router` construction has some non-idempotent side effect (it does not, based on `server/src/http.rs`'s content — it is a pure builder). Write it as:

```rust
    let app = router(state.clone());
    let _onion_service_guard = if let Ok(tor_state_dir) = std::env::var("POUCH_RELAY_TOR_STATE") {
        // ... same as above, passing app.clone() instead of router(state.clone()) ...
    } else {
        None
    };
    // ...
    axum::serve(listener, app).await?;
```

- [ ] **Step 4: Declare the new module**

Check `server/src/main.rs`'s existing `use pouch_relay::http::{...}` — this implies a `server/src/lib.rs` exists declaring `pub mod http; pub mod store;`. Read it, and add `pub mod onion;` alongside them.

- [ ] **Step 5: Run the config-only tests**

Run: `cargo test --workspace -p pouch-relay onion 2>&1 | tail -30`
Expected: PASS (`a_valid_nickname_builds_a_config`, `an_empty_nickname_is_rejected`).

- [ ] **Step 6: Full workspace check**

Run: `cargo check --workspace --locked 2>&1 | tail -80` then `cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -80`
Expected: clean.

- [ ] **Step 7: Manual verification — real onion service bootstrap**

This cannot be exercised by an automated test the way the rest of the suite is (slow, live-network, and the relay binary needs to keep running). Document as a manual step for `docs/PROGRESS.md` (Task 14 writes it up):

```
POUCH_RELAY_DB=/tmp/relay.db POUCH_RELAY_BIND=127.0.0.1:8551 \
POUCH_RELAY_TOR_STATE=/tmp/pouch-relay-tor-state \
./target/debug/pouch-relay
```
Expected output, once Tor bootstraps (can take from several seconds to roughly a minute on a first run with no cached consensus): `pouch-relay onion service listening at <52-char>.onion`, followed by the existing `pouch-relay listening on 127.0.0.1:8551 (access logging disabled)` line. Record the onion address obtained and how long it took to appear.

- [ ] **Step 8: Commit**

```bash
git add server/src/onion.rs server/src/main.rs server/src/lib.rs
git commit -m "Relay as a Tor onion service alongside the existing direct listener (D-039)"
```

---

### Task 10: CLI — send and receive over Tor

**Files:**
- Modify: `clients/cli/src/config.rs`
- Modify: `clients/cli/src/commands/messaging.rs`

**Interfaces:**
- Produces: `pub fn tor_config() -> Option<TorRelayConfig>` in `config.rs`, reading new env vars. `send`/`receive` (already `async fn`) opt into it after the existing synchronous `Pouch::open` call — no signature change to either command.

Only `send` and `receive` are touched, deliberately: they are the two commands that actually talk to the relay in a way the Phase 4 exit criterion ("messaging works end to end over Tor") needs to demonstrate, and both are already `async fn` (confirmed by reading the file during planning). `list`/`read` stay synchronous and Direct-only — they do not touch the network at all today (`pouch.conversations()`/`pouch.messages()` are local reads), so there is nothing about them that Tor changes.

- [ ] **Step 1: Implement `tor_config()` in `config.rs`**

Add to `clients/cli/src/config.rs`:

```rust
/// Tor connection settings, if `POUCH_RELAY_TOR_ONION` is set.
///
/// Three related variables, all required together once the first is
/// present — a partially specified Tor target is a misconfiguration, not
/// something to guess defaults for:
///
/// - `POUCH_RELAY_TOR_ONION`: the relay's onion address (no scheme, no port).
/// - `POUCH_RELAY_TOR_PORT`: the port, defaulting to 80 if unset.
/// - `POUCH_TOR_STATE_DIR`: where this client's Tor state persists,
///   defaulting to `pouch-tor-state` in the current directory if unset.
pub fn tor_config() -> Option<pouch_core::transport::TorRelayConfig> {
    let onion_host = std::env::var("POUCH_RELAY_TOR_ONION").ok()?;
    let onion_port = std::env::var("POUCH_RELAY_TOR_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(80);
    let state_dir =
        std::env::var("POUCH_TOR_STATE_DIR").unwrap_or_else(|_| "pouch-tor-state".to_string());
    Some(pouch_core::transport::TorRelayConfig {
        onion_host,
        onion_port,
        state_dir,
    })
}
```

- [ ] **Step 2: Wire into `send` and `receive`**

In `clients/cli/src/commands/messaging.rs`, change `send`:
```rust
    let mut key = db_key()?;
    let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;

    let manifest = pouch.send_message(conversation, text).await?;
```
to:
```rust
    let mut key = db_key()?;
    let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;
    if let Some(tor) = crate::config::tor_config() {
        pouch.connect_tor(tor).await?;
    }

    let manifest = pouch.send_message(conversation, text).await?;
```

Apply the identical two-line addition (`if let Some(tor) = crate::config::tor_config() { pouch.connect_tor(tor).await?; }`) to `receive`, immediately after its own `Pouch::open` call and before `pouch.receive_messages().await?`.

- [ ] **Step 3: Run the CLI crate's existing tests to confirm nothing broke**

Run: `cargo test --workspace -p pouch-cli 2>&1 | tail -30` (if the CLI crate has no unit tests of its own beyond what `core`'s end-to-end suite already covers, this may be a no-op — confirm by checking for a `#[test]` in `clients/cli/src`; if none exist, run `cargo build -p pouch-cli 2>&1 | tail -40` instead as the verification step)
Expected: clean.

- [ ] **Step 4: Manual verification — the actual Phase 4 exit criterion**

Not automatable in this environment (needs a running onion-service relay and real Tor bootstrap on both ends, and this session's sandbox networking, while apparently open per the research done ahead of this plan, should not be assumed identical to the deployment environment). Record as a manual demo, mirroring the Phase 1 demo's shape, for `docs/PROGRESS.md` (Task 14):

```sh
# terminal 1 — the relay, as an onion service
POUCH_RELAY_DB=/tmp/relay.db POUCH_RELAY_BIND=127.0.0.1:8551 \
POUCH_RELAY_TOR_STATE=/tmp/pouch-relay-tor-state \
./target/debug/pouch-relay
# note the printed .onion address

# terminal 2 — two CLI clients, both over Tor
export ONION=<the address printed above>
K1=$(python3 -c "import os;print(os.urandom(32).hex())")
K2=$(python3 -c "import os;print(os.urandom(32).hex())")
B="POUCH_DB=/tmp/brian.db POUCH_KEY=$K1 POUCH_RELAY_TOR_ONION=$ONION POUCH_RELAY_TOR_PORT=80 POUCH_TOR_STATE_DIR=/tmp/brian-tor"
M="POUCH_DB=/tmp/mai.db   POUCH_KEY=$K2 POUCH_RELAY_TOR_ONION=$ONION POUCH_RELAY_TOR_PORT=80 POUCH_TOR_STATE_DIR=/tmp/mai-tor"

env $B pouch-cli create Brian
env $M pouch-cli create Mai
CODE=$(env $M pouch-cli invite | head -1)
env $B pouch-cli add Mai "$CODE"
env $M pouch-cli receive
env $B pouch-cli send <conversation> "over Tor now"
env $M pouch-cli receive
```
Expected: the message arrives, and `send`'s printed manifest shows stage 7 as `TOR · <onion>:80` and stage 6 (`SENDER SEALED`) as `Ran`. Cross-check the relay's own database (`sqlite3 /tmp/relay.db`) contains no IP address — SQLite has never stored one (the relay writes four columns total, per `server/src/store.rs`, none of them a network address), so this is really confirming no *new* column was added, not discovering a fresh leak.

- [ ] **Step 5: Commit**

```bash
git add clients/cli/src/config.rs clients/cli/src/commands/messaging.rs
git commit -m "CLI: send/receive can route over Tor via POUCH_RELAY_TOR_ONION"
```

---

### Task 11: Desktop backend — Tor commands

**Files:**
- Modify: `clients/desktop/src-tauri/src/state.rs`
- Modify: `clients/desktop/src-tauri/src/commands.rs`

**Interfaces:**
- Produces: Tauri commands `connect_tor`, `use_direct_relay`, `transport_options`. `state.rs` gains `tor_state_dir(app: &tauri::AppHandle) -> Result<PathBuf, String>`.

- [ ] **Step 1: Add the Tor state directory helper to `state.rs`**

```rust
/// Where this device's Tor state (guards, consensus cache, onion keys —
/// none of it a message secret) persists across runs. A sibling of the
/// database directory, not inside it — Tor bootstrap state is not something
/// `SQLCipher` needs to protect the way message content is.
pub fn tor_state_dir(app_data_dir: &std::path::Path) -> std::path::PathBuf {
    app_data_dir.join("tor-state")
}
```

- [ ] **Step 2: Add the commands to `commands.rs`**

```rust
/* -- Phase 4: transport settings (SPEC §6.7.9) ------------------------------ */

/// One transport choice, with the exact honest copy the core owns — so the
/// screen never drifts from `Route::explanation()`.
#[derive(Serialize)]
pub struct TransportOptionView {
    pub route: String,
    pub label: String,
    pub explanation: String,
}

/// The choices the Transport settings screen offers. `Offline` is not
/// offered — it is a state, not a setting a user picks.
#[tauri::command]
pub fn transport_options() -> Vec<TransportOptionView> {
    use pouch_core::transport::Route;
    [Route::Direct, Route::Tor]
        .iter()
        .map(|r| TransportOptionView {
            route: r.label().to_string(),
            label: r.label().to_string(),
            explanation: r.explanation().to_string(),
        })
        .collect()
}

/// Switches to a Tor-routed relay connection. Slow — real Tor bootstrap —
/// and can fail; on failure the existing connection is left untouched
/// (`Pouch::connect_tor` never silently falls back to Direct).
#[tauri::command]
pub async fn connect_tor(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "Could not find a place to store data on this device.".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let onion_host = std::env::var("POUCH_RELAY_TOR_ONION")
        .map_err(|_| "No Tor relay address is configured for this build.".to_string())?;
    let onion_port = std::env::var("POUCH_RELAY_TOR_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(80);

    let config = pouch_core::transport::TorRelayConfig {
        onion_host,
        onion_port,
        state_dir: crate::state::tor_state_dir(&dir).to_string_lossy().to_string(),
    };

    let mut guard = state.lock().await;
    let pouch = guard
        .as_mut()
        .ok_or_else(|| "No identity is open on this device yet.".to_string())?;
    pouch.connect_tor(config).await.map_err(|e| e.to_string())
}

/// Switches back to the direct relay connection.
#[tauri::command]
pub async fn use_direct_relay(state: State<'_, AppState>) -> Result<(), String> {
    state
        .with(|p| {
            p.use_direct_relay(crate::state::relay_config())
                .map_err(|e| e.to_string())
        })
        .await
}
```

The `POUCH_RELAY_TOR_ONION`/`POUCH_RELAY_TOR_PORT` env-var read here mirrors the CLI's `tor_config()` from Task 10 — the desktop build's onion target is deployment configuration, not a user-entered value (the same reasoning `relay_config()` in `state.rs` already applies to the direct address). If a later phase wants the user to be able to type in an arbitrary onion address, that is a new, separate feature to design deliberately, not an incidental side effect of this task.

- [ ] **Step 3: Register the new commands**

Find wherever `main.rs` (or `lib.rs`) registers the existing Tauri commands (`tauri::generate_handler![...]` or equivalent) and add `commands::transport_options, commands::connect_tor, commands::use_direct_relay,` to the list, alongside the existing entries.

- [ ] **Step 4: Compile-check**

Run: `cd clients/desktop/src-tauri && cargo check --locked 2>&1 | tail -80`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add clients/desktop/src-tauri/src/state.rs clients/desktop/src-tauri/src/commands.rs
git commit -m "Desktop backend: connect_tor/use_direct_relay/transport_options commands"
```

(Include the command-registration file from Step 3 in this commit too, once located.)

---

### Task 12: Desktop frontend — Transport settings screen

**Files:**
- Modify: `clients/desktop/src/lib/bridge.ts`
- Create: `clients/desktop/src/screens/TransportSettings.tsx`
- Create: `clients/desktop/src/screens/TransportSettings.test.tsx`
- Modify: `clients/desktop/src/screens/PrivacyStorage.tsx`
- Modify: `clients/desktop/src/App.tsx`

**Interfaces:**
- Consumes: `transport_options`, `connect_tor`, `use_direct_relay`, `transport_state` (existing) Tauri commands.
- Produces: `PouchBridge.transportOptions()`, `.connectTor()`, `.useDirectRelay()`; `TransportSettings` component taking `{ bridge: PouchBridge; onBack: () => void }`.

- [ ] **Step 1: Extend `bridge.ts`**

Add to the `PouchBridge` interface, near `transportState`:
```ts
  transportOptions(): Promise<TransportOption[]>;
  connectTor(): Promise<void>;
  useDirectRelay(): Promise<void>;
```

Add the type, near `TransportLabel`:
```ts
export interface TransportOption {
  route: TransportLabel;
  label: string;
  explanation: string;
}
```

Add the wire shape and narrowing near the others:
```ts
interface WireTransportOption {
  route: string;
  label: string;
  explanation: string;
}
```

Add to the `tauriBridge` implementation:
```ts
    transportOptions: async () => {
      const rows = await invoke<WireTransportOption[]>("transport_options");
      return rows.map((r) => ({
        route: asTransportLabel(r.route),
        label: r.label,
        explanation: r.explanation,
      }));
    },

    connectTor: () => invoke<void>("connect_tor"),

    useDirectRelay: () => invoke<void>("use_direct_relay"),
```

- [ ] **Step 2: Write the failing frontend test**

Create `clients/desktop/src/screens/TransportSettings.test.tsx`, following the pattern of an existing screen test (check `IdentityChangeModal.test.tsx` or a screen test for the exact fake-bridge/`renderToStaticMarkup` pattern this project uses before writing this — it was described in `docs/CONTEXT.md` as "the frontend's honesty rules are tested through `renderToStaticMarkup` and a fake bridge rather than a browser"):

```tsx
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { TransportSettings } from "./TransportSettings";
import type { PouchBridge, TransportOption } from "../lib/bridge";

function fakeBridge(overrides: Partial<PouchBridge> = {}): PouchBridge {
  const options: TransportOption[] = [
    {
      route: "DIRECT",
      label: "DIRECT",
      explanation:
        "Messages go straight to the relay over TLS 1.3. The relay sees the IP address you connect from. Message content stays encrypted either way.",
    },
    {
      route: "TOR",
      label: "TOR",
      explanation:
        "Messages route through a Tor onion circuit. The relay never learns your IP address. Your internet provider can still see that you are using Tor.",
    },
  ];
  return {
    transportOptions: async () => options,
    transportState: async () => "DIRECT",
    connectTor: async () => {},
    useDirectRelay: async () => {},
    // ... every other PouchBridge member throws, matching this project's
    // existing fake-bridge pattern for methods this screen never calls —
    // copy the exact throw-stub style from whatever existing *.test.tsx
    // file was read as the pattern reference.
    ...overrides,
  } as PouchBridge;
}

describe("TransportSettings", () => {
  it("names both options without claiming either is the secure one", () => {
    const html = renderToStaticMarkup(
      <TransportSettings bridge={fakeBridge()} onBack={() => {}} />,
    );
    const lower = html.toLowerCase();
    for (const banned of ["unbreakable", "military grade", "100% secure", "totally safe", "the secure option", "the safe choice"]) {
      expect(lower).not.toContain(banned);
    }
    expect(html).toContain("Direct");
    expect(html).toContain("Tor");
  });

  it("states the direct-transport IP exposure honestly", () => {
    const html = renderToStaticMarkup(
      <TransportSettings bridge={fakeBridge()} onBack={() => {}} />,
    );
    expect(html).toContain("IP address");
  });
});
```

Before finalizing this file, open one existing `*.test.tsx` in `clients/desktop/src/screens/` or `clients/desktop/src/components/` to copy its actual fake-bridge boilerplate style exactly (the stub above is illustrative of intent; match the project's real pattern rather than inventing a new one).

- [ ] **Step 3: Run it to verify it fails**

Run: `cd clients/desktop && npm test -- TransportSettings 2>&1 | tail -40`
Expected: FAIL — `TransportSettings` does not exist yet.

- [ ] **Step 4: Implement the screen**

Create `clients/desktop/src/screens/TransportSettings.tsx`:

```tsx
/*
 * Screen 9 — Transport settings (SPEC §6.7.9).
 *
 * Two options, both named for what they cost rather than which one is
 * "secure" — SPEC is explicit that neither is labelled the secure one. The
 * copy itself comes from the core (`Route::explanation()`, via
 * `transportOptions()`) rather than being duplicated here, so the screen
 * cannot drift from what `RelayVisibility` and the manifest already say.
 */

import { useCallback, useEffect, useState } from "react";
import type { PouchBridge, TransportLabel, TransportOption } from "../lib/bridge";
import "./screens.css";

interface TransportSettingsProps {
  bridge: PouchBridge;
  onBack: () => void;
}

export function TransportSettings({ bridge, onBack }: TransportSettingsProps) {
  const [options, setOptions] = useState<TransportOption[]>([]);
  const [active, setActive] = useState<TransportLabel | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [opts, current] = await Promise.all([
      bridge.transportOptions(),
      bridge.transportState(),
    ]);
    setOptions(opts);
    setActive(current);
  }, [bridge]);

  useEffect(() => {
    refresh().catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [refresh]);

  async function choose(route: TransportLabel) {
    setBusy(true);
    setError(null);
    try {
      if (route === "TOR") {
        await bridge.connectTor();
      } else {
        await bridge.useDirectRelay();
      }
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="screen screen--narrow">
      <h1 className="screen__title">Transport</h1>
      <p className="screen__lede">How your device reaches the relay.</p>

      {error && (
        <p className="screen__error" role="alert">
          {error}
        </p>
      )}

      <fieldset className="field-group" disabled={busy}>
        <legend className="visually-hidden">Transport</legend>
        {options.map((option) => (
          <label key={option.route} className="choice choice--block">
            <input
              type="radio"
              name="transport"
              value={option.route}
              checked={active === option.route}
              onChange={() => void choose(option.route)}
            />
            <span>
              <strong>{option.label}</strong>
              <p className="panel__note">{option.explanation}</p>
            </span>
          </label>
        ))}
      </fieldset>

      {busy && (
        <p className="screen__note" role="status">
          Connecting… Tor can take a while the first time.
        </p>
      )}

      <div className="screen__actions">
        <button type="button" className="button-quiet" onClick={onBack}>
          Back
        </button>
      </div>
    </main>
  );
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd clients/desktop && npm test -- TransportSettings 2>&1 | tail -40`
Expected: PASS.

- [ ] **Step 6: Wire the screen into navigation**

In `clients/desktop/src/screens/PrivacyStorage.tsx`, add an `onTransportSettings: () => void` prop and a new panel (placed near the "Waiting to send" panel, before backup):

```tsx
      {/* -- transport -------------------------------------------------------- */}
      <section className="panel">
        <h2 className="panel__h">Transport</h2>
        <p className="panel__note">
          Choose how this device reaches the relay: direct, or through Tor.
        </p>
        <button type="button" className="button-quiet" onClick={onTransportSettings}>
          Transport settings
        </button>
      </section>
```

Add `onTransportSettings` to `PrivacyStorageProps` and pass it through from wherever `<PrivacyStorage />` is instantiated.

In `clients/desktop/src/App.tsx`:
- Add `| { name: "transport" }` to the `Route` union.
- Import `TransportSettings` from `./screens/TransportSettings`.
- Pass `onTransportSettings={() => setRoute({ name: "transport" })}` to `<PrivacyStorage />`.
- Add a render branch:
```tsx
      {route.name === "transport" && (
        <TransportSettings bridge={bridge} onBack={() => setRoute({ name: "privacy" })} />
      )}
```

- [ ] **Step 7: Full frontend verification**

Run: `cd clients/desktop && npm run typecheck && npm test && npm run build 2>&1 | tail -80`
Expected: all clean.

- [ ] **Step 8: Commit**

```bash
git add clients/desktop/src/lib/bridge.ts clients/desktop/src/screens/TransportSettings.tsx clients/desktop/src/screens/TransportSettings.test.tsx clients/desktop/src/screens/PrivacyStorage.tsx clients/desktop/src/App.tsx
git commit -m "Desktop: Transport settings screen (SPEC §6.7.9)"
```

---

### Task 13: Full-workspace verification pass

**Files:** none (verification only)

- [ ] **Step 1: Full Rust suite**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace 2>&1 | tail -100`
Expected: clean formatting, zero clippy warnings, all tests pass (the `#[ignore]`d live-Tor tests from Tasks 6/9 are skipped, not failed — that is expected in an automated run).

- [ ] **Step 2: Guardrail scripts**

Run: `./scripts/check-guardrails.sh` (Bash) and `node scripts/check-contrast.mjs`
Expected: both pass. Check `check-guardrails.sh`'s "forbidden logging of plaintext or key material" grep specifically against the new `server/src/onion.rs`/`core/src/transport/tor.rs` — neither should log anything (this project's server writes no logs at all, and the new Tor code paths follow the same silent-failure-returns-a-typed-error pattern as the rest of `transport.rs`).

- [ ] **Step 3: Desktop crate**

Run: `cd clients/desktop/src-tauri && cargo check --locked 2>&1 | tail -80` and `cd clients/desktop && npm ci && npm run typecheck && npm test && npm run build 2>&1 | tail -100`
Expected: clean. (The Tauri shell's own compile is a separate CI job per `docs/CONTEXT.md` and cannot run in this environment — `cargo check` on the crate is the local substitute.)

- [ ] **Step 4: Record the final test counts**

Note the new Rust and frontend test totals (starting point was 163 Rust / 36 frontend before this plan) for Task 14's `docs/PROGRESS.md` update.

- [ ] **Step 5: No commit** — this task is verification only; if anything fails, fix it and re-run rather than committing a broken state.

---

### Task 14: Documentation close-out — decisions, threat model, SPEC, progress, version bump

**Files:**
- Modify: `docs/DECISIONS.md` (D-042)
- Modify: `docs/THREAT_MODEL.md`
- Modify: `SPEC.md`
- Modify: `docs/PROGRESS.md`
- Modify: `docs/CONTEXT.md`
- Modify: `Cargo.toml`, `clients/desktop/src-tauri/Cargo.toml`, `clients/desktop/src-tauri/tauri.conf.json`, `clients/desktop/package.json` (version bump)

- [ ] **Step 1: Record the cover-traffic deferral (D-042)**

Append to `docs/DECISIONS.md`:

```markdown
---

## D-042 — Cover traffic not built this phase; deferred as a stop-and-ask
**Date:** 2026-08-02 · **Status:** accepted

SPEC's Phase 4 scope line names "optional cover traffic" alongside fixed-
size padding, but no section of SPEC specifies what shape it should take —
how often, what size, what triggers it, or how a receiver is meant to
distinguish real traffic from cover traffic without that distinction itself
leaking something. Inventing an answer to those questions now would be
exactly the class of decision SPEC §2.6 reserves for a stop-and-ask ("a task
seems to require writing a new cryptographic construction" extends
naturally to a new traffic-shaping protocol — the failure modes are the
same category, just outside the AEAD).

Phase 4's actual exit criteria (SPEC §9) do not require cover traffic:
messaging over Tor end to end, no client IP in server state, `TOR` shown
accurately in the Custody Strip, and sealed sender reporting as ran. All
four ship without it. Cover traffic remains a tracked, open item — the
project owner should specify its design (or explicitly decline it) before
any implementation is attempted, the same way D-037 and D-038 required an
explicit decision before the attachment pipeline's AEAD and metadata
library choices were made rather than assumed.
```

- [ ] **Step 2: Update `docs/THREAT_MODEL.md`**

Read the file's current §4/§5-equivalent sections (metadata tiers) first. Update the tier that currently lists IP address as "reduced but present" (matching the language already in SPEC §5's own "Reduced but present" paragraph, quoted during planning) to reflect that it is now eliminated with respect to the relay specifically for Tor-routed traffic, while still stating plainly that direct transport remains available and still exposes IP by choice, and that the local network and Tor guard node retain partial visibility even over Tor. Do not soften this into "IP address hidden" as a blanket claim — match the phase-accurate, route-conditional honesty pattern established by `RelayVisibility` in Task 8.

Also add the RUSTSEC-style caveat this session's D-039 research surfaced: `tor-hsservice`'s own documentation describes its hosting API as "a low-level implementation that may not be suitable for typical users" — if `docs/THREAT_MODEL.md` has a section listing known deviations or accepted risk (it does, per the existing HPKE/RUSTSEC-2026-0072 entry referenced in `docs/PROGRESS.md`'s Phase 1 section), add a line there naming this as a newer, less battle-tested dependency than `openmls`/`rusqlite`, consistent with D-039's own wording.

- [ ] **Step 3: Update `SPEC.md`'s Phase 4 section**

Find the Phase 4 section (already read during planning, at the point starting `### Phase 4 — Tor transport, then sealed sender`). Add a paragraph after the existing exit-criteria line, matching Phase 3's own pattern of stating a scope reduction inline rather than silently:

```markdown
**Cover traffic, named in this phase's scope line above, is not part of
its exit criteria and was not built** — decided 2026-08-02, D-042. SPEC
does not specify its shape (frequency, size, trigger), and inventing one
without that specification would be the same class of undesignated
construction SPEC §2.6 reserves for a stop-and-ask. Tracked as an open
item pending an explicit design decision from the project owner.
```

- [ ] **Step 4: Update `docs/PROGRESS.md`**

Following the existing document's structure (a "Current position" table at the top, then a per-phase section), update:

- The "Current position" table: `Phase complete` gains `· 3 — Attachments and compression, fully · 4 — Tor transport and sealed sender`; `Phase next` becomes `5 — Android client`, or if any of this plan's manual-verification items (Tasks 6/9/10 Step 7/8) could not actually be run against live Tor in the implementing session, say so explicitly here rather than marking the phase complete prematurely — mirror the existing honesty pattern ("CI green... not yet confirmed" language already used for the attachment pipeline in the same file).
- `Tests` row: update counts using Task 13's recorded totals.
- `Version` row: update per Step 6 below.
- Add a new `## Phase 4 — Tor transport, then sealed sender` section, following the structure of the existing Phase 3 section: what shipped (relay onion service, Tor-routed `RelayClient`, message padding, sealed-sender manifest activation, Transport settings screen), what was decided (D-039 arti/MSRV, D-040 the rusqlite conflict and its fix, D-041 message padding, D-042 cover traffic deferred — all cross-referenced), the manual verification results actually obtained (paste the real onion address and timing from Task 9 Step 7, the real CLI-over-Tor demo output from Task 10 Step 4, and the real `--ignored` test result from Task 6 Step 7 — not placeholder text; if a step could not be run in the implementing environment, state that plainly, matching this project's existing standard for admitting an unverified GUI claim), and what remains open (cover traffic, per D-042; anything else discovered during implementation that does not block the phase's own exit criteria).

- [ ] **Step 5: Update `docs/CONTEXT.md`'s "Where things stand" section**

Replace the current Phase 3 summary paragraph's forward-looking Phase 4 sentence with a short note that Phase 4 is now complete, in the same voice as the existing Phase 1/2/3 summaries — state what shipped, and repeat the one open item (cover traffic) so a future session does not need to re-read all of `PROGRESS.md` to know it is intentionally absent.

- [ ] **Step 6: Version bump**

Per the project convention (`docs/CONTEXT.md`'s conventions list), bump all four files together, e.g. `0.1.2` → `0.1.3`:
- `Cargo.toml`'s `[workspace.package] version`
- `clients/desktop/src-tauri/Cargo.toml`'s own `version`
- `clients/desktop/src-tauri/tauri.conf.json`'s `version`
- `clients/desktop/package.json`'s `version`

Run `cargo check --workspace --locked 2>&1 | tail -40` afterward to confirm the version bump alone did not break anything (it should not — this is metadata only).

- [ ] **Step 7: Commit**

```bash
git add docs/DECISIONS.md docs/THREAT_MODEL.md SPEC.md docs/PROGRESS.md docs/CONTEXT.md Cargo.toml Cargo.lock clients/desktop/src-tauri/Cargo.toml clients/desktop/src-tauri/tauri.conf.json clients/desktop/package.json
git commit -m "Phase 4 close-out: threat model, SPEC, progress log, cover-traffic deferral (D-042), version bump"
```

- [ ] **Step 8: Push**

Per `docs/CONTEXT.md`'s convention ("Push after each phase"), and only after confirming with whoever is running this plan that a push is wanted right now:
```bash
git push origin develop
```

---

## Self-Review Notes

**Spec coverage check**, against SPEC §9's Phase 4 paragraph and exit criteria: relay as onion service (Task 9) ✓; `arti` embedded in core (Tasks 5–7) ✓; transport settings screen (Task 12) ✓; fixed-size padding (Tasks 3–4, extending the existing attachment padding rather than duplicating it) ✓; cover traffic — deliberately not built, recorded as D-042 rather than silently skipped (Task 14) ✓; threat model updated (Task 14) ✓; messaging works end to end over Tor — Task 10's manual demo, Task 6/9's live-network tests ✓; server state confirmed to contain no client IP — the relay's schema already has no IP column (Task 10 Step 4 cross-checks this rather than re-proving it from scratch) ✓; Custody Strip shows `TOR` accurately — already true structurally once `Pouch::transport_state()` reports the real route (Task 7); the Custody Strip component itself reads `transportState()` and already narrows correctly per `asTransportLabel` in `bridge.ts`, so no separate task was needed for the Custody Strip specifically — confirmed by reading `bridge.ts` during planning ✓; manifest stage 6 reports ran — Tasks 3, 7 ✓.

**Type/signature consistency check**: `RelayClient::route()` (Task 5) is what Task 7's `Pouch::current_route`, Task 3/7's `manifest.sealed(route)`/`manifest.routed(route, ...)`, and Task 8's `RelayVisibility::for_message(..., route)` all consume — one accessor, four call sites, same type (`Route`) throughout. `TorRelayConfig` is defined once in `core/src/transport/tor.rs` (Task 6) and consumed by `Pouch::connect_tor` (Task 7), the CLI's `tor_config()` (Task 10), and the desktop `connect_tor` command (Task 11) — no divergent field names introduced at any call site (all three construct `{ onion_host, onion_port, state_dir }`).

**Placeholder scan**: no step in this plan says "add error handling" or "write tests for the above" without the actual code. The two places genuine external-API risk exists (Task 6's hyper/arti connector, Task 9's tor-hsservice bridging) are flagged explicitly as verified-against-docs.rs-but-not-yet-compiled, with a named fallback action ("check docs.rs for the pinned version") rather than left as an unstated risk — this is disclosed uncertainty about a third-party API surface, not a placeholder in the plan's own logic.
