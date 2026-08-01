//! The IPC surface the webview can call.
//!
//! Every command here is a thin wrapper over one `pouch_core::Pouch`
//! operation. **Nothing below `Pouch` is reachable from this file** — no key,
//! no cipher, no raw ciphertext blob, no storage handle (D-012). If a screen
//! appears to need something lower level, the answer is a new operation on
//! `Pouch`, not a new command that reaches past it.
//!
//! Errors come back as strings because that is what the webview renders. They
//! are the `Display` text of the core's own error types, which SPEC §6.9
//! requires to say what happened and what to do — so the UI can show them
//! directly rather than inventing its own wording.

use pouch_core::{
    ConversationSummary, IdentityState, Message, Pouch, RetentionPolicy, SecurityDetails,
};
use serde::Serialize;
use tauri::{Manager, State};

use crate::state::{database_path, relay_config, AppState};

/// A conversation, flattened for the webview.
#[derive(Serialize)]
pub struct ConversationView {
    pub id: String,
    pub contact_id: String,
    pub contact_name: String,
    /// `VERIFIED` / `UNVERIFIED` / `KEY CHANGED` — the Custody Strip label.
    pub identity: String,
    pub last_message: Option<String>,
}

impl From<ConversationSummary> for ConversationView {
    fn from(s: ConversationSummary) -> Self {
        Self {
            id: s.id,
            contact_id: s.contact_id,
            contact_name: s.contact_name,
            identity: s.identity.label().to_string(),
            last_message: s.last_message,
        }
    }
}

/// A message, flattened for the webview.
#[derive(Serialize)]
pub struct MessageView {
    pub id: String,
    pub outgoing: bool,
    pub body: String,
    pub at: u64,
}

impl From<Message> for MessageView {
    fn from(m: Message) -> Self {
        Self {
            id: m.id,
            outgoing: m.outgoing,
            body: m.body,
            at: m.at,
        }
    }
}

/// One row of a message manifest.
#[derive(Serialize)]
pub struct ManifestRow {
    pub number: u8,
    pub label: String,
    pub detail: String,
    pub ran: bool,
}

/// What a send produced.
#[derive(Serialize)]
pub struct SendResult {
    pub summary: String,
    pub rows: Vec<ManifestRow>,
    pub failed: bool,
}

/// What the relay could see about a message (SPEC §6.5.4).
#[derive(Serialize)]
pub struct RelayVisibilityView {
    pub inbox_id: String,
    pub blob_size: usize,
    pub visible: Vec<String>,
    pub not_visible: Vec<String>,
    pub still_inferable: Vec<String>,
}

/// Every mechanism in use, for the Security details screen.
#[derive(Serialize)]
pub struct SecurityDetailsView {
    pub ciphersuite: String,
    pub aead: String,
    pub key_agreement: String,
    pub signature: String,
    pub kdf: String,
    pub protocol: String,
    pub local_database: String,
    pub passphrase_derivation: String,
    pub transport: String,
    pub relay_address: String,
    pub openmls_version: String,
    pub app_version: String,
}

impl From<SecurityDetails> for SecurityDetailsView {
    fn from(d: SecurityDetails) -> Self {
        Self {
            ciphersuite: d.ciphersuite.into(),
            aead: d.aead.into(),
            key_agreement: d.key_agreement.into(),
            signature: d.signature.into(),
            kdf: d.kdf.into(),
            protocol: d.protocol.into(),
            local_database: d.local_database.into(),
            passphrase_derivation: d.passphrase_derivation.into(),
            transport: d.transport.into(),
            relay_address: d.relay_address,
            openmls_version: d.openmls_version.into(),
            app_version: d.app_version.into(),
        }
    }
}

/// Whether this device already holds an identity.
///
/// Decides whether the app opens on first run or on the conversation list.
#[tauri::command]
pub async fn has_identity(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
    if state.is_open().await {
        return Ok(true);
    }
    let path = db_path(&app)?;
    if !path.exists() {
        return Ok(false);
    }
    let mut key = device_key(&app)?;
    Pouch::exists(&path.to_string_lossy(), &mut key).map_err(|e| e.to_string())
}

/// Creates an identity and opens it.
#[tauri::command]
pub async fn create_identity(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    display_name: String,
) -> Result<String, String> {
    let path = db_path(&app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut key = device_key(&app)?;

    let pouch = Pouch::create(
        &display_name,
        &path.to_string_lossy(),
        &mut key,
        relay_config(),
    )
    .map_err(|e| e.to_string())?;

    let inbox = pouch.inbox_id().to_string();
    state.set(pouch).await;
    Ok(inbox)
}

/// Opens the identity already on this device.
#[tauri::command]
pub async fn open_identity(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if state.is_open().await {
        return Ok(());
    }
    let path = db_path(&app)?;
    let mut key = device_key(&app)?;

    let pouch = Pouch::open(&path.to_string_lossy(), &mut key, relay_config())
        .map_err(|e| e.to_string())?;
    state.set(pouch).await;
    Ok(())
}

/// The local-only display name.
#[tauri::command]
pub async fn display_name(state: State<'_, AppState>) -> Result<String, String> {
    state.with(|p| Ok(p.display_name().to_string())).await
}

/// An invite code to hand to someone.
#[tauri::command]
pub async fn invite_code(state: State<'_, AppState>) -> Result<String, String> {
    state
        .with(|p| p.invite_code().map_err(|e| e.to_string()))
        .await
}

/// Starts a conversation from someone else's invite code.
#[tauri::command]
pub async fn add_contact(
    state: State<'_, AppState>,
    display_name: String,
    code: String,
) -> Result<String, String> {
    let mut guard = state.lock().await;
    let pouch = guard
        .as_mut()
        .ok_or_else(|| "No identity is open on this device yet.".to_string())?;
    pouch
        .add_contact(&display_name, &code)
        .await
        .map_err(|e| e.to_string())
}

/// Every conversation on this device.
#[tauri::command]
pub async fn conversations(state: State<'_, AppState>) -> Result<Vec<ConversationView>, String> {
    state
        .with(|p| {
            p.conversations()
                .map(|list| list.into_iter().map(Into::into).collect())
                .map_err(|e| e.to_string())
        })
        .await
}

/// Every message in a conversation, oldest first.
#[tauri::command]
pub async fn messages(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Vec<MessageView>, String> {
    state
        .with(|p| {
            p.messages(&conversation_id)
                .map(|list| list.into_iter().map(Into::into).collect())
                .map_err(|e| e.to_string())
        })
        .await
}

/// Sends a message and returns the manifest describing what happened to it.
#[tauri::command]
pub async fn send_message(
    state: State<'_, AppState>,
    conversation_id: String,
    body: String,
) -> Result<SendResult, String> {
    let mut guard = state.lock().await;
    let pouch = guard
        .as_mut()
        .ok_or_else(|| "No identity is open on this device yet.".to_string())?;

    let manifest = pouch
        .send_message(&conversation_id, &body)
        .await
        .map_err(|e| e.to_string())?;

    Ok(SendResult {
        summary: manifest.summary(),
        rows: manifest
            .stages()
            .iter()
            .map(|(stage, outcome)| ManifestRow {
                number: stage.number(),
                label: stage.label().to_string(),
                detail: outcome.detail(),
                ran: outcome.ran(),
            })
            .collect(),
        failed: manifest.failure().is_some(),
    })
}

/// Collects and decrypts anything waiting.
#[tauri::command]
pub async fn receive_messages(state: State<'_, AppState>) -> Result<Vec<MessageView>, String> {
    let mut guard = state.lock().await;
    let pouch = guard
        .as_mut()
        .ok_or_else(|| "No identity is open on this device yet.".to_string())?;

    let received = pouch.receive_messages().await.map_err(|e| e.to_string())?;
    Ok(received.messages.into_iter().map(Into::into).collect())
}

/// The safety number for a contact, grouped in fives.
#[tauri::command]
pub async fn safety_number(
    state: State<'_, AppState>,
    contact_id: String,
) -> Result<String, String> {
    state
        .with(|p| {
            p.safety_number(&contact_id)
                .map(|n| n.grouped())
                .map_err(|e| e.to_string())
        })
        .await
}

/// Marks a contact verified after the user compared the number out of band.
#[tauri::command]
pub async fn verify_contact(
    state: State<'_, AppState>,
    contact_id: String,
    verified: bool,
) -> Result<(), String> {
    state
        .with(|p| p.verify_contact(&contact_id, verified).map_err(|e| e.to_string()))
        .await
}

/// `DIRECT` / `TOR` / `OFFLINE`, for the Custody Strip.
#[tauri::command]
pub async fn transport_state(state: State<'_, AppState>) -> Result<String, String> {
    let mut guard = state.lock().await;
    let pouch = guard
        .as_mut()
        .ok_or_else(|| "No identity is open on this device yet.".to_string())?;
    Ok(pouch.transport_state().await.label().to_string())
}

/// Every mechanism in use.
#[tauri::command]
pub async fn security_details(state: State<'_, AppState>) -> Result<SecurityDetailsView, String> {
    state.with(|p| Ok(p.security_details().into())).await
}

/// What the relay could see about a message of this size.
#[tauri::command]
pub async fn relay_visibility(
    state: State<'_, AppState>,
    blob_size: usize,
) -> Result<RelayVisibilityView, String> {
    use pouch_core::manifest::RelayVisibility;

    state
        .with(|p| {
            let v = RelayVisibility::for_message(p.inbox_id(), blob_size);
            Ok(RelayVisibilityView {
                inbox_id: v.inbox_id,
                blob_size: v.blob_size,
                visible: v.visible.into_iter().map(String::from).collect(),
                not_visible: v.not_visible.into_iter().map(String::from).collect(),
                still_inferable: v.still_inferable.into_iter().map(String::from).collect(),
            })
        })
        .await
}

/// Destroys everything on this device.
#[tauri::command]
pub async fn wipe_all(state: State<'_, AppState>) -> Result<(), String> {
    state.with(|p| p.wipe_all().map_err(|e| e.to_string())).await
}

/* -- Phase 3 (via D-037): backup export / import (SPEC §6.7.10) ------------ */

/// What the export screen shows and offers for download.
///
/// The recovery key is generated here, once, and this is the only time it
/// exists outside the user's own record of it — nothing in this project
/// stores it. `backup` travels to the webview as plain bytes rather than a
/// written file because this process has no file-save dialog; the screen
/// turns it into a download itself (SPEC §7.3: "the user places where they
/// choose").
#[derive(Serialize)]
pub struct ExportBackupView {
    pub recovery_key_hex: String,
    pub backup: Vec<u8>,
    pub file_name: String,
}

/// Encrypts everything this device holds into a portable backup.
#[tauri::command]
pub async fn export_backup(state: State<'_, AppState>) -> Result<ExportBackupView, String> {
    state
        .with(|p| {
            let recovery_key = pouch_core::new_recovery_key();
            let backup = p.export_backup(&recovery_key).map_err(|e| e.to_string())?;
            Ok(ExportBackupView {
                recovery_key_hex: hex::encode(&recovery_key),
                backup,
                file_name: format!("pouch-backup-{}.pouchbk", unix_seconds()),
            })
        })
        .await
}

/// What the import screen reports once a restore succeeds.
#[derive(Serialize)]
pub struct ImportBackupView {
    pub display_name: String,
    pub conversation_count: usize,
}

/// Restores a backup onto this device, as a fresh identity.
///
/// Refuses if an identity is already open here — `Pouch::import_backup`
/// creates a device from nothing, the same precondition `create_identity`
/// has, and overwriting a live identity with a restored one is not a flow
/// this screen offers (SPEC §6.7.10 is reached from first run, not from an
/// already-open device).
#[tauri::command]
pub async fn import_backup(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    recovery_key_hex: String,
    backup: Vec<u8>,
) -> Result<ImportBackupView, String> {
    if state.is_open().await {
        return Err(
            "An identity is already open on this device. Wipe local data first if you want to restore a backup here."
                .to_string(),
        );
    }

    let recovery_key = hex::decode(recovery_key_hex.trim())
        .map_err(|_| "That recovery key isn't valid hex — check you copied all of it.".to_string())?;

    let path = db_path(&app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut key = device_key(&app)?;

    let pouch = Pouch::import_backup(
        &path.to_string_lossy(),
        &mut key,
        &recovery_key,
        &backup,
        relay_config(),
    )
    .await
    .map_err(|e| e.to_string())?;

    let display_name = pouch.display_name().to_string();
    let conversation_count = pouch.conversations().map_err(|e| e.to_string())?.len();
    state.set(pouch).await;
    Ok(ImportBackupView {
        display_name,
        conversation_count,
    })
}

/// Seconds since the epoch, for a backup file name that sorts and does not
/// collide across exports in the same session.
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/* -- Phase 2: the storage controls (SPEC §6.7.7) --------------------------- */

/// A contact's identity key having changed, flattened for the webview.
#[derive(Serialize)]
pub struct IdentityChangeView {
    pub contact_id: String,
    pub contact_name: String,
    pub changed_at: u64,
}

/// How long this device keeps messages: `forever` / `30d` / `7d` / `24h`.
#[tauri::command]
pub async fn retention_policy(state: State<'_, AppState>) -> Result<String, String> {
    state
        .with(|p| {
            p.retention_policy()
                .map(|r| retention_word(r).to_string())
                .map_err(|e| e.to_string())
        })
        .await
}

/// Changes how long messages are kept, and returns how many were deleted.
///
/// The count is returned rather than discarded so the screen can say what
/// actually happened. "Messages are kept 7 days" alone leaves the user guessing
/// whether anything went.
#[tauri::command]
pub async fn set_retention_policy(
    state: State<'_, AppState>,
    policy: String,
) -> Result<usize, String> {
    let parsed = parse_retention(&policy)?;
    state
        .with(|p| p.set_retention_policy(parsed).map_err(|e| e.to_string()))
        .await
}

/// The disappearing-message interval for one conversation, in seconds.
#[tauri::command]
pub async fn disappearing_messages(
    state: State<'_, AppState>,
    conversation_id: String,
) -> Result<Option<u64>, String> {
    state
        .with(|p| {
            p.disappearing_messages(&conversation_id)
                .map_err(|e| e.to_string())
        })
        .await
}

/// Sets, or clears, disappearing messages for one conversation.
#[tauri::command]
pub async fn set_disappearing_messages(
    state: State<'_, AppState>,
    conversation_id: String,
    seconds: Option<u64>,
) -> Result<usize, String> {
    state
        .with(|p| {
            p.set_disappearing_messages(&conversation_id, seconds)
                .map_err(|e| e.to_string())
        })
        .await
}

/// How many messages are waiting for the relay to come back.
#[tauri::command]
pub async fn queued_count(state: State<'_, AppState>) -> Result<usize, String> {
    state
        .with(|p| p.queued_count().map_err(|e| e.to_string()))
        .await
}

/// Identity changes the user has not yet answered.
#[tauri::command]
pub async fn identity_changes(
    state: State<'_, AppState>,
) -> Result<Vec<IdentityChangeView>, String> {
    state
        .with(|p| {
            p.identity_changes()
                .map(|list| {
                    list.into_iter()
                        .map(|c| IdentityChangeView {
                            contact_id: c.contact_id,
                            contact_name: c.contact_name,
                            changed_at: c.changed_at,
                        })
                        .collect()
                })
                .map_err(|e| e.to_string())
        })
        .await
}

/// Records that the user answered an identity change warning.
///
/// Not a verification, and the command is named so it cannot be mistaken for
/// one at the call site.
#[tauri::command]
pub async fn acknowledge_identity_change(
    state: State<'_, AppState>,
    contact_id: String,
) -> Result<(), String> {
    state
        .with(|p| {
            p.acknowledge_identity_change(&contact_id)
                .map_err(|e| e.to_string())
        })
        .await
}

/// Whether opening this device requires a passphrase.
#[tauri::command]
pub async fn is_passphrase_protected(state: State<'_, AppState>) -> Result<bool, String> {
    state
        .with(|p| p.is_passphrase_protected().map_err(|e| e.to_string()))
        .await
}

/// Protects this device with a passphrase, re-encrypting the database.
#[tauri::command]
pub async fn set_passphrase(
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<(), String> {
    if passphrase.trim().is_empty() {
        return Err("An empty passphrase protects nothing.".to_string());
    }
    state
        .with(|p| p.set_passphrase(&passphrase).map_err(|e| e.to_string()))
        .await
}

/// Removes passphrase protection. A downgrade, and the screen says so.
#[tauri::command]
pub async fn clear_passphrase(state: State<'_, AppState>) -> Result<(), String> {
    state
        .with(|p| p.clear_passphrase().map_err(|e| e.to_string()))
        .await
}

/// The retention choices, so the webview does not hardcode them.
///
/// Returned as `(value, label)` pairs: the value is what the command takes, the
/// label is what the user reads.
#[tauri::command]
pub fn retention_choices() -> Vec<(String, String)> {
    [
        RetentionPolicy::Forever,
        RetentionPolicy::Days30,
        RetentionPolicy::Days7,
        RetentionPolicy::Hours24,
    ]
    .iter()
    .map(|p| (retention_word(*p).to_string(), p.label().to_string()))
    .collect()
}

/// The wire word for a policy.
fn retention_word(policy: RetentionPolicy) -> &'static str {
    match policy {
        RetentionPolicy::Forever => "forever",
        RetentionPolicy::Days30 => "30d",
        RetentionPolicy::Days7 => "7d",
        RetentionPolicy::Hours24 => "24h",
    }
}

/// Parses a wire word back to a policy.
///
/// An unrecognised value is rejected rather than defaulted. Defaulting here
/// would mean a typo in the interface silently selected a policy the user did
/// not choose — and in one direction that deletes their messages.
fn parse_retention(word: &str) -> Result<RetentionPolicy, String> {
    match word {
        "forever" => Ok(RetentionPolicy::Forever),
        "30d" => Ok(RetentionPolicy::Days30),
        "7d" => Ok(RetentionPolicy::Days7),
        "24h" => Ok(RetentionPolicy::Hours24),
        other => Err(format!(
            "'{other}' is not a retention setting this build understands."
        )),
    }
}

/// Identity states, so the webview does not hardcode the label strings.
#[tauri::command]
pub fn identity_labels() -> Vec<String> {
    [
        IdentityState::Verified,
        IdentityState::Unverified,
        IdentityState::KeyChanged,
    ]
    .iter()
    .map(|s| s.label().to_string())
    .collect()
}

fn db_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "Could not find a place to store data on this device.".to_string())?;
    Ok(database_path(dir))
}

/// The database key for this device.
///
/// **Development placeholder.** SPEC §7.2 requires this to come from the OS
/// keystore — Keychain, DPAPI, Secret Service — or from an Argon2id passphrase
/// when the user opts in. Neither is wired up yet, so this derives a key from a
/// file written alongside the database, which protects against nothing.
///
/// It is isolated in one function so the real implementation replaces exactly
/// one thing, and it returns an owned buffer because `Pouch` zeroizes it in
/// place. Tracked in docs/PROGRESS.md as Phase 2 work.
fn device_key(app: &tauri::AppHandle) -> Result<Vec<u8>, String> {
    use pouch_core::keying::development_device_key;

    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "Could not find a place to store data on this device.".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    development_device_key(&dir.join("device.key")).map_err(|e| e.to_string())
}
