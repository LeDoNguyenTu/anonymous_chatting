//! The shapes clients render.
//!
//! Every type here is a flattened, `Serialize`-able projection of something
//! the core already owns. They live in the core rather than in each client for
//! one reason: SPEC §9 requires the Android client to mirror the desktop
//! feature set, and two hand-maintained copies of the same structure drift.
//! The drift that matters is not cosmetic — these carry security state. A
//! field added to [`SecurityDetails`] and picked up by one client but not the
//! other produces a screen that quietly under-reports what is protecting the
//! user, which is the failure mode SPEC §2.3 exists to prevent.
//!
//! **Nothing below `Pouch` appears here.** No key, no cipher, no storage
//! handle, no raw ciphertext blob (D-012) — with one deliberate exception,
//! [`ExportBackupView`], where the encrypted backup and the recovery key are
//! the product the user asked for and have nowhere else to go. That exception
//! is stated on the type itself rather than left to be noticed.
//!
//! These are projections, not a second source of truth. Every string comes
//! from the core type it converts, so a client cannot invent its own wording
//! for a route, a stage, or an identity state.

use serde::Serialize;

use crate::api::{ConversationSummary, IdentityChangeNotice, Message, SecurityDetails};
use crate::manifest::{Manifest, RelayVisibility};
use crate::transport::Route;

/// A conversation, flattened for a list row.
#[derive(Debug, Clone, Serialize)]
pub struct ConversationView {
    /// The conversation's local identifier.
    pub id: String,
    /// The contact on the other side.
    pub contact_id: String,
    /// That contact's display name, as this device recorded it.
    pub contact_name: String,
    /// `VERIFIED` / `UNVERIFIED` / `KEY CHANGED` — the Custody Strip label.
    pub identity: String,
    /// The most recent message body, if there is one.
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

/// A single message.
#[derive(Debug, Clone, Serialize)]
pub struct MessageView {
    /// The message's local identifier.
    pub id: String,
    /// Whether this device sent it.
    pub outgoing: bool,
    /// The plaintext body.
    pub body: String,
    /// Seconds since the epoch, bucketed as the core stores it.
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

/// One row of a message manifest (SPEC §6.5).
#[derive(Debug, Clone, Serialize)]
pub struct ManifestRow {
    /// The stage number, 1 through 9.
    pub number: u8,
    /// The stage's name, as the manifest screen prints it.
    pub label: String,
    /// What happened at this stage, or why nothing did.
    pub detail: String,
    /// Whether the stage actually ran. A stage that did not run is still
    /// listed; it is never hidden.
    pub ran: bool,
}

/// What a send actually did.
///
/// `rows` is the manifest in stage order, including the stages that did not
/// run. A client renders those as `not yet implemented` rather than hiding
/// them, because a manifest that only lists successes is not a manifest.
#[derive(Debug, Clone, Serialize)]
pub struct SendResult {
    /// A one-line summary of the send.
    pub summary: String,
    /// Every stage, in order, run or not.
    pub rows: Vec<ManifestRow>,
    /// Whether the send failed at some stage.
    pub failed: bool,
}

impl From<&Manifest> for SendResult {
    fn from(manifest: &Manifest) -> Self {
        Self {
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
        }
    }
}

impl From<Manifest> for SendResult {
    fn from(manifest: Manifest) -> Self {
        Self::from(&manifest)
    }
}

/// What the relay could see about a message (SPEC §6.5.4).
#[derive(Debug, Clone, Serialize)]
pub struct RelayVisibilityView {
    /// The inbox the blob was filed under.
    pub inbox_id: String,
    /// The blob's size in bytes, after padding.
    pub blob_size: usize,
    /// What the relay can see.
    pub visible: Vec<String>,
    /// What it cannot.
    pub not_visible: Vec<String>,
    /// What a network observer can still infer regardless.
    pub still_inferable: Vec<String>,
}

impl From<RelayVisibility> for RelayVisibilityView {
    fn from(v: RelayVisibility) -> Self {
        Self {
            inbox_id: v.inbox_id,
            blob_size: v.blob_size,
            visible: v.visible.into_iter().map(String::from).collect(),
            not_visible: v.not_visible.into_iter().map(String::from).collect(),
            still_inferable: v.still_inferable.into_iter().map(String::from).collect(),
        }
    }
}

/// Every mechanism in use, for the Security details screen (SPEC §6.7.5).
#[derive(Debug, Clone, Serialize)]
pub struct SecurityDetailsView {
    /// The MLS ciphersuite in use.
    pub ciphersuite: String,
    /// The AEAD that ciphersuite selects.
    pub aead: String,
    /// The key agreement that ciphersuite selects.
    pub key_agreement: String,
    /// The signature scheme that ciphersuite selects.
    pub signature: String,
    /// The key derivation function.
    pub kdf: String,
    /// The messaging protocol and its RFC.
    pub protocol: String,
    /// How the local database is encrypted.
    pub local_database: String,
    /// How a passphrase becomes a database key, when one is set.
    pub passphrase_derivation: String,
    /// The transport in use right now, not the one available.
    pub transport: String,
    /// The relay this device is configured to reach.
    pub relay_address: String,
    /// The pinned `openmls` version.
    pub openmls_version: String,
    /// This build's version.
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

/// A contact's identity key having changed (SPEC §6.7.6).
#[derive(Debug, Clone, Serialize)]
pub struct IdentityChangeView {
    /// The contact whose key changed.
    pub contact_id: String,
    /// That contact's display name.
    pub contact_name: String,
    /// When the change was noticed, in seconds since the epoch.
    pub changed_at: u64,
}

impl From<IdentityChangeNotice> for IdentityChangeView {
    fn from(c: IdentityChangeNotice) -> Self {
        Self {
            contact_id: c.contact_id,
            contact_name: c.contact_name,
            changed_at: c.changed_at,
        }
    }
}

/// One transport the user can choose (SPEC §6.7.9).
///
/// `route` is the same token the Custody Strip and `transport_state` use, so a
/// settings screen can tell which option is active by comparing strings rather
/// than keeping a parallel notion of the same thing. `name` is that route
/// written as a title, and `explanation` is the core's own copy.
#[derive(Debug, Clone, Serialize)]
pub struct TransportOptionView {
    /// The route token, matching what the Custody Strip displays.
    pub route: String,
    /// The same route written as a title.
    pub name: String,
    /// What this route costs and what it buys, in the core's own words.
    pub explanation: String,
}

impl From<Route> for TransportOptionView {
    fn from(r: Route) -> Self {
        Self {
            route: r.label().to_string(),
            name: r.name().to_string(),
            explanation: r.explanation().to_string(),
        }
    }
}

impl TransportOptionView {
    /// The transports a settings screen offers.
    ///
    /// [`Route::Offline`] is not among them. It is a state the client reports
    /// when it cannot reach the relay, not something anyone selects — offering
    /// it would suggest disconnection is a privacy setting.
    ///
    /// Neither option is marked the secure one. The trade is stated and the
    /// choice is the user's.
    pub fn selectable() -> Vec<Self> {
        [Route::Direct, Route::Tor]
            .into_iter()
            .map(Self::from)
            .collect()
    }
}

/// What a conversation view needs to render a stored attachment.
///
/// `content` is decrypted plaintext on its way to an `<img>` tag or a file the
/// user saves — not ciphertext, and not a key. It is the only reason the
/// attachment was fetched.
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentView {
    /// The filename as the sender chose it, carried inside the encrypted
    /// payload and never exposed to the relay.
    pub filename: String,
    /// The decrypted, metadata-stripped file content.
    pub content: Vec<u8>,
}

/// A freshly exported backup, on its way to wherever the user puts it.
///
/// **This is the one type here that carries key material**, and deliberately:
/// SPEC §7.3 puts the recovery key in the user's hands and nowhere else, so
/// there is no version of this feature where the key does not cross to the
/// UI. `recovery_key_hex` exists exactly once, here, and nothing in this
/// project stores it. `backup` is ciphertext the client writes to a file the
/// user chooses.
///
/// Both fields are the product the user asked for. Neither is a convenience.
#[derive(Debug, Clone, Serialize)]
pub struct ExportBackupView {
    /// The recovery key, hex encoded, shown to the user exactly once.
    pub recovery_key_hex: String,
    /// The encrypted backup itself.
    pub backup: Vec<u8>,
    /// A suggested file name. The user chooses where it goes.
    pub file_name: String,
}

/// What an import screen reports once a restore succeeds.
#[derive(Debug, Clone, Serialize)]
pub struct ImportBackupView {
    /// The restored identity's display name.
    pub display_name: String,
    /// How many conversations came back with it.
    pub conversation_count: usize,
}

/// Seconds since the epoch, for a backup file name that sorts and does not
/// collide across exports in the same session.
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The name a backup file is given when the client has no better idea.
pub fn backup_file_name() -> String {
    format!("pouch-backup-{}.pouchbk", unix_seconds())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectable_transports_exclude_offline() {
        let options = TransportOptionView::selectable();

        assert_eq!(options.len(), 2);
        assert!(
            !options.iter().any(|o| o.route == Route::Offline.label()),
            "Offline is a reported state, not a transport anyone chooses"
        );
    }

    #[test]
    fn transport_copy_comes_from_the_route_itself() {
        // A client must not be able to invent its own wording for a route.
        // If this drifts, the settings screen and the Custody Strip start
        // describing the same transport differently.
        for option in TransportOptionView::selectable() {
            assert!(!option.name.is_empty());
            assert!(!option.explanation.is_empty());
            assert_ne!(option.route, option.name);
        }
    }

    #[test]
    fn a_backup_file_name_is_scoped_to_this_product() {
        let name = backup_file_name();
        assert!(name.starts_with("pouch-backup-"));
        assert!(name.ends_with(".pouchbk"));
    }
}
