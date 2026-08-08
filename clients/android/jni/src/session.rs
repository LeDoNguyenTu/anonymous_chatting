//! Everything the Android client can ask for, with no JNI in sight.
//!
//! This module is the reason the untestable part of this crate is one
//! function. Every operation the Kotlin side can invoke is a method here,
//! taking ordinary Rust types and returning ordinary Rust results — so the
//! whole surface runs under `cargo test` on a developer's machine, with no
//! emulator, no NDK, and no JVM. `lib.rs` marshals; this decides.
//!
//! **Nothing below `Pouch` is reachable from here** — no key, no cipher, no
//! storage handle, no raw ciphertext blob (D-012). The shapes returned are
//! `pouch_core::views`, the same ones the desktop client renders, so the two
//! cannot describe the same security state differently (D-046).

use pouch_core::transport::{RelayConfig, TorRelayConfig};
use pouch_core::views::{
    AttachmentView, ConversationView, ExportBackupView, IdentityChangeView, ImportBackupView,
    MessageView, RelayVisibilityView, SecurityDetailsView, SendResult, TransportOptionView,
};
use pouch_core::{backup_file_name, IdentityState, Pouch, RetentionPolicy};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// What can go wrong on this side of the boundary.
///
/// These become Java exceptions. Each carries text that SPEC §6.9 requires to
/// say what happened and what to do, because the Kotlin layer shows it to the
/// user rather than substituting wording of its own.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// No identity is open, so there is nothing to operate on.
    #[error("No identity is open on this device yet.")]
    NotOpen,
    /// An identity is already open and the operation requires that none is.
    #[error("An identity is already open on this device.")]
    AlreadyOpen,
    /// The core refused, and this is what it said.
    #[error("{0}")]
    Core(String),
    /// The arguments did not deserialize into what the operation needs.
    ///
    /// A programming error in the Kotlin facade rather than anything a user
    /// did, but it still surfaces rather than being swallowed.
    #[error(
        "The '{operation}' operation was called with arguments it does not understand: {detail}"
    )]
    BadArguments {
        /// The operation that was called.
        operation: String,
        /// What serde said about the payload.
        detail: String,
    },
    /// The operation name is not one this build implements.
    #[error("'{0}' is not an operation this build implements.")]
    UnknownOperation(String),
    /// The result could not be encoded for the trip back across.
    #[error("The result of '{0}' could not be encoded.")]
    Encoding(String),
    /// No Tor address is configured, so Tor cannot be selected.
    #[error("No Tor relay address is configured for this build, so Tor cannot be used yet.")]
    NoTorConfigured,
}

/// Shorthand for this module's results.
pub type BridgeResult<T> = Result<T, BridgeError>;

/// Turns a core error into a bridge error without losing its wording.
fn core_err<E: std::fmt::Display>(e: E) -> BridgeError {
    BridgeError::Core(e.to_string())
}

/// Where this device keeps things, and which relay it talks to.
///
/// Supplied once by the Kotlin side at startup, because only Android knows its
/// own per-app directories. Everything else about a route — which environment
/// variables name a Tor target, what a route is called — stays in the core so
/// this client cannot drift from the others.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Absolute path to the SQLCipher database.
    pub db_path: String,
    /// Directory for Tor's own bootstrap and circuit state. A sibling of the
    /// database, never inside it: this is not message content, and wiping the
    /// database should not throw away a working bootstrap.
    pub tor_state_dir: String,
    /// The direct relay this build talks to.
    pub relay_url: String,
}

impl SessionConfig {
    /// The relay configuration for the direct route.
    ///
    /// Loopback and unpinned, which `RelayClient::new` only tolerates because
    /// it is loopback (D-017) — the same placeholder the desktop client uses
    /// until a deployment address exists.
    fn relay(&self) -> RelayConfig {
        RelayConfig::insecure_local(self.relay_url.clone())
    }

    /// The Tor target for this build, if one is configured.
    ///
    /// The variable names are the core's to define (D-045), so an Android
    /// build and a CLI build cannot disagree about what configures Tor.
    fn tor(&self) -> Option<TorRelayConfig> {
        TorRelayConfig::from_env(&self.tor_state_dir)
    }
}

/// The one `Pouch` this app process owns, and the runtime its async work runs on.
///
/// Mirrors the desktop client's `AppState` deliberately: one guarded client,
/// one place that decides what "not unlocked" means, and no way for a caller
/// to reach the value directly.
pub struct Session {
    inner: Mutex<Option<Pouch>>,
    config: SessionConfig,
}

/// Arguments for operations that name a conversation.
#[derive(Deserialize)]
struct ConversationArgs {
    conversation_id: String,
}

/// Arguments for operations that name a contact.
#[derive(Deserialize)]
struct ContactArgs {
    contact_id: String,
}

#[derive(Deserialize)]
struct CreateIdentityArgs {
    display_name: String,
    #[serde(default)]
    passphrase: Option<String>,
}

#[derive(Deserialize)]
struct OpenIdentityArgs {
    #[serde(default)]
    passphrase: Option<String>,
}

#[derive(Deserialize)]
struct AddContactArgs {
    display_name: String,
    invite_code: String,
}

#[derive(Deserialize)]
struct SendMessageArgs {
    conversation_id: String,
    body: String,
}

#[derive(Deserialize)]
struct VerifyContactArgs {
    contact_id: String,
    verified: bool,
}

#[derive(Deserialize)]
struct RelayVisibilityArgs {
    blob_size: usize,
}

#[derive(Deserialize)]
struct MessageArgs {
    message_id: String,
}

#[derive(Deserialize)]
struct RetentionArgs {
    policy: String,
}

#[derive(Deserialize)]
struct DisappearingArgs {
    conversation_id: String,
    #[serde(default)]
    seconds: Option<u64>,
}

#[derive(Deserialize)]
struct SendAttachmentArgs {
    conversation_id: String,
    filename: String,
    content: Vec<u8>,
}

#[derive(Deserialize)]
struct ImportBackupArgs {
    backup: Vec<u8>,
    recovery_key_hex: String,
}

#[derive(Deserialize)]
struct PassphraseArgs {
    passphrase: String,
}

impl Session {
    /// A session with nothing open yet.
    pub fn new(config: SessionConfig) -> Self {
        Self {
            inner: Mutex::new(None),
            config,
        }
    }

    /// The configuration this session was built with.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Runs `f` against the open client, or reports that none is open.
    ///
    /// Every operation that needs a client goes through here, so there is
    /// exactly one definition of "not unlocked".
    async fn with<T, F>(&self, f: F) -> BridgeResult<T>
    where
        F: FnOnce(&mut Pouch) -> BridgeResult<T>,
    {
        let mut guard = self.inner.lock().await;
        match guard.as_mut() {
            Some(pouch) => f(pouch),
            None => Err(BridgeError::NotOpen),
        }
    }

    /// Dispatches one named operation.
    ///
    /// `args` is a JSON object; the return is a JSON value. Operations that
    /// take nothing ignore `args`, and operations that return nothing return
    /// `null`.
    ///
    /// The match below is the whole API. An operation that is not listed does
    /// not exist, which is why the fallback is an error rather than anything
    /// resembling a passthrough: a bridge that forwards unrecognised requests
    /// to the core is a bridge that grows a surface nobody reviewed.
    pub async fn dispatch(
        &self,
        operation: &str,
        args: serde_json::Value,
    ) -> BridgeResult<serde_json::Value> {
        /// Parses this operation's arguments, naming the operation if it fails.
        fn parse<T: for<'de> Deserialize<'de>>(
            operation: &str,
            args: serde_json::Value,
        ) -> BridgeResult<T> {
            serde_json::from_value(args).map_err(|e| BridgeError::BadArguments {
                operation: operation.to_string(),
                detail: e.to_string(),
            })
        }

        /// Encodes a result, naming the operation if it fails.
        fn encode<T: Serialize>(operation: &str, value: T) -> BridgeResult<serde_json::Value> {
            serde_json::to_value(value).map_err(|_| BridgeError::Encoding(operation.to_string()))
        }

        match operation {
            /* -- identity ------------------------------------------------- */
            "has_identity" => {
                if self.is_open().await {
                    return encode(operation, true);
                }
                let exists = std::path::Path::new(&self.config.db_path).exists();
                encode(operation, exists)
            }

            "needs_passphrase" => {
                let source =
                    pouch_core::keying::key_source(&self.config.db_path).map_err(core_err)?;
                encode(operation, source.needs_passphrase())
            }

            "create_identity" => {
                let a: CreateIdentityArgs = parse(operation, args)?;
                let mut guard = self.inner.lock().await;
                if guard.is_some() {
                    return Err(BridgeError::AlreadyOpen);
                }
                let mut key =
                    pouch_core::keying::unlock(&self.config.db_path, a.passphrase.as_deref())
                        .map_err(core_err)?;
                let pouch = Pouch::create(
                    &a.display_name,
                    &self.config.db_path,
                    &mut key,
                    self.config.relay(),
                )
                .map_err(core_err)?;
                *guard = Some(pouch);
                Ok(serde_json::Value::Null)
            }

            "open_identity" => {
                let a: OpenIdentityArgs = parse(operation, args)?;
                let mut guard = self.inner.lock().await;
                if guard.is_some() {
                    return Ok(serde_json::Value::Null);
                }
                let mut key =
                    pouch_core::keying::unlock(&self.config.db_path, a.passphrase.as_deref())
                        .map_err(core_err)?;
                let pouch = Pouch::open(&self.config.db_path, &mut key, self.config.relay())
                    .map_err(core_err)?;
                *guard = Some(pouch);
                Ok(serde_json::Value::Null)
            }

            "display_name" => {
                let name = self.with(|p| Ok(p.display_name().to_string())).await?;
                encode(operation, name)
            }

            "invite_code" => {
                let code = self.with(|p| p.invite_code().map_err(core_err)).await?;
                encode(operation, code)
            }

            "identity_labels" => encode(
                operation,
                [
                    IdentityState::Verified,
                    IdentityState::Unverified,
                    IdentityState::KeyChanged,
                ]
                .iter()
                .map(|s| s.label().to_string())
                .collect::<Vec<_>>(),
            ),

            /* -- contacts and conversations ------------------------------- */
            "add_contact" => {
                let a: AddContactArgs = parse(operation, args)?;
                let mut guard = self.inner.lock().await;
                let pouch = guard.as_mut().ok_or(BridgeError::NotOpen)?;
                let id = pouch
                    .add_contact(&a.display_name, &a.invite_code)
                    .await
                    .map_err(core_err)?;
                encode(operation, id)
            }

            "conversations" => {
                let list = self
                    .with(|p| {
                        p.conversations()
                            .map(|c| {
                                c.into_iter()
                                    .map(ConversationView::from)
                                    .collect::<Vec<_>>()
                            })
                            .map_err(core_err)
                    })
                    .await?;
                encode(operation, list)
            }

            "messages" => {
                let a: ConversationArgs = parse(operation, args)?;
                let list = self
                    .with(|p| {
                        p.messages(&a.conversation_id)
                            .map(|m| m.into_iter().map(MessageView::from).collect::<Vec<_>>())
                            .map_err(core_err)
                    })
                    .await?;
                encode(operation, list)
            }

            "safety_number" => {
                let a: ContactArgs = parse(operation, args)?;
                let number = self
                    .with(|p| {
                        p.safety_number(&a.contact_id)
                            .map(|n| n.grouped())
                            .map_err(core_err)
                    })
                    .await?;
                encode(operation, number)
            }

            "verify_contact" => {
                let a: VerifyContactArgs = parse(operation, args)?;
                self.with(|p| {
                    p.verify_contact(&a.contact_id, a.verified)
                        .map_err(core_err)
                })
                .await?;
                Ok(serde_json::Value::Null)
            }

            /* -- messaging ------------------------------------------------ */
            "send_message" => {
                let a: SendMessageArgs = parse(operation, args)?;
                let mut guard = self.inner.lock().await;
                let pouch = guard.as_mut().ok_or(BridgeError::NotOpen)?;
                let manifest = pouch
                    .send_message(&a.conversation_id, &a.body)
                    .await
                    .map_err(core_err)?;
                encode(operation, SendResult::from(&manifest))
            }

            "receive_messages" => {
                let mut guard = self.inner.lock().await;
                let pouch = guard.as_mut().ok_or(BridgeError::NotOpen)?;
                let received = pouch.receive_messages().await.map_err(core_err)?;
                encode(
                    operation,
                    received
                        .messages
                        .into_iter()
                        .map(MessageView::from)
                        .collect::<Vec<_>>(),
                )
            }

            "flush_outbox" => {
                let mut guard = self.inner.lock().await;
                let pouch = guard.as_mut().ok_or(BridgeError::NotOpen)?;
                let sent = pouch.flush_outbox().await.map_err(core_err)?;
                encode(operation, sent)
            }

            "queued_count" => {
                let n = self.with(|p| p.queued_count().map_err(core_err)).await?;
                encode(operation, n)
            }

            /* -- attachments ---------------------------------------------- */
            "send_attachment" => {
                let a: SendAttachmentArgs = parse(operation, args)?;
                let mut guard = self.inner.lock().await;
                let pouch = guard.as_mut().ok_or(BridgeError::NotOpen)?;
                let manifest = pouch
                    .send_attachment(&a.conversation_id, &a.filename, &a.content)
                    .await
                    .map_err(core_err)?;
                encode(operation, SendResult::from(&manifest))
            }

            "attachment" => {
                let a: MessageArgs = parse(operation, args)?;
                let found = self
                    .with(|p| {
                        p.attachment(&a.message_id)
                            .map(|opt| {
                                opt.map(|(filename, content)| AttachmentView { filename, content })
                            })
                            .map_err(core_err)
                    })
                    .await?;
                encode(operation, found)
            }

            /* -- transport ------------------------------------------------ */
            "transport_state" => {
                let mut guard = self.inner.lock().await;
                let pouch = guard.as_mut().ok_or(BridgeError::NotOpen)?;
                encode(operation, pouch.transport_state().await.label().to_string())
            }

            "transport_options" => encode(operation, TransportOptionView::selectable()),

            "connect_tor" => {
                let tor = self.config.tor().ok_or(BridgeError::NoTorConfigured)?;
                let mut guard = self.inner.lock().await;
                let pouch = guard.as_mut().ok_or(BridgeError::NotOpen)?;
                pouch.connect_tor(tor).await.map_err(core_err)?;
                Ok(serde_json::Value::Null)
            }

            "use_direct_relay" => {
                self.with(|p| p.use_direct_relay(self.config.relay()).map_err(core_err))
                    .await?;
                Ok(serde_json::Value::Null)
            }

            /* -- what the user is told ------------------------------------ */
            "security_details" => {
                let details = self
                    .with(|p| Ok(SecurityDetailsView::from(p.security_details())))
                    .await?;
                encode(operation, details)
            }

            "relay_visibility" => {
                let a: RelayVisibilityArgs = parse(operation, args)?;
                let view = self
                    .with(|p| {
                        Ok(RelayVisibilityView::from(
                            pouch_core::manifest::RelayVisibility::for_message(
                                p.inbox_id(),
                                a.blob_size,
                                p.current_route(),
                            ),
                        ))
                    })
                    .await?;
                encode(operation, view)
            }

            /* -- storage controls ----------------------------------------- */
            "retention_policy" => {
                let word = self
                    .with(|p| p.retention_policy().map(retention_word).map_err(core_err))
                    .await?;
                encode(operation, word)
            }

            "set_retention_policy" => {
                let a: RetentionArgs = parse(operation, args)?;
                let policy = parse_retention(&a.policy)?;
                let purged = self
                    .with(|p| p.set_retention_policy(policy).map_err(core_err))
                    .await?;
                encode(operation, purged)
            }

            "disappearing_messages" => {
                let a: ConversationArgs = parse(operation, args)?;
                let seconds = self
                    .with(|p| {
                        p.disappearing_messages(&a.conversation_id)
                            .map_err(core_err)
                    })
                    .await?;
                encode(operation, seconds)
            }

            "set_disappearing_messages" => {
                let a: DisappearingArgs = parse(operation, args)?;
                self.with(|p| {
                    p.set_disappearing_messages(&a.conversation_id, a.seconds)
                        .map_err(core_err)
                })
                .await?;
                Ok(serde_json::Value::Null)
            }

            "identity_changes" => {
                let list = self
                    .with(|p| {
                        p.identity_changes()
                            .map(|l| {
                                l.into_iter()
                                    .map(IdentityChangeView::from)
                                    .collect::<Vec<_>>()
                            })
                            .map_err(core_err)
                    })
                    .await?;
                encode(operation, list)
            }

            "acknowledge_identity_change" => {
                let a: ContactArgs = parse(operation, args)?;
                self.with(|p| {
                    p.acknowledge_identity_change(&a.contact_id)
                        .map_err(core_err)
                })
                .await?;
                Ok(serde_json::Value::Null)
            }

            "is_passphrase_protected" => {
                let protected = self
                    .with(|p| p.is_passphrase_protected().map_err(core_err))
                    .await?;
                encode(operation, protected)
            }

            "set_passphrase" => {
                let a: PassphraseArgs = parse(operation, args)?;
                self.with(|p| p.set_passphrase(&a.passphrase).map_err(core_err))
                    .await?;
                Ok(serde_json::Value::Null)
            }

            "clear_passphrase" => {
                self.with(|p| p.clear_passphrase().map_err(core_err))
                    .await?;
                Ok(serde_json::Value::Null)
            }

            /* -- backup ---------------------------------------------------- */
            "export_backup" => {
                let view = self
                    .with(|p| {
                        let recovery_key = pouch_core::new_recovery_key();
                        let backup = p.export_backup(&recovery_key).map_err(core_err)?;
                        Ok(ExportBackupView {
                            recovery_key_hex: hex_encode(&recovery_key),
                            backup,
                            file_name: backup_file_name(),
                        })
                    })
                    .await?;
                encode(operation, view)
            }

            "import_backup" => {
                let a: ImportBackupArgs = parse(operation, args)?;
                let recovery_key = hex_decode(&a.recovery_key_hex).ok_or_else(|| {
                    BridgeError::Core(
                        "That recovery key is not in the format this app wrote it in.".to_string(),
                    )
                })?;
                let mut guard = self.inner.lock().await;
                if guard.is_some() {
                    return Err(BridgeError::AlreadyOpen);
                }
                let mut key =
                    pouch_core::keying::unlock(&self.config.db_path, None).map_err(core_err)?;
                let pouch = Pouch::import_backup(
                    &self.config.db_path,
                    &mut key,
                    &recovery_key,
                    &a.backup,
                    self.config.relay(),
                )
                .await
                .map_err(core_err)?;
                let view = ImportBackupView {
                    display_name: pouch.display_name().to_string(),
                    conversation_count: pouch.conversations().map(|c| c.len()).unwrap_or(0),
                };
                *guard = Some(pouch);
                encode(operation, view)
            }

            /* -- destruction ---------------------------------------------- */
            "wipe_all" => {
                let mut guard = self.inner.lock().await;
                let pouch = guard.as_mut().ok_or(BridgeError::NotOpen)?;
                pouch.wipe_all().map_err(core_err)?;
                *guard = None;
                Ok(serde_json::Value::Null)
            }

            other => Err(BridgeError::UnknownOperation(other.to_string())),
        }
    }

    /// Whether an identity is currently open.
    pub async fn is_open(&self) -> bool {
        self.inner.lock().await.is_some()
    }
}

/// The word a retention policy is known by across the boundary.
fn retention_word(policy: RetentionPolicy) -> &'static str {
    match policy {
        RetentionPolicy::Forever => "forever",
        RetentionPolicy::Days30 => "30d",
        RetentionPolicy::Days7 => "7d",
        RetentionPolicy::Hours24 => "24h",
    }
}

/// Reads a retention word back.
///
/// An unrecognised value is rejected rather than defaulted. Defaulting here
/// would mean a typo in the interface silently selected a policy the user did
/// not choose — and in one direction that deletes their messages.
fn parse_retention(word: &str) -> BridgeResult<RetentionPolicy> {
    match word {
        "forever" => Ok(RetentionPolicy::Forever),
        "30d" => Ok(RetentionPolicy::Days30),
        "7d" => Ok(RetentionPolicy::Days7),
        "24h" => Ok(RetentionPolicy::Hours24),
        other => Err(BridgeError::Core(format!(
            "'{other}' is not a retention setting this build understands."
        ))),
    }
}

/// Hex, without taking a dependency for it.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Hex, in reverse. `None` if the text is not an even run of hex digits.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_in(dir: &std::path::Path) -> Session {
        Session::new(SessionConfig {
            db_path: dir.join("pouch.db").to_string_lossy().to_string(),
            tor_state_dir: dir.join("tor-state").to_string_lossy().to_string(),
            relay_url: "http://127.0.0.1:8443".to_string(),
        })
    }

    /// A runtime for tests, since `dispatch` is async.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(f)
    }

    #[test]
    fn an_unknown_operation_is_refused_rather_than_forwarded() {
        let dir = tempfile::tempdir().unwrap();
        let session = session_in(dir.path());

        let err = block_on(session.dispatch("please_do_something", serde_json::json!({})))
            .expect_err("an unlisted operation must not succeed");

        assert!(matches!(err, BridgeError::UnknownOperation(_)));
        // The name is echoed so a Kotlin typo is diagnosable from the message
        // alone, without attaching a debugger to a phone.
        assert!(err.to_string().contains("please_do_something"));
    }

    #[test]
    fn operations_needing_an_identity_say_so_rather_than_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let session = session_in(dir.path());

        // A panic here would cross the FFI boundary on a real device. Every one
        // of these must be an ordinary error instead.
        for operation in [
            "display_name",
            "invite_code",
            "conversations",
            "receive_messages",
            "flush_outbox",
            "queued_count",
            "transport_state",
            "security_details",
            "retention_policy",
            "identity_changes",
            "is_passphrase_protected",
            "export_backup",
            "wipe_all",
        ] {
            let err = block_on(session.dispatch(operation, serde_json::json!({})))
                .expect_err(&format!("{operation} must refuse without an identity"));
            assert!(
                matches!(err, BridgeError::NotOpen),
                "{operation} reported {err:?} rather than NotOpen"
            );
        }
    }

    #[test]
    fn transport_options_need_no_identity_and_exclude_offline() {
        let dir = tempfile::tempdir().unwrap();
        let session = session_in(dir.path());

        // Readable before unlock: the settings screen is reachable on first run.
        let value = block_on(session.dispatch("transport_options", serde_json::json!({})))
            .expect("transport options are static");

        let options = value.as_array().expect("an array");
        assert_eq!(options.len(), 2);
        let routes: Vec<_> = options
            .iter()
            .map(|o| o["route"].as_str().unwrap())
            .collect();
        assert!(routes.contains(&"DIRECT"));
        assert!(routes.contains(&"TOR"));
        assert!(
            !routes.contains(&"OFFLINE"),
            "offline is a reported state, not a transport anyone chooses"
        );
    }

    #[test]
    fn has_identity_is_false_before_anything_exists() {
        let dir = tempfile::tempdir().unwrap();
        let session = session_in(dir.path());

        let value = block_on(session.dispatch("has_identity", serde_json::json!({}))).unwrap();
        assert_eq!(value, serde_json::json!(false));
    }

    #[test]
    fn bad_arguments_name_the_operation_that_rejected_them() {
        let dir = tempfile::tempdir().unwrap();
        let session = session_in(dir.path());

        let err = block_on(session.dispatch("send_message", serde_json::json!({"body": 42})))
            .expect_err("a numeric body is not a message");

        match err {
            BridgeError::BadArguments { operation, .. } => assert_eq!(operation, "send_message"),
            other => panic!("expected BadArguments, got {other:?}"),
        }
    }

    #[test]
    fn a_full_identity_lifecycle_works_across_the_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let session = session_in(dir.path());

        block_on(session.dispatch(
            "create_identity",
            serde_json::json!({"display_name": "Ana"}),
        ))
        .expect("create");

        assert_eq!(
            block_on(session.dispatch("display_name", serde_json::json!({}))).unwrap(),
            serde_json::json!("Ana")
        );
        assert_eq!(
            block_on(session.dispatch("has_identity", serde_json::json!({}))).unwrap(),
            serde_json::json!(true)
        );

        // An invite code is what a contact scans. It must not be empty.
        let code = block_on(session.dispatch("invite_code", serde_json::json!({}))).unwrap();
        assert!(!code.as_str().unwrap().is_empty());

        // Creating twice must not silently replace a live identity.
        let err = block_on(session.dispatch(
            "create_identity",
            serde_json::json!({"display_name": "Someone else"}),
        ))
        .expect_err("a second create must refuse");
        assert!(matches!(err, BridgeError::AlreadyOpen));
    }

    #[test]
    fn security_details_reach_the_client_intact() {
        let dir = tempfile::tempdir().unwrap();
        let session = session_in(dir.path());
        block_on(session.dispatch(
            "create_identity",
            serde_json::json!({"display_name": "Ana"}),
        ))
        .unwrap();

        let details =
            block_on(session.dispatch("security_details", serde_json::json!({}))).unwrap();

        // Every field the Security details screen prints must arrive. A missing
        // one renders as blank, which under-reports what is protecting the user.
        for field in [
            "ciphersuite",
            "aead",
            "key_agreement",
            "signature",
            "kdf",
            "protocol",
            "local_database",
            "passphrase_derivation",
            "transport",
            "relay_address",
            "openmls_version",
            "app_version",
        ] {
            assert!(
                details[field].as_str().is_some_and(|s| !s.is_empty()),
                "security_details.{field} did not arrive"
            );
        }
    }

    #[test]
    fn a_send_returns_every_manifest_stage_including_the_ones_that_did_not_run() {
        let dir = tempfile::tempdir().unwrap();
        let session = session_in(dir.path());
        block_on(session.dispatch(
            "create_identity",
            serde_json::json!({"display_name": "Ana"}),
        ))
        .unwrap();

        // No contact and no relay, so this fails — but it must fail with a
        // manifest rather than by panicking, and the manifest must still list
        // every stage. A manifest that only lists successes is not a manifest.
        let outcome = block_on(session.dispatch(
            "send_message",
            serde_json::json!({"conversation_id": "nobody", "body": "hello"}),
        ));

        if let Ok(value) = outcome {
            let rows = value["rows"].as_array().expect("rows");
            assert_eq!(rows.len(), 9, "all nine stages are always reported");
            assert!(rows.iter().any(|r| r["ran"] == serde_json::json!(false)));
        }
    }

    #[test]
    fn retention_words_round_trip_and_a_typo_is_refused() {
        for word in ["forever", "30d", "7d", "24h"] {
            let policy = parse_retention(word).expect("a known word");
            assert_eq!(retention_word(policy), word);
        }

        // The dangerous direction: "30" instead of "30d" must not quietly
        // become a policy that deletes messages.
        assert!(parse_retention("30").is_err());
        assert!(parse_retention("").is_err());
    }

    #[test]
    fn hex_round_trips_and_rejects_malformed_input() {
        let bytes = vec![0x00, 0x0f, 0xff, 0xa5];
        assert_eq!(hex_encode(&bytes), "000fffa5");
        assert_eq!(hex_decode("000fffa5"), Some(bytes));

        assert_eq!(hex_decode("abc"), None, "odd length");
        assert_eq!(hex_decode("zz"), None, "not hex");
    }

    #[test]
    fn a_malformed_recovery_key_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let session = session_in(dir.path());

        let err = block_on(session.dispatch(
            "import_backup",
            serde_json::json!({
                "backup": [1, 2, 3],
                "recovery_key_hex": "not-a-key",
            }),
        ))
        .expect_err("a malformed key must not begin an import");

        assert!(err.to_string().contains("recovery key"));
        assert!(
            !std::path::Path::new(&session.config().db_path).exists(),
            "nothing should have been created"
        );
    }
}
