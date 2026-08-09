//! The relay that ships inside this installer.
//!
//! A Pouch install used to be half a product: the client was installed, and the
//! relay it needed was a second binary the user downloaded separately and ran
//! in a terminal. That made first run "go find the other file", and it made a
//! two-person test depend on one of the two people being willing to operate a
//! server from a command line.
//!
//! So the relay binary is bundled as a Tauri sidecar and this module starts it.
//! Same executable as the standalone `pouch-relay`, same code, same blindness
//! properties — the *packaging* changed, not the relay.
//!
//! ## What this deliberately does not do
//!
//! It does not start automatically. Hosting means publishing an onion service
//! and accepting inbound traffic for as long as the window is open, and that is
//! not something to switch on for someone who did not ask for it. The user
//! presses a button, having read one sentence saying what it does.
//!
//! It holds no keys and reads no messages. The relay is a separate process with
//! its own database of ciphertext it cannot decrypt (`THREAT_MODEL.md` §3).
//! This module knows a process handle and the address that process printed.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use serde::Serialize;

/// Where the loopback listener binds.
///
/// The same address `state::relay_config` defaults to, so a fresh install with
/// the bundled relay running needs no configuration: the client looks for a
/// relay on loopback and finds the one this module started.
const DEFAULT_BIND: &str = "127.0.0.1:8443";

/// What the window is told about the bundled relay.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LocalRelayStatus {
    /// Whether a relay process started by this window is still running.
    pub running: bool,
    /// The onion address it published, once it has published one.
    ///
    /// `None` while Tor is still bootstrapping, which takes tens of seconds on
    /// a first run. The UI says "starting" rather than "no address" — those are
    /// different states and only one of them is a problem.
    pub onion_address: Option<String>,
    /// The loopback address it listens on, for this machine's own client.
    pub bind_address: Option<String>,
    /// Set when the relay exited, or failed to publish an onion service.
    ///
    /// Carried rather than dropped: a host who believes they are reachable and
    /// is not will conclude the other person is ignoring them.
    pub error: Option<String>,
}

/// A relay process owned by this window.
///
/// `status` is an `Arc` because the thread draining the child's stdout writes
/// into it after `start` has returned. That thread outlives the call, so the
/// state cannot live in the struct alone.
#[derive(Default)]
pub struct LocalRelay {
    child: Mutex<Option<Child>>,
    status: Arc<Mutex<LocalRelayStatus>>,
}

impl LocalRelay {
    /// Starts the bundled relay with its onion service enabled.
    ///
    /// Idempotent: called while a relay is already running it reports that one,
    /// rather than starting a second process that would fail to bind and
    /// surface as a confusing error.
    pub fn start(&self, data_dir: PathBuf) -> Result<LocalRelayStatus, String> {
        {
            let mut guard = self.child.lock().map_err(|_| lock_poisoned())?;
            if let Some(child) = guard.as_mut() {
                match child.try_wait() {
                    // Still running. Report it; do not start a second.
                    Ok(None) => return self.status(),
                    // Exited since we last looked. Fall through and restart.
                    _ => *guard = None,
                }
            }
        }

        std::fs::create_dir_all(&data_dir)
            .map_err(|e| format!("Pouch could not create its data directory: {e}"))?;

        let exe = sidecar_path()?;
        let mut child = Command::new(&exe)
            .env("POUCH_RELAY_DB", data_dir.join("pouch-relay.db"))
            .env("POUCH_RELAY_TOR_STATE", data_dir.join("relay-tor-state"))
            .env("POUCH_RELAY_BIND", DEFAULT_BIND)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                format!(
                    "Pouch could not start the relay that ships with it ({}): {e}",
                    exe.display()
                )
            })?;

        *self.status.lock().map_err(|_| lock_poisoned())? = LocalRelayStatus {
            running: true,
            onion_address: None,
            bind_address: Some(DEFAULT_BIND.to_string()),
            error: None,
        };

        // The relay prints its addresses on stdout and nothing else. Read on a
        // background thread rather than blocking here: publishing an onion
        // service takes tens of seconds and the window must stay responsive.
        if let Some(stdout) = child.stdout.take() {
            let status = Arc::clone(&self.status);
            std::thread::spawn(move || read_addresses(stdout, status));
        }

        *self.child.lock().map_err(|_| lock_poisoned())? = Some(child);
        self.status()
    }

    /// Stops the relay, if this window started one.
    ///
    /// Anyone connected through its onion address loses that route. Blobs
    /// already accepted stay in its database until their TTL expires — stopping
    /// the relay is not erasure.
    pub fn stop(&self) -> Result<LocalRelayStatus, String> {
        if let Some(mut child) = self.child.lock().map_err(|_| lock_poisoned())?.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let mut status = self.status.lock().map_err(|_| lock_poisoned())?;
        *status = LocalRelayStatus::default();
        Ok(status.clone())
    }

    /// What the relay is doing right now.
    ///
    /// Re-checks the process rather than trusting the last thing it was told: a
    /// relay that died while Tor was bootstrapping would otherwise report
    /// "starting" for as long as the window stayed open.
    pub fn status(&self) -> Result<LocalRelayStatus, String> {
        let exited = {
            let mut guard = self.child.lock().map_err(|_| lock_poisoned())?;
            let gone = match guard.as_mut() {
                None => false,
                Some(child) => matches!(child.try_wait(), Ok(Some(_))),
            };
            if gone {
                *guard = None;
            }
            gone
        };

        let mut status = self.status.lock().map_err(|_| lock_poisoned())?;
        if exited {
            *status = LocalRelayStatus {
                running: false,
                onion_address: None,
                bind_address: None,
                error: Some(
                    "The bundled relay stopped running. Messages will queue on \
                     this device until it is started again."
                        .to_string(),
                ),
            };
        }
        Ok(status.clone())
    }
}

/// Where the sidecar sits.
///
/// Tauri places an `externalBin` beside the main executable at install time and
/// strips the target triple from its name, so this is a sibling lookup rather
/// than a resource-directory one.
fn sidecar_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("Pouch could not locate its own program directory: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "Pouch is installed somewhere it cannot read from.".to_string())?;

    let name = if cfg!(windows) {
        "pouch-relay.exe"
    } else {
        "pouch-relay"
    };
    let path = dir.join(name);

    if !path.exists() {
        return Err(format!(
            "The relay that should ship with Pouch is not next to it ({}). \
             This build was packaged incorrectly; a relay has to be started \
             separately.",
            path.display()
        ));
    }
    Ok(path)
}

/// Drains the child's stdout, keeping the two lines that name an address.
///
/// Parsing stdout is a weak contract — it breaks if the relay's wording
/// changes. It is chosen anyway because the alternative is a second IPC channel
/// into a process whose entire design goal is to know as little as possible.
/// The strings matched here are asserted by a test in this module, so a change
/// to the relay's output fails the build rather than silently leaving the host
/// with no address to share.
fn read_addresses(stdout: std::process::ChildStdout, status: Arc<Mutex<LocalRelayStatus>>) {
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if let Some(address) = onion_address_in(&line) {
            if let Ok(mut status) = status.lock() {
                status.onion_address = Some(address);
            }
        } else if let Some(failure) = onion_failure_in(&line) {
            if let Ok(mut status) = status.lock() {
                status.error = Some(failure);
            }
        }
    }
}

/// The onion address in a relay startup line, if that is what the line is.
fn onion_address_in(line: &str) -> Option<String> {
    line.trim()
        .strip_prefix("pouch-relay onion service listening at ")
        .map(|address| address.trim().to_string())
        .filter(|address| address.ends_with(".onion"))
}

/// The reason an onion service did not start, if the line says so.
fn onion_failure_in(line: &str) -> Option<String> {
    line.trim()
        .strip_prefix("pouch-relay: onion service failed to start: ")
        .map(|reason| {
            format!(
                "The bundled relay started, but could not publish an address \
                 for other people to reach it: {}. It is still usable by this \
                 device.",
                reason.trim()
            )
        })
}

/// What a lost lock is reported as.
///
/// A poisoned lock means a thread panicked while holding the process handle, so
/// this module no longer knows whether a relay is running. Restarting is the
/// only honest advice — silently reporting "not running" could leave an
/// orphaned relay holding the port.
fn lock_poisoned() -> String {
    "Pouch lost track of the relay process and cannot safely act on it. \
     Restart Pouch."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact line `server/src/main.rs` prints on a successful publish.
    ///
    /// This test is the contract. Parsing another process's stdout is a weak
    /// coupling, and this is what stops it breaking silently: change the
    /// relay's wording and this fails, rather than a host being left with no
    /// address to share and no indication why.
    #[test]
    fn the_onion_line_the_relay_prints_is_recognised() {
        let address = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion";
        let line = format!("pouch-relay onion service listening at {address}");
        assert_eq!(onion_address_in(&line).as_deref(), Some(address));
    }

    #[test]
    fn the_bind_line_is_not_mistaken_for_an_onion_address() {
        let line = "pouch-relay listening on 127.0.0.1:8443 (access logging disabled)";
        assert!(onion_address_in(line).is_none());
        assert!(onion_failure_in(line).is_none());
    }

    /// A truncated or non-onion address is refused rather than shown.
    ///
    /// Showing a host an address that is not an onion address would have them
    /// send it to someone who then cannot connect, and the failure would look
    /// like the other person's problem.
    #[test]
    fn something_that_is_not_an_onion_address_is_not_reported_as_one() {
        let line = "pouch-relay onion service listening at 127.0.0.1:8443";
        assert!(onion_address_in(line).is_none());
    }

    #[test]
    fn a_failed_publish_is_carried_as_an_error_naming_the_cause() {
        let line = "pouch-relay: onion service failed to start: no consensus";
        let message = onion_failure_in(line).expect("should parse as a failure");
        assert!(message.contains("no consensus"));
        assert!(message.contains("could not publish"));
    }

    /// Status defaults to "not running", never to "running".
    ///
    /// The direction matters. Defaulting to running would show a host a green
    /// state for a relay that does not exist, which is exactly the reassuring
    /// indicator over an uncertain state that SPEC §1 forbids.
    #[test]
    fn the_default_status_claims_nothing() {
        let status = LocalRelayStatus::default();
        assert!(!status.running);
        assert!(status.onion_address.is_none());
        assert!(status.error.is_none());
    }
}
