//! Pouch desktop shell.
//!
//! This process owns the window and nothing else. Every security-relevant
//! operation is a call into `pouch-core` (D-012) — the webview never sees a
//! key, a cipher, or a raw ciphertext blob, and the commands in `commands.rs`
//! stay at the level of `send_message` and `receive_messages` rather than
//! exposing anything beneath them.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;

use state::AppState;

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::has_identity,
            commands::create_identity,
            commands::open_identity,
            commands::display_name,
            commands::invite_code,
            commands::add_contact,
            commands::conversations,
            commands::messages,
            commands::send_message,
            commands::receive_messages,
            commands::safety_number,
            commands::verify_contact,
            commands::transport_state,
            commands::security_details,
            commands::relay_visibility,
            commands::wipe_all,
            commands::identity_labels,
            commands::retention_policy,
            commands::set_retention_policy,
            commands::retention_choices,
            commands::disappearing_messages,
            commands::set_disappearing_messages,
            commands::queued_count,
            commands::identity_changes,
            commands::acknowledge_identity_change,
            commands::is_passphrase_protected,
            commands::set_passphrase,
            commands::clear_passphrase,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the Pouch window");
}
