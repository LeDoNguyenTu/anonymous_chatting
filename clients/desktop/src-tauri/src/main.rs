// Pouch desktop shell.
//
// This process owns the window and nothing else. Every security-relevant
// operation is a call into `pouch-core` (DECISIONS.md D-012) — the webview
// never sees a key, a cipher, or a raw ciphertext blob, and the commands
// exposed here must stay at the level of `send_message` / `receive_messages`
// rather than exposing anything beneath them.
//
// Phase 0: the shell renders the token layer. Commands arrive in Phase 1.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("failed to start the Pouch window");
}
