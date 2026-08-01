//! Pouch CLI client.
//!
//! A headless client over the same `pouch-core` API the desktop client uses
//! (D-018). It exists so the Phase 1 exit criterion — two clients exchanging
//! text reliably — is verifiable by automation rather than by hand only, and so
//! the system can be demonstrated over SSH.
//!
//! It is not a privileged back door into the core. Every command is a call into
//! `pouch_core::Pouch`; nothing reaches past it. If this client ever needs
//! something the desktop client cannot get, that is a signal about the API, not
//! a licence to bypass it.
//!
//! This file does one thing: map a word to a command. The commands themselves
//! live in `commands/`, grouped by what the user is doing.

mod commands;
mod config;

use anyhow::{bail, Result};

const USAGE: &str = "\
pouch-cli — headless Pouch client

USAGE
  pouch-cli <command> [args]

COMMANDS
  create <display-name>       Create an identity on this device
  invite                      Print an invite code to hand to someone
  add <name> <invite-code>    Start a conversation from someone's invite code
  send <conversation> <text>  Send a message
  receive                     Collect and decrypt anything waiting
  list                        List conversations
  read <conversation>         Print a conversation
  safety <contact>            Print the safety number for a contact
  verify <contact>            Mark a contact verified after comparing
  security                    Print every mechanism in use
  wipe                        Destroy all local data

ENVIRONMENT
  POUCH_DB      path to the local database        (default ./pouch.db)
  POUCH_RELAY   relay base URL                    (default http://127.0.0.1:8443)
  POUCH_KEY     64 hex characters, the database key

  POUCH_KEY is a development convenience and is not how a real client should
  hold a key. The desktop and Android clients take it from the OS keystore, or
  derive it from a passphrase with Argon2id. An environment variable is
  readable by other processes and lands in shell history.
";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        print!("{USAGE}");
        return Ok(());
    };

    match command {
        "create" => commands::identity::create(&args),
        "invite" => commands::identity::invite(&args),
        "add" => commands::contacts::add(&args).await,
        "safety" => commands::contacts::safety(&args),
        "verify" => commands::contacts::verify(&args),
        "send" => commands::messaging::send(&args).await,
        "receive" => commands::messaging::receive(&args).await,
        "list" => commands::messaging::list(&args),
        "read" => commands::messaging::read(&args),
        "security" => commands::device::security(&args),
        "wipe" => commands::device::wipe(&args),
        other => {
            print!("{USAGE}");
            bail!("unknown command: {other}");
        }
    }
}
