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
  send-file <conv> <path>     Send a JPEG/PNG/WebP attachment, metadata stripped
  save-attachment <id> <path> Save a received attachment's content to a file
  receive                     Collect and decrypt anything waiting
  list                        List conversations
  read <conversation>         Print a conversation
  safety <contact>            Print the safety number for a contact
  verify <contact>            Mark a contact verified after comparing
  security                    Print every mechanism in use

STORAGE
  keep [forever|30d|7d|24h]   How long messages are kept on this device
  disappear <conv> [secs|off] Disappearing messages for one conversation
  queue                       Messages waiting for the relay to come back
  changes                     Contacts whose identity key changed
  acknowledge <contact>       Answer an identity change warning
  passphrase [set|off]        Protect this device with a passphrase
  backup export <path>        Write an encrypted backup, print the recovery key
  backup import <path>        Restore a backup onto POUCH_DB (must be empty)
  wipe                        Destroy all local data

ENVIRONMENT
  POUCH_DB            path to the local database    (default ./pouch.db)
  POUCH_RELAY         relay base URL                (default http://127.0.0.1:8443)
  POUCH_PASSPHRASE    passphrase, if this device is protected by one
  POUCH_RECOVERY_KEY  recovery key, for backup import only
  POUCH_KEY           64 hex characters, the database key

  POUCH_KEY is a development convenience and is not how a real client should
  hold a key. An environment variable is readable by other processes and lands
  in shell history. With no POUCH_KEY the client reads the keying file beside
  the database and uses a passphrase if one is set, or the development device
  key if not. POUCH_PASSPHRASE and POUCH_RECOVERY_KEY have the same
  shell-history problem and exist for the same reason: this client is headless.
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
        "send-file" => commands::attachments::send_file(&args).await,
        "save-attachment" => commands::attachments::save_attachment(&args),
        "receive" => commands::messaging::receive(&args).await,
        "list" => commands::messaging::list(&args),
        "read" => commands::messaging::read(&args),
        "security" => commands::device::security(&args),
        "keep" => commands::storage::keep(&args),
        "disappear" => commands::storage::disappear(&args),
        "queue" => commands::storage::queue(&args),
        "changes" => commands::storage::changes(&args),
        "acknowledge" => commands::storage::acknowledge(&args),
        "passphrase" => commands::storage::passphrase_command(&args),
        "backup" => match args.get(1).map(String::as_str) {
            Some("export") => commands::backup::export(&args),
            Some("import") => commands::backup::import(&args).await,
            _ => {
                bail!("usage: pouch-cli backup <export|import> <path>");
            }
        },
        "wipe" => commands::device::wipe(&args),
        other => {
            print!("{USAGE}");
            bail!("unknown command: {other}");
        }
    }
}
