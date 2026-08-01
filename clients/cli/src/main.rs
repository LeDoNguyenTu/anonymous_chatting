//! Pouch CLI client.
//!
//! A headless client over the same `pouch-core` API the desktop client uses
//! (D-018). It exists so the Phase 1 exit criterion — two clients exchanging
//! text reliably — is verifiable by automation rather than by hand only, and so
//! the system can be demonstrated over SSH.
//!
//! It is not a privileged back door into the core. Every operation below is a
//! call into `pouch_core::Pouch`; nothing reaches past it. If this client ever
//! needs something the desktop client cannot get, that is a signal about the
//! API, not a licence to bypass it.
//!
//! The database key here comes from an environment variable. That is
//! **development-grade only** and is stated as such in the help text — the real
//! clients take it from the OS keystore or derive it from a passphrase with
//! Argon2id (D-007). Phase 2 adds the passphrase path.

use anyhow::{bail, Context, Result};
use pouch_core::transport::RelayConfig;
use pouch_core::Pouch;

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

fn db_path() -> String {
    std::env::var("POUCH_DB").unwrap_or_else(|_| "pouch.db".to_string())
}

fn relay() -> RelayConfig {
    let url = std::env::var("POUCH_RELAY").unwrap_or_else(|_| "http://127.0.0.1:8443".to_string());
    match std::env::var("POUCH_RELAY_PIN") {
        Ok(pin) if !pin.is_empty() => RelayConfig::pinned(url, pin),
        _ => RelayConfig::insecure_local(url),
    }
}

/// Reads the database key.
///
/// Returned as an owned buffer because `Pouch` zeroizes it in place.
fn db_key() -> Result<Vec<u8>> {
    let hex_key =
        std::env::var("POUCH_KEY").context("POUCH_KEY is not set; it must be 64 hex characters")?;
    let key = hex::decode(hex_key.trim()).context("POUCH_KEY must be valid hex")?;
    if key.len() != 32 {
        bail!(
            "POUCH_KEY must be 64 hex characters (32 bytes), not {}",
            key.len() * 2
        );
    }
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        print!("{USAGE}");
        return Ok(());
    };

    match command {
        "create" => {
            let name = args
                .get(1)
                .context("usage: pouch-cli create <display-name>")?;
            let mut key = db_key()?;
            let pouch = Pouch::create(name, &db_path(), &mut key, relay())?;
            println!("identity created for {}", pouch.display_name());
            println!("inbox {}", pouch.inbox_id());
            println!();
            println!("Your account lives on this device. Nothing about you is sent to a server.");
        }

        "invite" => {
            let mut key = db_key()?;
            let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;
            println!("{}", pouch.invite_code()?);
            println!();
            println!(
                "This code holds your public key and inbox address. \
                 It contains no personal information."
            );
        }

        "add" => {
            let name = args
                .get(1)
                .context("usage: pouch-cli add <name> <invite-code>")?;
            let code = args
                .get(2)
                .context("usage: pouch-cli add <name> <invite-code>")?;
            let mut key = db_key()?;
            let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;
            let conversation = pouch.add_contact(name, code).await?;
            println!("conversation {conversation}");
            println!();
            println!(
                "{name} is UNVERIFIED. Compare safety numbers before you rely on this \
                 conversation: pouch-cli safety <contact>"
            );
        }

        "send" => {
            let conversation = args
                .get(1)
                .context("usage: pouch-cli send <conversation> <text>")?;
            let text = args
                .get(2)
                .context("usage: pouch-cli send <conversation> <text>")?;
            let mut key = db_key()?;
            let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;

            let manifest = pouch.send_message(conversation, text).await?;

            println!("{}", manifest.summary());
            println!();
            println!("MESSAGE MANIFEST");
            for line in manifest.lines() {
                println!("  {line}");
            }
        }

        "receive" => {
            let mut key = db_key()?;
            let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;
            let received = pouch.receive_messages().await?;
            if received.is_empty() {
                println!("nothing waiting");
            }
            for conversation in &received.conversations_opened {
                println!("conversation opened: {conversation}");
                println!("  The other person is UNVERIFIED. Compare safety numbers before");
                println!("  you rely on this conversation.");
            }
            for message in &received.messages {
                println!("{}", message.body);
            }
        }

        "list" => {
            let mut key = db_key()?;
            let pouch = Pouch::open(&db_path(), &mut key, relay())?;
            let conversations = pouch.conversations()?;
            if conversations.is_empty() {
                println!("No conversations yet. Add someone using their invite code.");
            }
            for c in conversations {
                println!(
                    "{}  {:<20} {}",
                    c.identity.label(),
                    c.contact_name,
                    c.last_message.unwrap_or_default()
                );
                println!("  contact {}", c.contact_id);
            }
        }

        "read" => {
            let conversation = args
                .get(1)
                .context("usage: pouch-cli read <conversation>")?;
            let mut key = db_key()?;
            let pouch = Pouch::open(&db_path(), &mut key, relay())?;
            for message in pouch.messages(conversation)? {
                let who = if message.outgoing { "you" } else { "them" };
                println!("{who:>5}  {}", message.body);
            }
        }

        "safety" => {
            let contact = args.get(1).context("usage: pouch-cli safety <contact>")?;
            let mut key = db_key()?;
            let pouch = Pouch::open(&db_path(), &mut key, relay())?;
            let number = pouch.safety_number(contact)?;
            println!("{}", number.grouped());
            println!();
            println!(
                "Compare this number with your contact in person or over a call you trust. \
                 If it matches, mark them verified."
            );
        }

        "verify" => {
            let contact = args.get(1).context("usage: pouch-cli verify <contact>")?;
            let mut key = db_key()?;
            let pouch = Pouch::open(&db_path(), &mut key, relay())?;
            pouch.verify_contact(contact, true)?;
            println!("Verified.");
        }

        "security" => {
            let mut key = db_key()?;
            let pouch = Pouch::open(&db_path(), &mut key, relay())?;
            let d = pouch.security_details();
            println!("Nothing here is secret. The security of this app rests on your keys,"); // guardrail-allow: prose, not a secret
            println!("not on hiding how it works.");
            println!();
            println!("  protocol            {}", d.protocol);
            println!("  ciphersuite         {}", d.ciphersuite);
            println!("  AEAD                {}", d.aead);
            println!("  key agreement       {}", d.key_agreement);
            println!("  signature           {}", d.signature);
            println!("  KDF                 {}  (a hash, not encryption)", d.kdf);
            println!("  local database      {}", d.local_database);
            println!("  passphrase to key   {}", d.passphrase_derivation); // guardrail-allow: the KDF's name, never a passphrase
            println!("  transport           {}", d.transport);
            println!("  relay               {}", d.relay_address);
            println!("  openmls             {}", d.openmls_version);
            println!("  version             {}", d.app_version);
            println!();
            println!("This app is unaudited student work.");
            println!("Do not rely on it if you face a serious adversary.");
        }

        "wipe" => {
            let confirm = args.get(1).map(String::as_str).unwrap_or("");
            if confirm != "wipe" {
                bail!("this destroys every message, contact, and key on this device and cannot be undone.\nrun: pouch-cli wipe wipe");
            }
            let mut key = db_key()?;
            let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;
            pouch.wipe_all()?;
            println!("All local data destroyed.");
        }

        other => {
            print!("{USAGE}");
            bail!("unknown command: {other}");
        }
    }

    Ok(())
}
