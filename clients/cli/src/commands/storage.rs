//! The storage controls: what is kept, for how long, and what protects it.
//!
//! SPEC §6.7.7 names these by what the user controls rather than by how they
//! work — "keep messages", not "retention TTL policy" — and every one of them
//! reports what it actually did. A control that says nothing after deleting
//! forty messages is a control the user cannot trust.

use anyhow::{bail, Result};
use pouch_core::{Pouch, RetentionPolicy};

use crate::config::{db_key, db_path, passphrase, relay};

/// Parses the retention argument.
fn policy(word: &str) -> Result<RetentionPolicy> {
    Ok(match word {
        "forever" => RetentionPolicy::Forever,
        "30d" => RetentionPolicy::Days30,
        "7d" => RetentionPolicy::Days7,
        "24h" => RetentionPolicy::Hours24,
        other => bail!("keep takes forever, 30d, 7d, or 24h — not {other}"),
    })
}

/// `pouch-cli keep [forever|30d|7d|24h]`
pub fn keep(args: &[String]) -> Result<()> {
    let mut key = db_key()?;
    let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;

    let Some(word) = args.get(1) else {
        println!("Messages are kept {}.", pouch.retention_policy()?.label());
        println!();
        println!("  pouch-cli keep forever    keep everything until you delete it");
        println!("  pouch-cli keep 30d        keep 30 days");
        println!("  pouch-cli keep 7d         keep 7 days");
        println!("  pouch-cli keep 24h        keep 24 hours");
        return Ok(());
    };

    let policy = policy(word)?;
    let deleted = pouch.set_retention_policy(policy)?;

    println!("Messages are kept {}.", policy.label());
    match deleted {
        0 => println!("Nothing was old enough to delete."),
        1 => println!("1 message was older than that and has been deleted."),
        n => println!("{n} messages were older than that and have been deleted."),
    }
    Ok(())
}

/// `pouch-cli disappear <conversation> [seconds|off]`
pub fn disappear(args: &[String]) -> Result<()> {
    let Some(conversation) = args.get(1) else {
        bail!("usage: pouch-cli disappear <conversation> [seconds|off]");
    };

    let mut key = db_key()?;
    let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;

    let Some(setting) = args.get(2) else {
        match pouch.disappearing_messages(conversation)? {
            Some(seconds) => println!("Messages in this conversation disappear after {seconds}s."),
            None => println!(
                "This conversation follows the device setting: messages are kept {}.",
                pouch.retention_policy()?.label()
            ),
        }
        return Ok(());
    };

    let seconds = match setting.as_str() {
        "off" => None,
        other => Some(
            other
                .parse::<u64>()
                .map_err(|_| anyhow::anyhow!("disappear takes a number of seconds, or off"))?,
        ),
    };

    let deleted = pouch.set_disappearing_messages(conversation, seconds)?;
    match seconds {
        Some(s) => println!("Messages in this conversation now disappear after {s}s."),
        None => println!(
            "This conversation now follows the device setting: messages are kept {}.",
            pouch.retention_policy()?.label()
        ),
    }
    if deleted > 0 {
        println!("{deleted} already older than that have been deleted.");
    }
    Ok(())
}

/// `pouch-cli queue`
pub fn queue(_args: &[String]) -> Result<()> {
    let mut key = db_key()?;
    let pouch = Pouch::open(&db_path(), &mut key, relay())?;

    match pouch.queued_count()? {
        0 => println!("Nothing is waiting to send."),
        1 => println!("1 message is waiting. It will send when you reconnect."),
        n => println!("{n} messages are waiting. They will send when you reconnect."),
    }
    Ok(())
}

/// `pouch-cli changes`
pub fn changes(_args: &[String]) -> Result<()> {
    let mut key = db_key()?;
    let pouch = Pouch::open(&db_path(), &mut key, relay())?;

    let changes = pouch.identity_changes()?;
    if changes.is_empty() {
        println!("No contact's identity key has changed.");
        return Ok(());
    }

    for change in changes {
        // The two readings, stated without accusing (SPEC §6.7.6).
        println!("{}'s identity key changed.", change.contact_name);
        println!("  contact {}", change.contact_id);
        println!();
        println!("  This usually means they reinstalled the app or switched devices.");
        println!("  It can also mean someone is intercepting your messages.");
        println!("  Compare the new safety number before you rely on this conversation:");
        println!("    pouch-cli safety {}", change.contact_id);
        println!("    pouch-cli acknowledge {}", change.contact_id);
        println!();
    }
    Ok(())
}

/// `pouch-cli acknowledge <contact>`
pub fn acknowledge(args: &[String]) -> Result<()> {
    let Some(contact) = args.get(1) else {
        bail!("usage: pouch-cli acknowledge <contact>");
    };

    let mut key = db_key()?;
    let pouch = Pouch::open(&db_path(), &mut key, relay())?;
    pouch.acknowledge_identity_change(contact)?;

    // Says exactly what it did and did not do.
    println!("Noted. This contact stays unverified until you compare a safety number.");
    Ok(())
}

/// `pouch-cli passphrase [off]`
pub fn passphrase_command(args: &[String]) -> Result<()> {
    let mut key = db_key()?;
    let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;

    match args.get(1).map(String::as_str) {
        None => {
            if pouch.is_passphrase_protected()? {
                println!("This device is protected by a passphrase."); // guardrail-allow: prose, not a secret
                println!("Opening it requires POUCH_PASSPHRASE."); // guardrail-allow: the variable's name, never its value
            } else {
                println!("This device is not protected by a passphrase."); // guardrail-allow: prose, not a secret
                println!();
                println!("The database key is in a file next to the database, so anyone"); // guardrail-allow: prose
                println!("who can read the database can read the key. A passphrase"); // guardrail-allow: prose
                println!("replaces it with something only you know."); // guardrail-allow: prose
                println!();
                println!("  POUCH_PASSPHRASE='...' pouch-cli passphrase set"); // guardrail-allow: a literal '...', never a real value
            }
            Ok(())
        }
        Some("set") => {
            let Some(new) = passphrase() else {
                bail!("set POUCH_PASSPHRASE to the passphrase you want to use");
            };
            if new.trim().is_empty() {
                bail!("an empty passphrase protects nothing");
            }
            pouch.set_passphrase(&new)?;
            println!("This device now requires a passphrase."); // guardrail-allow: prose, not a secret
            println!();
            println!("The database has been re-encrypted and the old key file deleted."); // guardrail-allow: prose
            println!("There is no recovery. If you forget it, this history is gone."); // guardrail-allow: prose
            Ok(())
        }
        Some("off") => {
            if !pouch.is_passphrase_protected()? {
                println!("This device is not protected by a passphrase."); // guardrail-allow: prose, not a secret
                return Ok(());
            }
            pouch.clear_passphrase()?;
            println!("Passphrase protection removed.");
            println!();
            println!("The key is now in a file next to the database. Anyone who can read");
            println!("the database can read the key. This is weaker than what you had.");
            Ok(())
        }
        Some(other) => bail!("passphrase takes set or off — not {other}"),
    }
}
