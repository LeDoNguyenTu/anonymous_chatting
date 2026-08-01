//! Sending, collecting, and reading messages.

use anyhow::{Context, Result};
use pouch_core::Pouch;

use crate::config::{db_key, db_path, relay};

/// `pouch-cli send <conversation> <text>`
pub async fn send(args: &[String]) -> Result<()> {
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
    Ok(())
}

/// `pouch-cli receive`
pub async fn receive(_args: &[String]) -> Result<()> {
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
        if message.body.starts_with("[attachment]") {
            println!(
                "  id: {}  (pouch-cli save-attachment {} <path>)",
                message.id, message.id
            );
        }
    }
    Ok(())
}

/// `pouch-cli list`
pub fn list(_args: &[String]) -> Result<()> {
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
    Ok(())
}

/// `pouch-cli read <conversation>`
pub fn read(args: &[String]) -> Result<()> {
    let conversation = args
        .get(1)
        .context("usage: pouch-cli read <conversation>")?;
    let mut key = db_key()?;
    let pouch = Pouch::open(&db_path(), &mut key, relay())?;
    for message in pouch.messages(conversation)? {
        let who = if message.outgoing { "you" } else { "them" };
        println!("{who:>5}  {}", message.body);
        if message.body.starts_with("[attachment]") {
            println!(
                "       id: {}  (pouch-cli save-attachment {} <path>)",
                message.id, message.id
            );
        }
    }
    Ok(())
}
