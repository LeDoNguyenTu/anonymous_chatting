//! Adding a contact, and verifying who they are.

use anyhow::{Context, Result};
use pouch_core::Pouch;

use crate::config::{db_key, db_path, open_for_relay, relay};

/// `pouch-cli add <name> <invite-code>`
pub async fn add(args: &[String]) -> Result<()> {
    let name = args
        .get(1)
        .context("usage: pouch-cli add <name> <invite-code>")?;
    let code = args
        .get(2)
        .context("usage: pouch-cli add <name> <invite-code>")?;
    let mut pouch = open_for_relay().await?;
    let conversation = pouch.add_contact(name, code).await?;
    println!("conversation {conversation}");
    println!();
    println!(
        "{name} is UNVERIFIED. Compare safety numbers before you rely on this \
         conversation: pouch-cli safety <contact>"
    );
    Ok(())
}

/// `pouch-cli safety <contact>`
pub fn safety(args: &[String]) -> Result<()> {
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
    Ok(())
}

/// `pouch-cli verify <contact>`
pub fn verify(args: &[String]) -> Result<()> {
    let contact = args.get(1).context("usage: pouch-cli verify <contact>")?;
    let mut key = db_key()?;
    let pouch = Pouch::open(&db_path(), &mut key, relay())?;
    pouch.verify_contact(contact, true)?;
    println!("Verified.");
    Ok(())
}
