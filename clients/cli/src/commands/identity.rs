//! Creating an identity, and publishing an invite code.
//!
//! The two operations that exist before there is anyone to talk to.

use anyhow::{Context, Result};
use pouch_core::Pouch;

use crate::config::{db_key, db_path, relay};

/// `pouch-cli create <display-name>`
pub fn create(args: &[String]) -> Result<()> {
    let name = args
        .get(1)
        .context("usage: pouch-cli create <display-name>")?;
    let mut key = db_key()?;
    let pouch = Pouch::create(name, &db_path(), &mut key, relay())?;
    println!("identity created for {}", pouch.display_name());
    println!("inbox {}", pouch.inbox_id());
    println!();
    println!("Your account lives on this device. Nothing about you is sent to a server.");
    Ok(())
}

/// `pouch-cli invite`
pub fn invite(_args: &[String]) -> Result<()> {
    let mut key = db_key()?;
    let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;
    println!("{}", pouch.invite_code()?);
    println!();
    println!(
        "This code holds your public key and inbox address. \
         It contains no personal information."
    );
    Ok(())
}
