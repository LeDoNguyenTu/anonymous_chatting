//! Encrypted backup export and import (SPEC §7.3).

use anyhow::{bail, Context, Result};
use pouch_core::Pouch;

use crate::config::{db_key, db_path, relay};

/// `pouch-cli backup export <path>`
pub fn export(args: &[String]) -> Result<()> {
    let Some(path) = args.get(2) else {
        bail!("usage: pouch-cli backup export <path>");
    };

    let mut key = db_key()?;
    let pouch = Pouch::open(&db_path(), &mut key, relay())?;

    let recovery_key = pouch_core::new_recovery_key();
    let backup = pouch.export_backup(&recovery_key)?;
    std::fs::write(path, &backup).with_context(|| format!("writing {path}"))?;

    println!("Backup written to {path}.");
    println!();
    println!("This key is the only way to open this backup:");
    println!();
    println!("  {}", hex::encode(&recovery_key));
    println!();
    println!("It is not stored anywhere — not in the backup file, not by this");
    println!("program. If you lose it, this backup cannot be opened by anyone,");
    println!("including you.");
    Ok(())
}

/// `pouch-cli backup import <path>`
///
/// Restores onto whatever `POUCH_DB` currently names. That path must not
/// already hold an identity — the same precondition `create` has — because
/// this replaces a device's whole identity, not merges into one.
pub async fn import(args: &[String]) -> Result<()> {
    let Some(path) = args.get(2) else {
        bail!("usage: pouch-cli backup import <path>");
    };
    let recovery_hex = std::env::var("POUCH_RECOVERY_KEY")
        .context("set POUCH_RECOVERY_KEY to the recovery key printed at export time")?;
    let recovery_key =
        hex::decode(recovery_hex.trim()).context("POUCH_RECOVERY_KEY must be valid hex")?;

    let backup = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let mut key = db_key()?;

    let pouch = Pouch::import_backup(&db_path(), &mut key, &recovery_key, &backup, relay())
        .await
        .context("could not restore this backup")?;

    println!("Restored: {}.", pouch.display_name());
    let conversations = pouch.conversations()?;
    println!(
        "{} conversation{} restored.",
        conversations.len(),
        if conversations.len() == 1 { "" } else { "s" }
    );
    Ok(())
}
