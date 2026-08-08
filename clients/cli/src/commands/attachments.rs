//! Sending and saving attachments (SPEC §7.1).

use anyhow::{bail, Context, Result};
use pouch_core::Pouch;

use crate::config::{db_key, db_path, open_for_relay, relay};

/// `pouch-cli send-file <conversation> <path>`
pub async fn send_file(args: &[String]) -> Result<()> {
    let conversation = args
        .get(1)
        .context("usage: pouch-cli send-file <conversation> <path>")?;
    let path = args
        .get(2)
        .context("usage: pouch-cli send-file <conversation> <path>")?;

    let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let filename = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.clone());

    let mut pouch = open_for_relay().await?;

    let manifest = pouch
        .send_attachment(conversation, &filename, &bytes)
        .await?;

    println!("{}", manifest.summary());
    println!();
    println!("ATTACHMENT MANIFEST");
    for line in manifest.lines() {
        println!("  {line}");
    }
    Ok(())
}

/// `pouch-cli save-attachment <message-id> <path>`
///
/// `<message-id>` is what `receive` and `read` print alongside an
/// attachment's placeholder body.
pub fn save_attachment(args: &[String]) -> Result<()> {
    let message_id = args
        .get(1)
        .context("usage: pouch-cli save-attachment <message-id> <path>")?;
    let dest = args
        .get(2)
        .context("usage: pouch-cli save-attachment <message-id> <path>")?;

    let mut key = db_key()?;
    let pouch = Pouch::open(&db_path(), &mut key, relay())?;

    let Some((filename, content)) = pouch.attachment(message_id)? else {
        bail!("no attachment is stored under that message id");
    };

    std::fs::write(dest, &content).with_context(|| format!("writing {dest}"))?;
    println!("Saved {filename} ({} bytes) to {dest}.", content.len());
    Ok(())
}
