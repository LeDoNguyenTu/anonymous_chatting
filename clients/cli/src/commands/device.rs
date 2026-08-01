//! Operations on the device itself: what it uses, and destroying it.

use anyhow::{bail, Result};
use pouch_core::Pouch;

use crate::config::{db_key, db_path, relay};

/// `pouch-cli security`
pub fn security(_args: &[String]) -> Result<()> {
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
    Ok(())
}

/// `pouch-cli wipe`
pub fn wipe(args: &[String]) -> Result<()> {
    let confirm = args.get(1).map(String::as_str).unwrap_or("");
    if confirm != "wipe" {
        bail!("this destroys every message, contact, and key on this device and cannot be undone.\nrun: pouch-cli wipe wipe");
    }
    let mut key = db_key()?;
    let mut pouch = Pouch::open(&db_path(), &mut key, relay())?;
    pouch.wipe_all()?;
    println!("All local data destroyed.");
    Ok(())
}
