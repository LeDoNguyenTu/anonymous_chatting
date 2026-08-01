//! Where the local database key comes from.
//!
//! One module, because there should be exactly one answer to "how does a key
//! reach this process" and it should be possible to find it.
//!
//! **Nothing here is a finished security control.** SPEC §7.2 requires the
//! database key to come from the OS keystore — Keychain on macOS, DPAPI on
//! Windows, Secret Service on Linux, Keystore on Android — or to be derived
//! from a user passphrase with Argon2id when the user opts in. Neither is
//! implemented. What is here is a development placeholder, named so that no
//! call site can use it without saying so.

use std::io::Write;
use std::path::Path;

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

/// Length of a SQLCipher key, in bytes.
pub const KEY_BYTES: usize = 32;

/// Things that can go wrong obtaining a key.
#[derive(Debug, thiserror::Error)]
pub enum KeyingError {
    /// The key file could not be read or written.
    #[error("could not read or create the device key file")]
    Io(#[from] std::io::Error),
    /// The key file exists but does not hold a key.
    #[error("the device key file is not a valid key")]
    Malformed,
}

/// Reads, or creates, a random device key stored beside the database.
///
/// # This protects against nothing
///
/// The key sits in a file next to the database it unlocks. Anyone who can read
/// the database can read the key, so an attacker with the disk has both. It
/// exists so the encrypted-storage path can be exercised end to end before the
/// keystore integration lands — SQLCipher is genuinely encrypting, and the
/// wrong key genuinely fails, which is what the rest of the system is written
/// against.
///
/// Replacing this is Phase 2 work and it is the only thing that needs to
/// change: every caller obtains its key here.
///
/// The returned buffer is owned by the caller and is zeroized in place by
/// `LocalStore::open`.
pub fn development_device_key(path: &Path) -> Result<Vec<u8>, KeyingError> {
    if path.exists() {
        let raw = std::fs::read(path)?;
        if raw.len() != KEY_BYTES {
            return Err(KeyingError::Malformed);
        }
        return Ok(raw);
    }

    let mut key = vec![0u8; KEY_BYTES];
    OsRng.fill_bytes(&mut key);

    // Written before it is handed out, so a crash between generating and
    // storing cannot leave a database encrypted under a key that exists
    // nowhere — which would be indistinguishable from data loss.
    write_private(path, &key)?;

    Ok(key)
}

/// Writes a file readable only by its owner, where the platform supports it.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), KeyingError> {
    let mut file = std::fs::File::create(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0600. Not a real defence — see the module docs — but a file holding
        // key material should not be world-readable even in a placeholder.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Derives a database key from a passphrase with Argon2id.
///
/// This is the path SPEC §7.2 wants for users who opt in to a passphrase. The
/// parameters are pinned here rather than taken from a caller, so every
/// database in the wild is derived the same way and a future change to them is
/// a visible, reviewable edit.
///
/// The salt must be stored alongside the database and is not secret.
pub fn key_from_passphrase(
    passphrase: &str,
    salt: &[u8],
) -> Result<Vec<u8>, argon2::password_hash::Error> {
    use argon2::{Algorithm, Argon2, Params, Version};

    // 64 MiB, 3 passes, 1 lane. Argon2's own recommendation for the
    // memory-constrained side of interactive use, and comfortably above the
    // point where GPU cracking stops being cheap.
    let params = Params::new(64 * 1024, 3, 1, Some(KEY_BYTES)).map_err(|_| {
        argon2::password_hash::Error::ParamValueInvalid(
            argon2::password_hash::errors::InvalidValue::InvalidFormat,
        )
    })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; KEY_BYTES];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| argon2::password_hash::Error::Crypto)?;

    Ok(key)
}

/// A fresh random salt for [`key_from_passphrase`].
pub fn new_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Zeroizes a key buffer. A convenience so call sites do not import `zeroize`
/// just to clean up after themselves.
pub fn erase(key: &mut [u8]) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_key_is_created_once_and_then_reused() {
        // If it changed between runs, every existing database would become
        // unopenable — which looks exactly like corruption.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("device.key");

        let first = development_device_key(&path).expect("creates");
        let second = development_device_key(&path).expect("reuses");

        assert_eq!(first.len(), KEY_BYTES);
        assert_eq!(first, second, "the device key changed between reads");
    }

    #[test]
    fn device_keys_differ_between_devices() {
        let a = tempfile::tempdir().expect("temp dir");
        let b = tempfile::tempdir().expect("temp dir");

        let ka = development_device_key(&a.path().join("device.key")).expect("a");
        let kb = development_device_key(&b.path().join("device.key")).expect("b");

        assert_ne!(ka, kb, "two devices produced the same key");
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("device.key");
        development_device_key(&path).expect("creates");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "the key file is readable by other users");
    }

    #[test]
    fn a_truncated_key_file_is_a_named_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("device.key");
        std::fs::write(&path, b"too short").expect("write");

        assert!(matches!(
            development_device_key(&path),
            Err(KeyingError::Malformed)
        ));
    }

    #[test]
    fn argon2id_derivation_is_deterministic() {
        // The user must get the same key from the same passphrase, or their
        // database stops opening.
        let salt = b"0123456789abcdef";
        let a = key_from_passphrase("correct horse battery staple", salt).expect("derives");
        let b = key_from_passphrase("correct horse battery staple", salt).expect("derives");

        assert_eq!(a, b);
        assert_eq!(a.len(), KEY_BYTES);
    }

    #[test]
    fn a_different_passphrase_gives_a_different_key() {
        let salt = b"0123456789abcdef";
        let a = key_from_passphrase("correct horse battery staple", salt).expect("derives");
        let b = key_from_passphrase("correct horse battery stapler", salt).expect("derives");
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_salt_gives_a_different_key() {
        // Without this, two users with the same passphrase would share a key.
        let a = key_from_passphrase("same passphrase", b"0123456789abcdef").expect("derives");
        let b = key_from_passphrase("same passphrase", b"fedcba9876543210").expect("derives");
        assert_ne!(a, b);
    }

    #[test]
    fn salts_are_unpredictable() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            assert!(seen.insert(new_salt()), "a salt repeated");
        }
    }

    #[test]
    fn erase_clears_the_buffer() {
        let mut key = vec![0xAB; KEY_BYTES];
        erase(&mut key);
        assert!(key.iter().all(|b| *b == 0));
    }
}
