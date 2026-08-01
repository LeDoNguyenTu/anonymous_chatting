//! Where the local database key comes from.
//!
//! One module, because there should be exactly one answer to "how does a key
//! reach this process" and it should be possible to find it.
//!
//! Two of the three routes SPEC §7.2 describes are implemented:
//!
//! - **Passphrase**, via Argon2id with pinned parameters. The key exists only
//!   while the application is running. Nothing on disk can be turned into it.
//! - **Device file**, the development placeholder. It protects against nothing
//!   — the key sits beside the database it unlocks — and is named so that no
//!   call site can use it without saying so.
//!
//! The third, the OS keystore (Keychain, DPAPI, Secret Service, Android
//! Keystore), is not implemented. It needs a platform dependency that touches
//! key storage directly, which is a stop-and-ask under SPEC §2.6 rather than
//! something to pick while passing.
//!
//! Which route a database uses is recorded in a small sidecar file, because the
//! answer has to be known *before* the encrypted database can be opened.

use std::io::Write;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

/// Length of a SQLCipher key, in bytes.
pub const KEY_BYTES: usize = 32;

/// Length of an Argon2id salt, in bytes.
const SALT_BYTES: usize = 16;

/// Things that can go wrong obtaining a key.
#[derive(Debug, thiserror::Error)]
pub enum KeyingError {
    /// The key file could not be read or written.
    #[error("could not read or create the device key file")]
    Io(#[from] std::io::Error),
    /// The key file exists but does not hold a key.
    #[error("the device key file is not a valid key")]
    Malformed,
    /// The passphrase could not be turned into a key.
    #[error("the passphrase could not be used to derive a key")]
    Derivation,
    /// A passphrase was required and none was supplied.
    #[error("this device is passphrase-protected — a passphrase is required to open it")]
    PassphraseRequired,
}

/// How a given database is unlocked.
///
/// Recorded beside the database rather than inside it, because it has to be
/// readable before the database can be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// A random key in a file next to the database. Protects against nothing.
    DeviceFile,
    /// Argon2id over a passphrase the user supplies each time, with this salt.
    Passphrase {
        /// The Argon2id salt. Not secret, and useless on its own.
        salt: Vec<u8>,
    },
}

impl KeySource {
    /// Whether opening this database requires the user to type something.
    pub fn needs_passphrase(&self) -> bool {
        matches!(self, KeySource::Passphrase { .. })
    }
}

/// The sidecar path for a database path.
///
/// A plain suffix rather than a hidden file: a user who moves their database
/// should be able to see that this belongs with it.
pub fn sidecar_path(db_path: &str) -> PathBuf {
    PathBuf::from(format!("{db_path}.keying"))
}

/// Reads how a database is unlocked.
///
/// A missing sidecar means the device-file placeholder, which is what every
/// Phase 1 database used. Treating "absent" as "passphrase" would lock people
/// out of their own history on upgrade.
pub fn key_source(db_path: &str) -> Result<KeySource, KeyingError> {
    let path = sidecar_path(db_path);
    if !path.exists() {
        return Ok(KeySource::DeviceFile);
    }

    let raw = std::fs::read(&path)?;
    match raw.split_first() {
        // Version byte 1, device file, and nothing after it.
        Some((1, [])) => Ok(KeySource::DeviceFile),
        // Version byte 2, passphrase, followed by the salt.
        Some((2, salt)) if salt.len() == SALT_BYTES => Ok(KeySource::Passphrase {
            salt: salt.to_vec(),
        }),
        _ => Err(KeyingError::Malformed),
    }
}

/// Records how a database is unlocked.
pub fn set_key_source(db_path: &str, source: &KeySource) -> Result<(), KeyingError> {
    let mut bytes = Vec::with_capacity(1 + SALT_BYTES);
    match source {
        KeySource::DeviceFile => bytes.push(1),
        KeySource::Passphrase { salt } => {
            bytes.push(2);
            bytes.extend_from_slice(salt);
        }
    }
    write_private(&sidecar_path(db_path), &bytes)
}

/// The conventional device-key path for a database path.
pub fn device_key_path(db_path: &str) -> PathBuf {
    PathBuf::from(format!("{db_path}.key"))
}

/// Obtains the key for a database, whichever way it is protected.
///
/// The one call a client should need. `passphrase` is ignored for a
/// device-file database and required for a passphrase-protected one — supplying
/// none for the latter is an error rather than a silent fall back to the
/// placeholder, which would turn "protected" into "not" without saying so.
pub fn unlock(db_path: &str, passphrase: Option<&str>) -> Result<Vec<u8>, KeyingError> {
    match key_source(db_path)? {
        KeySource::DeviceFile => development_device_key(&device_key_path(db_path)),
        KeySource::Passphrase { salt } => {
            let passphrase = passphrase.ok_or(KeyingError::PassphraseRequired)?;
            key_from_passphrase(passphrase, &salt).map_err(|_| KeyingError::Derivation)
        }
    }
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

    fn db(dir: &tempfile::TempDir) -> String {
        dir.path().join("pouch.db").to_string_lossy().into_owned()
    }

    #[test]
    fn a_database_with_no_sidecar_uses_the_device_file() {
        // Every Phase 1 database is in this state. Reading "absent" as
        // "passphrase" would lock people out of their own history on upgrade.
        let dir = tempfile::tempdir().expect("temp dir");
        assert_eq!(key_source(&db(&dir)).expect("reads"), KeySource::DeviceFile);
    }

    #[test]
    fn a_key_source_round_trips() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = db(&dir);

        let salt = new_salt();
        set_key_source(&path, &KeySource::Passphrase { salt: salt.clone() }).expect("writes");

        match key_source(&path).expect("reads") {
            KeySource::Passphrase { salt: back } => assert_eq!(back, salt),
            other => panic!("expected a passphrase source, got {other:?}"),
        }

        set_key_source(&path, &KeySource::DeviceFile).expect("writes");
        assert_eq!(key_source(&path).expect("reads"), KeySource::DeviceFile);
    }

    #[test]
    fn a_corrupt_sidecar_is_a_named_error_not_a_silent_downgrade() {
        // Falling back to the device file here would turn "protected" into
        // "not" without telling anyone.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = db(&dir);
        std::fs::write(sidecar_path(&path), b"\x02short").expect("writes");

        assert!(matches!(key_source(&path), Err(KeyingError::Malformed)));
    }

    #[test]
    fn unlocking_a_protected_database_without_a_passphrase_is_refused() {
        // The important one. A missing passphrase must not fall back to the
        // placeholder key, because that would open a database the user
        // believes is protected.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = db(&dir);
        set_key_source(&path, &KeySource::Passphrase { salt: new_salt() }).expect("writes");

        assert!(matches!(
            unlock(&path, None),
            Err(KeyingError::PassphraseRequired)
        ));
    }

    #[test]
    fn unlocking_yields_the_same_key_each_time() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = db(&dir);
        set_key_source(&path, &KeySource::Passphrase { salt: new_salt() }).expect("writes");

        let a = unlock(&path, Some("correct horse battery staple")).expect("unlocks");
        let b = unlock(&path, Some("correct horse battery staple")).expect("unlocks");
        assert_eq!(a, b);
        assert_eq!(a.len(), KEY_BYTES);

        let c = unlock(&path, Some("wrong passphrase")).expect("derives");
        assert_ne!(a, c);
    }

    #[test]
    fn the_sidecar_holds_no_key_material() {
        // It holds a salt, which is not secret. If a key ever appeared here the
        // passphrase would be pointless.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = db(&dir);
        let salt = new_salt();
        set_key_source(&path, &KeySource::Passphrase { salt: salt.clone() }).expect("writes");

        let key = key_from_passphrase("a passphrase", &salt).expect("derives");
        let raw = std::fs::read(sidecar_path(&path)).expect("reads");
        assert!(
            !raw.windows(KEY_BYTES).any(|w| w == key.as_slice()),
            "the derived key is sitting in the sidecar"
        );
        assert_eq!(
            raw.len(),
            1 + SALT_BYTES,
            "the sidecar holds more than a salt"
        );
    }
}
