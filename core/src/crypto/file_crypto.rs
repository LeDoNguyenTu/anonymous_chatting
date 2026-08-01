//! AEAD for things that are not MLS group messages: right now, a backup.
//!
//! D-006 forbids application code from invoking an AEAD directly or picking a
//! nonce, for messages — because the key persists across many of them, and
//! hand-picking nonces under a long-lived key is how reuse happens. A backup
//! is not a message: this module's whole contract is a fresh, single-use key
//! per call, so there is no second encryption under the same key for a nonce
//! to collide with. D-037 is the decision that authorizes this file to exist
//! and states the reasoning in full; nothing here should be used outside the
//! shape it describes.
//!
//! No new dependency. `AeadType::Aes128Gcm` and the HKDF functions are both
//! already implemented by `openmls_rust_crypto`, the same audited backend
//! `PouchProvider` already wraps for MLS.

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{AeadType, HashType};
use openmls_traits::OpenMlsProvider;
use rand::rngs::OsRng;
use rand::RngCore;

use super::{provider::PouchProvider, CryptoError};

/// AES-128-GCM key length.
pub const KEY_BYTES: usize = 16;
/// GCM's standard nonce length.
pub const NONCE_BYTES: usize = 12;

/// A fresh random key, sized for [`encrypt`]. Callers must use it once.
pub fn random_key() -> Vec<u8> {
    let mut key = vec![0u8; KEY_BYTES];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypts one payload under a key that must never be used again.
///
/// Returns `(nonce, ciphertext)`. The nonce is not secret and travels
/// alongside the ciphertext; what makes this safe despite being a randomly
/// generated nonce rather than one MLS derived is that `key` is single-use —
/// see D-037.
pub fn encrypt(
    provider: &PouchProvider,
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut nonce = vec![0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = provider
        .crypto()
        .aead_encrypt(AeadType::Aes128Gcm, key, plaintext, &nonce, aad)
        .map_err(|_| CryptoError::Encryption)?;

    Ok((nonce, ciphertext))
}

/// Reverses [`encrypt`].
pub fn decrypt(
    provider: &PouchProvider,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    provider
        .crypto()
        .aead_decrypt(AeadType::Aes128Gcm, key, ciphertext, nonce, aad)
        .map_err(|_| CryptoError::Decryption)
}

/// Derives an AES-128 key from a high-entropy secret — a recovery key, never
/// a human-chosen passphrase — via HKDF-SHA256 (RFC 5869).
///
/// This is deliberately not Argon2id. Argon2id's memory-hardness exists to
/// slow down brute-forcing a *low*-entropy, human-chosen secret; the recovery
/// key this is fed is 128 bits of `OsRng` output, which is not guessable
/// regardless of how cheap the KDF is. Running it through Argon2id anyway
/// would cost real time on every export and import for no security this input
/// needs. `salt` is stored alongside the encrypted backup and is not secret;
/// `info` is a fixed domain-separation label, not a secret either.
pub fn derive_key(
    provider: &PouchProvider,
    recovery_key: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let prk = provider
        .crypto()
        .hkdf_extract(HashType::Sha2_256, salt, recovery_key)
        .map_err(|_| CryptoError::Encryption)?;
    let okm = provider
        .crypto()
        .hkdf_expand(HashType::Sha2_256, prk.as_slice(), info, KEY_BYTES)
        .map_err(|_| CryptoError::Encryption)?;
    Ok(okm.as_slice().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payload_round_trips() {
        let provider = PouchProvider::new();
        let key = random_key();
        let (nonce, ct) =
            encrypt(&provider, &key, b"backup contents", b"pouch-backup-v1").expect("encrypts");
        let pt = decrypt(&provider, &key, &nonce, &ct, b"pouch-backup-v1").expect("decrypts");
        assert_eq!(pt, b"backup contents");
    }

    #[test]
    fn the_wrong_key_fails_authentication_rather_than_producing_garbage() {
        let provider = PouchProvider::new();
        let key = random_key();
        let (nonce, ct) = encrypt(&provider, &key, b"secret", b"aad").expect("encrypts");

        let wrong = random_key();
        assert!(decrypt(&provider, &wrong, &nonce, &ct, b"aad").is_err());
    }

    #[test]
    fn mismatched_associated_data_is_rejected() {
        // AAD binds context to the ciphertext. A backup for one purpose must
        // not decrypt under the label for another.
        let provider = PouchProvider::new();
        let key = random_key();
        let (nonce, ct) = encrypt(&provider, &key, b"secret", b"backup-v1").expect("encrypts");
        assert!(decrypt(&provider, &key, &nonce, &ct, b"backup-v2").is_err());
    }

    #[test]
    fn two_encryptions_never_reuse_a_nonce() {
        // Not itself the safety argument — D-037's argument is that a
        // single-use key makes nonce reuse harmless even if it happened — but
        // a repeat here would mean OsRng is broken, which is worth knowing.
        let provider = PouchProvider::new();
        let key = random_key();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let (nonce, _) = encrypt(&provider, &key, b"x", b"").expect("encrypts");
            assert!(seen.insert(nonce), "a nonce repeated");
        }
    }

    #[test]
    fn key_derivation_is_deterministic_given_the_same_inputs() {
        let provider = PouchProvider::new();
        let recovery = random_key();
        let salt = b"0123456789abcdef";

        let a = derive_key(&provider, &recovery, salt, b"pouch-backup-v1").expect("derives");
        let b = derive_key(&provider, &recovery, salt, b"pouch-backup-v1").expect("derives");
        assert_eq!(a, b);
        assert_eq!(a.len(), KEY_BYTES);
    }

    #[test]
    fn a_different_salt_gives_a_different_derived_key() {
        // Without this, exporting two backups with the same recovery key
        // would encrypt them under the same AES key.
        let provider = PouchProvider::new();
        let recovery = random_key();

        let a = derive_key(&provider, &recovery, b"salt-one-......", b"info").expect("derives");
        let b = derive_key(&provider, &recovery, b"salt-two-......", b"info").expect("derives");
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_recovery_key_gives_a_different_derived_key() {
        let provider = PouchProvider::new();
        let salt = b"0123456789abcdef";

        let a = derive_key(&provider, &random_key(), salt, b"info").expect("derives");
        let b = derive_key(&provider, &random_key(), salt, b"info").expect("derives");
        assert_ne!(a, b);
    }
}
