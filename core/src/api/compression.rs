//! Per-message compression, applied before encryption (SPEC §6.5.2, D-009).
//!
//! Compression after encryption accomplishes nothing — ciphertext is
//! incompressible by construction — so it has to happen first if it happens at
//! all. Doing that safely means never sharing compression state across
//! messages: compressing attacker-influenced content together with secret
//! content in the same context enables a CRIME/BREACH-family side channel,
//! where an attacker varies their own input and reads the secret's length off
//! the output size.
//!
//! Both functions here are one-shot, dictionary-free calls into `zstd`. That
//! is what "isolation" means in practice — there is no compressor object that
//! outlives a single call, and therefore nothing for one message's bytes to
//! leave behind for the next message's compression to be measured against.
//! `compression_is_isolated_across_calls` below is the test that would fail if
//! a future change introduced shared state, e.g. a reused dictionary or a
//! long-lived encoder held across messages.

use thiserror::Error;

/// zstd's compression level.
///
/// 3 is the library's own default: enough ratio to be worth doing, without the
/// latency of the higher levels on a message a user is waiting to see sent.
const LEVEL: i32 = 3;

/// Compression failed, or the input claimed a size beyond what this build will
/// decompress.
#[derive(Debug, Error)]
pub enum CompressionError {
    /// The encoder or decoder returned an error.
    #[error("compression failed")]
    Failed,
}

/// Compresses one payload, independently of any other call.
pub fn compress(bytes: &[u8]) -> Result<Vec<u8>, CompressionError> {
    zstd::stream::encode_all(bytes, LEVEL).map_err(|_| CompressionError::Failed)
}

/// Reverses [`compress`].
pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>, CompressionError> {
    zstd::stream::decode_all(bytes).map_err(|_| CompressionError::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_round_trips() {
        let original = b"the meeting is at dawn, bring the documents";
        let compressed = compress(original).expect("compresses");
        assert_eq!(decompress(&compressed).expect("decompresses"), original);
    }

    #[test]
    fn compression_is_isolated_across_calls() {
        // SPEC §8.7. Two payloads, one standing in for a secret the user
        // typed, one standing in for content an attacker fully controls
        // (repetitive text compresses hard, which is what makes it a
        // plausible probe). If any state — a dictionary, a retained window —
        // survived from compressing the attacker's payload into compressing
        // the secret's, the secret's compressed size would move when the
        // attacker's content changes. It must not.
        let secret = b"the password for the safe is 4471 north gate";

        let attacker_a = vec![b'A'; 4096];
        let attacker_b = vec![b'B'; 4096]; // same length, different content

        let secret_size_before = compress(secret).expect("compresses").len();
        compress(&attacker_a).expect("compresses");
        let secret_size_after_a = compress(secret).expect("compresses").len();
        compress(&attacker_b).expect("compresses");
        let secret_size_after_b = compress(secret).expect("compresses").len();

        assert_eq!(
            secret_size_before, secret_size_after_a,
            "the secret's compressed size changed after compressing unrelated content"
        );
        assert_eq!(
            secret_size_before, secret_size_after_b,
            "the secret's compressed size changed after compressing different unrelated content"
        );
    }

    #[test]
    fn highly_repetitive_content_actually_compresses() {
        // Sanity check that this is really zstd doing real work, not a no-op
        // pass-through that would make the isolation test above vacuous.
        let repetitive = vec![b'x'; 10_000];
        let compressed = compress(&repetitive).expect("compresses");
        assert!(
            compressed.len() < repetitive.len() / 10,
            "10,000 repeated bytes did not compress well; got {} bytes",
            compressed.len()
        );
    }

    #[test]
    fn decompressing_garbage_is_a_named_error_not_a_panic() {
        assert!(decompress(b"not a zstd frame").is_err());
    }
}
