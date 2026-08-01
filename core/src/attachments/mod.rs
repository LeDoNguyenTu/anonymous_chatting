//! The attachment pipeline (SPEC §7.1): strip, pad, encrypt.
//!
//! Order matters and is enforced by this module's one entry point rather
//! than left to the caller to get right: strip before pad (padding a file
//! that still carries EXIF pads a privacy leak, it does not remove one), pad
//! before encrypt (padding only hides size if it happens before the
//! ciphertext boundary). Key generation and the AEAD call are D-037's exact
//! shape — a fresh, single-use key per file, through the same audited
//! backend already in this crate.
//!
//! Images only — JPEG, PNG, WebP. Video is out of scope this phase; D-038
//! has the full reasoning.

pub mod metadata;
pub mod padding;

pub use metadata::{ImageFormat, StripReport};

use crate::crypto::{file_crypto, CryptoError, PouchProvider};

/// Domain separation for the AEAD's associated data — binds "this is an
/// attachment," distinct from the backup format's own AAD, even though the
/// two never share key material.
const CONTEXT: &[u8] = b"pouch-attachment-v1";

/// Things that can go wrong preparing or opening an attachment.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentError {
    /// Not a JPEG, PNG, or WebP by signature.
    #[error(
        "Pouch can only send JPEG, PNG, or WebP images right now — video attachments aren't \
         supported yet, because metadata stripping for video containers hasn't been verified safe"
    )]
    UnsupportedFormat,
    /// Recognised by signature but not readable as that format.
    #[error("this file could not be read as the image format it claims to be")]
    Malformed,
    /// The AEAD step failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// An attachment ready to upload: encrypted bytes, the key the recipient
/// needs, and what stripping actually found (for the preview manifest).
pub struct PreparedAttachment {
    /// Fresh, single-use — travels inside the E2EE message payload, never to
    /// the relay (SPEC §7.1 step 6).
    pub key: Vec<u8>,
    /// The AEAD nonce. Not secret; travels alongside the ciphertext.
    pub nonce: Vec<u8>,
    /// The encrypted, padded, stripped image — what actually gets uploaded.
    pub ciphertext: Vec<u8>,
    /// The stripped image, before padding — kept so the sender can store its
    /// own local copy without decrypting the blob it just uploaded.
    pub stripped: Vec<u8>,
    /// The detected container format.
    pub format: ImageFormat,
    /// What stripping found and removed, for the preview manifest.
    pub strip_report: StripReport,
    /// Size of the plaintext actually encrypted, after padding.
    pub padded_len: usize,
}

/// Runs the full pipeline: detect, strip, pad, generate a key, encrypt.
///
/// Refuses anything that is not JPEG, PNG, or WebP rather than sending it
/// with its metadata intact — SPEC §7.1's "flag if the chosen library does
/// not handle the container," exercised at the point a file is chosen
/// rather than silently skipped (D-038).
pub fn prepare(
    provider: &PouchProvider,
    bytes: &[u8],
) -> Result<PreparedAttachment, AttachmentError> {
    let format = metadata::detect(bytes).ok_or(AttachmentError::UnsupportedFormat)?;
    let (stripped, strip_report) = metadata::strip(bytes, format)?;

    let padded = padding::pad(&stripped);
    let padded_len = padded.len();

    let key = file_crypto::random_key();
    let (nonce, ciphertext) = file_crypto::encrypt(provider, &key, &padded, CONTEXT)?;

    Ok(PreparedAttachment {
        key,
        nonce,
        ciphertext,
        stripped,
        format,
        strip_report,
        padded_len,
    })
}

/// Reverses [`prepare`]: decrypts and unpads, returning the stripped image
/// bytes exactly as the sender's `strip` step produced them.
pub fn open(
    provider: &PouchProvider,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AttachmentError> {
    let padded = file_crypto::decrypt(provider, key, nonce, ciphertext, CONTEXT)?;
    padding::unpad(&padded).ok_or(AttachmentError::Malformed)
}

/// The version byte prefixed to whatever gets uploaded to a bucket. Not a
/// crypto parameter — a future incompatible change to the blob's own framing
/// bumps this so an old build reports "cannot read this" instead of
/// misreading it, the same reasoning `backup.rs`'s `FORMAT_VERSION` has.
const BLOB_FORMAT_VERSION: u8 = 1;

/// Wraps a nonce and ciphertext into the bytes actually uploaded to a relay
/// bucket (SPEC §7.1 step 5).
pub fn encode_blob(nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    out.push(BLOB_FORMAT_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

/// Reverses [`encode_blob`].
pub fn decode_blob(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AttachmentError> {
    let header_len = 1 + file_crypto::NONCE_BYTES;
    if bytes.len() < header_len || bytes[0] != BLOB_FORMAT_VERSION {
        return Err(AttachmentError::Malformed);
    }
    Ok((bytes[1..header_len].to_vec(), bytes[header_len..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_png() -> Vec<u8> {
        let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        push_chunk(&mut out, b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
        push_chunk(&mut out, b"tEXt", b"Author\0a photographer");
        push_chunk(&mut out, b"IDAT", &[0u8; 4]);
        push_chunk(&mut out, b"IEND", &[]);
        out
    }

    fn push_chunk(out: &mut Vec<u8>, kind: &[u8; 4], contents: &[u8]) {
        out.extend_from_slice(&(contents.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(contents);

        let mut crc_input = kind.to_vec();
        crc_input.extend_from_slice(contents);
        out.extend_from_slice(&crc32_ieee(&crc_input).to_be_bytes());
    }

    /// A standalone CRC-32 (IEEE 802.3), so this test fixture needs no new
    /// dependency. This is checksum arithmetic for building a well-formed
    /// test PNG, not EXIF parsing — unrelated to the "do not hand-parse
    /// EXIF" rule the production code in `metadata.rs` follows.
    fn crc32_ieee(bytes: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &b in bytes {
            crc ^= b as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    #[test]
    fn an_attachment_round_trips_and_the_stripped_metadata_stays_gone() {
        let provider = PouchProvider::new();
        let original = tiny_png();

        let prepared = prepare(&provider, &original).expect("prepares");
        assert!(prepared.strip_report.other_metadata_removed);
        assert_eq!(prepared.format, ImageFormat::Png);

        let opened = open(
            &provider,
            &prepared.key,
            &prepared.nonce,
            &prepared.ciphertext,
        )
        .expect("opens");

        assert_eq!(opened, prepared.stripped);
        assert!(
            !opened
                .windows(b"a photographer".len())
                .any(|w| w == b"a photographer"),
            "stripped metadata reappeared after the round trip"
        );
    }

    #[test]
    fn a_padded_attachment_is_never_smaller_than_a_fixed_bucket() {
        let provider = PouchProvider::new();
        let prepared = prepare(&provider, &tiny_png()).expect("prepares");
        assert!(prepared.padded_len >= 64 * 1024);
    }

    #[test]
    fn opening_with_the_wrong_key_fails_rather_than_producing_garbage() {
        let provider = PouchProvider::new();
        let prepared = prepare(&provider, &tiny_png()).expect("prepares");

        let wrong_key = file_crypto::random_key();
        assert!(open(&provider, &wrong_key, &prepared.nonce, &prepared.ciphertext).is_err());
    }

    #[test]
    fn a_file_that_is_not_jpeg_png_or_webp_is_refused() {
        let provider = PouchProvider::new();
        assert!(matches!(
            prepare(&provider, b"not an image"),
            Err(AttachmentError::UnsupportedFormat)
        ));
    }

    #[test]
    fn every_encryption_uses_a_fresh_key() {
        // D-037's shape: a new key per file, never reused across calls.
        let provider = PouchProvider::new();
        let a = prepare(&provider, &tiny_png()).expect("prepares");
        let b = prepare(&provider, &tiny_png()).expect("prepares");
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn encode_blob_and_decode_blob_round_trip() {
        let nonce = vec![1u8; file_crypto::NONCE_BYTES];
        let ciphertext = vec![2u8; 40];
        let blob = encode_blob(&nonce, &ciphertext);
        let (decoded_nonce, decoded_ciphertext) = decode_blob(&blob).expect("decodes");
        assert_eq!(decoded_nonce, nonce);
        assert_eq!(decoded_ciphertext, ciphertext);
    }

    #[test]
    fn decode_blob_rejects_a_future_format_version() {
        let mut blob = vec![BLOB_FORMAT_VERSION + 1];
        blob.extend_from_slice(&[0u8; file_crypto::NONCE_BYTES + 10]);
        assert!(matches!(
            decode_blob(&blob),
            Err(AttachmentError::Malformed)
        ));
    }

    #[test]
    fn decode_blob_rejects_a_truncated_buffer() {
        assert!(matches!(
            decode_blob(&[BLOB_FORMAT_VERSION]),
            Err(AttachmentError::Malformed)
        ));
    }
}
