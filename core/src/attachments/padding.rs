//! Fixed-size padding buckets (SPEC §7.1 step 3).
//!
//! Blunts size fingerprinting: a 70 KB photo and a 200 KB photo produce
//! identically sized blobs once both land in the 256 KB bucket, so the relay
//! — which sees nothing else about an attachment — cannot tell them apart by
//! size either.

const KB: usize = 1024;
const MB: usize = 1024 * KB;

/// SPEC §7.1: "64 KB, 256 KB, 1 MB, 4 MB, 16 MB, then 16 MB increments."
const FIXED_BUCKETS: [usize; 5] = [64 * KB, 256 * KB, MB, 4 * MB, 16 * MB];

const INCREMENT: usize = 16 * MB;

/// The padded size a plaintext of `len` bytes lands in.
fn bucket_for(len: usize) -> usize {
    for &bucket in &FIXED_BUCKETS {
        if len <= bucket {
            return bucket;
        }
    }
    len.div_ceil(INCREMENT) * INCREMENT
}

/// How many bytes at the front of a padded buffer record the real length.
///
/// Padding has to be reversible: the recipient decrypts a bucket-sized
/// buffer and needs to know where the real content ends and the zero
/// filler begins. An explicit length prefix does that without guessing at
/// trailing zero bytes, which real content could legitimately end with.
const LEN_PREFIX_BYTES: usize = 8;

/// Prefixes `data` with its own length, then zero-fills to the smallest
/// bucket that fits — the fixed point SPEC §7.1 names, or the next 16 MB
/// increment past it.
pub fn pad(data: &[u8]) -> Vec<u8> {
    let padded_len = bucket_for(LEN_PREFIX_BYTES + data.len());

    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(padded_len, 0);
    out
}

/// Reverses [`pad`].
///
/// `None` means `padded` was never produced by `pad` — too short to hold a
/// length prefix, or the prefix claims more content than is actually
/// present.
pub fn unpad(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < LEN_PREFIX_BYTES {
        return None;
    }
    let (prefix, rest) = padded.split_at(LEN_PREFIX_BYTES);
    // Built by folding rather than `[u8; 8]::try_from(prefix).unwrap()` — the
    // crate denies `expect`/`unwrap` outside tests (a panic in this path is a
    // denial of service), and `split_at` above already guarantees `prefix` is
    // exactly `LEN_PREFIX_BYTES` long, so there is nothing left to assert.
    let len = prefix
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)) as usize;
    rest.get(..len).map(|s| s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_content_lands_in_the_smallest_bucket() {
        assert_eq!(pad(b"hi").len(), 64 * KB);
    }

    #[test]
    fn content_just_over_a_bucket_lands_in_the_next_one() {
        let data = vec![0u8; 64 * KB - LEN_PREFIX_BYTES + 1];
        assert_eq!(pad(&data).len(), 256 * KB);
    }

    #[test]
    fn content_past_the_largest_fixed_bucket_uses_16mb_increments() {
        let data = vec![0u8; 16 * MB + 1];
        let padded_len = pad(&data).len();
        assert_eq!(padded_len, 32 * MB);
        assert_eq!(padded_len % INCREMENT, 0);
    }

    #[test]
    fn two_sizes_in_the_same_bucket_produce_identical_padded_sizes() {
        // The actual property padding exists for: an observer of the padded
        // size alone cannot distinguish a 70 KB file from a 200 KB one.
        let a = pad(&vec![7u8; 70 * KB]);
        let b = pad(&vec![7u8; 200 * KB]);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn unpad_reverses_pad_for_arbitrary_content() {
        for len in [0usize, 1, 1000, 64 * KB, 64 * KB + 500] {
            let data = vec![0xAB; len];
            let padded = pad(&data);
            assert_eq!(unpad(&padded), Some(data));
        }
    }

    #[test]
    fn unpad_does_not_include_the_zero_filler() {
        let data = b"real content".to_vec();
        let padded = pad(&data);
        let recovered = unpad(&padded).expect("unpads");
        assert_eq!(recovered, data);
        assert!(padded.len() > data.len(), "padding did not actually pad");
    }

    #[test]
    fn a_buffer_too_short_to_hold_a_length_prefix_is_rejected() {
        assert_eq!(unpad(&[0u8; 3]), None);
    }

    #[test]
    fn a_length_prefix_claiming_more_than_is_present_is_rejected() {
        let mut malformed = (u64::MAX).to_be_bytes().to_vec();
        malformed.extend_from_slice(b"short");
        assert_eq!(unpad(&malformed), None);
    }
}
