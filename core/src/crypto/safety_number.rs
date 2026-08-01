//! Safety numbers — the out-of-band check that a contact is who they claim.
//!
//! Two people read the same 60 digits off their two screens. If the numbers
//! match, no one substituted a key between them. If they do not, someone did,
//! or one of them reinstalled.
//!
//! **This is a display encoding of a hash, not a new cryptographic
//! construction.** SHA-256 is used through its intended interface; the digits
//! are a rendering of its output. It follows the published Signal safety-number
//! construction rather than departing from it, because the value of a
//! fingerprint format is entirely in it being a format people can compare, and
//! there is nothing to gain by being different.

use sha2::{Digest, Sha256};

/// Iterations of the hash used to derive the fingerprint.
///
/// Matches the published construction. The iteration count is not a
/// password-hardening measure — the input is a public key, not a secret, and
/// there is nothing to brute force. It exists to make generating a *colliding*
/// key expensive for an attacker who wants two keys whose displayed digits
/// agree.
const ITERATIONS: u32 = 5200;

/// Version prefix, so a future change to this format cannot be confused with
/// the current one.
const VERSION: [u8; 2] = [0x00, 0x00];

/// Digits contributed by each party.
const DIGITS_PER_PARTY: usize = 30;

/// A safety number, ready to display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    digits: String,
}

impl SafetyNumber {
    /// Derives the safety number for a pair of identity public keys.
    ///
    /// The two keys are sorted before being combined, so both parties compute
    /// the same value without needing to agree on who is "first". Without that,
    /// the two screens would show the same digits in a different order and
    /// every comparison would fail.
    pub fn derive(own_public_key: &[u8], their_public_key: &[u8]) -> Self {
        let (first, second) = if own_public_key <= their_public_key {
            (own_public_key, their_public_key)
        } else {
            (their_public_key, own_public_key)
        };

        let mut digits = String::with_capacity(DIGITS_PER_PARTY * 2);
        digits.push_str(&fingerprint(first));
        digits.push_str(&fingerprint(second));

        Self { digits }
    }

    /// The 60 digits, unformatted.
    pub fn digits(&self) -> &str {
        &self.digits
    }

    /// The digits grouped in blocks of five, as the UI displays them.
    ///
    /// Grouping is not decoration. The user is comparing sixty characters
    /// against another screen, and a run of sixty undifferentiated digits is
    /// where a mismatched pair gets read as matching.
    pub fn grouped(&self) -> String {
        self.digits
            .as_bytes()
            .chunks(5)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Constant-time comparison against another safety number.
    ///
    /// SPEC §2.1 forbids comparing secrets with `==`. A safety number is not
    /// secret, so this is belt and braces rather than strictly required — but
    /// the habit is what matters, and a future caller comparing something that
    /// *is* secret will find the right function already here.
    pub fn matches(&self, other: &SafetyNumber) -> bool {
        use subtle::ConstantTimeEq;
        if self.digits.len() != other.digits.len() {
            return false;
        }
        self.digits.as_bytes().ct_eq(other.digits.as_bytes()).into()
    }
}

/// Derives one party's 30 digits from their public key.
fn fingerprint(public_key: &[u8]) -> String {
    let mut hash = {
        let mut h = Sha256::new();
        h.update(VERSION);
        h.update(public_key);
        h.finalize().to_vec()
    };

    // Iterated hashing over (digest || key), as in the published construction.
    for _ in 0..ITERATIONS {
        let mut h = Sha256::new();
        h.update(&hash);
        h.update(public_key);
        hash = h.finalize().to_vec();
    }

    // Six groups of five digits, each taken from 40 bits of the digest.
    let mut out = String::with_capacity(DIGITS_PER_PARTY);
    for chunk in hash.chunks(5).take(DIGITS_PER_PARTY / 5) {
        let mut value: u64 = 0;
        for byte in chunk {
            value = (value << 8) | u64::from(*byte);
        }
        out.push_str(&format!("{:05}", value % 100_000));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &[u8] = b"alice-public-key-0123456789abcdef";
    const BOB: &[u8] = b"bob-public-key-0123456789abcdefgh";

    #[test]
    fn both_parties_compute_the_same_number() {
        // The property the whole feature rests on. If this fails, every
        // verification attempt in the product fails and users conclude they
        // are being attacked.
        let alice_view = SafetyNumber::derive(ALICE, BOB);
        let bob_view = SafetyNumber::derive(BOB, ALICE);
        assert_eq!(alice_view, bob_view);
        assert!(alice_view.matches(&bob_view));
    }

    #[test]
    fn it_is_sixty_digits() {
        let n = SafetyNumber::derive(ALICE, BOB);
        assert_eq!(n.digits().len(), 60);
        assert!(n.digits().bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn it_groups_in_fives() {
        let n = SafetyNumber::derive(ALICE, BOB);
        let grouped = n.grouped();
        let blocks: Vec<&str> = grouped.split(' ').collect();
        assert_eq!(blocks.len(), 12);
        assert!(blocks.iter().all(|b| b.len() == 5));
        assert_eq!(grouped.replace(' ', ""), n.digits());
    }

    #[test]
    fn a_different_contact_gives_a_different_number() {
        let real = SafetyNumber::derive(ALICE, BOB);
        let impostor = SafetyNumber::derive(ALICE, b"mallory-public-key-0123456789abc");
        assert_ne!(real, impostor);
        assert!(!real.matches(&impostor));
    }

    #[test]
    fn a_single_flipped_bit_changes_the_number() {
        // The attack this defends against is key substitution. If a
        // near-identical key produced a near-identical number, a user
        // comparing quickly would miss it.
        let mut tampered = BOB.to_vec();
        tampered[0] ^= 0x01;

        let honest = SafetyNumber::derive(ALICE, BOB);
        let substituted = SafetyNumber::derive(ALICE, &tampered);
        assert_ne!(honest, substituted);

        // And the difference must be spread across the digits, not confined to
        // the tail where a hurried reader would not look.
        let differing = honest
            .digits()
            .chars()
            .zip(substituted.digits().chars())
            .filter(|(a, b)| a != b)
            .count();
        assert!(
            differing > 10,
            "only {differing} of 60 digits changed; a substituted key would look familiar"
        );
    }

    #[test]
    fn it_is_deterministic_across_runs() {
        let a = SafetyNumber::derive(ALICE, BOB);
        let b = SafetyNumber::derive(ALICE, BOB);
        assert_eq!(a, b);
    }

    #[test]
    fn comparison_rejects_a_different_length() {
        let n = SafetyNumber::derive(ALICE, BOB);
        let truncated = SafetyNumber {
            digits: n.digits()[..30].to_string(),
        };
        assert!(!n.matches(&truncated));
    }
}
