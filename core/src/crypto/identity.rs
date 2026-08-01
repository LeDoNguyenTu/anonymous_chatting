//! Local identity, and the invite code that lets someone start a conversation.
//!
//! An identity is created entirely on the device. Nothing is registered with a
//! server, no phone number or email is involved, and the display name is local
//! metadata shared only with contacts the user adds by hand (SPEC §6.7.1).

use openmls::prelude::{
    tls_codec::Serialize as _, BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage,
    KeyPackageBundle, KeyPackageIn, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::{provider::PouchProvider, CryptoError, CIPHERSUITE};

/// A locally generated identity.
///
/// The signature key pair is the secret. It is held in memory only for as long
/// as the client runs, persisted only into the SQLCipher database, and never
/// logged, displayed, or exported (SPEC §2.5).
pub struct Identity {
    /// Local-only display name. Never sent to the relay, never in an invite
    /// code — only shared with contacts, inside the encrypted channel.
    display_name: String,
    /// Opaque random inbox address. Not derived from anything about the person.
    inbox_id: String,
    credential: CredentialWithKey,
    signer: SignatureKeyPair,
}

impl Identity {
    /// Creates a fresh identity.
    ///
    /// The credential carries the public signature key as its identity, not a
    /// name. MLS puts credential contents on the wire, so a name there would
    /// travel with every key package — exactly the personal data the invite
    /// code copy promises is absent.
    pub fn create(display_name: &str, provider: &PouchProvider) -> Result<Self, CryptoError> {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|_| CryptoError::IdentityCreation)?;
        signer
            .store(provider.storage())
            .map_err(|_| CryptoError::IdentityCreation)?;

        let credential = BasicCredential::new(signer.public().to_vec());

        Ok(Self {
            display_name: display_name.to_string(),
            inbox_id: random_inbox_id(),
            credential: CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.public().into(),
            },
            signer,
        })
    }

    /// Rebuilds an identity from stored parts.
    pub fn restore(
        display_name: String,
        inbox_id: String,
        signer: SignatureKeyPair,
    ) -> Result<Self, CryptoError> {
        let credential = BasicCredential::new(signer.public().to_vec());
        Ok(Self {
            display_name,
            inbox_id,
            credential: CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.public().into(),
            },
            signer,
        })
    }

    /// The local-only display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The opaque inbox address this identity collects messages from.
    pub fn inbox_id(&self) -> &str {
        &self.inbox_id
    }

    /// The public signature key. Safe to display and to publish — it is the
    /// input to the safety number, and Kerckhoffs's principle applies (D-014).
    pub fn public_key(&self) -> &[u8] {
        self.signer.public()
    }

    pub(crate) fn credential(&self) -> &CredentialWithKey {
        &self.credential
    }

    pub(crate) fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }

    /// Produces a key package and the invite code that carries it.
    ///
    /// A key package is single-use by design: MLS consumes its private half
    /// when someone joins with it. A fresh one is generated per invite rather
    /// than reused, because reuse degrades forward secrecy for the joining
    /// member.
    pub fn invite_code(&self, provider: &PouchProvider) -> Result<InviteCode, CryptoError> {
        let bundle: KeyPackageBundle = KeyPackage::builder()
            .build(CIPHERSUITE, provider, &self.signer, self.credential.clone())
            .map_err(|_| CryptoError::IdentityCreation)?;

        let key_package = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|_| CryptoError::IdentityCreation)?;

        Ok(InviteCode {
            inbox_id: self.inbox_id.clone(),
            public_key: self.signer.public().to_vec(),
            key_package,
        })
    }
}

/// What one person hands another so they can start a conversation.
///
/// Contains a public key, an opaque inbox address, and a single-use key
/// package. It contains **no personal information**: no name, no phone number,
/// no email, nothing derived from any of those. The Add contact screen says so
/// (SPEC §6.7.4), and this type is the reason that copy is true.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCode {
    /// Opaque random inbox address.
    pub inbox_id: String,
    /// The identity's public signature key.
    pub public_key: Vec<u8>,
    /// TLS-serialized MLS key package.
    pub key_package: Vec<u8>,
}

impl InviteCode {
    /// Encodes the code for display as text or in a QR code.
    pub fn encode(&self) -> Result<String, CryptoError> {
        use base64::Engine as _;
        let json = serde_json::to_vec(self).map_err(|_| CryptoError::MalformedInviteCode)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
    }

    /// Reads a code produced by [`Self::encode`].
    pub fn decode(encoded: &str) -> Result<Self, CryptoError> {
        use base64::Engine as _;
        // Whitespace is stripped because these get copied out of chat windows
        // and QR scanners, and a failure here reads to the user as "my contact
        // gave me a broken code".
        let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(cleaned.as_bytes())
            .map_err(|_| CryptoError::MalformedInviteCode)?;
        serde_json::from_slice(&json).map_err(|_| CryptoError::MalformedInviteCode)
    }

    /// Parses and validates the key package inside the code.
    ///
    /// **Fails closed on a ciphersuite mismatch.** SPEC §2.1 forbids downgrade
    /// paths: if the peer's key package names a different ciphersuite, this
    /// returns an error naming it rather than negotiating down to whatever the
    /// peer offered.
    pub fn key_package(&self, provider: &PouchProvider) -> Result<KeyPackage, CryptoError> {
        use openmls::prelude::tls_codec::Deserialize as _;

        let key_package_in = KeyPackageIn::tls_deserialize_exact(self.key_package.as_slice())
            .map_err(|_| CryptoError::MalformedInviteCode)?;

        let key_package = key_package_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| CryptoError::MalformedInviteCode)?;

        let offered = key_package.ciphersuite();
        if offered != CIPHERSUITE {
            return Err(CryptoError::CiphersuiteMismatch(describe(offered)));
        }

        Ok(key_package)
    }
}

/// Names a ciphersuite for an error message the user will read.
fn describe(suite: Ciphersuite) -> String {
    format!("{suite:?}")
}

/// A 128-bit opaque inbox address, hex encoded.
///
/// `OsRng` because SPEC §2.1 forbids any non-CSPRNG for security-relevant
/// values, and this one is: it is the only thing the relay knows about a user,
/// so it must not be guessable or derivable from anything about them.
fn random_inbox_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_needs_no_personal_data_and_registers_nothing() {
        let provider = PouchProvider::new();
        let id = Identity::create("Brian", &provider).expect("identity is created locally");

        assert_eq!(id.display_name(), "Brian");
        assert_eq!(id.inbox_id().len(), 32, "inbox id is 128 bits of hex");
        assert!(id.inbox_id().bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!id.public_key().is_empty());
    }

    #[test]
    fn inbox_ids_are_unpredictable() {
        let provider = PouchProvider::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..128 {
            let id = Identity::create("x", &provider).expect("identity");
            assert!(seen.insert(id.inbox_id().to_string()), "inbox ids repeat");
        }
    }

    #[test]
    fn an_invite_code_carries_no_display_name() {
        // The Add contact screen tells the user this code contains no personal
        // information. That claim has to survive contact with the encoder.
        let provider = PouchProvider::new();
        let id = Identity::create("Le-Do-Nguyen-Tu-CANARY", &provider).expect("identity");
        let code = id.invite_code(&provider).expect("invite code");

        let encoded = code.encode().expect("encodes");
        let raw = format!("{code:?}");

        for haystack in [&encoded, &raw] {
            assert!(
                !haystack.contains("CANARY"),
                "the display name leaked into the invite code"
            );
        }

        // And not hidden inside the base64 payload either.
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .expect("decodes");
        let text = String::from_utf8_lossy(&decoded);
        assert!(
            !text.contains("CANARY"),
            "display name leaked, base64 encoded"
        );
    }

    #[test]
    fn invite_codes_round_trip() {
        let provider = PouchProvider::new();
        let id = Identity::create("Brian", &provider).expect("identity");
        let code = id.invite_code(&provider).expect("invite code");

        let decoded = InviteCode::decode(&code.encode().expect("encodes")).expect("decodes");
        assert_eq!(decoded.inbox_id, code.inbox_id);
        assert_eq!(decoded.public_key, code.public_key);
        assert_eq!(decoded.key_package, code.key_package);
    }

    #[test]
    fn invite_codes_survive_being_copied_with_whitespace() {
        let provider = PouchProvider::new();
        let id = Identity::create("Brian", &provider).expect("identity");
        let encoded = id
            .invite_code(&provider)
            .expect("code")
            .encode()
            .expect("encodes");

        let wrapped = format!("  {}\n  {}  ", &encoded[..20], &encoded[20..]);
        assert!(
            InviteCode::decode(&wrapped).is_ok(),
            "wrapped code should parse"
        );
    }

    #[test]
    fn a_malformed_invite_code_is_rejected_with_a_named_error() {
        for bad in ["", "not-base64-!!!", "aGVsbG8"] {
            assert!(matches!(
                InviteCode::decode(bad),
                Err(CryptoError::MalformedInviteCode)
            ));
        }
    }

    #[test]
    fn each_invite_code_carries_a_fresh_key_package() {
        // Reusing a key package degrades forward secrecy for the joiner.
        let provider = PouchProvider::new();
        let id = Identity::create("Brian", &provider).expect("identity");
        let a = id.invite_code(&provider).expect("first");
        let b = id.invite_code(&provider).expect("second");
        assert_ne!(a.key_package, b.key_package, "key package was reused");
    }

    #[test]
    fn a_valid_key_package_parses_and_matches_the_ciphersuite() {
        let provider = PouchProvider::new();
        let id = Identity::create("Brian", &provider).expect("identity");
        let code = id.invite_code(&provider).expect("code");
        let kp = code.key_package(&provider).expect("key package validates");
        assert_eq!(kp.ciphersuite(), CIPHERSUITE);
    }

    #[test]
    fn a_corrupted_key_package_is_rejected() {
        let provider = PouchProvider::new();
        let id = Identity::create("Brian", &provider).expect("identity");
        let mut code = id.invite_code(&provider).expect("code");
        // Flip a byte in the middle of the key package.
        let mid = code.key_package.len() / 2;
        code.key_package[mid] ^= 0xFF;
        assert!(code.key_package(&provider).is_err());
    }
}
