// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Ed25519 keys.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ordin_core::{Algorithm, Digest};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::hex;
use crate::signature::{Signature, message};

/// The prefix of a public key's text form.
pub const KEY_PREFIX: &str = "ed25519:";

/// An Ed25519 public key, written `ed25519:` and 64 lowercase hex digits.
/// It is also the key's identity: keys are short enough to need no
/// fingerprint. The weak keys every message verifies against are refused.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// The key from its 32 bytes.
    ///
    /// # Errors
    ///
    /// The bytes aren't a point on the curve, or are a weak key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let bad = || Error::BadKey(format!("{KEY_PREFIX}{}", hex::encode(bytes)));
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| bad())?;
        if key.is_weak() {
            return Err(bad());
        }
        Ok(Self(key))
    }

    /// The key's 32 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn verifying(&self) -> &VerifyingKey {
        &self.0
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Keys sort by their bytes, which is also the order of their text.
impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{KEY_PREFIX}{}", hex::encode(&self.to_bytes()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        let bytes = text
            .strip_prefix(KEY_PREFIX)
            .and_then(hex::decode::<32>)
            .ok_or_else(|| {
                Error::malformed(
                    "a public key",
                    format!("{text:?} isn't ed25519: and 64 lowercase hex digits"),
                )
            })?;
        Self::from_bytes(&bytes)
    }
}

/// An Ed25519 secret key. Its bytes are cleared from memory when it is
/// dropped, and it never shows them: `Debug` shows only the public key.
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// A new key, from the operating system's random bytes.
    ///
    /// # Errors
    ///
    /// The operating system gave no random bytes.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|e| Error::Random(e.to_string()))?;
        Ok(Self::from_seed(&seed))
    }

    /// The key from its 32-byte seed.
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The 32-byte seed, cleared when dropped.
    pub(crate) fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The public key. It is never a weak key: Ed25519 clamps the secret
    /// scalar to a multiple of 8, so the public key has the base point's
    /// large order.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Signs a raw message.
    pub(crate) fn sign_message(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.0.sign(message)
    }

    /// Signs a package: its identity, the BLAKE3 digest of its manifest.
    ///
    /// # Errors
    ///
    /// The identity isn't a BLAKE3 digest.
    pub fn sign(&self, package: &Digest) -> Result<Signature, Error> {
        if package.algorithm() != Algorithm::Blake3 {
            return Err(Error::NotBlake3(package.to_string()));
        }
        let signature = self.sign_message(message(package).as_bytes());
        Ok(Signature::new(self.public_key(), *package, signature))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(for {})", self.public_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032, section 7.1: tests 1 to 3, as secret key, public key,
    /// message and signature.
    const RFC_8032: [(&str, &str, &str, &str); 3] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];

    fn bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc_8032_test_vectors() {
        for (secret, public, message, signature) in RFC_8032 {
            let key = SecretKey::from_seed(&hex::decode::<32>(secret).unwrap());
            assert_eq!(key.public_key().to_string(), format!("ed25519:{public}"));
            assert_eq!(
                hex::encode(&key.sign_message(&bytes(message)).to_bytes()),
                signature
            );
            assert_eq!(*key.seed(), hex::decode::<32>(secret).unwrap());
        }
    }

    #[test]
    fn a_secret_key_never_shows_its_bytes() {
        let (secret, public, _, _) = RFC_8032[0];
        let key = SecretKey::from_seed(&hex::decode::<32>(secret).unwrap());
        let shown = format!("{key:?}");
        assert_eq!(shown, format!("SecretKey(for ed25519:{public})"));
        assert!(!shown.contains(secret));
    }

    #[test]
    fn every_secret_gives_a_usable_public_key() {
        for n in 0..=255u8 {
            let key = SecretKey::from_seed(&[n; 32]).public_key();
            assert_eq!(PublicKey::from_bytes(&key.to_bytes()), Ok(key), "{n}");
        }
    }
}
