// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Why signing, verifying or reading a key failed.

/// Why signing, verifying or reading a key failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is larger than its format allows.
    #[error("{what} is at most {max} bytes; this one is {len}")]
    TooLarge {
        /// What was read.
        what: &'static str,
        /// The limit.
        max: usize,
        /// The size.
        len: usize,
    },
    /// The input isn't in its format.
    #[error("{what}: {reason}")]
    Malformed {
        /// What was read.
        what: &'static str,
        /// What is wrong.
        reason: String,
    },
    /// A format version this reader doesn't know.
    #[error("{what}: unknown format {version}; this reader knows format 1")]
    UnknownFormat {
        /// What was read.
        what: &'static str,
        /// The version, as written.
        version: String,
    },
    /// A public key that isn't one, or one of the weak keys every message
    /// verifies against.
    #[error("{0} isn't a usable Ed25519 public key")]
    BadKey(String),
    /// The signature doesn't verify.
    #[error("the signature by {key} doesn't verify")]
    BadSignature {
        /// Who it claims to be by.
        key: String,
    },
    /// Only BLAKE3 package identities are signed.
    #[error("only a BLAKE3 package identity can be signed, not {0}")]
    NotBlake3(String),
    /// The secret key is encrypted, and no passphrase was given.
    #[error("the secret key is encrypted; a passphrase is needed")]
    NeedsPassphrase,
    /// A passphrase was given for a secret key that isn't encrypted.
    #[error("the secret key isn't encrypted, so it takes no passphrase")]
    NotEncrypted,
    /// The passphrase doesn't open the secret key, or the file was
    /// changed.
    #[error("the passphrase is wrong, or the secret key file was changed")]
    WrongPassphrase,
    /// The passphrase is empty.
    #[error("a passphrase can't be empty")]
    EmptyPassphrase,
    /// The secret key opened, but isn't the public key the file records.
    #[error("the secret key isn't the public key {0} its file records")]
    KeyMismatch(String),
    /// The operating system gave no random bytes.
    #[error("no random bytes from the operating system: {0}")]
    Random(String),
    /// Deriving the key from the passphrase failed.
    #[error("deriving a key from the passphrase failed: {0}")]
    Kdf(String),
}

impl Error {
    pub(crate) fn malformed(what: &'static str, reason: impl Into<String>) -> Self {
        Self::Malformed {
            what,
            reason: reason.into(),
        }
    }
}
