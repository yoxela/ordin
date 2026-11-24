// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Package signatures with plain Ed25519 keys (ORD-140).
//!
//! `FORMAT.md` beside this crate is the reference for every format here.
//! In short:
//!
//! - A key signs a package's identity, the BLAKE3 digest of its manifest,
//!   in a message that names the format:
//!   `ordin-signature 1 package blake3:<hex>`. Signing never changes the
//!   manifest.
//! - A [`Signature`] is canonical JSON naming the key, the package and the
//!   64-byte signature. Reading one checks it with Ed25519's strict rules,
//!   so every [`Signature`] value verifies. Whether its key is trusted is
//!   the caller's question.
//! - A [`PublicKey`] is written `ed25519:` and 64 hex digits, and is its
//!   own identity. Weak keys are refused.
//! - A public key file is one line; a secret key file is canonical JSON,
//!   with the secret encrypted by XChaCha20-Poly1305 under a key Argon2id
//!   derives from a passphrase, unless the file is made without one.
//!
//! Secrets are cleared from memory when dropped, and never shown by
//! `Debug`. Nothing here does I/O except asking the operating system for
//! random bytes. No input makes it panic.

mod error;
mod file;
mod hex;
mod key;
mod signature;

pub use error::Error;
pub use file::{
    KdfParams, MAX_COMMENT, MAX_KEY_FILE_SIZE, PUBLIC_KEY_FILE_PREFIX, PublicKeyFile, SecretKeyFile,
};
pub use key::{KEY_PREFIX, PublicKey, SecretKey};
pub use signature::{MAX_SIGNATURE_SIZE, Signature, message};
