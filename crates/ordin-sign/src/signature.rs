// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! A package signature: one key's Ed25519 signature over a package's
//! identity, as canonical JSON.

use std::collections::BTreeMap;

use ordin_core::json::{self, Value};
use ordin_core::{Algorithm, Digest};

use crate::error::Error;
use crate::hex;
use crate::key::PublicKey;

/// The largest signature, in bytes. A signature is about 250.
pub const MAX_SIGNATURE_SIZE: usize = 1024;

/// The format version's key.
const FORMAT: &str = "ordin-signature";

const WHAT: &str = "a signature";

/// What a key signs for a package: the format and the package identity,
/// so the signature can't be taken for one over anything else.
#[must_use]
pub fn message(package: &Digest) -> String {
    format!("ordin-signature 1 package {package}")
}

/// A package signature that verifies: every value of this type was either
/// just made or checked when it was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    key: PublicKey,
    package: Digest,
    signature: ed25519_dalek::Signature,
}

fn string<'a>(map: &'a BTreeMap<String, Value>, field: &str) -> Result<&'a str, Error> {
    match map.get(field) {
        Some(Value::Str(text)) => Ok(text),
        Some(other) => Err(Error::malformed(
            WHAT,
            format!("{field} is {}, not a string", other.type_name()),
        )),
        None => Err(Error::malformed(WHAT, format!("{field} is missing"))),
    }
}

impl Signature {
    pub(crate) fn new(
        key: PublicKey,
        package: Digest,
        signature: ed25519_dalek::Signature,
    ) -> Self {
        Self {
            key,
            package,
            signature,
        }
    }

    /// Who signed.
    #[must_use]
    pub fn key(&self) -> PublicKey {
        self.key
    }

    /// The package signed: the BLAKE3 digest of its manifest.
    #[must_use]
    pub fn package(&self) -> Digest {
        self.package
    }

    /// Reads a signature and checks that it verifies. The bytes must be
    /// exactly what [`to_bytes`](Self::to_bytes) writes. The format
    /// version is checked before any other field.
    ///
    /// # Errors
    ///
    /// The bytes are too large, aren't canonical JSON in the format, name
    /// an unusable key, or the signature doesn't verify.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SIGNATURE_SIZE {
            return Err(Error::TooLarge {
                what: WHAT,
                max: MAX_SIGNATURE_SIZE,
                len: bytes.len(),
            });
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| Error::malformed(WHAT, "it isn't UTF-8"))?;
        let value = json::parse_bounded(text, 0, 8).map_err(|e| Error::malformed(WHAT, e.0))?;
        let Value::Object(map) = value else {
            return Err(Error::malformed(
                WHAT,
                format!("it is {}, not an object", value.type_name()),
            ));
        };
        match map.get(FORMAT) {
            None => return Err(Error::malformed(WHAT, format!("{FORMAT} is missing"))),
            Some(Value::Int(1)) => {}
            Some(other) => {
                return Err(Error::UnknownFormat {
                    what: WHAT,
                    version: json::canonical(other),
                });
            }
        }
        if let Some(field) = map
            .keys()
            .find(|k| !["key", FORMAT, "package", "signature"].contains(&k.as_str()))
        {
            return Err(Error::malformed(WHAT, format!("unknown field {field:?}")));
        }
        let key: PublicKey = string(&map, "key")?.parse()?;
        let package: Digest = string(&map, "package")?
            .parse()
            .map_err(|e: ordin_core::Error| Error::malformed(WHAT, format!("package: {e}")))?;
        if package.algorithm() != Algorithm::Blake3 {
            return Err(Error::NotBlake3(package.to_string()));
        }
        let signature = hex::decode::<64>(string(&map, "signature")?)
            .ok_or_else(|| Error::malformed(WHAT, "signature isn't 128 lowercase hex digits"))?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature);
        key.verifying()
            .verify_strict(message(&package).as_bytes(), &signature)
            .map_err(|_| Error::BadSignature {
                key: key.to_string(),
            })?;
        let read = Self::new(key, package, signature);
        if read.to_bytes() != bytes {
            return Err(Error::malformed(
                WHAT,
                "it isn't canonical JSON (RFC 8785) as Ordin writes it",
            ));
        }
        Ok(read)
    }

    /// The signature as canonical JSON (RFC 8785).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let value = Value::Object(BTreeMap::from([
            ("key".to_owned(), Value::Str(self.key.to_string())),
            (FORMAT.to_owned(), Value::Int(1)),
            ("package".to_owned(), Value::Str(self.package.to_string())),
            (
                "signature".to_owned(),
                Value::Str(hex::encode(&self.signature.to_bytes())),
            ),
        ]));
        json::canonical(&value).into_bytes()
    }
}
