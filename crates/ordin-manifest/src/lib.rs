// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The package manifest: its schema, validation and canonical JSON
//! (RFC 8785).
//!
//! `SCHEMA.md` beside this crate is the reference for every field and
//! rule. In short:
//!
//! - A signed manifest is read with [`Manifest::from_signed_bytes`], which
//!   requires the bytes to be canonical already, byte for byte, and
//!   returns the package's identity: the BLAKE3 digest of those bytes.
//! - [`Manifest::from_json`] reads any spacing and key order, for tools
//!   and tests, and checks every other rule. Never use it for signed
//!   manifests.
//! - [`Manifest::to_canonical_bytes`] and [`Manifest::digest`] encode a
//!   manifest and check the result against every rule again, so a
//!   manifest built in code can't skip one.
//!
//! Reading refuses duplicate keys, non-integer numbers, unknown fields
//! (unless the manifest's `ignorable` list names them), unknown values,
//! fields set to their default, unsorted sets and text that isn't in its
//! canonical form, and names the field that is wrong. Nothing here does
//! I/O, and no input makes it panic.

mod decode;
mod encode;
mod error;
pub use ordin_core::json;
mod known;
mod model;
pub mod spdx;
mod text;

use ordin_core::Digest;

pub use error::{Error, ErrorKind, Path, Segment};
pub use model::*;
pub use ordin_core::{Account, Mode};
pub use text::{Date, Id, UnitName, Url};

/// The largest manifest, in bytes.
pub const MAX_SIZE: usize = 1 << 20;

fn whole(kind: ErrorKind) -> Error {
    Error::at(&Path::default(), kind)
}

fn read(bytes: &[u8]) -> Result<(&str, json::Value), Error> {
    if bytes.len() > MAX_SIZE {
        return Err(whole(ErrorKind::TooLarge {
            max: MAX_SIZE,
            len: bytes.len(),
        }));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| whole(ErrorKind::NotUtf8))?;
    let value = json::parse(text).map_err(|e| whole(ErrorKind::Json(e.0)))?;
    Ok((text, value))
}

/// The first byte where `a` and `b` differ.
fn first_difference(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()))
}

/// Requires the re-encoded manifest to equal the bytes it was read from.
fn same_encoding(read: &str, encoded: &str) -> Result<(), Error> {
    if encoded == read {
        return Ok(());
    }
    Err(whole(ErrorKind::NotCanonical {
        at: first_difference(read.as_bytes(), encoded.as_bytes()),
    }))
}

impl Manifest {
    /// A manifest with the required fields and every other one at its
    /// default. Fields are public, so the rest can be set afterwards;
    /// [`to_canonical_bytes`](Self::to_canonical_bytes) checks them all.
    #[must_use]
    pub fn new(
        name: ordin_core::PackageName,
        version: ordin_version::Version,
        kind: Kind,
        arch: ordin_core::Arch,
        summary: String,
        license: License,
        facets: std::collections::BTreeMap<ordin_core::Facet, FacetEntry>,
    ) -> Self {
        Self {
            name,
            version,
            kind,
            arch,
            summary,
            description: None,
            homepage: None,
            license,
            source: None,
            provenance: None,
            facets,
            provides: Vec::new(),
            requires: Vec::new(),
            conflicts: Vec::new(),
            recommends: Vec::new(),
            supplements: Vec::new(),
            requires_apply: Vec::new(),
            requires_boot: Vec::new(),
            obsoletes: Vec::new(),
            replaces: Vec::new(),
            removes: std::collections::BTreeMap::new(),
            declares: Declares::default(),
            state: None,
            settings: Vec::new(),
            hooks: std::collections::BTreeMap::new(),
            tests: Vec::new(),
            security: None,
            delegated: None,
            live_apply: false,
            boot_critical: false,
            support: None,
            abi: std::collections::BTreeMap::new(),
            fixes: Vec::new(),
            notices: Vec::new(),
            ignorable: Vec::new(),
            ignored: Vec::new(),
        }
    }

    /// Reads a signed manifest: the bytes must be canonical JSON already.
    /// Returns the manifest and its identity.
    ///
    /// # Errors
    ///
    /// Returns the first rule the bytes break, and where.
    pub fn from_signed_bytes(bytes: &[u8]) -> Result<(Self, Digest), Error> {
        let (text, value) = read(bytes)?;
        let canonical = json::canonical(&value);
        if canonical != text {
            return Err(whole(ErrorKind::NotCanonical {
                at: first_difference(text.as_bytes(), canonical.as_bytes()),
            }));
        }
        let manifest = decode::Decoder::new().manifest(&value)?;
        // Decoding refuses every non-canonical choice the schema allows,
        // so encoding gives back the same bytes. Check it anyway: the
        // identity must be the digest of exactly what was read.
        same_encoding(text, &json::canonical(&encode::manifest(&manifest)))?;
        Ok((manifest, Digest::blake3(bytes)))
    }

    /// Reads a manifest from JSON in any spacing and key order, checking
    /// every other rule. For tools and tests; signed manifests must be
    /// read with [`from_signed_bytes`](Self::from_signed_bytes).
    ///
    /// # Errors
    ///
    /// Returns the first rule the text breaks, and where.
    pub fn from_json(text: &str) -> Result<Self, Error> {
        let (_, value) = read(text.as_bytes())?;
        decode::Decoder::new().manifest(&value)
    }

    /// The manifest's canonical bytes, checked against every rule.
    ///
    /// # Errors
    ///
    /// Returns the first rule the manifest breaks, and where.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let bytes = json::canonical(&encode::manifest(self)).into_bytes();
        Self::from_signed_bytes(&bytes)?;
        Ok(bytes)
    }

    /// The package's identity: the BLAKE3 digest of its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns the first rule the manifest breaks, and where.
    pub fn digest(&self) -> Result<Digest, Error> {
        Ok(Digest::blake3(&self.to_canonical_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_re_encoding_that_differs_is_refused_where_it_differs() {
        assert!(same_encoding("{}", "{}").is_ok());
        assert_eq!(
            same_encoding(r#"{"a":1}"#, r#"{"a":2}"#).unwrap_err().kind,
            ErrorKind::NotCanonical { at: 5 }
        );
        assert_eq!(
            same_encoding("{}", "{} ").unwrap_err().kind,
            ErrorKind::NotCanonical { at: 2 }
        );
        assert_eq!(first_difference(b"ab", b"ab"), 2);
    }
}
