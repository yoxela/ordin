// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Trees: one facet's file list in a single canonical, hashable form.
//!
//! `FORMAT.md` beside this crate is the reference for every field and
//! rule. In short:
//!
//! - A tree is canonical JSON (RFC 8785): `{"ordin-tree": 1, "entries":
//!   [...]}`, entries sorted by the bytes of their paths.
//! - An entry is a file, a directory, a symlink or a hard link. Device
//!   nodes, sockets and FIFOs can't be packaged.
//! - A file records its mode, owner and group names, size, BLAKE3 and
//!   fs-verity digests, `user.*` extended attributes and capabilities.
//!   Timestamps are never recorded.
//! - Every parent of an entry is a directory entry in the same tree, so
//!   no path passes through a symlink, and every hard link points at a
//!   file in the tree.
//! - A tree's identity is the BLAKE3 digest of its canonical bytes.
//!
//! [`Tree::from_canonical_bytes`] reads a tree strictly: the bytes must
//! already be canonical. [`Tree::new`] builds one from entries in any
//! order. [`Tree::to_canonical_bytes`] and [`Tree::digest`] encode it and
//! check the result against every rule again. Nothing here does I/O, and
//! no input makes it panic.
//!
//! [`file_digests`] and [`FileHasher`] compute the digests a file entry
//! records, in one pass over bytes the caller supplies.
//!
//! [`chunk`] cuts files into content-defined chunks for transport and
//! records them in a chunk index.

mod caps;
pub mod chunk;
mod decode;
mod digests;
mod encode;
mod error;
mod model;
mod path;
mod read;
mod xattr;

use ordin_core::Digest;
use ordin_core::json::MAX_INT;

pub use caps::{Capabilities, LinuxCap};
pub use digests::{FileDigests, FileHasher, file_digests};
pub use error::{Error, ErrorKind, Location};
pub use model::{DIR_MODE, Dir, Entry, FILE_MODE, File, Kind, Symlink};
pub use path::{NAME_MAX, PATH_MAX, SymlinkTarget, TreePath};
pub use xattr::{
    XATTR_NAME_MAX, XATTR_VALUE_MAX, XATTRS_MAX, XattrName, Xattrs, base64_decode, base64_encode,
};

/// The largest tree, in bytes.
pub const MAX_SIZE: usize = 64 << 20;

/// The most entries in a tree.
pub const MAX_ENTRIES: usize = 1 << 18;

/// A tree: entries sorted by path, every rule checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    entries: Vec<Entry>,
}

/// Requires `written` to be exactly the bytes that were `read`.
#[cfg(test)]
fn same_encoding(read: &str, written: &str) -> Result<(), Error> {
    if read == written {
        return Ok(());
    }
    Err(Error::tree(
        None,
        ErrorKind::NotCanonical {
            at: ordin_core::json::first_difference(read.as_bytes(), written.as_bytes()),
        },
    ))
}

fn at(index: usize, e: &Entry, field: Option<&str>, kind: ErrorKind) -> Error {
    Error::entry(index, Some(e.path.as_str()), field, kind)
}

/// The rules within one entry that its type can't express.
fn check_entry(index: usize, e: &Entry) -> Result<(), Error> {
    let (xattrs, file) = match &e.kind {
        Kind::File(f) => (&f.xattrs, Some(f)),
        Kind::Dir(d) => (&d.xattrs, None),
        Kind::Symlink(_) | Kind::HardLink(_) => return Ok(()),
    };
    if xattrs.len() > XATTRS_MAX {
        return Err(at(
            index,
            e,
            Some("xattrs"),
            ErrorKind::TooManyXattrs {
                max: XATTRS_MAX,
                len: xattrs.len(),
            },
        ));
    }
    if let Some((name, value)) = xattrs.iter().find(|(_, v)| v.len() > XATTR_VALUE_MAX) {
        return Err(at(
            index,
            e,
            Some(&format!("xattrs.{name}")),
            ErrorKind::XattrTooLarge {
                max: XATTR_VALUE_MAX,
                len: value.len(),
            },
        ));
    }
    let Some(f) = file else {
        return Ok(());
    };
    let max = MAX_INT.unsigned_abs();
    if f.size > max {
        return Err(at(
            index,
            e,
            Some("size"),
            ErrorKind::OutOfRange { max, value: f.size },
        ));
    }
    for (field, digest, expected) in [
        ("content", f.content, ordin_core::Algorithm::Blake3),
        ("fsverity", f.fsverity, ordin_core::Algorithm::Sha256),
    ] {
        if digest.algorithm() != expected {
            return Err(at(
                index,
                e,
                Some(field),
                ErrorKind::WrongAlgorithm { expected },
            ));
        }
    }
    if f.capabilities.as_ref().is_some_and(Capabilities::is_empty) {
        return Err(at(
            index,
            e,
            Some("capabilities"),
            ErrorKind::EmptyCapabilities,
        ));
    }
    Ok(())
}

/// Checks every rule, for entries in the order given.
fn check(entries: &[Entry]) -> Result<(), Error> {
    if entries.len() > MAX_ENTRIES {
        return Err(Error::tree(
            Some("entries"),
            ErrorKind::TooManyEntries {
                max: MAX_ENTRIES,
                len: entries.len(),
            },
        ));
    }
    for (index, (previous, e)) in entries.iter().zip(entries.iter().skip(1)).enumerate() {
        let kind = match e.path.cmp(&previous.path) {
            std::cmp::Ordering::Greater => continue,
            std::cmp::Ordering::Equal => ErrorKind::Duplicate,
            std::cmp::Ordering::Less => ErrorKind::NotSorted {
                previous: previous.path.to_string(),
            },
        };
        return Err(at(index + 1, e, None, kind));
    }
    let find = |path: &str| {
        entries
            .binary_search_by(|e| e.path.as_str().cmp(path))
            .ok()
            .and_then(|i| entries.get(i))
    };
    for (index, e) in entries.iter().enumerate() {
        check_entry(index, e)?;
        let parent = e.path.parent();
        if parent != "/" {
            match find(parent) {
                None => {
                    return Err(at(
                        index,
                        e,
                        None,
                        ErrorKind::NoParent {
                            parent: parent.to_owned(),
                        },
                    ));
                }
                Some(p) if !matches!(p.kind, Kind::Dir(_)) => {
                    return Err(at(
                        index,
                        e,
                        None,
                        ErrorKind::ParentNotDir {
                            parent: parent.to_owned(),
                            found: p.kind.type_name(),
                        },
                    ));
                }
                Some(_) => {}
            }
        }
        if let Kind::HardLink(target) = &e.kind {
            let kind = match find(target.as_str()) {
                None => ErrorKind::LinkTargetMissing {
                    target: target.to_string(),
                },
                Some(t) if !matches!(t.kind, Kind::File(_)) => ErrorKind::LinkTargetNotFile {
                    target: target.to_string(),
                    found: t.kind.type_name(),
                },
                Some(_) => continue,
            };
            return Err(at(index, e, Some("target"), kind));
        }
    }
    Ok(())
}

impl Tree {
    /// Builds a tree from entries in any order.
    ///
    /// # Errors
    ///
    /// Returns the first rule the entries break, and where.
    pub fn new(mut entries: Vec<Entry>) -> Result<Self, Error> {
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        check(&entries)?;
        Ok(Self { entries })
    }

    /// Reads a tree from its canonical bytes and returns it with its
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns the first rule the bytes break, and where.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<(Self, Digest), Error> {
        let entries = read::tree(Self::text(bytes)?)?;
        check(&entries)?;
        Ok((Self { entries }, Digest::blake3(bytes)))
    }

    /// The bytes as text, if they are within the size limit and UTF-8.
    fn text(bytes: &[u8]) -> Result<&str, Error> {
        if bytes.len() > MAX_SIZE {
            return Err(Error::tree(
                None,
                ErrorKind::TooLarge {
                    max: MAX_SIZE,
                    len: bytes.len(),
                },
            ));
        }
        std::str::from_utf8(bytes).map_err(|_| Error::tree(None, ErrorKind::NotUtf8))
    }

    /// The tree's canonical bytes, checked against every rule.
    ///
    /// # Errors
    ///
    /// Returns the first rule the tree breaks, and where.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let bytes = encode::text(&self.entries).into_bytes();
        Self::from_canonical_bytes(&bytes)?;
        Ok(bytes)
    }

    /// The tree's identity: the BLAKE3 digest of its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns the first rule the tree breaks, and where.
    pub fn digest(&self) -> Result<Digest, Error> {
        Ok(Digest::blake3(&self.to_canonical_bytes()?))
    }

    /// The entries, sorted by path.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry at `path`, if there is one.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&Entry> {
        self.entries
            .binary_search_by(|e| e.path.as_str().cmp(path))
            .ok()
            .and_then(|i| self.entries.get(i))
    }
}

/// The reader and writer this crate had before reading one entry at a
/// time, which built the whole tree as one JSON value. The tests hold the
/// new ones to them.
#[cfg(test)]
impl Tree {
    fn from_canonical_bytes_by_value(bytes: &[u8]) -> Result<(Self, Digest), Error> {
        use ordin_core::json;
        let text = Self::text(bytes)?;
        let value = json::parse(text).map_err(|e| Error::tree(None, ErrorKind::Json(e.0)))?;
        same_encoding(text, &json::canonical(&value))?;
        let entries = decode::tree(&value)?;
        check(&entries)?;
        let tree = Self { entries };
        same_encoding(text, &json::canonical(&encode::tree(&tree.entries)))?;
        Ok((tree, Digest::blake3(bytes)))
    }

    fn to_canonical_bytes_by_value(&self) -> String {
        ordin_core::json::canonical(&encode::tree(&self.entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_different_encoding_is_refused_where_it_differs() {
        assert!(same_encoding("{}", "{}").is_ok());
        assert_eq!(
            same_encoding("{\"a\":1}", "{\"a\":2}").unwrap_err().kind,
            ErrorKind::NotCanonical { at: 5 }
        );
    }

    const EVERYTHING: &[u8] = include_bytes!("../tests/data/everything.json");

    /// Both readers give the same answer: the same tree and identity, or a
    /// refusal. The errors may differ.
    fn agree(bytes: &[u8]) -> bool {
        let new = Tree::from_canonical_bytes(bytes);
        let old = Tree::from_canonical_bytes_by_value(bytes);
        assert_eq!(
            new.as_ref().ok(),
            old.as_ref().ok(),
            "{}",
            String::from_utf8_lossy(bytes)
        );
        new.is_ok()
    }

    /// The fixture with each change applied: a byte changed, inserted or
    /// removed.
    fn changed(changes: &[(usize, u8, u8)]) -> Vec<u8> {
        let mut bytes = EVERYTHING.to_vec();
        for &(at, byte, how) in changes {
            let i = at % (bytes.len() + 1);
            match how {
                0 if i < bytes.len() => bytes[i] ^= byte.max(1),
                1 => bytes.insert(i, byte),
                _ if i < bytes.len() => {
                    bytes.remove(i);
                }
                _ => {}
            }
        }
        bytes
    }

    #[test]
    fn both_readers_read_the_fixture_and_refuse_it_spaced_out() {
        assert!(agree(EVERYTHING));
        let value: serde_json::Value = serde_json::from_slice(EVERYTHING).unwrap();
        assert!(!agree(&serde_json::to_vec_pretty(&value).unwrap()));
        assert!(agree(br#"{"entries":[],"ordin-tree":1}"#));
        for refused in [
            &b"[]"[..],
            br#"{"ordin-tree":1}"#,
            br#"{"entries":{},"ordin-tree":1}"#,
        ] {
            assert!(!agree(refused));
        }
    }

    #[test]
    fn both_readers_refuse_too_many_entries() {
        let entries: Vec<String> = (0..=MAX_ENTRIES)
            .map(|i| format!(r#"{{"path":"/d{i:06}","type":"dir"}}"#))
            .collect();
        let text = format!(r#"{{"entries":[{}],"ordin-tree":1}}"#, entries.join(","));
        assert!(!agree(text.as_bytes()));
    }

    #[test]
    fn changed_bytes_are_sometimes_accepted() {
        // The comparison below has teeth only if some changes are read:
        // a changed digit of a digest or a size still makes a tree.
        let accepted = (0..EVERYTHING.len())
            .filter(|&at| agree(&changed(&[(at, 1, 0)])))
            .count();
        assert!(accepted > 100, "{accepted}");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4096))]

        #[test]
        fn both_readers_agree_on_changed_bytes(
            changes in proptest::collection::vec(
                (0..usize::MAX, proptest::prelude::any::<u8>(), 0u8..3),
                1..4,
            )
        ) {
            agree(&changed(&changes));
        }

        #[test]
        fn both_writers_agree(keep in proptest::collection::vec(proptest::prelude::any::<bool>(), 32)) {
            let (tree, _) = Tree::from_canonical_bytes(EVERYTHING).unwrap();
            let entries = tree
                .entries()
                .iter()
                .zip(keep)
                .filter(|(_, keep)| *keep)
                .map(|(e, _)| e.clone())
                .collect();
            if let Ok(tree) = Tree::new(entries) {
                let bytes = tree.to_canonical_bytes().unwrap();
                proptest::prop_assert_eq!(&bytes, &tree.to_canonical_bytes_by_value().into_bytes());
                proptest::prop_assert!(agree(&bytes));
            }
        }
    }
}
