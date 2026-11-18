// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Why a tree was refused, and where.

use std::fmt;

use ordin_core::Algorithm;

/// Where in a tree an error is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    /// The entry, by position, and its path when it has a readable one.
    pub entry: Option<(usize, Option<String>)>,
    /// The field within the entry, or within the tree when there is no
    /// entry.
    pub field: Option<String>,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.entry {
            None => f.write_str("the tree")?,
            Some((index, None)) => write!(f, "entry {index}")?,
            Some((index, Some(path))) => write!(f, "entry {index} ({path:?})")?,
        }
        if let Some(field) = &self.field {
            write!(f, ", field {field:?}")?;
        }
        Ok(())
    }
}

/// A tree that breaks a rule.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{at}: {kind}")]
pub struct Error {
    /// Where.
    pub at: Location,
    /// What is wrong.
    pub kind: ErrorKind,
}

/// What is wrong with a tree.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Bigger than a tree may be.
    #[error("a tree is at most {max} bytes; this one is {len}")]
    TooLarge {
        /// The limit.
        max: usize,
        /// The size.
        len: usize,
    },
    /// Not UTF-8.
    #[error("a tree is UTF-8 JSON")]
    NotUtf8,
    /// Not acceptable JSON.
    #[error("not acceptable JSON: {0}")]
    Json(String),
    /// Valid, but not the canonical encoding.
    #[error("not canonical JSON (RFC 8785); the first difference is at byte {at}")]
    NotCanonical {
        /// The first byte that differs.
        at: usize,
    },
    /// A format version this reader doesn't know.
    #[error("unknown tree format {0}; this reader knows format 1")]
    UnknownFormat(String),
    /// A value of the wrong JSON type.
    #[error("expected {expected}, found {found}")]
    WrongType {
        /// The type the field needs.
        expected: &'static str,
        /// The type it has.
        found: &'static str,
    },
    /// A required field is missing.
    #[error("missing")]
    Missing,
    /// A field the format doesn't have.
    #[error("not a field of this entry type in tree format 1")]
    UnknownField,
    /// A field written with its default value, which must be left out.
    #[error("written with its default value, which must be left out")]
    DefaultValue,
    /// A value its grammar refuses.
    #[error("{0}")]
    Invalid(String),
    /// An entry type that can't be packaged.
    #[error(
        "{0:?} isn't an entry type; a tree holds file, dir, symlink and hardlink entries, and device nodes, sockets and FIFOs can't be packaged"
    )]
    UnknownType(String),
    /// A number beyond its limit.
    #[error("at most {max}; this is {value}")]
    OutOfRange {
        /// The limit.
        max: u64,
        /// The value.
        value: u64,
    },
    /// A digest of the wrong algorithm.
    #[error("must be a {expected} digest")]
    WrongAlgorithm {
        /// The algorithm the field needs.
        expected: Algorithm,
    },
    /// More entries than a tree may have.
    #[error("a tree has at most {max} entries; this one has {len}")]
    TooManyEntries {
        /// The limit.
        max: usize,
        /// The count.
        len: usize,
    },
    /// More extended attributes than an entry may have.
    #[error("an entry has at most {max} extended attributes; this one has {len}")]
    TooManyXattrs {
        /// The limit.
        max: usize,
        /// The count.
        len: usize,
    },
    /// An extended attribute value that is too long.
    #[error("an extended attribute value is at most {max} bytes; this one is {len}")]
    XattrTooLarge {
        /// The limit.
        max: usize,
        /// The length.
        len: usize,
    },
    /// Capabilities with both sets empty.
    #[error("capabilities need at least one permitted or inheritable capability")]
    EmptyCapabilities,
    /// An entry that comes before the previous one in byte order.
    #[error(
        "entries are sorted by the bytes of their paths, and this one comes before {previous:?}"
    )]
    NotSorted {
        /// The previous entry's path.
        previous: String,
    },
    /// A path that appears twice.
    #[error("the path appears twice")]
    Duplicate,
    /// A path whose parent directory isn't in the tree.
    #[error("its parent {parent:?} isn't in the tree; every parent must be a dir entry")]
    NoParent {
        /// The parent's path.
        parent: String,
    },
    /// A path whose parent is not a directory.
    #[error("its parent {parent:?} is a {found} entry; every parent must be a dir entry")]
    ParentNotDir {
        /// The parent's path.
        parent: String,
        /// The parent's entry type.
        found: &'static str,
    },
    /// A hard link to a path that isn't in the tree.
    #[error("the hard link's target {target:?} isn't in the tree")]
    LinkTargetMissing {
        /// The target.
        target: String,
    },
    /// A hard link to something other than a regular file.
    #[error("a hard link's target must be a file entry; {target:?} is a {found} entry")]
    LinkTargetNotFile {
        /// The target.
        target: String,
        /// The target's entry type.
        found: &'static str,
    },
}

impl Error {
    /// An error about the whole tree, or one of its own fields.
    pub(crate) fn tree(field: Option<&str>, kind: ErrorKind) -> Self {
        Self {
            at: Location {
                entry: None,
                field: field.map(str::to_owned),
            },
            kind,
        }
    }

    /// An error about an entry, or one of its fields.
    pub(crate) fn entry(
        index: usize,
        path: Option<&str>,
        field: Option<&str>,
        kind: ErrorKind,
    ) -> Self {
        Self {
            at: Location {
                entry: Some((index, path.map(str::to_owned))),
                field: field.map(str::to_owned),
            },
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations_name_the_entry_and_field() {
        assert_eq!(
            Error::tree(None, ErrorKind::NotUtf8).to_string(),
            "the tree: a tree is UTF-8 JSON"
        );
        assert_eq!(
            Error::tree(Some("ordin-tree"), ErrorKind::UnknownFormat("2".into())).to_string(),
            "the tree, field \"ordin-tree\": unknown tree format 2; this reader knows format 1"
        );
        assert_eq!(
            Error::entry(3, None, Some("path"), ErrorKind::Missing).to_string(),
            "entry 3, field \"path\": missing"
        );
        assert_eq!(
            Error::entry(4, Some("/usr/a"), None, ErrorKind::Duplicate).to_string(),
            "entry 4 (\"/usr/a\"): the path appears twice"
        );
        assert_eq!(
            Error::entry(
                0,
                Some("/usr"),
                Some("content"),
                ErrorKind::WrongAlgorithm {
                    expected: Algorithm::Blake3
                }
            )
            .to_string(),
            "entry 0 (\"/usr\"), field \"content\": must be a blake3 digest"
        );
    }
}
