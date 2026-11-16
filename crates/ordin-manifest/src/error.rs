// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Why a manifest was refused, and where.

use std::fmt;

/// One step in a path to a field: an object key or an array position.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Segment {
    /// A field of an object.
    Key(String),
    /// A key of an object used as a map (a facet name, a license ID, a
    /// phase): shown as itself, written `*` in `ignorable` paths.
    Entry(String),
    /// A position in an array.
    Index(usize),
}

/// Where in a manifest a field is: `declares.users[2].name`.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Path(pub Vec<Segment>);

impl Path {
    /// The path one key further down.
    #[must_use]
    pub fn key(&self, key: &str) -> Self {
        let mut p = self.clone();
        p.0.push(Segment::Key(key.to_owned()));
        p
    }

    /// The path one map entry further down.
    #[must_use]
    pub fn entry(&self, key: &str) -> Self {
        let mut p = self.clone();
        p.0.push(Segment::Entry(key.to_owned()));
        p
    }

    /// The path one array position further down.
    #[must_use]
    pub fn index(&self, i: usize) -> Self {
        let mut p = self.clone();
        p.0.push(Segment::Index(i));
        p
    }

    /// The path as `ignorable` writes it: without array positions, and
    /// with map keys as `*`: `declares.users.uid`, `facets.*.size`.
    #[must_use]
    pub fn schema(&self) -> String {
        let keys: Vec<&str> = self
            .0
            .iter()
            .filter_map(|s| match s {
                Segment::Key(k) => Some(k.as_str()),
                Segment::Entry(_) => Some("*"),
                Segment::Index(_) => None,
            })
            .collect();
        keys.join(".")
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("the manifest");
        }
        for (i, segment) in self.0.iter().enumerate() {
            match segment {
                Segment::Key(k) | Segment::Entry(k) if i == 0 => write!(f, "{k}")?,
                Segment::Key(k) | Segment::Entry(k) => write!(f, ".{k}")?,
                Segment::Index(n) => write!(f, "[{n}]")?,
            }
        }
        Ok(())
    }
}

/// A refused manifest: where, and why.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {kind}")]
pub struct Error {
    /// The field.
    pub path: Path,
    /// What is wrong.
    pub kind: ErrorKind,
}

impl Error {
    /// An error at `path`.
    #[must_use]
    pub fn at(path: &Path, kind: ErrorKind) -> Self {
        Self {
            path: path.clone(),
            kind,
        }
    }
}

/// What is wrong with a manifest.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Larger than [`MAX_SIZE`](crate::MAX_SIZE).
    #[error("a manifest is at most {max} bytes; this one is {len}")]
    TooLarge {
        /// The limit.
        max: usize,
        /// The manifest's size.
        len: usize,
    },
    /// Not UTF-8.
    #[error("a manifest is UTF-8 text")]
    NotUtf8,
    /// Not acceptable JSON.
    #[error("{0}")]
    Json(String),
    /// Valid, but not its own canonical encoding.
    #[error("the bytes aren't canonical JSON (RFC 8785); they first differ at byte {at}")]
    NotCanonical {
        /// The first differing byte.
        at: usize,
    },
    /// A format version this reader doesn't know.
    #[error("this is manifest format {0}; Ordin reads format 1")]
    UnknownFormat(i64),
    /// A required field is missing.
    #[error("the field {0:?} is required")]
    Missing(&'static str),
    /// A field this format doesn't define, and `ignorable` doesn't list.
    #[error("unknown field {0:?}")]
    UnknownField(String),
    /// `ignorable` names a field the format defines.
    #[error("{0:?} is a field of this format, so it can't be ignorable")]
    KnownIgnorable(String),
    /// The wrong JSON type.
    #[error("expected {expected}, found {found}")]
    WrongType {
        /// What the schema wants.
        expected: &'static str,
        /// What is there.
        found: &'static str,
    },
    /// A value that isn't one of the allowed ones.
    #[error("{found:?} isn't one of {allowed}")]
    UnknownValue {
        /// What is there.
        found: String,
        /// The allowed values.
        allowed: String,
    },
    /// A field set to its default, which must be left out.
    #[error("this is the default value, so the field must be left out")]
    DefaultValue,
    /// An empty array or object, which must be left out.
    #[error("empty, so it must be left out")]
    Empty,
    /// A set or sorted array out of order: the first element was found
    /// before the second, which must come first.
    #[error("not in order: {1:?} must come before {0:?}")]
    NotSorted(String, String),
    /// A set with a repeated element.
    #[error("{0:?} appears twice")]
    Duplicate(String),
    /// Text that isn't in its canonical form.
    #[error("not in canonical form; write it as {0:?}")]
    NotCanonicalText(String),
    /// A value outside its allowed range or length.
    #[error("{0}")]
    OutOfRange(String),
    /// A value that breaks its grammar.
    #[error("{0}")]
    Invalid(String),
    /// A rule linking several fields.
    #[error("{0}")]
    Rule(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_show_keys_and_positions() {
        let p = Path::default()
            .key("declares")
            .key("users")
            .index(2)
            .key("name");
        assert_eq!(p.to_string(), "declares.users[2].name");
        assert_eq!(p.schema(), "declares.users.name");
        assert_eq!(Path::default().to_string(), "the manifest");
        assert_eq!(Path::default().index(0).key("a").to_string(), "[0].a");
        let facet = Path::default().key("facets").entry("doc").key("size");
        assert_eq!(facet.to_string(), "facets.doc.size");
        assert_eq!(facet.schema(), "facets.*.size");
        assert_eq!(Path::default().entry("x").to_string(), "x");
    }

    #[test]
    fn errors_say_where_and_why() {
        let p = Path::default().key("facets").key("debug").key("default");
        assert_eq!(
            Error::at(&p, ErrorKind::DefaultValue).to_string(),
            "facets.debug.default: this is the default value, so the field must be left out"
        );
        for (kind, text) in [
            (
                ErrorKind::TooLarge { max: 1, len: 2 },
                "a manifest is at most 1 bytes; this one is 2",
            ),
            (ErrorKind::NotUtf8, "a manifest is UTF-8 text"),
            (ErrorKind::Json("bad".into()), "bad"),
            (
                ErrorKind::NotCanonical { at: 3 },
                "the bytes aren't canonical JSON (RFC 8785); they first differ at byte 3",
            ),
            (
                ErrorKind::UnknownFormat(2),
                "this is manifest format 2; Ordin reads format 1",
            ),
            (ErrorKind::Missing("name"), "the field \"name\" is required"),
            (ErrorKind::UnknownField("x".into()), "unknown field \"x\""),
            (
                ErrorKind::KnownIgnorable("name".into()),
                "\"name\" is a field of this format, so it can't be ignorable",
            ),
            (
                ErrorKind::WrongType {
                    expected: "a string",
                    found: "an integer",
                },
                "expected a string, found an integer",
            ),
            (
                ErrorKind::UnknownValue {
                    found: "x".into(),
                    allowed: "a or b".into(),
                },
                "\"x\" isn't one of a or b",
            ),
            (ErrorKind::Empty, "empty, so it must be left out"),
            (
                ErrorKind::NotSorted("b".into(), "a".into()),
                "not in order: \"a\" must come before \"b\"",
            ),
            (ErrorKind::Duplicate("a".into()), "\"a\" appears twice"),
            (
                ErrorKind::NotCanonicalText("a = 1".into()),
                "not in canonical form; write it as \"a = 1\"",
            ),
            (ErrorKind::OutOfRange("too big".into()), "too big"),
            (ErrorKind::Invalid("bad".into()), "bad"),
            (ErrorKind::Rule("rule".into()), "rule"),
        ] {
            assert_eq!(kind.to_string(), text);
        }
    }
}
