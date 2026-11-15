// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Why a name, an atom or an architecture was rejected.

use core::fmt;

/// What kind of value an error is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A package name.
    PackageName,
    /// The name after `cap:`.
    Capability,
    /// The library name after `so:`.
    Soname,
    /// The path after `file:`.
    FilePath,
    /// A facet name.
    Facet,
    /// A symbol version node, after `@` in a soname.
    VersionNode,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PackageName => "a package name",
            Self::Capability => "a capability",
            Self::Soname => "a soname",
            Self::FilePath => "a file path",
            Self::Facet => "a facet",
            Self::VersionNode => "a symbol version node",
        })
    }
}

/// Why a value isn't valid.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Nothing was given.
    #[error("{0} can't be empty")]
    Empty(Kind),
    /// Shorter than the minimum.
    #[error("{what} is at least {min} characters; {text:?} is {len}")]
    TooShort {
        /// What was being parsed.
        what: Kind,
        /// The minimum length in bytes.
        min: usize,
        /// The text.
        text: String,
        /// Its length in bytes.
        len: usize,
    },
    /// Longer than the maximum.
    #[error("{what} is at most {max} bytes; this one is {len}")]
    TooLong {
        /// What was being parsed.
        what: Kind,
        /// The maximum length in bytes.
        max: usize,
        /// Its length in bytes.
        len: usize,
    },
    /// The first character can't start this kind of value.
    #[error("{what} must start with {rule}: {text:?}")]
    BadStart {
        /// What was being parsed.
        what: Kind,
        /// What it must start with.
        rule: &'static str,
        /// The text.
        text: String,
    },
    /// A character that isn't allowed.
    #[error("{what} can't contain {ch:?} (at byte {at}); {rule}")]
    BadChar {
        /// What was being parsed.
        what: Kind,
        /// The character.
        ch: char,
        /// Its byte offset.
        at: usize,
        /// Which characters are allowed.
        rule: &'static str,
    },
    /// A keyword of the dependency language.
    #[error("{0:?} is a keyword of the dependency language, so it can't be a package name")]
    Reserved(String),
    /// A path that isn't absolute and normalized.
    #[error("{text:?} isn't a usable file path: {reason}")]
    BadPath {
        /// The path.
        text: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A soname with `@` but no version node after it.
    #[error("the soname {0:?} has no version node after '@'")]
    EmptyVersionNode(String),
    /// A facet whose qualifier, after the `:`, is empty.
    #[error("the facet {0:?} has nothing after ':'")]
    EmptyQualifier(String),
    /// Text with a `:` whose prefix isn't `cap:`, `so:` or `file:`.
    #[error("{0:?} isn't an atom: an atom is a package name, or starts with cap:, so: or file:")]
    UnknownPrefix(String),
    /// An architecture Ordin doesn't know.
    #[error("unknown architecture {0:?}; Ordin knows x86_64, aarch64 and noarch")]
    UnknownArch(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_say_what_is_wrong() {
        assert_eq!(
            Error::Empty(Kind::Soname).to_string(),
            "a soname can't be empty"
        );
        assert_eq!(
            Error::TooShort {
                what: Kind::PackageName,
                min: 2,
                text: "a".into(),
                len: 1
            }
            .to_string(),
            "a package name is at least 2 characters; \"a\" is 1"
        );
        assert_eq!(
            Error::TooLong {
                what: Kind::FilePath,
                max: 4096,
                len: 5000
            }
            .to_string(),
            "a file path is at most 4096 bytes; this one is 5000"
        );
        assert_eq!(
            Error::BadStart {
                what: Kind::Capability,
                rule: "a lowercase letter or a digit",
                text: "-x".into()
            }
            .to_string(),
            "a capability must start with a lowercase letter or a digit: \"-x\""
        );
        assert_eq!(
            Error::BadChar {
                what: Kind::PackageName,
                ch: 'N',
                at: 0,
                rule: "use lowercase letters, digits, '+', '.' and '-'"
            }
            .to_string(),
            "a package name can't contain 'N' (at byte 0); use lowercase letters, digits, '+', '.' and '-'"
        );
        assert_eq!(
            Error::Reserved("and".into()).to_string(),
            "\"and\" is a keyword of the dependency language, so it can't be a package name"
        );
        assert_eq!(
            Error::BadPath {
                text: "usr".into(),
                reason: "it must be absolute"
            }
            .to_string(),
            "\"usr\" isn't a usable file path: it must be absolute"
        );
        assert!(
            Error::UnknownPrefix("x:y".into())
                .to_string()
                .contains("cap:, so: or file:")
        );
        assert!(
            Error::UnknownArch("i386".into())
                .to_string()
                .contains("x86_64, aarch64 and noarch")
        );
    }
}
