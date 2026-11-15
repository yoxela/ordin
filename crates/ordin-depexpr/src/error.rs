// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Why an expression was rejected, and where.

use ordin_core::Facet;

/// An error, with the byte offset in the expression where it was found.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("at byte {at}: {kind}")]
pub struct Error {
    /// The byte offset.
    pub at: usize,
    /// What is wrong.
    pub kind: ErrorKind,
}

/// What is wrong with an expression.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Nothing but whitespace.
    #[error("the expression is empty")]
    Empty,
    /// Longer than [`MAX_LEN`](crate::MAX_LEN).
    #[error("an expression is at most {max} bytes; this one is {len}")]
    TooLong {
        /// The limit.
        max: usize,
        /// The expression's length.
        len: usize,
    },
    /// Within [`MAX_LEN`](crate::MAX_LEN) as written, but longer once
    /// printed canonically (spaces are added around operators), so the
    /// canonical text couldn't be read back.
    #[error("an expression is at most {max} bytes in canonical form; this one is {len}")]
    CanonicalTooLong {
        /// The limit.
        max: usize,
        /// The canonical text's length.
        len: usize,
    },
    /// Nested deeper than [`MAX_DEPTH`](crate::MAX_DEPTH).
    #[error("parentheses and 'not' nest at most {0} deep")]
    TooDeep(usize),
    /// More than [`MAX_ATOMS`](crate::MAX_ATOMS) requirements.
    #[error("an expression names at most {0} atoms")]
    TooManyAtoms(usize),
    /// Something other than what the grammar allows here.
    #[error("expected {expected}, found {found}")]
    Expected {
        /// What the grammar allows.
        expected: &'static str,
        /// What is there, described.
        found: String,
    },
    /// `and` and `or` at the same level.
    #[error(
        "'and' and 'or' can't be mixed without parentheses; group one side, as in 'a and (b or c)'"
    )]
    MixedAndOr,
    /// A second `if` in the same group.
    #[error("only one 'if' per group; group the rest in parentheses")]
    ChainedIf,
    /// An atom that isn't valid.
    #[error(transparent)]
    Atom(ordin_core::Error),
    /// A facet that isn't valid.
    #[error(transparent)]
    Facet(ordin_core::Error),
    /// A version that isn't valid.
    #[error(transparent)]
    Version(ordin_version::Error),
    /// A version constraint on an atom that can't have one.
    #[error("only packages and cap: atoms can have a version constraint")]
    VersionNotAllowed,
    /// Facets on an atom that isn't a package.
    #[error("only package atoms can select facets")]
    FacetsNotAllowed,
    /// Facets given twice for one atom.
    #[error("facets can be given once per atom")]
    FacetsTwice,
    /// The same facet twice in one selector.
    #[error("the facet {0} is listed twice")]
    DuplicateFacet(Facet),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_say_what_and_where() {
        let e = Error {
            at: 7,
            kind: ErrorKind::Expected {
                expected: "an atom",
                found: "')'".into(),
            },
        };
        assert_eq!(e.to_string(), "at byte 7: expected an atom, found ')'");
        for (kind, text) in [
            (ErrorKind::Empty, "the expression is empty"),
            (
                ErrorKind::TooLong {
                    max: 4096,
                    len: 5000,
                },
                "an expression is at most 4096 bytes; this one is 5000",
            ),
            (
                ErrorKind::TooDeep(32),
                "parentheses and 'not' nest at most 32 deep",
            ),
            (
                ErrorKind::CanonicalTooLong {
                    max: 4096,
                    len: 4104,
                },
                "an expression is at most 4096 bytes in canonical form; this one is 4104",
            ),
            (
                ErrorKind::TooManyAtoms(256),
                "an expression names at most 256 atoms",
            ),
            (
                ErrorKind::ChainedIf,
                "only one 'if' per group; group the rest in parentheses",
            ),
            (
                ErrorKind::VersionNotAllowed,
                "only packages and cap: atoms can have a version constraint",
            ),
            (
                ErrorKind::FacetsNotAllowed,
                "only package atoms can select facets",
            ),
            (ErrorKind::FacetsTwice, "facets can be given once per atom"),
        ] {
            assert_eq!(kind.to_string(), text);
        }
        assert!(ErrorKind::MixedAndOr.to_string().contains("a and (b or c)"));
        let doc: Facet = "doc".parse().unwrap();
        assert_eq!(
            ErrorKind::DuplicateFacet(doc).to_string(),
            "the facet doc is listed twice"
        );
        let atom = ErrorKind::Atom(ordin_core::Error::Reserved("and".into()));
        assert!(atom.to_string().contains("keyword"));
        let facet = ErrorKind::Facet(ordin_core::Error::EmptyQualifier("locale:".into()));
        assert!(facet.to_string().contains("nothing after"));
        let version = ErrorKind::Version(ordin_version::Error::Empty);
        assert_eq!(version.to_string(), "a version can't be empty");
    }
}
