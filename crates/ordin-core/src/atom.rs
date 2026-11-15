// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Atoms: what a dependency names.

use core::fmt;
use core::str::FromStr;

use crate::error::Error;
use crate::name::{Capability, FilePath, PackageName, Soname};

/// What a dependency can name: a package, a capability (`cap:`), a shared
/// library (`so:`) or a file (`file:`).
///
/// A bare name is a package. The prefixes tell the other three apart, and
/// none of the four can contain the characters the dependency language
/// uses for operators and brackets.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Atom {
    /// A package, by name: `nginx`.
    Package(PackageName),
    /// A capability: `cap:http-server`.
    Cap(Capability),
    /// A shared library: `so:libssl.so.3`.
    So(Soname),
    /// A file: `file:/usr/bin/python3`.
    File(FilePath),
}

impl FromStr for Atom {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        if let Some(rest) = text.strip_prefix("cap:") {
            return rest.parse().map(Self::Cap);
        }
        if let Some(rest) = text.strip_prefix("so:") {
            return rest.parse().map(Self::So);
        }
        if let Some(rest) = text.strip_prefix("file:") {
            return rest.parse().map(Self::File);
        }
        if text.contains(':') {
            return Err(Error::UnknownPrefix(text.chars().take(64).collect()));
        }
        text.parse().map(Self::Package)
    }
}

impl fmt::Display for Atom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(name) => write!(f, "{name}"),
            Self::Cap(name) => write!(f, "cap:{name}"),
            Self::So(name) => write!(f, "so:{name}"),
            Self::File(path) => write!(f, "file:{path}"),
        }
    }
}

crate::serde_str::impl_serde!(Atom);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Kind;

    fn atom(text: &str) -> Atom {
        text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn each_kind_of_atom_parses_and_shows_unchanged() {
        assert!(matches!(atom("nginx"), Atom::Package(n) if n.as_str() == "nginx"));
        assert!(matches!(atom("cap:http-server"), Atom::Cap(c) if c.as_str() == "http-server"));
        assert!(matches!(atom("so:libssl.so.3"), Atom::So(s) if s.as_str() == "libssl.so.3"));
        assert!(
            matches!(atom("file:/usr/bin/python3"), Atom::File(p) if p.as_str() == "/usr/bin/python3")
        );
        for text in [
            "nginx",
            "cap:http-server",
            "so:libssl.so.3",
            "file:/usr/bin/python3",
            "cap:and",
        ] {
            assert_eq!(atom(text).to_string(), text);
        }
    }

    #[test]
    fn the_part_after_the_prefix_is_checked() {
        let err = |text: &str| text.parse::<Atom>().unwrap_err();
        assert_eq!(err("cap:"), Error::Empty(Kind::Capability));
        assert_eq!(err("so:"), Error::Empty(Kind::Soname));
        assert_eq!(err("file:"), Error::Empty(Kind::FilePath));
        assert!(matches!(err("file:usr"), Error::BadPath { .. }));
        assert!(matches!(
            err("cap:Big"),
            Error::BadChar {
                what: Kind::Capability,
                ..
            }
        ));
        assert!(matches!(
            err("so:a b"),
            Error::BadChar {
                what: Kind::Soname,
                ..
            }
        ));
        assert_eq!(err("and"), Error::Reserved("and".into()));
        assert!(matches!(
            err("Nginx"),
            Error::BadChar {
                what: Kind::PackageName,
                ..
            }
        ));
    }

    #[test]
    fn an_unknown_prefix_is_named() {
        let err = |text: &str| text.parse::<Atom>().unwrap_err();
        assert_eq!(err("pkg:nginx"), Error::UnknownPrefix("pkg:nginx".into()));
        assert_eq!(err("CAP:x"), Error::UnknownPrefix("CAP:x".into()));
        assert_eq!(err(":x"), Error::UnknownPrefix(":x".into()));
        assert_eq!(
            err(&format!("x:{}", "a".repeat(100))),
            Error::UnknownPrefix(format!("x:{}", "a".repeat(62)))
        );
    }
}
