// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Package names, capabilities, sonames and file paths: the names that
//! atoms are made of.
//!
//! Each type can only hold a valid value. They are built by parsing, keep
//! the text exactly as given, and show it unchanged, so parsing what they
//! show gives back an equal value.

use core::fmt;
use core::str::FromStr;

use crate::error::{Error, Kind};

/// The shortest package name or capability, in bytes.
pub const NAME_MIN: usize = 2;
/// The longest package name or capability, in bytes.
pub const NAME_MAX: usize = 128;
/// The longest soname, in bytes (the longest file name Linux allows).
pub const SONAME_MAX: usize = 255;
/// The longest symbol version node after `@` in a soname, in bytes.
pub const VERSION_NODE_MAX: usize = 64;
/// The longest file path, in bytes (Linux's `PATH_MAX`).
pub const PATH_MAX: usize = 4096;
/// The longest facet name, in bytes.
pub const FACET_MAX: usize = 64;

/// The dependency language's keywords, which can't be package names.
pub const KEYWORDS: [&str; 4] = ["and", "or", "not", "if"];

/// Defines a validated string type with `FromStr`, `Display`, `as_str` and
/// conversions, around a check function.
macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident, $check:path) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// The text, exactly as parsed.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(text: &str) -> Result<Self, Error> {
                $check(text)?;
                Ok(Self(text.to_owned()))
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(text: String) -> Result<Self, Error> {
                $check(&text)?;
                Ok(Self(text))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        crate::serde_str::impl_serde!($name);
    };
}

name_type!(
    /// A package name: lowercase ASCII letters, digits, `+`, `.` and `-`,
    /// starting with a letter or digit, 2 to 128 bytes long, and not one of
    /// the dependency language's [`KEYWORDS`].
    ///
    /// Names are lowercase only, so `Nginx` can never pass for `nginx`.
    /// Every package name in Debian trixie fits, except `and`, which the
    /// importer renames.
    PackageName,
    check_package_name
);

name_type!(
    /// A capability, the name after `cap:`: the same grammar as a package
    /// name. The keywords are allowed here, because the `cap:` prefix
    /// already tells them apart.
    Capability,
    check_capability
);

name_type!(
    /// A shared library name, the text after `so:`: the library's soname
    /// (ASCII letters, digits, `.`, `_`, `+` and `-`, up to 255 bytes, not
    /// `.` or `..`), optionally followed by `@` and a symbol version node
    /// (`[A-Za-z0-9._]+`, up to 64 bytes): `libc.so.6@GLIBC_2.38`.
    ///
    /// A library provides one atom per version node it defines, so a
    /// requirement on a node is met by plain atom equality, and the bare
    /// soname never stands in for a versioned one.
    ///
    /// Atoms carry no architecture, since Yoxela has no multilib. `#` and
    /// `/`, which are invalid today, are reserved for a future qualifier,
    /// so adding one can't change the meaning of an existing atom.
    Soname,
    check_soname
);

name_type!(
    /// A file path, the text after `file:`: absolute and normalized (no
    /// `.` or `..` parts, no `//`, no trailing `/`), printable ASCII
    /// without spaces, brackets, `,` or the dependency operators
    /// `= ! < > ~`, up to 4096 bytes.
    FilePath,
    check_file_path
);

name_type!(
    /// A facet: a named part of a package, such as `runtime`, `doc` or
    /// `locale:pt_BR`. The name is `[a-z][a-z0-9-]*`, optionally followed
    /// by `:` and a qualifier of `[A-Za-z0-9_@.+-]+` (locale names keep
    /// their usual case), up to 64 bytes in all.
    Facet,
    check_facet
);

const NAME_RULE: &str = "use lowercase letters, digits, '+', '.' and '-'";

fn check_name(text: &str, what: Kind) -> Result<(), Error> {
    if text.is_empty() {
        return Err(Error::Empty(what));
    }
    if text.len() > NAME_MAX {
        return Err(Error::TooLong {
            what,
            max: NAME_MAX,
            len: text.len(),
        });
    }
    if let Some((at, ch)) = text.char_indices().find(|&(_, c)| {
        !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'))
    }) {
        return Err(Error::BadChar {
            what,
            ch,
            at,
            rule: NAME_RULE,
        });
    }
    if !text.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return Err(Error::BadStart {
            what,
            rule: "a lowercase letter or a digit",
            text: text.to_owned(),
        });
    }
    if text.len() < NAME_MIN {
        return Err(Error::TooShort {
            what,
            min: NAME_MIN,
            text: text.to_owned(),
            len: text.len(),
        });
    }
    Ok(())
}

fn check_package_name(text: &str) -> Result<(), Error> {
    check_name(text, Kind::PackageName)?;
    if KEYWORDS.contains(&text) {
        return Err(Error::Reserved(text.to_owned()));
    }
    Ok(())
}

fn check_capability(text: &str) -> Result<(), Error> {
    check_name(text, Kind::Capability)
}

fn check_soname(text: &str) -> Result<(), Error> {
    let what = Kind::Soname;
    let (library, node) = match text.split_once('@') {
        Some((library, node)) => (library, Some(node)),
        None => (text, None),
    };
    if library.is_empty() {
        return Err(Error::Empty(what));
    }
    if library.len() > SONAME_MAX {
        return Err(Error::TooLong {
            what,
            max: SONAME_MAX,
            len: library.len(),
        });
    }
    if let Some((at, ch)) = library
        .char_indices()
        .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-')))
    {
        return Err(Error::BadChar {
            what,
            ch,
            at,
            rule: "use letters, digits, '.', '_', '+' and '-'",
        });
    }
    if library == "." || library == ".." {
        return Err(Error::BadStart {
            what,
            rule: "a name, not '.' or '..'",
            text: text.to_owned(),
        });
    }
    let Some(node) = node else {
        return Ok(());
    };
    if node.is_empty() {
        return Err(Error::EmptyVersionNode(text.to_owned()));
    }
    if node.len() > VERSION_NODE_MAX {
        return Err(Error::TooLong {
            what: Kind::VersionNode,
            max: VERSION_NODE_MAX,
            len: node.len(),
        });
    }
    if let Some((at, ch)) = node
        .char_indices()
        .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_')))
    {
        return Err(Error::BadChar {
            what: Kind::VersionNode,
            ch,
            at: library.len() + 1 + at,
            rule: "use letters, digits, '.' and '_'",
        });
    }
    Ok(())
}

impl Soname {
    /// The library's soname, without any version node: `libc.so.6`.
    #[must_use]
    pub fn library(&self) -> &str {
        self.0
            .split_once('@')
            .map_or(self.as_str(), |(library, _)| library)
    }

    /// The symbol version node after `@`, if any: `GLIBC_2.38`.
    #[must_use]
    pub fn version_node(&self) -> Option<&str> {
        self.0.split_once('@').map(|(_, node)| node)
    }
}

fn check_file_path(text: &str) -> Result<(), Error> {
    let what = Kind::FilePath;
    if text.is_empty() {
        return Err(Error::Empty(what));
    }
    if text.len() > PATH_MAX {
        return Err(Error::TooLong {
            what,
            max: PATH_MAX,
            len: text.len(),
        });
    }
    if let Some((at, ch)) = text.char_indices().find(|&(_, c)| {
        !c.is_ascii_graphic()
            || matches!(c, '(' | ')' | '[' | ']' | ',' | '=' | '!' | '<' | '>' | '~')
    }) {
        return Err(Error::BadChar {
            what,
            ch,
            at,
            rule: "use printable ASCII without spaces, brackets, ',' or the operators '=', '!', '<', '>' and '~'",
        });
    }
    let bad = |reason| {
        Err(Error::BadPath {
            text: text.to_owned(),
            reason,
        })
    };
    let Some(rest) = text.strip_prefix('/') else {
        return bad("it must be absolute, starting with '/'");
    };
    if rest.is_empty() || rest.ends_with('/') {
        return bad("it can't end with '/'");
    }
    for part in rest.split('/') {
        match part {
            "" => return bad("it can't contain '//'"),
            "." | ".." => return bad("it can't contain '.' or '..' parts"),
            _ => {}
        }
    }
    Ok(())
}

fn check_facet(text: &str) -> Result<(), Error> {
    let what = Kind::Facet;
    if text.is_empty() {
        return Err(Error::Empty(what));
    }
    if text.len() > FACET_MAX {
        return Err(Error::TooLong {
            what,
            max: FACET_MAX,
            len: text.len(),
        });
    }
    let (base, qualifier) = match text.split_once(':') {
        Some((base, qualifier)) => (base, Some(qualifier)),
        None => (text, None),
    };
    if !base.starts_with(|c: char| c.is_ascii_lowercase()) {
        return Err(Error::BadStart {
            what,
            rule: "a lowercase letter",
            text: text.to_owned(),
        });
    }
    if let Some((at, ch)) = base
        .char_indices()
        .find(|&(_, c)| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
    {
        return Err(Error::BadChar {
            what,
            ch,
            at,
            rule: "the name uses lowercase letters, digits and '-'",
        });
    }
    let Some(qualifier) = qualifier else {
        return Ok(());
    };
    if qualifier.is_empty() {
        return Err(Error::EmptyQualifier(text.to_owned()));
    }
    let offset = base.len() + 1;
    if let Some((at, ch)) = qualifier
        .char_indices()
        .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | '+' | '-')))
    {
        return Err(Error::BadChar {
            what,
            ch,
            at: offset + at,
            rule: "the part after ':' uses letters, digits, '_', '@', '.', '+' and '-'",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err<T: FromStr<Err = Error>>(text: &str) -> Error {
        match text.parse::<T>() {
            Ok(_) => panic!("{text:?} parsed"),
            Err(e) => e,
        }
    }

    #[test]
    fn real_package_names_parse() {
        for name in [
            "nginx",
            "0ad",
            "libstdc++6",
            "python3.13",
            "g++",
            "golang-github-container-orchestrated-devices-container-device-interface-dev",
            "r2",
            "andor",
            "or-tools",
        ] {
            let parsed: PackageName = name.parse().unwrap();
            assert_eq!(parsed.as_str(), name);
            assert_eq!(parsed.to_string(), name);
            assert_eq!(parsed.as_ref(), name);
            assert_eq!(PackageName::try_from(name.to_owned()).unwrap(), parsed);
        }
    }

    #[test]
    fn package_names_are_checked() {
        assert_eq!(err::<PackageName>(""), Error::Empty(Kind::PackageName));
        assert_eq!(
            err::<PackageName>("a"),
            Error::TooShort {
                what: Kind::PackageName,
                min: 2,
                text: "a".into(),
                len: 1
            }
        );
        assert!("ab".parse::<PackageName>().is_ok());
        assert!("a".repeat(128).parse::<PackageName>().is_ok());
        assert_eq!(
            err::<PackageName>(&"a".repeat(129)),
            Error::TooLong {
                what: Kind::PackageName,
                max: 128,
                len: 129
            }
        );
        assert_eq!(
            err::<PackageName>("Nginx"),
            Error::BadChar {
                what: Kind::PackageName,
                ch: 'N',
                at: 0,
                rule: NAME_RULE
            }
        );
        for (text, ch, at) in [
            ("foo_bar", '_', 3),
            ("foo bar", ' ', 3),
            ("foo:bar", ':', 3),
            ("fóo", 'ó', 1),
            ("foo*", '*', 3),
        ] {
            assert_eq!(
                err::<PackageName>(text),
                Error::BadChar {
                    what: Kind::PackageName,
                    ch,
                    at,
                    rule: NAME_RULE
                },
                "{text}"
            );
        }
        for text in ["-foo", "+foo", ".foo"] {
            assert!(
                matches!(err::<PackageName>(text), Error::BadStart { .. }),
                "{text}"
            );
        }
        // A single bad first character is reported as a bad start, not as
        // too short.
        assert!(matches!(err::<PackageName>("-"), Error::BadStart { .. }));
    }

    #[test]
    fn the_keywords_are_not_package_names() {
        for word in KEYWORDS {
            assert_eq!(err::<PackageName>(word), Error::Reserved(word.to_owned()));
            // They are fine as capabilities.
            assert!(word.len() < NAME_MIN || word.parse::<Capability>().is_ok());
        }
        assert!("and".parse::<Capability>().is_ok());
        assert!("not".parse::<Capability>().is_ok());
    }

    #[test]
    fn capabilities_follow_the_package_name_grammar() {
        assert!("http-server".parse::<Capability>().is_ok());
        assert!(matches!(
            err::<Capability>("Mta"),
            Error::BadChar {
                what: Kind::Capability,
                ..
            }
        ));
        assert!(matches!(
            err::<Capability>("x"),
            Error::TooShort {
                what: Kind::Capability,
                ..
            }
        ));
        assert_eq!(err::<Capability>(""), Error::Empty(Kind::Capability));
    }

    #[test]
    fn sonames_are_checked() {
        for name in [
            "libssl.so.3",
            "libgcc_s.so.1",
            "libstdc++.so.6",
            "ld-linux-x86-64.so.2",
            "a",
        ] {
            assert_eq!(name.parse::<Soname>().unwrap().as_str(), name);
        }
        assert_eq!(err::<Soname>(""), Error::Empty(Kind::Soname));
        assert!(matches!(
            err::<Soname>("lib/x.so"),
            Error::BadChar { ch: '/', at: 3, .. }
        ));
        assert!(matches!(
            err::<Soname>("lib x.so"),
            Error::BadChar { ch: ' ', .. }
        ));
        assert!(matches!(err::<Soname>("."), Error::BadStart { .. }));
        assert!(matches!(err::<Soname>(".."), Error::BadStart { .. }));
        assert!("...".parse::<Soname>().is_ok());
        assert!("a".repeat(255).parse::<Soname>().is_ok());
        // The 255-byte limit applies to the library name; the node has its own.
        assert!(
            format!("{}@GLIBC_2.38", "a".repeat(255))
                .parse::<Soname>()
                .is_ok()
        );
        assert!(matches!(
            err::<Soname>(&"a".repeat(256)),
            Error::TooLong {
                max: 255,
                len: 256,
                ..
            }
        ));
    }

    #[test]
    fn sonames_may_name_a_symbol_version_node() {
        for (text, library, node) in [
            ("libc.so.6@GLIBC_2.38", "libc.so.6", Some("GLIBC_2.38")),
            (
                "libstdc++.so.6@GLIBCXX_3.4.32",
                "libstdc++.so.6",
                Some("GLIBCXX_3.4.32"),
            ),
            (
                "libstdc++.so.6@CXXABI_1.3.13",
                "libstdc++.so.6",
                Some("CXXABI_1.3.13"),
            ),
            (
                "libssl.so.3@OPENSSL_3.0.0",
                "libssl.so.3",
                Some("OPENSSL_3.0.0"),
            ),
            ("libz.so.1@ZLIB_1.2.0", "libz.so.1", Some("ZLIB_1.2.0")),
            (
                "libc.so.6@GLIBC_PRIVATE",
                "libc.so.6",
                Some("GLIBC_PRIVATE"),
            ),
            ("libc.so.6", "libc.so.6", None),
        ] {
            let s: Soname = text.parse().unwrap();
            assert_eq!(s.as_str(), text);
            assert_eq!(s.to_string(), text);
            assert_eq!(s.library(), library);
            assert_eq!(s.version_node(), node);
        }
        // A node never matches the bare library: they are different atoms.
        let bare: Soname = "libc.so.6".parse().unwrap();
        let versioned: Soname = "libc.so.6@GLIBC_2.38".parse().unwrap();
        assert_ne!(bare, versioned);
    }

    #[test]
    fn bad_version_nodes_say_why() {
        assert_eq!(
            err::<Soname>("libc.so.6@"),
            Error::EmptyVersionNode("libc.so.6@".into())
        );
        assert_eq!(err::<Soname>("@GLIBC_2.38"), Error::Empty(Kind::Soname));
        let bad = |text: &str| match err::<Soname>(text) {
            Error::BadChar { what, ch, at, .. } => (what, ch, at),
            other => panic!("{text}: {other}"),
        };
        assert_eq!(bad("libc.so.6@GLIBC@2"), (Kind::VersionNode, '@', 15));
        assert_eq!(bad("libc.so.6@GLIBC-2"), (Kind::VersionNode, '-', 15));
        assert_eq!(bad("libc.so.6@GLIBC+2"), (Kind::VersionNode, '+', 15));
        assert_eq!(bad("libc.so.6@a b"), (Kind::VersionNode, ' ', 11));
        assert_eq!(bad("lib/c.so@GLIBC"), (Kind::Soname, '/', 3));
        assert_eq!(bad("libc#64.so"), (Kind::Soname, '#', 4));
        assert!(matches!(err::<Soname>(".@X"), Error::BadStart { .. }));
        assert!(format!("x@{}", "N".repeat(64)).parse::<Soname>().is_ok());
        assert_eq!(
            err::<Soname>(&format!("x@{}", "N".repeat(65))),
            Error::TooLong {
                what: Kind::VersionNode,
                max: 64,
                len: 65
            }
        );
        assert_eq!(
            err::<Soname>(&format!("{}@X", "a".repeat(256))),
            Error::TooLong {
                what: Kind::Soname,
                max: 255,
                len: 256
            }
        );
    }

    #[test]
    fn file_paths_are_absolute_and_normalized() {
        for path in [
            "/usr/bin/python3",
            "/a",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/opt/a.b/..c",
        ] {
            assert_eq!(path.parse::<FilePath>().unwrap().as_str(), path);
        }
        let reason = |text: &str| match err::<FilePath>(text) {
            Error::BadPath { reason, .. } => reason,
            other => panic!("{text}: {other}"),
        };
        assert!(reason("usr/bin").contains("absolute"));
        assert!(reason("/").contains("end with '/'"));
        assert!(reason("/usr/").contains("end with '/'"));
        assert!(reason("/usr//bin").contains("'//'"));
        assert!(reason("/usr/./bin").contains("'.' or '..'"));
        assert!(reason("/usr/../etc").contains("'.' or '..'"));
        assert!(reason("/..").contains("'.' or '..'"));
        assert_eq!(err::<FilePath>(""), Error::Empty(Kind::FilePath));
        for (text, ch) in [
            ("/a b", ' '),
            ("/a(b)", '('),
            ("/a]", ']'),
            ("/a,b", ','),
            ("/a\tb", '\t'),
            ("/é", 'é'),
            ("/a=b", '='),
            ("/a!", '!'),
            ("/a<b", '<'),
            ("/a>b", '>'),
            ("/srv/~x", '~'),
        ] {
            assert!(
                matches!(err::<FilePath>(text), Error::BadChar { ch: c, .. } if c == ch),
                "{text:?}"
            );
        }
        let longest = format!("/{}", "a".repeat(PATH_MAX - 1));
        assert!(longest.parse::<FilePath>().is_ok());
        assert!(matches!(
            err::<FilePath>(&format!("{longest}a")),
            Error::TooLong {
                max: 4096,
                len: 4097,
                ..
            }
        ));
    }

    #[test]
    fn facets_are_a_name_and_an_optional_qualifier() {
        for facet in [
            "runtime",
            "doc",
            "debug",
            "dev",
            "locale:pt_BR",
            "locale:sr@latin",
            "x1-y:a.b+c-d",
            "a",
        ] {
            assert_eq!(facet.parse::<Facet>().unwrap().as_str(), facet);
        }
        assert_eq!(err::<Facet>(""), Error::Empty(Kind::Facet));
        assert!(matches!(
            err::<Facet>("Doc"),
            Error::BadStart {
                what: Kind::Facet,
                ..
            }
        ));
        assert!(matches!(err::<Facet>("1doc"), Error::BadStart { .. }));
        assert!(matches!(err::<Facet>(":en"), Error::BadStart { .. }));
        assert!(matches!(
            err::<Facet>("doC"),
            Error::BadChar { ch: 'C', at: 2, .. }
        ));
        assert!(matches!(
            err::<Facet>("do_c"),
            Error::BadChar { ch: '_', at: 2, .. }
        ));
        assert_eq!(
            err::<Facet>("locale:"),
            Error::EmptyQualifier("locale:".into())
        );
        assert!(matches!(
            err::<Facet>("locale:pt BR"),
            Error::BadChar { ch: ' ', at: 9, .. }
        ));
        assert!(matches!(
            err::<Facet>("locale:a:b"),
            Error::BadChar { ch: ':', at: 8, .. }
        ));
        assert!(matches!(
            err::<Facet>("locale:a,b"),
            Error::BadChar { ch: ',', .. }
        ));
        assert!(matches!(
            err::<Facet>("doc]"),
            Error::BadChar { ch: ']', .. }
        ));
        assert!("a".repeat(64).parse::<Facet>().is_ok());
        assert!(matches!(
            err::<Facet>(&"a".repeat(65)),
            Error::TooLong {
                max: 64,
                len: 65,
                ..
            }
        ));
    }

    #[test]
    fn names_order_and_compare_by_their_text() {
        let a: PackageName = "aa".parse().unwrap();
        let b: PackageName = "ab".parse().unwrap();
        assert!(a < b);
        assert_ne!(a, b);
    }
}
