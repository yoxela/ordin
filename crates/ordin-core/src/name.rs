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
/// The longest file path, in bytes (Linux's `PATH_MAX`).
pub const PATH_MAX: usize = 4096;

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
    /// A shared library name, the text after `so:`: ASCII letters, digits,
    /// `.`, `_`, `+` and `-`, up to 255 bytes, and not `.` or `..`.
    Soname,
    check_soname
);

name_type!(
    /// A file path, the text after `file:`: absolute and normalized (no
    /// `.` or `..` parts, no `//`, no trailing `/`), printable ASCII
    /// without spaces or `( ) [ ] ,`, up to 4096 bytes.
    FilePath,
    check_file_path
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
    if text.is_empty() {
        return Err(Error::Empty(what));
    }
    if text.len() > SONAME_MAX {
        return Err(Error::TooLong {
            what,
            max: SONAME_MAX,
            len: text.len(),
        });
    }
    if let Some((at, ch)) = text
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
    if text == "." || text == ".." {
        return Err(Error::BadStart {
            what,
            rule: "a name, not '.' or '..'",
            text: text.to_owned(),
        });
    }
    Ok(())
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
    if let Some((at, ch)) = text
        .char_indices()
        .find(|&(_, c)| !c.is_ascii_graphic() || matches!(c, '(' | ')' | '[' | ']' | ','))
    {
        return Err(Error::BadChar {
            what,
            ch,
            at,
            rule: "use printable ASCII without spaces or '(', ')', '[', ']' and ','",
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
    fn names_order_and_compare_by_their_text() {
        let a: PackageName = "aa".parse().unwrap();
        let b: PackageName = "ab".parse().unwrap();
        assert!(a < b);
        assert_ne!(a, b);
    }
}
