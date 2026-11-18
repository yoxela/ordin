// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Account names and file modes, shared by manifests and trees.

use core::fmt;
use core::str::FromStr;

use crate::error::{Error, Kind};
use crate::serde_str::impl_serde;

/// The longest account name, in bytes.
pub const ACCOUNT_MAX: usize = 32;

/// A user or group name: `[A-Za-z_][A-Za-z0-9_-]*`, 1 to 32 bytes, as
/// systemd allows (`_apt`, `systemd-network`, `Debian-exim`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Account(String);

impl Account {
    /// The name, exactly as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `root`, the default owner and group.
    #[must_use]
    pub fn root() -> Self {
        Self("root".to_owned())
    }

    /// Whether this is `root`.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0 == "root"
    }
}

impl FromStr for Account {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        if text.is_empty() {
            return Err(Error::Empty(Kind::Account));
        }
        if text.len() > ACCOUNT_MAX {
            return Err(Error::TooLong {
                what: Kind::Account,
                max: ACCOUNT_MAX,
                len: text.len(),
            });
        }
        if !text.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            return Err(Error::BadStart {
                what: Kind::Account,
                rule: "a letter or '_'",
                text: text.to_owned(),
            });
        }
        match text
            .char_indices()
            .find(|&(_, c)| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        {
            Some((at, ch)) => Err(Error::BadChar {
                what: Kind::Account,
                ch,
                at,
                rule: "use letters, digits, '_' and '-'",
            }),
            None => Ok(Self(text.to_owned())),
        }
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl_serde!(Account);

/// A file mode: permission bits plus setuid, setgid and sticky, written as
/// four octal digits (`"0750"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mode(u16);

impl Mode {
    /// `0644`, a file's usual mode.
    pub const FILE: Self = Self(0o644);

    /// `0755`, a directory's or program's usual mode.
    pub const DIR: Self = Self(0o755);

    /// A mode from its value, at most `0o7777`.
    #[must_use]
    pub fn new(value: u16) -> Option<Self> {
        (value <= 0o7777).then_some(Self(value))
    }

    /// The mode's value.
    #[must_use]
    pub fn value(self) -> u16 {
        self.0
    }
}

impl FromStr for Mode {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        let bad = || Error::BadMode(text.to_owned());
        let [a, b, c, d] = text.as_bytes() else {
            return Err(bad());
        };
        let mut value = 0;
        for digit in [a, b, c, d] {
            if !(b'0'..=b'7').contains(digit) {
                return Err(bad());
            }
            value = value * 8 + u16::from(digit - b'0');
        }
        Ok(Self(value))
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

impl_serde!(Mode);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_follow_systemd() {
        for ok in [
            "_apt",
            "_chrony",
            "systemd-network",
            "Debian-exim",
            "a",
            "A9",
            &"a".repeat(32),
        ] {
            assert_eq!(ok.parse::<Account>().unwrap().as_str(), ok);
            assert_eq!(ok.parse::<Account>().unwrap().to_string(), ok);
        }
        for bad in [
            "",
            "1user",
            "-x",
            "us.er",
            "us+er",
            "us er",
            &"a".repeat(33),
        ] {
            assert!(bad.parse::<Account>().is_err(), "{bad:?}");
        }
        assert_eq!(
            "us.er".parse::<Account>().unwrap_err().to_string(),
            "an account name can't contain '.' (at byte 2); use letters, digits, '_' and '-'"
        );
        assert_eq!(
            "".parse::<Account>().unwrap_err(),
            Error::Empty(Kind::Account)
        );
        assert_eq!(
            "a".repeat(33).parse::<Account>().unwrap_err().to_string(),
            "an account name is at most 32 bytes; this one is 33"
        );
        assert_eq!(
            "9x".parse::<Account>().unwrap_err().to_string(),
            "an account name must start with a letter or '_': \"9x\""
        );
    }

    #[test]
    fn root_is_the_default_account() {
        assert_eq!(Account::root().as_str(), "root");
        assert!(Account::root().is_root());
        assert!(!"_apt".parse::<Account>().unwrap().is_root());
        assert!(!"rootx".parse::<Account>().unwrap().is_root());
    }

    #[test]
    fn modes_are_four_octal_digits() {
        assert_eq!("0750".parse::<Mode>().unwrap().value(), 0o750);
        assert_eq!("0750".parse::<Mode>().unwrap().to_string(), "0750");
        assert_eq!("7777".parse::<Mode>().unwrap().value(), 0o7777);
        assert_eq!("4755".parse::<Mode>().unwrap().value(), 0o4755);
        assert_eq!("0001".parse::<Mode>().unwrap().value(), 1);
        for bad in ["750", "00750", "0758", "075a", "", "08", "-750", "+750"] {
            assert_eq!(
                bad.parse::<Mode>().unwrap_err(),
                Error::BadMode(bad.to_owned()),
                "{bad:?}"
            );
        }
        assert_eq!(Mode::new(0o644).unwrap().to_string(), "0644");
        assert_eq!(Mode::FILE.to_string(), "0644");
        assert_eq!(Mode::DIR.to_string(), "0755");
        assert_eq!(Mode::new(0o7777).unwrap().value(), 0o7777);
        assert!(Mode::new(0o10000).is_none());
        assert_eq!(
            Error::BadMode("75".into()).to_string(),
            "a mode is four octal digits, such as \"0750\": \"75\""
        );
    }

    #[test]
    fn serde_uses_the_text_form() {
        let a: Account = serde_json::from_str("\"_apt\"").unwrap();
        assert_eq!(serde_json::to_string(&a).unwrap(), "\"_apt\"");
        assert!(serde_json::from_str::<Account>("\"1x\"").is_err());
        let m: Mode = serde_json::from_str("\"0755\"").unwrap();
        assert_eq!(serde_json::to_string(&m).unwrap(), "\"0755\"");
        assert!(serde_json::from_str::<Mode>("\"0855\"").is_err());
    }
}
