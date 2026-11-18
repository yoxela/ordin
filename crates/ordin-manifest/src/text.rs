// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The manifest's own small grammars: unit names, IDs, dates, URLs and
//! free text. Account names and modes live in `ordin-core`. Each check returns why a value is refused.

use std::fmt;
use std::str::FromStr;

/// Defines a validated string type around a check function.
macro_rules! text_type {
    ($(#[$doc:meta])* $name:ident, $check:path) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// The text, exactly as given.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(text: &str) -> Result<Self, String> {
                $check(text)?;
                Ok(Self(text.to_owned()))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

text_type!(
    /// A systemd unit name: `getty@.service`, `dev-disk-by\x2dlabel.mount`.
    UnitName,
    check_unit
);

text_type!(
    /// A setting, test or notice name: `[a-z0-9][a-z0-9.-]*`, 1 to 64
    /// bytes.
    Id,
    check_id
);

text_type!(
    /// An `https://` URL, up to 2,048 bytes of printable ASCII.
    Url,
    check_url
);

/// The unit types a package may declare.
const UNIT_TYPES: [&str; 9] = [
    ".service",
    ".socket",
    ".timer",
    ".path",
    ".mount",
    ".automount",
    ".swap",
    ".target",
    ".slice",
];

fn check_unit(text: &str) -> Result<(), String> {
    if text.len() > 255 {
        return Err(format!(
            "a unit name is at most 255 bytes; this one is {}",
            text.len()
        ));
    }
    let Some(stem) = UNIT_TYPES.iter().find_map(|t| text.strip_suffix(t)) else {
        return Err(format!(
            "{text:?} needs a unit type suffix: {}",
            UNIT_TYPES.join(", ")
        ));
    };
    let (prefix, instance) = match stem.split_once('@') {
        Some((p, i)) => (p, Some(i)),
        None => (stem, None),
    };
    if prefix.is_empty() {
        return Err(format!("{text:?} has no name before its suffix or '@'"));
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '-' | '\\');
    for part in std::iter::once(prefix).chain(instance) {
        if let Some(c) = part.chars().find(|&c| !allowed(c)) {
            return Err(format!("a unit name can't contain {c:?}: {text:?}"));
        }
        // A backslash only starts an \xNN escape: every piece after one
        // starts with 'x' and two hex digits. Splitting, not index
        // arithmetic, so the check always moves forward.
        let escapes_ok = part.split('\\').skip(1).all(|after| {
            matches!(after.as_bytes(), [b'x', high, low, ..]
                if high.is_ascii_hexdigit() && low.is_ascii_hexdigit())
        });
        if !escapes_ok {
            return Err(format!(
                "a '\\' in a unit name starts an \\xNN escape: {text:?}"
            ));
        }
    }
    Ok(())
}

fn check_id(text: &str) -> Result<(), String> {
    if text.is_empty() || text.len() > 64 {
        return Err(format!(
            "a name is 1 to 64 bytes; {text:?} is {}",
            text.len()
        ));
    }
    if !text.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return Err(format!(
            "a name starts with a lowercase letter or digit: {text:?}"
        ));
    }
    match text
        .chars()
        .find(|&c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'))
    {
        Some(c) => Err(format!(
            "a name uses lowercase letters, digits, '.' and '-'; {c:?} isn't allowed: {text:?}"
        )),
        None => Ok(()),
    }
}

fn check_url(text: &str) -> Result<(), String> {
    if text.len() > 2048 {
        return Err(format!(
            "a URL is at most 2048 bytes; this one is {}",
            text.len()
        ));
    }
    let Some(rest) = text.strip_prefix("https://") else {
        return Err(format!("a URL starts with https://: {text:?}"));
    };
    if rest.is_empty() || rest.starts_with('/') {
        return Err(format!("a URL needs a host: {text:?}"));
    }
    printable_ascii(text, "a URL")
}

/// Printable ASCII, no spaces.
pub(crate) fn printable_ascii(text: &str, what: &str) -> Result<(), String> {
    match text.chars().find(|c| !c.is_ascii_graphic()) {
        Some(c) => Err(format!(
            "{what} is printable ASCII without spaces; {c:?} isn't allowed"
        )),
        None => Ok(()),
    }
}

/// Free text of 1 to `max` characters, with no control characters except
/// `\n` where `lines` allows it.
pub(crate) fn free_text(text: &str, max: usize, lines: bool) -> Result<(), String> {
    let count = text.chars().count();
    if count == 0 || count > max {
        return Err(format!("this text is 1 to {max} characters; it is {count}"));
    }
    match text
        .chars()
        .find(|&c| c.is_control() && !(lines && c == '\n'))
    {
        Some(c) => Err(format!(
            "control character {c:?} isn't allowed{}",
            if lines {
                "; only '\\n' is"
            } else {
                "; this is one line"
            }
        )),
        None => Ok(()),
    }
}

/// A calendar date, `YYYY-MM-DD`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

impl FromStr for Date {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let bad = || format!("a date is YYYY-MM-DD, a real calendar date: {text:?}");
        let b = text.as_bytes();
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return Err(bad());
        }
        let num = |range: std::ops::Range<usize>| {
            text.get(range)
                .filter(|s| s.bytes().all(|c| c.is_ascii_digit()))
                .and_then(|s| s.parse::<u16>().ok())
        };
        let (Some(year), Some(month), Some(day)) = (num(0..4), num(5..7), num(8..10)) else {
            return Err(bad());
        };
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return Err(bad()),
        };
        if !(1..=days).contains(&day) || year < 1970 {
            return Err(bad());
        }
        Ok(Self {
            year,
            month: u8::try_from(month).map_err(|_| bad())?,
            day: u8::try_from(day).map_err(|_| bad())?,
        })
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_follow_systemd() {
        for ok in [
            "nginx.service",
            "getty@.service",
            "getty@tty1.service",
            "dev-disk-by\\x2dlabel.mount",
            "a\\x2d\\x2Db.mount",
            "\\x2d.mount",
            "getty@a\\x2d.service",
            "foo.socket",
            "a:b_c.d-e.timer",
            "x.slice",
        ] {
            assert_eq!(ok.parse::<UnitName>().unwrap().to_string(), ok);
        }
        let err = |t: &str| t.parse::<UnitName>().unwrap_err();
        assert!(err("nginx").contains("suffix"));
        assert!(err("nginx.scope").contains("suffix"));
        assert!(err(".service").contains("no name"));
        assert!(err("@x.service").contains("no name"));
        assert!(err("a b.service").contains("' '"));
        assert!(err("a\\x2.service").contains("\\xNN"));
        assert!(err("a\\y20.service").contains("\\xNN"));
        assert!(err("a\\.service").contains("\\xNN"));
        assert!(err("a\\xg0.service").contains("\\xNN"));
        assert!(err("a\\x0g.service").contains("\\xNN"));
        assert!(err("a\\x2d\\.service").contains("\\xNN"));
        assert!(err("a\\\\x2d.service").contains("\\xNN"));
        assert!(err("getty@a\\x2.service").contains("\\xNN"));
        assert!(err(&format!("{}.service", "a".repeat(250))).contains("255"));
    }

    #[test]
    fn ids_urls_and_free_text() {
        assert!("listen-port".parse::<Id>().is_ok());
        assert!("a.b".parse::<Id>().is_ok());
        for bad in ["", "-a", "Big", "a_b", &"a".repeat(65)] {
            assert!(bad.parse::<Id>().is_err(), "{bad:?}");
        }
        assert!("https://nginx.org/".parse::<Url>().is_ok());
        for bad in [
            "http://x",
            "https://",
            "https:///x",
            "https://a b",
            "ftp://x",
        ] {
            assert!(bad.parse::<Url>().is_err(), "{bad:?}");
        }
        assert!(
            format!("https://{}", "a".repeat(2041))
                .parse::<Url>()
                .is_err()
        );
        assert_eq!("https://a".parse::<Url>().unwrap().to_string(), "https://a");
        assert!(free_text("HTTP server", 120, false).is_ok());
        assert!(free_text("", 120, false).unwrap_err().contains("1 to 120"));
        assert!(free_text(&"é".repeat(121), 120, false).is_err());
        assert!(free_text(&"é".repeat(120), 120, false).is_ok());
        assert!(
            free_text("a\nb", 120, false)
                .unwrap_err()
                .contains("one line")
        );
        assert!(free_text("a\nb", 120, true).is_ok());
        assert!(
            free_text("a\tb", 120, true)
                .unwrap_err()
                .contains("only '\\n'")
        );
        assert!(printable_ascii("a b", "x").is_err());
    }

    #[test]
    fn limits_are_inclusive() {
        assert!(
            format!("{}.service", "a".repeat(247))
                .parse::<UnitName>()
                .is_ok()
        );
        assert!(
            format!("{}.service", "a".repeat(248))
                .parse::<UnitName>()
                .is_err()
        );
        assert!("a".repeat(64).parse::<Id>().is_ok());
        assert!(
            format!("https://{}", "a".repeat(2040))
                .parse::<Url>()
                .is_ok()
        );
        assert!(
            format!("https://{}", "a".repeat(2041))
                .parse::<Url>()
                .is_err()
        );
    }

    #[test]
    fn dates_check_both_separators_and_the_calendar() {
        for bad in ["2026x01-01", "2026-01x01", "2026-0101-", "20260-1-01"] {
            assert!(bad.parse::<Date>().is_err(), "{bad:?}");
        }
        for good in ["2000-02-29", "1970-01-01", "1996-02-29"] {
            assert!(good.parse::<Date>().is_ok(), "{good:?}");
        }
        assert!("1900-02-29".parse::<Date>().is_err());
    }

    #[test]
    fn dates_print_as_read() {
        assert_eq!(
            "2027-06-30".parse::<Date>().unwrap().to_string(),
            "2027-06-30"
        );
        assert!("2024-02-29".parse::<Date>().is_ok());
        for bad in [
            "2026-02-29",
            "2100-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-04-31",
            "2026-1-01",
            "2026/01/01",
            "1969-12-31",
            "+026-01-01",
            "2026-01-0x",
            "2026-01-00",
        ] {
            assert!(bad.parse::<Date>().is_err(), "{bad:?}");
        }
        let a: Date = "2026-01-02".parse().unwrap();
        let b: Date = "2026-02-01".parse().unwrap();
        assert!(a < b);
    }
}
