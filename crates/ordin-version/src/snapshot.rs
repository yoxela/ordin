// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Snapshot versions, for builds from a commit rather than a release.

use crate::{Error, Version};

/// Where a snapshot sits relative to the release it is named after.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position {
    /// After the release, on the way to the next one: `1.4.2^…`.
    After,
    /// Before the release, which isn't out yet: `1.5~…`.
    Before,
}

/// Builds the upstream version of a snapshot.
///
/// The date and commit count decide the ordering; the commit hash comes
/// last and is only there to read. Git hashes can't be ordered, so they
/// never decide anything.
///
/// | Call | Result |
/// | --- | --- |
/// | `snapshot(Some("1.4.2"), After, "20261112", 37, "3fa9c1e")` | `1.4.2^20261112.37.g3fa9c1e` |
/// | `snapshot(Some("1.5"), Before, "20261112", 12, "8b2d4a0")` | `1.5~20261112.12.g8b2d4a0` |
/// | `snapshot(None, After, "20261112", 37, "3fa9c1e")` | `0^20261112.37.g3fa9c1e` |
///
/// `None` is for a project with no release tags at all, which starts from
/// `0^`.
///
/// # Errors
///
/// Returns [`Error::Snapshot`] if `base` isn't a valid upstream version
/// without `-`, a snapshot before no release is asked for, `date` isn't a
/// real `YYYYMMDD` date, or `hash` isn't 7 to 64 lowercase hex digits.
pub fn snapshot(
    base: Option<&str>,
    position: Position,
    date: &str,
    commits: u32,
    hash: &str,
) -> Result<String, Error> {
    let base = match (base, position) {
        (Some(base), _) => base,
        (None, Position::After) => "0",
        (None, Position::Before) => {
            return Err(Error::Snapshot("a snapshot can't come before no release"));
        }
    };
    if Version::new(0, base, None, 0).is_err() {
        return Err(Error::Snapshot(
            "the base must be a valid upstream version without '-'",
        ));
    }
    if !is_date(date) {
        return Err(Error::Snapshot(
            "the date must be a real date written YYYYMMDD",
        ));
    }
    if !(7..=64).contains(&hash.len())
        || !hash
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Snapshot(
            "the commit hash must be 7 to 64 lowercase hex digits",
        ));
    }
    let mark = match position {
        Position::After => '^',
        Position::Before => '~',
    };
    let upstream = format!("{base}{mark}{date}.{commits}.g{hash}");
    // The result must itself be a valid upstream version.
    Version::new(0, &upstream, None, 0)
        .map(|_| upstream)
        .map_err(|_| Error::Snapshot("the snapshot version would be too long"))
}

/// A real calendar date written `YYYYMMDD`, from 1970 on.
fn is_date(text: &str) -> bool {
    if text.len() != 8 || !text.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let number = |range: core::ops::Range<usize>| {
        text.get(range)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or_default()
    };
    let (year, month, day) = (number(0..4), number(4..6), number(6..8));
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1970 && (1..=days).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use Position::{After, Before};

    fn v(text: &str) -> Version {
        text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn the_spec_examples() {
        assert_eq!(
            snapshot(Some("1.4.2"), After, "20261112", 37, "3fa9c1e").unwrap(),
            "1.4.2^20261112.37.g3fa9c1e"
        );
        assert_eq!(
            snapshot(Some("1.5"), Before, "20261112", 12, "8b2d4a0").unwrap(),
            "1.5~20261112.12.g8b2d4a0"
        );
        assert_eq!(
            snapshot(None, After, "20261112", 37, "3fa9c1e").unwrap(),
            "0^20261112.37.g3fa9c1e"
        );
    }

    #[test]
    fn snapshots_sort_between_their_releases_by_date_then_count() {
        let after = |date, n| v(&snapshot(Some("1.4.2"), After, date, n, "abcdef0").unwrap());
        let before = |date, n| v(&snapshot(Some("1.5"), Before, date, n, "abcdef0").unwrap());
        let ascending = [
            v("1.4.2"),
            after("20261112", 9),
            after("20261112", 10),
            after("20261113", 1),
            v("1.4.3"),
            before("20261201", 1),
            before("20261202", 1),
            v("1.5~rc1"),
            v("1.5"),
        ];
        for pair in ascending.windows(2) {
            assert!(pair[0] < pair[1], "{} < {}", pair[0], pair[1]);
        }
        // The hash never decides.
        let a = v(&snapshot(Some("1"), After, "20261112", 3, "fffffff").unwrap());
        let b = v(&snapshot(Some("1"), After, "20261112", 4, "0000000").unwrap());
        assert!(a < b);
        // A project with no tags sorts below its first release.
        assert!(v(&snapshot(None, After, "20261112", 1, "abcdef0").unwrap()) < v("0.1"));
    }

    #[test]
    fn bad_parts_are_refused() {
        let err = |base, position, date, hash| {
            snapshot(base, position, date, 1, hash)
                .unwrap_err()
                .to_string()
        };
        assert!(err(None, Before, "20261112", "abcdef0").contains("before no release"));
        assert!(err(Some("x1"), After, "20261112", "abcdef0").contains("valid upstream"));
        assert!(err(Some("1-2"), After, "20261112", "abcdef0").contains("valid upstream"));
        for date in [
            "2026111",
            "202611120",
            "2026-11-1",
            "20261301",
            "20260230",
            "20250229",
            "19691231",
            "20261100",
        ] {
            assert!(
                err(Some("1"), After, date, "abcdef0").contains("real date"),
                "{date}"
            );
        }
        let too_long = "a".repeat(65);
        for hash in ["abcdef", "ABCDEF0", "abcdefg", too_long.as_str()] {
            assert!(
                err(Some("1"), After, "20261112", hash).contains("hex digits"),
                "{hash}"
            );
        }
        let long = "1".repeat(240);
        assert!(err(Some(&long), After, "20261112", "abcdef0").contains("too long"));
    }

    #[test]
    fn leap_years_follow_the_calendar() {
        assert!(is_date("20240229"));
        assert!(is_date("20000229"));
        assert!(!is_date("19000229"));
        // A century that isn't a multiple of 400 is not a leap year; 1900
        // alone can't show it, because it is refused for being before 1970.
        assert!(!is_date("21000229"));
        assert!(is_date("21000228"));
        assert!(is_date("20260228"));
        assert!(!is_date("20260229"));
        assert!(is_date("19700101"));
        assert!(is_date("20261231"));
        assert!(is_date("20260430"));
        assert!(!is_date("20260431"));
    }
}
