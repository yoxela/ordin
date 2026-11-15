// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The version type: `[epoch:]upstream[-release[+uN]]`.

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use crate::compare::compare_text;
use crate::error::{Error, Part};

/// The longest version Ordin accepts, in bytes. It bounds the work any
/// comparison does.
pub const MAX_LEN: usize = 256;

/// A package version: `[epoch:]upstream[-release[+uN]]`.
///
/// - The **epoch** is a number, 0 when absent and hidden when 0. It is
///   only raised when upstream's numbering goes backward.
/// - The **upstream** version is the software's own. It starts with a
///   digit and may use letters, digits and `. + ~ ^`, plus `-` when a
///   release follows.
/// - The **release** is the packaging revision after the last `-`, using
///   letters, digits and `. + ~ ^`. Debian native packages have none.
/// - The **update level** `+uN` at the end of the release counts updates
///   on a base package. It is 0 when absent and hidden when 0.
///
/// Versions compare by epoch, then upstream, then release (with
/// [`compare_text`]), then update level. Equality follows the ordering, so
/// `1.0`, `1.00`, `0:1.0` and `1.0-0` are all equal, as they are in dpkg.
/// [`Display`](fmt::Display) keeps the text as written, apart from hiding
/// an epoch or update level of 0.
#[derive(Clone, Debug)]
pub struct Version {
    epoch: u32,
    upstream: String,
    release: Option<String>,
    update: u32,
}

impl Version {
    /// Makes a version from its parts, checking each.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the first part that is invalid.
    pub fn new(
        epoch: u32,
        upstream: &str,
        release: Option<&str>,
        update: u32,
    ) -> Result<Self, Error> {
        let len = upstream.len() + release.map_or(0, |r| r.len() + 1);
        if len > MAX_LEN {
            return Err(Error::TooLong(len));
        }
        check_upstream(upstream, release.is_some())?;
        if let Some(release) = release {
            check_release(release)?;
        }
        Ok(Self {
            epoch,
            upstream: upstream.to_owned(),
            release: release.map(str::to_owned),
            update,
        })
    }

    /// A bound made by this crate from a valid version, such as
    /// [`compatible_bound`](Self::compatible_bound). It is checked by
    /// construction, and may be a few bytes over [`MAX_LEN`].
    pub(crate) fn bound(epoch: u32, upstream: String) -> Self {
        Self {
            epoch,
            upstream,
            release: None,
            update: 0,
        }
    }

    /// The epoch, 0 when absent.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The upstream version.
    #[must_use]
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// The release without its update level, if there is one.
    #[must_use]
    pub fn release(&self) -> Option<&str> {
        self.release.as_deref()
    }

    /// The update level, 0 when absent.
    #[must_use]
    pub fn update(&self) -> u32 {
        self.update
    }
}

impl FromStr for Version {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        if text.is_empty() {
            return Err(Error::Empty);
        }
        if text.len() > MAX_LEN {
            return Err(Error::TooLong(text.len()));
        }
        let (epoch, rest) = match text.split_once(':') {
            Some((epoch, rest)) => (parse_epoch(epoch)?, rest),
            None => (0, text),
        };
        let Some((upstream, release)) = rest.rsplit_once('-') else {
            return Self::new(epoch, rest, None, 0);
        };
        let (release, update) = split_update(release)?;
        Self::new(epoch, upstream, Some(release), update)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch != 0 {
            write!(f, "{}:", self.epoch)?;
        }
        f.write_str(&self.upstream)?;
        if let Some(release) = &self.release {
            write!(f, "-{release}")?;
        }
        if self.update != 0 {
            write!(f, "+u{}", self.update)?;
        }
        Ok(())
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| compare_text(&self.upstream, &other.upstream))
            .then_with(|| {
                compare_text(
                    self.release.as_deref().unwrap_or_default(),
                    other.release.as_deref().unwrap_or_default(),
                )
            })
            .then_with(|| self.update.cmp(&other.update))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

fn parse_epoch(text: &str) -> Result<u32, Error> {
    if text.is_empty() || !text.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Error::BadEpoch(text.to_owned()));
    }
    text.parse().map_err(|_| Error::BadEpoch(text.to_owned()))
}

/// Splits a trailing `+uN` off a release. A `+u` followed by anything but
/// digits (`+ubuntu1`) is part of the release.
fn split_update(release: &str) -> Result<(&str, u32), Error> {
    match update_digits(release) {
        Some((base, digits)) => Ok((base, parse_update(digits)?)),
        None => Ok((release, 0)),
    }
}

/// The release before a trailing `+u` and digits, and those digits, if it
/// has them.
fn update_digits(release: &str) -> Option<(&str, &str)> {
    release
        .rsplit_once("+u")
        .filter(|(_, digits)| !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()))
}

fn parse_update(digits: &str) -> Result<u32, Error> {
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(Error::BadUpdate(digits.to_owned()));
    }
    digits
        .parse()
        .map_err(|_| Error::BadUpdate(digits.to_owned()))
}

fn check_upstream(upstream: &str, has_release: bool) -> Result<(), Error> {
    let Some(first) = upstream.chars().next() else {
        return Err(Error::EmptyUpstream);
    };
    if !first.is_ascii_digit() {
        return Err(Error::UpstreamStart(upstream.to_owned()));
    }
    check_chars(upstream, Part::Upstream, |c| {
        allowed_in_both(c) || (has_release && c == '-')
    })
}

fn check_release(release: &str) -> Result<(), Error> {
    if release.is_empty() {
        return Err(Error::EmptyRelease);
    }
    check_chars(release, Part::Release, allowed_in_both)?;
    // Any trailing `+u` and digits would be read back as an update level,
    // even digits that make an invalid one (`+u01`).
    if update_digits(release).is_some() {
        return Err(Error::ReleaseEndsInUpdate(release.to_owned()));
    }
    Ok(())
}

fn allowed_in_both(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '~' | '^')
}

fn check_chars(text: &str, part: Part, allowed: impl Fn(char) -> bool) -> Result<(), Error> {
    match text.char_indices().find(|&(_, c)| !allowed(c)) {
        Some((at, ch)) => Err(Error::BadChar { part, ch, at }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    fn parts(text: &str) -> (u32, String, Option<String>, u32) {
        let v = v(text);
        (
            v.epoch(),
            v.upstream().to_owned(),
            v.release().map(str::to_owned),
            v.update(),
        )
    }

    #[test]
    fn the_four_parts_parse() {
        assert_eq!(parts("1.27.3"), (0, "1.27.3".into(), None, 0));
        assert_eq!(parts("1.27.3-2"), (0, "1.27.3".into(), Some("2".into()), 0));
        assert_eq!(
            parts("1.27.3-2+u3"),
            (0, "1.27.3".into(), Some("2".into()), 3)
        );
        assert_eq!(
            parts("1:1.27.3-2"),
            (1, "1.27.3".into(), Some("2".into()), 0)
        );
        assert_eq!(
            parts("2:1.0-beta-1+deb12u2"),
            (2, "1.0-beta".into(), Some("1+deb12u2".into()), 0)
        );
        assert_eq!(
            parts("1.0-1ubuntu1+ubuntu2"),
            (0, "1.0".into(), Some("1ubuntu1+ubuntu2".into()), 0)
        );
        assert_eq!(parts("1.0-1+u"), (0, "1.0".into(), Some("1+u".into()), 0));
        assert_eq!(parts("1.0-1+u0"), (0, "1.0".into(), Some("1".into()), 0));
        assert_eq!(parts("1.0-1+u4294967295").3, u32::MAX);
        assert_eq!(parts("4294967295:1").0, u32::MAX);
    }

    #[test]
    fn display_hides_a_zero_epoch_and_update_and_keeps_the_rest() {
        for (input, shown) in [
            ("0:1.0", "1.0"),
            ("1:1.0", "1:1.0"),
            ("01:1.0", "1:1.0"),
            ("1.0-1+u0", "1.0-1"),
            ("1.0-1+u3", "1.0-1+u3"),
            ("1.00-01", "1.00-01"),
            ("1.2^git3~x-4", "1.2^git3~x-4"),
        ] {
            assert_eq!(v(input).to_string(), shown, "{input}");
        }
    }

    #[test]
    fn equality_follows_the_ordering() {
        assert_eq!(v("1.0"), v("1.00"));
        assert_eq!(v("1.0"), v("0:1.0"));
        assert_eq!(v("1.0"), v("1.0-0"));
        assert_eq!(v("1.0-1"), v("1.0-1+u0"));
        assert_ne!(v("1.0"), v("1.0-1"));
        assert_ne!(v("1.0"), v("1.0."));
    }

    #[test]
    fn the_parts_compare_in_order() {
        let ascending = [
            "1.0~rc1-1",
            "1.0-1",
            "1.0-1+u1",
            "1.0-1+u2",
            "1.0-1+u10",
            "1.0-1.1",
            "1.0-2",
            "1.0.1-1",
            "1.1",
            "9999",
            "1:0.1",
            "2:0.0",
        ];
        for (i, a) in ascending.iter().enumerate() {
            for b in &ascending[i + 1..] {
                assert!(v(a) < v(b), "{a} < {b}");
                assert!(v(b) > v(a), "{b} > {a}");
            }
        }
        assert_eq!(v("1.0").partial_cmp(&v("1.0")), Some(Ordering::Equal));
    }

    #[test]
    fn the_update_level_outranks_nothing_but_itself() {
        // Release `1` with update 1 is still below release `1+a`: the base
        // release decides first.
        assert!(v("1.0-1+u1") < v("1.0-1+a"));
        assert!(v("1.0-1+u9") < v("1.0-2"));
    }

    #[test]
    fn bad_versions_say_why() {
        let err = |text: &str| text.parse::<Version>().unwrap_err();
        assert_eq!(err(""), Error::Empty);
        assert_eq!(err(&"1".repeat(257)), Error::TooLong(257));
        assert_eq!(err(":1.0"), Error::BadEpoch(String::new()));
        assert_eq!(err("a:1.0"), Error::BadEpoch("a".into()));
        // u32's parser takes a leading `+`; an epoch must be digits only.
        assert_eq!(err("+1:1.0"), Error::BadEpoch("+1".into()));
        assert_eq!(err("4294967296:1.0"), Error::BadEpoch("4294967296".into()));
        assert_eq!(err("1:"), Error::EmptyUpstream);
        assert_eq!(err("-1"), Error::EmptyUpstream);
        assert_eq!(err("a1.0"), Error::UpstreamStart("a1.0".into()));
        assert_eq!(err("1.0-"), Error::EmptyRelease);
        assert_eq!(err("1.0-1+u01"), Error::BadUpdate("01".into()));
        assert_eq!(
            err("1.0-1+u4294967296"),
            Error::BadUpdate("4294967296".into())
        );
        assert_eq!(err("1.0-+u1"), Error::EmptyRelease);
        assert_eq!(
            err("1.0-1+u2+u3"),
            Error::ReleaseEndsInUpdate("1+u2".into())
        );
        // Found by fuzzing: the hidden `+u0` would leave `+u01` to be read
        // back as an invalid update level.
        assert_eq!(
            err("1.0-1+u01+u0"),
            Error::ReleaseEndsInUpdate("1+u01".into())
        );
        assert_eq!(
            err("1:2:3"),
            Error::BadChar {
                part: Part::Upstream,
                ch: ':',
                at: 1
            }
        );
        assert_eq!(
            err("1.0 -1"),
            Error::BadChar {
                part: Part::Upstream,
                ch: ' ',
                at: 3
            }
        );
        assert_eq!(
            err("1.0-1_2"),
            Error::BadChar {
                part: Part::Release,
                ch: '_',
                at: 1
            }
        );
        assert_eq!(
            err("1.é"),
            Error::BadChar {
                part: Part::Upstream,
                ch: 'é',
                at: 2
            }
        );
    }

    #[test]
    fn new_checks_each_part() {
        assert!(Version::new(0, "1.0", Some("1"), 2).is_ok());
        assert_eq!(
            Version::new(0, "1.0-x", None, 0).unwrap_err(),
            Error::BadChar {
                part: Part::Upstream,
                ch: '-',
                at: 3
            }
        );
        assert!(Version::new(0, "1.0-x", Some("1"), 0).is_ok());
        assert_eq!(
            Version::new(0, "1.0", Some("1+u2"), 0).unwrap_err(),
            Error::ReleaseEndsInUpdate("1+u2".into())
        );
        assert_eq!(
            Version::new(0, "1.0", Some("1+u01"), 0).unwrap_err(),
            Error::ReleaseEndsInUpdate("1+u01".into())
        );
        assert!(Version::new(0, "1.0", Some("1+u"), 0).is_ok());
        assert!(Version::new(0, "1.0", Some("1+ux1"), 0).is_ok());
        assert_eq!(
            Version::new(0, "1.0", Some("1-2"), 0).unwrap_err(),
            Error::BadChar {
                part: Part::Release,
                ch: '-',
                at: 1
            }
        );
        assert_eq!(
            Version::new(0, "1.0", Some(""), 0).unwrap_err(),
            Error::EmptyRelease
        );
        assert_eq!(
            Version::new(0, "", None, 0).unwrap_err(),
            Error::EmptyUpstream
        );
        let long = "1".repeat(200);
        assert_eq!(
            Version::new(0, &long, Some(&long), 0).unwrap_err(),
            Error::TooLong(401)
        );
        assert!(Version::new(0, &"1".repeat(256), None, 0).is_ok());
        assert_eq!(
            Version::new(0, &"1".repeat(255), Some("1"), 0).unwrap_err(),
            Error::TooLong(257)
        );
    }

    #[test]
    fn the_longest_accepted_version_is_max_len() {
        assert!("1".repeat(MAX_LEN).parse::<Version>().is_ok());
        assert_eq!(
            "1".repeat(MAX_LEN + 1).parse::<Version>().unwrap_err(),
            Error::TooLong(MAX_LEN + 1)
        );
    }
}
