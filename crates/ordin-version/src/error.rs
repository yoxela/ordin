// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Why a version, a semantic version or a snapshot was rejected.

use core::fmt;

use crate::MAX_LEN;

/// The part of a version an error is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// The software's own version.
    Upstream,
    /// The packaging release, after the last `-`.
    Release,
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Upstream => "the upstream version",
            Self::Release => "the release",
        })
    }
}

/// Why something couldn't be made into a version.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The text was empty.
    #[error("a version can't be empty")]
    Empty,
    /// The text was longer than [`MAX_LEN`] bytes.
    #[error("a version is at most {MAX_LEN} bytes; this one is {0}")]
    TooLong(usize),
    /// The epoch, before the first `:`, isn't a number that fits in 32 bits.
    #[error("the epoch {0:?} must be a number that fits in 32 bits")]
    BadEpoch(String),
    /// Nothing is left for the upstream version.
    #[error("the upstream version is empty")]
    EmptyUpstream,
    /// The upstream version doesn't start with a digit.
    #[error("the upstream version {0:?} must start with a digit")]
    UpstreamStart(String),
    /// The release, after the last `-`, is empty.
    #[error("the release after the last '-' is empty")]
    EmptyRelease,
    /// A character that isn't allowed in that part.
    #[error("{part} can't contain {ch:?} (at byte {at})")]
    BadChar {
        /// Where the character is.
        part: Part,
        /// The character.
        ch: char,
        /// Its byte offset within the part.
        at: usize,
    },
    /// The update level after `+u` isn't a plain number that fits in 32
    /// bits.
    #[error("the update level {0:?} must be a number without leading zeros that fits in 32 bits")]
    BadUpdate(String),
    /// A release that ends in `+u` and digits, which would be read back as
    /// an update level.
    #[error("the release {0:?} ends in what would be read as an update level")]
    ReleaseEndsInUpdate(String),
    /// The text isn't a semantic version.
    #[error("{text:?} isn't a semantic version: {reason}")]
    Semver {
        /// The text.
        text: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The parts given can't make a snapshot version.
    #[error("can't build a snapshot version: {0}")]
    Snapshot(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_say_what_is_wrong() {
        assert_eq!(Error::Empty.to_string(), "a version can't be empty");
        assert_eq!(
            Error::TooLong(300).to_string(),
            "a version is at most 256 bytes; this one is 300"
        );
        assert_eq!(
            Error::BadChar {
                part: Part::Release,
                ch: ' ',
                at: 2
            }
            .to_string(),
            "the release can't contain ' ' (at byte 2)"
        );
        assert_eq!(
            Error::BadChar {
                part: Part::Upstream,
                ch: ':',
                at: 0
            }
            .to_string(),
            "the upstream version can't contain ':' (at byte 0)"
        );
        assert_eq!(
            Error::Semver {
                text: "1.0".into(),
                reason: "it needs three numbers"
            }
            .to_string(),
            "\"1.0\" isn't a semantic version: it needs three numbers"
        );
        assert_eq!(
            Error::Snapshot("the date isn't YYYYMMDD").to_string(),
            "can't build a snapshot version: the date isn't YYYYMMDD"
        );
    }
}
