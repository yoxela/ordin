// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Semantic versions, normalized into Ordin's ordering.

use crate::{Error, MAX_LEN};

/// Turns a semantic version (semver 2.0.0) into the upstream version Ordin
/// orders correctly.
///
/// The pre-release moves behind a `~`, so it sorts before the release:
/// `2.0.0-rc.1` becomes `2.0.0~rc.1`. Build metadata (`+build.5`) is
/// checked and then dropped, because semver says it never affects
/// ordering and in Ordin it would. The build records it in provenance
/// instead.
///
/// # Errors
///
/// Returns [`Error::Semver`] if `text` isn't a semantic version.
pub fn normalize_semver(text: &str) -> Result<String, Error> {
    let bad = |reason| Error::Semver {
        text: text.chars().take(MAX_LEN).collect(),
        reason,
    };
    if text.len() > MAX_LEN {
        return Err(bad("it is too long"));
    }
    let (rest, build) = match text.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (text, None),
    };
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };
    let numbers: Vec<&str> = core.split('.').collect();
    if numbers.len() != 3 {
        return Err(bad("it needs exactly three numbers, MAJOR.MINOR.PATCH"));
    }
    if !numbers.iter().all(|n| is_number(n)) {
        return Err(bad(
            "MAJOR, MINOR and PATCH must be numbers without leading zeros",
        ));
    }
    if let Some(pre) = pre
        && !identifiers(pre, true)
    {
        return Err(bad(
            "the pre-release must be dot-separated identifiers of letters, digits and '-', with no leading zeros in numbers",
        ));
    }
    if let Some(build) = build
        && !identifiers(build, false)
    {
        return Err(bad(
            "the build metadata must be dot-separated identifiers of letters, digits and '-'",
        ));
    }
    Ok(match pre {
        Some(pre) => format!("{core}~{pre}"),
        None => core.to_owned(),
    })
}

/// A numeric identifier: digits, and no leading zero unless it is `0`.
fn is_number(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|c| c.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'))
}

/// Dot-separated, non-empty identifiers of `[0-9A-Za-z-]`. In a
/// pre-release, an all-digit identifier must not have a leading zero.
fn identifiers(text: &str, pre_release: bool) -> bool {
    text.split('.').all(|id| {
        !id.is_empty()
            && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            && (!pre_release || !id.bytes().all(|c| c.is_ascii_digit()) || is_number(id))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Version;

    fn upstream(text: &str) -> String {
        normalize_semver(text).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn pre_releases_move_behind_a_tilde() {
        assert_eq!(upstream("2.0.0"), "2.0.0");
        assert_eq!(upstream("2.0.0-rc.1"), "2.0.0~rc.1");
        assert_eq!(upstream("1.0.0-x-y.7"), "1.0.0~x-y.7");
        assert_eq!(upstream("0.0.0-0"), "0.0.0~0");
    }

    #[test]
    fn build_metadata_is_dropped() {
        assert_eq!(upstream("1.0.0+build.5"), "1.0.0");
        assert_eq!(upstream("1.0.0-beta+exp.sha.5114f85"), "1.0.0~beta");
        assert_eq!(upstream("1.0.0+0012"), "1.0.0");
    }

    #[test]
    fn semver_precedence_survives_normalization() {
        // The example list in semver 2.0.0, section 11.
        let ascending = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "2.0.0",
            "2.1.0",
            "2.1.1",
        ];
        let versions: Vec<Version> = ascending
            .iter()
            .map(|s| upstream(s).parse().unwrap())
            .collect();
        for pair in versions.windows(2) {
            assert!(pair[0] < pair[1], "{} < {}", pair[0], pair[1]);
        }
    }

    #[test]
    fn not_semver_is_refused() {
        for (text, reason) in [
            ("1.0", "exactly three numbers"),
            ("1.0.0.0", "exactly three numbers"),
            ("v1.0.0", "without leading zeros"),
            ("01.0.0", "without leading zeros"),
            ("1..0", "without leading zeros"),
            ("1.0.x", "without leading zeros"),
            ("1.0.0-", "pre-release"),
            ("1.0.0-01", "pre-release"),
            ("1.0.0-a..b", "pre-release"),
            ("1.0.0-a_b", "pre-release"),
            ("1.0.0+", "build metadata"),
            ("1.0.0+a+b", "build metadata"),
            ("1.0.0+a b", "build metadata"),
            ("", "exactly three numbers"),
        ] {
            let e = normalize_semver(text).unwrap_err().to_string();
            assert!(e.contains(reason), "{text:?}: {e}");
        }
        let long = format!("1.0.0-{}", "a".repeat(MAX_LEN));
        assert!(
            normalize_semver(&long)
                .unwrap_err()
                .to_string()
                .contains("too long")
        );
    }

    #[test]
    fn the_longest_accepted_semver_is_max_len() {
        let longest = format!("1.0.0-{}", "a".repeat(MAX_LEN - 6));
        assert_eq!(longest.len(), MAX_LEN);
        assert!(normalize_semver(&longest).is_ok());
        let over = format!("{longest}a");
        assert!(
            normalize_semver(&over)
                .unwrap_err()
                .to_string()
                .contains("too long")
        );
    }

    #[test]
    fn numeric_pre_release_identifiers_need_no_leading_zero() {
        assert!(normalize_semver("1.0.0-0a").is_ok());
        assert!(normalize_semver("1.0.0-10").is_ok());
        assert!(normalize_semver("1.0.0-010").is_err());
        assert!(normalize_semver("1.0.0+010").is_ok());
    }
}
