// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The release version and where it is recorded: the workspace
//! `Cargo.toml`, the tag name and `CHANGELOG.md`.

use super::Error;

/// The workspace version and repository, read from the root `Cargo.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workspace {
    /// `[workspace.package] version`, checked by [`check_version`].
    pub version: String,
    /// `[workspace.package] repository`: the clone URL.
    pub repository: String,
    /// The GitHub `owner/name` of the repository.
    pub slug: String,
}

/// Reads the version and repository from the root `Cargo.toml`.
///
/// # Errors
///
/// Returns an error if the file isn't TOML, a field is missing, or a value
/// is malformed.
pub fn workspace(cargo_toml: &str) -> Result<Workspace, Error> {
    let doc: toml::Table = cargo_toml
        .parse()
        .map_err(|e| Error::parse("Cargo.toml", e))?;
    let field = |name: &str| {
        doc.get("workspace")
            .and_then(|w| w.get("package"))
            .and_then(|p| p.get(name))
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                Error::parse(
                    "Cargo.toml",
                    format!("no [workspace.package] {name} string"),
                )
            })
    };
    let version = field("version")?;
    check_version(&version)?;
    let repository = field("repository")?;
    let slug = github_slug(&repository)?;
    Ok(Workspace {
        version,
        repository,
        slug,
    })
}

/// Checks a release version: `MAJOR.MINOR.PATCH` in decimal without leading
/// zeros, optionally followed by `-` and a pre-release of letters, digits
/// and dots.
///
/// # Errors
///
/// Returns what is wrong with the version.
pub fn check_version(version: &str) -> Result<(), Error> {
    let bad = |why: &str| Error::parse("the version", format!("`{version}` {why}"));
    let (core, pre) = match version.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (version, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return Err(bad("should be MAJOR.MINOR.PATCH"));
    }
    for part in parts {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad("should have only digits in MAJOR.MINOR.PATCH"));
        }
        if part.len() > 1 && part.starts_with('0') {
            return Err(bad("has a leading zero"));
        }
    }
    if let Some(pre) = pre {
        let ok = pre
            .split('.')
            .all(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()));
        if !ok {
            return Err(bad("has a malformed pre-release"));
        }
    }
    Ok(())
}

/// The tag for a version.
#[must_use]
pub fn tag_for(version: &str) -> String {
    format!("v{version}")
}

/// Checks a tag name and returns its version.
///
/// # Errors
///
/// Returns an error unless the tag is `v` followed by a valid version.
pub fn tag_version(tag: &str) -> Result<&str, Error> {
    let version = tag
        .strip_prefix('v')
        .ok_or_else(|| Error::parse("the tag", format!("`{tag}` should start with v")))?;
    check_version(version)?;
    Ok(version)
}

/// Checks that `tag` names `version`.
///
/// # Errors
///
/// Returns an error if the tag is malformed or names another version.
pub fn check_tag(tag: &str, version: &str) -> Result<(), Error> {
    if tag_version(tag)? == version {
        Ok(())
    } else {
        Err(Error::check(format!(
            "the tag {tag} doesn't match the workspace version {version}"
        )))
    }
}

/// The `owner/name` of a GitHub repository URL.
///
/// # Errors
///
/// Returns an error unless the URL is `https://github.com/<owner>/<name>`
/// with plain names.
pub fn github_slug(url: &str) -> Result<String, Error> {
    let bad = || {
        Error::parse(
            "the repository URL",
            format!("`{url}` should be https://github.com/<owner>/<name>"),
        )
    };
    let rest = url.strip_prefix("https://github.com/").ok_or_else(bad)?;
    let (owner, name) = rest.split_once('/').ok_or_else(bad)?;
    let plain = |s: &str| {
        !s.is_empty()
            && !s.starts_with('.')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    };
    if plain(owner) && plain(name) && !name.ends_with(".git") {
        Ok(format!("{owner}/{name}"))
    } else {
        Err(bad())
    }
}

/// Checks that `CHANGELOG.md` has a dated section for `version`
/// (`## [0.1.0] - 2026-11-20`), and no longer calls it unreleased.
///
/// # Errors
///
/// Returns an error that says which heading is missing or left over.
pub fn check_changelog(changelog: &str, version: &str) -> Result<(), Error> {
    let heading = format!("## [{version}] - ");
    let dated = changelog.lines().any(|line| {
        line.strip_prefix(&heading)
            .is_some_and(|date| is_iso_date(date.trim_end()))
    });
    if !dated {
        return Err(Error::check(format!(
            "CHANGELOG.md has no `## [{version}] - YYYY-MM-DD` heading"
        )));
    }
    let unreleased = format!("## [Unreleased] ({version})");
    if changelog.lines().any(|line| line.trim_end() == unreleased) {
        return Err(Error::check(format!(
            "CHANGELOG.md still has `{unreleased}`; rename it to the dated heading"
        )));
    }
    Ok(())
}

/// Whether `s` is `YYYY-MM-DD` with a month from 01 to 12 and a day from 01
/// to 31.
fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    if !(digits(0..4) && digits(5..7) && digits(8..10)) {
        return false;
    }
    let month = (b[5] - b'0') * 10 + (b[6] - b'0');
    let day = (b[8] - b'0') * 10 + (b[9] - b'0');
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const CARGO: &str = "[workspace]\nmembers = []\n\n[workspace.package]\n\
                         version = \"0.1.0\"\nrepository = \"https://github.com/yoxela/ordin\"\n";

    #[test]
    fn reads_the_workspace_version_and_repository() {
        assert_eq!(
            workspace(CARGO).unwrap(),
            Workspace {
                version: "0.1.0".into(),
                repository: "https://github.com/yoxela/ordin".into(),
                slug: "yoxela/ordin".into(),
            }
        );
    }

    #[test]
    fn the_real_workspace_has_a_valid_version_and_repository() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml")).unwrap();
        assert_eq!(workspace(&text).unwrap().slug, "yoxela/ordin");
    }

    #[test]
    fn missing_or_bad_fields_are_errors() {
        assert!(workspace("not toml [").is_err());
        let e = workspace("[workspace.package]\nrepository = \"https://github.com/a/b\"\n")
            .unwrap_err();
        assert!(
            e.to_string().contains("no [workspace.package] version"),
            "{e}"
        );
        let e = workspace("[workspace.package]\nversion = \"0.1.0\"\n").unwrap_err();
        assert!(e.to_string().contains("repository"), "{e}");
        let e = workspace("[workspace.package]\nversion = 1\nrepository = \"x\"\n").unwrap_err();
        assert!(e.to_string().contains("version"), "{e}");
        assert!(workspace(&CARGO.replace("0.1.0", "0.1")).is_err());
        assert!(workspace(&CARGO.replace("https://github.com/", "https://example.com/")).is_err());
    }

    #[test]
    fn versions_are_strict() {
        for good in ["0.1.0", "1.20.300", "1.0.0-rc.1", "2.0.0-alpha", "10.0.0"] {
            assert_eq!(check_version(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.x",
            "1..3",
            "1.2.3-",
            "1.2.3-rc..1",
            "1.2.3-rc_1",
            "1.2.3-r/c",
            "v1.2.3",
            " 1.2.3",
            "1.2.3 ",
        ] {
            assert!(check_version(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn version_errors_say_why() {
        let why = |v: &str| check_version(v).unwrap_err().to_string();
        assert!(why("1.2").contains("MAJOR.MINOR.PATCH"));
        assert!(why("1.x.3").contains("only digits"));
        assert!(why("1.02.3").contains("leading zero"));
        assert!(why("1.2.3-a..b").contains("pre-release"));
    }

    #[test]
    fn tags_name_versions() {
        assert_eq!(tag_for("0.1.0"), "v0.1.0");
        assert_eq!(tag_version("v0.1.0"), Ok("0.1.0"));
        assert!(
            tag_version("0.1.0")
                .unwrap_err()
                .to_string()
                .contains("start with v")
        );
        assert!(tag_version("v0.1").is_err());
        assert_eq!(check_tag("v0.1.0", "0.1.0"), Ok(()));
        let e = check_tag("v0.2.0", "0.1.0").unwrap_err();
        assert_eq!(
            e.to_string(),
            "the tag v0.2.0 doesn't match the workspace version 0.1.0"
        );
        assert!(check_tag("x0.1.0", "0.1.0").is_err());
    }

    #[test]
    fn github_slugs_are_plain() {
        assert_eq!(
            github_slug("https://github.com/yoxela/ordin").unwrap(),
            "yoxela/ordin"
        );
        assert_eq!(
            github_slug("https://github.com/a-b/c_d.e").unwrap(),
            "a-b/c_d.e"
        );
        for bad in [
            "http://github.com/a/b",
            "https://github.com/a",
            "https://github.com/a/b/c",
            "https://github.com//b",
            "https://github.com/a/",
            "https://github.com/../b",
            "https://github.com/a/.x",
            "https://github.com/a/b.git",
            "https://github.com/a b/c",
            "https://gitlab.com/a/b",
        ] {
            assert!(github_slug(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_changelog_needs_a_dated_heading() {
        let ok = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-11-20\n\n- things\n";
        assert_eq!(check_changelog(ok, "0.1.0"), Ok(()));
        assert_eq!(
            check_changelog("## [0.1.0] - 2026-11-20  \n", "0.1.0"),
            Ok(())
        );
        let e = check_changelog("## [Unreleased] (0.1.0)\n", "0.1.0").unwrap_err();
        assert!(
            e.to_string()
                .contains("no `## [0.1.0] - YYYY-MM-DD` heading"),
            "{e}"
        );
        for bad in [
            "## [0.1.0]\n",
            "## [0.1.0] - soon\n",
            "## [0.1.0] - 2026-13-01\n",
            "## [0.1.0] - 2026-11-32\n",
            "## [0.1.0] - 2026-00-10\n",
            "## [0.1.0] - 2026-11-00\n",
            "## [0.1.0] - 2026/11/20\n",
            "## [0.1.0] - 26-11-20\n",
            "## [0.1.0] - 2026-11-2x\n",
            "### [0.1.0] - 2026-11-20\n",
            "## [0.1.1] - 2026-11-20\n",
        ] {
            assert!(check_changelog(bad, "0.1.0").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_leftover_unreleased_heading_is_an_error() {
        let both = "## [Unreleased] (0.1.0)\n\n## [0.1.0] - 2026-11-20\n";
        let e = check_changelog(both, "0.1.0").unwrap_err();
        assert!(
            e.to_string()
                .contains("still has `## [Unreleased] (0.1.0)`"),
            "{e}"
        );
    }

    #[test]
    fn dates_check_every_field() {
        assert!(is_iso_date("2026-01-01"));
        assert!(is_iso_date("2026-12-31"));
        for bad in [
            "2026-1-01",
            "2026-01-1",
            "x026-01-01",
            "2026-x1-01",
            "2026-01-x1",
            "2026-01-01x",
            "2026a01-01",
            "2026-01a01",
        ] {
            assert!(!is_iso_date(bad), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn every_valid_version_round_trips_through_its_tag(
            major in 0u32..1000, minor in 0u32..1000, patch in 0u32..1000,
        ) {
            let version = format!("{major}.{minor}.{patch}");
            prop_assert_eq!(check_version(&version), Ok(()));
            let tag = tag_for(&version);
            prop_assert_eq!(tag_version(&tag), Ok(version.as_str()));
        }
    }
}
