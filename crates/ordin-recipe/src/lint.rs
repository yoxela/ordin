// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The checks `ordin lint` makes, and the recipe's `[[lint.allow]]`
//! entries that accept a warning on purpose.

use std::fmt;

use ordin_tree::TreePath;

/// A check `ordin lint` makes, named by its ID.
///
/// The order is the order a report lists warnings in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Check {
    /// The license is `NOASSERTION`: nobody has said what it is.
    LicenseUnknown,
    /// A setuid or setgid file that isn't declared.
    SetuidUndeclared,
    /// A file, directory or declared state path anyone can write to.
    WorldWritable,
    /// A program needs a private symbol version, which nothing can
    /// promise but an exact version of the library's package.
    SoPrivateVersion,
    /// A library name or version node an `so:` atom can't hold.
    SoBadName,
    /// An `so:` requirement on a library with no version after `.so`.
    SoUnversioned,
    /// An `so:` requirement that no program or library in the package
    /// needs.
    SoUnneeded,
    /// A file with the ELF magic that couldn't be read.
    ElfUnreadable,
    /// A `#!` line Ordin won't guess about.
    ShebangUnusual,
    /// A `#!` interpreter that the package doesn't ship and that isn't
    /// a known one.
    InterpreterUnknown,
    /// A facet that holds no files.
    FacetEmpty,
    /// A file in `runtime` that looks like it belongs in another facet.
    FacetMisclassified,
    /// A `[[lint.allow]]` entry, or one of its paths, that matched no
    /// warning.
    UnusedAllow,
}

impl Check {
    /// Every check, in report order.
    pub const ALL: [Self; 13] = [
        Self::LicenseUnknown,
        Self::SetuidUndeclared,
        Self::WorldWritable,
        Self::SoPrivateVersion,
        Self::SoBadName,
        Self::SoUnversioned,
        Self::SoUnneeded,
        Self::ElfUnreadable,
        Self::ShebangUnusual,
        Self::InterpreterUnknown,
        Self::FacetEmpty,
        Self::FacetMisclassified,
        Self::UnusedAllow,
    ];

    /// The ID a recipe and a report name it by.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::LicenseUnknown => "license-unknown",
            Self::SetuidUndeclared => "setuid-undeclared",
            Self::WorldWritable => "world-writable",
            Self::SoPrivateVersion => "so-private-version",
            Self::SoBadName => "so-bad-name",
            Self::SoUnversioned => "so-unversioned",
            Self::SoUnneeded => "so-unneeded",
            Self::ElfUnreadable => "elf-unreadable",
            Self::ShebangUnusual => "shebang-unusual",
            Self::InterpreterUnknown => "interpreter-unknown",
            Self::FacetEmpty => "facet-empty",
            Self::FacetMisclassified => "facet-misclassified",
            Self::UnusedAllow => "unused-allow",
        }
    }

    /// The check named `id`.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.id() == id)
    }

    /// Whether its warnings name a path in the package, so an allow can
    /// be narrowed to some paths.
    #[must_use]
    pub fn has_paths(self) -> bool {
        !matches!(
            self,
            Self::LicenseUnknown
                | Self::SoUnversioned
                | Self::SoUnneeded
                | Self::FacetEmpty
                | Self::UnusedAllow
        )
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// The longest reason an allow may give, in characters.
pub const REASON_MAX: usize = 200;

/// `[[lint.allow]]`: a warning accepted on purpose, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allow {
    /// The check.
    pub check: Check,
    /// Why the warning is accepted: one line.
    pub reason: String,
    /// The paths it covers, each with everything below it; empty for the
    /// whole package.
    pub paths: Vec<TreePath>,
    /// The recipe line its table starts on, for a report.
    pub line: usize,
}

impl Allow {
    /// Whether it covers a warning about `path`, or about no path.
    #[must_use]
    pub fn covers(&self, check: Check, path: Option<&str>) -> bool {
        self.check == check
            && (self.paths.is_empty() || path.is_some_and(|p| self.covering(p).is_some()))
    }

    /// The first of its paths that covers `path`: the path itself, or a
    /// directory above it.
    #[must_use]
    pub fn covering(&self, path: &str) -> Option<&TreePath> {
        self.paths.iter().find(|p| below(path, p.as_str()))
    }
}

/// Whether `path` is `dir` or below it.
#[must_use]
pub fn below(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_check_has_one_id() {
        for check in Check::ALL {
            assert_eq!(Check::from_id(check.id()), Some(check));
            assert_eq!(check.to_string(), check.id());
        }
        assert_eq!(Check::from_id("world_writable"), None);
        let mut sorted = Check::ALL;
        sorted.sort();
        assert_eq!(sorted, Check::ALL);
    }

    #[test]
    fn only_checks_about_a_path_take_paths() {
        let pathless: Vec<_> = Check::ALL.into_iter().filter(|c| !c.has_paths()).collect();
        assert_eq!(
            pathless,
            [
                Check::LicenseUnknown,
                Check::SoUnversioned,
                Check::SoUnneeded,
                Check::FacetEmpty,
                Check::UnusedAllow
            ]
        );
    }

    #[test]
    fn an_allow_covers_its_paths_and_below() {
        assert!(below("/usr/a", "/usr/a"));
        assert!(below("/usr/a/b", "/usr/a"));
        assert!(!below("/usr/ab", "/usr/a"));
        assert!(!below("/usr", "/usr/a"));
        let allow = Allow {
            check: Check::WorldWritable,
            reason: "shared".to_owned(),
            paths: vec!["/usr/a".parse().unwrap(), "/usr/c".parse().unwrap()],
            line: 3,
        };
        assert!(allow.covers(Check::WorldWritable, Some("/usr/a/x")));
        assert_eq!(
            allow.covering("/usr/c").map(TreePath::as_str),
            Some("/usr/c")
        );
        assert!(!allow.covers(Check::WorldWritable, Some("/usr/b")));
        assert!(!allow.covers(Check::WorldWritable, None));
        assert!(!allow.covers(Check::SetuidUndeclared, Some("/usr/a")));
        let whole = Allow {
            paths: Vec::new(),
            ..allow
        };
        assert!(whole.covers(Check::WorldWritable, None));
        assert!(whole.covers(Check::WorldWritable, Some("/usr/b")));
        assert!(!whole.covers(Check::FacetEmpty, None));
    }
}
