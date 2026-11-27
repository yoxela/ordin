// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The recipe (`ordin.toml`) schema, its typed expression language and
//! preset expansion.
//!
//! Rung 1 (ORD-121) is what this crate reads so far: the ten or so lines
//! a packager adds for what `ordin pack` can't infer. [`parse`] reads the
//! text, refuses every key it doesn't know, checks each value with the
//! same parsers and rules the manifest uses, and names the line and
//! column of the first problem. `FORMAT.md` is the reference.
//!
//! It does no I/O: the caller reads the file, and the license texts it
//! names.

use std::collections::BTreeMap;
use std::fmt;

use ordin_core::{Arch, Facet, FilePath, PackageName};
use ordin_depexpr::Expr;
use ordin_manifest::{
    Group, Presentation, Provide, Seed, Setting, StateFile, StatePath, Unit, Url, User,
};
use ordin_tree::TreePath;

mod lint;
mod probe;
mod read;

pub use lint::{Allow, Check, REASON_MAX, below};

/// The recipe format this crate reads.
pub const FORMAT: i64 = 1;

/// The largest recipe read, in bytes.
pub const MAX_SIZE: usize = 1 << 20;

/// Why a recipe was refused, and where: the line and column, from 1,
/// of the first problem found.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{line}:{column}: {message}")]
pub struct Error {
    /// The line.
    pub line: usize,
    /// The column, in characters.
    pub column: usize,
    /// What was wrong, and what was expected.
    pub message: String,
}

/// A rung-1 recipe.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recipe {
    /// `[package]`: what the command line can also give.
    pub package: Package,
    /// `[license]`: how the license is shown, and where its texts are.
    pub license: LicenseFiles,
    /// Everything else, which only a recipe gives.
    pub declared: Declared,
    /// `[[lint.allow]]`: warnings `ordin lint` accepts on purpose.
    pub lint: Vec<Allow>,
}

/// The `[package]` fields that the command line can also give, and
/// overrides.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Package {
    /// The package's name.
    pub name: Option<PackageName>,
    /// The upstream version, with an optional epoch: `2.12`, `1:2.0`.
    pub version: Option<String>,
    /// The release.
    pub release: Option<String>,
    /// What it runs on.
    pub arch: Option<Arch>,
    /// One line about it.
    pub summary: Option<String>,
    /// Longer text about it.
    pub description: Option<String>,
    /// Where users go for the software.
    pub homepage: Option<Url>,
    /// Its SPDX license expression.
    pub license: Option<String>,
}

/// `[license]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LicenseFiles {
    /// How the license is shown; informational if not given.
    pub presentation: Option<Presentation>,
    /// Each license ID's text, by a path relative to the recipe's own
    /// directory.
    pub files: BTreeMap<String, RelativePath>,
}

/// What only a recipe declares.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Declared {
    /// Requirements besides the inferred ones.
    pub requires: Vec<Expr>,
    /// Provides besides the inferred ones.
    pub provides: Vec<Provide>,
    /// Packages that may not be installed with it.
    pub conflicts: Vec<Expr>,
    /// System users.
    pub users: Vec<User>,
    /// System groups.
    pub groups: Vec<Group>,
    /// Units and their presets.
    pub units: Vec<Unit>,
    /// Settings.
    pub settings: Vec<Setting>,
    /// State under `/var` and `/run`, besides what is inferred.
    pub state: DeclaredState,
    /// Paths moved to another facet than their path rule's.
    pub facets: Vec<FacetMove>,
}

/// `[state]`: declared state, which wins over what is inferred at the
/// same path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeclaredState {
    /// The state version on disk that this release expects.
    pub version: u64,
    /// Paths removed on upgrade.
    pub obsolete: Vec<FilePath>,
    /// `[[state.path]]`.
    pub paths: Vec<StatePath>,
    /// `[[state.file]]`.
    pub files: Vec<StateFile>,
    /// `[[state.seed]]`.
    pub seeds: Vec<Seed>,
}

impl DeclaredState {
    /// Whether it declares nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.version == 0
            && self.obsolete.is_empty()
            && self.paths.is_empty()
            && self.files.is_empty()
            && self.seeds.is_empty()
    }
}

/// A path, and everything below it, moved to a facet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FacetMove {
    /// The facet.
    pub facet: Facet,
    /// The path, as it is in the package.
    pub path: TreePath,
}

/// A relative path that stays below the directory it is relative to:
/// names separated by single `/`, none of them `.` or `..`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelativePath(String);

impl RelativePath {
    /// The longest path accepted, in bytes.
    pub const MAX_LEN: usize = 4096;

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for RelativePath {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        if text.is_empty() {
            return Err("a path can't be empty".into());
        }
        if text.len() > Self::MAX_LEN {
            return Err(format!("a path is at most {} bytes", Self::MAX_LEN));
        }
        if text.starts_with('/') {
            return Err(format!(
                "a path here is relative to the recipe's directory, not absolute: {text:?}"
            ));
        }
        if text.contains('\0') {
            return Err("a path can't hold a NUL character".into());
        }
        for name in text.split('/') {
            match name {
                "" => {
                    return Err(format!(
                        "a path can't have an empty name (a doubled or trailing '/'): {text:?}"
                    ));
                }
                "." | ".." => {
                    return Err(format!(
                        "a path can't have a '.' or '..' name, so it stays below the recipe's directory: {text:?}"
                    ));
                }
                _ => {}
            }
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reads a recipe.
///
/// # Errors
///
/// The first problem, with its line and column: a TOML syntax error, a
/// key this format doesn't have, a value of the wrong type or form, or a
/// rule of the manifest the recipe's declarations break.
pub fn parse(text: &str) -> Result<Recipe, Error> {
    if text.len() > MAX_SIZE {
        return Err(Error {
            line: 1,
            column: 1,
            message: format!(
                "a recipe is at most {MAX_SIZE} bytes; this one is {}",
                text.len()
            ),
        });
    }
    let (recipe, locations) = read::recipe(text)?;
    probe::check(&recipe, &locations, text)?;
    Ok(recipe)
}
