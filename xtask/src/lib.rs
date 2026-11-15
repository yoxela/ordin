// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Project tooling for Ordin.
//!
//! `cargo xtask check-layers` enforces the architecture's build rules
//! (ORD-002): layers, licenses, the layer-0 I/O ban, what `ordind` may link,
//! SPDX headers, and the lint and clippy configuration that implements them.
//! The [`release`] module holds the release flows (ORD-004), and
//! [`version_corpus`] the dpkg corpus for `ordin-version` (ORD-011).

use std::fmt;
use std::path::Path;

pub mod files;
pub mod model;
pub mod release;
pub mod rules;
pub mod version_corpus;

/// Which rule a violation breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// A missing or invalid `[package.metadata.ordin] layer`.
    Layer,
    /// A license that doesn't match the crate's layer.
    License,
    /// A dependency on a crate in a higher layer.
    UpwardDependency,
    /// A dependency on a tool crate.
    ToolDependency,
    /// A permissive crate that ships a GPL crate.
    PermissiveDependsOnGpl,
    /// A layer-0 crate that ships an I/O crate.
    Layer0Io,
    /// `ordind` linking archive, decompression, ELF or solver code.
    OrdindDenylist,
    /// A source file whose SPDX header is missing or wrong.
    SpdxHeader,
    /// A crate's `[lints]` table out of step with the workspace.
    LintTable,
    /// A crate-level `clippy.toml` that is missing, extra or out of step.
    ClippyConfig,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = match self {
            Self::Layer => "layer",
            Self::License => "license",
            Self::UpwardDependency => "upward-dependency",
            Self::ToolDependency => "tool-dependency",
            Self::PermissiveDependsOnGpl => "permissive-depends-on-gpl",
            Self::Layer0Io => "layer-0-io",
            Self::OrdindDenylist => "ordind-denylist",
            Self::SpdxHeader => "spdx-header",
            Self::LintTable => "lint-table",
            Self::ClippyConfig => "clippy-config",
        };
        f.write_str(id)
    }
}

/// One broken rule in one crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// The crate that breaks the rule.
    pub crate_name: String,
    /// The rule it breaks.
    pub rule: Rule,
    /// What is wrong, in a sentence that follows the crate's name.
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} {}", self.rule, self.crate_name, self.message)
    }
}

/// Why the checks couldn't run at all.
#[derive(Debug)]
pub enum Error {
    /// `cargo metadata` failed.
    Metadata(String),
    /// A file couldn't be read.
    Io(String, String),
    /// A TOML file couldn't be parsed.
    Parse(String, String),
}

impl Error {
    fn io(path: &Path, e: &std::io::Error) -> Self {
        Self::Io(path.display().to_string(), e.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata(e) => write!(f, "cargo metadata failed: {e}"),
            Self::Io(path, e) => write!(f, "can't read {path}: {e}"),
            Self::Parse(path, e) => write!(f, "can't parse {path}: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Runs every check on the workspace whose root `Cargo.toml` is `manifest`.
/// The violations are sorted by crate, then rule, then message.
///
/// # Errors
///
/// Returns an error if `cargo metadata` fails or a file can't be read.
pub fn check_workspace(manifest: &Path) -> Result<Vec<Violation>, Error> {
    let meta = cargo_metadata::MetadataCommand::new()
        .manifest_path(manifest)
        .exec()
        .map_err(|e| Error::Metadata(e.to_string()))?;
    let model = model::Model::from_metadata(&meta);
    let mut violations = rules::check(&model);
    violations.extend(files::check(&model, meta.workspace_root.as_std_path())?);
    violations.sort_by(|a, b| {
        (&a.crate_name, a.rule, &a.message).cmp(&(&b.crate_name, b.rule, &b.message))
    });
    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn violations_display_rule_crate_and_message() {
        let v = Violation {
            crate_name: "ordin-core".into(),
            rule: Rule::Layer0Io,
            message: "is in layer 0 but depends on the I/O crate tokio: ordin-core -> tokio".into(),
        };
        assert_eq!(
            v.to_string(),
            "[layer-0-io] ordin-core is in layer 0 but depends on the I/O crate tokio: ordin-core -> tokio"
        );
    }

    #[test]
    fn every_rule_has_a_distinct_id() {
        let rules = [
            Rule::Layer,
            Rule::License,
            Rule::UpwardDependency,
            Rule::ToolDependency,
            Rule::PermissiveDependsOnGpl,
            Rule::Layer0Io,
            Rule::OrdindDenylist,
            Rule::SpdxHeader,
            Rule::LintTable,
            Rule::ClippyConfig,
        ];
        let mut ids: Vec<String> = rules.iter().map(ToString::to_string).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), rules.len());
    }

    #[test]
    fn errors_name_what_failed() {
        assert!(
            Error::Metadata("boom".into())
                .to_string()
                .contains("cargo metadata")
        );
        let io = Error::io(Path::new("/x/Cargo.toml"), &std::io::Error::other("denied"));
        assert_eq!(io.to_string(), "can't read /x/Cargo.toml: denied");
        assert!(
            Error::Parse("a.toml".into(), "bad".into())
                .to_string()
                .contains("can't parse a.toml")
        );
    }

    #[test]
    fn a_missing_manifest_is_a_metadata_error() {
        let e = check_workspace(Path::new("/nonexistent/xtask/Cargo.toml")).unwrap_err();
        assert!(matches!(e, Error::Metadata(_)));
    }
}
