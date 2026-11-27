// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `ordin lint`: likely mistakes in a package, before it is published.
//!
//! The package is read, its files through the archive, which checks each
//! one it reads against its digest. The recipe (`./ordin.toml`, or
//! `--manifest`) gives the `[[lint.allow]]` entries that accept warnings
//! on purpose.

use std::io::{BufReader, Read, Seek};
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use ordin_archive::Reader;
use ordin_pack::{LintError, LintReport, lint};
use ordin_recipe::Allow;

use crate::cli::LintArgs;
use crate::verify::is_corruption;
use crate::{files, recipe};

/// The exit code when warnings remain.
pub const WARNINGS: u8 = 4;

/// A package linted.
#[derive(Debug)]
pub struct Linted {
    /// The package file.
    pub file: PathBuf,
    /// The recipe read, if any.
    pub recipe: Option<PathBuf>,
    /// What was found.
    pub report: LintReport,
}

impl Linted {
    /// 0 when no warning remains, [`WARNINGS`] otherwise.
    pub fn exit_code(&self) -> u8 {
        if self.report.warnings.is_empty() {
            0
        } else {
            WARNINGS
        }
    }
}

/// What linting concluded.
#[derive(Debug)]
pub enum Outcome {
    /// The package was read, and linted.
    Linted(Linted),
    /// A part of the file is damaged: the error names it.
    Corrupt(anyhow::Error),
}

/// Runs `ordin lint`.
///
/// # Errors
///
/// The recipe or the package can't be read, or the package can't be
/// linted. A package that is damaged is [`Outcome::Corrupt`], not an
/// error.
pub fn run(args: &LintArgs) -> Result<Outcome> {
    let used = recipe::read(args.manifest.as_deref(), args.no_manifest)?;
    let allows = used.as_ref().map_or(&[][..], |u| &u.recipe.lint[..]);
    let input = BufReader::new(files::open_regular(&args.file, "not a regular file")?);
    let report = match check(input, &args.file, allows)? {
        Ok(report) => report,
        Err(corrupt) => return Ok(Outcome::Corrupt(corrupt)),
    };
    Ok(Outcome::Linted(Linted {
        file: args.file.clone(),
        recipe: used.map(|u| u.path),
        report,
    }))
}

/// Lints the package read from `input`, named `path`: its report, or
/// why it is corrupt.
///
/// # Errors
///
/// It can't be read, or can't be linted for another reason than damage.
fn check(
    input: impl Read + Seek,
    path: &Path,
    allows: &[Allow],
) -> Result<std::result::Result<LintReport, anyhow::Error>> {
    let shown = path.display().to_string();
    let linted = Reader::open(input)
        .map_err(LintError::from)
        .and_then(|mut reader| lint(&mut reader, allows));
    match linted {
        Ok(report) => Ok(Ok(report)),
        Err(LintError::Read(e)) if is_corruption(&e) => {
            Ok(Err(anyhow!(e).context(format!("{shown} is corrupt"))))
        }
        Err(e) => Err(anyhow!(e).context(shown)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Input that can be sought but not read.
    struct Unreadable;

    impl Read for Unreadable {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("the disk is gone"))
        }
    }

    impl Seek for Unreadable {
        fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
            Ok(4096)
        }
    }

    #[test]
    fn a_read_failure_is_an_error_and_damage_is_corruption() {
        let e = check(Unreadable, Path::new("p.ordin"), &[]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "p.ordin: the archive: reading the file: the disk is gone"
        );
        let damaged = std::io::Cursor::new(vec![1; 4096]);
        let e = check(damaged, Path::new("p.ordin"), &[])
            .unwrap()
            .unwrap_err();
        assert!(
            format!("{e:#}").starts_with("p.ordin is corrupt: the archive: "),
            "{e:#}"
        );
    }
}
