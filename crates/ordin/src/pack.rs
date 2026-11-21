// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `ordin pack`: rung 0, an install root to a package with one command.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use ordin_pack::{Output, PackError, PackOptions, Packed};
use ordin_tree::chunk::ChunkParams;
use ordin_version::Version;

use crate::cli::PackArgs;

/// The largest license text read, in bytes.
pub const MAX_LICENSE_TEXT: u64 = 1 << 20;

/// What `ordin pack` did.
#[derive(Debug)]
pub struct Report {
    /// The package, and where it was written.
    pub packed: Packed,
    /// What the packager should know, in order.
    pub warnings: Vec<String>,
}

/// The version: `VERSION` with the release appended.
fn version(text: &str, release: &str) -> Result<Version> {
    let full = format!("{text}-{release}");
    let version: Version = full
        .parse()
        .with_context(|| format!("the version {text:?} with release {release:?}"))?;
    // The release is the text after the last '-', so it reads back as
    // given only if the upstream version and update level do too.
    if version.release() != Some(release) {
        bail!("the version {text:?} with release {release:?} doesn't read back as given");
    }
    Ok(version)
}

/// Reads one license text, refusing anything but a regular file of at
/// most [`MAX_LICENSE_TEXT`] bytes.
fn read_text(path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).with_context(|| format!("{}", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("{}", path.display()))?;
    if !meta.is_file() {
        bail!("{}: a license text must be a regular file", path.display());
    }
    let mut text = Vec::new();
    file.take(MAX_LICENSE_TEXT + 1)
        .read_to_end(&mut text)
        .with_context(|| format!("{}", path.display()))?;
    if text.len() as u64 > MAX_LICENSE_TEXT {
        bail!(
            "{}: a license text is at most {MAX_LICENSE_TEXT} bytes",
            path.display()
        );
    }
    Ok(text)
}

fn license_texts(files: &[(String, PathBuf)]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut texts = BTreeMap::new();
    for (id, path) in files {
        if texts.insert(id.clone(), read_text(path)?).is_some() {
            bail!("--license-file names {id} twice");
        }
    }
    Ok(texts)
}

/// Adds what to do about an error, where there is something to do.
fn hint(e: PackError) -> anyhow::Error {
    match &e {
        PackError::MissingLicenseText(id) => {
            anyhow!("{e}; give it with --license-file {id}=PATH")
        }
        PackError::ExtraLicenseText { id, .. } => {
            anyhow!("{e}; add {id} to --license, or drop its --license-file")
        }
        _ => anyhow!(e),
    }
}

/// Runs `ordin pack`.
///
/// # Errors
///
/// Anything that stops the package being made, with a hint where one
/// helps.
pub fn run(args: &PackArgs) -> Result<Report> {
    let mut warnings = Vec::new();
    let version = version(&args.version, &args.release)?;
    let summary = args.summary.clone().unwrap_or_else(|| {
        warnings.push("no --summary was given, so the summary is the package's name".to_owned());
        args.name.to_string()
    });
    let license = args.license.clone().unwrap_or_else(|| {
        warnings.push("no --license was given, so the license is NOASSERTION".to_owned());
        "NOASSERTION".to_owned()
    });
    let out = args
        .out
        .clone()
        .map_or_else(|| Output::Named(PathBuf::from(".")), Output::File);
    let options = PackOptions {
        root: args.dir.clone(),
        name: args.name.clone(),
        version,
        arch: args.arch,
        summary,
        license,
        license_texts: license_texts(&args.license_files)?,
        owners: args.owners.clone(),
        setuid: args.setuid.iter().cloned().collect(),
        prefixes: args.prefixes.clone(),
        chunking: ChunkParams::DEFAULT,
        write: ordin_archive::Options::default(),
    };
    let packed = ordin_pack::pack(&options, &out).map_err(hint)?;
    warnings.extend(packed.warnings.iter().map(ToString::to_string));
    warnings.extend(packed.notes.iter().map(ToString::to_string));
    warnings.extend(packed.inferred.iter().map(ToString::to_string));
    Ok(Report { packed, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_release_is_appended_to_the_version() {
        let v = version("2.12", "1").unwrap();
        assert_eq!(v.to_string(), "2.12-1");
        let v = version("1:1.0-rc1", "3").unwrap();
        assert_eq!(
            (v.epoch(), v.upstream(), v.release()),
            (1, "1.0-rc1", Some("3"))
        );
        assert!(version("", "1").is_err());
        assert!(version("1.0", "").is_err());
        // A release that would carry an update level, or more than a
        // release, doesn't read back as given.
        assert_eq!(
            version("1.0", "1+u2").unwrap_err().to_string(),
            "the version \"1.0\" with release \"1+u2\" doesn't read back as given"
        );
        assert!(version("1.0", "1-2").is_err());
        // An update level of 0 is hidden, so the release differs alone.
        assert!(version("1.0", "1+u0").is_err());
    }
}
