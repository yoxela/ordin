// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `ordin pack`: rung 0, an install root to a package with one command.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use ordin_manifest::Presentation;
use ordin_pack::{Output, PackError, PackOptions, Packed};
use ordin_sign::{PublicKey, SecretKey};
use ordin_tree::chunk::ChunkParams;
use ordin_version::Version;

use crate::cli::{PackArgs, VersionFrom};
use crate::recipe::{self, Used};
use crate::{files, keys};

/// The largest license text read, in bytes: the most a `.ordin` file
/// may carry.
pub const MAX_LICENSE_TEXT: u64 = ordin_archive::MAX_LICENSE_TEXT;

/// What `ordin pack` did.
#[derive(Debug)]
pub struct Report {
    /// The package, and where it was written.
    pub packed: Packed,
    /// The key it was signed with, if any.
    pub signer: Option<PublicKey>,
    /// The recipe read, if any.
    pub recipe: Option<PathBuf>,
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
    files::read_small(path, MAX_LICENSE_TEXT, "a license text")
}

/// The license texts: the recipe's, read below its directory, then each
/// `--license-file`, which replaces the recipe's text for its ID.
fn license_texts(
    recipe: Option<&Used>,
    flags: &[(String, PathBuf)],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut texts = BTreeMap::new();
    if let Some(used) = recipe {
        for (id, path) in &used.recipe.license.files {
            let text = files::read_beneath(used.dir(), path, MAX_LICENSE_TEXT, "a license text")?;
            texts.insert(id.clone(), text);
        }
    }
    let mut given = BTreeSet::new();
    for (id, path) in flags {
        if !given.insert(id) {
            bail!("--license-file names {id} twice");
        }
        texts.insert(id.clone(), read_text(path)?);
    }
    Ok(texts)
}

/// A command-line mistake found once the recipe is read: something
/// needed that neither the flags nor the recipe give. It exits with 2,
/// as a mistake clap finds does.
#[derive(Debug)]
pub struct Usage(pub String);

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Usage {}

/// Adds what to do about an error, where there is something to do.
fn hint(e: PackError) -> anyhow::Error {
    match &e {
        PackError::MissingLicenseText(id) => {
            anyhow!(
                "{e}; give it with --license-file {id}=PATH, or in the recipe's [license] files"
            )
        }
        PackError::ExtraLicenseText { id, .. } => {
            anyhow!("{e}; add {id} to the license, or drop its text")
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
    let used = recipe::read(args.manifest.as_deref(), args.no_manifest)?;
    let package = used.as_ref().map(|u| &u.recipe.package);
    let from_recipe = |field: fn(&ordin_recipe::Package) -> Option<String>| package.and_then(field);
    let Some(name) = args
        .name
        .clone()
        .or_else(|| package.and_then(|p| p.name.clone()))
    else {
        return Err(Usage(
            "the package has no name: give --name, or name in the recipe's [package]".to_owned(),
        )
        .into());
    };
    let (upstream, commit) = match (args.version_from, &args.version) {
        (Some(VersionFrom::Git), _) => {
            let made =
                ordin_pack::git::version(Path::new(".")).context("making the version from git")?;
            (made.upstream, Some(made.commit))
        }
        (None, Some(version)) => (version.clone(), None),
        (None, None) => match from_recipe(|p| p.version.clone()) {
            Some(version) => (version, None),
            None => {
                return Err(Usage(
                    "the package has no version: give --version or --version-from git, or version in the recipe's [package]".to_owned(),
                )
                .into());
            }
        },
    };
    let release = args
        .release
        .clone()
        .or_else(|| from_recipe(|p| p.release.clone()))
        .unwrap_or_else(|| "1".to_owned());
    let version = version(&upstream, &release)?;
    let summary = args
        .summary
        .clone()
        .or_else(|| from_recipe(|p| p.summary.clone()))
        .unwrap_or_else(|| {
            warnings.push("no summary was given, so the summary is the package's name".to_owned());
            name.to_string()
        });
    let license = args
        .license
        .clone()
        .or_else(|| from_recipe(|p| p.license.clone()))
        .unwrap_or_else(|| {
            warnings.push("no license was given, so the license is NOASSERTION".to_owned());
            "NOASSERTION".to_owned()
        });
    let signer = args
        .sign_key
        .as_deref()
        .map(|key| keys::load(key, args.passphrase_file.as_deref()))
        .transpose()?;
    let signed_by = signer.as_ref().map(SecretKey::public_key);
    let out = args
        .out
        .clone()
        .map_or_else(|| Output::Named(PathBuf::from(".")), Output::File);
    let options = PackOptions {
        root: args.dir.clone(),
        name,
        version,
        arch: args.arch.or_else(|| package.and_then(|p| p.arch)),
        summary,
        description: package.and_then(|p| p.description.clone()),
        homepage: package.and_then(|p| p.homepage.clone()),
        license,
        presentation: used
            .as_ref()
            .and_then(|u| u.recipe.license.presentation)
            .unwrap_or(Presentation::Informational),
        license_texts: license_texts(used.as_ref(), &args.license_files)?,
        owners: args.owners.clone(),
        setuid: args.setuid.iter().cloned().collect(),
        prefixes: args.prefixes.clone(),
        chunking: ChunkParams::DEFAULT,
        write: ordin_archive::Options::default(),
        signer: signer.map(Arc::new),
        commit,
        declared: used
            .as_ref()
            .map(|u| u.recipe.declared.clone())
            .unwrap_or_default(),
    };
    let packed = ordin_pack::pack(&options, &out).map_err(hint)?;
    warnings.extend(packed.warnings.iter().map(ToString::to_string));
    warnings.extend(packed.notes.iter().map(ToString::to_string));
    warnings.extend(packed.inferred.iter().map(ToString::to_string));
    Ok(Report {
        packed,
        signer: signed_by,
        recipe: used.map(|u| u.path),
        warnings,
    })
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
