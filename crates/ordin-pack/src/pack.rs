// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Rung 0: an install root to a `.ordin` file, in one call.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ordin_archive::{Options as WriteOptions, Package, WriteError, Written};
use ordin_core::{Arch, Digest, Facet, FilePath, PackageName};
use ordin_depexpr::{Expr, Requirement};
use ordin_manifest::spdx;
use ordin_manifest::{
    FacetEntry, Kind as PackageKind, License, Manifest, Presentation, Provide, State,
};
use ordin_sign::SecretKey;
use ordin_tree::chunk::ChunkParams;
use ordin_tree::{Kind, TreePath};
use ordin_version::Version;
use tempfile::NamedTempFile;

use crate::error::WalkError;
use crate::facets::{FacetError, FacetNote, classify};
use crate::infer::{InferError, InferNote, infer};
use crate::layout::{LayoutError, LayoutOptions, normalize};
use crate::owners::OwnerOverride;
use crate::source::RootSource;
use crate::walk::{self, Warning, walk};

/// Everything rung 0 needs to pack an install root.
#[derive(Clone, Debug)]
pub struct PackOptions {
    /// The install root.
    pub root: PathBuf,
    /// The package's name.
    pub name: PackageName,
    /// Its version, with its release.
    pub version: Version,
    /// What it runs on; detected from its programs and libraries if not
    /// given, and `noarch` when it has none.
    pub arch: Option<Arch>,
    /// One line about it.
    pub summary: String,
    /// Its SPDX license expression. `NOASSERTION` when nobody has said.
    pub license: String,
    /// The text of each license ID the expression names, by ID.
    pub license_texts: BTreeMap<String, Vec<u8>>,
    /// Owners other than `root:root`, by install-root path.
    pub owners: Vec<OwnerOverride>,
    /// Setuid and setgid files declared on purpose, by install-root path.
    pub setuid: BTreeSet<TreePath>,
    /// Prefixes the software was installed with, whose contents move to
    /// `/usr`.
    pub prefixes: Vec<TreePath>,
    /// How files are cut into chunks.
    pub chunking: ChunkParams,
    /// How the file is written.
    pub write: WriteOptions,
    /// The key to sign the package with, if any.
    pub signer: Option<Arc<SecretKey>>,
}

/// Where [`pack`] writes the package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// This file.
    File(PathBuf),
    /// [`default_file_name`] in this directory, once the architecture is
    /// known.
    Named(PathBuf),
}

/// The default file name: `NAME-VERSION.ARCH.ordin`. An epoch's `:`
/// becomes `_`, which no version contains.
#[must_use]
pub fn default_file_name(name: &PackageName, version: &Version, arch: Arch) -> String {
    let version = version.to_string().replace(':', "_");
    format!("{name}-{version}.{arch}.ordin")
}

/// What [`pack`] made.
#[derive(Clone, Debug)]
pub struct Packed {
    /// The manifest.
    pub manifest: Manifest,
    /// Where it was written.
    pub out: PathBuf,
    /// The file that was written.
    pub written: Written,
    /// Setuid and setgid files nobody declared.
    pub warnings: Vec<Warning>,
    /// What the facet classification noted.
    pub notes: Vec<FacetNote>,
    /// What inferring requirements noted.
    pub inferred: Vec<InferNote>,
}

/// Why a package couldn't be made.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    /// The package couldn't be signed.
    #[error("signing")]
    Sign(#[from] ordin_sign::Error),
    /// The install root couldn't be walked.
    #[error(transparent)]
    Walk(#[from] WalkError),
    /// A path doesn't fit Ordin's layout.
    #[error(transparent)]
    Layout(#[from] LayoutError),
    /// A facet override can't be used.
    #[error(transparent)]
    Facets(#[from] FacetError),
    /// The license isn't an SPDX expression.
    #[error("the license {license:?}: {why}")]
    License {
        /// The expression given.
        license: String,
        /// What is wrong with it.
        why: String,
    },
    /// A license ID has no text.
    #[error("the license {0} has no text")]
    MissingLicenseText(String),
    /// A text was given for an ID the license doesn't name.
    #[error("a text was given for {id}, which the license {license} doesn't name")]
    ExtraLicenseText {
        /// The ID.
        id: String,
        /// The license.
        license: String,
    },
    /// A declared setuid file isn't in the package.
    #[error("{0}: declared setuid or setgid, but no file in the package came from it")]
    SetuidMissing(TreePath),
    /// A declared setuid file has neither bit.
    #[error("{0}: declared setuid or setgid, but the file is neither")]
    NotSetuid(TreePath),
    /// A facet's tree breaks a rule, for example by being too large.
    #[error("the tree for facet {facet}")]
    Tree {
        /// The facet.
        facet: Facet,
        /// What is wrong.
        source: Box<ordin_tree::Error>,
    },
    /// Requirements couldn't be inferred.
    #[error(transparent)]
    Infer(#[from] InferError),
    /// The architecture given isn't the one the files are built for.
    #[error("--arch {given} was given, but {path} is built for {found}")]
    Arch {
        /// The architecture given.
        given: Arch,
        /// The architecture found.
        found: Arch,
        /// The file that showed it.
        path: TreePath,
    },
    /// The manifest breaks a rule.
    #[error("the manifest: {0}")]
    Manifest(Box<ordin_manifest::Error>),
    /// The output would be inside the install root.
    #[error("{out}: the package can't be written inside the directory it packs ({root})")]
    OutputInsideRoot {
        /// The output path.
        out: PathBuf,
        /// The install root.
        root: PathBuf,
    },
    /// The install root couldn't be opened to read its files.
    #[error("{path}")]
    Root {
        /// The install root.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// Writing the package failed.
    #[error(transparent)]
    Write(#[from] WriteError),
    /// The output file couldn't be made or put in place.
    #[error("{path}")]
    Output {
        /// The output path.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
}

impl From<ordin_manifest::Error> for PackError {
    fn from(e: ordin_manifest::Error) -> Self {
        Self::Manifest(Box::new(e))
    }
}

/// The license, with a digest for each text, checked against the
/// expression.
fn license(options: &PackOptions) -> Result<License, PackError> {
    let parsed = spdx::parse(&options.license).map_err(|why| PackError::License {
        license: options.license.clone(),
        why,
    })?;
    let ids = parsed.text_ids();
    if let Some(id) = ids
        .iter()
        .find(|id| !options.license_texts.contains_key(*id))
    {
        return Err(PackError::MissingLicenseText(id.clone()));
    }
    if let Some(id) = options.license_texts.keys().find(|id| !ids.contains(*id)) {
        return Err(PackError::ExtraLicenseText {
            id: id.clone(),
            license: parsed.to_string(),
        });
    }
    Ok(License {
        spdx: parsed.to_string(),
        presentation: Presentation::Informational,
        texts: options
            .license_texts
            .iter()
            .map(|(id, text)| (id.clone(), Digest::blake3(text)))
            .collect(),
    })
}

/// The setuid bit and the setgid bit of a mode.
const SETUID_OR_SETGID: u16 = 0o6000;

/// The declared setuid files, at their paths in the package.
fn setuid(
    declared: &BTreeSet<TreePath>,
    layout: &crate::layout::Layout,
) -> Result<Vec<FilePath>, PackError> {
    let mut found = Vec::with_capacity(declared.len());
    for path in declared {
        let Some((at, entry)) = layout
            .origins
            .iter()
            .find(|(_, origin)| *origin == path)
            .and_then(|(at, _)| Some((at, layout.tree.get(at.as_str())?)))
        else {
            return Err(PackError::SetuidMissing(path.clone()));
        };
        match &entry.kind {
            Kind::File(f) if f.mode.value() & SETUID_OR_SETGID != 0 => {}
            _ => return Err(PackError::NotSetuid(path.clone())),
        }
        // Every tree path is a valid file path.
        if let Ok(file) = at.as_str().parse() {
            found.push(file);
        }
    }
    Ok(found)
}

/// The directory `out` is written in: its parent, or the current
/// directory for a bare file name.
fn output_dir(out: &Path) -> PathBuf {
    match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Refuses an output directory inside the install root.
fn check_output(root: &Path, dir: &Path, out: &Path) -> Result<(), PackError> {
    let root_real = root.canonicalize().map_err(|source| PackError::Root {
        path: root.to_path_buf(),
        source,
    })?;
    let dir_real = dir.canonicalize().map_err(|source| PackError::Output {
        path: out.to_path_buf(),
        source,
    })?;
    if dir_real.starts_with(&root_real) {
        return Err(PackError::OutputInsideRoot {
            out: out.to_path_buf(),
            root: root.to_path_buf(),
        });
    }
    Ok(())
}

/// The architecture: the one given, which must match the files, or the
/// files', or `noarch` when there are no programs or libraries.
fn arch(given: Option<Arch>, found: Option<&(Arch, TreePath)>) -> Result<Arch, PackError> {
    match (given, found) {
        (Some(given), Some((found, path))) if given != *found => Err(PackError::Arch {
            given,
            found: *found,
            path: path.clone(),
        }),
        (Some(given), _) => Ok(given),
        (None, Some((found, _))) => Ok(*found),
        (None, None) => Ok(Arch::Noarch),
    }
}

/// Packs `options.root` and writes the package to `out`.
///
/// The file is written to a temporary file beside `out`, synced, made
/// readable by everyone (mode 0644) and renamed over `out`, so `out` is
/// either the old file or the complete new one. Chunk packs are spooled
/// in the same directory.
///
/// # Errors
///
/// Anything the walk, layout normalization, facet classification or the
/// writer refuses, a license that isn't an SPDX expression or whose texts
/// don't match it, a declared setuid file that isn't one, an output path
/// inside the install root, and any I/O error writing the output.
pub fn pack(options: &PackOptions, out: &Output) -> Result<Packed, PackError> {
    let dir = match out {
        Output::File(file) => output_dir(file),
        Output::Named(dir) => dir.clone(),
    };
    let shown = match out {
        Output::File(file) => file.clone(),
        Output::Named(dir) => dir.clone(),
    };
    check_output(&options.root, &dir, &shown)?;
    let license = license(options)?;
    let walked = walk(
        &options.root,
        &walk::Options {
            owners: options.owners.clone(),
            setuid: options.setuid.clone(),
        },
    )?;
    let layout = normalize(
        &walked.tree,
        &LayoutOptions {
            name: options.name.clone(),
            prefixes: options.prefixes.clone(),
        },
    )?;
    let setuid = setuid(&options.setuid, &layout)?;
    let mut source = RootSource::new(&options.root, layout.origins.clone()).map_err(|source| {
        PackError::Root {
            path: options.root.clone(),
            source,
        }
    })?;
    let inferred = infer(&layout.tree, &mut source)?;
    let arch = arch(options.arch, inferred.arch.as_ref())?;
    let out = match out {
        Output::File(file) => file.clone(),
        Output::Named(dir) => {
            let name = default_file_name(&options.name, &options.version, arch);
            // The current directory is shown as the bare name.
            if dir == Path::new(".") {
                PathBuf::from(name)
            } else {
                dir.join(name)
            }
        }
    };
    let out = out.as_path();
    let classified = classify(&layout.tree, &[])?;
    let mut facets = BTreeMap::new();
    let mut trees = BTreeMap::new();
    for (facet, built) in classified.facets {
        let tree = built.tree.digest().map_err(|source| PackError::Tree {
            facet: facet.clone(),
            source: Box::new(source),
        })?;
        facets.insert(
            facet.clone(),
            FacetEntry {
                tree,
                size: built.size,
                default: facet != Facet::debug(),
            },
        );
        trees.insert(facet, built.tree);
    }
    let mut manifest = Manifest::new(
        options.name.clone(),
        options.version.clone(),
        PackageKind::Base,
        arch,
        options.summary.clone(),
        license,
        facets,
    );
    manifest.requires = inferred
        .requires
        .iter()
        .map(|atom| Expr::Req(Requirement::new(atom.clone())))
        .collect();
    manifest.provides = inferred
        .provides
        .iter()
        .map(|atom| Provide {
            atom: atom.clone(),
            version: None,
        })
        .collect();
    manifest.declares.config = layout.config.clone();
    manifest.declares.setuid = setuid;
    if !(layout.state_paths.is_empty() && layout.state_files.is_empty() && layout.seeds.is_empty())
    {
        manifest.state = Some(State {
            version: 0,
            migration: ordin_manifest::Migration::None,
            paths: layout.state_paths.clone(),
            files: layout.state_files.clone(),
            seeds: layout.seeds.clone(),
            obsolete: Vec::new(),
            migrations: Vec::new(),
        });
    }
    let identity = Digest::blake3(&manifest.to_canonical_bytes()?);
    let signatures = match &options.signer {
        Some(key) => vec![key.sign(&identity)?],
        None => Vec::new(),
    };

    let output = |source| PackError::Output {
        path: out.to_path_buf(),
        source,
    };
    let temp = temp_file_in(&dir).map_err(output)?;
    let mut writer = BufWriter::new(temp.as_file());
    let package = Package {
        manifest: &manifest,
        trees: &trees,
        licenses: &options.license_texts,
        chunking: options.chunking,
        signatures: &signatures,
    };
    let written = ordin_archive::write(&package, &mut source, &options.write, &dir, &mut writer)?;
    writer.flush().map_err(output)?;
    drop(writer);
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .map_err(output)?;
    temp.as_file().sync_all().map_err(output)?;
    temp.persist(out).map_err(|e| output(e.error))?;
    // The rename is only durable once the directory is synced.
    std::fs::File::open(&dir)
        .and_then(|d| d.sync_all())
        .map_err(output)?;
    Ok(Packed {
        manifest,
        out: out.to_path_buf(),
        written,
        warnings: walked.warnings,
        notes: classified.notes,
        inferred: inferred.notes,
    })
}

/// Makes the temporary file a package is written to, in `dir`, as
/// `tempfile` would: under a name nothing has yet (`O_EXCL`, so an
/// existing file or symlink is never opened), readable and writable by its
/// owner only, and removed if it is dropped. It is opened here, and not by
/// `tempfile`, because `tempfile` adds the temporary file's full path to
/// the system's error, and the error is about the output named.
fn temp_file_in(dir: &Path) -> io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .prefix(".ordin-")
        .suffix(".tmp")
        .make_in(dir, |path| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_temporary_file_is_new_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let temp = temp_file_in(dir.path()).unwrap();
        let name = temp.path().file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with(".ordin-") && name.ends_with(".tmp"),
            "{name}"
        );
        assert_eq!(temp.path().parent().unwrap(), dir.path());
        let mode = temp.as_file().metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o600);
        let path = temp.path().to_path_buf();
        drop(temp);
        assert!(!path.exists());
        // The system's error, as it was.
        let e = temp_file_in(&dir.path().join("missing")).unwrap_err();
        assert_eq!(e.to_string(), "No such file or directory (os error 2)");
    }

    #[test]
    fn the_default_file_name_names_the_package() {
        let name: PackageName = "hello".parse().unwrap();
        let v: Version = "1:2.12-1".parse().unwrap();
        assert_eq!(
            default_file_name(&name, &v, Arch::Noarch),
            "hello-1_2.12-1.noarch.ordin"
        );
    }

    #[test]
    fn the_architecture_is_given_found_or_noarch() {
        let p: TreePath = "/usr/bin/x".parse().unwrap();
        let found = (Arch::Aarch64, p.clone());
        assert_eq!(arch(None, None).unwrap(), Arch::Noarch);
        assert_eq!(arch(None, Some(&found)).unwrap(), Arch::Aarch64);
        assert_eq!(arch(Some(Arch::X86_64), None).unwrap(), Arch::X86_64);
        assert_eq!(
            arch(Some(Arch::Aarch64), Some(&found)).unwrap(),
            Arch::Aarch64
        );
        for given in [Arch::X86_64, Arch::Noarch] {
            assert_eq!(
                arch(Some(given), Some(&found)).unwrap_err().to_string(),
                format!("--arch {given} was given, but /usr/bin/x is built for aarch64")
            );
        }
    }

    #[test]
    fn a_bare_file_name_is_written_in_the_current_directory() {
        assert_eq!(output_dir(Path::new("x.ordin")), PathBuf::from("."));
        assert_eq!(output_dir(Path::new("a/x.ordin")), PathBuf::from("a"));
        assert_eq!(output_dir(Path::new("/x.ordin")), PathBuf::from("/"));
        assert_eq!(output_dir(Path::new("/")), PathBuf::from("."));
    }
}
