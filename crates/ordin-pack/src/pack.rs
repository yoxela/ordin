// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Rung 0: an install root to a `.ordin` file, in one call.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ordin_archive::{Options as WriteOptions, Package, WriteError, Written};
use ordin_core::{Arch, Digest, Facet, FilePath, PackageName};
use ordin_manifest::spdx;
use ordin_manifest::{FacetEntry, Kind as PackageKind, License, Manifest, Presentation, State};
use ordin_tree::chunk::ChunkParams;
use ordin_tree::{Kind, TreePath};
use ordin_version::Version;

use crate::error::WalkError;
use crate::facets::{FacetError, FacetNote, classify};
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
    /// What it runs on.
    pub arch: Arch,
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
}

/// What [`pack`] made.
#[derive(Clone, Debug)]
pub struct Packed {
    /// The manifest.
    pub manifest: Manifest,
    /// The file that was written.
    pub written: Written,
    /// Setuid and setgid files nobody declared.
    pub warnings: Vec<Warning>,
    /// What the facet classification noted.
    pub notes: Vec<FacetNote>,
}

/// Why a package couldn't be made.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    /// The install root couldn't be walked.
    #[error("{0}")]
    Walk(#[from] WalkError),
    /// A path doesn't fit Ordin's layout.
    #[error("{0}")]
    Layout(#[from] LayoutError),
    /// A facet override can't be used.
    #[error("{0}")]
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
    #[error("the tree for facet {facet}: {source}")]
    Tree {
        /// The facet.
        facet: Facet,
        /// What is wrong.
        source: Box<ordin_tree::Error>,
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
    #[error("{path}: {source}")]
    Root {
        /// The install root.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// Writing the package failed.
    #[error("{0}")]
    Write(#[from] WriteError),
    /// The output file couldn't be made or put in place.
    #[error("{path}: {source}")]
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

/// Refuses an output path inside the install root.
fn check_output(root: &Path, out: &Path) -> Result<PathBuf, PackError> {
    let dir = output_dir(out);
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
    Ok(dir)
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
pub fn pack(options: &PackOptions, out: &Path) -> Result<Packed, PackError> {
    let dir = check_output(&options.root, out)?;
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
        options.arch,
        options.summary.clone(),
        license,
        facets,
    );
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
    manifest.to_canonical_bytes()?;

    let mut source = RootSource::new(&options.root, layout.origins.clone()).map_err(|source| {
        PackError::Root {
            path: options.root.clone(),
            source,
        }
    })?;
    let output = |source| PackError::Output {
        path: out.to_path_buf(),
        source,
    };
    let temp = tempfile::Builder::new()
        .prefix(".ordin-")
        .suffix(".tmp")
        .tempfile_in(&dir)
        .map_err(output)?;
    let mut writer = BufWriter::new(temp.as_file());
    let package = Package {
        manifest: &manifest,
        trees: &trees,
        licenses: &options.license_texts,
        chunking: options.chunking,
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
        written,
        warnings: walked.warnings,
        notes: classified.notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_file_name_is_written_in_the_current_directory() {
        assert_eq!(output_dir(Path::new("x.ordin")), PathBuf::from("."));
        assert_eq!(output_dir(Path::new("a/x.ordin")), PathBuf::from("a"));
        assert_eq!(output_dir(Path::new("/x.ordin")), PathBuf::from("/"));
        assert_eq!(output_dir(Path::new("/")), PathBuf::from("."));
    }
}
