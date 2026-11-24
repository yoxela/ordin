// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `ordin show`: what a package holds, read without installing or
//! unpacking it.
//!
//! Opening the file checks its archive, its OCI files and its manifest.
//! `--facets` also reads each facet's tree, checked against the digest the
//! manifest records. The chunks are never read: checking them is
//! `ordin verify`'s work.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ordin_archive::Reader;
use ordin_core::Facet;

use crate::cli::ShowArgs;
use crate::output::show::{self as out, Package};

/// Opens `path` for reading if it is a regular file. A FIFO or a device
/// is refused before it is opened, so it can't make `show` wait.
fn open(path: &Path) -> Result<File> {
    let shown = || path.display().to_string();
    if !std::fs::metadata(path).with_context(shown)?.is_file() {
        bail!("{}: not a regular file", path.display());
    }
    let file = File::open(path).with_context(shown)?;
    // The path may have been replaced in between.
    if !file.metadata().with_context(shown)?.is_file() {
        bail!("{}: not a regular file", path.display());
    }
    Ok(file)
}

/// The canonical entries array of a tree's canonical bytes.
fn entries(bytes: Vec<u8>) -> Result<String> {
    let text = String::from_utf8(bytes)?;
    text.strip_prefix("{\"entries\":")
        .and_then(|rest| rest.strip_suffix(",\"ordin-tree\":1}"))
        .map(str::to_owned)
        .context("a tree isn't laid out as format 1 writes it")
}

/// Runs `ordin show` and returns what it prints.
///
/// # Errors
///
/// The file can't be opened, isn't a package, or a tree it holds doesn't
/// read.
pub fn run(args: &ShowArgs) -> Result<String> {
    let path = &args.file;
    let shown = || path.display().to_string();
    let mut reader = Reader::open(BufReader::new(open(path)?)).with_context(shown)?;
    let facets: Vec<Facet> = reader.facets().cloned().collect();
    let manifest = reader.manifest().clone();
    let package = Package {
        file: path,
        manifest: &manifest,
        package: reader.package(),
        image: reader.image(),
    };
    if args.json {
        let signed = String::from_utf8(manifest.to_canonical_bytes()?)?;
        let mut files = Vec::new();
        if args.facets {
            for facet in &facets {
                let tree = reader.tree(facet).with_context(shown)?;
                files.push((facet.clone(), entries(tree.to_canonical_bytes()?)?));
            }
        }
        return Ok(out::json(
            &package,
            &signed,
            args.facets.then_some(&files[..]),
        ));
    }
    if !args.facets {
        return Ok(out::text(&package, None));
    }
    // One tree at a time: each is listed, counted and dropped.
    let (mut counts, mut listings) = (Vec::new(), String::new());
    for facet in &facets {
        let tree = reader.tree(facet).with_context(shown)?;
        counts.push((facet.clone(), tree.entries().len()));
        listings.push_str(&out::facet_text(facet, &tree));
    }
    Ok(out::text(&package, Some(&counts)) + &listings)
}
