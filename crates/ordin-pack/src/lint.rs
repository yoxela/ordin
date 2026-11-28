// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `ordin lint`: likely mistakes in a package, found before it is
//! published.
//!
//! [`lint`] reads a `.ordin` file's manifest and facet trees, and infers
//! requirements again from the files themselves, read through the
//! archive, which checks each one against its digest. Each warning names
//! its [`Check`], so a recipe's `[[lint.allow]]` can accept it on purpose,
//! with a reason.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File as FsFile;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use ordin_archive::{PackTable, ReadError, Reader, Source};
use ordin_core::{Atom, Facet, FilePath};
use ordin_depexpr::Requirement;
use ordin_manifest::Manifest;
use ordin_recipe::{Allow, Check, below};
use ordin_tree::chunk::ChunkIndex;
use ordin_tree::{Entry, File, Kind, Tree, TreePath};

use crate::elf::MAGIC;
use crate::infer::{InferError, InferNote, Inferred, LIBRARY_DIRS, infer};
use crate::shebang::HEAD;

/// Interpreters every system is expected to have one way or another, so
/// a `#!` line naming one isn't unusual.
pub const KNOWN_INTERPRETERS: &[&str] = &[
    "/usr/bin/awk",
    "/usr/bin/bash",
    "/usr/bin/busybox",
    "/usr/bin/csh",
    "/usr/bin/dash",
    "/usr/bin/expect",
    "/usr/bin/fish",
    "/usr/bin/gawk",
    "/usr/bin/ksh",
    "/usr/bin/luajit",
    "/usr/bin/make",
    "/usr/bin/mawk",
    "/usr/bin/mksh",
    "/usr/bin/node",
    "/usr/bin/nodejs",
    "/usr/bin/pwsh",
    "/usr/bin/Rscript",
    "/usr/bin/sed",
    "/usr/bin/sh",
    "/usr/bin/tcsh",
    "/usr/bin/zsh",
    "/usr/sbin/nft",
];

/// Interpreters known with or without a version after their name:
/// `/usr/bin/python3` and `/usr/bin/python3.12`.
pub const VERSIONED_INTERPRETERS: &[&str] = &[
    "/usr/bin/guile",
    "/usr/bin/lua",
    "/usr/bin/perl",
    "/usr/bin/php",
    "/usr/bin/python3",
    "/usr/bin/ruby",
    "/usr/bin/tclsh",
    "/usr/bin/wish",
];

/// Whether `path` is an interpreter Ordin knows.
#[must_use]
pub fn known_interpreter(path: &str) -> bool {
    KNOWN_INTERPRETERS.contains(&path)
        || VERSIONED_INTERPRETERS.iter().any(|base| {
            path.strip_prefix(base)
                .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
        })
}

/// A likely mistake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// What found it.
    pub check: Check,
    /// The path in the package it is about, if any.
    pub path: Option<String>,
    /// What is wrong.
    pub message: String,
    /// What to do about it, if there is something better than allowing
    /// it.
    pub hint: Option<String>,
}

/// A warning a recipe accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The warning.
    pub finding: Finding,
    /// The allow's reason.
    pub reason: String,
    /// The recipe line the allow starts on.
    pub line: usize,
}

/// What [`lint`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LintReport {
    /// Warnings no allow accepts, in check order, then path order.
    pub warnings: Vec<Finding>,
    /// Warnings an allow accepts, in the same order.
    pub allowed: Vec<Accepted>,
}

/// Why a package couldn't be linted.
#[derive(Debug, thiserror::Error)]
pub enum LintError {
    /// A part of the package couldn't be read, or isn't what it should
    /// be.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// Inferring requirements from its files failed.
    #[error(transparent)]
    Infer(InferError),
    /// Two facets hold the same path, not both as directories.
    #[error("{path} is in both {first} and {second}")]
    Clash {
        /// The path.
        path: TreePath,
        /// The facet it was found in first.
        first: Facet,
        /// The other.
        second: Facet,
    },
    /// The facets' trees together don't make one tree.
    #[error("the facets together aren't one tree: {0}")]
    Merge(ordin_tree::Error),
    /// A file was read that no facet holds.
    #[error("{0} is in no facet")]
    NotInPackage(TreePath),
    /// A temporary copy of an ELF file failed.
    #[error("a temporary copy of {path}: {source}")]
    Temp {
        /// The file.
        path: TreePath,
        /// Why.
        source: io::Error,
    },
}

/// Something to read and seek: a file's content as inference reads it.
trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

/// A file's content as inference reads it: the first [`HEAD`] bytes of
/// most files, or the whole of an ELF file, in an unlinked temporary
/// file.
type Content = Box<dyn ReadSeek>;

/// Where a file's content is written as it is read: its head is kept,
/// and the whole file is copied only once it starts with the ELF magic.
#[derive(Debug, Default)]
struct Sink {
    head: Vec<u8>,
    elf: Option<FsFile>,
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(f) = &mut self.elf {
            f.write_all(buf)?;
            return Ok(buf.len());
        }
        let taken = HEAD.saturating_sub(self.head.len()).min(buf.len());
        let (kept, rest) = buf.split_at(taken);
        self.head.extend_from_slice(kept);
        if self.head.len() >= MAGIC.len() && self.head.starts_with(MAGIC) {
            let mut f = tempfile::tempfile()?;
            f.write_all(&self.head)?;
            f.write_all(rest)?;
            self.elf = Some(f);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn finish(self) -> io::Result<Content> {
        match self.elf {
            Some(mut f) => {
                f.seek(SeekFrom::Start(0))?;
                Ok(Box::new(f))
            }
            None => Ok(Box::new(Cursor::new(self.head))),
        }
    }
}

/// The package's files, read through the archive for inference.
struct Package<'a, R> {
    reader: &'a mut Reader<R>,
    index: &'a ChunkIndex,
    tables: &'a BTreeMap<Facet, PackTable>,
    facet_of: &'a BTreeMap<TreePath, Facet>,
    /// Why the last file couldn't be read, kept whole: inference sees
    /// only an `io::Error`.
    failed: Option<LintError>,
}

impl<R: Read + Seek> Package<'_, R> {
    fn read(&mut self, path: &TreePath, file: &File) -> Result<Content, LintError> {
        let Some((facet, table)) = self
            .facet_of
            .get(path)
            .and_then(|f| self.tables.get_key_value(f))
        else {
            return Err(LintError::NotInPackage(path.clone()));
        };
        let mut sink = Sink::default();
        self.reader
            .read_file(facet, table, self.index, path, file, &mut sink)?;
        sink.finish().map_err(|source| LintError::Temp {
            path: path.clone(),
            source,
        })
    }
}

impl<R: Read + Seek> Source for Package<'_, R> {
    type Reader = Content;

    fn open(&mut self, path: &TreePath, file: &File) -> io::Result<Content> {
        self.read(path, file).map_err(|e| {
            let shown = io::Error::other(e.to_string());
            self.failed = Some(e);
            shown
        })
    }
}

/// Every facet's tree as one, and the facet of each path that isn't a
/// directory.
fn merged(trees: &BTreeMap<Facet, Tree>) -> Result<(Tree, BTreeMap<TreePath, Facet>), LintError> {
    let mut entries: BTreeMap<TreePath, (Entry, &Facet)> = BTreeMap::new();
    for (facet, tree) in trees {
        for entry in tree.entries() {
            if let Some((first, first_facet)) = entries.get(&entry.path) {
                if matches!(first.kind, Kind::Dir(_)) && matches!(entry.kind, Kind::Dir(_)) {
                    continue;
                }
                return Err(LintError::Clash {
                    path: entry.path.clone(),
                    first: (*first_facet).clone(),
                    second: facet.clone(),
                });
            }
            entries.insert(entry.path.clone(), (entry.clone(), facet));
        }
    }
    let facet_of = entries
        .iter()
        .filter(|(_, (e, _))| !matches!(e.kind, Kind::Dir(_)))
        .map(|(p, (_, f))| (p.clone(), (*f).clone()))
        .collect();
    let tree =
        Tree::new(entries.into_values().map(|(e, _)| e).collect()).map_err(LintError::Merge)?;
    Ok((tree, facet_of))
}

/// Lints the package `reader` reads, accepting what `allows` allows.
///
/// # Errors
///
/// A part of the package can't be read or isn't what it should be, its
/// facets don't make one tree, or inferring requirements from its files
/// fails.
pub fn lint<R: Read + Seek>(
    reader: &mut Reader<R>,
    allows: &[Allow],
) -> Result<LintReport, LintError> {
    let manifest = reader.manifest().clone();
    let facets: Vec<Facet> = reader.facets().cloned().collect();
    let index = reader.chunk_index()?;
    let mut trees = BTreeMap::new();
    let mut tables = BTreeMap::new();
    for facet in facets {
        trees.insert(facet.clone(), reader.tree(&facet)?);
        tables.insert(facet.clone(), reader.pack_table(&facet)?);
    }
    let (tree, facet_of) = merged(&trees)?;
    let mut source = Package {
        reader,
        index: &index,
        tables: &tables,
        facet_of: &facet_of,
        failed: None,
    };
    // The same skips as when it was packed, from its own manifest.
    let skip: Vec<FilePath> = manifest
        .inference_skip
        .iter()
        .map(|s| s.path.clone())
        .collect();
    let inferred = infer(&tree, &mut source, &skip)
        .map_err(|e| source.failed.take().unwrap_or(LintError::Infer(e)))?;

    let mut found = Vec::new();
    license(&manifest, &mut found);
    setuid(&manifest, &tree, &mut found);
    world_writable(&manifest, &tree, &mut found);
    notes(&inferred, &mut found);
    interpreters(&inferred, &tree, &mut found);
    so_requirements(&manifest, &inferred, &mut found);
    facet_checks(&trees, &mut found);
    found.sort_by(|a, b| (a.check, &a.path).cmp(&(b.check, &b.path)));
    Ok(judge(found, allows))
}

fn finding(check: Check, path: Option<&str>, message: String, hint: Option<String>) -> Finding {
    Finding {
        check,
        path: path.map(str::to_owned),
        message,
        hint,
    }
}

fn license(manifest: &Manifest, found: &mut Vec<Finding>) {
    if manifest.license.spdx == "NOASSERTION" {
        found.push(finding(
            Check::LicenseUnknown,
            None,
            "the license is NOASSERTION: the package doesn't say what it is".to_owned(),
            Some(
                "give it with --license, or license in the recipe's [package], with its text"
                    .to_owned(),
            ),
        ));
    }
}

const SETUID: u16 = 0o4000;
const SETGID: u16 = 0o2000;

fn setuid(manifest: &Manifest, tree: &Tree, found: &mut Vec<Finding>) {
    // A declaration names the file itself, never one of its hard links:
    // `pack` refuses that.
    let declared = |p: &TreePath| {
        manifest
            .declares
            .setuid
            .iter()
            .any(|d| d.as_str() == p.as_str())
    };
    for entry in tree.entries() {
        let Kind::File(file) = &entry.kind else {
            continue;
        };
        let mode = file.mode.value();
        let (uid, gid) = (mode & SETUID != 0, mode & SETGID != 0);
        if !(uid || gid) || declared(&entry.path) {
            continue;
        }
        let message = match (uid, gid) {
            (true, true) => format!(
                "is setuid and setgid: it runs as {} with group {}, whoever starts it",
                file.owner, file.group
            ),
            (true, false) => format!("is setuid: it runs as {}, whoever starts it", file.owner),
            _ => format!(
                "is setgid: it runs with group {}, whoever starts it",
                file.group
            ),
        };
        found.push(finding(
            Check::SetuidUndeclared,
            Some(entry.path.as_str()),
            message,
            Some(format!(
                "declare it with --setuid {} if it must be, or drop the bit",
                entry.path
            )),
        ));
    }
}

const OTHER_WRITE: u16 = 0o002;

fn world_writable(manifest: &Manifest, tree: &Tree, found: &mut Vec<Finding>) {
    let hint = || Some("take away write permission for others".to_owned());
    for entry in tree.entries() {
        let (mode, what) = match &entry.kind {
            Kind::File(f) => (f.mode.value(), "a file"),
            Kind::Dir(d) => (d.mode.value(), "a directory"),
            _ => continue,
        };
        if mode & OTHER_WRITE != 0 {
            found.push(finding(
                Check::WorldWritable,
                Some(entry.path.as_str()),
                format!("{what} anyone can write to (mode {mode:04o})"),
                hint(),
            ));
        }
    }
    let Some(state) = &manifest.state else {
        return;
    };
    let paths = state
        .paths
        .iter()
        .map(|p| (&p.path, p.mode, "a state directory"));
    let files = state
        .files
        .iter()
        .map(|f| (&f.path, f.mode, "a state file"));
    for (path, mode, what) in paths.chain(files) {
        let mode = mode.value();
        if mode & OTHER_WRITE != 0 {
            found.push(finding(
                Check::WorldWritable,
                Some(path.as_str()),
                format!("{what} anyone can write to (mode {mode:04o})"),
                hint(),
            ));
        }
    }
}

fn notes(inferred: &Inferred, found: &mut Vec<Finding>) {
    for note in &inferred.notes {
        let (check, path, message, hint) = match note {
            InferNote::UnreadableElf { path, why } => (
                Check::ElfUnreadable,
                path,
                format!("has the ELF magic but can't be read, so it adds no requirements: {why}"),
                None,
            ),
            InferNote::PrivateVersion {
                path,
                library,
                node,
            } => (
                Check::SoPrivateVersion,
                path,
                format!(
                    "needs the private version {node} of {library}, which only an exact \
                     version of the package providing it can promise"
                ),
                Some(
                    "require that package at its exact version, in the recipe's requires"
                        .to_owned(),
                ),
            ),
            InferNote::BadVersion {
                path,
                library,
                node,
            } => (
                Check::SoBadName,
                path,
                format!(
                    "the version {node:?} of {library} can't be an so: atom, so it is left \
                     out and {library} is taken without a version"
                ),
                None,
            ),
            InferNote::BadSoname { path, name } => (
                Check::SoBadName,
                path,
                format!("the library name {name:?} can't be an so: atom, so it isn't recorded"),
                None,
            ),
            InferNote::Shebang { path, why } => (
                Check::ShebangUnusual,
                path,
                format!("its interpreter isn't recorded: {why}"),
                Some("declare what it needs in the recipe's requires".to_owned()),
            ),
        };
        found.push(finding(check, Some(path.as_str()), message, hint));
    }
}

fn interpreters(inferred: &Inferred, tree: &Tree, found: &mut Vec<Finding>) {
    for (path, interpreter) in &inferred.scripts {
        if tree.get(interpreter.as_str()).is_none() && !known_interpreter(interpreter.as_str()) {
            found.push(finding(
                Check::InterpreterUnknown,
                Some(path.as_str()),
                format!("its interpreter {interpreter} isn't in the package, nor one Ordin knows"),
                Some(
                    "check its #! line: a misspelt name, or a path from the build machine, is \
                     the usual cause"
                        .to_owned(),
                ),
            ));
        }
    }
}

fn so_requirements(manifest: &Manifest, inferred: &Inferred, found: &mut Vec<Finding>) {
    // A library is needed with any of its versions: a declared
    // so:libc.so.6 is what a program needing so:libc.so.6@GLIBC_2.34 uses.
    let needed: BTreeSet<&str> = inferred
        .requires
        .iter()
        .filter_map(|a| match a {
            Atom::So(so) => Some(so.library()),
            _ => None,
        })
        .collect();
    let needs = |r: &&Requirement| matches!(&r.atom, Atom::So(so) if needed.contains(so.library()));
    let mut unversioned = BTreeSet::new();
    for expr in &manifest.requires {
        let requirements = expr.requirements();
        for r in &requirements {
            if let Atom::So(so) = &r.atom
                && so.library().ends_with(".so")
            {
                unversioned.insert(so.library().to_owned());
            }
        }
        let all_so = requirements.iter().all(|r| matches!(r.atom, Atom::So(_)));
        if all_so && !requirements.iter().any(needs) {
            found.push(finding(
                Check::SoUnneeded,
                None,
                format!("{expr} is required, but no program or library in the package needs it"),
                Some(
                    "drop it, or allow it with a reason if the package loads the library with \
                     dlopen"
                        .to_owned(),
                ),
            ));
        }
    }
    for library in unversioned {
        found.push(finding(
            Check::SoUnversioned,
            None,
            format!(
                "so:{library} is required, but {library} has no version after .so, so any \
                 build of it meets the requirement"
            ),
            Some(
                "link against the library's versioned soname; one ending in .so is usually a \
                 development link"
                    .to_owned(),
            ),
        ));
    }
}

/// Whether `name` is a man page section's directory: `man1`, `man3p`,
/// `mann`.
fn man_section(name: &str) -> bool {
    name.strip_prefix("man")
        .and_then(|rest| rest.chars().next())
        .is_some_and(|c| c.is_ascii_digit() || c == 'n')
}

const HEADERS: &[&str] = &[".h", ".hh", ".hpp", ".hxx"];

/// A directory, what its contents are, and their facet.
type DirRule = (&'static str, &'static str, fn() -> Facet);

/// Directories whose contents belong in another facet than `runtime`.
const DIRS: &[DirRule] = &[
    ("/usr/man", "man pages", Facet::doc),
    ("/usr/doc", "documentation", Facet::doc),
    ("/usr/info", "info pages", Facet::doc),
    ("/usr/share/gtk-doc", "API documentation", Facet::doc),
    ("/usr/share/aclocal", "autoconf macros", Facet::dev),
];

/// What `entry` looks like if it doesn't look like `runtime`: the path
/// to move (a directory above it, where a whole one looks wrong), what
/// it looks like, and the facet it looks like it belongs in.
fn misplaced(entry: &Entry) -> Option<(String, &'static str, Facet)> {
    let path = entry.path.as_str();
    for (dir, what, facet) in DIRS {
        if below(path, dir) {
            return Some(((*dir).to_owned(), what, facet()));
        }
    }
    for lib in LIBRARY_DIRS {
        let cmake = format!("{lib}/cmake");
        if below(path, &cmake) {
            return Some((cmake, "CMake package files", Facet::dev()));
        }
    }
    let names: Vec<&str> = path.split('/').collect();
    let dirs = names.len().saturating_sub(1);
    if let Some(at) = names
        .windows(2)
        .take(dirs.saturating_sub(1))
        .position(|w| w[0] == "man" && man_section(w[1]))
    {
        return Some((names[..=at].join("/"), "man pages", Facet::doc()));
    }
    let name = names.last().copied().unwrap_or_default();
    if HEADERS.iter().any(|ext| name.ends_with(ext)) {
        let subject = match names[..dirs].iter().rposition(|n| *n == "include") {
            Some(at) => names[..=at].join("/"),
            None => path.to_owned(),
        };
        return Some((subject, "C or C++ headers", Facet::dev()));
    }
    let (what, facet) = if name.ends_with(".la") {
        ("a libtool archive", Facet::dev())
    } else if name.ends_with(".pc") {
        ("a pkg-config file", Facet::dev())
    } else if name.ends_with(".debug") {
        ("split debug information", Facet::debug())
    } else if matches!(entry.kind, Kind::Symlink(_))
        && LIBRARY_DIRS.contains(&entry.path.parent())
        && name.starts_with("lib")
        && name.ends_with(".so")
    {
        ("a development link", Facet::dev())
    } else {
        return None;
    };
    Some((path.to_owned(), what, facet))
}

fn facet_checks(trees: &BTreeMap<Facet, Tree>, found: &mut Vec<Finding>) {
    for (facet, tree) in trees {
        if tree
            .entries()
            .iter()
            .all(|e| matches!(e.kind, Kind::Dir(_)))
        {
            found.push(finding(
                Check::FacetEmpty,
                None,
                format!("the facet {facet} holds no files"),
                None,
            ));
        }
    }
    let Some(runtime) = trees.get(&Facet::runtime()) else {
        return;
    };
    let mut moves: BTreeMap<String, (&str, Facet)> = BTreeMap::new();
    for entry in runtime.entries() {
        if matches!(entry.kind, Kind::Dir(_)) {
            continue;
        }
        if let Some((subject, what, facet)) = misplaced(entry) {
            moves.entry(subject).or_insert((what, facet));
        }
    }
    for (subject, (what, facet)) in moves {
        found.push(finding(
            Check::FacetMisclassified,
            Some(&subject),
            format!("looks like {what}, but it is in runtime"),
            Some(format!(
                "move it with [facets.{facet}] extra = [{subject:?}] in the recipe"
            )),
        ));
    }
}

/// Splits `found` into warnings and what `allows` accepts, and warns
/// about each allow, or allowed path, that accepted nothing.
fn judge(found: Vec<Finding>, allows: &[Allow]) -> LintReport {
    let mut report = LintReport::default();
    let mut used: BTreeSet<(usize, Option<&TreePath>)> = BTreeSet::new();
    for f in found {
        let path = f.path.as_deref();
        match allows
            .iter()
            .enumerate()
            .find(|(_, a)| a.covers(f.check, path))
        {
            Some((i, a)) => {
                used.insert((i, path.and_then(|p| a.covering(p))));
                report.allowed.push(Accepted {
                    finding: f,
                    reason: a.reason.clone(),
                    line: a.line,
                });
            }
            None => report.warnings.push(f),
        }
    }
    for (i, a) in allows.iter().enumerate() {
        let hint = || Some("remove it from the recipe".to_owned());
        if a.paths.is_empty() {
            if !used.contains(&(i, None)) {
                report.warnings.push(finding(
                    Check::UnusedAllow,
                    None,
                    format!(
                        "the allow for {} at line {} matches no warning",
                        a.check, a.line
                    ),
                    hint(),
                ));
            }
            continue;
        }
        for p in &a.paths {
            if !used.contains(&(i, Some(p))) {
                report.warnings.push(finding(
                    Check::UnusedAllow,
                    Some(p.as_str()),
                    format!(
                        "the allow for {} at line {} matches no warning here",
                        a.check, a.line
                    ),
                    hint(),
                ));
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ordin_core::{Account, Algorithm, Digest};
    use ordin_tree::{DIR_MODE, Dir, FILE_MODE, Xattrs};

    use super::*;

    fn sink(writes: &[&[u8]]) -> Vec<u8> {
        let mut sink = Sink::default();
        for w in writes {
            assert_eq!(sink.write(w).unwrap(), w.len());
        }
        sink.flush().unwrap();
        let mut content = sink.finish().unwrap();
        let mut bytes = Vec::new();
        content.read_to_end(&mut bytes).unwrap();
        // It can be read again from the start, as inference does.
        content.seek(SeekFrom::Start(1)).unwrap();
        let mut rest = Vec::new();
        content.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, bytes.get(1..).unwrap_or_default());
        bytes
    }

    #[test]
    fn only_an_elf_file_is_kept_whole() {
        let long = vec![b'x'; HEAD * 3];
        // Anything else keeps its head only, however it is written.
        assert_eq!(sink(&[&long]), &long[..HEAD]);
        assert_eq!(sink(&[&long[..10], &long[10..]]), &long[..HEAD]);
        assert_eq!(sink(&[&long[..HEAD], b"more"]), &long[..HEAD]);
        assert_eq!(sink(&[b"#!/bin/sh\n"]), b"#!/bin/sh\n");
        assert_eq!(sink(&[]), b"");
        // The magic alone, or split across writes, keeps everything.
        let mut elf = MAGIC.to_vec();
        elf.extend_from_slice(&long);
        assert_eq!(sink(&[&elf]), elf);
        assert_eq!(sink(&[&elf[..2], &elf[2..3], &elf[3..9], &elf[9..]]), elf);
        assert_eq!(sink(&[MAGIC]), MAGIC);
        // A file too short for the magic isn't ELF.
        assert_eq!(sink(&[&MAGIC[..3]]), &MAGIC[..3]);
        // The magic after the start doesn't count.
        let late = [b"x".as_slice(), MAGIC, &long].concat();
        assert_eq!(sink(&[&late]), &late[..HEAD]);
    }

    fn p(path: &str) -> TreePath {
        path.parse().unwrap()
    }

    fn dir(path: &str) -> Entry {
        Entry {
            path: p(path),
            kind: Kind::Dir(Dir {
                mode: DIR_MODE,
                owner: Account::root(),
                group: Account::root(),
                xattrs: Xattrs::new(),
            }),
        }
    }

    fn file(path: &str) -> Entry {
        Entry {
            path: p(path),
            kind: Kind::File(File {
                mode: FILE_MODE,
                owner: Account::root(),
                group: Account::root(),
                size: 0,
                content: Digest::blake3(b""),
                fsverity: Digest::new(Algorithm::Sha256, [0; 32]),
                xattrs: Xattrs::new(),
                capabilities: None,
            }),
        }
    }

    fn trees(facets: &[(&str, Vec<Entry>)]) -> BTreeMap<Facet, Tree> {
        facets
            .iter()
            .map(|(f, entries)| (f.parse().unwrap(), Tree::new(entries.clone()).unwrap()))
            .collect()
    }

    #[test]
    fn facets_make_one_tree_sharing_only_directories() {
        let (tree, facet_of) = merged(&trees(&[
            (
                "doc",
                vec![dir("/usr"), dir("/usr/share"), file("/usr/share/a")],
            ),
            ("runtime", vec![dir("/usr"), file("/usr/b")]),
        ]))
        .unwrap();
        let paths: Vec<&str> = tree.entries().iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["/usr", "/usr/b", "/usr/share", "/usr/share/a"]);
        let of: Vec<(&str, String)> = facet_of
            .iter()
            .map(|(p, f)| (p.as_str(), f.to_string()))
            .collect();
        assert_eq!(
            of,
            [
                ("/usr/b", "runtime".to_owned()),
                ("/usr/share/a", "doc".to_owned())
            ]
        );
        for (first, second) in [
            (file("/usr/a"), file("/usr/a")),
            (file("/usr/a"), dir("/usr/a")),
            (dir("/usr/a"), file("/usr/a")),
        ] {
            let e = merged(&trees(&[
                ("doc", vec![dir("/usr"), first]),
                ("runtime", vec![dir("/usr"), second]),
            ]))
            .unwrap_err();
            assert_eq!(e.to_string(), "/usr/a is in both doc and runtime");
        }
    }

    #[test]
    fn a_file_in_no_facet_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/a"), b"a\n").unwrap();
        let options = crate::PackOptions {
            root: root.clone(),
            name: "aa".parse().unwrap(),
            version: "1-1".parse().unwrap(),
            arch: None,
            summary: "a".to_owned(),
            description: None,
            homepage: None,
            license: "NONE".to_owned(),
            presentation: ordin_manifest::Presentation::Informational,
            license_texts: BTreeMap::new(),
            owners: Vec::new(),
            setuid: BTreeSet::new(),
            prefixes: Vec::new(),
            chunking: ordin_tree::chunk::ChunkParams::DEFAULT,
            write: ordin_archive::Options {
                level: 1,
                threads: std::num::NonZeroUsize::MIN,
            },
            signer: None,
            commit: None,
            declared: ordin_recipe::Declared::default(),
        };
        let out = dir.path().join("a.ordin");
        crate::pack(&options, &crate::Output::File(out.clone())).unwrap();
        let mut reader =
            Reader::open(std::io::BufReader::new(FsFile::open(&out).unwrap())).unwrap();
        let index = reader.chunk_index().unwrap();
        let tables = BTreeMap::new();
        let facet_of = BTreeMap::new();
        let mut package = Package {
            reader: &mut reader,
            index: &index,
            tables: &tables,
            facet_of: &facet_of,
            failed: None,
        };
        let Entry {
            kind: Kind::File(f),
            ..
        } = file("/usr/bin/a")
        else {
            unreachable!()
        };
        let Err(e) = package.open(&p("/usr/bin/a"), &f) else {
            panic!("a file in no facet must be refused");
        };
        assert_eq!(e.to_string(), "/usr/bin/a is in no facet");
        assert!(matches!(package.failed, Some(LintError::NotInPackage(_))));
    }
}
