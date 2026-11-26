// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `ordin unpack`: a package's files written to a new directory, without
//! root, for looking at what is inside.
//!
//! Everything is written into a new private directory beside the one
//! asked for, and renamed into place only when all of it is there, so a
//! failure leaves nothing behind and nothing is ever replaced. Each
//! directory is opened a name at a time without following symlinks, and
//! each file is created new, so nothing in the package can make a write
//! land outside. Each file is read through the package reader, which
//! checks every chunk and then the whole file against its tree.
//!
//! Only permission bits are applied. Owners, the setuid, setgid and
//! sticky bits, extended attributes and capabilities need root, or would
//! make the copy grant what the package grants, so they are left out and
//! recorded instead: the sidecar file holds every unpacked facet's tree,
//! exactly.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File as FsFile;
use std::io::{BufReader, BufWriter, Read, Seek};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ordin_archive::{PackTable, Reader};
use ordin_core::json::{self, Value};
use ordin_core::{Digest, Facet};
use ordin_tree::chunk::ChunkIndex;
use ordin_tree::{Entry, Kind, Tree, TreePath};
use rustix::fs::{self as sys, AtFlags, Mode, OFlags, RenameFlags};
use tempfile::TempDir;

use crate::cli::UnpackArgs;
use crate::files;

/// Opens a directory to write in: never through a symlink.
const OPEN_DIR: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW);

/// Creates a file: always a new one, never through a symlink.
const CREATE_FILE: OFlags = OFlags::WRONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW);

/// The suffix of the sidecar file's name.
pub const SIDECAR_SUFFIX: &str = ".ordin-meta.json";

/// The mode a directory has while it is being filled: its owner can do
/// anything in it, and nobody else anything.
const WHILE_FILLING: u32 = 0o700;

/// What `ordin unpack` wrote.
#[derive(Debug)]
pub struct Unpacked {
    /// The package file.
    pub file: PathBuf,
    /// The directory written.
    pub to: PathBuf,
    /// The sidecar file, with each unpacked facet's tree.
    pub meta: PathBuf,
    /// The package's identity.
    pub package: Digest,
    /// The facets unpacked, in order.
    pub facets: Vec<Facet>,
    /// How many directories were made.
    pub dirs: usize,
    /// How many files were written.
    pub files: usize,
    /// How many symlinks were made.
    pub symlinks: usize,
    /// How many hard links were made.
    pub hard_links: usize,
    /// How many bytes of file content were written.
    pub size: u64,
}

/// The permission bits of a mode: what is applied.
fn permissions(mode: ordin_core::Mode) -> Mode {
    Mode::from_raw_mode(u32::from(mode.value()) & 0o777)
}

/// The facets' entries as one tree, in path order, each with its facet.
/// A directory may be in several facets if it is the same in each; any
/// other path may be in only one.
///
/// # Errors
///
/// A path two facets both have, other than one identical directory.
fn merge(trees: &[(Facet, Tree)]) -> Result<Vec<(&Facet, &Entry)>> {
    let mut merged: BTreeMap<&TreePath, (&Facet, &Entry)> = BTreeMap::new();
    for (facet, tree) in trees {
        for entry in tree.entries() {
            let Some((other, first)) = merged.get(&entry.path) else {
                merged.insert(&entry.path, (facet, entry));
                continue;
            };
            match (&first.kind, &entry.kind) {
                (Kind::Dir(a), Kind::Dir(b)) if a == b => {}
                (Kind::Dir(_), Kind::Dir(_)) => bail!(
                    "{} is a directory in facets {other} and {facet} with different \
                     owners, modes or attributes",
                    entry.path.as_str()
                ),
                _ => bail!(
                    "{} is in facets {other} and {facet}; only a directory can be in two",
                    entry.path.as_str()
                ),
            }
        }
    }
    Ok(merged.into_values().collect())
}

/// The last name of `path`.
fn name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or_default()
}

/// Opens the directory `path` under `root`, a name at a time, never
/// following a symlink. `/` is `root` itself.
fn open_dir(root: &OwnedFd, path: &str) -> rustix::io::Result<OwnedFd> {
    let mut dir = sys::openat(root, ".", OPEN_DIR, Mode::empty())?;
    for name in path.split('/').filter(|n| !n.is_empty()) {
        dir = sys::openat(&dir, name, OPEN_DIR, Mode::empty())?;
    }
    Ok(dir)
}

/// The counts of what was written.
#[derive(Default)]
struct Counts {
    dirs: usize,
    files: usize,
    symlinks: usize,
    hard_links: usize,
    size: u64,
}

/// What reading the files needs.
struct Source<R> {
    reader: Reader<R>,
    index: ChunkIndex,
    tables: BTreeMap<Facet, PackTable>,
}

/// Writes one entry under `root`.
fn write_entry<R: Read + Seek>(
    root: &OwnedFd,
    source: &mut Source<R>,
    facet: &Facet,
    entry: &Entry,
    counts: &mut Counts,
) -> Result<()> {
    let path = entry.path.as_str();
    let parent = open_dir(root, entry.path.parent())?;
    let name = name(path);
    match &entry.kind {
        Kind::Dir(_) => {
            sys::mkdirat(&parent, name, Mode::from_raw_mode(WHILE_FILLING))?;
            // The umask may have taken some of those bits.
            let dir = sys::openat(&parent, name, OPEN_DIR, Mode::empty())?;
            sys::fchmod(&dir, Mode::from_raw_mode(WHILE_FILLING))?;
            counts.dirs += 1;
        }
        Kind::File(file) => {
            let fd = sys::openat(&parent, name, CREATE_FILE, Mode::from_raw_mode(0o600))?;
            let mut out = BufWriter::new(FsFile::from(fd));
            let table = source
                .tables
                .get(facet)
                .context("the facet has no pack table")?;
            source
                .reader
                .read_file(facet, table, &source.index, &entry.path, file, &mut out)?;
            let written = out.into_inner().map_err(|e| e.into_error())?;
            sys::fchmod(&written, permissions(file.mode))?;
            counts.files += 1;
            counts.size += file.size;
        }
        Kind::Symlink(link) => {
            sys::symlinkat(link.target.as_str(), &parent, name)?;
            counts.symlinks += 1;
        }
        Kind::HardLink(target) => {
            let from = open_dir(root, target.parent())?;
            sys::linkat(
                &from,
                self::name(target.as_str()),
                &parent,
                name,
                AtFlags::empty(),
            )?;
            counts.hard_links += 1;
        }
    }
    Ok(())
}

/// Gives every directory in `dirs` its permission bits, deepest first, so
/// a directory its owner can't write is filled before it closes.
fn close_dirs(root: &OwnedFd, dirs: &[(&TreePath, ordin_core::Mode)]) -> Result<()> {
    for (path, mode) in dirs.iter().rev() {
        let dir = open_dir(root, path.as_str()).with_context(|| path.as_str().to_owned())?;
        sys::fchmod(&dir, permissions(*mode)).with_context(|| path.as_str().to_owned())?;
    }
    Ok(())
}

/// Opens every directory in `dirs` again, parents first, so the
/// temporary directory can be removed whatever their modes. A directory
/// is changed through its parent, since its own mode may not let it be
/// opened.
fn reopen_dirs(root: &OwnedFd, dirs: &[(&TreePath, ordin_core::Mode)]) {
    for (path, _) in dirs {
        if let Ok(parent) = open_dir(root, path.parent()) {
            let _ = sys::chmodat(
                &parent,
                name(path.as_str()),
                Mode::from_raw_mode(WHILE_FILLING),
                AtFlags::empty(),
            );
        }
    }
}

/// Closes the directories in `temp` and renames it to `to`, which must
/// not exist. If either fails, the directories are opened again so that
/// dropping `temp` removes everything.
fn place(temp: TempDir, dirs: &[(&TreePath, ordin_core::Mode)], to: &Path) -> Result<()> {
    let root = sys::open(temp.path(), OPEN_DIR, Mode::empty())?;
    let placed = close_dirs(&root, dirs).and_then(|()| {
        sys::renameat_with(sys::CWD, temp.path(), sys::CWD, to, RenameFlags::NOREPLACE)
            .with_context(|| to.display().to_string())
    });
    match placed {
        Ok(()) => {
            // It is `to` now: nothing at the old name is ours to remove.
            let mut temp = temp;
            temp.disable_cleanup(true);
            Ok(())
        }
        Err(e) => {
            reopen_dirs(&root, dirs);
            drop(temp);
            Err(e)
        }
    }
}

/// Writes the sidecar `meta`, then places `temp` at `to`. If placing
/// fails, the sidecar is removed again.
fn finish(
    meta: &Path,
    text: &str,
    temp: TempDir,
    dirs: &[(&TreePath, ordin_core::Mode)],
    to: &Path,
) -> Result<()> {
    files::write_new(meta, text.as_bytes(), 0o644)?;
    place(temp, dirs, to).inspect_err(|_| {
        let _ = std::fs::remove_file(meta);
    })
}

/// The sidecar file's canonical JSON: each facet's tree, exactly, and the
/// package's identity.
fn sidecar(trees: &[(Facet, Tree)], package: Digest) -> Result<String> {
    let mut text = String::from("{\"facets\":{");
    for (i, (facet, tree)) in trees.iter().enumerate() {
        if i > 0 {
            text.push(',');
        }
        json::write_canonical(&Value::Str(facet.to_string()), &mut text);
        text.push(':');
        text.push_str(&String::from_utf8(tree.to_canonical_bytes()?)?);
    }
    text.push_str("},\"ordin-unpack\":1,\"package\":");
    json::write_canonical(&Value::Str(package.to_string()), &mut text);
    text.push('}');
    Ok(text)
}

/// Where the directory goes and its sidecar: `to`'s parent, and the
/// sidecar beside `to`.
fn destination(to: &Path) -> Result<(PathBuf, PathBuf)> {
    let Some(last) = to.file_name() else {
        bail!(
            "{}: --to must name a new directory, by a name that isn't '.' or '..'",
            to.display()
        );
    };
    let parent = match to.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut meta = OsString::from(last);
    meta.push(SIDECAR_SUFFIX);
    Ok((parent, to.with_file_name(meta)))
}

/// Refuses a path that exists, as anything.
fn must_be_new(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok() {
        bail!(
            "{}: already exists; ordin unpack never replaces anything",
            path.display()
        );
    }
    Ok(())
}

/// Runs `ordin unpack`.
///
/// # Errors
///
/// `--to` or its sidecar already exists, the package can't be read or
/// is damaged, a `--facet` isn't in it, two facets disagree about a path,
/// or writing fails. Nothing is left behind.
pub fn run(args: &UnpackArgs) -> Result<Unpacked> {
    let to = &args.to;
    let (parent, meta) = destination(to)?;
    must_be_new(to)?;
    must_be_new(&meta)?;
    let file = &args.file;
    let shown = || file.display().to_string();
    let mut reader = Reader::open(BufReader::new(files::open_regular(
        file,
        "not a regular file",
    )?))
    .with_context(shown)?;
    let all: Vec<Facet> = reader.facets().cloned().collect();
    let asked: BTreeSet<&Facet> = args.facet.iter().collect();
    if let Some(missing) = asked.iter().find(|f| !all.contains(f)) {
        let has: Vec<String> = all.iter().map(ToString::to_string).collect();
        bail!(
            "{}: the package has no facet {missing}; it has {}",
            file.display(),
            has.join(", ")
        );
    }
    let facets: Vec<Facet> = all
        .into_iter()
        .filter(|f| asked.is_empty() || asked.contains(f))
        .collect();
    let mut trees = Vec::with_capacity(facets.len());
    let mut tables = BTreeMap::new();
    for facet in &facets {
        trees.push((facet.clone(), reader.tree(facet).with_context(shown)?));
        tables.insert(facet.clone(), reader.pack_table(facet).with_context(shown)?);
    }
    let entries = merge(&trees).with_context(shown)?;
    let index = reader.chunk_index().with_context(shown)?;
    let package = reader.package();
    let mut source = Source {
        reader,
        index,
        tables,
    };

    let temp = tempfile::Builder::new()
        .prefix(".ordin-unpack-")
        .tempdir_in(&parent)
        .with_context(|| parent.display().to_string())?;
    let root = sys::open(temp.path(), OPEN_DIR, Mode::empty())
        .with_context(|| parent.display().to_string())?;
    // Private while it is filled, and afterwards: only its owner sees in.
    sys::fchmod(&root, Mode::from_raw_mode(WHILE_FILLING))
        .with_context(|| parent.display().to_string())?;
    let mut counts = Counts::default();
    for (facet, entry) in &entries {
        write_entry(&root, &mut source, facet, entry, &mut counts)
            .with_context(|| format!("{}{}", to.display(), entry.path.as_str()))?;
    }
    let dirs: Vec<(&TreePath, ordin_core::Mode)> = entries
        .iter()
        .filter_map(|(_, e)| match &e.kind {
            Kind::Dir(d) => Some((&e.path, d.mode)),
            _ => None,
        })
        .collect();
    finish(&meta, &sidecar(&trees, package)?, temp, &dirs, to)?;
    Ok(Unpacked {
        file: file.clone(),
        to: to.clone(),
        meta,
        package,
        facets,
        dirs: counts.dirs,
        files: counts.files,
        symlinks: counts.symlinks,
        hard_links: counts.hard_links,
        size: counts.size,
    })
}

#[cfg(test)]
mod tests {
    use ordin_core::Account;
    use ordin_tree::{Dir, Symlink, Xattrs};

    use super::*;

    fn facet(name: &str) -> Facet {
        name.parse().unwrap()
    }

    fn dir(path: &str, mode: u16) -> Entry {
        Entry {
            path: path.parse().unwrap(),
            kind: Kind::Dir(Dir {
                mode: ordin_core::Mode::new(mode).unwrap(),
                owner: Account::root(),
                group: Account::root(),
                xattrs: Xattrs::new(),
            }),
        }
    }

    fn link(path: &str, target: &str) -> Entry {
        Entry {
            path: path.parse().unwrap(),
            kind: Kind::Symlink(Symlink {
                target: target.parse().unwrap(),
                owner: Account::root(),
                group: Account::root(),
            }),
        }
    }

    fn tree(entries: Vec<Entry>) -> Tree {
        Tree::new(entries).unwrap()
    }

    #[test]
    fn facets_merge_into_one_tree_in_path_order() {
        let trees = [
            (
                facet("doc"),
                tree(vec![dir("/usr", 0o755), dir("/usr/share", 0o755)]),
            ),
            (
                facet("runtime"),
                tree(vec![dir("/usr", 0o755), dir("/usr/bin", 0o755)]),
            ),
        ];
        let merged: Vec<(String, String)> = merge(&trees)
            .unwrap()
            .into_iter()
            .map(|(f, e)| (f.to_string(), e.path.as_str().to_owned()))
            .collect();
        assert_eq!(
            merged,
            [
                ("doc".to_owned(), "/usr".to_owned()),
                ("runtime".to_owned(), "/usr/bin".to_owned()),
                ("doc".to_owned(), "/usr/share".to_owned()),
            ]
        );
    }

    #[test]
    fn facets_that_disagree_about_a_path_are_refused() {
        let refused = |a: Vec<Entry>, b: Vec<Entry>| {
            let trees = [(facet("doc"), tree(a)), (facet("runtime"), tree(b))];
            merge(&trees).unwrap_err().to_string()
        };
        assert_eq!(
            refused(vec![dir("/usr", 0o755)], vec![dir("/usr", 0o750)]),
            "/usr is a directory in facets doc and runtime with different owners, \
             modes or attributes"
        );
        // A symlink in one facet where the other has a directory: writing
        // under it could leave the tree.
        assert_eq!(
            refused(
                vec![link("/lib", "/etc")],
                vec![dir("/lib", 0o755), dir("/lib/x", 0o755)]
            ),
            "/lib is in facets doc and runtime; only a directory can be in two"
        );
        assert_eq!(
            refused(vec![link("/a", "b")], vec![link("/a", "b")]),
            "/a is in facets doc and runtime; only a directory can be in two"
        );
    }

    #[test]
    fn directories_are_opened_without_following_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("a/b")).unwrap();
        std::os::unix::fs::symlink("a", temp.path().join("s")).unwrap();
        std::os::unix::fs::symlink("b", temp.path().join("a/t")).unwrap();
        let root = sys::open(temp.path(), OPEN_DIR, Mode::empty()).unwrap();
        assert!(open_dir(&root, "/").is_ok());
        assert!(open_dir(&root, "/a/b").is_ok());
        // Linux refuses a symlink opened as a directory without following
        // it with ENOTDIR or ELOOP.
        for through in ["/s", "/s/b", "/a/t"] {
            let e = open_dir(&root, through).unwrap_err();
            assert!(
                matches!(e, rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP),
                "{through}: {e}"
            );
        }
    }

    #[test]
    fn only_permission_bits_are_applied() {
        let m = |v| permissions(ordin_core::Mode::new(v).unwrap()).as_raw_mode();
        assert_eq!(m(0o4755), 0o755);
        assert_eq!(m(0o2750), 0o750);
        assert_eq!(m(0o1777), 0o777);
        assert_eq!(m(0o7000), 0);
        assert_eq!(m(0o640), 0o640);
    }

    #[test]
    fn the_sidecar_goes_beside_the_directory() {
        let d = |to: &str| {
            let (parent, meta) = destination(Path::new(to)).unwrap();
            (parent.display().to_string(), meta.display().to_string())
        };
        assert_eq!(d("out"), (".".to_owned(), "out.ordin-meta.json".to_owned()));
        assert_eq!(
            d("a/out"),
            ("a".to_owned(), "a/out.ordin-meta.json".to_owned())
        );
        assert_eq!(
            d("a/out/"),
            ("a".to_owned(), "a/out.ordin-meta.json".to_owned())
        );
        assert_eq!(d("/x"), ("/".to_owned(), "/x.ordin-meta.json".to_owned()));
        for bad in ["/", ".", "..", "a/.."] {
            let e = destination(Path::new(bad)).unwrap_err().to_string();
            assert_eq!(
                e,
                format!("{bad}: --to must name a new directory, by a name that isn't '.' or '..'")
            );
        }
    }

    #[test]
    fn the_sidecar_holds_each_tree_exactly() {
        let doc = tree(vec![dir("/usr", 0o755)]);
        let runtime = tree(vec![dir("/usr", 0o755), link("/usr/x", "y")]);
        let package = Digest::blake3(b"p");
        let text = sidecar(
            &[
                (facet("doc"), doc.clone()),
                (facet("runtime"), runtime.clone()),
            ],
            package,
        )
        .unwrap();
        let t = |tree: &Tree| String::from_utf8(tree.to_canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            text,
            format!(
                r#"{{"facets":{{"doc":{},"runtime":{}}},"ordin-unpack":1,"package":"{package}"}}"#,
                t(&doc),
                t(&runtime)
            )
        );
        // It is canonical JSON.
        assert_eq!(json::canonical(&json::parse(&text).unwrap()), text);
    }

    #[test]
    fn a_failed_rename_leaves_nothing_whatever_the_modes() {
        let parent = tempfile::tempdir().unwrap();
        let temp = tempfile::tempdir_in(parent.path()).unwrap();
        let gone = temp.path().to_path_buf();
        std::fs::create_dir_all(gone.join("a/b")).unwrap();
        std::fs::write(gone.join("a/b/f"), b"x").unwrap();
        // The destination appeared after it was checked.
        let to = parent.path().join("to");
        std::fs::create_dir(&to).unwrap();
        std::fs::write(to.join("theirs"), b"keep").unwrap();
        let (a, b): (TreePath, TreePath) = ("/a".parse().unwrap(), "/a/b".parse().unwrap());
        let none = ordin_core::Mode::new(0).unwrap();
        let e = place(temp, &[(&a, none), (&b, none)], &to).unwrap_err();
        assert!(format!("{e:#}").contains("File exists"), "{e:#}");
        assert!(!gone.exists());
        assert_eq!(std::fs::read(to.join("theirs")).unwrap(), b"keep");
    }

    #[test]
    fn a_failed_rename_removes_the_sidecar_too() {
        let parent = tempfile::tempdir().unwrap();
        let temp = tempfile::tempdir_in(parent.path()).unwrap();
        let gone = temp.path().to_path_buf();
        let to = parent.path().join("to");
        std::fs::create_dir(&to).unwrap();
        std::fs::write(to.join("theirs"), b"keep").unwrap();
        let meta = parent.path().join("to.ordin-meta.json");
        assert!(finish(&meta, "{}", temp, &[], &to).is_err());
        assert!(!meta.exists());
        assert!(!gone.exists());
        // And one that succeeds keeps it.
        let temp = tempfile::tempdir_in(parent.path()).unwrap();
        let to = parent.path().join("new");
        let meta = parent.path().join("new.ordin-meta.json");
        finish(&meta, "{}", temp, &[], &to).unwrap();
        assert_eq!(std::fs::read(&meta).unwrap(), b"{}");
        assert!(to.is_dir());
    }

    #[test]
    fn placing_closes_the_directories_and_renames() {
        let parent = tempfile::tempdir().unwrap();
        let temp = tempfile::tempdir_in(parent.path()).unwrap();
        let old = temp.path().to_path_buf();
        std::fs::create_dir_all(old.join("a/b")).unwrap();
        let (a, b): (TreePath, TreePath) = ("/a".parse().unwrap(), "/a/b".parse().unwrap());
        let to = parent.path().join("to");
        place(
            temp,
            &[
                (&a, ordin_core::Mode::new(0o555).unwrap()),
                (&b, ordin_core::Mode::new(0o750).unwrap()),
            ],
            &to,
        )
        .unwrap();
        assert!(!old.exists());
        let mode = |p: &str| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(to.join(p)).unwrap().permissions().mode() & 0o7777
        };
        assert_eq!(mode("a"), 0o555);
        assert_eq!(mode("a/b"), 0o750);
        // So the test directory can be removed.
        sys::chmod(to.join("a"), Mode::from_raw_mode(0o755)).unwrap();
    }
}
