// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Laying out archives as an install root.
//!
//! The archives are pinned by hash, but they are still read as if they
//! weren't trusted, because a wrong entry must never write outside the
//! install root:
//!
//! - Every path is a sequence of plain names: an absolute path, a `..` or a
//!   name that isn't UTF-8 is refused.
//! - Every path written is remembered, and nothing is written below a path
//!   that isn't a directory written here, so a symlink in an archive can
//!   never be followed. Files are created new (`O_EXCL`), and a path is
//!   never written twice, except a directory with the same mode each time.
//! - Only files, directories, symlinks and hard links to files already
//!   written are taken. Devices, FIFOs and anything else are refused, and
//!   so are setuid, setgid and sticky bits.
//! - The number of entries and the bytes written are capped.
//!
//! Every entry must be placed or excluded by its source, and every place
//! and exclude must match something, so an upstream change is noticed.
//! Directories are the exception: one that isn't placed is skipped, and
//! made where something placed needs it.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tar::EntryType;

use super::list::{Link, Source};
use crate::release::Error;

/// How much one install root may hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Entries read from all its archives, skipped ones included.
    pub entries: usize,
    /// Bytes of file content written.
    pub bytes: u64,
}

/// The limits the corpus is laid out with: Go, the largest package, has
/// about 17,000 entries and 240 MB.
pub const LIMITS: Limits = Limits {
    entries: 100_000,
    bytes: 2 << 30,
};

/// What was written at a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node {
    Dir { mode: u32, explicit: bool },
    File,
    Symlink,
}

/// Where an archive path goes.
enum Target {
    /// It is excluded.
    Excluded,
    /// Nothing places it.
    Unplaced,
    /// This path in the install root.
    At(String),
}

/// An install root being laid out.
#[derive(Debug)]
pub struct Stage {
    root: PathBuf,
    nodes: BTreeMap<String, Node>,
    entries: usize,
    bytes: u64,
    limits: Limits,
}

impl Stage {
    /// Starts an install root at `root`, which must not exist yet.
    ///
    /// # Errors
    ///
    /// Returns an error if `root` exists or can't be made.
    pub fn create(root: &Path, limits: Limits) -> Result<Self, Error> {
        DirBuilder::new()
            .mode(0o755)
            .create(root)
            .map_err(|e| Error::io(root, &e))?;
        Ok(Self {
            root: root.to_path_buf(),
            nodes: BTreeMap::new(),
            entries: 0,
            bytes: 0,
            limits,
        })
    }

    /// The install root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether `path` is a regular file written here.
    #[must_use]
    pub fn is_file(&self, path: &str) -> bool {
        self.nodes.get(path) == Some(&Node::File)
    }

    /// Lays out the tar stream `tar` as `source` says. `label` names the
    /// source in errors.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive can't be read, an entry is refused
    /// or not placed, a place or exclude matches nothing, a limit is passed,
    /// or a file can't be written.
    pub fn add_tar(&mut self, tar: impl Read, source: &Source, label: &str) -> Result<(), Error> {
        let fail = |e: io::Error| Error::parse(label, e);
        let mut placed = vec![false; source.place.len()];
        let mut excluded = vec![false; source.exclude.len()];
        let mut prefix: Option<Vec<String>> = None;
        let mut archive = tar::Archive::new(tar);
        for entry in archive.entries().map_err(fail)? {
            let mut entry = entry.map_err(fail)?;
            self.entries += 1;
            if self.entries > self.limits.entries {
                return Err(refused(
                    label,
                    format!("more than {} entries", self.limits.entries),
                ));
            }
            let kind = entry.header().entry_type();
            if kind == EntryType::XGlobalHeader {
                continue;
            }
            let shown = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
            let parts = names(&entry.path_bytes(), label)?;
            let Some(path) = strip(
                parts,
                source.strip,
                &mut prefix,
                kind.is_dir(),
                &shown,
                label,
            )?
            else {
                continue;
            };
            let to = match target(&path, source, &mut placed, &mut excluded) {
                Target::Excluded => continue,
                Target::Unplaced if kind.is_dir() => continue,
                Target::Unplaced => {
                    return Err(refused(
                        label,
                        format!("{shown} is neither placed nor excluded"),
                    ));
                }
                Target::At(to) => to,
            };
            let mode = entry.header().mode().map_err(fail)?;
            if mode & 0o7000 != 0 {
                return Err(refused(
                    label,
                    format!("{shown} is setuid, setgid or sticky ({mode:o})"),
                ));
            }
            let mode = mode & 0o777;
            match kind {
                EntryType::Directory => self.dir(&to, mode, label)?,
                EntryType::Regular | EntryType::Continuous => {
                    self.file(&to, mode, &mut entry, label)?;
                }
                EntryType::Symlink => {
                    let link = entry
                        .link_name_bytes()
                        .ok_or_else(|| refused(label, format!("{shown} has no target")))?;
                    let link = std::str::from_utf8(&link)
                        .map_err(|_| refused(label, format!("{shown}'s target isn't UTF-8")))?
                        .to_owned();
                    self.symlink(&to, &link, label)?;
                }
                EntryType::Link => {
                    let link = entry
                        .link_name_bytes()
                        .ok_or_else(|| refused(label, format!("{shown} has no target")))?;
                    let original = names(&link, label)?;
                    let original =
                        strip(original, source.strip, &mut prefix, false, &shown, label)?
                            .and_then(|p| match target(&p, source, &mut placed, &mut excluded) {
                                Target::At(at) => Some(at),
                                Target::Excluded | Target::Unplaced => None,
                            })
                            .ok_or_else(|| {
                                refused(
                                    label,
                                    format!("{shown} links to a file that isn't laid out"),
                                )
                            })?;
                    self.hard_link(&to, &original, label)?;
                }
                other => {
                    return Err(refused(
                        label,
                        format!("{shown} is a {other:?}, which isn't a file, directory or link"),
                    ));
                }
            }
        }
        if let Some(i) = placed.iter().position(|used| !used) {
            return Err(refused(
                label,
                format!("place from {:?} matched nothing", source.place[i].from),
            ));
        }
        if let Some(i) = excluded.iter().position(|used| !used) {
            return Err(refused(
                label,
                format!("exclude {:?} matched nothing", source.exclude[i].path),
            ));
        }
        Ok(())
    }

    /// Adds a symlink the package's entry declares.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is already taken or below something
    /// that isn't a directory.
    pub fn link(&mut self, link: &Link, label: &str) -> Result<(), Error> {
        self.symlink(&link.path, &link.target, label)
    }

    /// Gives each directory its mode, below ones first, so a directory that
    /// can't be written to is only made so once everything is in it.
    ///
    /// # Errors
    ///
    /// Returns an error if a mode can't be set.
    pub fn finish(&self) -> Result<usize, Error> {
        for (path, node) in self.nodes.iter().rev() {
            if let Node::Dir { mode, .. } = node {
                let at = self.root.join(path);
                fs::set_permissions(&at, Permissions::from_mode(*mode))
                    .map_err(|e| Error::io(&at, &e))?;
            }
        }
        Ok(self.nodes.len())
    }

    /// Makes every directory above `path` that isn't there yet, and refuses
    /// a path below anything else.
    fn parents(&mut self, path: &str, label: &str) -> Result<(), Error> {
        for (i, _) in path.match_indices('/') {
            let above = &path[..i];
            match self.nodes.get(above) {
                Some(Node::Dir { .. }) => {}
                Some(_) => {
                    return Err(refused(
                        label,
                        format!("{path} is below {above}, which isn't a directory"),
                    ));
                }
                None => {
                    let at = self.root.join(above);
                    DirBuilder::new()
                        .mode(0o755)
                        .create(&at)
                        .map_err(|e| Error::io(&at, &e))?;
                    self.nodes.insert(
                        above.to_owned(),
                        Node::Dir {
                            mode: 0o755,
                            explicit: false,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    /// Refuses a path already written.
    fn new_path(&mut self, path: &str, label: &str) -> Result<PathBuf, Error> {
        if path.is_empty() || self.nodes.contains_key(path) {
            return Err(refused(label, format!("{} is laid out twice", shown(path))));
        }
        self.parents(path, label)?;
        Ok(self.root.join(path))
    }

    fn dir(&mut self, path: &str, mode: u32, label: &str) -> Result<(), Error> {
        if path.is_empty() {
            return Ok(());
        }
        match self.nodes.get_mut(path) {
            Some(Node::Dir {
                mode: was,
                explicit,
            }) => {
                if !*explicit {
                    *was = mode;
                    *explicit = true;
                } else if *was != mode {
                    return Err(refused(
                        label,
                        format!("{path} is a directory with mode {was:o} and with {mode:o}"),
                    ));
                }
                Ok(())
            }
            Some(_) => Err(refused(label, format!("{path} is laid out twice"))),
            None => {
                let at = self.new_path(path, label)?;
                DirBuilder::new()
                    .mode(0o755)
                    .create(&at)
                    .map_err(|e| Error::io(&at, &e))?;
                self.nodes.insert(
                    path.to_owned(),
                    Node::Dir {
                        mode,
                        explicit: true,
                    },
                );
                Ok(())
            }
        }
    }

    fn file(
        &mut self,
        path: &str,
        mode: u32,
        content: &mut impl Read,
        label: &str,
    ) -> Result<(), Error> {
        let at = self.new_path(path, label)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&at)
            .map_err(|e| Error::io(&at, &e))?;
        let left = self.limits.bytes - self.bytes;
        let written = io::copy(&mut content.take(left.saturating_add(1)), &mut file)
            .map_err(|e| Error::io(&at, &e))?;
        if written > left {
            return Err(refused(
                label,
                format!("more than {} bytes of files", self.limits.bytes),
            ));
        }
        self.bytes += written;
        file.set_permissions(Permissions::from_mode(mode))
            .map_err(|e| Error::io(&at, &e))?;
        self.nodes.insert(path.to_owned(), Node::File);
        Ok(())
    }

    fn symlink(&mut self, path: &str, target: &str, label: &str) -> Result<(), Error> {
        if target.is_empty() {
            return Err(refused(label, format!("{path} is a symlink to nothing")));
        }
        let at = self.new_path(path, label)?;
        std::os::unix::fs::symlink(target, &at).map_err(|e| Error::io(&at, &e))?;
        self.nodes.insert(path.to_owned(), Node::Symlink);
        Ok(())
    }

    fn hard_link(&mut self, path: &str, original: &str, label: &str) -> Result<(), Error> {
        if !self.is_file(original) {
            return Err(refused(
                label,
                format!("{path} links to {original}, which isn't a file laid out before it"),
            ));
        }
        let at = self.new_path(path, label)?;
        fs::hard_link(self.root.join(original), &at).map_err(|e| Error::io(&at, &e))?;
        self.nodes.insert(path.to_owned(), Node::File);
        Ok(())
    }
}

fn refused(label: &str, message: String) -> Error {
    Error::check(format!("{label}: {message}"))
}

fn shown(path: &str) -> &str {
    if path.is_empty() { "the root" } else { path }
}

/// The names in an archive path. `./` and `.` names are dropped, and a
/// trailing `/` is allowed; an absolute path, `..`, an empty name (an empty
/// path included) or a name that isn't UTF-8 is refused.
fn names(raw: &[u8], label: &str) -> Result<Vec<String>, Error> {
    let shown = String::from_utf8_lossy(raw);
    let text = std::str::from_utf8(raw)
        .map_err(|_| refused(label, format!("{shown} isn't a UTF-8 path")))?;
    if text.starts_with('/') {
        return Err(refused(label, format!("{shown} is an absolute path")));
    }
    let text = text.strip_suffix('/').unwrap_or(text);
    let mut out = Vec::new();
    for name in text.split('/') {
        match name {
            "." => {}
            ".." => return Err(refused(label, format!("{shown} has a .. in it"))),
            "" => return Err(refused(label, format!("{shown} has an empty name in it"))),
            _ if name.chars().any(char::is_control) => {
                return Err(refused(
                    label,
                    format!("{shown:?} has a control character in it"),
                ));
            }
            name => out.push(name.to_owned()),
        }
    }
    Ok(out)
}

/// The path after the first `strip` names, which must be the same for every
/// entry. `None` for an entry at or above them, which must be a directory.
fn strip(
    names: Vec<String>,
    strip: usize,
    prefix: &mut Option<Vec<String>>,
    dir: bool,
    shown: &str,
    label: &str,
) -> Result<Option<String>, Error> {
    let head = &names[..strip.min(names.len())];
    let same = match prefix {
        Some(p) => p.starts_with(head),
        None => true,
    };
    if !same {
        return Err(refused(
            label,
            format!("{shown} isn't below the same {strip} leading names as the others"),
        ));
    }
    if names.len() <= strip {
        if !dir {
            return Err(refused(
                label,
                format!("{shown} is above the {strip} leading names stripped"),
            ));
        }
        return Ok(None);
    }
    if prefix.is_none() {
        *prefix = Some(head.to_vec());
    }
    Ok(Some(names[strip..].join("/")))
}

/// Whether `path` is `dir` or below it; everything is below "".
fn below(path: &str, dir: &str) -> bool {
    dir.is_empty()
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Where `path` goes: excluded, by the most specific place, or nowhere.
fn target(path: &str, source: &Source, placed: &mut [bool], excluded: &mut [bool]) -> Target {
    if let Some(i) = source.exclude.iter().position(|e| below(path, &e.path)) {
        excluded[i] = true;
        return Target::Excluded;
    }
    let best = source
        .place
        .iter()
        .enumerate()
        .filter(|(_, p)| below(path, &p.from))
        .max_by_key(|(_, p)| p.from.len());
    let Some((i, place)) = best else {
        return Target::Unplaced;
    };
    placed[i] = true;
    let rest = path[place.from.len()..].trim_start_matches('/');
    Target::At(match (place.to.is_empty(), rest.is_empty()) {
        (true, _) => rest.to_owned(),
        (false, true) => place.to.clone(),
        (false, false) => format!("{}/{rest}", place.to),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::list::{Exclude, Format, Place};

    /// One tar entry.
    enum E<'a> {
        Dir(&'a str, u32),
        File(&'a str, u32, &'a [u8]),
        Sym(&'a str, &'a str),
        Hard(&'a str, &'a str),
        Fifo(&'a str),
        Global,
    }

    /// A tar file of `entries`. Names are written into the header as they
    /// are, so tests can give names the tar crate's own setters refuse.
    fn tar(entries: &[E<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut b = tar::Builder::new(&mut out);
            for e in entries {
                let mut h = tar::Header::new_ustar();
                let (name, kind, mode, data, link): (&str, EntryType, u32, &[u8], &str) = match e {
                    E::Dir(n, m) => (n, EntryType::Directory, *m, b"", ""),
                    E::File(n, m, d) => (n, EntryType::Regular, *m, d, ""),
                    E::Sym(n, t) => (n, EntryType::Symlink, 0o777, b"", t),
                    E::Hard(n, t) => (n, EntryType::Link, 0o644, b"", t),
                    E::Fifo(n) => (n, EntryType::Fifo, 0o644, b"", ""),
                    E::Global => (
                        "pax_global_header",
                        EntryType::XGlobalHeader,
                        0o644,
                        b"",
                        "",
                    ),
                };
                let raw = h.as_old_mut();
                raw.name[..name.len()].copy_from_slice(name.as_bytes());
                raw.linkname[..link.len()].copy_from_slice(link.as_bytes());
                h.set_entry_type(kind);
                h.set_mode(mode);
                h.set_size(data.len() as u64);
                h.set_cksum();
                b.append(&h, data).unwrap();
            }
            b.finish().unwrap();
        }
        out
    }

    /// A tar file of one entry whose name and target are written as they
    /// are, even when they aren't UTF-8.
    fn raw(name: &[u8], link: &[u8], kind: EntryType) -> Vec<u8> {
        let mut h = tar::Header::new_ustar();
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        h.as_old_mut().linkname[..link.len()].copy_from_slice(link);
        h.set_entry_type(kind);
        h.set_mode(0o644);
        h.set_size(0);
        h.set_cksum();
        let mut out = Vec::new();
        {
            let mut b = tar::Builder::new(&mut out);
            b.append(&h, &b""[..]).unwrap();
            b.finish().unwrap();
        }
        out
    }

    fn source(strip: usize, place: &[(&str, &str)], exclude: &[&str]) -> Source {
        Source {
            url: "https://example.org/a.tar.gz".to_owned(),
            size: 1,
            sha256: String::new(),
            format: Format::TarGz,
            strip,
            place: place
                .iter()
                .map(|(from, to)| Place {
                    from: (*from).to_owned(),
                    to: (*to).to_owned(),
                })
                .collect(),
            exclude: exclude
                .iter()
                .map(|p| Exclude {
                    path: (*p).to_owned(),
                    reason: "test".to_owned(),
                })
                .collect(),
        }
    }

    fn identity() -> Source {
        source(0, &[("", "")], &[])
    }

    fn stage(dir: &tempfile::TempDir) -> Stage {
        Stage::create(&dir.path().join("root"), LIMITS).unwrap()
    }

    fn add(entries: &[E<'_>], source: &Source) -> Result<(tempfile::TempDir, Stage), Error> {
        let dir = tempfile::tempdir().unwrap();
        let mut s = stage(&dir);
        s.add_tar(tar(entries).as_slice(), source, "a")?;
        Ok((dir, s))
    }

    fn refusal(entries: &[E<'_>], source: &Source) -> String {
        add(entries, source).unwrap_err().to_string()
    }

    /// Every path below the root, with what it is and its mode.
    fn listing(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for e in fs::read_dir(&dir).unwrap() {
                let p = e.unwrap().path();
                let meta = fs::symlink_metadata(&p).unwrap();
                let rel = p.strip_prefix(root).unwrap().display().to_string();
                let mode = meta.permissions().mode() & 0o7777;
                if meta.is_dir() {
                    out.push(format!("d {mode:o} {rel}"));
                    stack.push(p);
                } else if meta.file_type().is_symlink() {
                    out.push(format!(
                        "l {rel} -> {}",
                        fs::read_link(&p).unwrap().display()
                    ));
                } else {
                    out.push(format!(
                        "f {mode:o} {rel} {}",
                        fs::read_to_string(&p).unwrap()
                    ));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn entries_are_placed_by_the_most_specific_place() {
        let src = source(
            1,
            &[
                ("rg", "usr/bin/rg"),
                ("doc", "usr/share/doc/rg"),
                ("doc/rg.1", "usr/share/man/man1/rg.1"),
            ],
            &["complete/_rg.ps1"],
        );
        let (_dir, s) = add(
            &[
                E::Global,
                E::Dir("rg-1/", 0o755),
                E::File("rg-1/rg", 0o755, b"elf"),
                E::Dir("rg-1/doc/", 0o750),
                E::File("rg-1/doc/rg.1", 0o644, b"man"),
                E::File("rg-1/doc/FAQ.md", 0o644, b"faq"),
                E::Dir("rg-1/complete/", 0o755),
                E::File("rg-1/complete/_rg.ps1", 0o644, b"ps"),
                E::Sym("rg-1/doc/guide", "FAQ.md"),
                E::Hard("rg-1/doc/faq", "rg-1/doc/FAQ.md"),
            ],
            &src,
        )
        .unwrap();
        assert!(s.is_file("usr/bin/rg") && s.is_file("usr/share/doc/rg/faq"));
        assert!(!s.is_file("usr/share/doc/rg/guide") && !s.is_file("usr/share/doc/rg"));
        assert_eq!(s.finish().unwrap(), 12);
        assert_eq!(
            listing(s.root()),
            [
                "d 750 usr/share/doc/rg",
                "d 755 usr",
                "d 755 usr/bin",
                "d 755 usr/share",
                "d 755 usr/share/doc",
                "d 755 usr/share/man",
                "d 755 usr/share/man/man1",
                "f 644 usr/share/doc/rg/FAQ.md faq",
                "f 644 usr/share/doc/rg/faq faq",
                "f 644 usr/share/man/man1/rg.1 man",
                "f 755 usr/bin/rg elf",
                "l usr/share/doc/rg/guide -> FAQ.md",
            ]
        );
    }

    #[test]
    fn several_archives_share_directories_with_the_same_mode() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = stage(&dir);
        let one = tar(&[
            E::Dir("./", 0o755),
            E::Dir("./usr/", 0o755),
            E::File("./usr/a", 0o644, b"a"),
        ]);
        let two = tar(&[E::Dir("./usr", 0o755), E::File("./usr/b", 0o600, b"b")]);
        s.add_tar(one.as_slice(), &identity(), "one").unwrap();
        s.add_tar(two.as_slice(), &identity(), "two").unwrap();
        // A directory first made for what is below it takes the mode it is
        // given later.
        let three = tar(&[E::File("x/y", 0o644, b"y"), E::Dir("x", 0o700)]);
        s.add_tar(three.as_slice(), &identity(), "three").unwrap();
        s.link(
            &Link {
                path: "usr/c".to_owned(),
                target: "a".to_owned(),
            },
            "links",
        )
        .unwrap();
        s.finish().unwrap();
        assert_eq!(
            listing(s.root()),
            [
                "d 700 x",
                "d 755 usr",
                "f 600 usr/b b",
                "f 644 usr/a a",
                "f 644 x/y y",
                "l usr/c -> a",
            ]
        );
        let four = tar(&[E::Dir("usr", 0o700)]);
        assert_eq!(
            s.add_tar(four.as_slice(), &identity(), "four")
                .unwrap_err()
                .to_string(),
            "four: usr is a directory with mode 755 and with 700"
        );
        let five = tar(&[E::File("usr/a", 0o644, b"again")]);
        assert_eq!(
            s.add_tar(five.as_slice(), &identity(), "five")
                .unwrap_err()
                .to_string(),
            "five: usr/a is laid out twice"
        );
        let six = tar(&[E::Dir("usr/a", 0o755)]);
        assert_eq!(
            s.add_tar(six.as_slice(), &identity(), "six")
                .unwrap_err()
                .to_string(),
            "six: usr/a is laid out twice"
        );
    }

    #[test]
    fn nothing_is_written_through_a_symlink_or_outside_the_root() {
        let id = identity();
        let cases: [(&[E<'_>], &str); 9] = [
            (
                &[E::Sym("usr", "/etc"), E::File("usr/passwd", 0o644, b"x")],
                "a: usr/passwd is below usr, which isn't a directory",
            ),
            (
                &[E::File("usr", 0o644, b""), E::Dir("usr/bin", 0o755)],
                "a: usr/bin is below usr, which isn't a directory",
            ),
            (&[E::File("../x", 0o644, b"")], "a: ../x has a .. in it"),
            (
                &[E::File("a/../../x", 0o644, b"")],
                "a: a/../../x has a .. in it",
            ),
            (
                &[E::File("/etc/x", 0o644, b"")],
                "a: /etc/x is an absolute path",
            ),
            (
                &[E::File("a//x", 0o644, b"")],
                "a: a//x has an empty name in it",
            ),
            (
                &[E::File("a\u{1b}x", 0o644, b"")],
                "a: \"a\\u{1b}x\" has a control character in it",
            ),
            (&[E::Sym("a", "")], "a: a has no target"),
            (
                &[E::File("a", 0o644, b""), E::Sym("a", "b")],
                "a: a is laid out twice",
            ),
        ];
        for (entries, expected) in cases {
            assert_eq!(refusal(entries, &id), expected);
        }
        // A file named by the root is refused too.
        assert_eq!(
            refusal(&[E::File("a", 0o644, b"")], &source(0, &[("a", "")], &[])),
            "a: the root is laid out twice"
        );
        let dir = tempfile::tempdir().unwrap();
        let mut s = stage(&dir);
        let not_utf8 = raw(&[0xff, b'a'], b"", EntryType::Regular);
        assert_eq!(
            s.add_tar(not_utf8.as_slice(), &id, "b")
                .unwrap_err()
                .to_string(),
            "b: \u{fffd}a isn't a UTF-8 path"
        );
        let empty = raw(b"", b"", EntryType::Directory);
        assert_eq!(
            s.add_tar(empty.as_slice(), &id, "e")
                .unwrap_err()
                .to_string(),
            "e:  has an empty name in it"
        );
        let target = raw(b"s", &[0xff], EntryType::Symlink);
        assert_eq!(
            s.add_tar(target.as_slice(), &id, "c")
                .unwrap_err()
                .to_string(),
            "c: s's target isn't UTF-8"
        );
        // Nothing was written.
        assert!(fs::read_dir(s.root()).unwrap().next().is_none());
    }

    #[test]
    fn only_plain_files_directories_and_links_are_taken() {
        let id = identity();
        assert_eq!(
            refusal(&[E::Fifo("a")], &id),
            "a: a is a Fifo, which isn't a file, directory or link"
        );
        for mode in [0o4755, 0o2755, 0o1777] {
            assert_eq!(
                refusal(&[E::File("a", mode, b"")], &id),
                format!("a: a is setuid, setgid or sticky ({mode:o})")
            );
        }
        assert_eq!(
            refusal(&[E::Hard("b", "a")], &id),
            "a: b links to a, which isn't a file laid out before it"
        );
        assert_eq!(
            refusal(&[E::Dir("a", 0o755), E::Hard("b", "a")], &id),
            "a: b links to a, which isn't a file laid out before it"
        );
        let src = source(0, &[("", "")], &["y"]);
        assert_eq!(
            refusal(
                &[
                    E::File("y", 0o644, b""),
                    E::File("x", 0o644, b""),
                    E::Hard("x2", "y")
                ],
                &src
            ),
            "a: x2 links to a file that isn't laid out"
        );
        assert_eq!(
            refusal(
                &[
                    E::File("x", 0o644, b""),
                    E::File("y", 0o644, b""),
                    E::Hard("b", "../z")
                ],
                &src
            ),
            "a: ../z has a .. in it"
        );
        let dir = tempfile::tempdir().unwrap();
        let mut s = stage(&dir);
        let nameless = raw(b"s", b"", EntryType::Symlink);
        assert_eq!(
            s.add_tar(nameless.as_slice(), &id, "a")
                .unwrap_err()
                .to_string(),
            "a: s has no target"
        );
        let hard = raw(b"h", b"", EntryType::Link);
        assert_eq!(
            s.add_tar(hard.as_slice(), &id, "a")
                .unwrap_err()
                .to_string(),
            "a: h has no target"
        );
    }

    #[test]
    fn every_entry_and_every_rule_must_be_used() {
        let src = source(1, &[("a", "usr/a")], &["b"]);
        assert_eq!(
            refusal(
                &[E::File("p/a", 0o644, b""), E::File("p/c", 0o644, b"")],
                &src
            ),
            "a: p/c is neither placed nor excluded"
        );
        assert_eq!(
            refusal(&[E::File("p/a", 0o644, b"")], &src),
            "a: exclude \"b\" matched nothing"
        );
        assert_eq!(
            refusal(&[E::File("p/b", 0o644, b"")], &src),
            "a: place from \"a\" matched nothing"
        );
        // An unplaced directory is skipped; one excluded takes what is below.
        let (_dir, s) = add(
            &[
                E::Dir("p/d", 0o755),
                E::Dir("p/b", 0o755),
                E::File("p/b/x", 0o644, b""),
                E::File("p/a", 0o644, b""),
            ],
            &src,
        )
        .unwrap();
        assert_eq!(listing(s.root()), ["d 755 usr", "f 644 usr/a "]);
    }

    #[test]
    fn stripped_names_must_be_shared() {
        let src = source(2, &[("", "")], &[]);
        assert_eq!(
            refusal(
                &[
                    E::Dir("a/b", 0o755),
                    E::File("a/b/x", 0o644, b""),
                    E::File("a/c/y", 0o644, b"")
                ],
                &src
            ),
            "a: a/c/y isn't below the same 2 leading names as the others"
        );
        assert_eq!(
            refusal(&[E::File("a/b/x", 0o644, b""), E::Dir("z", 0o755)], &src),
            "a: z isn't below the same 2 leading names as the others"
        );
        assert_eq!(
            refusal(&[E::File("a", 0o644, b"")], &src),
            "a: a is above the 2 leading names stripped"
        );
        let (_dir, s) = add(
            &[
                E::Dir("a", 0o755),
                E::Dir("a/b", 0o755),
                E::File("a/b/x", 0o644, b"x"),
                E::Dir("a", 0o755),
            ],
            &src,
        )
        .unwrap();
        assert_eq!(listing(s.root()), ["f 644 x x"]);
    }

    #[test]
    fn limits_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let small = Limits {
            entries: 2,
            bytes: 4,
        };
        let mut s = Stage::create(&dir.path().join("r"), small).unwrap();
        let three = tar(&[E::Dir("a", 0o755), E::Dir("b", 0o755), E::Dir("c", 0o755)]);
        assert_eq!(
            s.add_tar(three.as_slice(), &identity(), "x")
                .unwrap_err()
                .to_string(),
            "x: more than 2 entries"
        );
        let mut s = Stage::create(&dir.path().join("s"), small).unwrap();
        let fits = tar(&[E::File("a", 0o644, b"abcd")]);
        s.add_tar(fits.as_slice(), &identity(), "x").unwrap();
        let over = tar(&[E::File("b", 0o644, b"e")]);
        assert_eq!(
            s.add_tar(over.as_slice(), &identity(), "x")
                .unwrap_err()
                .to_string(),
            "x: more than 4 bytes of files"
        );
        assert_eq!(
            Stage::create(&dir.path().join("s"), small)
                .unwrap_err()
                .to_string(),
            format!(
                "{}: File exists (os error 17)",
                dir.path().join("s").display()
            )
        );
        let mut s = Stage::create(&dir.path().join("t"), LIMITS).unwrap();
        assert!(
            s.add_tar(
                &b"not a tar file, but long enough to be read as a header"[..],
                &identity(),
                "y"
            )
            .is_err()
        );
        // An empty archive places nothing.
        assert_eq!(
            s.add_tar([0u8; 1024].as_slice(), &identity(), "y")
                .unwrap_err()
                .to_string(),
            "y: place from \"\" matched nothing"
        );
    }

    #[test]
    fn a_directory_placed_at_the_root_is_the_root() {
        let (_dir, s) = add(
            &[E::Dir("top", 0o700), E::File("top/a", 0o644, b"a")],
            &source(0, &[("top", "")], &[]),
        )
        .unwrap();
        s.finish().unwrap();
        assert_eq!(listing(s.root()), ["f 644 a a"]);
        let mode = fs::metadata(s.root()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        let dir = tempfile::tempdir().unwrap();
        let mut s = stage(&dir);
        let nothing = Link {
            path: "a".to_owned(),
            target: String::new(),
        };
        assert_eq!(
            s.link(&nothing, "p").unwrap_err().to_string(),
            "p: a is a symlink to nothing"
        );
    }

    #[test]
    fn paths_are_below_their_directories() {
        assert!(below("a", ""));
        assert!(below("a/b", "a"));
        assert!(below("a", "a"));
        assert!(!below("ab", "a"));
        assert!(!below("a", "a/b"));
        assert_eq!(shown(""), "the root");
        assert_eq!(shown("a"), "a");
    }
}
