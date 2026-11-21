// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Requirements, provides and the architecture, inferred from a package's
//! files: shared libraries from ELF files (ORD-112) and interpreters from
//! `#!` lines (ORD-113).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

use object::read::ReadCache;
use ordin_archive::Source;
use ordin_core::{Arch, Atom};
use ordin_tree::{Kind, Tree, TreePath};

use crate::elf::{self, Info, MAGIC, Machine};
use crate::shebang::{self, HEAD, Shebang};

/// Where the dynamic loader looks by default. Only a library directly in
/// one of these provides its soname; one elsewhere still meets the
/// package's own needs.
pub const LIBRARY_DIRS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/usr/lib/x86_64-linux-musl",
    "/usr/lib/aarch64-linux-musl",
];

/// Subtrees whose files aren't looked at: split debug information, and
/// documentation, whose examples nobody runs from there.
pub const SKIPPED: &[&str] = &["/usr/lib/debug/", "/usr/share/doc/"];

/// Something about the inference a packager should know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InferNote {
    /// A file with the ELF magic that couldn't be read, so it adds
    /// nothing.
    UnreadableElf {
        /// The file.
        path: TreePath,
        /// Why.
        why: String,
    },
    /// A private symbol version, which proves nothing about the library,
    /// left out.
    PrivateVersion {
        /// The file that needs it.
        path: TreePath,
        /// The library.
        library: String,
        /// The version node.
        node: String,
    },
    /// A version node an `so:` atom can't hold, so the library is needed
    /// without it.
    BadVersion {
        /// The file.
        path: TreePath,
        /// The library.
        library: String,
        /// The version node.
        node: String,
    },
    /// A library name an `so:` atom can't hold, left out.
    BadSoname {
        /// The file.
        path: TreePath,
        /// The name, with bytes that aren't UTF-8 replaced.
        name: String,
    },
    /// A `#!` line Ordin won't guess about.
    Shebang {
        /// The script.
        path: TreePath,
        /// Why.
        why: String,
    },
}

impl fmt::Display for InferNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreadableElf { path, why } => {
                write!(
                    f,
                    "{path}: not read as ELF, so it adds no requirements: {why}"
                )
            }
            Self::PrivateVersion {
                path,
                library,
                node,
            } => write!(
                f,
                "{path}: needs the private version {node} of {library}, which only an exact \
                 version of the package providing it can promise; declare that by hand"
            ),
            Self::BadVersion {
                path,
                library,
                node,
            } => write!(
                f,
                "{path}: the version {node:?} of {library} can't be an so: atom, so it needs \
                 {library} without a version"
            ),
            Self::BadSoname { path, name } => write!(
                f,
                "{path}: the library name {name:?} can't be an so: atom, so it isn't recorded"
            ),
            Self::Shebang { path, why } => {
                write!(f, "{path}: its interpreter isn't recorded: {why}")
            }
        }
    }
}

/// Why requirements couldn't be inferred.
#[derive(Debug, thiserror::Error)]
pub enum InferError {
    /// Two files are built for different architectures.
    #[error("{path} is built for {arch}, but {first} is built for {first_arch}; a package has one")]
    Mixed {
        /// The first file found.
        first: TreePath,
        /// Its architecture.
        first_arch: Arch,
        /// The file that differs.
        path: TreePath,
        /// Its architecture.
        arch: Arch,
    },
    /// A program or library built for a machine Ordin doesn't package for.
    #[error("{path} is {what}, and Ordin packages only 64-bit x86_64 and aarch64")]
    Foreign {
        /// The file.
        path: TreePath,
        /// What it is built for.
        what: String,
    },
    /// A file couldn't be read.
    #[error("{path}: {source}")]
    Read {
        /// The file.
        path: TreePath,
        /// What went wrong.
        source: io::Error,
    },
}

/// What a package's files say about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inferred {
    /// The architecture of its programs and libraries, and the first file
    /// that showed it; `None` if it has none.
    pub arch: Option<(Arch, TreePath)>,
    /// What it needs, sorted.
    pub requires: Vec<Atom>,
    /// What it provides, sorted.
    pub provides: Vec<Atom>,
    /// Notes, in path order.
    pub notes: Vec<InferNote>,
}

/// Reads until `buf` is full or the reader ends.
fn read_head(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while let Some(space) = buf.get_mut(filled..).filter(|s| !s.is_empty()) {
        match reader.read(space) {
            Ok(0) => break,
            Ok(n) => filled += n.min(space.len()),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn describe(machine: Machine) -> String {
    match machine {
        Machine::X86_64 => "x86_64".to_owned(),
        Machine::Aarch64 => "aarch64".to_owned(),
        Machine::Other {
            class64,
            little,
            machine,
        } => format!(
            "a {}-bit {}-endian ELF file for machine {machine}",
            if class64 { 64 } else { 32 },
            if little { "little" } else { "big" }
        ),
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Sorted atoms, from their text.
#[derive(Default)]
struct Atoms(BTreeMap<String, Atom>);

impl Atoms {
    /// Adds `text` if it is an atom, and says whether it is.
    fn add(&mut self, text: String) -> bool {
        match text.parse::<Atom>() {
            Ok(atom) => {
                self.0.insert(text, atom);
                true
            }
            Err(_) => false,
        }
    }

    fn into_vec(self) -> Vec<Atom> {
        self.0.into_values().collect()
    }
}

fn skipped(path: &str) -> bool {
    SKIPPED.iter().any(|dir| path.starts_with(dir))
}

/// Infers what the files of `tree` need and provide, reading each through
/// `source`.
///
/// # Errors
///
/// A file that can't be read, programs or libraries for two
/// architectures, or one for a machine Ordin doesn't package for.
pub fn infer<S>(tree: &Tree, source: &mut S) -> Result<Inferred, InferError>
where
    S: Source,
    S::Reader: Read + Seek,
{
    let mut notes = Vec::new();
    let mut elfs: Vec<(TreePath, Info)> = Vec::new();
    let mut scripts = Vec::new();
    for entry in tree.entries() {
        let Kind::File(file) = &entry.kind else {
            continue;
        };
        if skipped(entry.path.as_str()) {
            continue;
        }
        let read_error = |source| InferError::Read {
            path: entry.path.clone(),
            source,
        };
        let mut reader = source.open(&entry.path, file).map_err(read_error)?;
        let mut head = [0; HEAD];
        let filled = read_head(&mut reader, &mut head).map_err(read_error)?;
        let head = head.get(..filled).unwrap_or_default();
        if head.starts_with(MAGIC) {
            reader.seek(SeekFrom::Start(0)).map_err(read_error)?;
            let cache = ReadCache::new(reader);
            match elf::inspect(&cache) {
                Ok(Some(info)) => elfs.push((entry.path.clone(), info)),
                Ok(None) => {}
                Err(e) => notes.push(InferNote::UnreadableElf {
                    path: entry.path.clone(),
                    why: e.0,
                }),
            }
        } else if file.mode.value() & 0o111 != 0 {
            match shebang::parse(head) {
                Some(Shebang::Interpreter(interpreter)) => {
                    scripts.push((entry.path.clone(), interpreter));
                }
                Some(Shebang::Unusual(why)) => notes.push(InferNote::Shebang {
                    path: entry.path.clone(),
                    why,
                }),
                None => {}
            }
        }
    }
    elfs.retain(|(_, info)| info.kind != elf::Kind::Other);

    let mut arch: Option<(Arch, TreePath)> = None;
    for (path, info) in &elfs {
        let found = match info.machine {
            Machine::X86_64 => Arch::X86_64,
            Machine::Aarch64 => Arch::Aarch64,
            other @ Machine::Other { .. } => {
                return Err(InferError::Foreign {
                    path: path.clone(),
                    what: describe(other),
                });
            }
        };
        match &arch {
            None => arch = Some((found, path.clone())),
            Some((first_arch, first)) if *first_arch != found => {
                return Err(InferError::Mixed {
                    first: first.clone(),
                    first_arch: *first_arch,
                    path: path.clone(),
                    arch: found,
                });
            }
            Some(_) => {}
        }
    }

    let shipped: BTreeSet<&[u8]> = elfs
        .iter()
        .filter_map(|(_, info)| info.soname.as_deref())
        .collect();

    let mut provides = Atoms::default();
    for (path, info) in &elfs {
        let Some(soname) = info.soname.as_deref() else {
            continue;
        };
        if !LIBRARY_DIRS.contains(&path.parent()) {
            continue;
        }
        let library = text(soname);
        if !provides.add(format!("so:{library}")) {
            notes.push(InferNote::BadSoname {
                path: path.clone(),
                name: library,
            });
            continue;
        }
        for node in &info.defines {
            let node = text(node);
            if !provides.add(format!("so:{library}@{node}")) {
                notes.push(InferNote::BadVersion {
                    path: path.clone(),
                    library: library.clone(),
                    node,
                });
            }
        }
    }

    let mut requires = Atoms::default();
    for (path, info) in &elfs {
        for needed in &info.needed {
            if shipped.contains(needed.as_slice()) {
                continue;
            }
            let library = text(needed);
            if format!("so:{library}").parse::<Atom>().is_err() {
                notes.push(InferNote::BadSoname {
                    path: path.clone(),
                    name: library,
                });
                continue;
            }
            let mut versioned = false;
            let mut bare = false;
            for need in info
                .needs
                .iter()
                .filter(|n| n.library == *needed && !n.weak)
            {
                let node = text(&need.node);
                if node.contains("PRIVATE") {
                    notes.push(InferNote::PrivateVersion {
                        path: path.clone(),
                        library: library.clone(),
                        node,
                    });
                } else if requires.add(format!("so:{library}@{node}")) {
                    versioned = true;
                } else {
                    notes.push(InferNote::BadVersion {
                        path: path.clone(),
                        library: library.clone(),
                        node,
                    });
                    bare = true;
                }
            }
            if bare || !versioned {
                requires.add(format!("so:{library}"));
            }
        }
    }
    for (_, interpreter) in scripts {
        if tree.get(interpreter.as_str()).is_none() {
            requires.add(format!("file:{interpreter}"));
        }
    }
    notes.sort_by(|a, b| note_path(a).cmp(note_path(b)));
    Ok(Inferred {
        arch,
        requires: requires.into_vec(),
        provides: provides.into_vec(),
        notes,
    })
}

fn note_path(note: &InferNote) -> &TreePath {
    match note {
        InferNote::UnreadableElf { path, .. }
        | InferNote::PrivateVersion { path, .. }
        | InferNote::BadVersion { path, .. }
        | InferNote::BadSoname { path, .. }
        | InferNote::Shebang { path, .. } => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Chunks<'a>(Vec<&'a [u8]>);

    impl Read for Chunks<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.first_mut() {
                None => Ok(0),
                Some(&mut []) => {
                    self.0.remove(0);
                    Err(io::Error::from(ErrorKind::Interrupted))
                }
                Some(chunk) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    *chunk = &chunk[n..];
                    if chunk.is_empty() {
                        self.0.remove(0);
                    }
                    Ok(n)
                }
            }
        }
    }

    #[test]
    fn the_head_is_read_across_short_reads() {
        let mut buf = [0; 6];
        let mut r = Chunks(vec![b"ab", b"", b"cdefgh"]);
        assert_eq!(read_head(&mut r, &mut buf).unwrap(), 6);
        assert_eq!(&buf, b"abcdef");
        let mut r = Chunks(vec![b"xyz"]);
        assert_eq!(read_head(&mut r, &mut buf).unwrap(), 3);
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("broken"))
            }
        }
        assert!(read_head(&mut Failing, &mut buf).is_err());
    }

    #[test]
    fn machines_are_described() {
        assert_eq!(describe(Machine::X86_64), "x86_64");
        assert_eq!(describe(Machine::Aarch64), "aarch64");
        assert_eq!(
            describe(Machine::Other {
                class64: false,
                little: true,
                machine: 3
            }),
            "a 32-bit little-endian ELF file for machine 3"
        );
        assert_eq!(
            describe(Machine::Other {
                class64: true,
                little: false,
                machine: 21
            }),
            "a 64-bit big-endian ELF file for machine 21"
        );
    }

    #[test]
    fn notes_say_what_happened() {
        let p: TreePath = "/usr/bin/x".parse().unwrap();
        let shown = [
            InferNote::UnreadableElf {
                path: p.clone(),
                why: "bad".into(),
            },
            InferNote::PrivateVersion {
                path: p.clone(),
                library: "libc.so.6".into(),
                node: "GLIBC_PRIVATE".into(),
            },
            InferNote::BadVersion {
                path: p.clone(),
                library: "libx.so.1".into(),
                node: "V-1".into(),
            },
            InferNote::BadSoname {
                path: p.clone(),
                name: "lib x".into(),
            },
            InferNote::Shebang {
                path: p,
                why: "env is given options".into(),
            },
        ]
        .map(|n| n.to_string());
        assert_eq!(
            shown,
            [
                "/usr/bin/x: not read as ELF, so it adds no requirements: bad",
                "/usr/bin/x: needs the private version GLIBC_PRIVATE of libc.so.6, which only an \
                 exact version of the package providing it can promise; declare that by hand",
                "/usr/bin/x: the version \"V-1\" of libx.so.1 can't be an so: atom, so it needs \
                 libx.so.1 without a version",
                "/usr/bin/x: the library name \"lib x\" can't be an so: atom, so it isn't recorded",
                "/usr/bin/x: its interpreter isn't recorded: env is given options",
            ]
        );
    }
}
