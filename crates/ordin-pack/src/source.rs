// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading the files of a walked install root again, to write them into
//! a package.
//!
//! The root may have changed since the walk, so nothing is trusted:
//! - Every path is opened one name at a time below the root, never
//!   following a symlink.
//! - Only regular files on the root's own mount are read, so a FIFO can't
//!   hang the read.
//! - The writer then checks every file's size and digests against its
//!   tree.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use ordin_tree::{File, TreePath};
use rustix::fs::{self as sys, AtFlags, FileType, OFlags, StatxFlags};

/// How the root directory is opened. It may be reached through symlinks,
/// because the caller named it.
const OPEN_ROOT: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::DIRECTORY);

/// How anything below the root is opened.
const OPEN_BELOW: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW);

const DETAILS: StatxFlags = StatxFlags::TYPE.union(StatxFlags::MNT_ID);

/// The type and mount of what is open.
fn details(fd: &OwnedFd) -> io::Result<(FileType, u64)> {
    let stat = sys::statx(fd, c"", AtFlags::EMPTY_PATH, DETAILS)?;
    Ok((
        FileType::from_raw_mode(u32::from(stat.stx_mode)),
        stat.stx_mnt_id,
    ))
}

/// Refuses anything but `expected` on the root's mount.
fn check(found: (FileType, u64), expected: FileType, mount: u64) -> io::Result<()> {
    let (kind, at) = found;
    if kind != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "it is a {} now, not a {}",
                type_name(kind),
                type_name(expected)
            ),
        ));
    }
    if at != mount {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "it is on another mount now",
        ));
    }
    Ok(())
}

fn type_name(kind: FileType) -> &'static str {
    match kind {
        FileType::RegularFile => "regular file",
        FileType::Directory => "directory",
        FileType::Symlink => "symlink",
        FileType::Fifo => "FIFO",
        FileType::Socket => "socket",
        FileType::CharacterDevice | FileType::BlockDevice => "device",
        FileType::Unknown => "file of unknown type",
    }
}

fn name(part: &str) -> io::Result<CString> {
    CString::new(part).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL in a name"))
}

/// The files of an install root, by their paths in the normalized tree.
#[derive(Debug)]
pub struct RootSource {
    root: OwnedFd,
    mount: u64,
    origins: BTreeMap<TreePath, TreePath>,
}

impl RootSource {
    /// Opens `root`. `origins` gives where each path of the normalized
    /// tree was in the root; a path it doesn't list is read where it is.
    ///
    /// # Errors
    ///
    /// The root can't be opened, or isn't a directory.
    pub fn new(root: &Path, origins: BTreeMap<TreePath, TreePath>) -> io::Result<Self> {
        let fd = sys::open(root, OPEN_ROOT, sys::Mode::empty())?;
        let (_, mount) = details(&fd)?;
        Ok(Self {
            root: fd,
            mount,
            origins,
        })
    }
}

impl ordin_archive::Source for RootSource {
    type Reader = std::fs::File;

    fn open(&mut self, path: &TreePath, _: &File) -> io::Result<Self::Reader> {
        let origin = self.origins.get(path).unwrap_or(path);
        let mut names = origin.as_str().split('/').filter(|n| !n.is_empty());
        let last = names.next_back().unwrap_or_default();
        let mut dir: Option<OwnedFd> = None;
        for part in names {
            let at = dir.as_ref().unwrap_or(&self.root);
            let fd = sys::openat(
                at,
                name(part)?.as_c_str(),
                OPEN_BELOW.union(OFlags::DIRECTORY),
                sys::Mode::empty(),
            )?;
            check(details(&fd)?, FileType::Directory, self.mount)?;
            dir = Some(fd);
        }
        let at = dir.as_ref().unwrap_or(&self.root);
        let fd = sys::openat(at, name(last)?.as_c_str(), OPEN_BELOW, sys::Mode::empty())?;
        check(details(&fd)?, FileType::RegularFile, self.mount)?;
        Ok(std::fs::File::from(fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_expected_type_on_the_roots_mount_is_read() {
        assert!(check((FileType::RegularFile, 7), FileType::RegularFile, 7).is_ok());
        let e = check((FileType::Fifo, 7), FileType::RegularFile, 7).unwrap_err();
        assert_eq!(e.to_string(), "it is a FIFO now, not a regular file");
        let e = check((FileType::RegularFile, 8), FileType::RegularFile, 7).unwrap_err();
        assert_eq!(e.to_string(), "it is on another mount now");
        let names: Vec<&str> = [
            FileType::RegularFile,
            FileType::Directory,
            FileType::Symlink,
            FileType::Fifo,
            FileType::Socket,
            FileType::CharacterDevice,
            FileType::BlockDevice,
            FileType::Unknown,
        ]
        .into_iter()
        .map(type_name)
        .collect();
        assert_eq!(
            names,
            [
                "regular file",
                "directory",
                "symlink",
                "FIFO",
                "socket",
                "device",
                "device",
                "file of unknown type"
            ]
        );
    }

    #[test]
    fn names_with_a_nul_are_refused() {
        assert_eq!(
            name("a\0b").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
