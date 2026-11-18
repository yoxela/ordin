// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The entries of a tree.

use ordin_core::{Account, Digest, Mode};

use crate::caps::Capabilities;
use crate::path::{SymlinkTarget, TreePath};
use crate::xattr::Xattrs;

/// A file's mode when none is written.
pub const FILE_MODE: Mode = Mode::FILE;

/// A directory's mode when none is written.
pub const DIR_MODE: Mode = Mode::DIR;

/// One path in a tree and what is there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Where it is.
    pub path: TreePath,
    /// What it is.
    pub kind: Kind,
}

/// What an entry is. Device nodes, sockets and FIFOs can't be packaged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A regular file.
    File(File),
    /// A directory.
    Dir(Dir),
    /// A symbolic link.
    Symlink(Symlink),
    /// Another name for a regular file in the same tree, sharing its
    /// content and metadata.
    HardLink(TreePath),
}

impl Kind {
    /// The name of the entry type, as a tree writes it.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Dir(_) => "dir",
            Self::Symlink(_) => "symlink",
            Self::HardLink(_) => "hardlink",
        }
    }
}

/// A regular file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    /// Permission bits, setuid, setgid and sticky.
    pub mode: Mode,
    /// The owning user, by name.
    pub owner: Account,
    /// The owning group, by name.
    pub group: Account,
    /// The size in bytes, at most 2⁵³−1.
    pub size: u64,
    /// The BLAKE3 digest of the content: the file object's identity.
    pub content: Digest,
    /// The fs-verity digest of the content: SHA-256, 4 KiB blocks, no
    /// salt. On a host, the file object is stored under it.
    pub fsverity: Digest,
    /// `user.*` extended attributes.
    pub xattrs: Xattrs,
    /// File capabilities, if any.
    pub capabilities: Option<Capabilities>,
}

/// A directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dir {
    /// Permission bits, setuid, setgid and sticky.
    pub mode: Mode,
    /// The owning user, by name.
    pub owner: Account,
    /// The owning group, by name.
    pub group: Account,
    /// `user.*` extended attributes.
    pub xattrs: Xattrs,
}

/// A symbolic link. Linux gives a symlink no mode of its own and no
/// `user.*` attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symlink {
    /// What it points at, exactly as written.
    pub target: SymlinkTarget,
    /// The owning user, by name.
    pub owner: Account,
    /// The owning group, by name.
    pub group: Account,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names_are_the_written_ones() {
        let root = Account::root;
        let p: TreePath = "/usr/a".parse().unwrap();
        let file = Kind::File(File {
            mode: FILE_MODE,
            owner: root(),
            group: root(),
            size: 0,
            content: Digest::blake3(b""),
            fsverity: Digest::new(ordin_core::Algorithm::Sha256, [0; 32]),
            xattrs: Xattrs::new(),
            capabilities: None,
        });
        let dir = Kind::Dir(Dir {
            mode: DIR_MODE,
            owner: root(),
            group: root(),
            xattrs: Xattrs::new(),
        });
        let link = Kind::Symlink(Symlink {
            target: "a".parse().unwrap(),
            owner: root(),
            group: root(),
        });
        let names: Vec<_> = [file, dir, link, Kind::HardLink(p)]
            .iter()
            .map(Kind::type_name)
            .collect();
        assert_eq!(names, ["file", "dir", "symlink", "hardlink"]);
    }
}
