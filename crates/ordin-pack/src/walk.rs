// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Recording a directory as a tree.
//!
//! The directory may not be trustworthy, and it may change while it is
//! read, so:
//!
//! - Every step opens the next name relative to the directory already
//!   open, without following symlinks. Only the root path itself may
//!   lead through one.
//! - Files are opened without blocking, so a FIFO swapped in can't hang
//!   the walk, and what was opened must be what was listed.
//! - A file or directory that changes during the walk is an error.
//! - A walk stays on one mount.
//! - The number of entries is limited as they are found.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File as OpenFile;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::vec;

use ordin_core::{Account, Blake3Hasher, Digest, Mode};
use ordin_tree::{
    Capabilities, Dir, Entry, File, Kind, MAX_ENTRIES, Symlink, SymlinkTarget, Tree, TreePath,
    Xattrs, file_digests,
};
use rustix::fs::{self as sys, AtFlags, FileType, OFlags, Statx, StatxFlags, StatxTimestamp};
use rustix::io::Errno;

use crate::attrs::{Attributes, Disposition, disposition};
use crate::error::{WalkError, WalkErrorKind};
use crate::owners::{OwnerOverride, Owners};

/// How the root directory is opened. It may be reached through symlinks,
/// because the caller named it.
const OPEN_ROOT: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::DIRECTORY);

/// How a regular file below the root is opened.
const OPEN_FILE: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW);

/// How a directory below the root is opened.
const OPEN_DIR: OFlags = OPEN_FILE.union(OFlags::DIRECTORY);

/// What a walk needs to know about each path.
const DETAILS: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::MODE)
    .union(StatxFlags::NLINK)
    .union(StatxFlags::INO)
    .union(StatxFlags::SIZE)
    .union(StatxFlags::MTIME)
    .union(StatxFlags::CTIME)
    .union(StatxFlags::MNT_ID);

/// Linux's limit on an attribute value and on a file's list of attribute
/// names (`XATTR_SIZE_MAX` and `XATTR_LIST_MAX`), so one read always fits.
const ATTRIBUTE_BUFFER: usize = 65_536;

/// The setuid bit of a mode.
const SETUID: u16 = 0o4000;

/// The setgid bit of a mode.
const SETGID: u16 = 0o2000;

/// What a walk is told besides the directory.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Owners other than the default `root:root`.
    pub owners: Vec<OwnerOverride>,
    /// Files that are setuid or setgid on purpose, as the manifest's
    /// `setuid` field declares them.
    pub setuid: BTreeSet<TreePath>,
}

/// The result of a walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Walk {
    /// The directory's contents. The directory itself isn't an entry.
    pub tree: Tree,
    /// What a packager should look at, sorted by path.
    pub warnings: Vec<Warning>,
}

/// A setuid or setgid file nobody declared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// The file.
    pub path: TreePath,
    /// The user it runs as, if it is setuid.
    pub setuid: Option<Account>,
    /// The group it runs with, if it is setgid.
    pub setgid: Option<Account>,
    /// Whether the account is the default rather than one asked for. A
    /// setuid file owned by the packager on disk becomes setuid root.
    pub default_owner: bool,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let default = if self.default_owner {
            ", the default (--owner sets another)"
        } else {
            ""
        };
        let mut parts = Vec::new();
        if let Some(owner) = &self.setuid {
            parts.push(format!("setuid, so it runs as {owner}{default}"));
        }
        if let Some(group) = &self.setgid {
            parts.push(format!("setgid, so it runs with group {group}{default}"));
        }
        write!(f, "{}: not declared: {}", self.path, parts.join("; "))
    }
}

/// What can be compared about a path: everything that changes when it
/// does, and nothing that merely reading it changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    mode: u16,
    links: u32,
    inode: Inode,
    mount: u64,
    size: u64,
    modified: (i64, u32),
    changed: (i64, u32),
}

/// What identifies a file on the system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Inode {
    device: (u32, u32),
    number: u64,
}

fn time(t: StatxTimestamp) -> (i64, u32) {
    (t.tv_sec, t.tv_nsec)
}

/// Refuses an answer from the kernel that lacks part of [`DETAILS`].
fn require_details(mask: u32) -> Result<(), WalkErrorKind> {
    if StatxFlags::from_bits_retain(mask).contains(DETAILS) {
        Ok(())
    } else {
        Err(WalkErrorKind::MissingDetails)
    }
}

fn io(action: &'static str) -> impl FnOnce(Errno) -> WalkErrorKind {
    move |errno| WalkErrorKind::Io {
        action,
        source: errno.into(),
    }
}

impl Snapshot {
    fn new(stat: &Statx) -> Result<Self, WalkErrorKind> {
        require_details(stat.stx_mask)?;
        Ok(Self {
            mode: stat.stx_mode,
            links: stat.stx_nlink,
            inode: Inode {
                device: (stat.stx_dev_major, stat.stx_dev_minor),
                number: stat.stx_ino,
            },
            mount: stat.stx_mnt_id,
            size: stat.stx_size,
            modified: time(stat.stx_mtime),
            changed: time(stat.stx_ctime),
        })
    }

    /// The name's details, not following a symlink.
    fn of_name(dir: &OwnedFd, name: &CStr) -> Result<Self, WalkErrorKind> {
        let flags = AtFlags::SYMLINK_NOFOLLOW.union(AtFlags::NO_AUTOMOUNT);
        let stat = sys::statx(dir, name, flags, DETAILS).map_err(io("read its details"))?;
        Self::new(&stat)
    }

    /// The details of what is open.
    fn of_open(fd: impl AsFd) -> Result<Self, WalkErrorKind> {
        let stat =
            sys::statx(fd, c"", AtFlags::EMPTY_PATH, DETAILS).map_err(io("read its details"))?;
        Self::new(&stat)
    }

    fn file_type(self) -> FileType {
        FileType::from_raw_mode(self.mode.into())
    }

    /// The permission, setuid, setgid and sticky bits.
    fn permissions(self) -> Result<Mode, WalkErrorKind> {
        Mode::new(self.mode % 0o10000).ok_or(WalkErrorKind::Changed)
    }

    /// Refuses a difference from `earlier`.
    fn expect(self, earlier: Self) -> Result<(), WalkErrorKind> {
        if self == earlier {
            Ok(())
        } else {
            Err(WalkErrorKind::Changed)
        }
    }
}

/// How many bytes of attribute names there are. A filesystem without
/// extended attributes has none.
fn listed(result: rustix::io::Result<usize>) -> Result<usize, WalkErrorKind> {
    match result {
        Err(Errno::OPNOTSUPP) => Ok(0),
        other => other.map_err(io("list its extended attributes")),
    }
}

/// How long an attribute's value is. An attribute that was listed and is
/// now gone means the file changed.
fn value_length(result: rustix::io::Result<usize>) -> Result<usize, WalkErrorKind> {
    match result {
        Err(Errno::NODATA) => Err(WalkErrorKind::Changed),
        other => other.map_err(io("read an extended attribute")),
    }
}

/// Why reading a file failed.
fn read_failed(source: std::io::Error) -> WalkErrorKind {
    WalkErrorKind::Io {
        action: "read the file",
        source,
    }
}

/// Refuses a file that gave a different number of bytes than its size.
fn expect_size(read: u64, listed: u64) -> Result<(), WalkErrorKind> {
    if read == listed {
        Ok(())
    } else {
        Err(WalkErrorKind::Changed)
    }
}

/// What to call a kind of file that can't be packaged.
fn unsupported(file_type: FileType) -> &'static str {
    match file_type {
        FileType::Fifo => "a FIFO",
        FileType::Socket => "a socket",
        FileType::CharacterDevice => "a character device",
        FileType::BlockDevice => "a block device",
        _ => "a file of an unknown type",
    }
}

/// Bytes from the directory, made safe to print.
fn shown(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).escape_debug().to_string()
}

/// A regular file, under every name it has in the tree.
#[derive(Debug)]
struct FileRecord {
    /// The first name in sort order, which becomes the file entry.
    first: TreePath,
    /// Its other names, which become hard links.
    others: Vec<TreePath>,
    snapshot: Snapshot,
    mode: Mode,
    content: Digest,
    fsverity: Digest,
    xattrs: Xattrs,
    capabilities: Option<Capabilities>,
}

impl FileRecord {
    fn add_name(&mut self, path: TreePath) {
        self.others.push(path.clone().max(self.first.clone()));
        self.first = path.min(self.first.clone());
    }
}

/// A directory being walked.
#[derive(Debug)]
struct Frame {
    dir: OwnedFd,
    /// Its path in the tree: empty for the root.
    path: String,
    snapshot: Snapshot,
    /// The digest of the names it held when it was listed.
    listed: Digest,
    names: vec::IntoIter<CString>,
}

impl Frame {
    /// Refuses a directory that changed since it was opened: something
    /// may have come or gone while its contents were read.
    ///
    /// Its details are compared, and its names are listed again: adding
    /// or removing an entry may leave a directory's size and timestamps
    /// as they were (on ext4, a directory stays 4096 bytes and its times
    /// come from a coarse clock).
    fn expect_unchanged(&self) -> Result<(), WalkError> {
        let at = |kind| WalkError {
            path: format!("{}/", self.path),
            kind,
        };
        Snapshot::of_open(&self.dir)
            .and_then(|now| now.expect(self.snapshot))
            .map_err(at)?;
        if names_digest(&listing(&self.dir).map_err(at)?) != self.listed {
            return Err(at(WalkErrorKind::Changed));
        }
        Ok(())
    }
}

/// The names in an open directory, without `.` and `..`, sorted so that
/// a walk always meets the same problem first.
fn listing(dir: &OwnedFd) -> Result<Vec<CString>, WalkErrorKind> {
    let mut names = Vec::new();
    for entry in sys::Dir::read_from(dir).map_err(io("read the directory"))? {
        let entry = entry.map_err(io("read the directory"))?;
        let name = entry.file_name();
        if !matches!(name.to_bytes(), b"." | b"..") {
            names.push(name.to_owned());
        }
    }
    names.sort_unstable();
    Ok(names)
}

/// A digest of sorted names, each with its closing NUL, so no two lists
/// give the same bytes.
fn names_digest(names: &[CString]) -> Digest {
    let mut hasher = Blake3Hasher::default();
    for name in names {
        hasher.update(name.as_bytes_with_nul());
    }
    hasher.finish()
}

#[derive(Debug)]
struct Walker {
    mount: u64,
    limit: usize,
    found: usize,
    owners: Owners,
    entries: Vec<Entry>,
    files: BTreeMap<Inode, FileRecord>,
    name_buffer: Vec<u8>,
    value_buffer: Vec<u8>,
}

impl Walker {
    fn new(mount: u64, limit: usize, owners: Owners) -> Self {
        Self {
            mount,
            limit,
            found: 0,
            owners,
            entries: Vec::new(),
            files: BTreeMap::new(),
            name_buffer: vec![0; ATTRIBUTE_BUFFER],
            value_buffer: vec![0; ATTRIBUTE_BUFFER],
        }
    }

    /// The names in an open directory, sorted, counted against the limit,
    /// and the digest of the list.
    fn names(&mut self, dir: &OwnedFd) -> Result<(vec::IntoIter<CString>, Digest), WalkErrorKind> {
        let names = listing(dir)?;
        self.found = self.found.saturating_add(names.len());
        if self.found > self.limit {
            return Err(WalkErrorKind::TooManyEntries);
        }
        let digest = names_digest(&names);
        Ok((names.into_iter(), digest))
    }

    /// The attributes of what is open, sorted into what a tree records.
    fn attributes(&mut self, fd: impl AsFd, regular: bool) -> Result<Attributes, WalkErrorKind> {
        let fd = fd.as_fd();
        let mut attributes = Attributes::default();
        let length = listed(sys::flistxattr(fd, &mut self.name_buffer[..]))?;
        for name in self.name_buffer[..length]
            .split(|&byte| byte == 0)
            .filter(|name| !name.is_empty())
        {
            let keep = disposition(name, regular)?;
            if keep != Disposition::Ignore {
                let read = sys::fgetxattr(fd, name, &mut self.value_buffer[..]);
                let value = &self.value_buffer[..value_length(read)?];
                attributes.record(keep, name, value)?;
            }
        }
        Ok(attributes)
    }

    fn file(
        &mut self,
        dir: &OwnedFd,
        name: &CStr,
        path: TreePath,
        listed: Snapshot,
    ) -> Result<(), WalkErrorKind> {
        // Another name for a file already read.
        if let Some(record) = self.files.get_mut(&listed.inode) {
            listed.expect(record.snapshot)?;
            record.add_name(path);
            return Ok(());
        }
        let fd =
            sys::openat(dir, name, OPEN_FILE, sys::Mode::empty()).map_err(io("open the file"))?;
        Snapshot::of_open(&fd)?.expect(listed)?;
        let attributes = self.attributes(&fd, true)?;
        let mut file = OpenFile::from(fd);
        let digests = file_digests(&mut file).map_err(read_failed)?;
        Snapshot::of_open(&file)?.expect(listed)?;
        expect_size(digests.size, listed.size)?;
        let record = FileRecord {
            first: path,
            others: Vec::new(),
            snapshot: listed,
            mode: listed.permissions()?,
            content: digests.content,
            fsverity: digests.fsverity,
            xattrs: attributes.xattrs,
            capabilities: attributes.capabilities,
        };
        self.files.insert(listed.inode, record);
        Ok(())
    }

    fn directory(
        &mut self,
        dir: &OwnedFd,
        name: &CStr,
        path: TreePath,
        listed: Snapshot,
    ) -> Result<Frame, WalkErrorKind> {
        let fd = sys::openat(dir, name, OPEN_DIR, sys::Mode::empty())
            .map_err(io("open the directory"))?;
        Snapshot::of_open(&fd)?.expect(listed)?;
        let xattrs = self.attributes(&fd, false)?.xattrs;
        let (names, digest) = self.names(&fd)?;
        let owners = self.owners.of(&path);
        let frame = Frame {
            dir: fd,
            path: path.to_string(),
            snapshot: listed,
            listed: digest,
            names,
        };
        self.entries.push(Entry {
            path,
            kind: Kind::Dir(Dir {
                mode: listed.permissions()?,
                owner: owners.owner,
                group: owners.group,
                xattrs,
            }),
        });
        Ok(frame)
    }

    fn symlink(
        &mut self,
        dir: &OwnedFd,
        name: &CStr,
        path: TreePath,
        listed: Snapshot,
    ) -> Result<(), WalkErrorKind> {
        let target = sys::readlinkat(dir, name, Vec::new()).map_err(io("read the symlink"))?;
        Snapshot::of_name(dir, name)?.expect(listed)?;
        let target: SymlinkTarget = target
            .to_str()
            .map_err(|_| WalkErrorKind::TargetNotUtf8)?
            .parse()
            .map_err(WalkErrorKind::BadTarget)?;
        let owners = self.owners.of(&path);
        self.entries.push(Entry {
            path,
            kind: Kind::Symlink(Symlink {
                target,
                owner: owners.owner,
                group: owners.group,
            }),
        });
        Ok(())
    }

    /// Records one name, and returns the directory to go into if it is one.
    fn visit_name(
        &mut self,
        dir: &OwnedFd,
        parent: &str,
        name: &CStr,
    ) -> Result<Option<Frame>, WalkErrorKind> {
        let text = name.to_str().map_err(|_| WalkErrorKind::NotUtf8)?;
        let path: TreePath = format!("{parent}/{text}")
            .parse()
            .map_err(WalkErrorKind::BadPath)?;
        let listed = Snapshot::of_name(dir, name)?;
        if listed.mount != self.mount {
            return Err(WalkErrorKind::CrossesMount);
        }
        match listed.file_type() {
            FileType::RegularFile => self.file(dir, name, path, listed).map(|()| None),
            FileType::Directory => self.directory(dir, name, path, listed).map(Some),
            FileType::Symlink => self.symlink(dir, name, path, listed).map(|()| None),
            other => Err(WalkErrorKind::Unsupported(unsupported(other))),
        }
    }

    fn visit(
        &mut self,
        dir: &OwnedFd,
        parent: &str,
        name: &CStr,
    ) -> Result<Option<Frame>, WalkError> {
        self.visit_name(dir, parent, name)
            .map_err(|kind| WalkError {
                path: format!("{parent}/{}", shown(name.to_bytes())),
                kind,
            })
    }

    /// Turns what was found into entries and warnings.
    fn finish(mut self, options: &Options) -> Result<Walk, WalkError> {
        let mut warnings = Vec::new();
        for record in self.files.into_values() {
            let owners = self.owners.of(&record.first);
            let bits = record.mode.value();
            let declared = options.setuid.contains(&record.first)
                || record.others.iter().any(|p| options.setuid.contains(p));
            if bits & (SETUID + SETGID) != 0 && !declared {
                warnings.push(Warning {
                    path: record.first.clone(),
                    setuid: (bits & SETUID != 0).then(|| owners.owner.clone()),
                    setgid: (bits & SETGID != 0).then(|| owners.group.clone()),
                    default_owner: !owners.overridden,
                });
            }
            for other in record.others {
                self.entries.push(Entry {
                    path: other,
                    kind: Kind::HardLink(record.first.clone()),
                });
            }
            self.entries.push(Entry {
                path: record.first,
                kind: Kind::File(File {
                    mode: record.mode,
                    owner: owners.owner,
                    group: owners.group,
                    size: record.snapshot.size,
                    content: record.content,
                    fsverity: record.fsverity,
                    xattrs: record.xattrs,
                    capabilities: record.capabilities,
                }),
            });
        }
        self.owners.check_all_used()?;
        warnings.sort_by(|a, b| a.path.cmp(&b.path));
        let tree = Tree::new(self.entries).map_err(|e| WalkError {
            path: "/".to_owned(),
            kind: WalkErrorKind::Tree(Box::new(e)),
        })?;
        Ok(Walk { tree, warnings })
    }
}

fn walk_limited(root: &Path, options: &Options, limit: usize) -> Result<Walk, WalkError> {
    let at_root = |kind| WalkError {
        path: shown(root.as_os_str().as_bytes()),
        kind,
    };
    let dir = sys::open(root, OPEN_ROOT, sys::Mode::empty())
        .map_err(io("open the directory"))
        .map_err(at_root)?;
    let snapshot = Snapshot::of_open(&dir).map_err(at_root)?;
    let mut walker = Walker::new(snapshot.mount, limit, Owners::new(&options.owners)?);
    let (names, digest) = walker.names(&dir).map_err(at_root)?;
    let mut stack = vec![Frame {
        dir,
        path: String::new(),
        snapshot,
        listed: digest,
        names,
    }];
    while let Some(frame) = stack.last_mut() {
        if let Some(name) = frame.names.next() {
            let child = walker.visit(&frame.dir, &frame.path, &name)?;
            stack.extend(child);
        } else {
            frame.expect_unchanged()?;
            stack.pop();
        }
    }
    walker.finish(options)
}

/// Records the directory `root` as a tree: `root/usr/bin/x` becomes
/// `/usr/bin/x`. Owners come from `options`, never from the files on
/// disk, and timestamps aren't recorded.
///
/// # Errors
///
/// Anything that can't be recorded exactly, naming the path: device
/// nodes, sockets and FIFOs, names that aren't valid in a tree,
/// attributes that can't be packaged, unreadable files, mount points
/// inside the tree, and anything that changes during the walk.
pub fn walk(root: &Path, options: &Options) -> Result<Walk, WalkError> {
    walk_limited(root, options, MAX_ENTRIES)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, SystemTime};

    use super::*;

    fn snapshot() -> Snapshot {
        Snapshot {
            mode: 0o100_644,
            links: 1,
            inode: Inode {
                device: (8, 1),
                number: 42,
            },
            mount: 7,
            size: 10,
            modified: (100, 5),
            changed: (200, 6),
        }
    }

    fn dir_fd(path: &Path) -> OwnedFd {
        sys::open(path, OPEN_ROOT, sys::Mode::empty()).unwrap()
    }

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn details_must_all_be_reported() {
        require_details(DETAILS.bits()).unwrap();
        require_details(DETAILS.bits() + StatxFlags::BTIME.bits()).unwrap();
        for partial in [DETAILS.bits() - StatxFlags::MNT_ID.bits(), 0] {
            assert!(matches!(
                require_details(partial),
                Err(WalkErrorKind::MissingDetails)
            ));
        }
    }

    #[test]
    fn snapshots_hold_what_the_file_says() {
        let root = temp();
        let path = root.path().join("file");
        fs::write(&path, b"12345").unwrap();
        let when = SystemTime::UNIX_EPOCH + Duration::new(1_000_000, 5);
        fs::File::open(&path).unwrap().set_modified(when).unwrap();
        let dir = dir_fd(root.path());
        let by_name = Snapshot::of_name(&dir, c"file").unwrap();
        assert_eq!(by_name.modified, (1_000_000, 5));
        assert_ne!(by_name.changed, by_name.modified);
        assert_eq!(by_name.size, 5);
        assert_eq!(by_name.links, 1);
        assert_eq!(by_name.file_type(), FileType::RegularFile);
        let open = fs::File::open(&path).unwrap();
        assert_eq!(Snapshot::of_open(&open).unwrap(), by_name);
    }

    #[test]
    fn reads_are_held_to_the_listed_size() {
        expect_size(5, 5).unwrap();
        assert!(matches!(expect_size(4, 5), Err(WalkErrorKind::Changed)));
        let e = read_failed(Errno::IO.into());
        assert!(e.to_string().starts_with("can't read the file: "), "{e}");
    }

    #[test]
    fn a_directory_changed_while_open_is_noticed() {
        // In the temporary directory (often tmpfs, where a directory's
        // size changes with its entries) and beside this test binary (on
        // disk, often ext4, where it doesn't and times come from a coarse
        // clock).
        let exe = std::env::current_exe().unwrap();
        let places = [
            tempfile::tempdir().unwrap(),
            tempfile::tempdir_in(exe.parent().unwrap()).unwrap(),
        ];
        for root in &places {
            let r = root.path();
            fs::write(r.join("a"), b"a").unwrap();
            fs::write(r.join("b"), b"b").unwrap();
            let frame = || {
                let dir = dir_fd(r);
                Frame {
                    snapshot: Snapshot::of_open(&dir).unwrap(),
                    listed: names_digest(&listing(&dir).unwrap()),
                    dir,
                    path: "/sub".to_owned(),
                    names: Vec::new().into_iter(),
                }
            };
            let changed = |frame: &Frame, what: &str| {
                let e = frame.expect_unchanged().unwrap_err();
                assert_eq!(e.path, "/sub/", "{what}");
                assert!(matches!(e.kind, WalkErrorKind::Changed), "{what}: {e}");
            };

            let f = frame();
            f.expect_unchanged().unwrap();
            // Reading a file inside changes nothing.
            fs::read(r.join("a")).unwrap();
            f.expect_unchanged().unwrap();

            fs::write(r.join("new"), b"x").unwrap();
            changed(&f, "added");

            let f = frame();
            fs::remove_file(r.join("new")).unwrap();
            changed(&f, "removed");

            let f = frame();
            fs::rename(r.join("b"), r.join("c")).unwrap();
            changed(&f, "renamed: the same count, other names");
        }
    }

    #[test]
    fn name_lists_have_distinct_digests() {
        let names = |list: &[&str]| -> Vec<CString> {
            list.iter().map(|n| CString::new(*n).unwrap()).collect()
        };
        let digests = [
            names_digest(&names(&[])),
            names_digest(&names(&["ab"])),
            names_digest(&names(&["a", "b"])),
            names_digest(&names(&["a", "c"])),
        ];
        for (i, a) in digests.iter().enumerate() {
            for b in &digests[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(names_digest(&names(&["a"])), names_digest(&names(&["a"])));
    }

    #[test]
    fn the_first_name_is_the_smallest() {
        let mut record = FileRecord {
            first: "/m".parse().unwrap(),
            others: Vec::new(),
            snapshot: snapshot(),
            mode: Mode::FILE,
            content: Digest::blake3(b""),
            fsverity: Digest::blake3(b""),
            xattrs: Xattrs::new(),
            capabilities: None,
        };
        record.add_name("/z".parse().unwrap());
        record.add_name("/a".parse().unwrap());
        assert_eq!(record.first.as_str(), "/a");
        let others: Vec<_> = record.others.iter().map(TreePath::as_str).collect();
        assert_eq!(others, ["/z", "/m"]);
    }

    #[test]
    fn any_difference_is_a_change() {
        let base = snapshot();
        base.expect(base).unwrap();
        let changes: [fn(&mut Snapshot); 8] = [
            |s| s.mode = 0o100_755,
            |s| s.links = 2,
            |s| s.inode.number = 43,
            |s| s.inode.device = (8, 2),
            |s| s.mount = 8,
            |s| s.size = 11,
            |s| s.modified.1 = 6,
            |s| s.changed.0 = 201,
        ];
        for change in changes {
            let mut other = base;
            change(&mut other);
            assert!(matches!(other.expect(base), Err(WalkErrorKind::Changed)));
        }
    }

    #[test]
    fn permissions_leave_out_the_file_type() {
        let mut s = snapshot();
        s.mode = 0o104_755;
        assert_eq!(s.permissions().unwrap().value(), 0o4755);
    }

    #[test]
    fn attribute_results_are_read_correctly() {
        assert_eq!(listed(Ok(5)).unwrap(), 5);
        assert_eq!(listed(Err(Errno::OPNOTSUPP)).unwrap(), 0);
        assert!(matches!(
            listed(Err(Errno::ACCESS)),
            Err(WalkErrorKind::Io { .. })
        ));
        assert_eq!(value_length(Ok(5)).unwrap(), 5);
        assert!(matches!(
            value_length(Err(Errno::NODATA)),
            Err(WalkErrorKind::Changed)
        ));
        assert!(matches!(
            value_length(Err(Errno::ACCESS)),
            Err(WalkErrorKind::Io { .. })
        ));
    }

    #[test]
    fn kinds_that_cannot_be_packaged_have_names() {
        assert_eq!(unsupported(FileType::Fifo), "a FIFO");
        assert_eq!(unsupported(FileType::Socket), "a socket");
        assert_eq!(unsupported(FileType::CharacterDevice), "a character device");
        assert_eq!(unsupported(FileType::BlockDevice), "a block device");
        assert_eq!(unsupported(FileType::Unknown), "a file of an unknown type");
    }

    #[test]
    fn opening_never_follows_a_symlink() {
        let root = temp();
        fs::create_dir(root.path().join("real")).unwrap();
        fs::write(root.path().join("file"), b"x").unwrap();
        symlink("real", root.path().join("to-dir")).unwrap();
        symlink("file", root.path().join("to-file")).unwrap();
        let dir = dir_fd(root.path());
        for (name, flags) in [(c"to-dir", OPEN_DIR), (c"to-file", OPEN_FILE)] {
            let e = sys::openat(&dir, name, flags, sys::Mode::empty()).unwrap_err();
            assert!(matches!(e, Errno::LOOP | Errno::NOTDIR), "{name:?}: {e}");
        }
    }

    #[test]
    fn a_fifo_swapped_in_does_not_hang_and_is_noticed() {
        // The file was listed, then replaced by a FIFO before it was
        // opened. Nothing is writing to the FIFO, so a blocking open would
        // never return.
        let root = temp();
        let path = root.path().join("file");
        fs::write(&path, b"x").unwrap();
        let dir = dir_fd(root.path());
        let listed = Snapshot::of_name(&dir, c"file").unwrap();
        fs::remove_file(&path).unwrap();
        sys::mknodat(&dir, c"file", FileType::Fifo, sys::Mode::RUSR, 0).unwrap();
        let mut walker = Walker::new(listed.mount, 10, Owners::new(&[]).unwrap());
        let e = walker
            .file(&dir, c"file", "/file".parse().unwrap(), listed)
            .unwrap_err();
        assert!(matches!(e, WalkErrorKind::Changed), "{e}");
    }

    #[test]
    fn a_mount_is_not_crossed() {
        // Making a real mount needs privileges, so the walker is told it
        // started on another mount: every name then looks like a mount point.
        let root = temp();
        fs::write(root.path().join("file"), b"x").unwrap();
        let dir = dir_fd(root.path());
        let here = Snapshot::of_open(&dir).unwrap().mount;
        let mut walker = Walker::new(here + 1, 10, Owners::new(&[]).unwrap());
        let e = walker.visit(&dir, "", c"file").unwrap_err();
        assert_eq!(e.path, "/file");
        assert!(matches!(e.kind, WalkErrorKind::CrossesMount), "{e}");
    }

    #[test]
    fn the_entry_limit_applies_as_names_are_found() {
        let root = temp();
        fs::create_dir(root.path().join("d")).unwrap();
        fs::write(root.path().join("d/one"), b"1").unwrap();
        fs::write(root.path().join("two"), b"2").unwrap();
        let options = Options::default();
        let walk = walk_limited(root.path(), &options, 3).unwrap();
        assert_eq!(walk.tree.entries().len(), 3);
        // Limits count across directories, not per directory.
        let e = walk_limited(root.path(), &options, 2).unwrap_err();
        assert!(matches!(e.kind, WalkErrorKind::TooManyEntries), "{e}");
    }

    #[test]
    fn warnings_say_who_the_file_runs_as() {
        let path: TreePath = "/usr/bin/x".parse().unwrap();
        let root = Account::root();
        let adm: Account = "adm".parse().unwrap();
        let warning = |setuid, setgid, default_owner| Warning {
            path: path.clone(),
            setuid,
            setgid,
            default_owner,
        };
        assert_eq!(
            warning(Some(root.clone()), None, true).to_string(),
            "/usr/bin/x: not declared: setuid, so it runs as root, the default (--owner sets another)"
        );
        assert_eq!(
            warning(None, Some(adm.clone()), false).to_string(),
            "/usr/bin/x: not declared: setgid, so it runs with group adm"
        );
        assert_eq!(
            warning(Some(adm.clone()), Some(adm), false).to_string(),
            "/usr/bin/x: not declared: setuid, so it runs as adm; setgid, so it runs with group adm"
        );
    }
}
