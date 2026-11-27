// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading the small files the commands are given, and writing new ones.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};
use ordin_recipe::RelativePath;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};

/// Opens `path` for reading if it is a regular file, and says `refused`
/// otherwise. A FIFO or a device is refused before it is opened, so it
/// can't make a command wait.
pub fn open_regular(path: &Path, refused: &str) -> Result<File> {
    let shown = || path.display().to_string();
    if !std::fs::metadata(path).with_context(shown)?.is_file() {
        bail!("{}: {refused}", path.display());
    }
    let file = File::open(path).with_context(shown)?;
    // The path may have been replaced in between.
    if !file.metadata().with_context(shown)?.is_file() {
        bail!("{}: {refused}", path.display());
    }
    Ok(file)
}

/// Reads all of `file`, refusing more than `max` bytes.
fn read_at_most(file: &File, path: &Path, max: u64, what: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .with_context(|| path.display().to_string())?;
    if bytes.len() as u64 > max {
        bail!("{}: {what} is at most {max} bytes", path.display());
    }
    Ok(bytes)
}

/// Reads a regular file of at most `max` bytes: `what` names it in
/// errors.
pub fn read_small(path: &Path, max: u64, what: &str) -> Result<Vec<u8>> {
    let file = open_regular(path, &format!("{what} must be a regular file"))?;
    read_at_most(&file, path, max, what)
}

/// How [`read_beneath`] opens the directory it starts from.
const OPEN_TOP: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

/// How it opens each directory below that: never through a symlink.
const OPEN_BELOW: OFlags = OPEN_TOP.union(OFlags::NOFOLLOW);

/// How it opens the file: never through a symlink, and without blocking
/// or taking a terminal, in case it was replaced since it was checked.
const OPEN_FILE: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

/// Reads a regular file of at most `max` bytes at `path` below `dir`,
/// without going through a symlink, so a recipe can't name a file outside
/// its own directory. `what` names it in errors.
pub fn read_beneath(dir: &Path, path: &RelativePath, max: u64, what: &str) -> Result<Vec<u8>> {
    // Below the working directory, the path as the recipe wrote it.
    let shown = if dir == Path::new(".") {
        Path::new(path.as_str()).to_path_buf()
    } else {
        dir.join(path.as_str())
    };
    let context = || shown.display().to_string();
    let mut at =
        fs::open(dir, OPEN_TOP, Mode::empty()).with_context(|| dir.display().to_string())?;
    let (parents, last) = match path.as_str().rsplit_once('/') {
        Some((parents, last)) => (parents.split('/').collect(), last),
        None => (Vec::new(), path.as_str()),
    };
    let refuse = |kind: FileType| -> Result<()> {
        if kind == FileType::Symlink {
            bail!(
                "{}: {what} can't be reached through a symlink",
                shown.display()
            );
        }
        Ok(())
    };
    for name in parents {
        refuse(FileType::from_raw_mode(
            fs::statat(&at, name, AtFlags::SYMLINK_NOFOLLOW)
                .with_context(context)?
                .st_mode,
        ))?;
        at = fs::openat(&at, name, OPEN_BELOW, Mode::empty()).with_context(context)?;
    }
    // A FIFO or a device is refused before it is opened, so it can't make
    // the command wait, and after, in case it was replaced in between.
    let kind = FileType::from_raw_mode(
        fs::statat(&at, last, AtFlags::SYMLINK_NOFOLLOW)
            .with_context(context)?
            .st_mode,
    );
    refuse(kind)?;
    if kind != FileType::RegularFile {
        bail!("{}: {what} must be a regular file", shown.display());
    }
    let fd = fs::openat(&at, last, OPEN_FILE, Mode::empty()).with_context(context)?;
    let file = File::from(fd);
    if !file.metadata().with_context(context)?.is_file() {
        bail!("{}: {what} must be a regular file", shown.display());
    }
    read_at_most(&file, &shown, max, what)
}

/// Reads a secret key file of at most `max` bytes, refusing one that
/// anyone but its owner can read or write, as `ssh` does.
pub fn read_secret(path: &Path, max: u64) -> Result<Vec<u8>> {
    let what = "a secret key file";
    let file = open_regular(path, &format!("{what} must be a regular file"))?;
    let mode = file
        .metadata()
        .with_context(|| path.display().to_string())?
        .permissions()
        .mode()
        & 0o7777;
    if mode & 0o077 != 0 {
        bail!(
            "{}: {what} must be readable by its owner only, not mode {mode:04o}; run chmod 600 {}",
            path.display(),
            path.display()
        );
    }
    read_at_most(&file, path, max, what)
}

/// Writes a new file with this mode, refusing to replace one that exists,
/// and syncs it.
pub fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let shown = || path.display().to_string();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(shown)?;
    // The mode given is filtered by the umask; set it exactly.
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .with_context(shown)?;
    file.write_all(bytes).with_context(shown)?;
    file.sync_all().with_context(shown)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_files_are_read_whole_or_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"1234").unwrap();
        assert_eq!(read_small(&path, 4, "a thing").unwrap(), b"1234");
        assert_eq!(
            read_small(&path, 3, "a thing").unwrap_err().to_string(),
            format!("{}: a thing is at most 3 bytes", path.display())
        );
        assert_eq!(
            read_small(dir.path(), 3, "a thing")
                .unwrap_err()
                .to_string(),
            format!("{}: a thing must be a regular file", dir.path().display())
        );
        assert!(read_small(&dir.path().join("missing"), 3, "a thing").is_err());
    }

    #[test]
    fn a_secret_key_file_is_its_owners_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        write_new(&path, b"secret", 0o600).unwrap();
        assert_eq!(read_secret(&path, 10).unwrap(), b"secret");
        assert!(
            read_secret(&path, 5)
                .unwrap_err()
                .to_string()
                .ends_with("a secret key file is at most 5 bytes")
        );
        for mode in [0o640, 0o604, 0o620, 0o602, 0o644] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let e = read_secret(&path, 10).unwrap_err().to_string();
            assert!(
                e.contains(&format!("not mode {mode:04o}; run chmod 600")),
                "{e}"
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_secret(&path, 10).is_ok());
        assert!(
            read_secret(dir.path(), 10)
                .unwrap_err()
                .to_string()
                .ends_with("a secret key file must be a regular file")
        );
    }

    #[test]
    fn new_files_get_exactly_their_mode_and_are_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new");
        write_new(&path, b"x", 0o640).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640);
        assert!(write_new(&path, b"y", 0o640).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }

    #[test]
    fn only_regular_files_are_opened() {
        let e = open_regular(Path::new("/dev/null"), "no").unwrap_err();
        assert_eq!(e.to_string(), "/dev/null: no");
    }
}
