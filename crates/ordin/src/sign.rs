// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `ordin sign`: adds a signature to a package, or replaces the key's
//! own, without changing anything else.

use std::fs::OpenOptions;
use std::io::{self, BufReader, BufWriter, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ordin_archive::Reader;
use ordin_core::Digest;
use ordin_sign::{PublicKey, Signature};
use tempfile::NamedTempFile;

use crate::cli::SignArgs;
use crate::{files, keys};

/// What `ordin sign` did.
#[derive(Debug)]
pub struct Signed {
    /// The file written.
    pub file: PathBuf,
    /// The package's identity, which signing never changes.
    pub package: Digest,
    /// The new image manifest's digest.
    pub image: Digest,
    /// The key that signed.
    pub key: PublicKey,
    /// Whether it replaced the key's own signature.
    pub replaced: bool,
    /// Every key the package is now signed by.
    pub signatures: Vec<PublicKey>,
}

/// Makes the temporary file a signed package is written to, in `dir`, as
/// `tempfile` would: under a name nothing has yet (`O_EXCL`, so an
/// existing file or symlink is never opened), readable and writable by its
/// owner only, and removed if it is dropped. It is opened here, and not by
/// `tempfile`, because `tempfile` adds the temporary file's full path to
/// the system's error, and the error is about the output named.
fn temp_file_in(dir: &Path) -> io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .prefix(".ordin-")
        .suffix(".tmp")
        .make_in(dir, |path| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
        })
}

/// Writes `out` from a temporary file in its directory, so a failure
/// leaves the old file as it was, and syncs the rename.
fn replace(out: &Path, write: impl FnOnce(&mut dyn Write) -> Result<()>) -> Result<()> {
    let shown = || out.display().to_string();
    let dir = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let temp = temp_file_in(&dir).with_context(shown)?;
    let mut writer = BufWriter::new(temp.as_file());
    write(&mut writer)?;
    writer.flush().with_context(shown)?;
    drop(writer);
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .with_context(shown)?;
    temp.as_file().sync_all().with_context(shown)?;
    temp.persist(out).map_err(|e| e.error).with_context(shown)?;
    std::fs::File::open(&dir)
        .and_then(|d| d.sync_all())
        .with_context(shown)?;
    Ok(())
}

/// Runs `ordin sign`.
///
/// # Errors
///
/// The key can't be loaded, the file isn't a package, or writing failed.
pub fn run(args: &SignArgs) -> Result<Signed> {
    let key = keys::load(&args.key, args.passphrase_file.as_deref())?;
    let public = key.public_key();
    let shown = || args.file.display().to_string();
    let file = files::open_regular(&args.file, "not a regular file")?;
    let mut reader = Reader::open(BufReader::new(file)).with_context(shown)?;
    let package = reader.package();
    let mut signatures: Vec<Signature> = reader
        .signatures()
        .iter()
        .filter(|s| s.key() != public)
        .cloned()
        .collect();
    let replaced = signatures.len() != reader.signatures().len();
    signatures.push(key.sign(&package)?);
    signatures.sort_by_key(Signature::key);
    let out = args.out.clone().unwrap_or_else(|| args.file.clone());
    let mut image = package;
    replace(&out, |w| {
        image = ordin_archive::rewrite(&mut reader, &signatures, &mut &mut *w)
            .with_context(|| out.display().to_string())?
            .image;
        Ok(())
    })?;
    Ok(Signed {
        file: out,
        package,
        image,
        key: public,
        replaced,
        signatures: signatures.iter().map(Signature::key).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_temporary_file_is_new_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let temp = temp_file_in(dir.path()).unwrap();
        let name = temp.path().file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with(".ordin-") && name.ends_with(".tmp"),
            "{name}"
        );
        assert_eq!(temp.path().parent().unwrap(), dir.path());
        let mode = temp.as_file().metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o600);
        let path = temp.path().to_path_buf();
        drop(temp);
        assert!(!path.exists());
        // The system's error, as it was.
        let e = temp_file_in(&dir.path().join("missing")).unwrap_err();
        assert_eq!(e.to_string(), "No such file or directory (os error 2)");
    }
}
