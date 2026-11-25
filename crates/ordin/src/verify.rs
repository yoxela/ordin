// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `ordin verify`: whether a package file is intact, and signed by a key
//! the caller trusts.
//!
//! Every byte is checked (see `ordin_archive::Reader::verify`), then each
//! signature's key against the keys given with `--trust`. Only a package
//! signed by one of them is trusted: with no `--trust`, nothing is.

use std::collections::BTreeSet;
use std::io::{BufReader, Read, Seek};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use ordin_archive::{ReadError, ReadErrorKind, Reader, Verified};
use ordin_core::Digest;
use ordin_sign::{MAX_KEY_FILE_SIZE, PublicKey, PublicKeyFile};

use crate::cli::VerifyArgs;
use crate::files;

/// The exit code for a package that isn't intact.
pub const CORRUPT: u8 = 3;
/// The exit code for an intact package with no signature.
pub const UNSIGNED: u8 = 4;
/// The exit code for an intact package signed by no trusted key.
pub const UNTRUSTED: u8 = 5;

/// What a check of an intact package concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A key given with `--trust` signed it.
    Trusted,
    /// Nobody signed it.
    Unsigned,
    /// It is signed, but by no key given with `--trust`.
    Untrusted,
}

impl Verdict {
    /// Its name in `--json` output.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Unsigned => "unsigned",
            Self::Untrusted => "untrusted",
        }
    }

    /// The exit code it gives.
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Trusted => 0,
            Self::Unsigned => UNSIGNED,
            Self::Untrusted => UNTRUSTED,
        }
    }
}

/// An intact package, and who signed it.
#[derive(Debug)]
pub struct Report {
    /// The file checked.
    pub file: PathBuf,
    /// The package's identity.
    pub package: Digest,
    /// The OCI image manifest's digest.
    pub image: Digest,
    /// What was checked.
    pub verified: Verified,
    /// Each signature's key, sorted, and whether it is trusted.
    pub signers: Vec<(PublicKey, bool)>,
    /// Whether any `--trust` key was given.
    pub trust_given: bool,
}

impl Report {
    /// The conclusion.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        verdict(&self.signers)
    }
}

/// The conclusion from the signers and whether each is trusted.
fn verdict(signers: &[(PublicKey, bool)]) -> Verdict {
    if signers.iter().any(|(_, trusted)| *trusted) {
        Verdict::Trusted
    } else if signers.is_empty() {
        Verdict::Unsigned
    } else {
        Verdict::Untrusted
    }
}

/// What `ordin verify` found.
#[derive(Debug)]
pub enum Checked {
    /// Every byte is as it should be.
    Intact(Report),
    /// A part of the file isn't: the error names it.
    Corrupt(anyhow::Error),
}

/// Reads a public key file given with `--trust`.
fn trusted_key(path: &Path) -> Result<PublicKey> {
    let shown = || path.display().to_string();
    let bytes = files::read_small(path, MAX_KEY_FILE_SIZE as u64, "a public key file")?;
    Ok(PublicKeyFile::from_bytes(&bytes).with_context(shown)?.key)
}

/// Whether `e` says the file is damaged, rather than that it couldn't be
/// read.
fn is_corruption(e: &ReadError) -> bool {
    !matches!(e.kind(), ReadErrorKind::Io(_) | ReadErrorKind::Output(_))
}

/// Runs `ordin verify`.
///
/// # Errors
///
/// A `--trust` file isn't a public key file, or the package can't be
/// opened or read. A package that reads but is damaged is
/// [`Checked::Corrupt`], not an error.
pub fn run(args: &VerifyArgs) -> Result<Checked> {
    let trusted = args
        .trust
        .iter()
        .map(|p| trusted_key(p))
        .collect::<Result<BTreeSet<PublicKey>>>()?;
    let file = files::open_regular(&args.file, "not a regular file")?;
    check(BufReader::new(file), &args.file, &trusted)
}

/// Checks the package read from `input`, named `path`, against the
/// `trusted` keys.
fn check(input: impl Read + Seek, path: &Path, trusted: &BTreeSet<PublicKey>) -> Result<Checked> {
    let shown = path.display().to_string();
    let checked = Reader::open(input).and_then(|mut reader| {
        let verified = reader.verify()?;
        Ok((reader, verified))
    });
    let (reader, verified) = match checked {
        Ok(read) => read,
        Err(e) if is_corruption(&e) => {
            return Ok(Checked::Corrupt(
                anyhow!(e).context(format!("{shown} is corrupt")),
            ));
        }
        Err(e) => return Err(anyhow!(e).context(shown)),
    };
    let signers = reader
        .signatures()
        .iter()
        .map(|s| (s.key(), trusted.contains(&s.key())))
        .collect();
    Ok(Checked::Intact(Report {
        file: path.to_path_buf(),
        package: reader.package(),
        image: reader.image(),
        verified,
        signers,
        trust_given: !trusted.is_empty(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Input that can be sought but not read.
    struct Unreadable;

    impl Read for Unreadable {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("the disk is gone"))
        }
    }

    impl Seek for Unreadable {
        fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
            Ok(4096)
        }
    }

    #[test]
    fn a_read_failure_is_an_error_and_damage_is_corruption() {
        let none = BTreeSet::new();
        let e = check(Unreadable, Path::new("p.ordin"), &none).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "p.ordin: the archive: reading the file: the disk is gone"
        );
        let damaged = std::io::Cursor::new(vec![1; 4096]);
        let Checked::Corrupt(e) = check(damaged, Path::new("p.ordin"), &none).unwrap() else {
            panic!("damaged bytes must be corrupt");
        };
        assert!(
            format!("{e:#}").starts_with("p.ordin is corrupt: the archive: "),
            "{e:#}"
        );
    }

    #[test]
    fn only_a_trusted_signer_makes_a_package_trusted() {
        let key = |_| ordin_sign::SecretKey::generate().unwrap().public_key();
        assert_eq!(verdict(&[]), Verdict::Unsigned);
        assert_eq!(verdict(&[(key(1), false)]), Verdict::Untrusted);
        assert_eq!(
            verdict(&[(key(1), false), (key(2), false)]),
            Verdict::Untrusted
        );
        assert_eq!(verdict(&[(key(1), true)]), Verdict::Trusted);
        assert_eq!(
            verdict(&[(key(1), false), (key(2), true)]),
            Verdict::Trusted
        );
        assert_eq!(
            [Verdict::Trusted, Verdict::Unsigned, Verdict::Untrusted].map(Verdict::exit_code),
            [0, 4, 5]
        );
        assert_eq!(
            [Verdict::Trusted, Verdict::Unsigned, Verdict::Untrusted].map(Verdict::name),
            ["trusted", "unsigned", "untrusted"]
        );
    }
}
