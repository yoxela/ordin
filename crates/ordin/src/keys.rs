// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `ordin key generate`, and loading a secret key to sign with.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ordin_sign::{MAX_KEY_FILE_SIZE, PublicKey, PublicKeyFile, SecretKey, SecretKeyFile};
use zeroize::Zeroizing;

use crate::cli::KeyGenerateArgs;
use crate::files;
use crate::passphrase::{self, Passphrase};

/// The public key file beside a secret key file: its name with `.pub`.
#[must_use]
pub fn public_path(secret: &Path) -> PathBuf {
    let mut name = secret.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// Loads the secret key at `path`, asking for its passphrase on the
/// terminal if it is encrypted and no passphrase file is given.
pub fn load(path: &Path, passphrase_file: Option<&Path>) -> Result<SecretKey> {
    let shown = || path.display().to_string();
    let bytes = Zeroizing::new(files::read_secret(path, MAX_KEY_FILE_SIZE as u64)?);
    let file = SecretKeyFile::from_bytes(&bytes).with_context(shown)?;
    let passphrase: Option<Passphrase> = match (file.is_encrypted(), passphrase_file) {
        (true, Some(f)) => Some(passphrase::from_file(f)?),
        (true, None) => Some(passphrase::ask(
            &format!("Passphrase for {}: ", path.display()),
            false,
        )?),
        (false, Some(_)) => bail!(
            "{}: the secret key isn't encrypted, so it takes no --passphrase-file",
            path.display()
        ),
        (false, None) => None,
    };
    file.open(passphrase.as_ref().map(|p| p.as_slice()))
        .with_context(shown)
}

/// What `ordin key generate` made.
#[derive(Debug)]
pub struct Generated {
    /// The secret key file.
    pub secret: PathBuf,
    /// The public key file.
    pub public: PathBuf,
    /// The public key.
    pub key: PublicKey,
    /// Whether the secret key file is encrypted.
    pub encrypted: bool,
}

/// Runs `ordin key generate`.
///
/// # Errors
///
/// The comment isn't allowed, either file exists, no passphrase could be
/// had, or writing failed.
pub fn generate(args: &KeyGenerateArgs) -> Result<Generated> {
    let secret_path = args.name.clone();
    let public_path = public_path(&secret_path);
    for path in [&secret_path, &public_path] {
        if path.symlink_metadata().is_ok() {
            bail!(
                "{}: already exists; a key is never replaced",
                path.display()
            );
        }
    }
    let comment = args.comment.as_deref().unwrap_or("");
    // Check the comment before asking for anything.
    let key = SecretKey::generate()?;
    let public = PublicKeyFile::new(key.public_key(), comment)?;
    let passphrase: Option<Passphrase> = if args.no_passphrase {
        None
    } else if let Some(file) = &args.passphrase_file {
        Some(passphrase::from_file(file)?)
    } else {
        Some(passphrase::ask("Passphrase for the new key: ", true)?)
    };
    let sealed = SecretKeyFile::seal(&key, passphrase.as_ref().map(|p| p.as_slice()))?;
    files::write_new(&secret_path, &sealed.to_bytes(), 0o600)?;
    if let Err(e) = files::write_new(&public_path, public.to_text().as_bytes(), 0o644) {
        // Never leave a secret key without its public key.
        let _ = std::fs::remove_file(&secret_path);
        return Err(e);
    }
    Ok(Generated {
        secret: secret_path,
        public: public_path,
        key: public.key,
        encrypted: sealed.is_encrypted(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_key_file_is_named_after_the_secret_one() {
        assert_eq!(
            public_path(Path::new("dir/release")),
            PathBuf::from("dir/release.pub")
        );
        assert_eq!(public_path(Path::new("k.key")), PathBuf::from("k.key.pub"));
    }
}
