// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The command line.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use ordin_core::{Arch, Facet, PackageName};
use ordin_pack::OwnerOverride;
use ordin_tree::TreePath;

/// Ordin, the package manager for Linux servers.
#[derive(Debug, Parser)]
#[command(name = "ordin", version)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Make a package from an install root.
    Pack(Box<PackArgs>),
    /// Show what a package holds, without installing or unpacking it.
    Show(ShowArgs),
    /// Sign a package with a key, or sign it again.
    Sign(SignArgs),
    /// Check that a package is intact and signed by a key you trust.
    Verify(VerifyArgs),
    /// Warn about likely mistakes in a package, before it is published.
    Lint(LintArgs),
    /// Write a package's files to a new directory, without root.
    Unpack(UnpackArgs),
    /// Manage signing keys.
    #[command(subcommand)]
    Key(KeyCommand),
}

/// Where `--version-from` makes the version from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum VersionFrom {
    /// The git checkout at the working directory.
    Git,
}

/// `ordin key`.
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Make a new Ed25519 key pair: NAME, the secret key, and NAME.pub.
    Generate(KeyGenerateArgs),
}

/// `ordin key generate`.
#[derive(Debug, Args)]
pub struct KeyGenerateArgs {
    /// The secret key file to write; the public key goes in NAME.pub.
    pub name: PathBuf,
    /// Who or what the key is for, written in the public key file.
    #[arg(long)]
    pub comment: Option<String>,
    /// Read the passphrase from this file instead of asking for it.
    #[arg(long, value_name = "FILE", conflicts_with = "no_passphrase")]
    pub passphrase_file: Option<PathBuf>,
    /// Store the secret key in the clear, protected only by its file's
    /// permissions.
    #[arg(long)]
    pub no_passphrase: bool,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `ordin sign`.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// The package file.
    pub file: PathBuf,
    /// The secret key file to sign with.
    #[arg(long, value_name = "NAME")]
    pub key: PathBuf,
    /// Read the key's passphrase from this file instead of asking for it.
    #[arg(long, value_name = "FILE")]
    pub passphrase_file: Option<PathBuf>,
    /// The file to write; the package itself if not given.
    #[arg(long, short)]
    pub out: Option<PathBuf>,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `ordin unpack`.
#[derive(Debug, Args)]
pub struct UnpackArgs {
    /// The package file.
    pub file: PathBuf,
    /// The directory to write, which must not exist yet. Owners, special
    /// mode bits, attributes and capabilities go in DIR.ordin-meta.json.
    #[arg(long, value_name = "DIR")]
    pub to: PathBuf,
    /// Unpack only this facet. Give it once for each; without it, every
    /// facet is unpacked.
    #[arg(long, value_name = "NAME")]
    pub facet: Vec<Facet>,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `ordin verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// The package file.
    pub file: PathBuf,
    /// A public key file of a signer you trust. Give it once for each
    /// key; without it, no signature is trusted.
    #[arg(long, value_name = "KEY.pub")]
    pub trust: Vec<PathBuf>,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `ordin lint`.
#[derive(Debug, Args)]
pub struct LintArgs {
    /// The package file.
    pub file: PathBuf,
    /// The recipe whose [[lint.allow]] entries accept warnings;
    /// ./ordin.toml if there is one and this isn't given.
    #[arg(long, value_name = "FILE", conflicts_with = "no_manifest")]
    pub manifest: Option<PathBuf>,
    /// Don't read ./ordin.toml.
    #[arg(long)]
    pub no_manifest: bool,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `ordin show`.
#[derive(Debug, Args)]
pub struct ShowArgs {
    /// The package file.
    pub file: PathBuf,
    /// Also list each facet's files.
    #[arg(long)]
    pub facets: bool,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `ordin pack`.
#[derive(Debug, Args)]
pub struct PackArgs {
    /// The install root: what `make install DESTDIR=…` filled.
    pub dir: PathBuf,
    /// The recipe to read; ./ordin.toml if there is one and this isn't
    /// given. Flags win over what it says.
    #[arg(long, value_name = "FILE", conflicts_with = "no_manifest")]
    pub manifest: Option<PathBuf>,
    /// Don't read ./ordin.toml.
    #[arg(long)]
    pub no_manifest: bool,
    /// The package's name; needed unless the recipe gives it.
    #[arg(long)]
    pub name: Option<PackageName>,
    /// The upstream version, with an optional epoch: `2.12`, `1:2.0`;
    /// needed unless --version-from or the recipe gives it.
    #[arg(
        long = "version",
        value_name = "VERSION",
        conflicts_with = "version_from"
    )]
    pub version: Option<String>,
    /// Make the version from somewhere else: `git` makes a snapshot
    /// version from the working directory's checkout, such as
    /// `1.4.2^20261112.37.g3fa9c1e`, and records its commit.
    #[arg(long, value_name = "SOURCE")]
    pub version_from: Option<VersionFrom>,
    /// The release number; 1 unless the recipe gives another.
    #[arg(long)]
    pub release: Option<String>,
    /// The SPDX license expression; NOASSERTION if not given.
    #[arg(long)]
    pub license: Option<String>,
    /// The text of one license ID in --license. Repeat for each.
    #[arg(long = "license-file", value_name = "ID=PATH", value_parser = license_file)]
    pub license_files: Vec<(String, PathBuf)>,
    /// One line about the package; its name if not given.
    #[arg(long)]
    pub summary: Option<String>,
    /// x86_64, aarch64 or noarch; found from the package's programs and
    /// libraries if not given, and noarch if it has none.
    #[arg(long)]
    pub arch: Option<Arch>,
    /// The file to write; NAME-VERSION.ARCH.ordin here if not given.
    #[arg(long, short)]
    pub out: Option<PathBuf>,
    /// The owner of a path in DIR and everything below it. Repeatable.
    #[arg(long = "owner", value_name = "PATH=USER:GROUP", value_parser = owner)]
    pub owners: Vec<OwnerOverride>,
    /// A file in DIR that is setuid or setgid on purpose. Repeatable.
    #[arg(long = "setuid", value_name = "PATH", value_parser = path)]
    pub setuid: Vec<TreePath>,
    /// A prefix the software was installed with, such as opt/foo; its
    /// contents move to /usr. Repeatable.
    #[arg(long = "prefix", value_name = "PATH", value_parser = path)]
    pub prefixes: Vec<TreePath>,
    /// Sign the package with this secret key file.
    #[arg(long, value_name = "NAME")]
    pub sign_key: Option<PathBuf>,
    /// Read the key's passphrase from this file instead of asking for it.
    #[arg(long, value_name = "FILE", requires = "sign_key")]
    pub passphrase_file: Option<PathBuf>,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// A path in the install root, with or without its leading `/`.
fn path(text: &str) -> Result<TreePath, String> {
    let absolute = if text.starts_with('/') {
        text.to_owned()
    } else {
        format!("/{text}")
    };
    absolute.parse()
}

/// `PATH=USER:GROUP`, the path with or without its leading `/`.
fn owner(text: &str) -> Result<OwnerOverride, String> {
    if text.starts_with('/') {
        text.parse()
    } else {
        format!("/{text}").parse()
    }
}

/// `ID=PATH`.
fn license_file(text: &str) -> Result<(String, PathBuf), String> {
    match text.split_once('=') {
        Some((id, path)) if !id.is_empty() && !path.is_empty() => {
            Ok((id.to_owned(), PathBuf::from(path)))
        }
        _ => Err(format!("a license file is ID=PATH: {text:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_may_leave_out_the_leading_slash() {
        assert_eq!(path("usr/bin/x").unwrap().as_str(), "/usr/bin/x");
        assert_eq!(path("/usr/bin/x").unwrap().as_str(), "/usr/bin/x");
        assert!(path("usr//x").is_err());
        assert_eq!(
            owner("var/lib/x=www:www").unwrap(),
            owner("/var/lib/x=www:www").unwrap()
        );
        assert!(owner("var/lib/x").is_err());
    }

    #[test]
    fn license_files_name_an_id_and_a_path() {
        assert_eq!(
            license_file("MIT=COPYING").unwrap(),
            ("MIT".to_owned(), PathBuf::from("COPYING"))
        );
        assert_eq!(
            license_file("MIT=a=b").unwrap(),
            ("MIT".to_owned(), PathBuf::from("a=b"))
        );
        for bad in ["MIT", "=COPYING", "MIT="] {
            assert_eq!(
                license_file(bad).unwrap_err(),
                format!("a license file is ID=PATH: {bad:?}")
            );
        }
    }
}
