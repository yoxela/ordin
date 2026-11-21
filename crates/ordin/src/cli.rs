// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The command line.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use ordin_core::{Arch, PackageName};
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
    Pack(PackArgs),
}

/// `ordin pack`.
#[derive(Debug, Args)]
pub struct PackArgs {
    /// The install root: what `make install DESTDIR=…` filled.
    pub dir: PathBuf,
    /// The package's name.
    #[arg(long)]
    pub name: PackageName,
    /// The upstream version, with an optional epoch: `2.12`, `1:2.0`.
    #[arg(long = "version", value_name = "VERSION")]
    pub version: String,
    /// The release number.
    #[arg(long, default_value = "1")]
    pub release: String,
    /// The SPDX license expression; NOASSERTION if not given.
    #[arg(long)]
    pub license: Option<String>,
    /// The text of one license ID in --license. Repeat for each.
    #[arg(long = "license-file", value_name = "ID=PATH", value_parser = license_file)]
    pub license_files: Vec<(String, PathBuf)>,
    /// One line about the package; its name if not given.
    #[arg(long)]
    pub summary: Option<String>,
    /// x86_64, aarch64 or noarch; this machine's if not given.
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
