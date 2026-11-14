// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask`: Ordin's project tooling. See the library for the checks
//! and the release flows.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use xtask::release::{self, exec::System};

const USAGE: &str = "usage: cargo xtask <command>
  check-layers [--manifest-path <Cargo.toml>]
  dist --tag <tag> --out <dir>                 (inside the release container)
  pre-release
  release-sign <tag> --allowed-signers <file> --key <file>";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["check-layers"] => check_layers(&root().join("Cargo.toml")),
        ["check-layers", "--manifest-path", path] => check_layers(&PathBuf::from(path)),
        ["dist", "--tag", tag, "--out", out] => report(
            "dist",
            release::dist::run(
                &System,
                &root().join("Cargo.toml"),
                tag,
                std::env::var("SOURCE_DATE_EPOCH").ok().as_deref(),
                Path::new(out),
                &mut io::stderr(),
            )
            .map(|_| ()),
        ),
        ["pre-release"] => report(
            "pre-release",
            release::pre_release::run(&System, &root(), &mut io::stderr()).map(|tag| {
                print!("{}", release::pre_release::tag_commands(&tag));
            }),
        ),
        [
            "release-sign",
            tag,
            "--allowed-signers",
            signers,
            "--key",
            key,
        ] => report("release-sign", release_sign(tag, signers, key)),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn release_sign(tag: &str, signers: &str, key: &str) -> Result<(), release::Error> {
    let cargo_toml = root().join("Cargo.toml");
    let text =
        std::fs::read_to_string(&cargo_toml).map_err(|e| release::Error::io(&cargo_toml, &e))?;
    let workspace = release::version::workspace(&text)?;
    // Under target/, which is ignored by git and on disk rather than in a
    // memory-backed /tmp: a rebuild needs a few gigabytes.
    let work_parent = root().join("target/release-sign");
    std::fs::create_dir_all(&work_parent).map_err(|e| release::Error::io(&work_parent, &e))?;
    let opts = release::sign::Options {
        tag: tag.to_owned(),
        allowed_signers: PathBuf::from(signers),
        key: PathBuf::from(key),
        repository: workspace.repository,
        slug: workspace.slug,
        work_parent,
    };
    match release::sign::run(&System, &opts, &mut io::stdin().lock(), &mut io::stderr())? {
        release::sign::Outcome::Published => Ok(()),
        release::sign::Outcome::Declined => Err(release::Error::check("not published")),
    }
}

/// Exit codes: 0 done, 1 a check or step failed.
fn report(command: &str, result: Result<(), release::Error>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{command}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Exit codes: 0 clean, 1 violations found, 2 the check couldn't run.
fn check_layers(manifest: &Path) -> ExitCode {
    match xtask::check_workspace(manifest) {
        Ok(violations) if violations.is_empty() => {
            println!("check-layers: ok");
            ExitCode::SUCCESS
        }
        Ok(violations) => {
            for v in &violations {
                eprintln!("{v}");
            }
            eprintln!("check-layers: {} violation(s)", violations.len());
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("check-layers: {e}");
            ExitCode::from(2)
        }
    }
}
