// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask`: Ordin's project tooling. See the library for the checks
//! and the release flows.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use xtask::release::{self, exec::System};
use xtask::{corpus, version_corpus};

const USAGE: &str = "usage: cargo xtask <command>
  check-layers [--manifest-path <Cargo.toml>]
  corpus [--update]
  dist --tag <tag> --out <dir>                 (inside the release container)
  pre-release
  release-sign <tag> --allowed-signers <file> --key <file>
  version-corpus --census <census.json> --out <file>
  version-corpus --check [<file>]";

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
        ["corpus"] => report("corpus", run_corpus(false)),
        ["corpus", "--update"] => report("corpus", run_corpus(true)),
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
        ["version-corpus", "--census", census, "--out", out] => report(
            "version-corpus",
            write_corpus(Path::new(census), Path::new(out)),
        ),
        ["version-corpus", "--check"] => report(
            "version-corpus",
            check_corpus(&root().join(version_corpus::CORPUS)),
        ),
        ["version-corpus", "--check", file] => {
            report("version-corpus", check_corpus(Path::new(file)))
        }
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

/// The dogfood corpus (ORD-152), built in cargo's target directory.
fn run_corpus(update: bool) -> Result<(), release::Error> {
    let meta = cargo_metadata::MetadataCommand::new()
        .manifest_path(root().join("Cargo.toml"))
        .no_deps()
        .exec()
        .map_err(|e| release::Error::check(format!("cargo metadata failed: {e}")))?;
    let opts = corpus::Options {
        root: meta.workspace_root.into_std_path_buf(),
        target: meta.target_directory.into_std_path_buf(),
        cargo: std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()),
        update,
    };
    let report = corpus::run(&System, &opts, &mut io::stderr())?;
    if update {
        println!(
            "corpus: {} packages, {} golden files written; review them with `git diff corpus/`",
            report.packages.len(),
            report.updated.len()
        );
    } else {
        println!("corpus: ok, {} packages", report.packages.len());
    }
    Ok(())
}

fn read(path: &Path) -> Result<String, release::Error> {
    std::fs::read_to_string(path).map_err(|e| release::Error::io(path, &e))
}

fn write_corpus(census: &Path, out: &Path) -> Result<(), release::Error> {
    let text = version_corpus::generate(&System, &read(census)?, &mut io::stderr())?;
    std::fs::write(out, text).map_err(|e| release::Error::io(out, &e))?;
    eprintln!("version-corpus: wrote {}", out.display());
    Ok(())
}

fn check_corpus(file: &Path) -> Result<(), release::Error> {
    let count = version_corpus::check(&System, &read(file)?, &mut io::stderr())?;
    println!("version-corpus: ok, {count} versions");
    Ok(())
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
