// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask corpus`: the dogfood corpus (ORD-152).
//!
//! Each package in `corpus/corpus.toml` is made from real upstream
//! artifacts:
//!
//! 1. Each source is downloaded, or found among the kept downloads, and its
//!    size and SHA-256 are checked before anything reads it ([`fetch`]).
//! 2. The sources are laid out as an install root ([`stage`]): a `tar.gz`
//!    is read directly, and a `deb` through `dpkg-deb --fsys-tarfile`,
//!    which only decompresses it.
//! 3. The release `ordin` packs the install root with the package's recipe,
//!    `corpus/<name>/ordin.toml`, and the license texts the list names.
//! 4. `ordin show --json` of the package must equal
//!    `corpus/<name>/show.json`. With `--update`, it is written there
//!    instead, to be reviewed in the diff.
//!
//! The golden files hold the package and image digests, so CI on x86_64 and
//! on aarch64 checking the same files shows that every package packs to the
//! same bytes on both.

pub mod fetch;
pub mod list;
pub mod snapshot;
pub mod stage;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;
use serde_json::Value;

use crate::release::exec::{Cmd, Exec};
use crate::release::{Error, say};
use list::{Format, Package};
use stage::{LIMITS, Stage};

/// Where the corpus lives, relative to the workspace.
pub const DIR: &str = "corpus";

/// The list, relative to the workspace.
pub const LIST: &str = "corpus/corpus.toml";

/// What a run needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// The workspace.
    pub root: PathBuf,
    /// Cargo's target directory. The release `ordin` is built there, and the
    /// work happens in `corpus/` below it.
    pub target: PathBuf,
    /// The cargo program.
    pub cargo: String,
    /// Write the golden files instead of checking them.
    pub update: bool,
}

/// What a run did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Each package, in the list's order.
    pub packages: Vec<String>,
    /// The golden files written, with `--update`.
    pub updated: Vec<String>,
}

/// Packs every corpus package and checks or writes its golden file.
///
/// # Errors
///
/// Returns an error if the list is wrong, a download or layout fails, the
/// build, `ordin pack` or `ordin show` fails, or, without `update`, any
/// package differs from its golden file. Every package is packed before the
/// differences are reported.
pub fn run(exec: &dyn Exec, opts: &Options, log: &mut dyn Write) -> Result<Report, Error> {
    let list = opts.root.join(LIST);
    let text = fs::read_to_string(&list).map_err(|e| Error::io(&list, &e))?;
    let packages = list::parse(&text)?;
    check_directories(&opts.root.join(DIR), &packages)?;

    say(log, "corpus: building the release ordin");
    exec.run(
        &Cmd::new(&opts.cargo)
            .args(["build", "--release", "--locked", "-p", "ordin"])
            .dir(&opts.root)
            .interactive(),
    )?;
    let ordin = opts.target.join("release/ordin");
    let ordin = ordin
        .to_str()
        .ok_or_else(|| Error::check(format!("{} isn't a UTF-8 path", ordin.display())))?
        .to_owned();

    let work = opts.target.join("corpus");
    let downloads = work.join("downloads");
    fs::create_dir_all(&downloads).map_err(|e| Error::io(&downloads, &e))?;
    let keep: BTreeSet<&str> = packages.iter().flat_map(Package::hashes).collect();
    fetch::prune(&downloads, &keep, log)?;
    let stages = fresh(&work.join("stage"))?;
    let out = fresh(&work.join("out"))?;

    let mut report = Report::default();
    let mut differ = Vec::new();
    for package in &packages {
        say(log, &format!("corpus: {}: {}", package.name, package.about));
        let stage = lay_out(exec, package, &downloads, &stages.join(&package.name), log)?;
        let found = pack(exec, &ordin, opts, package, &stage, &out, log)?;
        let golden = opts.root.join(DIR).join(&package.name).join("show.json");
        let text = snapshot::pretty(&found);
        if opts.update {
            if fs::read_to_string(&golden).ok().as_deref() != Some(text.as_str()) {
                fs::write(&golden, &text).map_err(|e| Error::io(&golden, &e))?;
                say(
                    log,
                    &format!(
                        "corpus: {}: wrote {}/{}/show.json",
                        package.name, DIR, package.name
                    ),
                );
                report.updated.push(package.name.clone());
            }
        } else {
            match fs::read_to_string(&golden) {
                Ok(expected) if expected == text => {}
                Ok(expected) => {
                    let expected: Value = serde_json::from_str(&expected)
                        .map_err(|e| Error::parse(&golden.display().to_string(), e))?;
                    let mut diffs = snapshot::differences(&expected, &found);
                    if diffs.is_empty() {
                        diffs.push("the same value, laid out differently".to_owned());
                    }
                    differ.push((package.name.clone(), diffs));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    differ.push((
                        package.name.clone(),
                        vec!["there is no show.json yet".to_owned()],
                    ));
                }
                Err(e) => return Err(Error::io(&golden, &e)),
            }
        }
        report.packages.push(package.name.clone());
    }
    if !differ.is_empty() {
        let mut message = String::new();
        for (name, diffs) in &differ {
            message.push_str(&format!("{name} differs from {DIR}/{name}/show.json:\n"));
            for d in diffs {
                message.push_str(&format!("  {d}\n"));
            }
        }
        message.push_str(
            "run `cargo xtask corpus --update` and review the change with `git diff corpus/`",
        );
        return Err(Error::check(message));
    }
    fs::remove_dir_all(&stages).map_err(|e| Error::io(&stages, &e))?;
    Ok(report)
}

/// Refuses a directory under `corpus/` that no package names, and a
/// package with no recipe.
fn check_directories(dir: &Path, packages: &[Package]) -> Result<(), Error> {
    let names: BTreeSet<&str> = packages.iter().map(|p| p.name.as_str()).collect();
    for entry in fs::read_dir(dir).map_err(|e| Error::io(dir, &e))? {
        let entry = entry.map_err(|e| Error::io(dir, &e))?;
        let is_dir = entry
            .file_type()
            .map_err(|e| Error::io(&entry.path(), &e))?
            .is_dir();
        let name = entry.file_name();
        if is_dir && !name.to_str().is_some_and(|n| names.contains(n)) {
            return Err(Error::check(format!(
                "{DIR}/{} is no package's directory; remove it or add the package to {LIST}",
                name.to_string_lossy()
            )));
        }
    }
    for name in names {
        let recipe = dir.join(name).join("ordin.toml");
        if !fs::symlink_metadata(&recipe).is_ok_and(|m| m.is_file()) {
            return Err(Error::check(format!(
                "{name} has no recipe, {DIR}/{name}/ordin.toml"
            )));
        }
    }
    Ok(())
}

/// `dir`, emptied: removed if it is there, and made again.
fn fresh(dir: &Path) -> Result<PathBuf, Error> {
    match fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(dir, &e)),
    }
    fs::create_dir_all(dir).map_err(|e| Error::io(dir, &e))?;
    Ok(dir.to_path_buf())
}

/// Downloads a package's sources and lays them out at `root`.
fn lay_out(
    exec: &dyn Exec,
    package: &Package,
    downloads: &Path,
    root: &Path,
    log: &mut dyn Write,
) -> Result<Stage, Error> {
    let mut stage = Stage::create(root, LIMITS)?;
    for source in &package.sources {
        let file = fetch::fetch(exec, downloads, source, log)?;
        let label = format!("{}: {}", package.name, source.url);
        match source.format {
            Format::TarGz => {
                let f = File::open(&file).map_err(|e| Error::io(&file, &e))?;
                stage.add_tar(MultiGzDecoder::new(f), source, &label)?;
            }
            Format::Deb => {
                let tar = exec.run(&Cmd::new("dpkg-deb").arg("--fsys-tarfile").arg(&file))?;
                stage.add_tar(Cursor::new(tar.stdout), source, &label)?;
            }
        }
    }
    for link in &package.links {
        stage.link(link, &package.name)?;
    }
    let count = stage.finish()?;
    say(
        log,
        &format!("corpus: {}: laid out {count} paths", package.name),
    );
    Ok(stage)
}

/// Packs the install root and returns `ordin show --json` of the package.
fn pack(
    exec: &dyn Exec,
    ordin: &str,
    opts: &Options,
    package: &Package,
    stage: &Stage,
    out: &Path,
    log: &mut dyn Write,
) -> Result<Value, Error> {
    let file = format!("{}.ordin", package.name);
    let mut cmd = Cmd::new(ordin)
        .arg("pack")
        .arg(stage.root())
        .arg("--manifest")
        .arg(opts.root.join(DIR).join(&package.name).join("ordin.toml"));
    for (id, path) in &package.licenses {
        if !stage.is_file(path) {
            return Err(Error::check(format!(
                "{}: the license text {path} for {id} isn't a file in the install root",
                package.name
            )));
        }
        let mut arg = OsString::from(format!("{id}="));
        arg.push(stage.root().join(path));
        cmd = cmd.arg("--license-file").arg(arg);
    }
    let packed = exec.run(&cmd.arg("-o").arg(&file).dir(out))?;
    for line in packed.stderr_text().lines() {
        say(log, &format!("corpus: {}: {line}", package.name));
    }
    let shown = exec.run(&Cmd::new(ordin).args(["show", &file, "--json"]).dir(out))?;
    serde_json::from_slice(&shown.stdout)
        .map_err(|e| Error::parse(&format!("ordin show --json of {file}"), e))
}

#[cfg(test)]
mod tests;
