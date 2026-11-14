// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Throwaway repositories, keys and release files for the release tests.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use xtask::release::dist;

/// Test setup either works or fails the test with this error.
pub type R<T> = Result<T, Box<dyn std::error::Error>>;

fn checked(what: &str, out: &std::process::Output) -> R<String> {
    if out.status.success() {
        Ok(String::from_utf8(out.stdout.clone())?.trim().to_owned())
    } else {
        Err(format!("{what}: {}", String::from_utf8_lossy(&out.stderr)).into())
    }
}

/// Runs git with no user or system configuration.
pub fn git(dir: &Path, args: &[&str]) -> R<String> {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=Tester",
            "-c",
            "user.email=tester@example.invalid",
        ])
        .args(["-c", "init.defaultBranch=main", "-c", "gpg.format=ssh"])
        .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
        .args(args)
        .output()?;
    checked(&format!("git {args:?}"), &out)
}

/// Makes an ed25519 key pair with no passphrase and returns the public key
/// (type and base64).
pub fn keygen(path: &Path) -> R<String> {
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f"])
        .arg(path)
        .output()?;
    checked("ssh-keygen", &out)?;
    let public = fs::read_to_string(path.with_extension("pub"))?;
    let fields: Vec<&str> = public.split_whitespace().take(2).collect();
    Ok(fields.join(" "))
}

pub fn cargo_toml(version: &str) -> String {
    format!(
        "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"{version}\"\n\
         repository = \"https://github.com/test/ordin\"\n"
    )
}

pub const CHANGELOG: &str =
    "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-11-20\n\n- first\n";

/// A repository with an `origin`, as a maintainer's checkout would be.
pub struct Repo {
    pub dir: tempfile::TempDir,
    pub tag_key: PathBuf,
    pub release_key: PathBuf,
    pub other_key: PathBuf,
    /// The trusted copy of allowed_signers, outside the repository.
    pub trusted: PathBuf,
    pub origin: PathBuf,
    pub work: PathBuf,
}

impl Repo {
    /// A clone of a fresh origin whose main has one empty commit.
    pub fn new() -> R<Self> {
        let dir = tempfile::tempdir()?;
        let keys = dir.path().join("keys");
        fs::create_dir(&keys)?;
        let tag_key = keys.join("tag");
        let release_key = keys.join("release");
        let other_key = keys.join("other");
        let tag_public = keygen(&tag_key)?;
        let release_public = keygen(&release_key)?;
        keygen(&other_key)?;
        let trusted = dir.path().join("trusted_signers");
        fs::write(
            &trusted,
            format!(
                "tester namespaces=\"git\" {tag_public}\n\
                 ordin-release namespaces=\"ordin-release\" {release_public}\n"
            ),
        )?;
        let origin = dir.path().join("origin.git");
        let work = dir.path().join("work");
        let path = |p: &Path| p.to_str().map(str::to_owned).ok_or("not UTF-8");
        git(dir.path(), &["init", "--quiet", "--bare", &path(&origin)?])?;
        git(
            dir.path(),
            &["clone", "--quiet", &path(&origin)?, &path(&work)?],
        )?;
        let repo = Self {
            dir,
            tag_key,
            release_key,
            other_key,
            trusted,
            origin,
            work,
        };
        repo.commit(&[], "first")?;
        repo.push("main")?;
        Ok(repo)
    }

    /// The repository files a release needs, with the trusted signers.
    pub fn release_files(&self, version: &str) -> R<Vec<(&'static str, String)>> {
        Ok(vec![
            ("Cargo.toml", cargo_toml(version)),
            ("CHANGELOG.md", CHANGELOG.to_owned()),
            (
                "release/allowed_signers",
                fs::read_to_string(&self.trusted)?,
            ),
        ])
    }

    /// Writes `files` and commits everything, returning the commit.
    pub fn commit(&self, files: &[(&str, String)], message: &str) -> R<String> {
        for (name, text) in files {
            let path = self.work.join(name);
            fs::create_dir_all(path.parent().ok_or("no parent")?)?;
            fs::write(path, text)?;
        }
        git(&self.work, &["add", "--all"])?;
        git(
            &self.work,
            &["commit", "--quiet", "--allow-empty", "-m", message],
        )?;
        git(&self.work, &["rev-parse", "HEAD"])
    }

    pub fn push(&self, refname: &str) -> R<String> {
        git(&self.work, &["push", "--quiet", "origin", refname])
    }

    /// Signs `tag` on HEAD with `key` and pushes it.
    pub fn tag(&self, tag: &str, key: &Path) -> R<()> {
        let setting = format!("user.signingkey={}", key.display());
        let message = format!("Ordin {tag}");
        git(
            &self.work,
            &["-c", &setting, "tag", "-s", tag, "-m", &message],
        )?;
        self.push(tag)?;
        Ok(())
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

/// Writes a set of release files (archives with made-up contents and a
/// correct SHA256SUMS) to `dir`.
pub fn release_dir(dir: &Path, version: &str) -> R<()> {
    fs::create_dir_all(dir)?;
    let mut sums = BTreeMap::new();
    for name in dist::release_files(version) {
        if name == dist::SUMS {
            continue;
        }
        let path = dir.join(&name);
        fs::write(&path, format!("contents of {name}"))?;
        sums.insert(name, dist::sha256_file(&path)?);
    }
    fs::write(dir.join(dist::SUMS), dist::format_sums(&sums))?;
    Ok(())
}
