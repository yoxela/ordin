// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask pre-release`: checks that `main` is ready to tag, then
//! prints the commands that tag and push it. It changes nothing itself.

use std::fs;
use std::io::Write;
use std::path::Path;

use super::exec::{Cmd, Exec};
use super::{ALLOWED_SIGNERS, Error, checks, say, signers, version};

/// The branch releases are tagged from.
pub const BRANCH: &str = "main";

fn read(root: &Path, name: &str) -> Result<String, Error> {
    let path = root.join(name);
    fs::read_to_string(&path).map_err(|e| Error::io(&path, &e))
}

/// A GitHub API call. With a `jq` filter the call follows every page, and
/// the filter prints one JSON value per line; without one it reads a
/// single page, because gh would concatenate pages of a list into
/// separate JSON documents.
fn gh_api(exec: &dyn Exec, root: &Path, path: &str, jq: Option<&str>) -> Result<String, Error> {
    let mut cmd = Cmd::new("gh").dir(root).arg("api");
    if let Some(jq) = jq {
        cmd = cmd.args(["--paginate", "--jq", jq]);
    }
    Ok(exec.run(&cmd.arg(path))?.stdout_text())
}

fn check_runs(
    exec: &dyn Exec,
    root: &Path,
    slug: &str,
    sha: &str,
) -> Result<Vec<checks::CheckRun>, Error> {
    let lines = gh_api(
        exec,
        root,
        &format!("repos/{slug}/commits/{sha}/check-runs?per_page=100"),
        Some(".check_runs[]"),
    )?;
    checks::parse_check_runs(&lines)
}

/// Runs the checks on the repository at `root`, writing progress to `log`.
/// Returns the tag to create.
///
/// # Errors
///
/// Returns the first check that fails.
pub fn run(exec: &dyn Exec, root: &Path, log: &mut dyn Write) -> Result<String, Error> {
    let git = |args: &[&str]| -> Result<String, Error> {
        Ok(exec.run(&Cmd::git(root).args(args))?.stdout_text())
    };

    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"])?;
    if branch != BRANCH {
        return Err(Error::check(format!(
            "releases are tagged on {BRANCH}, not {branch}"
        )));
    }
    let status = git(&["status", "--porcelain", "--untracked-files=all"])?;
    if !status.is_empty() {
        return Err(Error::check(format!(
            "the working tree isn't clean:\n{status}"
        )));
    }
    let head = git(&["rev-parse", "HEAD"])?;
    let remote = git(&["ls-remote", "origin", &format!("refs/heads/{BRANCH}")])?;
    let remote_head = remote.split_whitespace().next().unwrap_or_default();
    if remote_head != head {
        return Err(Error::check(format!(
            "{BRANCH} is {head} here but {} on origin; pull or push first",
            if remote_head.is_empty() {
                "missing"
            } else {
                remote_head
            }
        )));
    }
    say(
        log,
        &format!("pre-release: {BRANCH} is clean and matches origin at {head}"),
    );

    let workspace = version::workspace(&read(root, "Cargo.toml")?)?;
    version::check_changelog(&read(root, "CHANGELOG.md")?, &workspace.version)?;
    let tag = version::tag_for(&workspace.version);
    let tag_ref = format!("refs/tags/{tag}");
    if exec
        .run(&Cmd::git(root).args(["rev-parse", "--quiet", "--verify", &tag_ref]))
        .is_ok()
    {
        return Err(Error::check(format!("the tag {tag} already exists here")));
    }
    if !git(&["ls-remote", "origin", &tag_ref])?.is_empty() {
        return Err(Error::check(format!(
            "the tag {tag} already exists on origin"
        )));
    }
    signers::load(&read(root, ALLOWED_SIGNERS)?)?;
    say(
        log,
        &format!(
            "pre-release: version {} is in Cargo.toml and CHANGELOG.md",
            workspace.version
        ),
    );

    let slug = &workspace.slug;
    let required = checks::required_checks(&gh_api(
        exec,
        root,
        &format!("repos/{slug}/rules/branches/{BRANCH}"),
        None,
    )?)?;
    let on_commit = check_runs(exec, root, slug, &head)?;
    let pulls = gh_api(
        exec,
        root,
        &format!("repos/{slug}/commits/{head}/pulls"),
        None,
    )?;
    let on_pull = match checks::merged_pull_head(&pulls)? {
        Some(sha) => check_runs(exec, root, slug, &sha)?,
        None => Vec::new(),
    };
    let problems = checks::problems(&required, &on_commit, &on_pull);
    if !problems.is_empty() {
        return Err(Error::check(format!(
            "the checks on {head} don't allow a release:\n- {}",
            problems.join("\n- ")
        )));
    }
    say(
        log,
        &format!(
            "pre-release: all {} required checks passed, and nothing on {BRANCH} failed",
            required.len()
        ),
    );
    Ok(tag)
}

/// The commands that create and push the signed tag.
#[must_use]
pub fn tag_commands(tag: &str) -> String {
    let version = tag.trim_start_matches('v');
    format!(
        "Ready. Create and push the signed tag:\n\n  \
         git tag -s {tag} -m \"Ordin {version}\"\n  \
         git push origin {tag}\n\n\
         The release workflow then builds a draft. When it has finished, run\n  \
         make release-sign TAG={tag}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tag_commands_name_the_tag() {
        let text = tag_commands("v0.1.0");
        assert!(
            text.contains("git tag -s v0.1.0 -m \"Ordin 0.1.0\""),
            "{text}"
        );
        assert!(text.contains("git push origin v0.1.0"), "{text}");
        assert!(text.contains("make release-sign TAG=v0.1.0"), "{text}");
    }
}
