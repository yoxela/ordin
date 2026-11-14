// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask release-sign <tag>`: verifies a draft release that CI built,
//! then signs, uploads and publishes it.
//!
//! 1. Clones the repository afresh and verifies the tag's signature against
//!    the maintainer's own copy of `allowed_signers`, never the
//!    repository's. The repository's copy must match it byte for byte.
//! 2. Checks the tag names itself and the workspace version, and that its
//!    commit is on `main`.
//! 3. Downloads the draft, checks its file list and `SHA256SUMS`, and
//!    verifies CI's build provenance for every file.
//! 4. Rebuilds the tag with `scripts/release/build.sh` from the clone, and
//!    requires every file to match the draft byte for byte.
//! 5. Signs every file with the release key, verifies each signature,
//!    and asks before going on.
//! 6. Uploads the signatures, downloads the whole draft again to check
//!    nothing changed, and publishes it.

use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::exec::{Cmd, Exec};
use super::{
    ALLOWED_SIGNERS, BUILD_SCRIPT, Error, FILE_NAMESPACE, FILE_PRINCIPAL, RELEASE_WORKFLOW, dist,
    say, signers, version,
};

/// What `release-sign` works on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// The tag to release.
    pub tag: String,
    /// The maintainer's trusted `allowed_signers`, kept outside the
    /// repository.
    pub allowed_signers: PathBuf,
    /// The release signing key (the private key, or its public half when
    /// the key is loaded in an agent).
    pub key: PathBuf,
    /// Where to clone the repository from.
    pub repository: String,
    /// The repository's GitHub `owner/name`.
    pub slug: String,
    /// Where to create the temporary work directory.
    pub work_parent: PathBuf,
}

/// How a run ended without an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The release is published.
    Published,
    /// The maintainer said no; nothing was uploaded.
    Declined,
}

/// The principal in git's report of a good, trusted SSH signature:
/// `Good "git" signature for <principal> with <type> key <fingerprint>`.
#[must_use]
pub fn tag_signer(report: &str) -> Option<String> {
    report.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("Good \"git\" signature for ")?;
        let (principal, _) = rest.split_once(" with ")?;
        (!principal.is_empty() && !principal.contains(' ')).then(|| principal.to_owned())
    })
}

/// The tag name recorded inside an annotated tag object (the output of
/// `git cat-file tag`), if the tag points at a commit.
#[must_use]
pub fn tag_object_name(object: &str) -> Option<String> {
    let header: Vec<&str> = object.lines().take_while(|l| !l.is_empty()).collect();
    let field = |key: &str| {
        header
            .iter()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
    };
    (field("type") == Some("commit"))
        .then(|| field("tag").map(str::to_owned))
        .flatten()
}

/// Checks a release's JSON from `gh release view --json isDraft,tagName,assets`:
/// still a draft, for `tag`, with exactly the `expected` files.
///
/// # Errors
///
/// Returns what doesn't match.
pub fn check_draft(json: &str, tag: &str, expected: &[String]) -> Result<(), Error> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error::parse("the release", e))?;
    if v.get("tagName").and_then(Value::as_str) != Some(tag) {
        return Err(Error::check(format!("the release isn't for {tag}")));
    }
    if v.get("isDraft").and_then(Value::as_bool) != Some(true) {
        return Err(Error::check(format!(
            "the release for {tag} isn't a draft; it may already be published"
        )));
    }
    let mut names: Vec<String> = v
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::parse("the release", "no assets list"))?
        .iter()
        .map(|a| a.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect::<Option<_>>()
        .ok_or_else(|| Error::parse("the release", "an asset has no name"))?;
    names.sort();
    if names != expected {
        return Err(Error::check(format!(
            "the draft for {tag} has {names:?}, expected {expected:?}"
        )));
    }
    Ok(())
}

/// Checks that two directories hold the same regular files, byte for byte.
///
/// # Errors
///
/// Returns an error naming what differs.
pub fn compare_dirs(ours: &Path, theirs: &Path) -> Result<(), Error> {
    let a = dist::regular_files(ours)?;
    let b = dist::regular_files(theirs)?;
    let names =
        |files: &[(String, PathBuf)]| files.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    if names(&a) != names(&b) {
        return Err(Error::check(format!(
            "{} has {:?} but {} has {:?}",
            ours.display(),
            names(&a),
            theirs.display(),
            names(&b)
        )));
    }
    let differ: Vec<&str> = a
        .iter()
        .zip(&b)
        .filter_map(|((name, x), (_, y))| match (fs::read(x), fs::read(y)) {
            (Ok(x), Ok(y)) if x == y => None,
            _ => Some(name.as_str()),
        })
        .collect();
    if differ.is_empty() {
        Ok(())
    } else {
        Err(Error::check(format!(
            "these files differ between {} and {}: {}",
            ours.display(),
            theirs.display(),
            differ.join(", ")
        )))
    }
}

/// Whether the answer to a yes/no question is yes. Anything else is no.
#[must_use]
pub fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    fs::read(path).map_err(|e| Error::io(path, &e))
}

/// Runs the whole flow. The work directory is removed when the run ends
/// without an error, and kept for inspection otherwise.
///
/// # Errors
///
/// Returns the first check or step that fails.
pub fn run(
    exec: &dyn Exec,
    opts: &Options,
    answer: &mut dyn BufRead,
    log: &mut dyn Write,
) -> Result<Outcome, Error> {
    let version = version::tag_version(&opts.tag)?.to_owned();
    let trusted = read_bytes(&opts.allowed_signers)?;
    let trusted_text = String::from_utf8(trusted.clone())
        .map_err(|e| Error::parse("the trusted allowed_signers", e))?;
    signers::load(&trusted_text)?;
    let work = tempfile::Builder::new()
        .prefix("ordin-release-")
        .tempdir_in(&opts.work_parent)
        .map_err(|e| Error::io(&opts.work_parent, &e))?;
    let result = steps(exec, opts, &version, &trusted, work.path(), answer, log);
    if result.is_err() {
        let kept = work.keep();
        say(
            log,
            &format!(
                "release-sign: the work directory is kept at {}",
                kept.display()
            ),
        );
    }
    result
}

fn steps(
    exec: &dyn Exec,
    opts: &Options,
    version: &str,
    trusted: &[u8],
    work: &Path,
    answer: &mut dyn BufRead,
    log: &mut dyn Write,
) -> Result<Outcome, Error> {
    let tag = opts.tag.as_str();
    let slug = opts.slug.as_str();
    let src = work.join("src");
    let git = |args: &[&str]| exec.run(&Cmd::git(&src).args(args));

    // 1. The tag, verified against the trusted signers.
    say(log, &format!("release-sign: cloning {}", opts.repository));
    exec.run(
        &Cmd::git(work)
            .args(["clone", "--quiet", "--", &opts.repository])
            .arg(&src),
    )?;
    let signers_setting = format!(
        "gpg.ssh.allowedSignersFile={}",
        opts.allowed_signers.display()
    );
    let report = git(&[
        "-c",
        &signers_setting,
        "-c",
        "gpg.minTrustLevel=fully",
        "verify-tag",
        "--",
        tag,
    ])
    .map_err(|e| Error::check(format!("the tag {tag} has no trusted signature: {e}")))?;
    let signer = tag_signer(&report.stderr_text())
        .ok_or_else(|| Error::check(format!("git verified {tag} but named no trusted signer")))?;
    let object = git(&["cat-file", "tag", tag])?.stdout_text();
    if tag_object_name(&object).as_deref() != Some(tag) {
        return Err(Error::check(format!(
            "the tag object at {tag} doesn't name {tag} and a commit"
        )));
    }
    let commit = git(&["rev-parse", "--verify", &format!("{tag}^{{commit}}")])?.stdout_text();
    git(&["merge-base", "--is-ancestor", &commit, "origin/main"])
        .map_err(|_| Error::check(format!("{tag} ({commit}) isn't on main")))?;
    git(&["checkout", "--quiet", "--detach", tag])?;
    if read_bytes(&src.join(ALLOWED_SIGNERS))? != trusted {
        return Err(Error::check(format!(
            "{ALLOWED_SIGNERS} at {tag} differs from {}; review the change and update your copy first",
            opts.allowed_signers.display()
        )));
    }
    let cargo_toml = String::from_utf8(read_bytes(&src.join("Cargo.toml"))?)
        .map_err(|e| Error::parse("Cargo.toml", e))?;
    version::check_tag(tag, &version::workspace(&cargo_toml)?.version)?;
    say(
        log,
        &format!("release-sign: {tag} is {commit} on main, signed by {signer}"),
    );

    // 2. The draft, with CI's provenance.
    let expected = dist::release_files(version);
    let view = || -> Result<String, Error> {
        Ok(exec
            .run(&Cmd::new("gh").args([
                "release",
                "view",
                tag,
                "--repo",
                slug,
                "--json",
                "isDraft,tagName,assets",
            ]))?
            .stdout_text())
    };
    check_draft(&view()?, tag, &expected)?;
    let draft = work.join("draft");
    let download = |dir: &Path| {
        exec.run(
            &Cmd::new("gh")
                .args(["release", "download", tag, "--repo", slug, "--dir"])
                .arg(dir),
        )
    };
    download(&draft)?;
    dist::check_sums(&draft)?;
    let workflow = format!("{slug}/{RELEASE_WORKFLOW}");
    let source_ref = format!("refs/tags/{tag}");
    for name in &expected {
        exec.run(
            &Cmd::new("gh")
                .args(["attestation", "verify"])
                .arg(draft.join(name))
                .args([
                    "--repo",
                    slug,
                    "--signer-workflow",
                    &workflow,
                    "--source-ref",
                    &source_ref,
                    "--source-digest",
                    &commit,
                    "--deny-self-hosted-runners",
                ]),
        )
        .map_err(|e| {
            Error::check(format!(
                "{name} has no valid build provenance from {workflow}: {e}"
            ))
        })?;
    }
    say(
        log,
        &format!(
            "release-sign: the draft has {} files with CI provenance",
            expected.len()
        ),
    );

    // 3. The rebuild.
    let build = work.join("build");
    say(
        log,
        "release-sign: rebuilding the tag in the pinned container",
    );
    exec.run(
        &Cmd::new("bash")
            .arg(src.join(BUILD_SCRIPT))
            .arg(&src)
            .arg(&build)
            .arg(tag)
            .interactive(),
    )?;
    compare_dirs(&build.join("dist"), &draft)?;
    say(
        log,
        "release-sign: the rebuild matches the draft byte for byte",
    );

    // 4. Signatures, verified.
    let mut signatures = Vec::new();
    for name in &expected {
        let file = draft.join(name);
        exec.run(
            &Cmd::new("ssh-keygen")
                .args(["-Y", "sign", "-n", FILE_NAMESPACE, "-f"])
                .arg(&opts.key)
                .arg(&file)
                .interactive(),
        )?;
        let sig = draft.join(format!("{name}.sig"));
        exec.run(
            &Cmd::new("ssh-keygen")
                .args(["-Y", "verify", "-f"])
                .arg(&opts.allowed_signers)
                .args(["-I", FILE_PRINCIPAL, "-n", FILE_NAMESPACE, "-s"])
                .arg(&sig)
                .stdin(&file),
        )
        .map_err(|e| Error::check(format!("the signature on {name} doesn't verify: {e}")))?;
        signatures.push(sig);
    }

    // 5. The maintainer decides.
    say(
        log,
        &format!("\nRelease {tag}: commit {commit}, tag signed by {signer}"),
    );
    for name in &expected {
        say(
            log,
            &format!("  {}  {name}", dist::sha256_file(&draft.join(name))?),
        );
    }
    let _ = write!(
        log,
        "Upload the {} signatures and publish {tag}? [y/N] ",
        signatures.len()
    );
    let _ = log.flush();
    let mut line = String::new();
    answer
        .read_line(&mut line)
        .map_err(|e| Error::io(Path::new("stdin"), &e))?;
    if !is_yes(&line) {
        say(log, "release-sign: nothing uploaded");
        return Ok(Outcome::Declined);
    }

    // 6. Upload, check nothing else changed, publish.
    exec.run(
        &Cmd::new("gh")
            .args(["release", "upload", tag, "--repo", slug])
            .args(&signatures),
    )?;
    let mut with_signatures = expected.clone();
    with_signatures.extend(expected.iter().map(|n| format!("{n}.sig")));
    with_signatures.sort();
    check_draft(&view()?, tag, &with_signatures)?;
    let uploaded = work.join("uploaded");
    download(&uploaded)?;
    compare_dirs(&uploaded, &draft)?;
    exec.run(&Cmd::new("gh").args(["release", "edit", tag, "--repo", slug, "--draft=false"]))?;
    say(log, &format!("release-sign: published {tag}"));
    Ok(Outcome::Published)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tag_signer_comes_from_a_good_trusted_signature() {
        let good = "Good \"git\" signature for barraterre with ED25519 key SHA256:abc\n";
        assert_eq!(tag_signer(good).as_deref(), Some("barraterre"));
        assert_eq!(
            tag_signer(&format!("noise\n  {good}")).as_deref(),
            Some("barraterre")
        );
        for bad in [
            "Good \"git\" signature with ED25519 key SHA256:abc\nNo principal matched.",
            "Good \"git\" signature for  with ED25519 key",
            "Good \"git\" signature for a b with ED25519 key",
            "Good \"git\" signature for barraterre",
            "Bad \"git\" signature for barraterre with ED25519 key",
            "",
        ] {
            assert_eq!(tag_signer(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_tag_object_names_itself_and_a_commit() {
        let object = "object abc\ntype commit\ntag v0.1.0\ntagger x <x> 1 +0000\n\nOrdin 0.1.0\ntag v9.9.9\n";
        assert_eq!(tag_object_name(object).as_deref(), Some("v0.1.0"));
        assert_eq!(
            tag_object_name(&object.replace("type commit", "type tree")),
            None
        );
        assert_eq!(
            tag_object_name("object abc\ntype commit\n\ntag v1.0.0\n"),
            None
        );
        assert_eq!(tag_object_name("type commit\ntagv0.1.0\n"), None);
    }

    fn assets(names: &[&str]) -> String {
        names
            .iter()
            .map(|n| format!("{{\"name\":\"{n}\"}}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    #[test]
    fn a_draft_must_be_for_the_tag_and_have_exactly_the_files() {
        let expected = vec!["SHA256SUMS".to_owned(), "a.tar.gz".to_owned()];
        let json = |draft: bool, tag: &str, names: &[&str]| {
            format!(
                "{{\"isDraft\":{draft},\"tagName\":\"{tag}\",\"assets\":[{}]}}",
                assets(names)
            )
        };
        assert_eq!(
            check_draft(
                &json(true, "v1.0.0", &["a.tar.gz", "SHA256SUMS"]),
                "v1.0.0",
                &expected
            ),
            Ok(())
        );
        let e = check_draft(
            &json(false, "v1.0.0", &["a.tar.gz", "SHA256SUMS"]),
            "v1.0.0",
            &expected,
        )
        .unwrap_err();
        assert!(e.to_string().contains("isn't a draft"), "{e}");
        let e = check_draft(
            &json(true, "v2.0.0", &["a.tar.gz", "SHA256SUMS"]),
            "v1.0.0",
            &expected,
        )
        .unwrap_err();
        assert!(e.to_string().contains("isn't for v1.0.0"), "{e}");
        let e = check_draft(&json(true, "v1.0.0", &["a.tar.gz"]), "v1.0.0", &expected).unwrap_err();
        assert!(e.to_string().contains("expected"), "{e}");
        let extra = json(true, "v1.0.0", &["a.tar.gz", "SHA256SUMS", "evil"]);
        assert!(check_draft(&extra, "v1.0.0", &expected).is_err());
        assert!(
            check_draft(
                "{\"isDraft\":true,\"tagName\":\"v1.0.0\"}",
                "v1.0.0",
                &expected
            )
            .is_err()
        );
        assert!(
            check_draft(
                "{\"isDraft\":true,\"tagName\":\"v1.0.0\",\"assets\":[{}]}",
                "v1.0.0",
                &expected
            )
            .is_err()
        );
        assert!(check_draft("nope", "v1.0.0", &expected).is_err());
    }

    #[test]
    fn directories_compare_by_names_and_bytes() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        for d in [&a, &b] {
            fs::write(d.path().join("x"), "same").unwrap();
        }
        assert_eq!(compare_dirs(a.path(), b.path()), Ok(()));
        fs::write(b.path().join("y"), "extra").unwrap();
        assert!(
            compare_dirs(a.path(), b.path())
                .unwrap_err()
                .to_string()
                .contains("has [\"x\"]")
        );
        fs::write(a.path().join("y"), "EXTRA").unwrap();
        let e = compare_dirs(a.path(), b.path()).unwrap_err().to_string();
        assert!(
            e.starts_with("these files differ between ") && e.ends_with(": y"),
            "{e}"
        );
        assert!(compare_dirs(&a.path().join("missing"), b.path()).is_err());
        assert!(compare_dirs(a.path(), &b.path().join("missing")).is_err());
    }

    #[test]
    fn only_yes_is_yes() {
        for yes in ["y", "Y", "yes", "YES", " yes\n"] {
            assert!(is_yes(yes), "{yes:?}");
        }
        for no in ["", "n", "no", "yess", "ye", "y es", "\n"] {
            assert!(!is_yes(no), "{no:?}");
        }
    }
}
