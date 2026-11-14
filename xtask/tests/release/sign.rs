// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `release-sign` end to end: a real repository, real tag and file
//! signatures, and a fake GitHub.

use std::fs;
use std::path::Path;
use std::process::Command;

use xtask::release::sign::{Options, Outcome, run};
use xtask::release::{Error, dist};

use crate::fake::{Fake, copy_dir, fail, names};
use crate::repo::{R, Repo, git, release_dir};

struct Setup {
    repo: Repo,
    fake: Fake,
    opts: Options,
}

impl Setup {
    /// A tag `tag` on main, signed by the trusted tag key, for a workspace
    /// at `version`, with a draft whose rebuild matches.
    fn new(tag: &str, version: &str) -> R<Self> {
        Self::with_repo(tagged_repo(tag, version)?, tag, version)
    }

    fn with_repo(repo: Repo, tag: &str, version: &str) -> R<Self> {
        let server = repo.path("server");
        release_dir(&server, version)?;
        let rebuild = repo.path("rebuild");
        copy_dir(&server, &rebuild)?;
        let work_parent = repo.path("release-work");
        fs::create_dir(&work_parent)?;
        let opts = Options {
            tag: tag.to_owned(),
            allowed_signers: repo.trusted.clone(),
            key: repo.release_key.clone(),
            repository: repo.origin.display().to_string(),
            slug: "test/ordin".into(),
            work_parent,
        };
        let fake = Fake::new(server, rebuild, tag);
        Ok(Self { repo, fake, opts })
    }

    fn run(&self, answer: &str) -> (Result<Outcome, Error>, String) {
        let mut log = Vec::new();
        let result = run(&self.fake, &self.opts, &mut answer.as_bytes(), &mut log);
        (result, String::from_utf8_lossy(&log).into_owned())
    }

    fn work_dirs(&self) -> R<usize> {
        Ok(fs::read_dir(&self.opts.work_parent)?.count())
    }

    fn uploaded(&self) -> bool {
        self.fake.called("gh", &["release", "upload"])
    }

    fn published(&self) -> bool {
        self.fake.called("gh", &["release", "edit"])
    }

    /// Runs, expecting an error containing `message`, nothing published
    /// and the work directory kept.
    fn fails_with(&self, message: &str) -> R<()> {
        let (result, log) = self.run("y\n");
        let e = match result {
            Ok(outcome) => return Err(format!("expected an error, got {outcome:?}\n{log}").into()),
            Err(e) => e.to_string(),
        };
        assert!(
            e.contains(message),
            "expected {message:?} in: {e}\nlog:\n{log}"
        );
        assert!(!self.published(), "published despite: {e}");
        assert_eq!(self.work_dirs()?, 1);
        assert!(log.contains("the work directory is kept at"), "{log}");
        Ok(())
    }
}

/// A repository whose main holds a release of `version`, tagged `tag` by
/// the trusted tag key.
fn tagged_repo(tag: &str, version: &str) -> R<Repo> {
    let repo = Repo::new()?;
    repo.commit(&repo.release_files(version)?, "release")?;
    repo.push("main")?;
    repo.tag(tag, &repo.tag_key)?;
    Ok(repo)
}

/// Whether `<file>.sig` verifies as a release signature on `file`.
fn verifies(signers: &Path, file: &Path) -> R<bool> {
    let mut sig = file.as_os_str().to_owned();
    sig.push(".sig");
    Ok(Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(signers)
        .args(["-I", "ordin-release", "-n", "ordin-release", "-s"])
        .arg(sig)
        .stdin(fs::File::open(file)?)
        .output()?
        .status
        .success())
}

#[test]
fn a_matching_draft_is_signed_uploaded_and_published() {
    let s = Setup::new("v0.1.0", "0.1.0").unwrap();
    let (result, log) = s.run("yes\n");
    assert_eq!(result, Ok(Outcome::Published), "{log}");
    for name in dist::release_files("0.1.0") {
        assert!(
            verifies(&s.repo.trusted, &s.fake.server.join(&name)).unwrap(),
            "{name}"
        );
    }
    assert!(!*s.fake.draft.borrow());
    assert_eq!(s.work_dirs().unwrap(), 0, "the work directory is removed");
    assert!(log.contains("signed by tester"), "{log}");
    assert!(
        log.contains("the rebuild matches the draft byte for byte"),
        "{log}"
    );
    assert!(
        log.contains("Upload the 5 signatures and publish v0.1.0? [y/N]"),
        "{log}"
    );
    assert!(log.contains("published v0.1.0"), "{log}");

    let commit = git(&s.repo.work, &["rev-parse", "HEAD"]).unwrap();
    let attestations = s
        .fake
        .calls_to("gh")
        .into_iter()
        .filter(|a| a[0] == "attestation")
        .collect::<Vec<_>>();
    assert_eq!(attestations.len(), 5);
    assert_eq!(
        attestations[0][3..],
        [
            "--repo",
            "test/ordin",
            "--signer-workflow",
            "test/ordin/.github/workflows/release.yml",
            "--source-ref",
            "refs/tags/v0.1.0",
            "--source-digest",
            commit.as_str(),
            "--deny-self-hosted-runners",
        ]
    );
    // The digest of every file appears in the summary.
    for name in dist::release_files("0.1.0") {
        let digest = dist::sha256_file(&s.fake.server.join(&name)).unwrap();
        assert!(log.contains(&format!("{digest}  {name}")), "{log}");
    }
}

#[test]
fn declining_uploads_nothing() {
    let s = Setup::new("v0.1.0", "0.1.0").unwrap();
    let (result, log) = s.run("n\n");
    assert_eq!(result, Ok(Outcome::Declined), "{log}");
    assert!(!s.uploaded());
    assert!(!s.published());
    assert!(log.contains("nothing uploaded"), "{log}");
    assert_eq!(s.work_dirs().unwrap(), 0);
    assert!(
        names(&s.fake.server)
            .unwrap()
            .iter()
            .all(|n| !n.ends_with(".sig"))
    );
}

#[test]
fn a_rebuild_that_differs_signs_nothing() {
    let s = Setup::new("v0.1.0", "0.1.0").unwrap();
    let name = dist::archive_name("0.1.0", "x86_64-unknown-linux-musl");
    fs::write(s.fake.rebuild.join(&name), "something else").unwrap();
    s.fails_with("differ between").unwrap();
    assert!(!s.fake.called("ssh-keygen", &["-Y", "sign"]));
}

#[test]
fn a_tag_signed_by_an_untrusted_key_is_refused() {
    let repo = Repo::new().unwrap();
    repo.commit(&repo.release_files("0.1.0").unwrap(), "release")
        .unwrap();
    git(&repo.work, &["push", "--quiet", "origin", "main"]).unwrap();
    let other = repo.other_key.clone();
    repo.tag("v0.1.0", &other).unwrap();
    let s = Setup::with_repo(repo, "v0.1.0", "0.1.0").unwrap();
    s.fails_with("has no trusted signature").unwrap();
    assert!(!s.fake.called("gh", &[]));
}

#[test]
fn an_unsigned_tag_is_refused() {
    let repo = Repo::new().unwrap();
    repo.commit(&repo.release_files("0.1.0").unwrap(), "release")
        .unwrap();
    git(&repo.work, &["tag", "-a", "v0.1.0", "-m", "unsigned"]).unwrap();
    git(&repo.work, &["push", "--quiet", "origin", "main", "v0.1.0"]).unwrap();
    let s = Setup::with_repo(repo, "v0.1.0", "0.1.0").unwrap();
    s.fails_with("has no trusted signature").unwrap();
}

#[test]
fn a_tag_object_moved_to_another_name_is_refused() {
    let repo = tagged_repo("v0.1.0", "0.1.0").unwrap();
    let object = git(&repo.work, &["rev-parse", "refs/tags/v0.1.0"]).unwrap();
    git(&repo.work, &["update-ref", "refs/tags/v0.1.1", &object]).unwrap();
    git(&repo.work, &["push", "--quiet", "origin", "v0.1.1"]).unwrap();
    let s = Setup::with_repo(repo, "v0.1.1", "0.1.1").unwrap();
    s.fails_with("doesn't name v0.1.1").unwrap();
}

#[test]
fn a_tag_off_main_is_refused() {
    let repo = Repo::new().unwrap();
    git(&repo.work, &["checkout", "--quiet", "-b", "side"]).unwrap();
    repo.commit(&repo.release_files("0.1.0").unwrap(), "not merged")
        .unwrap();
    repo.tag("v0.1.0", &repo.tag_key).unwrap();
    let s = Setup::with_repo(repo, "v0.1.0", "0.1.0").unwrap();
    s.fails_with("isn't on main").unwrap();
}

#[test]
fn a_tag_that_does_not_match_the_workspace_version_is_refused() {
    let s = Setup::new("v0.2.0", "0.1.0").unwrap();
    s.fails_with("doesn't match the workspace version 0.1.0")
        .unwrap();
    assert!(!s.fake.called("gh", &[]));
}

#[test]
fn signers_that_changed_in_the_repository_are_refused() {
    let repo = Repo::new().unwrap();
    let mut files = repo.release_files("0.1.0").unwrap();
    files[2].1.push_str("# a new line\n");
    repo.commit(&files, "release").unwrap();
    git(&repo.work, &["push", "--quiet", "origin", "main"]).unwrap();
    repo.tag("v0.1.0", &repo.tag_key).unwrap();
    let s = Setup::with_repo(repo, "v0.1.0", "0.1.0").unwrap();
    s.fails_with("review the change and update your copy first")
        .unwrap();
}

#[test]
fn a_draft_with_unexpected_files_is_refused() {
    let s = Setup::new("v0.1.0", "0.1.0").unwrap();
    fs::write(s.fake.server.join("extra"), "x").unwrap();
    s.fails_with("expected").unwrap();
    assert!(!s.fake.called("gh", &["release", "download"]));
}

#[test]
fn a_draft_whose_sums_do_not_match_is_refused_even_if_the_rebuild_agrees() {
    let s = Setup::new("v0.1.0", "0.1.0").unwrap();
    let name = dist::archive_name("0.1.0", "aarch64-unknown-linux-gnu");
    for dir in [&s.fake.server, &s.fake.rebuild] {
        fs::write(dir.join(&name), "tampered").unwrap();
    }
    s.fails_with("doesn't match its SHA256SUMS entry").unwrap();
    assert!(!s.fake.called("bash", &[]));
}

#[test]
fn a_file_without_provenance_is_refused() {
    let mut s = Setup::new("v0.1.0", "0.1.0").unwrap();
    s.fake.hook = Box::new(|_, cmd| {
        let args = cmd.arg_strings();
        (args[0] == "attestation" && args[2].ends_with(dist::SUMS)).then(|| fail(cmd))
    });
    s.fails_with("SHA256SUMS has no valid build provenance")
        .unwrap();
    assert!(!s.fake.called("bash", &[]));
}

#[test]
fn a_signature_the_trusted_signers_do_not_accept_stops_the_release() {
    let mut s = Setup::new("v0.1.0", "0.1.0").unwrap();
    s.opts.key = s.repo.other_key.clone();
    s.fails_with("doesn't verify").unwrap();
    assert!(!s.uploaded());
}

#[test]
fn a_draft_changed_during_the_upload_is_not_published() {
    let mut s = Setup::new("v0.1.0", "0.1.0").unwrap();
    s.fake.hook = Box::new(|fake, cmd| {
        if cmd.arg_strings()[..2] == ["release", "upload"] {
            let name = dist::archive_name("0.1.0", "x86_64-unknown-linux-gnu");
            fs::write(fake.server.join(name), "swapped").unwrap();
        }
        None
    });
    s.fails_with("differ between").unwrap();
}

#[test]
fn a_draft_published_by_someone_else_meanwhile_is_left_alone() {
    let mut s = Setup::new("v0.1.0", "0.1.0").unwrap();
    s.fake.hook = Box::new(|fake, cmd| {
        if cmd.arg_strings()[..2] == ["release", "upload"] {
            *fake.draft.borrow_mut() = false;
        }
        None
    });
    s.fails_with("isn't a draft").unwrap();
}

#[test]
fn bad_trusted_signers_stop_before_anything_runs() {
    let s = Setup::new("v0.1.0", "0.1.0").unwrap();
    fs::write(&s.repo.trusted, "* namespaces=\"git\" ssh-ed25519 K\n").unwrap();
    let (result, _) = s.run("y\n");
    assert!(result.unwrap_err().to_string().contains("plain name"));
    fs::write(&s.repo.trusted, [0xff, 0xfe]).unwrap();
    let (result, _) = s.run("y\n");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("trusted allowed_signers")
    );
    fs::remove_file(&s.repo.trusted).unwrap();
    let (result, _) = s.run("y\n");
    assert!(matches!(result, Err(Error::Io { .. })));
    let mut bad_tag = Setup::new("v0.1.0", "0.1.0").unwrap();
    bad_tag.opts.tag = "0.1.0".into();
    assert!(
        bad_tag
            .run("y\n")
            .0
            .unwrap_err()
            .to_string()
            .contains("start with v")
    );
    assert!(s.fake.calls.borrow().is_empty());
    assert!(bad_tag.fake.calls.borrow().is_empty());
}

#[test]
fn a_missing_work_parent_is_an_error() {
    let mut s = Setup::new("v0.1.0", "0.1.0").unwrap();
    s.opts.work_parent = s.repo.path("missing");
    assert!(matches!(s.run("y\n").0, Err(Error::Io { .. })));
}

#[test]
fn a_clone_that_fails_stops_the_release() {
    let mut s = Setup::new("v0.1.0", "0.1.0").unwrap();
    s.opts.repository = s.repo.path("no-such-origin").display().to_string();
    s.fails_with("git clone").unwrap();
}

#[test]
fn a_failed_rebuild_stops_the_release() {
    let mut s = Setup::new("v0.1.0", "0.1.0").unwrap();
    s.fake.hook = Box::new(|_, cmd| (cmd.program == "bash").then(|| fail(cmd)));
    s.fails_with("refused by the fake").unwrap();
    assert!(!s.fake.called("ssh-keygen", &["-Y", "sign"]));
}

#[test]
fn a_signing_key_that_cannot_be_used_stops_the_release() {
    let mut s = Setup::new("v0.1.0", "0.1.0").unwrap();
    s.opts.key = s.repo.path("no-such-key");
    s.fails_with("ssh-keygen -Y sign").unwrap();
    assert!(!s.uploaded());
}

#[test]
fn a_failed_upload_is_not_published() {
    let mut s = Setup::new("v0.1.0", "0.1.0").unwrap();
    s.fake.hook =
        Box::new(|_, cmd| (cmd.arg_strings()[..2] == ["release", "upload"]).then(|| fail(cmd)));
    s.fails_with("gh release upload").unwrap();
}
