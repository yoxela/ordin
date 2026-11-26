// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Versions from git checkouts (ORD-122), against real repositories made
//! with fixed dates. The repositories are made with the git configuration
//! of nobody in particular, so whoever runs the tests can't change them.

#[cfg(test)]
mod git {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use ordin_pack::git::{GitError, GitVersion, version};
    use tempfile::TempDir;

    /// 2026-11-13 01:30 at +05:00, which is 2026-11-12 in UTC.
    const EARLY: &str = "2026-11-13T01:30:00+05:00";
    /// 2026-11-14 12:00 UTC.
    const LATE: &str = "2026-11-14T12:00:00+00:00";

    /// Runs git in `dir` as nobody in particular, at `date`, and returns
    /// what it printed.
    fn run(dir: &Path, args: &[&str], date: &str) -> String {
        let output = Command::new("git")
            .current_dir(dir)
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_DATE", date)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    /// A new repository, outside any other.
    fn repo(extra: &[&str]) -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut args = vec!["init", "-q"];
        args.extend(extra);
        run(dir.path(), &args, EARLY);
        dir
    }

    /// Commits a change to `file`, at `date`.
    fn commit(dir: &Path, file: &str, date: &str) -> String {
        let path = dir.join(file);
        let mut text = fs::read_to_string(&path).unwrap_or_default();
        text.push_str("x\n");
        fs::write(&path, text).unwrap();
        run(dir, &["add", file], date);
        run(dir, &["commit", "-q", "-m", "change"], date);
        run(dir, &["rev-parse", "HEAD"], date)
    }

    fn expect(dir: &Path, upstream: &str, commit: &str) {
        assert_eq!(
            version(dir).unwrap(),
            GitVersion {
                upstream: upstream.to_owned(),
                commit: commit.to_owned(),
            }
        );
    }

    #[test]
    fn without_tags_a_snapshot_starts_from_zero() {
        let r = repo(&[]);
        commit(r.path(), "a", EARLY);
        commit(r.path(), "a", EARLY);
        let head = commit(r.path(), "a", EARLY);
        // The date is the commit's, in UTC; the count is every commit.
        expect(r.path(), &format!("0^20261112.3.g{}", &head[..7]), &head);
    }

    #[test]
    fn after_a_tag_a_snapshot_counts_the_commits_since_it() {
        let r = repo(&[]);
        commit(r.path(), "a", EARLY);
        run(r.path(), &["tag", "v1.4.2"], EARLY);
        commit(r.path(), "a", EARLY);
        let head = commit(r.path(), "a", LATE);
        // The date is the latest commit's.
        expect(
            r.path(),
            &format!("1.4.2^20261114.2.g{}", &head[..7]),
            &head,
        );
        // An annotated tag nearer to the commit, without a `v`, wins.
        let tagged = commit(r.path(), "a", LATE);
        run(r.path(), &["tag", "-a", "-m", "release", "1.5"], LATE);
        expect(r.path(), "1.5", &tagged);
        let head = commit(r.path(), "a", LATE);
        expect(r.path(), &format!("1.5^20261114.1.g{}", &head[..7]), &head);
    }

    #[test]
    fn at_a_tag_the_version_is_the_tags() {
        let r = repo(&[]);
        commit(r.path(), "a", EARLY);
        let head = commit(r.path(), "a", EARLY);
        run(r.path(), &["tag", "v2.0"], EARLY);
        expect(r.path(), "2.0", &head);
    }

    #[test]
    fn tags_that_dont_look_like_versions_are_passed_over() {
        let r = repo(&[]);
        commit(r.path(), "a", EARLY);
        run(r.path(), &["tag", "v1.0"], EARLY);
        let head = commit(r.path(), "a", EARLY);
        run(r.path(), &["tag", "nightly"], EARLY);
        run(r.path(), &["tag", "vnext"], EARLY);
        expect(r.path(), &format!("1.0^20261112.1.g{}", &head[..7]), &head);
    }

    #[test]
    fn a_tag_that_isnt_a_valid_version_is_refused() {
        let r = repo(&[]);
        commit(r.path(), "a", EARLY);
        run(r.path(), &["tag", "1.0_beta!"], EARLY);
        // At the tag, and after it.
        for _ in 0..2 {
            match version(r.path()) {
                Err(GitError::BadTag { tag, why }) => {
                    assert_eq!(tag, "1.0_beta!");
                    assert!(why.contains("can't contain '_'"), "{why}");
                }
                other => panic!("{other:?}"),
            }
            commit(r.path(), "a", EARLY);
        }
    }

    #[test]
    fn changed_tracked_files_are_refused_but_untracked_ones_are_not() {
        let r = repo(&[]);
        let head = commit(r.path(), "a", EARLY);
        // An untracked install root doesn't count.
        fs::create_dir_all(r.path().join("root/usr/bin")).unwrap();
        fs::write(r.path().join("root/usr/bin/x"), b"x").unwrap();
        expect(r.path(), &format!("0^20261112.1.g{}", &head[..7]), &head);
        // A changed tracked file does.
        fs::write(r.path().join("a"), b"changed\n").unwrap();
        let dirty = |r: &TempDir| match version(r.path()) {
            Err(GitError::Dirty { commit }) => commit,
            other => panic!("{other:?}"),
        };
        assert_eq!(dirty(&r), head);
        assert!(
            version(r.path())
                .unwrap_err()
                .to_string()
                .contains("commit or stash them")
        );
        // So does a new file that is staged.
        run(r.path(), &["checkout", "-q", "a"], EARLY);
        fs::write(r.path().join("new"), b"new\n").unwrap();
        run(r.path(), &["add", "new"], EARLY);
        assert_eq!(dirty(&r), head);
    }

    #[test]
    fn a_shallow_clone_is_refused() {
        let r = repo(&[]);
        commit(r.path(), "a", EARLY);
        commit(r.path(), "a", EARLY);
        let clone = tempfile::tempdir().unwrap();
        let from = format!("file://{}", r.path().display());
        run(
            clone.path(),
            &["clone", "-q", "--depth", "1", &from, "c"],
            EARLY,
        );
        let e = version(&clone.path().join("c")).unwrap_err();
        assert!(matches!(e, GitError::Shallow), "{e}");
        assert!(e.to_string().contains("fetch-depth: 0"), "{e}");
    }

    #[test]
    fn outside_a_repository_or_before_a_commit_git_says_why() {
        let none = tempfile::tempdir().unwrap();
        match version(none.path()) {
            Err(GitError::Failed { command, stderr }) => {
                assert_eq!(command, "rev-parse --is-shallow-repository");
                assert!(stderr.contains("not a git repository"), "{stderr}");
            }
            other => panic!("{other:?}"),
        }
        let empty = repo(&[]);
        match version(empty.path()) {
            Err(GitError::Failed { command, stderr }) => {
                assert_eq!(command, "rev-parse HEAD");
                assert!(!stderr.is_empty());
            }
            other => panic!("{other:?}"),
        }
        let e = version(empty.path()).unwrap_err().to_string();
        assert!(e.starts_with("git rev-parse HEAD failed: "), "{e}");
    }

    #[test]
    fn a_sha256_repository_records_its_longer_commit() {
        let r = repo(&["--object-format=sha256"]);
        let head = commit(r.path(), "a", EARLY);
        assert_eq!(head.len(), 64);
        expect(r.path(), &format!("0^20261112.1.g{}", &head[..7]), &head);
    }
}
