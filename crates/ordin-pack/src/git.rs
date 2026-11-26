// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Versions from a git checkout (ORD-122).
//!
//! A snapshot build is versioned from the nearest release tag, the commit
//! date and the number of commits since the tag: `1.4.2^20261112.37.g3fa9c1e`,
//! or `0^…` for a project with no tags, and just the tag's version for the
//! tagged commit itself. The hash is only there to read; the full commit is
//! recorded in the manifest's provenance.
//!
//! The `git` program is run with read-only commands only, with the
//! file-system monitor off, replace refs ignored, no pager, no prompt,
//! no optional locks and the C locale, and every output is parsed
//! strictly. A checkout whose tracked files differ from its commit is
//! refused, since the version would describe something else; untracked
//! files, such as the install root, don't count. A shallow clone is
//! refused, since it can't count the commits since the tag.

use std::path::Path;
use std::process::{Command, Output, Stdio};

use ordin_version::{Position, Version, snapshot};

/// The most of git's error output kept in an error, in characters.
const MAX_STDERR: usize = 500;

/// How many hex digits of the commit a snapshot version shows. Fixed,
/// unlike git's own abbreviation, which grows with the repository.
pub const SHORT_HASH: usize = 7;

/// A version made from a git checkout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitVersion {
    /// The upstream version.
    pub upstream: String,
    /// The commit's full object name.
    pub commit: String,
}

/// Why a version couldn't be made from a git checkout.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GitError {
    /// The `git` program couldn't be run.
    #[error("can't run git: {0}")]
    Run(std::io::Error),
    /// A git command failed.
    #[error("git {command} failed: {stderr}")]
    Failed {
        /// The command.
        command: &'static str,
        /// What git said, cut short.
        stderr: String,
    },
    /// A git command printed something this doesn't understand.
    #[error("git {command} printed {output:?}, which isn't what was expected")]
    Unexpected {
        /// The command.
        command: &'static str,
        /// What it printed.
        output: String,
    },
    /// The checkout is a shallow clone.
    #[error(
        "this is a shallow clone, so the commits since the tag can't be counted; \
         fetch the whole history (git fetch --unshallow, or fetch-depth: 0 in GitHub Actions)"
    )]
    Shallow,
    /// Tracked files differ from the commit.
    #[error(
        "tracked files differ from the commit {commit}; commit or stash them, so the \
         version describes what is packed"
    )]
    Dirty {
        /// The commit checked out.
        commit: String,
    },
    /// The nearest tag isn't a version.
    #[error("the tag {tag} isn't a version: {why}")]
    BadTag {
        /// The tag.
        tag: String,
        /// Why.
        why: String,
    },
    /// The snapshot version can't be made.
    #[error("{0}")]
    Snapshot(ordin_version::Error),
}

/// Runs `git` in `dir`, read-only and without anything the repository's
/// configuration could start.
fn run_git(dir: &Path, args: &[&str]) -> Result<Output, GitError> {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "--no-pager",
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(args)
        .env("LC_ALL", "C")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .map_err(GitError::Run)
}

/// What git said on standard error, as one line, cut short.
fn said(output: &Output) -> String {
    let text = String::from_utf8_lossy(&output.stderr);
    let line = text.trim().replace('\n', "; ");
    line.chars().take(MAX_STDERR).collect()
}

/// A way to run git: the arguments in, what it did out.
trait Git: FnMut(&[&str]) -> Result<Output, GitError> {}

impl<F: FnMut(&[&str]) -> Result<Output, GitError>> Git for F {}

/// Runs a git command that must succeed and print one line.
fn line(git: &mut impl Git, command: &'static str, args: &[&str]) -> Result<String, GitError> {
    let output = git(args)?;
    if !output.status.success() {
        return Err(GitError::Failed {
            command,
            stderr: said(&output),
        });
    }
    let text = String::from_utf8(output.stdout).map_err(|e| GitError::Unexpected {
        command,
        output: String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })?;
    match text.strip_suffix('\n') {
        Some(one) if !one.contains('\n') => Ok(one.to_owned()),
        _ => Err(GitError::Unexpected {
            command,
            output: text,
        }),
    }
}

/// Lowercase hex digits only.
fn is_hex(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A full commit object name: 40 hex digits (SHA-1) or 64 (SHA-256).
fn is_commit(text: &str) -> bool {
    matches!(text.len(), 40 | 64) && is_hex(text)
}

/// `git describe --long --always`'s output: the tag and the commits
/// since it, or `None` if no tag was found and git printed the hash
/// alone. Tags can contain `-`, so it is read from the end.
fn parse_describe(text: &str) -> Option<Option<(&str, u32)>> {
    if let Some((rest, hash)) = text.rsplit_once("-g") {
        let (tag, count) = rest.rsplit_once('-')?;
        // Parsing alone would take a leading '+'.
        let digits = count.bytes().all(|b| b.is_ascii_digit());
        if tag.is_empty() || !digits || !is_hex(hash) {
            return None;
        }
        return Some(Some((tag, count.parse().ok()?)));
    }
    is_hex(text).then_some(None)
}

/// The committer's time from a raw commit object: seconds since 1970.
fn committer_time(commit: &str) -> Option<i64> {
    let header = commit.split("\n\n").next()?;
    let line = header.lines().find_map(|l| l.strip_prefix("committer "))?;
    let mut fields = line.rsplit(' ');
    let _zone = fields.next()?;
    fields.next()?.parse().ok()
}

/// The date in UTC of `seconds` since 1970, as `YYYYMMDD`.
fn utc_date(seconds: i64) -> String {
    // Howard Hinnant's days-to-civil algorithm.
    let days = seconds.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}")
}

/// The release a tag names: the tag, without a `v` before a digit.
fn tag_version(tag: &str) -> &str {
    match tag.strip_prefix('v') {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => tag,
    }
}

/// Makes the upstream version of the checkout at `dir` and finds its
/// commit.
///
/// # Errors
///
/// `git` can't be run or fails, for example because `dir` isn't in a
/// repository or the repository has no commits; the checkout is a shallow
/// clone or its tracked files differ from its commit; the nearest version
/// tag isn't a valid version; or git prints something unexpected.
pub fn version(dir: &Path) -> Result<GitVersion, GitError> {
    version_with(&mut |args: &[&str]| run_git(dir, args))
}

/// [`version`], with `git` running each command.
fn version_with(git: &mut impl Git) -> Result<GitVersion, GitError> {
    let shallow = "rev-parse --is-shallow-repository";
    match line(git, shallow, &["rev-parse", "--is-shallow-repository"])?.as_str() {
        "false" => {}
        "true" => return Err(GitError::Shallow),
        other => {
            return Err(GitError::Unexpected {
                command: shallow,
                output: other.to_owned(),
            });
        }
    }
    let head = "rev-parse HEAD";
    let commit = line(
        git,
        head,
        &["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"],
    )?;
    if !is_commit(&commit) {
        return Err(GitError::Unexpected {
            command: head,
            output: commit,
        });
    }
    let diff = git(&[
        "diff",
        "--quiet",
        "--no-ext-diff",
        "--no-textconv",
        "HEAD",
        "--",
    ])?;
    match diff.status.code() {
        Some(0) => {}
        Some(1) => return Err(GitError::Dirty { commit }),
        _ => {
            return Err(GitError::Failed {
                command: "diff",
                stderr: said(&diff),
            });
        }
    }
    let describe = "describe";
    let described = line(
        git,
        describe,
        &[
            "describe",
            "--tags",
            "--long",
            "--always",
            "--abbrev=40",
            "--match",
            "v[0-9]*",
            "--match",
            "[0-9]*",
            "HEAD",
        ],
    )?;
    let Some(nearest) = parse_describe(&described) else {
        return Err(GitError::Unexpected {
            command: describe,
            output: described,
        });
    };
    if let Some((tag, 0)) = nearest {
        let base = tag_version(tag);
        return Version::new(0, base, None, 0)
            .map(|_| GitVersion {
                upstream: base.to_owned(),
                commit,
            })
            .map_err(|e| GitError::BadTag {
                tag: tag.to_owned(),
                why: e.to_string(),
            });
    }
    let (base, count) = match nearest {
        Some((tag, count)) => {
            let base = tag_version(tag);
            if let Err(e) = Version::new(0, base, None, 0) {
                return Err(GitError::BadTag {
                    tag: tag.to_owned(),
                    why: e.to_string(),
                });
            }
            (Some(base), count)
        }
        None => {
            let count = "rev-list --count";
            let text = line(git, count, &["rev-list", "--count", "HEAD"])?;
            let n = text.parse().map_err(|_| GitError::Unexpected {
                command: count,
                output: text.clone(),
            })?;
            (None, n)
        }
    };
    let cat = "cat-file commit";
    let raw = git(&["cat-file", "commit", &commit])?;
    if !raw.status.success() {
        return Err(GitError::Failed {
            command: cat,
            stderr: said(&raw),
        });
    }
    let object = String::from_utf8_lossy(&raw.stdout);
    let Some(time) = committer_time(&object) else {
        return Err(GitError::Unexpected {
            command: cat,
            output: object.chars().take(MAX_STDERR).collect(),
        });
    };
    let short = commit.get(..SHORT_HASH).unwrap_or(&commit);
    let upstream = snapshot(base, Position::After, &utc_date(time), count, short)
        .map_err(GitError::Snapshot)?;
    Ok(GitVersion { upstream, commit })
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use super::*;

    const HEAD: &str = "3fa9c1e5d8b2a7f40c6e1d9b8a7f6e5d4c3b2a19";

    /// What a git command did: its exit code and output.
    fn did(code: i32, stdout: &[u8], stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    /// The command a call is, by its first two arguments.
    fn key(args: &[&str]) -> String {
        args.iter().take(2).copied().collect::<Vec<_>>().join(" ")
    }

    /// A git that answers each command as a clean checkout two commits
    /// after `v1.0` would, except for the answers in `changed`.
    fn fake(changed: Vec<(&'static str, Output)>) -> impl Git {
        let commit = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                      committer C <c@example.invalid> 1794441600 +0000\n\nmessage\n";
        let mut answers = [
            ("rev-parse --is-shallow-repository", did(0, b"false\n", "")),
            (
                "rev-parse --verify",
                did(0, format!("{HEAD}\n").as_bytes(), ""),
            ),
            ("diff --quiet", did(0, b"", "")),
            (
                "describe --tags",
                did(0, format!("v1.0-2-g{HEAD}\n").as_bytes(), ""),
            ),
            ("rev-list --count", did(0, b"5\n", "")),
            ("cat-file commit", did(0, commit.as_bytes(), "")),
        ];
        for (k, output) in changed {
            if let Some(a) = answers.iter_mut().find(|(have, _)| *have == k) {
                a.1 = output;
            }
        }
        move |args: &[&str]| {
            let k = key(args);
            Ok(answers
                .iter()
                .find(|(have, _)| *have == k)
                .unwrap_or_else(|| panic!("unexpected git {args:?}"))
                .1
                .clone())
        }
    }

    fn run(changed: Vec<(&'static str, Output)>) -> Result<GitVersion, GitError> {
        version_with(&mut fake(changed))
    }

    #[test]
    fn a_clean_checkout_after_a_tag_gives_a_snapshot() {
        assert_eq!(
            run(vec![]).unwrap(),
            GitVersion {
                upstream: "1.0^20261112.2.g3fa9c1e".to_owned(),
                commit: HEAD.to_owned(),
            }
        );
        // Without a tag, the commits are counted from the start.
        let untagged = did(0, format!("{HEAD}\n").as_bytes(), "");
        assert_eq!(
            run(vec![("describe --tags", untagged)]).unwrap().upstream,
            "0^20261112.5.g3fa9c1e"
        );
    }

    #[test]
    fn unexpected_answers_name_the_command() {
        let unexpected = |changed, expected: &str| match run(changed) {
            Err(GitError::Unexpected { command, .. }) => assert_eq!(command, expected),
            other => panic!("{expected}: {other:?}"),
        };
        unexpected(
            vec![("rev-parse --is-shallow-repository", did(0, b"maybe\n", ""))],
            "rev-parse --is-shallow-repository",
        );
        unexpected(
            vec![("rev-parse --verify", did(0, b"HEAD\n", ""))],
            "rev-parse HEAD",
        );
        // Two lines, no line at all, and bytes that aren't UTF-8.
        let two = format!("{HEAD}\n{HEAD}\n");
        unexpected(
            vec![("rev-parse --verify", did(0, two.as_bytes(), ""))],
            "rev-parse HEAD",
        );
        unexpected(
            vec![("rev-parse --verify", did(0, HEAD.as_bytes(), ""))],
            "rev-parse HEAD",
        );
        unexpected(
            vec![("rev-parse --verify", did(0, b"\xff\n", ""))],
            "rev-parse HEAD",
        );
        unexpected(
            vec![("describe --tags", did(0, b"not a description\n", ""))],
            "describe",
        );
        unexpected(
            vec![
                (
                    "describe --tags",
                    did(0, format!("{HEAD}\n").as_bytes(), ""),
                ),
                ("rev-list --count", did(0, b"many\n", "")),
            ],
            "rev-list --count",
        );
        unexpected(
            vec![("cat-file commit", did(0, b"tree x\n\nno committer\n", ""))],
            "cat-file commit",
        );
    }

    #[test]
    fn failures_carry_what_git_said() {
        let failed = |changed, expected: &str| match run(changed) {
            Err(GitError::Failed { command, stderr }) => {
                assert_eq!(command, expected);
                stderr
            }
            other => panic!("{expected}: {other:?}"),
        };
        assert_eq!(
            failed(
                vec![(
                    "rev-parse --verify",
                    did(128, b"", "fatal: one\nfatal: two\n")
                )],
                "rev-parse HEAD"
            ),
            "fatal: one; fatal: two"
        );
        failed(vec![("diff --quiet", did(2, b"", "error"))], "diff");
        failed(vec![("describe --tags", did(128, b"", "bad"))], "describe");
        failed(
            vec![("cat-file commit", did(128, b"", "bad"))],
            "cat-file commit",
        );
        // A long message is cut short.
        let long = "x".repeat(2 * MAX_STDERR);
        assert_eq!(
            failed(vec![("diff --quiet", did(129, b"", &long))], "diff").len(),
            MAX_STDERR
        );
        // A dirty checkout and a shallow clone are their own errors.
        assert!(matches!(
            run(vec![("diff --quiet", did(1, b"", ""))]),
            Err(GitError::Dirty { commit }) if commit == HEAD
        ));
        assert!(matches!(
            run(vec![(
                "rev-parse --is-shallow-repository",
                did(0, b"true\n", "")
            )]),
            Err(GitError::Shallow)
        ));
    }

    #[test]
    fn a_line_is_exactly_one_line() {
        let answer = |stdout: &'static [u8]| {
            move |_: &[&str]| -> Result<Output, GitError> { Ok(did(0, stdout, "")) }
        };
        assert_eq!(line(&mut answer(b"one\n"), "x", &[]).unwrap(), "one");
        assert_eq!(line(&mut answer(b"\n"), "x", &[]).unwrap(), "");
        for bad in [&b"one\ntwo\n"[..], b"one", b"", b"one\n\n"] {
            assert!(
                matches!(
                    line(&mut answer(bad), "x", &[]),
                    Err(GitError::Unexpected { command: "x", .. })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_commit_before_1970_cant_be_a_snapshot() {
        let old = "committer C <c> -86400 +0000\n\nold\n";
        match run(vec![("cat-file commit", did(0, old.as_bytes(), ""))]) {
            Err(GitError::Snapshot(e)) => assert!(e.to_string().contains("YYYYMMDD"), "{e}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn git_that_cant_be_run_is_an_error() {
        let mut gone = |_: &[&str]| -> Result<Output, GitError> {
            Err(GitError::Run(std::io::Error::other("no git")))
        };
        let e = version_with(&mut gone).unwrap_err();
        assert_eq!(e.to_string(), "can't run git: no git");
    }

    #[test]
    fn describe_output_is_read_from_the_end() {
        let hash = "3fa9c1e5d8b2a7f40c6e1d9b8a7f6e5d4c3b2a19";
        assert_eq!(
            parse_describe(&format!("v1.4.2-37-g{hash}")),
            Some(Some(("v1.4.2", 37)))
        );
        // A tag with '-' and '-g' in it.
        assert_eq!(
            parse_describe(&format!("1.0-gold-rc-0-g{hash}")),
            Some(Some(("1.0-gold-rc", 0)))
        );
        // No tag: the hash alone.
        assert_eq!(parse_describe(hash), Some(None));
        for bad in [
            String::new(),
            format!("-37-g{hash}"),
            format!("v1-x-g{hash}"),
            format!("v1--g{hash}"),
            "v1-3-g".to_owned(),
            format!("v1-3-g{}", hash.to_uppercase()),
            "v1.4.2".to_owned(),
            format!("v1-99999999999-g{hash}"),
            format!("v1-+5-g{hash}"),
            format!("{hash}\n"),
        ] {
            assert_eq!(parse_describe(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_committer_time_comes_from_the_header() {
        let commit = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                      author A <a@example.invalid> 1000 +0000\n\
                      committer C <c@example.invalid> 1763000000 -0700\n\
                      \n\
                      committer X <x> 5 +0000\n";
        assert_eq!(committer_time(commit), Some(1_763_000_000));
        // A name with spaces.
        assert_eq!(
            committer_time("committer A B C <abc> 42 +0100\n\nmessage"),
            Some(42)
        );
        assert_eq!(committer_time("tree x\n\ncommitter X <x> 5 +0000\n"), None);
        assert_eq!(committer_time("committer X <x> soon +0000\n"), None);
        assert_eq!(committer_time("committer \n"), None);
        assert_eq!(committer_time(""), None);
    }

    #[test]
    fn dates_are_in_utc() {
        assert_eq!(utc_date(0), "19700101");
        assert_eq!(utc_date(86_399), "19700101");
        assert_eq!(utc_date(86_400), "19700102");
        // 2026-11-12, and the last second before it.
        assert_eq!(utc_date(1_794_441_600), "20261112");
        assert_eq!(utc_date(1_794_441_599), "20261111");
        // Leap days and the turn of centuries.
        assert_eq!(utc_date(951_782_400), "20000229");
        assert_eq!(utc_date(951_868_800), "20000301");
        assert_eq!(utc_date(4_107_542_400), "21000301");
        assert_eq!(utc_date(4_107_456_000), "21000228");
        assert_eq!(utc_date(-1), "19691231");
    }

    #[test]
    fn a_tag_names_its_release_without_a_v() {
        assert_eq!(tag_version("v1.4.2"), "1.4.2");
        assert_eq!(tag_version("1.4.2"), "1.4.2");
        assert_eq!(tag_version("version"), "version");
        assert_eq!(tag_version("v"), "v");
        assert_eq!(tag_version("vv1"), "vv1");
    }

    #[test]
    fn commits_are_full_object_names() {
        assert!(is_commit(&"a".repeat(40)));
        assert!(is_commit(&"0".repeat(64)));
        assert!(!is_commit(&"a".repeat(39)));
        assert!(!is_commit(&"a".repeat(41)));
        assert!(!is_commit(&"A".repeat(40)));
        assert!(!is_hex(""));
        assert!(is_hex("0123456789abcdef"));
        assert!(!is_hex("g"));
    }
}
