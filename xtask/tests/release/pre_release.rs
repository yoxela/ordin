// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `pre-release` end to end: a real checkout and origin, and a fake GitHub
//! API.

use std::fs;

use xtask::release::Error;
use xtask::release::pre_release::run;

use crate::fake::Fake;
use crate::repo::{R, Repo, git};

const RULES: &str = r#"[{"type":"required_status_checks","parameters":{"required_status_checks":[
    {"context":"rustfmt"},{"context":"mutants (changed code)"}]}}]"#;

fn run_line(id: u64, name: &str, conclusion: &str) -> String {
    format!(
        "{{\"id\":{id},\"name\":\"{name}\",\"status\":\"completed\",\"conclusion\":\"{conclusion}\"}}\n"
    )
}

struct Setup {
    repo: Repo,
    fake: Fake,
    head: String,
}

impl Setup {
    /// A clean main at 0.1.0, matching origin, whose checks passed.
    fn new() -> R<Self> {
        let repo = Repo::new()?;
        let head = repo.commit(&repo.release_files("0.1.0")?, "release")?;
        repo.push("main")?;
        let mut fake = Fake::new(repo.path("unused"), repo.path("unused"), "v0.1.0");
        fake.api = [
            (
                "repos/test/ordin/rules/branches/main".to_owned(),
                RULES.to_owned(),
            ),
            (
                format!("repos/test/ordin/commits/{head}/check-runs?per_page=100"),
                run_line(1, "rustfmt", "success") + &run_line(2, "fuzz", "success"),
            ),
            (
                format!("repos/test/ordin/commits/{head}/pulls"),
                r#"[{"merged_at":"2026-11-20T10:00:00Z","head":{"sha":"pr-head"}}]"#.to_owned(),
            ),
            (
                "repos/test/ordin/commits/pr-head/check-runs?per_page=100".to_owned(),
                run_line(3, "mutants (changed code)", "success"),
            ),
        ]
        .into_iter()
        .collect();
        Ok(Self { repo, fake, head })
    }

    fn run(&self) -> (Result<String, Error>, String) {
        let mut log = Vec::new();
        let result = run(&self.fake, &self.repo.work, &mut log);
        (result, String::from_utf8_lossy(&log).into_owned())
    }

    fn fails_with(&self, message: &str) -> R<()> {
        let (result, log) = self.run();
        let e = match result {
            Ok(tag) => return Err(format!("expected an error, got {tag}\n{log}").into()),
            Err(e) => e.to_string(),
        };
        assert!(
            e.contains(message),
            "expected {message:?} in: {e}\nlog:\n{log}"
        );
        Ok(())
    }

    fn set_api(&mut self, path: &str, body: &str) {
        self.fake.api.insert(path.to_owned(), body.to_owned());
    }
}

#[test]
fn a_ready_main_gives_its_tag() {
    let s = Setup::new().unwrap();
    let (result, log) = s.run();
    assert_eq!(result.as_deref(), Ok("v0.1.0"), "{log}");
    assert!(
        log.contains(&format!("main is clean and matches origin at {}", s.head)),
        "{log}"
    );
    assert!(
        log.contains("version 0.1.0 is in Cargo.toml and CHANGELOG.md"),
        "{log}"
    );
    assert!(log.contains("all 2 required checks passed"), "{log}");
}

#[test]
fn another_branch_is_refused() {
    let s = Setup::new().unwrap();
    git(&s.repo.work, &["checkout", "--quiet", "-b", "feature"]).unwrap();
    s.fails_with("releases are tagged on main, not feature")
        .unwrap();
}

#[test]
fn a_dirty_tree_is_refused() {
    let s = Setup::new().unwrap();
    fs::write(s.repo.work.join("stray"), "x").unwrap();
    s.fails_with("the working tree isn't clean:\n?? stray")
        .unwrap();
}

#[test]
fn a_main_that_differs_from_origin_is_refused() {
    let s = Setup::new().unwrap();
    let head = s.repo.commit(&[], "unpushed").unwrap();
    s.fails_with(&format!("main is {head} here but {} on origin", s.head))
        .unwrap();
}

#[test]
fn a_main_missing_from_origin_is_refused() {
    let s = Setup::new().unwrap();
    git(&s.repo.origin, &["update-ref", "-d", "refs/heads/main"]).unwrap();
    s.fails_with("but missing on origin").unwrap();
}

#[test]
fn an_undated_changelog_is_refused() {
    let s = Setup::new().unwrap();
    s.repo
        .commit(
            &[("CHANGELOG.md", "## [Unreleased] (0.1.0)\n".to_owned())],
            "undo",
        )
        .unwrap();
    git(&s.repo.work, &["push", "--quiet", "origin", "main"]).unwrap();
    s.fails_with("CHANGELOG.md has no `## [0.1.0] - YYYY-MM-DD` heading")
        .unwrap();
}

#[test]
fn an_existing_tag_is_refused_here_and_on_origin() {
    let s = Setup::new().unwrap();
    git(&s.repo.work, &["tag", "v0.1.0"]).unwrap();
    s.fails_with("the tag v0.1.0 already exists here").unwrap();
    git(&s.repo.work, &["push", "--quiet", "origin", "v0.1.0"]).unwrap();
    git(&s.repo.work, &["tag", "-d", "v0.1.0"]).unwrap();
    s.fails_with("the tag v0.1.0 already exists on origin")
        .unwrap();
}

#[test]
fn signers_that_break_the_policy_are_refused() {
    let s = Setup::new().unwrap();
    s.repo
        .commit(
            &[("release/allowed_signers", "# none\n".to_owned())],
            "drop keys",
        )
        .unwrap();
    git(&s.repo.work, &["push", "--quiet", "origin", "main"]).unwrap();
    s.fails_with("no key for the `git` namespace").unwrap();
}

#[test]
fn a_failed_check_on_main_is_refused() {
    let mut s = Setup::new().unwrap();
    let path = format!(
        "repos/test/ordin/commits/{}/check-runs?per_page=100",
        s.head
    );
    let lines = run_line(1, "rustfmt", "success") + &run_line(2, "fuzz", "failure");
    s.set_api(&path, &lines);
    s.fails_with("don't allow a release:\n- `fuzz` concluded failure")
        .unwrap();
}

#[test]
fn a_check_that_only_ran_on_an_unmerged_pull_request_does_not_count() {
    let mut s = Setup::new().unwrap();
    let path = format!("repos/test/ordin/commits/{}/pulls", s.head);
    s.set_api(&path, r#"[{"merged_at":null,"head":{"sha":"pr-head"}}]"#);
    s.fails_with("the required check `mutants (changed code)` didn't succeed")
        .unwrap();
}

#[test]
fn a_github_error_stops_the_checks() {
    let mut s = Setup::new().unwrap();
    s.fake.api.remove("repos/test/ordin/rules/branches/main");
    s.fails_with("refused by the fake").unwrap();
}

#[test]
fn the_api_calls_are_paginated_only_with_a_filter() {
    let s = Setup::new().unwrap();
    s.run().0.unwrap();
    let api: Vec<Vec<String>> = s.fake.calls_to("gh");
    assert_eq!(api[0], ["api", "repos/test/ordin/rules/branches/main"]);
    assert_eq!(
        api[1],
        [
            "api",
            "--paginate",
            "--jq",
            ".check_runs[]",
            &format!(
                "repos/test/ordin/commits/{}/check-runs?per_page=100",
                s.head
            ),
        ]
    );
    assert_eq!(api.len(), 4);
}

#[test]
fn missing_check_runs_or_pull_requests_stop_the_checks() {
    let mut s = Setup::new().unwrap();
    let path = format!(
        "repos/test/ordin/commits/{}/check-runs?per_page=100",
        s.head
    );
    s.fake.api.remove(&path);
    s.fails_with("check-runs").unwrap();
    let mut s = Setup::new().unwrap();
    let path = format!("repos/test/ordin/commits/{}/pulls", s.head);
    s.fake.api.remove(&path);
    s.fails_with("/pulls").unwrap();
}
