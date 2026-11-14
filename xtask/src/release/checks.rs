// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Whether a commit's GitHub checks allow a release, from the REST API's
//! JSON. Pure functions; [`super::pre_release`] fetches the data.

use std::collections::BTreeMap;

use serde_json::Value;

use super::Error;

/// One check run on a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckRun {
    /// The run's ID. A re-run gets a higher one.
    pub id: u64,
    /// The check's name, which required checks match against.
    pub name: String,
    /// `queued`, `in_progress` or `completed`.
    pub status: String,
    /// The result, once completed.
    pub conclusion: Option<String>,
}

/// Parses check runs, one JSON object per line, as printed by
/// `gh api --paginate --jq '.check_runs[]'`.
///
/// # Errors
///
/// Returns an error if a line isn't a check run.
pub fn parse_check_runs(lines: &str) -> Result<Vec<CheckRun>, Error> {
    lines
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let v: Value =
                serde_json::from_str(line).map_err(|e| Error::parse("a check run", e))?;
            let text = |key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
            Ok(CheckRun {
                id: v
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| Error::parse("a check run", "no id"))?,
                name: text("name").ok_or_else(|| Error::parse("a check run", "no name"))?,
                status: text("status").ok_or_else(|| Error::parse("a check run", "no status"))?,
                conclusion: text("conclusion"),
            })
        })
        .collect()
}

/// The required status checks in the JSON of
/// `GET /repos/{owner}/{repo}/rules/branches/{branch}`, sorted.
///
/// # Errors
///
/// Returns an error if the JSON isn't a list of rules, or no rule requires
/// any check: a release must never be checked against nothing.
pub fn required_checks(rules: &str) -> Result<Vec<String>, Error> {
    let v: Value = serde_json::from_str(rules).map_err(|e| Error::parse("the branch rules", e))?;
    let rules = v
        .as_array()
        .ok_or_else(|| Error::parse("the branch rules", "not a list"))?;
    let mut contexts: Vec<String> = rules
        .iter()
        .filter(|r| r.get("type").and_then(Value::as_str) == Some("required_status_checks"))
        .filter_map(|r| r.pointer("/parameters/required_status_checks"))
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(|c| c.get("context").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    contexts.sort();
    contexts.dedup();
    if contexts.is_empty() {
        return Err(Error::check(
            "main's rules require no status checks; restore the ruleset before releasing",
        ));
    }
    Ok(contexts)
}

/// The head commit of the merged pull request in the JSON of
/// `GET /repos/{owner}/{repo}/commits/{sha}/pulls`, if there is one.
///
/// # Errors
///
/// Returns an error if the JSON isn't a list of pull requests.
pub fn merged_pull_head(pulls: &str) -> Result<Option<String>, Error> {
    let v: Value = serde_json::from_str(pulls).map_err(|e| Error::parse("the pull requests", e))?;
    let pulls = v
        .as_array()
        .ok_or_else(|| Error::parse("the pull requests", "not a list"))?;
    Ok(pulls
        .iter()
        .filter(|p| p.get("merged_at").is_some_and(|m| !m.is_null()))
        .find_map(|p| p.pointer("/head/sha").and_then(Value::as_str))
        .map(str::to_owned))
}

/// The newest run of each check, by name.
fn latest(runs: &[CheckRun]) -> BTreeMap<&str, &CheckRun> {
    let mut by_name: BTreeMap<&str, &CheckRun> = BTreeMap::new();
    for run in runs {
        let newer = by_name
            .get(run.name.as_str())
            .is_none_or(|seen| run.id > seen.id);
        if newer {
            by_name.insert(&run.name, run);
        }
    }
    by_name
}

fn succeeded(run: &CheckRun) -> bool {
    run.status == "completed" && run.conclusion.as_deref() == Some("success")
}

/// What stops a release of a commit, given the required checks, the newest
/// check runs on the commit itself (including scheduled runs such as
/// fuzzing), and the runs on the head of the pull request that merged it.
///
/// - Every check on the commit has finished, and none failed: success,
///   skipped and neutral are fine, anything else is a problem. A fuzz crash
///   on `main` is a release blocker.
/// - Every required check succeeded, on the commit or, for checks that only
///   run on pull requests, on the merged pull request's head.
#[must_use]
pub fn problems(required: &[String], commit: &[CheckRun], pull: &[CheckRun]) -> Vec<String> {
    let mut out = Vec::new();
    let on_commit = latest(commit);
    let on_pull = latest(pull);
    for (name, run) in &on_commit {
        if run.status != "completed" {
            out.push(format!("`{name}` hasn't finished ({})", run.status));
            continue;
        }
        match run.conclusion.as_deref() {
            Some("success" | "skipped" | "neutral") => {}
            other => out.push(format!(
                "`{name}` concluded {}",
                other.unwrap_or("with no result")
            )),
        }
    }
    for name in required {
        let ok = on_commit
            .get(name.as_str())
            .or_else(|| on_pull.get(name.as_str()))
            .is_some_and(|run| succeeded(run));
        if !ok && !out.iter().any(|p| p.starts_with(&format!("`{name}`"))) {
            out.push(format!("the required check `{name}` didn't succeed"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(id: u64, name: &str, status: &str, conclusion: Option<&str>) -> CheckRun {
        CheckRun {
            id,
            name: name.into(),
            status: status.into(),
            conclusion: conclusion.map(str::to_owned),
        }
    }

    fn ok(id: u64, name: &str) -> CheckRun {
        run(id, name, "completed", Some("success"))
    }

    fn req(names: &[&str]) -> Vec<String> {
        names.iter().map(|&n| n.to_owned()).collect()
    }

    #[test]
    fn check_runs_parse_one_per_line() {
        let text = "{\"id\":1,\"name\":\"rustfmt\",\"status\":\"completed\",\"conclusion\":\"success\"}\n\n\
                    {\"id\":2,\"name\":\"fuzz\",\"status\":\"in_progress\",\"conclusion\":null}\n";
        assert_eq!(
            parse_check_runs(text).unwrap(),
            vec![ok(1, "rustfmt"), run(2, "fuzz", "in_progress", None)]
        );
        assert_eq!(parse_check_runs("").unwrap(), vec![]);
        for bad in [
            "nope",
            "{\"name\":\"a\",\"status\":\"completed\"}",
            "{\"id\":1,\"status\":\"completed\"}",
            "{\"id\":1,\"name\":\"a\"}",
        ] {
            assert!(parse_check_runs(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn required_checks_come_from_every_status_check_rule() {
        let rules = r#"[
            {"type":"deletion"},
            {"type":"required_status_checks","parameters":{"required_status_checks":[
                {"context":"rustfmt","integration_id":15368},{"context":"coverage"}]}},
            {"type":"pull_request","parameters":{"required_status_checks":[{"context":"ignored"}]}},
            {"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"rustfmt"}]}}
        ]"#;
        assert_eq!(
            required_checks(rules).unwrap(),
            req(&["coverage", "rustfmt"])
        );
    }

    #[test]
    fn no_required_checks_is_an_error() {
        let e = required_checks(r#"[{"type":"deletion"}]"#).unwrap_err();
        assert!(e.to_string().contains("require no status checks"), "{e}");
        assert!(required_checks("{}").is_err());
        assert!(required_checks("nope").is_err());
    }

    #[test]
    fn the_merged_pull_requests_head_is_found() {
        let pulls = r#"[
            {"merged_at":null,"head":{"sha":"open"}},
            {"head":{"sha":"no-field"}},
            {"merged_at":"2026-11-14T10:00:00Z","head":{"sha":"abc"}}
        ]"#;
        assert_eq!(merged_pull_head(pulls).unwrap().as_deref(), Some("abc"));
        assert_eq!(merged_pull_head("[]").unwrap(), None);
        assert!(merged_pull_head("{}").is_err());
        assert!(merged_pull_head("nope").is_err());
    }

    #[test]
    fn a_green_commit_has_no_problems() {
        let required = req(&["rustfmt", "mutants"]);
        let commit = [
            ok(1, "rustfmt"),
            run(2, "fuzz", "completed", Some("skipped")),
        ];
        let pull = [ok(3, "mutants")];
        assert_eq!(problems(&required, &commit, &pull), Vec::<String>::new());
        let neutral = [
            ok(1, "rustfmt"),
            ok(2, "mutants"),
            run(3, "x", "completed", Some("neutral")),
        ];
        assert_eq!(problems(&required, &neutral, &[]), Vec::<String>::new());
    }

    #[test]
    fn failed_or_unfinished_runs_on_the_commit_are_problems() {
        let commit = [
            run(1, "fuzz", "completed", Some("failure")),
            run(2, "coverage", "in_progress", None),
            run(3, "odd", "completed", None),
            ok(4, "rustfmt"),
        ];
        assert_eq!(
            problems(&req(&["rustfmt"]), &commit, &[]),
            vec![
                "`coverage` hasn't finished (in_progress)".to_owned(),
                "`fuzz` concluded failure".to_owned(),
                "`odd` concluded with no result".to_owned(),
            ]
        );
    }

    #[test]
    fn a_required_check_must_succeed_somewhere() {
        let required = req(&["mutants", "rustfmt"]);
        assert_eq!(
            problems(&required, &[ok(1, "rustfmt")], &[]),
            vec!["the required check `mutants` didn't succeed".to_owned()]
        );
        let pull = [run(2, "mutants", "completed", Some("failure"))];
        assert_eq!(
            problems(&required, &[ok(1, "rustfmt")], &pull),
            vec!["the required check `mutants` didn't succeed".to_owned()]
        );
        let skipped = [
            ok(1, "rustfmt"),
            run(2, "mutants", "completed", Some("skipped")),
        ];
        assert_eq!(
            problems(&required, &skipped, &[ok(3, "mutants")]),
            vec!["the required check `mutants` didn't succeed".to_owned()]
        );
    }

    #[test]
    fn a_required_check_that_failed_on_the_commit_is_reported_once() {
        let commit = [run(1, "rustfmt", "completed", Some("failure"))];
        assert_eq!(
            problems(&req(&["rustfmt"]), &commit, &[ok(2, "rustfmt")]),
            vec!["`rustfmt` concluded failure".to_owned()]
        );
    }

    #[test]
    fn on_a_repeated_id_the_first_run_stays() {
        let repeated = [
            ok(1, "rustfmt"),
            run(1, "rustfmt", "completed", Some("failure")),
        ];
        assert_eq!(
            problems(&req(&["rustfmt"]), &repeated, &[]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_newest_run_of_a_check_wins() {
        let rerun_passed = [
            run(1, "rustfmt", "completed", Some("failure")),
            ok(2, "rustfmt"),
        ];
        assert_eq!(
            problems(&req(&["rustfmt"]), &rerun_passed, &[]),
            Vec::<String>::new()
        );
        let rerun_failed = [
            ok(2, "rustfmt"),
            run(1, "rustfmt", "completed", Some("failure")),
            run(3, "rustfmt", "completed", Some("failure")),
        ];
        assert_eq!(
            problems(&req(&["rustfmt"]), &rerun_failed, &[]),
            vec!["`rustfmt` concluded failure".to_owned()]
        );
        let pull = [
            ok(5, "mutants"),
            run(4, "mutants", "completed", Some("failure")),
        ];
        assert_eq!(
            problems(&req(&["mutants"]), &[], &pull),
            Vec::<String>::new()
        );
    }
}
