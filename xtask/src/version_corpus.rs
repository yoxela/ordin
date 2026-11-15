// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask version-corpus`: the corpus that holds `ordin-version` to
//! dpkg's ordering (ORD-011).
//!
//! The corpus file lists every distinct package version in a Debian
//! release, in ascending order, one line per group of equal versions.
//! `ordin-version`'s corpus test checks that Ordin orders them the same
//! way. That test alone would be circular, because the file is sorted with
//! Ordin's own ordering, so:
//!
//! - [`generate`] sorts the census's versions with `ordin-version`, then
//!   requires `dpkg --compare-versions` to agree on every adjacent pair and
//!   every equal pair, and writes nothing if it doesn't. dpkg's ordering
//!   is a total order, so agreement on adjacent pairs is agreement on all.
//! - [`check`] reads a corpus file and verifies it with dpkg alone, without
//!   `ordin-version`. CI runs it, so the committed file is always dpkg's
//!   order and not only Ordin's.

use std::cmp::Ordering;
use std::io::Write;

use serde_json::Value;

use crate::release::exec::{Cmd, Exec};
use crate::release::{Error, say};

/// Where the corpus file lives, relative to the workspace.
pub const CORPUS: &str = "crates/ordin-version/tests/data/trixie-versions.txt";

/// Builds the corpus file from an `ordin-census` JSON report.
///
/// # Errors
///
/// Returns an error if the report can't be read, a version doesn't parse,
/// or dpkg disagrees with Ordin about any pair.
pub fn generate(exec: &dyn Exec, census: &str, log: &mut dyn Write) -> Result<String, Error> {
    let (source, versions) = census_versions(census)?;
    let groups = sort_and_group(versions)?;
    let dpkg = dpkg_version(exec)?;
    verify(exec, &groups, log)?;
    Ok(format_corpus(&source, &dpkg, &groups))
}

/// Verifies a corpus file with dpkg alone. Returns how many versions it
/// holds.
///
/// # Errors
///
/// Returns an error if the file is malformed or empty, or dpkg disagrees
/// with any pair.
pub fn check(exec: &dyn Exec, corpus: &str, log: &mut dyn Write) -> Result<usize, Error> {
    let groups = parse_corpus(corpus)?;
    if groups.is_empty() {
        return Err(Error::check("the corpus holds no versions"));
    }
    verify(exec, &groups, log)?;
    Ok(groups.iter().map(Vec::len).sum())
}

/// The groups of equal versions in a corpus file, in its order. Lines
/// starting with `#` and blank lines are skipped.
///
/// # Errors
///
/// Returns an error if a version appears twice.
pub fn parse_corpus(text: &str) -> Result<Vec<Vec<String>>, Error> {
    let mut seen = std::collections::BTreeSet::new();
    let mut groups = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let group: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        for v in &group {
            if !seen.insert(v.clone()) {
                return Err(Error::parse("the corpus", format!("{v} appears twice")));
            }
        }
        groups.push(group);
    }
    Ok(groups)
}

/// The census's source line and every distinct version in it.
fn census_versions(census: &str) -> Result<(String, Vec<String>), Error> {
    let report: Value =
        serde_json::from_str(census).map_err(|e| Error::parse("the census report", e))?;
    let meta = |key: &str| {
        report
            .pointer(&format!("/meta/{key}"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned()
    };
    let source = format!("{} ({})", meta("source"), meta("generated"));
    let packages = report
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::parse("the census report", "no packages list"))?;
    let mut versions = std::collections::BTreeSet::new();
    for p in packages {
        let v = p
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::parse("the census report", "a package has no version"))?;
        versions.insert(v.to_owned());
    }
    if versions.is_empty() {
        return Err(Error::check("the census report lists no packages"));
    }
    Ok((source, versions.into_iter().collect()))
}

/// Sorts versions with `ordin-version` and groups equal ones. Within a
/// group, versions are in byte order, so the file is deterministic.
fn sort_and_group(versions: Vec<String>) -> Result<Vec<Vec<String>>, Error> {
    let mut parsed = Vec::with_capacity(versions.len());
    for text in versions {
        let v: ordin_version::Version = text
            .parse()
            .map_err(|e| Error::parse(&format!("the version {text:?}"), e))?;
        parsed.push((v, text));
    }
    parsed.sort_by(|(a, ta), (b, tb)| a.cmp(b).then_with(|| ta.cmp(tb)));
    let mut groups: Vec<Vec<String>> = Vec::new();
    let mut last: Option<ordin_version::Version> = None;
    for (v, text) in parsed {
        match (&last, groups.last_mut()) {
            (Some(prev), Some(group)) if prev.cmp(&v) == Ordering::Equal => group.push(text),
            _ => groups.push(vec![text]),
        }
        last = Some(v);
    }
    Ok(groups)
}

/// Requires dpkg to agree that each group's versions are equal and that
/// each group is below the next.
fn verify(exec: &dyn Exec, groups: &[Vec<String>], log: &mut dyn Write) -> Result<(), Error> {
    let total = groups.iter().map(Vec::len).sum::<usize>();
    say(
        log,
        &format!("version-corpus: checking {total} versions with dpkg"),
    );
    let mut done = 0;
    let mut previous: Option<&String> = None;
    for (first, rest) in groups.iter().filter_map(|g| g.split_first()) {
        if let Some(prev) = previous {
            dpkg_agrees(exec, prev, "lt", first)?;
        }
        for other in rest {
            dpkg_agrees(exec, first, "eq", other)?;
        }
        previous = Some(first);
        let size = rest.len() + 1;
        done += size;
        if done % 5000 < size {
            say(log, &format!("version-corpus: {done} of {total}"));
        }
    }
    say(log, "version-corpus: dpkg agrees on every pair");
    Ok(())
}

fn dpkg_agrees(exec: &dyn Exec, a: &str, op: &str, b: &str) -> Result<(), Error> {
    exec.run(&Cmd::new("dpkg").args(["--compare-versions", a, op, b]))
        .map(|_| ())
        .map_err(|e| Error::check(format!("dpkg doesn't agree that {a} {op} {b}: {e}")))
}

/// dpkg's version, from the first line of `dpkg --version`.
fn dpkg_version(exec: &dyn Exec) -> Result<String, Error> {
    let out = exec.run(&Cmd::new("dpkg").arg("--version"))?.stdout_text();
    out.lines()
        .next()
        .and_then(|line| {
            line.split_whitespace()
                .skip_while(|w| *w != "version")
                .nth(1)
        })
        .map(|v| v.trim_end_matches('.').to_owned())
        .ok_or_else(|| Error::parse("dpkg --version", "no version in its output"))
}

fn format_corpus(source: &str, dpkg: &str, groups: &[Vec<String>]) -> String {
    let count: usize = groups.iter().map(Vec::len).sum();
    let mut out = format!(
        "# Every distinct package version in {source},\n\
         # {count} in all, in ascending order. Versions on one line are equal.\n\
         #\n\
         # Generated by `cargo xtask version-corpus`, which sorts them with\n\
         # ordin-version and requires `dpkg --compare-versions` (dpkg {dpkg}) to\n\
         # agree on every adjacent and every equal pair. CI checks the file\n\
         # against dpkg again with `cargo xtask version-corpus --check`.\n"
    );
    for group in groups {
        out.push_str(&group.join(" "));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::release::exec::Captured;

    /// A dpkg that answers with `ordin-version`'s ordering, except that it
    /// disagrees about `disagree`, if set.
    struct FakeDpkg {
        disagree: Option<(&'static str, &'static str)>,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl FakeDpkg {
        fn new() -> Self {
            Self {
                disagree: None,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl Exec for FakeDpkg {
        fn run(&self, cmd: &Cmd) -> Result<Captured, Error> {
            let args = cmd.arg_strings();
            self.calls.borrow_mut().push(args.clone());
            let ok = |stdout: &str| {
                Ok(Captured {
                    stdout: stdout.as_bytes().to_vec(),
                    stderr: Vec::new(),
                })
            };
            let fail = || {
                Err(Error::Command {
                    command: cmd.display(),
                    detail: "exit status: 1".into(),
                })
            };
            if args == ["--version"] {
                return ok(
                    "Debian 'dpkg' package management program version 1.22.22 (amd64).\nmore\n",
                );
            }
            // `--compare-versions <a> <op> <b>`, the only other call.
            let (a, op, b) = (&args[1], &args[2], &args[3]);
            if self.disagree.is_some_and(|(x, y)| x == a && y == b) {
                return fail();
            }
            let a: ordin_version::Version = a.parse().map_err(|e| Error::parse("a", e))?;
            let b: ordin_version::Version = b.parse().map_err(|e| Error::parse("b", e))?;
            let holds = if op == "lt" { a < b } else { a == b };
            if holds { ok("") } else { fail() }
        }
    }

    const CENSUS: &str = r#"{
        "meta": {"source": "https://deb.debian.org/debian trixie [main] amd64", "generated": "2026-11-13 18:07 UTC"},
        "packages": [
            {"package": "a", "version": "1.10-1"},
            {"package": "b", "version": "1.9-1"},
            {"package": "c", "version": "1.9-1"},
            {"package": "d", "version": "1:0.1"},
            {"package": "e", "version": "1.0~rc1"},
            {"package": "f", "version": "1.00"},
            {"package": "g", "version": "1.0"},
            {"package": "h", "version": "0:1.0-0"}
        ]
    }"#;

    #[test]
    fn generate_sorts_groups_and_checks_with_dpkg() {
        let dpkg = FakeDpkg::new();
        let mut log = Vec::new();
        let text = generate(&dpkg, CENSUS, &mut log).unwrap();
        let body: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            body,
            ["1.0~rc1", "0:1.0-0 1.0 1.00", "1.9-1", "1.10-1", "1:0.1"]
        );
        assert!(
            text.contains("trixie [main] amd64 (2026-11-13 18:07 UTC)"),
            "{text}"
        );
        assert!(text.contains("# 7 in all"), "{text}");
        assert!(text.contains("(dpkg 1.22.22)"), "{text}");
        // Four adjacent pairs and two equal pairs, plus `--version`.
        let compares = dpkg
            .calls
            .borrow()
            .iter()
            .filter(|c| c[0] == "--compare-versions")
            .count();
        assert_eq!(compares, 6);
        let log = String::from_utf8(log).unwrap();
        assert!(log.contains("dpkg agrees on every pair"), "{log}");
        // The file it writes passes the check.
        assert_eq!(check(&FakeDpkg::new(), &text, &mut Vec::new()).unwrap(), 7);
    }

    #[test]
    fn a_disagreement_is_reported_and_nothing_is_written() {
        let mut dpkg = FakeDpkg::new();
        dpkg.disagree = Some(("1.9-1", "1.10-1"));
        let e = generate(&dpkg, CENSUS, &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(e.contains("dpkg doesn't agree that 1.9-1 lt 1.10-1"), "{e}");
        dpkg.disagree = Some(("0:1.0-0", "1.00"));
        let e = generate(&dpkg, CENSUS, &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(e.contains("that 0:1.0-0 eq 1.00"), "{e}");
    }

    #[test]
    fn check_uses_dpkg_alone() {
        // Out of order for Ordin and dpkg alike: the check must fail.
        let e = check(&FakeDpkg::new(), "# header\n\n1.10\n1.9\n", &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(e.contains("1.10 lt 1.9"), "{e}");
        // Only dpkg is asked: one call per pair, and no `--version`.
        let dpkg = FakeDpkg::new();
        assert_eq!(check(&dpkg, "1.0 1.00\n2\n", &mut Vec::new()).unwrap(), 3);
        assert_eq!(dpkg.calls.borrow().len(), 2);
    }

    #[test]
    fn malformed_input_is_refused() {
        let dpkg = FakeDpkg::new();
        assert!(
            check(&dpkg, "# only a header\n", &mut Vec::new())
                .unwrap_err()
                .to_string()
                .contains("no versions")
        );
        assert!(
            parse_corpus("1.0\n1.0\n")
                .unwrap_err()
                .to_string()
                .contains("1.0 appears twice")
        );
        let err = |census: &str| {
            generate(&dpkg, census, &mut Vec::new())
                .unwrap_err()
                .to_string()
        };
        assert!(err("nope").contains("can't parse the census report"));
        assert!(err("{}").contains("no packages list"));
        assert!(err(r#"{"packages": [{"package": "a"}]}"#).contains("has no version"));
        assert!(err(r#"{"packages": []}"#).contains("lists no packages"));
        assert!(err(r#"{"packages": [{"version": "x1"}]}"#).contains("the version \"x1\""));
    }

    #[test]
    fn a_census_without_meta_still_works() {
        let text = generate(
            &FakeDpkg::new(),
            r#"{"packages": [{"version": "1"}]}"#,
            &mut Vec::new(),
        )
        .unwrap();
        assert!(text.contains("unknown (unknown)"), "{text}");
    }

    #[test]
    fn dpkg_version_needs_a_version_word() {
        struct Silent;
        impl Exec for Silent {
            fn run(&self, _: &Cmd) -> Result<Captured, Error> {
                Ok(Captured {
                    stdout: b"dpkg\n".to_vec(),
                    stderr: Vec::new(),
                })
            }
        }
        assert!(
            dpkg_version(&Silent)
                .unwrap_err()
                .to_string()
                .contains("no version")
        );
    }

    #[test]
    fn progress_is_logged_every_5000_versions() {
        let groups: Vec<Vec<String>> = (1..=10_001).map(|n| vec![n.to_string()]).collect();
        let mut log = Vec::new();
        verify(&FakeDpkg::new(), &groups, &mut log).unwrap();
        let log = String::from_utf8(log).unwrap();
        assert!(log.contains("5000 of 10001"), "{log}");
        assert!(log.contains("10000 of 10001"), "{log}");
        assert_eq!(log.lines().count(), 4, "{log}");
    }
}
