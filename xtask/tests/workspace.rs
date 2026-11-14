// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! End-to-end runs of `check_workspace`: on the real workspace, which must be
//! clean, and on throwaway workspaces that break every rule beside a crate
//! that breaks none.

mod common;

use std::fs;
use std::path::Path;

use common::{GPL, INHERIT, MIT, TempWorkspace, broken_workspace};
use xtask::{Rule, check_workspace};

#[test]
fn the_real_workspace_is_clean() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
    let violations = check_workspace(&manifest).unwrap();
    let shown: Vec<String> = violations.iter().map(ToString::to_string).collect();
    assert!(shown.is_empty(), "violations:\n{}", shown.join("\n"));
}

#[test]
fn a_workspace_that_breaks_every_rule_reports_each_one() {
    let ws = broken_workspace("broken").unwrap();
    let violations = check_workspace(&ws.manifest()).unwrap();
    let found: Vec<(String, Rule)> = violations
        .iter()
        .map(|v| (v.crate_name.clone(), v.rule))
        .collect();
    assert_eq!(
        found,
        vec![
            ("bad-core".to_owned(), Rule::License),
            ("bad-core".to_owned(), Rule::UpwardDependency),
            ("bad-core".to_owned(), Rule::SpdxHeader),
            ("bad-core".to_owned(), Rule::LintTable),
            ("bad-core".to_owned(), Rule::ClippyConfig),
            ("engine".to_owned(), Rule::ClippyConfig),
            ("no-layer".to_owned(), Rule::Layer),
            ("ordin-fuzz".to_owned(), Rule::SpdxHeader),
        ],
        "{violations:#?}"
    );
    // The whole report, as a reviewed snapshot: any change to the wording,
    // the order or the paths shows up in review.
    let report: Vec<String> = violations.iter().map(ToString::to_string).collect();
    insta::assert_snapshot!(report.join("\n"));
}

#[test]
fn a_permissive_crate_reaching_a_gpl_crate_is_reported_end_to_end() {
    let ws = TempWorkspace::new("license-direction").unwrap();
    let a = ws
        .krate(
            "a-core",
            Some("0"),
            MIT,
            INHERIT,
            "b-core = { path = \"../b-core\" }",
            MIT,
        )
        .unwrap();
    ws.layer_0_clippy(&a).unwrap();
    // b-core is in layer 0 but wrongly GPL: a-core reaches a GPL crate.
    let b = ws
        .krate("b-core", Some("0"), GPL, INHERIT, "", GPL)
        .unwrap();
    ws.layer_0_clippy(&b).unwrap();
    let violations = check_workspace(&ws.manifest()).unwrap();
    let found: Vec<(String, Rule)> = violations
        .iter()
        .map(|v| (v.crate_name.clone(), v.rule))
        .collect();
    assert_eq!(
        found,
        vec![
            ("a-core".to_owned(), Rule::PermissiveDependsOnGpl),
            ("b-core".to_owned(), Rule::License)
        ]
    );
}

#[test]
fn the_fuzz_workspace_must_be_gpl_with_matching_headers() {
    let ws = TempWorkspace::new("fuzz-license").unwrap();
    ws.krate("only", Some("2"), GPL, INHERIT, "", GPL).unwrap();
    // Clean first: GPL with a GPL header.
    ws.fuzz(GPL, GPL).unwrap();
    assert_eq!(check_workspace(&ws.manifest()).unwrap(), vec![]);
    // Then permissive, with a matching header: only the license is wrong.
    ws.fuzz(MIT, MIT).unwrap();
    let violations = check_workspace(&ws.manifest()).unwrap();
    let found: Vec<(String, Rule)> = violations
        .iter()
        .map(|v| (v.crate_name.clone(), v.rule))
        .collect();
    assert_eq!(found, vec![("ordin-fuzz".to_owned(), Rule::License)]);
}

#[test]
fn an_unreadable_workspace_clippy_config_is_an_error() {
    let ws = TempWorkspace::new("no-clippy").unwrap();
    ws.krate("only", Some("2"), GPL, INHERIT, "", GPL).unwrap();
    fs::remove_file(ws.root().join("clippy.toml")).unwrap();
    let e = check_workspace(&ws.manifest()).unwrap_err();
    assert!(e.to_string().contains("clippy.toml"));
}

#[test]
fn an_unparsable_clippy_config_is_an_error() {
    let ws = TempWorkspace::new("bad-clippy").unwrap();
    let only = ws.krate("only", Some("0"), MIT, INHERIT, "", MIT).unwrap();
    fs::write(only.join("clippy.toml"), "this is = = not toml").unwrap();
    let e = check_workspace(&ws.manifest()).unwrap_err();
    assert!(e.to_string().contains("can't parse"));
}
