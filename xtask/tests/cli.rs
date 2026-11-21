// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The `xtask` binary: arguments, output and exit codes.

mod common;

use std::process::{Command, Output};

use common::broken_workspace;

fn xtask(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
}

#[test]
fn a_clean_workspace_exits_0() {
    let out = xtask(&["check-layers"]).unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "check-layers: ok\n");
}

#[test]
fn violations_are_listed_and_exit_1() {
    let ws = broken_workspace("cli-broken").unwrap();
    let manifest = ws.manifest();
    let out = xtask(&[
        "check-layers",
        "--manifest-path",
        &manifest.to_string_lossy(),
    ])
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[upward-dependency] bad-core (layer 0) depends on engine (layer 2)"));
    assert!(
        stderr.ends_with("check-layers: 8 violation(s)\n"),
        "{stderr}"
    );
}

#[test]
fn a_check_that_cannot_run_exits_2() {
    let out = xtask(&["check-layers", "--manifest-path", "/nonexistent/Cargo.toml"]).unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).starts_with("check-layers: cargo metadata failed")
    );
}

#[test]
fn unknown_or_missing_commands_print_usage_and_exit_2() {
    for args in [
        &[][..],
        &["nope"][..],
        &["check-layers", "extra"][..],
        &["check-layers", "--manifest-path"][..],
        &["dist", "--tag", "v0.1.0"][..],
        &["dist", "--out", "x", "--tag", "v0.1.0"][..],
        &["pre-release", "now"][..],
        &["release-sign", "v0.1.0"][..],
        &[
            "release-sign",
            "v0.1.0",
            "--key",
            "k",
            "--allowed-signers",
            "s",
        ][..],
    ] {
        let out = xtask(args).unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.starts_with("usage: cargo xtask <command>\n"),
            "{stderr}"
        );
        for command in ["check-layers", "dist", "pre-release", "release-sign"] {
            assert!(stderr.contains(&format!("\n  {command}")), "{stderr}");
        }
    }
}

/// The workspace version, for commands that check the tag against it.
fn version() -> Result<String, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml"))?;
    Ok(xtask::release::version::workspace(&text)?.version)
}

#[test]
fn dist_checks_the_tag_and_timestamp_before_building() {
    let out = xtask(&["dist", "--tag", "v0.0.0-never", "--out", "/nonexistent/out"]).unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with("dist: the tag v0.0.0-never doesn't match"),
        "{stderr}"
    );

    let tag = format!("v{}", version().unwrap());
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["dist", "--tag", &tag, "--out", "/nonexistent/out"])
        .env_remove("SOURCE_DATE_EPOCH")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Until ORD-006 ships their license notices, the third-party crates
    // `ordin` links stop dist before it looks at the timestamp. The
    // timestamp check is tested on a model workspace in tests/release.
    assert!(
        stderr.starts_with("dist: the programs link third-party crates ("),
        "{stderr}"
    );
    assert!(stderr.contains(" clap, "), "{stderr}");
}

#[test]
fn release_sign_reports_failures_with_exit_1() {
    let out = xtask(&[
        "release-sign",
        "0.1.0",
        "--allowed-signers",
        "s",
        "--key",
        "k",
    ])
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with("release-sign: can't parse the tag"),
        "{stderr}"
    );
    let tag = format!("v{}", version().unwrap());
    let out = xtask(&[
        "release-sign",
        &tag,
        "--allowed-signers",
        "/nonexistent/signers",
        "--key",
        "k",
    ])
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with("release-sign: /nonexistent/signers: "),
        "{stderr}"
    );
}

/// Whether pre-release passes depends on the checkout it runs in, so this
/// only checks that it runs and reports: never a usage error.
#[test]
fn pre_release_runs_its_checks() {
    let out = xtask(&["pre-release"]).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    match out.status.code() {
        Some(0) => assert!(String::from_utf8_lossy(&out.stdout).contains("git tag -s")),
        Some(1) => assert!(stderr.contains("pre-release: "), "{stderr}"),
        other => panic!("exit {other:?}: {stderr}"),
    }
}
