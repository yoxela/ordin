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
    ] {
        let out = xtask(args).unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&out.stderr).starts_with("usage: cargo xtask check-layers")
        );
    }
}
