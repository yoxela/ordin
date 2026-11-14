// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The `xtask` binary: arguments and exit codes.

use std::process::Command;

fn xtask(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
}

#[test]
fn check_layers_passes_on_the_real_workspace() {
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
fn unknown_or_missing_commands_print_usage_and_exit_2() {
    for args in [&[][..], &["nope"][..], &["check-layers", "extra"][..]] {
        let out = xtask(args).unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("usage: cargo xtask check-layers"));
    }
}
