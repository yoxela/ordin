// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask`: Ordin's project tooling. See the library for the checks.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask check-layers [--manifest-path <Cargo.toml>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["check-layers"] => {
            check_layers(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml"))
        }
        ["check-layers", "--manifest-path", path] => check_layers(&PathBuf::from(path)),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Exit codes: 0 clean, 1 violations found, 2 the check couldn't run.
fn check_layers(manifest: &Path) -> ExitCode {
    match xtask::check_workspace(manifest) {
        Ok(violations) if violations.is_empty() => {
            println!("check-layers: ok");
            ExitCode::SUCCESS
        }
        Ok(violations) => {
            for v in &violations {
                eprintln!("{v}");
            }
            eprintln!("check-layers: {} violation(s)", violations.len());
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("check-layers: {e}");
            ExitCode::from(2)
        }
    }
}
