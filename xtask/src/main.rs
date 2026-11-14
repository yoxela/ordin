// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask`: Ordin's project tooling. See the library for the checks.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["check-layers"] => check_layers(),
        _ => {
            eprintln!("usage: cargo xtask check-layers");
            ExitCode::from(2)
        }
    }
}

fn check_layers() -> ExitCode {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("Cargo.toml");
    match xtask::check_workspace(&manifest) {
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
