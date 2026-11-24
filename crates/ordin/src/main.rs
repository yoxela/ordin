// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The ordin command-line interface.
//!
//! Exit codes: 0 when the command did what it was asked, 1 when it
//! couldn't (the error says why), and 2 when the command line itself is
//! wrong.

mod cli;
mod output;
mod pack;
mod show;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Pack(args) => match pack::run(&args) {
            Ok(report) if args.json => {
                output::print(&output::pack_json(&report), &[]);
                ExitCode::SUCCESS
            }
            Ok(report) => {
                output::print(&output::pack_text(&report), &report.warnings);
                ExitCode::SUCCESS
            }
            Err(e) if args.json => {
                output::print(&output::error_json(&e), &[]);
                ExitCode::FAILURE
            }
            Err(e) => {
                output::print_error(&e);
                ExitCode::FAILURE
            }
        },
        Command::Show(args) => match show::run(&args) {
            Ok(shown) => {
                output::print(&shown, &[]);
                ExitCode::SUCCESS
            }
            Err(e) if args.json => {
                output::print(&output::error_json(&e), &[]);
                ExitCode::FAILURE
            }
            Err(e) => {
                output::print_error(&e);
                ExitCode::FAILURE
            }
        },
    }
}
