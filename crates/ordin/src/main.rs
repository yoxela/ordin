// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The ordin command-line interface.
//!
//! Exit codes: 0 when the command did what it was asked, 1 when it
//! couldn't (the error says why), and 2 when the command line itself is
//! wrong. `ordin verify` adds 3 for a corrupt package, 4 for an intact one
//! that isn't signed, and 5 for one signed by no trusted key.

mod cli;
mod files;
mod keys;
mod output;
mod pack;
mod passphrase;
mod show;
mod sign;
mod unpack;
mod verify;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, KeyCommand};
use crate::verify::Checked;

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
        Command::Sign(args) => match sign::run(&args) {
            Ok(signed) if args.json => {
                output::print(&output::sign_json(&signed), &[]);
                ExitCode::SUCCESS
            }
            Ok(signed) => {
                output::print(&output::sign_text(&signed), &[]);
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e, args.json),
        },
        Command::Verify(args) => match verify::run(&args) {
            Ok(Checked::Intact(report)) => {
                if args.json {
                    output::print(&output::verify_json(&report), &[]);
                } else {
                    output::print(&output::verify_text(&report), &[]);
                    if let Some(why) = output::verify_failure(&report) {
                        output::print_failure(&why);
                    }
                }
                ExitCode::from(report.verdict().exit_code())
            }
            Ok(Checked::Corrupt(e)) => {
                if args.json {
                    output::print(&output::corrupt_json(&e), &[]);
                } else {
                    output::print_error(&e);
                }
                ExitCode::from(verify::CORRUPT)
            }
            Err(e) => fail(&e, args.json),
        },
        Command::Unpack(args) => match unpack::run(&args) {
            Ok(unpacked) if args.json => {
                output::print(&output::unpack_json(&unpacked), &[]);
                ExitCode::SUCCESS
            }
            Ok(unpacked) => {
                output::print(&output::unpack_text(&unpacked), &[]);
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e, args.json),
        },
        Command::Key(KeyCommand::Generate(args)) => match keys::generate(&args) {
            Ok(made) if args.json => {
                output::print(&output::key_json(&made), &[]);
                ExitCode::SUCCESS
            }
            Ok(made) => {
                let warnings = output::key_warnings(&made);
                output::print(&output::key_text(&made), &warnings);
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e, args.json),
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

/// Prints an error, as JSON if asked, and fails.
fn fail(e: &anyhow::Error, json: bool) -> ExitCode {
    if json {
        output::print(&output::error_json(e), &[]);
    } else {
        output::print_error(e);
    }
    ExitCode::FAILURE
}
