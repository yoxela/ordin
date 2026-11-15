// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask version-corpus` from the command line, with a fake `dpkg`
//! first on `PATH`, so the tests don't depend on the machine's dpkg. CI
//! checks the real corpus against the real dpkg in its own step.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

type R<T> = Result<T, Box<dyn std::error::Error>>;

/// A fake `dpkg` that prints a version, and agrees with every comparison
/// unless one of its arguments is `666`.
const FAKE_DPKG: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "Debian 'dpkg' package management program version 9.9.9 (amd64)."
  exit 0
fi
for arg in "$@"; do
  [ "$arg" = "666" ] && exit 1
done
exit 0
"#;

/// A directory holding the fake `dpkg`.
fn fake_dpkg() -> R<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    let dpkg = dir.path().join("dpkg");
    fs::write(&dpkg, FAKE_DPKG)?;
    fs::set_permissions(&dpkg, fs::Permissions::from_mode(0o755))?;
    Ok(dir)
}

fn xtask(bin: &Path, args: &[&str]) -> R<Output> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![bin.to_path_buf()];
    paths.extend(std::env::split_paths(&path));
    Ok(Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .env("PATH", std::env::join_paths(paths)?)
        .output()?)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn generate_writes_the_corpus_where_asked() {
    let bin = fake_dpkg().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let census = dir.path().join("census.json");
    fs::write(
        &census,
        r#"{"packages": [{"version": "1.10"}, {"version": "1.9"}, {"version": "1.09"}]}"#,
    )
    .unwrap();
    let out_file = dir.path().join("versions.txt");
    let out = xtask(
        bin.path(),
        &[
            "version-corpus",
            "--census",
            &census.to_string_lossy(),
            "--out",
            &out_file.to_string_lossy(),
        ],
    )
    .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("version-corpus: wrote"));
    let written = fs::read_to_string(&out_file).unwrap();
    assert!(written.contains("(dpkg 9.9.9)"), "{written}");
    let body: Vec<&str> = written.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(body, ["1.09 1.9", "1.10"]);
}

#[test]
fn check_without_a_file_reads_the_committed_corpus() {
    let bin = fake_dpkg().unwrap();
    let out = xtask(bin.path(), &["version-corpus", "--check"]).unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "version-corpus: ok, 23260 versions\n");
}

#[test]
fn check_fails_when_dpkg_disagrees() {
    let bin = fake_dpkg().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let corpus = dir.path().join("versions.txt");
    fs::write(&corpus, "# header\n1\n666\n").unwrap();
    let out = xtask(
        bin.path(),
        &["version-corpus", "--check", &corpus.to_string_lossy()],
    )
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(
        text(&out.stderr).contains("dpkg doesn't agree that 1 lt 666"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn files_that_cannot_be_read_are_named() {
    let bin = fake_dpkg().unwrap();
    let out = xtask(
        bin.path(),
        &["version-corpus", "--check", "/nonexistent/versions.txt"],
    )
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("/nonexistent/versions.txt"),
        "{}",
        text(&out.stderr)
    );
    let out = xtask(
        bin.path(),
        &[
            "version-corpus",
            "--census",
            "/nonexistent/census.json",
            "--out",
            "/nonexistent/out",
        ],
    )
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("/nonexistent/census.json"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn generate_needs_an_output_file() {
    let bin = fake_dpkg().unwrap();
    let out = xtask(bin.path(), &["version-corpus", "--census", "census.json"]).unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("version-corpus --census <census.json> --out <file>"));
}
