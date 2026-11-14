// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! End-to-end runs of `check_workspace`: on the real workspace, which must be
//! clean, and on a throwaway workspace that breaks every rule beside a crate
//! that breaks none.

use std::fs;
use std::path::{Path, PathBuf};

use xtask::files::{LAYER_0_DISALLOWED_METHODS, LAYER_0_DISALLOWED_TYPES};
use xtask::{Rule, check_workspace};

#[test]
fn the_real_workspace_is_clean() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
    let violations = check_workspace(&manifest).unwrap();
    let shown: Vec<String> = violations.iter().map(ToString::to_string).collect();
    assert!(shown.is_empty(), "violations:\n{}", shown.join("\n"));
}

const MIT: &str = "MIT OR Apache-2.0";
const GPL: &str = "GPL-3.0-or-later";

struct TempWorkspace(PathBuf);

impl TempWorkspace {
    fn new(name: &str) -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("xtask-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nresolver = \"3\"\nmembers = [\"crates/*\"]\n\n\
             [workspace.lints.rust]\nunsafe_code = \"forbid\"\n\n\
             [workspace.lints.clippy]\nunwrap_used = \"deny\"\n",
        )?;
        fs::write(dir.join("clippy.toml"), "allow-unwrap-in-tests = true\n")?;
        Ok(Self(dir))
    }

    /// Adds a crate. `layer` is the raw TOML value, or `None` to leave it out.
    fn krate(
        &self,
        name: &str,
        layer: Option<&str>,
        license: &str,
        lints: &str,
        deps: &str,
        header_license: &str,
    ) -> std::io::Result<PathBuf> {
        let dir = self.0.join("crates").join(name);
        fs::create_dir_all(dir.join("src"))?;
        let metadata = layer
            .map(|l| format!("[package.metadata.ordin]\nlayer = {l}\n\n"))
            .unwrap_or_default();
        fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\nlicense = \"{license}\"\n\n\
                 {metadata}[dependencies]\n{deps}\n{lints}"
            ),
        )?;
        fs::write(
            dir.join("src/lib.rs"),
            format!(
                "// SPDX-License-Identifier: {header_license}\n// SPDX-FileCopyrightText: 2026 The Ordin Authors\n"
            ),
        )?;
        Ok(dir)
    }

    fn layer_0_clippy(&self, crate_dir: &Path) -> std::io::Result<()> {
        let quote = |items: &[&str]| {
            items
                .iter()
                .map(|i| format!("\"{i}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        fs::write(
            crate_dir.join("clippy.toml"),
            format!(
                "allow-unwrap-in-tests = true\ndisallowed-types = [{}]\ndisallowed-methods = [{}]\n",
                quote(LAYER_0_DISALLOWED_TYPES),
                quote(LAYER_0_DISALLOWED_METHODS)
            ),
        )
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const INHERIT: &str = "[lints]\nworkspace = true\n";

#[test]
fn a_workspace_that_breaks_every_rule_reports_each_one() {
    let ws = TempWorkspace::new("broken").unwrap();

    // Clean: layer 0, permissive, I/O banned, header and lints right.
    let good = ws
        .krate("good-core", Some("0"), MIT, INHERIT, "", MIT)
        .unwrap();
    ws.layer_0_clippy(&good).unwrap();

    // Layer 0 with a GPL license, no clippy.toml, a header for the wrong
    // license, its own lint table, and an upward dependency.
    ws.krate(
        "bad-core",
        Some("0"),
        GPL,
        "[lints.rust]\nunsafe_code = \"forbid\"\n",
        "engine = { path = \"../engine\" }",
        MIT,
    )
    .unwrap();

    // Layer 2 with its own clippy.toml, which it may not have.
    let engine = ws
        .krate("engine", Some("2"), GPL, INHERIT, "", GPL)
        .unwrap();
    fs::write(engine.join("clippy.toml"), "allow-unwrap-in-tests = true\n").unwrap();

    // No layer at all.
    ws.krate("no-layer", None, GPL, INHERIT, "", GPL).unwrap();

    let violations = check_workspace(&ws.0.join("Cargo.toml")).unwrap();
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
        ],
        "{violations:#?}"
    );
    // The header message names the file relative to the workspace root.
    assert!(
        violations
            .iter()
            .any(|v| v.message.starts_with("crates/bad-core/src/lib.rs: "))
    );
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
    let violations = check_workspace(&ws.0.join("Cargo.toml")).unwrap();
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
fn an_unreadable_workspace_clippy_config_is_an_error() {
    let ws = TempWorkspace::new("no-clippy").unwrap();
    ws.krate("only", Some("2"), GPL, INHERIT, "", GPL).unwrap();
    fs::remove_file(ws.0.join("clippy.toml")).unwrap();
    let e = check_workspace(&ws.0.join("Cargo.toml")).unwrap_err();
    assert!(e.to_string().contains("clippy.toml"));
}

#[test]
fn an_unparsable_clippy_config_is_an_error() {
    let ws = TempWorkspace::new("bad-clippy").unwrap();
    let only = ws.krate("only", Some("0"), MIT, INHERIT, "", MIT).unwrap();
    fs::write(only.join("clippy.toml"), "this is = = not toml").unwrap();
    let e = check_workspace(&ws.0.join("Cargo.toml")).unwrap_err();
    assert!(e.to_string().contains("can't parse"));
}
