// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Throwaway workspaces for the end-to-end tests.
//!
//! Every helper here is used by [`broken_workspace`], so each test file that
//! uses it uses all of them.

use std::fs;
use std::path::{Path, PathBuf};

use xtask::files::{LAYER_0_DISALLOWED_METHODS, LAYER_0_DISALLOWED_TYPES};

pub const MIT: &str = "MIT OR Apache-2.0";
pub const GPL: &str = "GPL-3.0-or-later";
pub const INHERIT: &str = "[lints]\nworkspace = true\n";

/// A workspace in a temporary directory, removed when dropped.
pub struct TempWorkspace(PathBuf);

impl TempWorkspace {
    pub fn new(name: &str) -> std::io::Result<Self> {
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

    /// The workspace's root directory.
    pub fn root(&self) -> &Path {
        &self.0
    }

    /// The workspace's root `Cargo.toml`.
    pub fn manifest(&self) -> PathBuf {
        self.root().join("Cargo.toml")
    }

    /// Adds a crate. `layer` is the raw TOML value, or `None` to leave it out.
    pub fn krate(
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
        fs::write(dir.join("src/lib.rs"), header(header_license))?;
        Ok(dir)
    }

    /// Writes the layer-0 `clippy.toml` that bans I/O.
    pub fn layer_0_clippy(&self, crate_dir: &Path) -> std::io::Result<()> {
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

    /// Adds a `fuzz/` workspace with one target.
    pub fn fuzz(&self, license: &str, header_license: &str) -> std::io::Result<()> {
        let dir = self.0.join("fuzz");
        fs::create_dir_all(dir.join("fuzz_targets"))?;
        fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"ordin-fuzz\"\nlicense = \"{license}\"\n"),
        )?;
        fs::write(dir.join("fuzz_targets/target.rs"), header(header_license))
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn header(license: &str) -> String {
    format!(
        "// SPDX-License-Identifier: {license}\n// SPDX-FileCopyrightText: 2026 The Ordin Authors\n"
    )
}

/// A workspace that breaks every file and graph rule that a single crate can,
/// beside a crate that breaks none.
pub fn broken_workspace(name: &str) -> std::io::Result<TempWorkspace> {
    let ws = TempWorkspace::new(name)?;

    // Clean: layer 0, permissive, I/O banned, header and lints right.
    let good = ws.krate("good-core", Some("0"), MIT, INHERIT, "", MIT)?;
    ws.layer_0_clippy(&good)?;

    // Layer 0 with a GPL license, no clippy.toml, a header for the wrong
    // license, its own lint table, and an upward dependency.
    ws.krate(
        "bad-core",
        Some("0"),
        GPL,
        "[lints.rust]\nunsafe_code = \"forbid\"\n",
        "engine = { path = \"../engine\" }",
        MIT,
    )?;

    // Layer 2 with its own clippy.toml, which it may not have.
    let engine = ws.krate("engine", Some("2"), GPL, INHERIT, "", GPL)?;
    fs::write(engine.join("clippy.toml"), "allow-unwrap-in-tests = true\n")?;

    // No layer at all.
    ws.krate("no-layer", None, GPL, INHERIT, "", GPL)?;

    // A fuzz target whose header names the wrong license.
    ws.fuzz(GPL, MIT)?;
    Ok(ws)
}
