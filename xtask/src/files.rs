// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Checks over the workspace's files: SPDX headers, lint tables and the
//! layer-0 `clippy.toml` files. The checks are pure functions over file
//! contents; [`check`] does the reading.

use std::fs;
use std::path::{Path, PathBuf};

use crate::model::{Layer, Model};
use crate::{Rule, Violation};

/// Crates that repeat the workspace lints with `unsafe_code = "deny"`.
pub const UNSAFE_CRATES: &[&str] = &["ordin-store", "ordin-sandbox"];

/// The copyright holder named in every header.
const COPYRIGHT_HOLDER: &str = "The Ordin Authors";

/// Types a layer-0 crate may not use, because they do I/O.
pub const LAYER_0_DISALLOWED_TYPES: &[&str] = &[
    "std::fs::File",
    "std::fs::OpenOptions",
    "std::fs::DirBuilder",
    "std::fs::ReadDir",
    "std::fs::DirEntry",
    "std::net::TcpStream",
    "std::net::TcpListener",
    "std::net::UdpSocket",
    "std::process::Command",
    "std::process::Child",
];

/// Functions a layer-0 crate may not call, because they do I/O.
pub const LAYER_0_DISALLOWED_METHODS: &[&str] = &[
    "std::fs::read",
    "std::fs::read_to_string",
    "std::fs::write",
    "std::fs::read_dir",
    "std::fs::create_dir",
    "std::fs::create_dir_all",
    "std::fs::remove_file",
    "std::fs::remove_dir",
    "std::fs::remove_dir_all",
    "std::fs::rename",
    "std::fs::copy",
    "std::fs::metadata",
    "std::fs::symlink_metadata",
    "std::fs::canonicalize",
    "std::fs::hard_link",
    "std::fs::read_link",
    "std::fs::set_permissions",
    "std::fs::exists",
    "std::net::ToSocketAddrs::to_socket_addrs",
];

/// Checks the first two lines of a Rust source file: the SPDX license
/// identifier, matching the crate's license, then the copyright line.
///
/// # Errors
///
/// Returns what is wrong with the header.
pub fn check_header(contents: &str, license: &str) -> Result<(), String> {
    let mut lines = contents.lines();
    let first = lines.next().unwrap_or_default();
    let expected = format!("// SPDX-License-Identifier: {license}");
    if first != expected {
        return Err(format!(
            "first line should be `{expected}`, found `{first}`"
        ));
    }
    let second = lines.next().unwrap_or_default();
    let ok = second
        .strip_prefix("// SPDX-FileCopyrightText: ")
        .and_then(|rest| rest.split_once(' '))
        .is_some_and(|(year, holder)| {
            year.len() == 4
                && year.bytes().all(|b| b.is_ascii_digit())
                && holder == COPYRIGHT_HOLDER
        });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "second line should be `// SPDX-FileCopyrightText: <year> {COPYRIGHT_HOLDER}`, found `{second}`"
        ))
    }
}

/// Checks a crate's `[lints]` table against the workspace's `[workspace.lints]`.
///
/// Every crate inherits the workspace lints, except [`UNSAFE_CRATES`], which
/// must repeat them exactly with `unsafe_code = "deny"`.
///
/// # Errors
///
/// Returns what is wrong with the crate's lint table.
pub fn check_lints(
    name: &str,
    workspace_manifest: &toml::Table,
    crate_manifest: &toml::Table,
) -> Result<(), String> {
    let actual = crate_manifest.get("lints");
    if UNSAFE_CRATES.contains(&name) {
        let mut expected = workspace_manifest
            .get("workspace")
            .and_then(|w| w.get("lints"))
            .and_then(toml::Value::as_table)
            .cloned()
            .ok_or_else(|| "the workspace Cargo.toml has no [workspace.lints]".to_owned())?;
        let rust = expected
            .entry("rust")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let Some(rust) = rust.as_table_mut() {
            rust.insert(
                "unsafe_code".to_owned(),
                toml::Value::String("deny".to_owned()),
            );
        }
        if actual == Some(&toml::Value::Table(expected)) {
            Ok(())
        } else {
            Err(
                "[lints] must repeat [workspace.lints] exactly, with unsafe_code = \"deny\""
                    .to_owned(),
            )
        }
    } else {
        let mut inherit = toml::Table::new();
        inherit.insert("workspace".to_owned(), toml::Value::Boolean(true));
        if actual == Some(&toml::Value::Table(inherit)) {
            Ok(())
        } else {
            Err("[lints] must be exactly `workspace = true`".to_owned())
        }
    }
}

/// Checks a layer-0 crate's own `clippy.toml`. It replaces the workspace's
/// `clippy.toml` for that crate, so it must repeat every workspace setting
/// and add exactly the I/O bans.
///
/// # Errors
///
/// Returns each problem found.
pub fn check_layer_0_clippy(
    workspace_clippy: &toml::Table,
    crate_clippy: &toml::Table,
) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    for (key, value) in workspace_clippy {
        if crate_clippy.get(key) != Some(value) {
            problems.push(format!(
                "must repeat the workspace setting `{key} = {value}`"
            ));
        }
    }
    for (key, expected) in [
        ("disallowed-types", LAYER_0_DISALLOWED_TYPES),
        ("disallowed-methods", LAYER_0_DISALLOWED_METHODS),
    ] {
        let mut paths = disallowed_paths(crate_clippy.get(key));
        paths.sort_unstable();
        let mut wanted: Vec<&str> = expected.to_vec();
        wanted.sort_unstable();
        if paths != wanted {
            problems.push(format!(
                "`{key}` must list exactly the layer-0 I/O bans ({} entries)",
                wanted.len()
            ));
        }
    }
    for key in crate_clippy.keys() {
        let known = workspace_clippy.contains_key(key)
            || key == "disallowed-types"
            || key == "disallowed-methods";
        if !known {
            problems.push(format!("has a setting the workspace doesn't: `{key}`"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// The `path` of every entry in a `disallowed-*` list. Entries are either a
/// plain string or a table with a `path`.
fn disallowed_paths(value: Option<&toml::Value>) -> Vec<&str> {
    value
        .and_then(toml::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    e.as_str()
                        .or_else(|| e.get("path").and_then(toml::Value::as_str))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Every `.rs` file under `dir`, skipping `target` and hidden directories,
/// in sorted order.
///
/// # Errors
///
/// Returns an I/O error if a directory can't be read.
pub fn rust_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if entry.file_type()?.is_dir() {
                if name != "target" && !name.starts_with('.') {
                    stack.push(path);
                }
            } else if name.ends_with(".rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Runs every file check over the workspace at `root`.
///
/// # Errors
///
/// Returns an error if a file the checks need can't be read or parsed.
pub fn check(model: &Model, root: &Path) -> Result<Vec<Violation>, crate::Error> {
    let workspace_manifest = read_toml(&root.join("Cargo.toml"))?;
    let workspace_clippy = read_toml(&root.join("clippy.toml"))?;
    let mut out = Vec::new();
    for (_, package) in model.members() {
        let push = |out: &mut Vec<Violation>, rule, message| {
            out.push(Violation {
                crate_name: package.name.clone(),
                rule,
                message,
            });
        };

        let license = package.license.as_deref().unwrap_or_default();
        check_headers(
            &package.name,
            &package.manifest_dir,
            license,
            root,
            &mut out,
        )?;

        let crate_manifest = read_toml(&package.manifest_dir.join("Cargo.toml"))?;
        if let Err(e) = check_lints(&package.name, &workspace_manifest, &crate_manifest) {
            push(&mut out, Rule::LintTable, e);
        }

        let clippy_path = package.manifest_dir.join("clippy.toml");
        let is_layer_0 = matches!(package.layer, Some(Ok(Layer::Level(0))));
        match (is_layer_0, clippy_path.exists()) {
            (true, true) => {
                if let Err(problems) = check_layer_0_clippy(&workspace_clippy, &read_toml(&clippy_path)?) {
                    for p in problems {
                        push(&mut out, Rule::ClippyConfig, format!("clippy.toml {p}"));
                    }
                }
            }
            (true, false) => push(&mut out, Rule::ClippyConfig, "is in layer 0 but has no clippy.toml banning I/O".into()),
            (false, true) => push(
                &mut out,
                Rule::ClippyConfig,
                "has its own clippy.toml, which would replace the workspace's; only layer-0 crates may".into(),
            ),
            (false, false) => {}
        }
    }
    check_fuzz(root, &mut out)?;
    Ok(out)
}

/// The fuzz workspace (`fuzz/`) is not a member, but it is GPL like every
/// other tool, and its sources carry the matching header.
fn check_fuzz(root: &Path, out: &mut Vec<Violation>) -> Result<(), crate::Error> {
    let dir = root.join("fuzz");
    let manifest = dir.join("Cargo.toml");
    if !manifest.exists() {
        return Ok(());
    }
    let fuzz = read_toml(&manifest)?;
    let package = fuzz.get("package");
    let field = |key: &str| {
        package
            .and_then(|p| p.get(key))
            .and_then(toml::Value::as_str)
    };
    let name = field("name").unwrap_or("fuzz").to_owned();
    let license = field("license").unwrap_or_default();
    if license != crate::rules::GPL {
        out.push(Violation {
            crate_name: name.clone(),
            rule: Rule::License,
            message: format!(
                "is licensed {license}, but fuzz/ must be {}",
                crate::rules::GPL
            ),
        });
    }
    check_headers(&name, &dir, license, root, out)
}

/// Checks the SPDX header of every `.rs` file under `dir`.
fn check_headers(
    name: &str,
    dir: &Path,
    license: &str,
    root: &Path,
    out: &mut Vec<Violation>,
) -> Result<(), crate::Error> {
    for file in rust_files(dir).map_err(|e| crate::Error::io(dir, &e))? {
        let contents = fs::read_to_string(&file).map_err(|e| crate::Error::io(&file, &e))?;
        if let Err(e) = check_header(&contents, license) {
            let shown = file.strip_prefix(root).unwrap_or(&file).display();
            out.push(Violation {
                crate_name: name.to_owned(),
                rule: Rule::SpdxHeader,
                message: format!("{shown}: {e}"),
            });
        }
    }
    Ok(())
}

fn read_toml(path: &Path) -> Result<toml::Table, crate::Error> {
    let text = fs::read_to_string(path).map_err(|e| crate::Error::io(path, &e))?;
    text.parse::<toml::Table>()
        .map_err(|e| crate::Error::Parse(path.display().to_string(), e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_HEADER: &str = "// SPDX-License-Identifier: MIT OR Apache-2.0\n// SPDX-FileCopyrightText: 2026 The Ordin Authors\n\n//! Docs.\n";

    #[test]
    fn accepts_a_correct_header() {
        assert_eq!(check_header(GOOD_HEADER, "MIT OR Apache-2.0"), Ok(()));
    }

    #[test]
    fn rejects_a_header_for_the_wrong_license() {
        let e = check_header(GOOD_HEADER, "GPL-3.0-or-later").unwrap_err();
        assert!(e.contains("GPL-3.0-or-later"));
    }

    #[test]
    fn rejects_missing_or_malformed_lines() {
        assert!(check_header("", "MIT OR Apache-2.0").is_err());
        assert!(check_header("//! Docs only\n", "MIT OR Apache-2.0").is_err());
        let no_copyright = "// SPDX-License-Identifier: MIT OR Apache-2.0\n\n";
        assert!(check_header(no_copyright, "MIT OR Apache-2.0").is_err());
        let wrong_holder = "// SPDX-License-Identifier: MIT OR Apache-2.0\n// SPDX-FileCopyrightText: 2026 Someone Else\n";
        assert!(check_header(wrong_holder, "MIT OR Apache-2.0").is_err());
        let bad_year = "// SPDX-License-Identifier: MIT OR Apache-2.0\n// SPDX-FileCopyrightText: 26 The Ordin Authors\n";
        assert!(check_header(bad_year, "MIT OR Apache-2.0").is_err());
        let word_year = "// SPDX-License-Identifier: MIT OR Apache-2.0\n// SPDX-FileCopyrightText: abcd The Ordin Authors\n";
        assert!(check_header(word_year, "MIT OR Apache-2.0").is_err());
        let no_year = "// SPDX-License-Identifier: MIT OR Apache-2.0\n// SPDX-FileCopyrightText: TheOrdinAuthors\n";
        assert!(check_header(no_year, "MIT OR Apache-2.0").is_err());
    }

    fn table(text: &str) -> toml::Table {
        text.parse().unwrap()
    }

    const WORKSPACE: &str = "[workspace.lints.rust]\nunsafe_code = \"forbid\"\nmissing_docs = \"warn\"\n\n[workspace.lints.clippy]\nunwrap_used = \"deny\"\n";

    #[test]
    fn ordinary_crates_must_inherit_the_workspace_lints() {
        let ws = table(WORKSPACE);
        assert_eq!(
            check_lints("ordin-core", &ws, &table("[lints]\nworkspace = true\n")),
            Ok(())
        );
        assert!(check_lints("ordin-core", &ws, &table("")).is_err());
        assert!(check_lints("ordin-core", &ws, &table("[lints]\nworkspace = false\n")).is_err());
        assert!(
            check_lints(
                "ordin-core",
                &ws,
                &table("[lints.rust]\nunsafe_code = \"forbid\"\n")
            )
            .is_err()
        );
    }

    #[test]
    fn unsafe_crates_must_repeat_the_workspace_lints_with_deny() {
        let ws = table(WORKSPACE);
        let good = "[lints.rust]\nunsafe_code = \"deny\"\nmissing_docs = \"warn\"\n\n[lints.clippy]\nunwrap_used = \"deny\"\n";
        assert_eq!(check_lints("ordin-store", &ws, &table(good)), Ok(()));
        let forbid = good.replace("\"deny\"\nmissing", "\"forbid\"\nmissing");
        assert!(check_lints("ordin-store", &ws, &table(&forbid)).is_err());
        let missing_clippy = "[lints.rust]\nunsafe_code = \"deny\"\nmissing_docs = \"warn\"\n";
        assert!(check_lints("ordin-sandbox", &ws, &table(missing_clippy)).is_err());
        assert!(check_lints("ordin-sandbox", &ws, &table("[lints]\nworkspace = true\n")).is_err());
    }

    #[test]
    fn unsafe_crates_need_a_workspace_lint_table_to_compare_with() {
        let e = check_lints(
            "ordin-store",
            &table("[workspace]\n"),
            &table("[lints]\nworkspace = true\n"),
        )
        .unwrap_err();
        assert!(e.contains("[workspace.lints]"));
    }

    #[test]
    fn unsafe_crates_get_a_rust_table_even_if_the_workspace_has_none() {
        let ws = table("[workspace.lints.clippy]\nunwrap_used = \"deny\"\n");
        let good =
            "[lints.rust]\nunsafe_code = \"deny\"\n\n[lints.clippy]\nunwrap_used = \"deny\"\n";
        assert_eq!(check_lints("ordin-store", &ws, &table(good)), Ok(()));
    }

    fn layer_0_clippy(extra: &str) -> String {
        let types: Vec<String> = LAYER_0_DISALLOWED_TYPES
            .iter()
            .map(|t| format!("{{ path = \"{t}\", reason = \"no I/O\" }}"))
            .collect();
        // Methods as plain strings, to cover both entry forms.
        let methods: Vec<String> = LAYER_0_DISALLOWED_METHODS
            .iter()
            .map(|m| format!("\"{m}\""))
            .collect();
        format!(
            "allow-unwrap-in-tests = true\n{extra}disallowed-types = [{}]\ndisallowed-methods = [{}]\n",
            types.join(", "),
            methods.join(", ")
        )
    }

    #[test]
    fn accepts_a_complete_layer_0_clippy_config() {
        let ws = table("allow-unwrap-in-tests = true\n");
        assert_eq!(
            check_layer_0_clippy(&ws, &table(&layer_0_clippy(""))),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_layer_0_clippy_config_that_drifts() {
        let ws = table("allow-unwrap-in-tests = true\nallow-expect-in-tests = true\n");
        // Missing a workspace setting.
        let problems = check_layer_0_clippy(&ws, &table(&layer_0_clippy(""))).unwrap_err();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("allow-expect-in-tests"));
        // A different value for a workspace setting.
        let ws = table("allow-unwrap-in-tests = false\n");
        assert!(check_layer_0_clippy(&ws, &table(&layer_0_clippy(""))).is_err());
        // An extra setting.
        let ws = table("allow-unwrap-in-tests = true\n");
        let problems = check_layer_0_clippy(
            &ws,
            &table(&layer_0_clippy("too-many-lines-threshold = 10\n")),
        )
        .unwrap_err();
        assert!(problems[0].contains("too-many-lines-threshold"));
    }

    #[test]
    fn rejects_incomplete_or_extra_bans() {
        let ws = table("allow-unwrap-in-tests = true\n");
        let missing_one =
            layer_0_clippy("").replace("{ path = \"std::fs::File\", reason = \"no I/O\" }, ", "");
        assert!(check_layer_0_clippy(&ws, &table(&missing_one)).is_err());
        let extra_one = layer_0_clippy("").replace(
            "disallowed-methods = [",
            "disallowed-methods = [\"std::env::var\", ",
        );
        assert!(check_layer_0_clippy(&ws, &table(&extra_one)).is_err());
        let none = "allow-unwrap-in-tests = true\n";
        assert_eq!(
            check_layer_0_clippy(&ws, &table(none)).unwrap_err().len(),
            2
        );
    }

    #[test]
    fn finds_rust_files_but_skips_target_and_hidden_directories() {
        let dir = std::env::temp_dir().join(format!("xtask-rust-files-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for sub in ["src/a", "target/debug", ".git", "tests"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        for file in [
            "src/lib.rs",
            "src/a/b.rs",
            "tests/t.rs",
            "target/debug/gen.rs",
            ".git/x.rs",
            "README.md",
        ] {
            fs::write(dir.join(file), "").unwrap();
        }
        let found: Vec<String> = rust_files(&dir)
            .unwrap()
            .iter()
            .map(|p| p.strip_prefix(&dir).unwrap().display().to_string())
            .collect();
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(found, vec!["src/a/b.rs", "src/lib.rs", "tests/t.rs"]);
    }

    #[test]
    fn reports_a_missing_directory_as_an_error() {
        assert!(rust_files(Path::new("/nonexistent/xtask-test")).is_err());
    }
}
