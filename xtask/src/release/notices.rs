// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The license notices of third-party code in the release binaries
//! (ORD-006).
//!
//! Each archive carries:
//! - `THIRD-PARTY-NOTICES.txt`: every third-party crate the programs link
//!   for that target, with the crate's own license files, verbatim
//! - `THIRD-PARTY/rust-library-COPYRIGHT.html`: the pinned toolchain's
//!   notice for Rust's standard library, which every binary contains
//! - `THIRD-PARTY/musl-COPYRIGHT`, in the musl archives: musl's notice,
//!   kept in the repository at `release/notices/`, because the toolchain
//!   links musl statically and ships no notice for it
//!
//! A crate is linked when a program reaches it through normal
//! dependencies on that target. Build and dev dependencies, and
//! proc-macro crates with everything only they use, run on the build
//! machine and never reach a binary. Nothing here records a path, so no
//! local directory ends up in an archive.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use cargo_metadata::{DependencyKind, Metadata, Package, PackageId, TargetKind};

use super::Error;
use super::dist::PROGRAMS;

/// The largest license file read, in bytes.
pub const MAX_TEXT: u64 = 1 << 20;

/// The generated file in each archive.
pub const NOTICES: &str = "THIRD-PARTY-NOTICES.txt";

/// The directory of notices taken whole.
pub const THIRD_PARTY: &str = "THIRD-PARTY";

/// The Rust standard library's notice, in the toolchain's sysroot.
pub const RUST_LIBRARY: &str = "share/doc/rust/COPYRIGHT-library.html";

/// musl's notice, in the repository: the `COPYRIGHT` file of the musl
/// release the toolchain's self-contained musl is built from.
pub const MUSL: &str = "release/notices/musl-COPYRIGHT";

/// That release.
pub const MUSL_VERSION: &str = "1.2.5";

/// File names that hold a license or notice, compared without case.
const PREFIXES: &[&str] = &[
    "license",
    "licence",
    "copying",
    "copyright",
    "notice",
    "unlicense",
];

/// One third-party crate and its license files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// The crate's name.
    pub name: String,
    /// Its version.
    pub version: String,
    /// Its SPDX license expression.
    pub license: String,
    /// Its license files, by name, sorted.
    pub files: Vec<(String, String)>,
}

/// Whether a package is a proc-macro crate, which runs in the compiler.
fn is_proc_macro(package: &Package) -> bool {
    package
        .targets
        .iter()
        .any(|t| t.kind.contains(&TargetKind::ProcMacro))
}

/// The third-party packages the programs link, as `meta` resolves them
/// for one target (`cargo metadata --filter-platform`), sorted by name and
/// version.
///
/// # Errors
///
/// Returns an error if `meta` has no dependency graph.
pub fn linked(meta: &Metadata) -> Result<Vec<&Package>, Error> {
    let resolve = meta
        .resolve
        .as_ref()
        .ok_or_else(|| Error::check("cargo metadata gave no dependency graph"))?;
    let nodes: BTreeMap<&PackageId, _> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();
    let packages: BTreeMap<&PackageId, &Package> =
        meta.packages.iter().map(|p| (&p.id, p)).collect();
    let members: BTreeSet<&PackageId> = meta.workspace_members.iter().collect();
    let mut stack: Vec<&PackageId> = meta
        .packages
        .iter()
        .filter(|p| {
            members.contains(&p.id) && PROGRAMS.iter().any(|(name, _)| *name == p.name.as_str())
        })
        .map(|p| &p.id)
        .collect();
    let mut seen = BTreeSet::new();
    let mut found = Vec::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(package) = packages.get(id) else {
            continue;
        };
        if !members.contains(id) {
            if is_proc_macro(package) {
                continue;
            }
            found.push(*package);
        }
        for dep in nodes.get(id).map_or(&[][..], |n| n.deps.as_slice()) {
            if dep
                .dep_kinds
                .iter()
                .any(|k| k.kind == DependencyKind::Normal)
            {
                stack.push(&dep.pkg);
            }
        }
    }
    found.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(found)
}

/// Whether a file name is a license or notice file.
fn is_notice_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// Reads one license file: a regular file, never a symlink, of at most
/// [`MAX_TEXT`] bytes of UTF-8.
fn read_text(path: &Path, what: &str) -> Result<String, Error> {
    let meta = fs::symlink_metadata(path).map_err(|e| Error::io(path, &e))?;
    if !meta.is_file() {
        return Err(Error::check(format!("{what} isn't a regular file")));
    }
    if meta.len() > MAX_TEXT {
        return Err(Error::check(format!(
            "{what} is larger than {MAX_TEXT} bytes"
        )));
    }
    let bytes = fs::read(path).map_err(|e| Error::io(path, &e))?;
    String::from_utf8(bytes).map_err(|_| Error::check(format!("{what} isn't UTF-8")))
}

/// A crate's license files: the files in its root whose names start with
/// `LICENSE`, `LICENCE`, `COPYING`, `COPYRIGHT`, `NOTICE` or `UNLICENSE`
/// (any case), the files of a `LICENSES/` directory there, and the file
/// its `license-file` names, which must be inside the crate.
///
/// # Errors
///
/// Returns an error, naming the crate, if a file can't be read or isn't a
/// regular UTF-8 file of at most [`MAX_TEXT`] bytes, or `license-file`
/// leaves the crate.
pub fn license_files(
    crate_name: &str,
    dir: &Path,
    license_file: Option<&Path>,
) -> Result<Vec<(String, String)>, Error> {
    let mut files = BTreeMap::new();
    let mut add = |name: String, path: &Path| -> Result<(), Error> {
        let text = read_text(path, &format!("{crate_name}'s {name}"))?;
        files.insert(name, text);
        Ok(())
    };
    for entry in fs::read_dir(dir).map_err(|e| Error::io(dir, &e))? {
        let entry = entry.map_err(|e| Error::io(dir, &e))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| Error::io(&path, &e))?;
        if name == "LICENSES" && kind.is_dir() {
            for inner in fs::read_dir(&path).map_err(|e| Error::io(&path, &e))? {
                let inner = inner.map_err(|e| Error::io(&path, &e))?;
                if let Some(file) = inner.file_name().to_str() {
                    add(format!("LICENSES/{file}"), &inner.path())?;
                }
            }
        } else if is_notice_name(&name) && !kind.is_dir() {
            add(name, &path)?;
        }
    }
    if let Some(file) = license_file {
        let inside = file
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
        if !inside {
            return Err(Error::check(format!(
                "{crate_name}'s license-file {} is outside the crate",
                file.display()
            )));
        }
        let name = file
            .components()
            .filter_map(|c| match c {
                Component::Normal(part) => part.to_str(),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/");
        add(name, &dir.join(file))?;
    }
    Ok(files.into_iter().collect())
}

/// The notices of every third-party crate in `meta`'s graph for one
/// target.
///
/// # Errors
///
/// Returns an error naming every crate with no license expression or no
/// license file, or the first file that can't be used.
pub fn collect(meta: &Metadata) -> Result<Vec<Notice>, Error> {
    let mut notices = Vec::new();
    let mut missing = Vec::new();
    for package in linked(meta)? {
        let label = format!("{} {}", package.name, package.version);
        let dir = package
            .manifest_path
            .parent()
            .ok_or_else(|| Error::check(format!("{label} has no crate directory")))?;
        let files = license_files(
            &label,
            dir.as_std_path(),
            package.license_file.as_ref().map(|f| f.as_std_path()),
        )?;
        match (&package.license, files.is_empty()) {
            (Some(license), false) => notices.push(Notice {
                name: package.name.to_string(),
                version: package.version.to_string(),
                license: license.clone(),
                files,
            }),
            (None, _) => missing.push(format!("{label} (no license expression)")),
            (Some(_), true) => missing.push(format!("{label} (no license file)")),
        }
    }
    if !missing.is_empty() {
        return Err(Error::check(format!(
            "these crates in the release binaries can't be given a license notice: {}",
            missing.join(", ")
        )));
    }
    Ok(notices)
}

const RULE: &str =
    "==============================================================================\n";
const THIN: &str =
    "------------------------------------------------------------------------------\n";

/// `THIRD-PARTY-NOTICES.txt` for one target.
#[must_use]
pub fn render(version: &str, target: &str, notices: &[Notice]) -> String {
    let mut out = format!(
        "Third-party software in ordin {version} for {target}\n\n\
         The programs in this archive contain the software below. Each crate's\n\
         license files follow the list, exactly as the crate ships them.\n\n\
         - Rust's standard library: see {THIRD_PARTY}/rust-library-COPYRIGHT.html\n"
    );
    if is_musl(target) {
        out.push_str(&format!(
            "- musl libc {MUSL_VERSION}, linked statically: see {THIRD_PARTY}/musl-COPYRIGHT\n"
        ));
    }
    out.push_str("\nCrates:\n");
    for n in notices {
        out.push_str(&format!("- {} {} ({})\n", n.name, n.version, n.license));
    }
    for n in notices {
        out.push('\n');
        out.push_str(RULE);
        out.push_str(&format!(
            "{} {}\nLicense: {}\n",
            n.name, n.version, n.license
        ));
        for (name, text) in &n.files {
            out.push('\n');
            out.push_str(THIN);
            out.push_str(name);
            out.push('\n');
            out.push_str(THIN);
            out.push_str(text);
            if !text.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    out
}

/// Whether a target links musl statically.
#[must_use]
pub fn is_musl(target: &str) -> bool {
    target.ends_with("-linux-musl")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notice_names_are_matched_without_case() {
        for name in [
            "LICENSE",
            "LICENSE-MIT",
            "license.txt",
            "LICENCE",
            "COPYING",
            "COPYRIGHT",
            "NOTICE",
            "UNLICENSE",
            "License_A2",
        ] {
            assert!(is_notice_name(name), "{name}");
        }
        for name in ["README.md", "Cargo.toml", "src", "MY-LICENSE"] {
            assert!(!is_notice_name(name), "{name}");
        }
    }

    #[test]
    fn license_files_are_read_from_the_crate_root() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        fs::write(d.join("LICENSE-MIT"), "MIT text").unwrap();
        fs::write(d.join("COPYING"), "copying\n").unwrap();
        fs::write(d.join("README.md"), "no").unwrap();
        fs::create_dir(d.join("LICENSES")).unwrap();
        fs::write(d.join("LICENSES/Apache-2.0.txt"), "apache").unwrap();
        fs::create_dir_all(d.join("doc")).unwrap();
        fs::write(d.join("doc/terms.txt"), "terms").unwrap();
        // A directory named like a license file is not one.
        fs::create_dir(d.join("license-notes")).unwrap();
        let files = license_files("x 1.0", d, Some(Path::new("doc/terms.txt"))).unwrap();
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "COPYING",
                "LICENSE-MIT",
                "LICENSES/Apache-2.0.txt",
                "doc/terms.txt"
            ]
        );
        assert_eq!(files[1].1, "MIT text");
        // license-file naming a file already found reads it once.
        let again = license_files("x 1.0", d, Some(Path::new("./COPYING"))).unwrap();
        assert_eq!(again.len(), 3);
    }

    #[test]
    fn license_files_must_be_small_regular_utf8_files_in_the_crate() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), d.join("LICENSE")).unwrap();
        assert_eq!(
            license_files("x 1.0", d, None).unwrap_err().to_string(),
            "x 1.0's LICENSE isn't a regular file"
        );
        fs::remove_file(d.join("LICENSE")).unwrap();

        fs::write(d.join("LICENSE"), vec![b'a'; MAX_TEXT as usize]).unwrap();
        assert!(license_files("x 1.0", d, None).is_ok());
        fs::write(d.join("LICENSE"), vec![b'a'; MAX_TEXT as usize + 1]).unwrap();
        assert_eq!(
            license_files("x 1.0", d, None).unwrap_err().to_string(),
            "x 1.0's LICENSE is larger than 1048576 bytes"
        );
        fs::write(d.join("LICENSE"), b"\xff").unwrap();
        assert_eq!(
            license_files("x 1.0", d, None).unwrap_err().to_string(),
            "x 1.0's LICENSE isn't UTF-8"
        );
        fs::remove_file(d.join("LICENSE")).unwrap();

        for escape in ["../secret", "/etc/passwd"] {
            assert_eq!(
                license_files("x 1.0", d, Some(Path::new(escape)))
                    .unwrap_err()
                    .to_string(),
                format!("x 1.0's license-file {escape} is outside the crate")
            );
        }
        assert!(matches!(
            license_files("x 1.0", d, Some(Path::new("missing"))).unwrap_err(),
            Error::Io { .. }
        ));
        assert!(license_files("x 1.0", &d.join("missing"), None).is_err());
        // A file in LICENSES/ is held to the same rules.
        fs::create_dir(d.join("LICENSES")).unwrap();
        fs::write(d.join("LICENSES/x"), b"\xff").unwrap();
        assert!(license_files("x 1.0", d, None).is_err());
    }

    fn notice(name: &str, files: &[(&str, &str)]) -> Notice {
        Notice {
            name: name.into(),
            version: "1.0.0".into(),
            license: "MIT".into(),
            files: files
                .iter()
                .map(|(n, t)| ((*n).to_owned(), (*t).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn the_notices_list_then_reproduce_each_crate() {
        let notices = [
            notice("a", &[("LICENSE", "A text\n")]),
            notice("b", &[("COPYING", "B text")]),
        ];
        let gnu = render("0.1.1", "x86_64-unknown-linux-gnu", &notices);
        assert_eq!(
            gnu,
            format!(
                "Third-party software in ordin 0.1.1 for x86_64-unknown-linux-gnu\n\n\
                 The programs in this archive contain the software below. Each crate's\n\
                 license files follow the list, exactly as the crate ships them.\n\n\
                 - Rust's standard library: see THIRD-PARTY/rust-library-COPYRIGHT.html\n\n\
                 Crates:\n- a 1.0.0 (MIT)\n- b 1.0.0 (MIT)\n\n\
                 {RULE}a 1.0.0\nLicense: MIT\n\n{THIN}LICENSE\n{THIN}A text\n\n\
                 {RULE}b 1.0.0\nLicense: MIT\n\n{THIN}COPYING\n{THIN}B text\n"
            )
        );
        let musl = render("0.1.1", "aarch64-unknown-linux-musl", &notices);
        assert!(
            musl.contains("- musl libc 1.2.5, linked statically: see THIRD-PARTY/musl-COPYRIGHT\n")
        );
        assert!(!gnu.contains("musl"));
        assert!(is_musl("x86_64-unknown-linux-musl"));
        assert!(!is_musl("x86_64-unknown-linux-gnu"));
    }
}
