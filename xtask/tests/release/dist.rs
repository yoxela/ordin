// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `dist` end to end on a throwaway workspace with Ordin's six programs.
//! `cargo build` is faked; everything else is real.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use xtask::release::dist::{self, PROGRAMS, TARGETS, check_sums, run};
use xtask::release::{Error, exec::Cmd};

use crate::fake::{Fake, fail};
use crate::repo::{R, cargo_toml};

struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    /// A workspace at 0.1.0 with the six programs, license texts and a
    /// README. `ordin` gets `extra_deps` under `[dependencies]`.
    fn new(extra_deps: &str) -> R<Self> {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let members = cargo_toml("0.1.0").replace("members = []", "members = [\"crates/*\"]");
        fs::write(root.join("Cargo.toml"), members)?;
        for (package, bin) in PROGRAMS {
            let crate_dir = root.join("crates").join(package);
            fs::create_dir_all(crate_dir.join("src"))?;
            let deps = if *package == "ordin" { extra_deps } else { "" };
            fs::write(
                crate_dir.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{package}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
                     [[bin]]\nname = \"{bin}\"\npath = \"src/main.rs\"\n\n[dependencies]\n{deps}\n"
                ),
            )?;
            fs::write(crate_dir.join("src/main.rs"), "fn main() {}\n")?;
        }
        fs::create_dir(root.join("LICENSES"))?;
        fs::write(root.join("LICENSES/MIT.txt"), "MIT text")?;
        fs::write(root.join("LICENSES/GPL-3.0-or-later.txt"), "GPL text")?;
        fs::write(root.join("README.md"), "# Ordin\n")?;
        Ok(Self { dir })
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn fake(&self) -> Fake {
        Fake::new(
            self.root().join("unused"),
            self.root().join("unused"),
            "v0.1.0",
        )
    }

    fn dist(
        &self,
        fake: &Fake,
        tag: &str,
        epoch: Option<&str>,
        out: &str,
    ) -> Result<Vec<PathBuf>, Error> {
        let mut log = Vec::new();
        run(
            fake,
            &self.root().join("Cargo.toml"),
            tag,
            epoch,
            &self.root().join(out),
            &mut log,
        )
    }
}

struct Member {
    path: String,
    mode: u32,
    mtime: u64,
    uid: u64,
    gid: u64,
    data: String,
}

fn members(archive: &Path) -> R<Vec<Member>> {
    let gz = flate2::read::GzDecoder::new(fs::File::open(archive)?);
    let mut tar = tar::Archive::new(gz);
    let mut found = Vec::new();
    for entry in tar.entries()? {
        let mut entry = entry?;
        let header = entry.header().clone();
        let mut data = String::new();
        entry.read_to_string(&mut data)?;
        found.push(Member {
            path: entry.path()?.display().to_string(),
            mode: header.mode()?,
            mtime: header.mtime()?,
            uid: header.uid()?,
            gid: header.gid()?,
            data,
        });
    }
    Ok(found)
}

#[test]
fn dist_builds_every_target_and_packs_deterministic_archives() {
    let ws = Workspace::new("").unwrap();
    let fake = ws.fake();
    let written = ws.dist(&fake, "v0.1.0", Some("1763000000"), "out").unwrap();
    let names: Vec<String> = written
        .iter()
        .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, dist::release_files("0.1.0"));
    check_sums(&ws.root().join("out")).unwrap();

    let builds = fake.calls_to("cargo");
    assert_eq!(builds.len(), TARGETS.len());
    for (args, target) in builds.iter().zip(TARGETS) {
        assert_eq!(
            args[..6],
            [
                "build",
                "--release",
                "--locked",
                "--offline",
                "--target",
                target
            ]
        );
    }
    assert!(
        fake.calls
            .borrow()
            .iter()
            .all(|c: &Cmd| c.dir.as_deref() == Some(ws.root()))
    );

    let archive = ws
        .root()
        .join("out")
        .join(dist::archive_name("0.1.0", "aarch64-unknown-linux-musl"));
    let top = "ordin-0.1.0-aarch64-unknown-linux-musl";
    let found = members(&archive).unwrap();
    let paths: Vec<&str> = found.iter().map(|m| m.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            top.to_owned() + "/",
            top.to_owned() + "/LICENSES/",
            top.to_owned() + "/LICENSES/GPL-3.0-or-later.txt",
            top.to_owned() + "/LICENSES/MIT.txt",
            top.to_owned() + "/README.md",
            top.to_owned() + "/ordin",
            top.to_owned() + "/ordin-build",
            top.to_owned() + "/ordin-helper",
            top.to_owned() + "/ordin-repo",
            top.to_owned() + "/ordin-rescue",
            top.to_owned() + "/ordind",
        ]
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
    );
    for m in &found {
        assert_eq!((m.mtime, m.uid, m.gid), (1_763_000_000, 0, 0), "{}", m.path);
        let executable =
            m.path.ends_with('/') || !m.path.contains("LICENSES/") && !m.path.ends_with(".md");
        assert_eq!(m.mode, if executable { 0o755 } else { 0o644 }, "{}", m.path);
    }
    let ordin = found.iter().find(|m| m.path.ends_with("/ordin")).unwrap();
    assert_eq!(ordin.data, "ordin for aarch64-unknown-linux-musl");
    assert_eq!(found[2].data, "GPL text");

    // The same inputs give the same bytes; another timestamp doesn't.
    ws.dist(&fake, "v0.1.0", Some("1763000000"), "again")
        .unwrap();
    ws.dist(&fake, "v0.1.0", Some("1763000001"), "later")
        .unwrap();
    let sums = |dir: &str| fs::read(ws.root().join(dir).join(dist::SUMS)).unwrap();
    assert_eq!(sums("out"), sums("again"));
    assert_ne!(sums("out"), sums("later"));
}

#[test]
fn a_tag_for_another_version_builds_nothing() {
    let ws = Workspace::new("").unwrap();
    let fake = ws.fake();
    let e = ws.dist(&fake, "v0.2.0", Some("1"), "out").unwrap_err();
    assert!(
        e.to_string()
            .contains("doesn't match the workspace version 0.1.0"),
        "{e}"
    );
    assert!(fake.calls.borrow().is_empty());
    assert!(!ws.root().join("out").exists());
}

#[test]
fn a_missing_source_date_epoch_builds_nothing() {
    let ws = Workspace::new("").unwrap();
    let fake = ws.fake();
    let e = ws.dist(&fake, "v0.1.0", None, "out").unwrap_err();
    assert!(e.to_string().contains("SOURCE_DATE_EPOCH isn't set"), "{e}");
    assert!(fake.calls.borrow().is_empty());
}

#[test]
fn programs_that_link_third_party_code_are_refused() {
    // A path dependency outside the workspace is third-party code.
    let dep = tempfile::tempdir().unwrap();
    fs::create_dir(dep.path().join("src")).unwrap();
    fs::write(
        dep.path().join("Cargo.toml"),
        "[package]\nname = \"helper\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[workspace]\n",
    )
    .unwrap();
    fs::write(dep.path().join("src/lib.rs"), "").unwrap();
    let ws = Workspace::new(&format!(
        "helper = {{ path = \"{}\" }}",
        dep.path().display()
    ))
    .unwrap();
    let fake = ws.fake();
    let e = ws.dist(&fake, "v0.1.0", Some("1"), "out").unwrap_err();
    assert!(
        e.to_string().contains("link third-party crates (helper)"),
        "{e}"
    );
    assert!(fake.calls.borrow().is_empty());
}

#[test]
fn an_existing_output_directory_is_never_reused() {
    let ws = Workspace::new("").unwrap();
    fs::create_dir(ws.root().join("out")).unwrap();
    let fake = ws.fake();
    assert!(matches!(
        ws.dist(&fake, "v0.1.0", Some("1"), "out"),
        Err(Error::Io { .. })
    ));
    assert!(fake.calls.borrow().is_empty());
}

#[test]
fn a_failed_build_stops_dist() {
    let ws = Workspace::new("").unwrap();
    let mut fake = ws.fake();
    fake.hook = Box::new(|_, cmd| Some(fail(cmd)));
    let e = ws.dist(&fake, "v0.1.0", Some("1"), "out").unwrap_err();
    assert!(matches!(e, Error::Command { .. }), "{e}");
    assert_eq!(fake.calls.borrow().len(), 1);
}

#[test]
fn a_broken_workspace_is_an_error() {
    let ws = Workspace::new("").unwrap();
    let fake = ws.fake();
    let mut log = Vec::new();
    let e = run(
        &fake,
        &ws.root().join("missing/Cargo.toml"),
        "v0.1.0",
        Some("1"),
        &ws.root().join("out"),
        &mut log,
    )
    .unwrap_err();
    assert!(e.to_string().contains("cargo metadata"), "{e}");
}

#[test]
fn a_build_that_leaves_no_binaries_is_an_error() {
    let ws = Workspace::new("").unwrap();
    let mut fake = ws.fake();
    fake.hook = Box::new(|_, _| Some(crate::fake::ok("")));
    let e = ws.dist(&fake, "v0.1.0", Some("1"), "out").unwrap_err();
    assert!(matches!(e, Error::Io { .. }), "{e}");
    assert!(e.to_string().contains("release/ordin"), "{e}");
}

#[test]
fn sums_must_list_exactly_the_files_present() {
    let ws = Workspace::new("").unwrap();
    let fake = ws.fake();
    ws.dist(&fake, "v0.1.0", Some("1"), "out").unwrap();
    let out = ws.root().join("out");
    fs::write(out.join("extra.tar.gz"), "x").unwrap();
    let e = check_sums(&out).unwrap_err().to_string();
    assert!(e.contains("SHA256SUMS lists"), "{e}");
    // Signatures beside the files are not listed and don't count.
    fs::remove_file(out.join("extra.tar.gz")).unwrap();
    fs::write(out.join("SHA256SUMS.sig"), "sig").unwrap();
    check_sums(&out).unwrap();
}
