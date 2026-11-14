// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask dist`: builds the release binaries for every target and
//! packs them into deterministic archives, with a `SHA256SUMS` file.
//!
//! It runs inside the pinned build container, where
//! `scripts/release/build.sh` sets the linkers, path remapping and
//! `SOURCE_DATE_EPOCH`. The archives depend only on the files and that
//! timestamp: entries are sorted, owned by root, and have fixed modes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use flate2::{Compression, GzBuilder};
use sha2::{Digest, Sha256};

use super::exec::{Cmd, Exec};
use super::{Error, say, version};
use crate::model::Model;

/// The release targets, built in this order.
pub const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
];

/// The programs in each archive: Cargo package, then binary name.
pub const PROGRAMS: &[(&str, &str)] = &[
    ("ordin", "ordin"),
    ("ordind", "ordind"),
    ("ordin-helper", "ordin-helper"),
    ("ordin-build-bin", "ordin-build"),
    ("ordin-repo-bin", "ordin-repo"),
    ("ordin-rescue", "ordin-rescue"),
];

/// The checksum file published with the archives.
pub const SUMS: &str = "SHA256SUMS";

/// The archive name for one target.
#[must_use]
pub fn archive_name(version: &str, target: &str) -> String {
    format!("ordin-{version}-{target}.tar.gz")
}

/// Every file a release publishes before signing, sorted.
#[must_use]
pub fn release_files(version: &str) -> Vec<String> {
    let mut files: Vec<String> = TARGETS.iter().map(|t| archive_name(version, t)).collect();
    files.push(SUMS.to_owned());
    files.sort();
    files
}

/// Third-party packages that the shipped programs link, sorted. Their
/// license notices would have to ship too, and the archives don't carry
/// any yet, so `dist` refuses to build until they do.
#[must_use]
pub fn third_party_in_programs(model: &Model) -> Vec<String> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut stack: Vec<&str> = model
        .packages
        .iter()
        .filter(|(_, p)| p.workspace_member && PROGRAMS.iter().any(|(pkg, _)| *pkg == p.name))
        .map(|(id, _)| id.as_str())
        .collect();
    let mut found = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(package) = model.packages.get(id) else {
            continue;
        };
        if !package.workspace_member {
            found.insert(package.name.clone());
        }
        for (dep, kinds) in &package.deps {
            if kinds.normal {
                stack.push(dep);
            }
        }
    }
    found.into_iter().collect()
}

/// The `cargo build` command for one target.
#[must_use]
pub fn build_command(root: &Path, target: &str) -> Cmd {
    let mut cmd = Cmd::new("cargo")
        .dir(root)
        .args([
            "build",
            "--release",
            "--locked",
            "--offline",
            "--target",
            target,
        ])
        .interactive();
    for (package, _) in PROGRAMS {
        cmd = cmd.args(["--package", package]);
    }
    cmd
}

/// Parses `SOURCE_DATE_EPOCH`.
///
/// # Errors
///
/// Returns an error if it is unset or not a decimal number of seconds.
pub fn source_date_epoch(value: Option<&str>) -> Result<u64, Error> {
    let value = value.ok_or_else(|| {
        Error::check("SOURCE_DATE_EPOCH isn't set; run dist through scripts/release/build.sh")
    })?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::parse(
            "SOURCE_DATE_EPOCH",
            format!("`{value}` isn't a number of seconds"),
        ));
    }
    value
        .parse()
        .map_err(|e| Error::parse("SOURCE_DATE_EPOCH", e))
}

/// One entry in an archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The path inside the archive. Directories end with `/`.
    pub path: String,
    /// The permission bits.
    pub mode: u32,
    /// The file to copy, or `None` for a directory.
    pub source: Option<PathBuf>,
}

/// Lists a directory's regular files, sorted by name.
///
/// # Errors
///
/// Returns an error if the directory can't be read, or holds anything but
/// regular files with UTF-8 names. Symbolic links are never followed.
pub fn regular_files(dir: &Path) -> Result<Vec<(String, PathBuf)>, Error> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| Error::io(dir, &e))? {
        let entry = entry.map_err(|e| Error::io(dir, &e))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| Error::io(&path, &e))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::check(format!("{} has a name that isn't UTF-8", path.display())))?;
        if !kind.is_file() {
            return Err(Error::check(format!(
                "{} isn't a regular file; only regular files are released",
                path.display()
            )));
        }
        files.push((name, path));
    }
    files.sort();
    Ok(files)
}

/// The entries of one target's archive, sorted by path: the programs, the
/// license texts and the README, under `ordin-<version>-<target>/`.
///
/// # Errors
///
/// Returns an error if `LICENSES/` can't be listed.
pub fn archive_entries(
    root: &Path,
    binaries: &Path,
    version: &str,
    target: &str,
) -> Result<Vec<Entry>, Error> {
    let top = format!("ordin-{version}-{target}");
    let dir = |path: String| Entry {
        path,
        mode: 0o755,
        source: None,
    };
    let mut entries = vec![dir(format!("{top}/")), dir(format!("{top}/LICENSES/"))];
    for (_, bin) in PROGRAMS {
        entries.push(Entry {
            path: format!("{top}/{bin}"),
            mode: 0o755,
            source: Some(binaries.join(bin)),
        });
    }
    for (name, path) in regular_files(&root.join("LICENSES"))? {
        entries.push(Entry {
            path: format!("{top}/LICENSES/{name}"),
            mode: 0o644,
            source: Some(path),
        });
    }
    entries.push(Entry {
        path: format!("{top}/README.md"),
        mode: 0o644,
        source: Some(root.join("README.md")),
    });
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// Writes a gzip-compressed tar archive of `entries`, every one stamped
/// with `mtime` and owned by root.
///
/// # Errors
///
/// Returns an error if a source isn't a regular file or can't be read, or
/// the archive can't be written.
pub fn write_archive(entries: &[Entry], mtime: u64, out: &Path) -> Result<(), Error> {
    let file = fs::File::create_new(out).map_err(|e| Error::io(out, &e))?;
    let gz = GzBuilder::new().mtime(0).write(file, Compression::best());
    let mut tar = tar::Builder::new(gz);
    for entry in entries {
        let mut header = tar::Header::new_ustar();
        header
            .set_path(&entry.path)
            .map_err(|e| Error::io(Path::new(&entry.path), &e))?;
        header.set_mode(entry.mode);
        header.set_mtime(mtime);
        header.set_uid(0);
        header.set_gid(0);
        match &entry.source {
            None => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_cksum();
                tar.append(&header, io::empty())
                    .map_err(|e| Error::io(out, &e))?;
            }
            Some(source) => {
                let meta = fs::symlink_metadata(source).map_err(|e| Error::io(source, &e))?;
                if !meta.is_file() {
                    return Err(Error::check(format!(
                        "{} isn't a regular file",
                        source.display()
                    )));
                }
                let data = fs::File::open(source).map_err(|e| Error::io(source, &e))?;
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(meta.len());
                header.set_cksum();
                tar.append(&header, data.take(meta.len()))
                    .map_err(|e| Error::io(source, &e))?;
            }
        }
    }
    let gz = tar.into_inner().map_err(|e| Error::io(out, &e))?;
    let mut file = gz.finish().map_err(|e| Error::io(out, &e))?;
    file.flush().map_err(|e| Error::io(out, &e))?;
    file.sync_all().map_err(|e| Error::io(out, &e))
}

/// The SHA-256 of a file, in lowercase hex.
///
/// # Errors
///
/// Returns an error if the file can't be read.
pub fn sha256_file(path: &Path) -> Result<String, Error> {
    let mut file = fs::File::open(path).map_err(|e| Error::io(path, &e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf).map_err(|e| Error::io(path, &e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A `SHA256SUMS` file in the format `sha256sum -c` reads: one line per
/// file, sorted by name.
#[must_use]
pub fn format_sums(sums: &BTreeMap<String, String>) -> String {
    sums.iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect()
}

/// Parses a `SHA256SUMS` file written by [`format_sums`].
///
/// # Errors
///
/// Returns an error for a malformed line, a name with a path in it, or a
/// name listed twice.
pub fn parse_sums(text: &str) -> Result<BTreeMap<String, String>, Error> {
    let mut sums = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let bad = |why: &str| Error::parse(SUMS, format!("line {}: {why}", n + 1));
        let (digest, name) = line
            .split_once("  ")
            .ok_or_else(|| bad("expected `<sha256>  <name>`"))?;
        let hex_ok = digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex_ok {
            return Err(bad("the digest isn't 64 lowercase hex digits"));
        }
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            return Err(bad("the name must be a plain file name"));
        }
        if sums.insert(name.to_owned(), digest.to_owned()).is_some() {
            return Err(bad("the name is listed twice"));
        }
    }
    Ok(sums)
}

/// Checks a directory of release files against its `SHA256SUMS`: the same
/// names, and every digest matching.
///
/// # Errors
///
/// Returns an error naming the first mismatch.
pub fn check_sums(dir: &Path) -> Result<(), Error> {
    let sums_path = dir.join(SUMS);
    let text = fs::read_to_string(&sums_path).map_err(|e| Error::io(&sums_path, &e))?;
    let listed = parse_sums(&text)?;
    let present: Vec<(String, PathBuf)> = regular_files(dir)?
        .into_iter()
        .filter(|(name, _)| name != SUMS && !name.ends_with(".sig"))
        .collect();
    let names: Vec<&String> = present.iter().map(|(n, _)| n).collect();
    let expected: Vec<&String> = listed.keys().collect();
    if names != expected {
        return Err(Error::check(format!(
            "{SUMS} lists {expected:?} but the directory has {names:?}"
        )));
    }
    for (name, path) in &present {
        if listed.get(name) != Some(&sha256_file(path)?) {
            return Err(Error::check(format!(
                "{name} doesn't match its {SUMS} entry"
            )));
        }
    }
    Ok(())
}

/// Builds and packs a release into `out`, which must not exist yet.
/// Returns the files written, sorted.
///
/// # Errors
///
/// Returns an error if the tag doesn't match the workspace version, a
/// shipped program links third-party code, `SOURCE_DATE_EPOCH` is missing,
/// a build fails, or a file can't be written.
pub fn run(
    exec: &dyn Exec,
    manifest: &Path,
    tag: &str,
    source_date_epoch_var: Option<&str>,
    out: &Path,
    log: &mut dyn Write,
) -> Result<Vec<PathBuf>, Error> {
    let meta = cargo_metadata::MetadataCommand::new()
        .manifest_path(manifest)
        .exec()
        .map_err(|e| Error::Command {
            command: "cargo metadata".into(),
            detail: e.to_string(),
        })?;
    let root = meta.workspace_root.as_std_path();
    let cargo_toml = root.join("Cargo.toml");
    let text = fs::read_to_string(&cargo_toml).map_err(|e| Error::io(&cargo_toml, &e))?;
    let version = version::workspace(&text)?.version;
    version::check_tag(tag, &version)?;
    let third_party = third_party_in_programs(&Model::from_metadata(&meta));
    if !third_party.is_empty() {
        return Err(Error::check(format!(
            "the programs link third-party crates ({}), whose license notices the \
             archives don't carry yet; add them to dist before releasing",
            third_party.join(", ")
        )));
    }
    let mtime = source_date_epoch(source_date_epoch_var)?;
    fs::create_dir(out).map_err(|e| Error::io(out, &e))?;
    let target_dir = meta.target_directory.as_std_path();
    for target in TARGETS {
        say(log, &format!("dist: building {target}"));
        exec.run(&build_command(root, target))?;
    }
    let mut sums = BTreeMap::new();
    let mut written = Vec::new();
    for target in TARGETS {
        let name = archive_name(&version, target);
        let path = out.join(&name);
        let binaries = target_dir.join(target).join("release");
        write_archive(
            &archive_entries(root, &binaries, &version, target)?,
            mtime,
            &path,
        )?;
        sums.insert(name, sha256_file(&path)?);
        written.push(path);
    }
    let sums_path = out.join(SUMS);
    fs::write(&sums_path, format_sums(&sums)).map_err(|e| Error::io(&sums_path, &e))?;
    written.push(sums_path);
    written.sort();
    for path in &written {
        say(log, &format!("dist: wrote {}", path.display()));
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DepKinds, Package};

    fn package(name: &str, member: bool, deps: &[(&str, DepKinds)]) -> (String, Package) {
        (
            format!("{name}-id"),
            Package {
                name: name.into(),
                workspace_member: member,
                layer: None,
                license: None,
                manifest_dir: PathBuf::new(),
                deps: deps.iter().map(|(d, k)| (format!("{d}-id"), *k)).collect(),
            },
        )
    }

    const NORMAL: DepKinds = DepKinds {
        normal: true,
        build: false,
        dev: false,
    };
    const BUILD: DepKinds = DepKinds {
        normal: false,
        build: true,
        dev: false,
    };
    const DEV: DepKinds = DepKinds {
        normal: false,
        build: false,
        dev: true,
    };

    #[test]
    fn names_follow_the_version_and_target() {
        assert_eq!(
            archive_name("0.1.0", "x86_64-unknown-linux-musl"),
            "ordin-0.1.0-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            release_files("0.1.0"),
            [
                "SHA256SUMS",
                "ordin-0.1.0-aarch64-unknown-linux-gnu.tar.gz",
                "ordin-0.1.0-aarch64-unknown-linux-musl.tar.gz",
                "ordin-0.1.0-x86_64-unknown-linux-gnu.tar.gz",
                "ordin-0.1.0-x86_64-unknown-linux-musl.tar.gz",
            ]
        );
    }

    #[test]
    fn third_party_code_reached_by_normal_edges_is_found() {
        let model = Model {
            packages: [
                package(
                    "ordin",
                    true,
                    &[("ordin-core", NORMAL), ("proptest", DEV), ("cc", BUILD)],
                ),
                package(
                    "ordin-core",
                    true,
                    &[("serde", NORMAL), ("ordin", NORMAL), ("gone", NORMAL)],
                ),
                package("ordin-rescue", true, &[("libc", NORMAL)]),
                package("xtask", true, &[("toml", NORMAL)]),
                package("serde", false, &[("serde_derive", NORMAL)]),
                package("serde_derive", false, &[]),
                package("libc", false, &[]),
                package("proptest", false, &[]),
                package("cc", false, &[]),
                package("toml", false, &[]),
                // A third-party package that happens to share a program's
                // name is not a program.
                package("ordind", false, &[("hidden", NORMAL)]),
                package("hidden", false, &[]),
            ]
            .into_iter()
            .collect(),
        };
        assert_eq!(
            third_party_in_programs(&model),
            ["libc", "serde", "serde_derive"]
        );
        assert!(third_party_in_programs(&Model::default()).is_empty());
    }

    #[test]
    fn the_build_command_names_every_program() {
        let cmd = build_command(Path::new("/src"), "aarch64-unknown-linux-musl");
        assert_eq!(cmd.program, "cargo");
        assert_eq!(cmd.dir.as_deref(), Some(Path::new("/src")));
        assert!(cmd.interactive);
        assert_eq!(
            cmd.display(),
            "cargo build --release --locked --offline --target aarch64-unknown-linux-musl \
             --package ordin --package ordind --package ordin-helper --package ordin-build-bin \
             --package ordin-repo-bin --package ordin-rescue"
        );
    }

    #[test]
    fn the_source_date_epoch_is_a_plain_number() {
        assert_eq!(source_date_epoch(Some("1763000000")), Ok(1_763_000_000));
        assert_eq!(source_date_epoch(Some("0")), Ok(0));
        assert!(
            source_date_epoch(None)
                .unwrap_err()
                .to_string()
                .contains("isn't set")
        );
        for bad in ["", "-1", "+5", "1.5", " 1", "99999999999999999999999"] {
            assert!(source_date_epoch(Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sums_round_trip_and_reject_bad_lines() {
        let d = "a".repeat(64);
        let sums: BTreeMap<String, String> = [
            ("b.tar.gz".to_owned(), d.clone()),
            ("a.tar.gz".to_owned(), "0".repeat(64)),
        ]
        .into_iter()
        .collect();
        let text = format_sums(&sums);
        assert_eq!(
            text,
            format!("{}  a.tar.gz\n{d}  b.tar.gz\n", "0".repeat(64))
        );
        assert_eq!(parse_sums(&text).unwrap(), sums);
        for (bad, why) in [
            (format!("{d} a"), "expected"),
            (format!("{}  a", "a".repeat(63)), "64 lowercase"),
            (format!("{}  a", "A".repeat(64)), "64 lowercase"),
            (format!("{}  a", "g".repeat(64)), "64 lowercase"),
            (format!("{d}  "), "plain file name"),
            (format!("{d}  x/a"), "plain file name"),
            (format!("{d}  .a"), "plain file name"),
            (format!("{d}  a\n{d}  a"), "twice"),
        ] {
            let e = parse_sums(&bad).unwrap_err().to_string();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn digests_are_lowercase_hex() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "abc").unwrap();
        assert_eq!(
            sha256_file(&f).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(sha256_file(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn only_regular_files_are_listed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("b"), "").unwrap();
        fs::write(dir.path().join("a"), "").unwrap();
        let names: Vec<String> = regular_files(dir.path())
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, ["a", "b"]);
        std::os::unix::fs::symlink("a", dir.path().join("c")).unwrap();
        assert!(
            regular_files(dir.path())
                .unwrap_err()
                .to_string()
                .contains("isn't a regular file")
        );
        assert!(regular_files(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn non_utf8_names_are_refused() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(std::ffi::OsStr::from_bytes(b"\xff")), "").unwrap();
        assert!(
            regular_files(dir.path())
                .unwrap_err()
                .to_string()
                .contains("UTF-8")
        );
    }

    #[test]
    fn archives_refuse_anything_but_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let entry = |source: PathBuf| Entry {
            path: "x/f".into(),
            mode: 0o644,
            source: Some(source),
        };
        let e = write_archive(
            &[entry(dir.path().to_path_buf())],
            0,
            &dir.path().join("a.tar.gz"),
        )
        .unwrap_err();
        assert!(e.to_string().contains("isn't a regular file"), "{e}");
        let e = write_archive(
            &[entry(dir.path().join("missing"))],
            0,
            &dir.path().join("b.tar.gz"),
        )
        .unwrap_err();
        assert!(matches!(e, Error::Io { .. }), "{e}");
        let long = Entry {
            path: "x".repeat(300),
            mode: 0o644,
            source: None,
        };
        assert!(write_archive(&[long], 0, &dir.path().join("c.tar.gz")).is_err());
        fs::write(dir.path().join("exists"), "").unwrap();
        assert!(write_archive(&[], 0, &dir.path().join("exists")).is_err());
    }
}
