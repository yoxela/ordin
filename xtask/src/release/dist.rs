// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! `cargo xtask dist`: builds the release binaries for every target and
//! packs them into deterministic archives, with a `SHA256SUMS` file.
//!
//! It runs inside the pinned build container, where
//! `scripts/release/build.sh` sets the linkers, path remapping and
//! `SOURCE_DATE_EPOCH`. The archives depend only on the files and that
//! timestamp: entries are sorted, owned by root, and have fixed modes.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use flate2::{Compression, GzBuilder};
use sha2::{Digest, Sha256};

use super::exec::{Cmd, Exec};
use super::notices::{self, MUSL, NOTICES, RUST_LIBRARY, THIRD_PARTY};
use super::{Error, say, version};

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

/// What an archive entry holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// A directory.
    Dir,
    /// A copy of this regular file.
    File(PathBuf),
    /// These bytes, made by `dist`.
    Bytes(Vec<u8>),
}

/// One entry in an archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The path inside the archive. Directories end with `/`.
    pub path: String,
    /// The permission bits.
    pub mode: u32,
    /// What it holds.
    pub content: Content,
}

/// What a target's archive carries about third-party code: the generated
/// `THIRD-PARTY-NOTICES.txt`, and the files copied whole into
/// `THIRD-PARTY/`, by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThirdParty {
    /// `THIRD-PARTY-NOTICES.txt`.
    pub notices: String,
    /// Files for `THIRD-PARTY/`, by their names there.
    pub files: Vec<(String, PathBuf)>,
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

/// The entries of one target's archive, sorted by path, under
/// `ordin-<version>-<target>/`: the programs, the license texts, the
/// README and the third-party notices.
///
/// # Errors
///
/// Returns an error if `LICENSES/` can't be listed.
pub fn archive_entries(
    root: &Path,
    binaries: &Path,
    version: &str,
    target: &str,
    third_party: &ThirdParty,
) -> Result<Vec<Entry>, Error> {
    let top = format!("ordin-{version}-{target}");
    let dir = |path: String| Entry {
        path,
        mode: 0o755,
        content: Content::Dir,
    };
    let file = |path: String, source: PathBuf| Entry {
        path,
        mode: 0o644,
        content: Content::File(source),
    };
    let mut entries = vec![
        dir(format!("{top}/")),
        dir(format!("{top}/LICENSES/")),
        dir(format!("{top}/{THIRD_PARTY}/")),
    ];
    for (_, bin) in PROGRAMS {
        entries.push(Entry {
            path: format!("{top}/{bin}"),
            mode: 0o755,
            content: Content::File(binaries.join(bin)),
        });
    }
    for (name, path) in regular_files(&root.join("LICENSES"))? {
        entries.push(file(format!("{top}/LICENSES/{name}"), path));
    }
    entries.push(file(format!("{top}/README.md"), root.join("README.md")));
    entries.push(Entry {
        path: format!("{top}/{NOTICES}"),
        mode: 0o644,
        content: Content::Bytes(third_party.notices.as_bytes().to_vec()),
    });
    for (name, path) in &third_party.files {
        entries.push(file(format!("{top}/{THIRD_PARTY}/{name}"), path.clone()));
    }
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
        match &entry.content {
            Content::Dir => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_cksum();
                tar.append(&header, io::empty())
                    .map_err(|e| Error::io(out, &e))?;
            }
            Content::Bytes(bytes) => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                header.set_cksum();
                tar.append(&header, bytes.as_slice())
                    .map_err(|e| Error::io(Path::new(&entry.path), &e))?;
            }
            Content::File(source) => {
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

/// The toolchain's sysroot, as `rustc` in `root` reports it, so the
/// toolchain `rust-toolchain.toml` pins.
fn sysroot(exec: &dyn Exec, root: &Path) -> Result<PathBuf, Error> {
    let out = exec.run(&Cmd::new("rustc").dir(root).args(["--print", "sysroot"]))?;
    Ok(PathBuf::from(out.stdout_text()))
}

/// Requires a notice file that is copied whole to be a regular file.
fn notice_file(path: PathBuf, what: &str) -> Result<PathBuf, Error> {
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => Ok(path),
        _ => Err(Error::check(format!(
            "{what} ({}) is missing or isn't a regular file",
            path.display()
        ))),
    }
}

/// The third-party notices for every target, before anything is built.
fn third_party(
    exec: &dyn Exec,
    manifest: &Path,
    root: &Path,
    version: &str,
) -> Result<BTreeMap<String, ThirdParty>, Error> {
    let rust = notice_file(
        sysroot(exec, root)?.join(RUST_LIBRARY),
        "the toolchain's notice for Rust's standard library",
    )?;
    let mut all = BTreeMap::new();
    for target in TARGETS {
        let meta = cargo_metadata::MetadataCommand::new()
            .manifest_path(manifest)
            .other_options(vec!["--filter-platform".to_owned(), (*target).to_owned()])
            .exec()
            .map_err(|e| Error::Command {
                command: format!("cargo metadata --filter-platform {target}"),
                detail: e.to_string(),
            })?;
        let mut files = vec![("rust-library-COPYRIGHT.html".to_owned(), rust.clone())];
        if notices::is_musl(target) {
            files.push((
                "musl-COPYRIGHT".to_owned(),
                notice_file(root.join(MUSL), "musl's notice")?,
            ));
        }
        all.insert(
            (*target).to_owned(),
            ThirdParty {
                notices: notices::render(version, target, &notices::collect(&meta)?),
                files,
            },
        );
    }
    Ok(all)
}

/// Builds and packs a release into `out`, which must not exist yet.
/// Returns the files written, sorted.
///
/// # Errors
///
/// Returns an error if the tag doesn't match the workspace version,
/// `SOURCE_DATE_EPOCH` is missing, a third-party crate in the programs
/// can't be given a license notice, a build fails, or a file can't be
/// written.
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
    let mtime = source_date_epoch(source_date_epoch_var)?;
    let third_party = third_party(exec, manifest, root, &version)?;
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
        let notices = third_party
            .get(*target)
            .ok_or_else(|| Error::check(format!("no notices for {target}")))?;
        write_archive(
            &archive_entries(root, &binaries, &version, target, notices)?,
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
            content: Content::File(source),
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
            content: Content::Dir,
        };
        assert!(write_archive(&[long], 0, &dir.path().join("c.tar.gz")).is_err());
        let generated = Entry {
            path: "y".repeat(300),
            mode: 0o644,
            content: Content::Bytes(b"x".to_vec()),
        };
        assert!(write_archive(&[generated], 0, &dir.path().join("d.tar.gz")).is_err());
        fs::write(dir.path().join("exists"), "").unwrap();
        assert!(write_archive(&[], 0, &dir.path().join("exists")).is_err());
    }
}
