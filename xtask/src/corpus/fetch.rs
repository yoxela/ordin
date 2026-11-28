// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Downloading a source and checking it before anything reads it.
//!
//! Downloads are kept by their SHA-256, so a source is fetched once, and
//! every run checks the kept copy again. `curl` runs without the user's
//! `.curlrc`, over `https` only, redirects included.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::list::Source;
use crate::release::dist::sha256_file;
use crate::release::exec::{Cmd, Exec};
use crate::release::{Error, say};

/// The kept copy of `source` in `dir`, downloaded if it isn't there or
/// isn't right.
///
/// # Errors
///
/// Returns an error if the download fails, or the file isn't the size and
/// SHA-256 the source declares; a wrong download is removed.
pub fn fetch(
    exec: &dyn Exec,
    dir: &Path,
    source: &Source,
    log: &mut dyn Write,
) -> Result<PathBuf, Error> {
    let kept = dir.join(&source.sha256);
    if fs::symlink_metadata(&kept).is_ok() {
        match check(&kept, source) {
            Ok(()) => return Ok(kept),
            Err(e) => {
                say(log, &format!("corpus: {e}; downloading it again"));
                fs::remove_file(&kept).map_err(|e| Error::io(&kept, &e))?;
            }
        }
    }
    let part = dir.join(format!("{}.part", source.sha256));
    match fs::remove_file(&part) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(&part, &e)),
    }
    say(log, &format!("corpus: downloading {}", source.url));
    let downloaded = exec
        .run(&curl(source, &part))
        .and_then(|_| check(&part, source));
    if let Err(e) = downloaded {
        let _ = fs::remove_file(&part);
        return Err(e);
    }
    fs::rename(&part, &kept).map_err(|e| Error::io(&kept, &e))?;
    Ok(kept)
}

/// The `curl` command that downloads `source` to `out`.
fn curl(source: &Source, out: &Path) -> Cmd {
    Cmd::new("curl")
        // First, or curl reads ~/.curlrc.
        .arg("--disable")
        .args(["--proto", "=https", "--proto-redir", "=https", "--tlsv1.2"])
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--retry",
            "3",
        ])
        .arg("--max-filesize")
        .arg(source.size.to_string())
        .arg("--output")
        .arg(out)
        .arg(&source.url)
}

/// Checks that `path` is a regular file of the source's size and SHA-256.
fn check(path: &Path, source: &Source) -> Result<(), Error> {
    let meta = fs::symlink_metadata(path).map_err(|e| Error::io(path, &e))?;
    if !meta.is_file() {
        return Err(Error::check(format!(
            "{} isn't a regular file",
            path.display()
        )));
    }
    if meta.len() != source.size {
        return Err(Error::check(format!(
            "{} is {} bytes, not {}",
            source.url,
            meta.len(),
            source.size
        )));
    }
    let hash = sha256_file(path)?;
    if hash != source.sha256 {
        return Err(Error::check(format!(
            "{} has SHA-256 {hash}, not {}",
            source.url, source.sha256
        )));
    }
    Ok(())
}

/// Removes downloads in `dir` that no source names any more. Only files
/// named like a download (64 hex digits, perhaps with `.part`) are ever
/// removed.
///
/// # Errors
///
/// Returns an error if the directory can't be read or a file removed.
pub fn prune(dir: &Path, keep: &BTreeSet<&str>, log: &mut dyn Write) -> Result<(), Error> {
    for entry in fs::read_dir(dir).map_err(|e| Error::io(dir, &e))? {
        let entry = entry.map_err(|e| Error::io(dir, &e))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let hash = name.strip_suffix(".part").unwrap_or(name);
        let ours = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
        if ours && (hash.len() != name.len() || !keep.contains(hash)) {
            let path = entry.path();
            if fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
                say(log, &format!("corpus: removing the unused download {name}"));
                fs::remove_file(&path).map_err(|e| Error::io(&path, &e))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::corpus::list::Format;
    use crate::release::exec::Captured;

    const CONTENT: &[u8] = b"corpus";
    /// A SHA-256 that isn't `CONTENT`'s.
    const WRONG: &str = "4bbc9a3c1e0f3ee0a7e2cbdc1ba2ac4b2c8dac8a68c7b7aa5a6e0a5b0bde5c54";

    /// Writes `content` to curl's --output, and records each command.
    struct Curl {
        content: Option<&'static [u8]>,
        runs: RefCell<Vec<Cmd>>,
    }

    impl Exec for Curl {
        fn run(&self, cmd: &Cmd) -> Result<Captured, Error> {
            self.runs.borrow_mut().push(cmd.clone());
            let args = cmd.arg_strings();
            let out = args.iter().position(|a| a == "--output").unwrap() + 1;
            match self.content {
                Some(content) => {
                    fs::write(&args[out], content).unwrap();
                    Ok(Captured::default())
                }
                None => {
                    fs::write(&args[out], b"half").unwrap();
                    Err(Error::check("curl failed"))
                }
            }
        }
    }

    fn curl_with(content: Option<&'static [u8]>) -> Curl {
        Curl {
            content,
            runs: RefCell::new(Vec::new()),
        }
    }

    fn source(hash: &str) -> Source {
        Source {
            url: "https://example.org/a.tar.gz".to_owned(),
            size: CONTENT.len() as u64,
            sha256: hash.to_owned(),
            format: Format::TarGz,
            strip: 0,
            place: Vec::new(),
            exclude: Vec::new(),
        }
    }

    fn real_hash() -> String {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, CONTENT).unwrap();
        sha256_file(&f).unwrap()
    }

    #[test]
    fn a_download_is_checked_and_kept_by_its_hash() {
        let hash = real_hash();
        let dir = tempfile::tempdir().unwrap();
        let curl = curl_with(Some(CONTENT));
        let mut log = Vec::new();
        let kept = fetch(&curl, dir.path(), &source(&hash), &mut log).unwrap();
        assert_eq!(kept, dir.path().join(&hash));
        assert_eq!(fs::read(&kept).unwrap(), CONTENT);
        let runs = curl.runs.borrow();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].program, "curl");
        let part = dir.path().join(format!("{hash}.part"));
        assert_eq!(
            runs[0].arg_strings(),
            [
                "--disable",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--tlsv1.2",
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--retry",
                "3",
                "--max-filesize",
                "6",
                "--output",
                &part.display().to_string(),
                "https://example.org/a.tar.gz"
            ]
        );
        drop(runs);
        assert!(!part.exists());
        assert_eq!(
            String::from_utf8(log).unwrap(),
            "corpus: downloading https://example.org/a.tar.gz\n"
        );
        // Kept and right: nothing is downloaded.
        let again = curl_with(Some(CONTENT));
        fetch(&again, dir.path(), &source(&hash), &mut Vec::new()).unwrap();
        assert!(again.runs.borrow().is_empty());
        // Kept but wrong: downloaded again.
        fs::write(&kept, b"CORPUS").unwrap();
        let mut log = Vec::new();
        let fixed = curl_with(Some(CONTENT));
        fetch(&fixed, dir.path(), &source(&hash), &mut log).unwrap();
        assert_eq!(fixed.runs.borrow().len(), 1);
        assert_eq!(fs::read(&kept).unwrap(), CONTENT);
        assert!(String::from_utf8(log).unwrap().starts_with(&format!(
            "corpus: https://example.org/a.tar.gz has SHA-256 {}, not {hash}; downloading it again\n",
            real_hash_of(b"CORPUS")
        )));
    }

    fn real_hash_of(content: &[u8]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, content).unwrap();
        sha256_file(&f).unwrap()
    }

    #[test]
    fn a_wrong_or_failed_download_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let wrong = source(WRONG);
        let e = fetch(
            &curl_with(Some(CONTENT)),
            dir.path(),
            &wrong,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "https://example.org/a.tar.gz has SHA-256 {}, not {WRONG}",
                real_hash()
            )
        );
        let short = curl_with(Some(b"corp"));
        let e = fetch(&short, dir.path(), &source(&real_hash()), &mut Vec::new()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "https://example.org/a.tar.gz is 4 bytes, not 6"
        );
        let e = fetch(
            &curl_with(None),
            dir.path(),
            &source(&real_hash()),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(e.to_string(), "curl failed");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        // A leftover partial download is replaced; anything else in its
        // place stops the fetch.
        let hash = real_hash();
        fs::write(dir.path().join(format!("{hash}.part")), b"old").unwrap();
        fetch(
            &curl_with(Some(CONTENT)),
            dir.path(),
            &source(&hash),
            &mut Vec::new(),
        )
        .unwrap();
        let other = real_hash_of(b"other!");
        let part = dir.path().join(format!("{other}.part"));
        fs::create_dir(&part).unwrap();
        fs::write(part.join("x"), b"").unwrap();
        assert!(
            fetch(
                &curl_with(Some(b"other!")),
                dir.path(),
                &source(&other),
                &mut Vec::new()
            )
            .is_err()
        );
        // A kept path that isn't a file is refused, and can't be removed as one.
        let kept = dir.path().join(&other);
        fs::create_dir(&kept).unwrap();
        let mut log = Vec::new();
        assert!(
            fetch(
                &curl_with(Some(b"other!")),
                dir.path(),
                &source(&other),
                &mut log
            )
            .is_err()
        );
        assert_eq!(
            String::from_utf8(log).unwrap(),
            format!(
                "corpus: {} isn't a regular file; downloading it again\n",
                kept.display()
            )
        );
    }

    #[test]
    fn unused_downloads_are_pruned_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let keep = "a".repeat(64);
        let old = "b".repeat(64);
        for name in [
            keep.clone(),
            old.clone(),
            format!("{keep}.part"),
            "notes".to_owned(),
            "c".repeat(63),
        ] {
            fs::write(dir.path().join(name), b"").unwrap();
        }
        fs::create_dir(dir.path().join("d".repeat(64))).unwrap();
        let mut log = Vec::new();
        prune(dir.path(), &BTreeSet::from([keep.as_str()]), &mut log).unwrap();
        let mut left: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                keep.clone(),
                "c".repeat(63),
                "d".repeat(64),
                "notes".to_owned()
            ]
        );
        assert_eq!(String::from_utf8(log).unwrap().lines().count(), 2,);
        assert!(prune(&dir.path().join("none"), &BTreeSet::new(), &mut Vec::new()).is_err());
    }
}
